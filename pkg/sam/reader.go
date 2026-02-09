package sam

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/atoz-project/go-secretsdump/internal/crypto"
	"golang.org/x/text/encoding/unicode"
	"www.velocidex.com/golang/regparser"
)

// Reader parses SAM and SYSTEM registry hives to extract local user hashes.
type Reader struct {
	bootKey []byte
	samReg  *regparser.Registry
}

// Open reads both the SAM and SYSTEM hive data, extracts the boot key,
// and prepares the reader for hash extraction.
func Open(samReader, systemReader io.Reader) (*Reader, error) {
	systemData, err := io.ReadAll(systemReader)
	if err != nil {
		return nil, fmt.Errorf("read SYSTEM hive: %w", err)
	}
	if len(systemData) == 0 {
		return nil, fmt.Errorf("SYSTEM hive is empty")
	}

	samData, err := io.ReadAll(samReader)
	if err != nil {
		return nil, fmt.Errorf("read SAM hive: %w", err)
	}
	if len(samData) == 0 {
		return nil, fmt.Errorf("SAM hive is empty")
	}

	// Extract boot key from SYSTEM hive.
	bootKey, err := ExtractBootKey(systemData)
	if err != nil {
		return nil, fmt.Errorf("extract boot key: %w", err)
	}

	samReg, err := regparser.NewRegistry(bytes.NewReader(samData))
	if err != nil {
		return nil, fmt.Errorf("parse SAM hive: %w", err)
	}

	return &Reader{
		bootKey: bootKey,
		samReg:  samReg,
	}, nil
}

// BootKey returns the extracted 16-byte boot key.
// This can be passed to ntds.Open() for NTDS.dit parsing.
func (r *Reader) BootKey() []byte {
	return r.bootKey
}

// DumpAll returns all local user hashes from the SAM hive.
func (r *Reader) DumpAll() ([]LocalHash, error) {
	// Get the SAM system key (derived from boot key + F value).
	fData, err := r.getRegValue("SAM\\Domains\\Account", "F")
	if err != nil {
		return nil, fmt.Errorf("read SAM F value: %w", err)
	}
	sysKey, err := deriveSysKey(fData, r.bootKey)
	if err != nil {
		return nil, fmt.Errorf("derive sys key: %w", err)
	}

	// Enumerate user RIDs.
	rids, err := r.enumUserRIDs()
	if err != nil {
		return nil, fmt.Errorf("enum user RIDs: %w", err)
	}

	utf16Dec := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder()

	var results []LocalHash
	for _, rid := range rids {
		// Read V value for this user.
		ridHex := strings.ToUpper(fmt.Sprintf("%08X", rid))
		vData, err := r.getRegValue("SAM\\Domains\\Account\\Users\\"+ridHex, "V")
		if err != nil {
			continue
		}

		v, err := parseUserV(vData)
		if err != nil {
			continue
		}

		// Extract username.
		username := ""
		usernameData := v.getField(v.username, v.data)
		if len(usernameData) > 0 {
			b, err := utf16Dec.Bytes(usernameData)
			if err != nil {
				username = string(usernameData)
			} else {
				username = string(b)
			}
		}

		// Decrypt NTLM hash.
		ntlmData := v.getField(v.ntlmHash, v.data)
		ntHash := crypto.EmptyNT
		if len(ntlmData) > 0 {
			decrypted, err := decryptSAMHash(ntlmData, sysKey, rid)
			if err == nil && decrypted != nil {
				plainHash, err := crypto.RemoveDES(decrypted, rid)
				if err == nil {
					ntHash = plainHash
				}
			}
		}

		// Decrypt LM hash.
		lmData := v.getField(v.lmHash, v.data)
		lmHash := crypto.EmptyLM
		if len(lmData) > 0 {
			decrypted, err := decryptSAMHash(lmData, sysKey, rid)
			if err == nil && decrypted != nil {
				plainHash, err := crypto.RemoveDES(decrypted, rid)
				if err == nil {
					lmHash = plainHash
				}
			}
		}

		results = append(results, LocalHash{
			Username: username,
			RID:      rid,
			LMHash:   lmHash,
			NTHash:   ntHash,
			Enabled:  true, // SAM reader doesn't check account status in original code.
		})
	}

	if results == nil {
		results = []LocalHash{}
	}
	return results, nil
}

// getRegValue reads a named value from a registry key.
func (r *Reader) getRegValue(keyPath, valueName string) ([]byte, error) {
	key := r.samReg.OpenKey(keyPath)
	if key == nil {
		return nil, fmt.Errorf("key not found: %s", keyPath)
	}
	for _, v := range key.Values() {
		if strings.EqualFold(v.ValueName(), valueName) {
			vd := v.ValueData()
			if vd != nil && vd.Error == nil {
				return vd.Data, nil
			}
		}
	}
	return nil, fmt.Errorf("value %q not found in %s", valueName, keyPath)
}

// enumUserRIDs enumerates user RIDs from SAM\Domains\Account\Users.
func (r *Reader) enumUserRIDs() ([]uint32, error) {
	usersKey := r.samReg.OpenKey("SAM\\Domains\\Account\\Users")
	if usersKey == nil {
		return nil, fmt.Errorf("SAM Users key not found")
	}

	var rids []uint32
	for _, sub := range usersKey.Subkeys() {
		name := sub.Name()
		if strings.EqualFold(name, "Names") {
			continue
		}
		b, err := hex.DecodeString(name)
		if err != nil {
			continue
		}
		if len(b) == 4 {
			rids = append(rids, binary.BigEndian.Uint32(b))
		}
	}
	return rids, nil
}

// samEntry is a SAM V value field descriptor.
type samEntry struct {
	offset uint32
	length uint32
}

// userV holds parsed SAM V value data.
type userV struct {
	username samEntry
	lmHash   samEntry
	ntlmHash samEntry
	data     []byte
}

// parseUserV parses the SAM V value structure.
func parseUserV(data []byte) (*userV, error) {
	// SAM V structure: 17 SAMEntry fields (each 12 bytes = 3 uint32), then data.
	// Fields: [0]=unknown, [1]=username, [2]=fullname, [3]=comment,
	// [4]=userComment, [5]=unknown, [6]=homedir, [7]=homedirConnect,
	// [8]=scriptPath, [9]=profilePath, [10]=workstations, [11]=hoursAllowed,
	// [12]=unknown, [13]=LMHash, [14]=NTLMHash, [15]=NTLMHistory, [16]=LMHistory
	entrySize := 12 // 3 * uint32
	numEntries := 17
	headerSize := entrySize * numEntries
	if len(data) < headerSize {
		return nil, fmt.Errorf("V value too short: %d bytes", len(data))
	}

	v := &userV{}
	rd := bytes.NewReader(data)

	entries := make([]samEntry, numEntries)
	for i := 0; i < numEntries; i++ {
		var offset, length, padding uint32
		binary.Read(rd, binary.LittleEndian, &offset)
		binary.Read(rd, binary.LittleEndian, &length)
		binary.Read(rd, binary.LittleEndian, &padding)
		entries[i] = samEntry{offset: offset, length: length}
	}

	v.username = entries[1]
	v.lmHash = entries[13]
	v.ntlmHash = entries[14]
	v.data = data[headerSize:]

	return v, nil
}

// getField extracts field data from the V value body.
func (v *userV) getField(entry samEntry, body []byte) []byte {
	if entry.length == 0 {
		return nil
	}
	start := int(entry.offset)
	end := start + int(entry.length)
	if start >= len(body) || end > len(body) {
		return nil
	}
	return body[start:end]
}
