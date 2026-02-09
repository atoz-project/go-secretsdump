package ntds

import (
	"bytes"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode"

	"github.com/atoz-project/go-secretsdump/internal/descrypto"
	utfenc "golang.org/x/text/encoding/unicode"
)

// decryptPEK extracts and decrypts the PEK (Password Encryption Key) from the
// pekList column value using the boot key.
func decryptPEK(pekListRaw, bootKey []byte) ([][]byte, error) {
	if len(pekListRaw) < 24 {
		return nil, fmt.Errorf("pekList data too short: %d bytes", len(pekListRaw))
	}

	header := pekListRaw[:8]
	keyMaterial := pekListRaw[8:24]
	encryptedPek := pekListRaw[24:]

	switch {
	case bytes.Equal(header[:4], []byte{2, 0, 0, 0}):
		// Windows 2012 R2 and earlier: RC4-based PEK decryption.
		h := md5.New()
		h.Write(bootKey)
		for i := 0; i < 1000; i++ {
			h.Write(keyMaterial)
		}
		tmpKey := h.Sum(nil)

		rc, err := rc4.NewCipher(tmpKey)
		if err != nil {
			return nil, fmt.Errorf("rc4 cipher: %w", err)
		}
		dst := make([]byte, len(encryptedPek))
		rc.XORKeyStream(dst, encryptedPek)

		// Skip 32-byte plain header, then extract 20-byte PEK keys.
		if len(dst) < 32 {
			return nil, fmt.Errorf("decrypted PEK data too short")
		}
		decPek := dst[32:]
		pekKeyLen := 20
		var keys [][]byte
		for i := 0; i+pekKeyLen <= len(decPek); i += pekKeyLen {
			// PEK key is bytes [4:20] of each 20-byte block.
			keys = append(keys, decPek[i+4:i+20])
		}
		return keys, nil

	case bytes.Equal(header[:4], []byte{3, 0, 0, 0}):
		// Windows 2016+: AES-based PEK decryption.
		dec, err := descrypto.DecryptAES(bootKey, encryptedPek, keyMaterial)
		if err != nil {
			return nil, fmt.Errorf("AES decrypt PEK: %w", err)
		}
		if len(dec) < 52 {
			return nil, fmt.Errorf("decrypted AES PEK too short")
		}
		// Skip 32-byte plain header, then key is bytes [4:20].
		return [][]byte{dec[36:52]}, nil

	default:
		return nil, fmt.Errorf("unknown PEK version: %x", header[:4])
	}
}

// cryptedHash holds the parsed fields of an encrypted hash blob.
type cryptedHash struct {
	header        [8]byte
	keyMaterial   [16]byte
	encryptedHash []byte
}

func parseCryptedHash(data []byte) (cryptedHash, error) {
	if len(data) < 24 {
		return cryptedHash{}, fmt.Errorf("crypted hash too short: %d bytes", len(data))
	}
	ch := cryptedHash{}
	copy(ch.header[:], data[:8])
	copy(ch.keyMaterial[:], data[8:24])
	ch.encryptedHash = data[24:]
	return ch, nil
}

// removeRC4 decrypts RC4-encrypted hash data using the PEK key.
func removeRC4(pek [][]byte, ch cryptedHash) ([]byte, error) {
	pekIdx := ch.header[4]
	if int(pekIdx) >= len(pek) {
		return nil, fmt.Errorf("PEK index %d out of range (have %d keys)", pekIdx, len(pek))
	}
	tmpKey := md5.Sum(append(pek[pekIdx], ch.keyMaterial[:]...))
	rc, err := rc4.NewCipher(tmpKey[:])
	if err != nil {
		return nil, err
	}
	plain := make([]byte, len(ch.encryptedHash))
	rc.XORKeyStream(plain, ch.encryptedHash)
	return plain, nil
}

// decryptHash decrypts an LM or NT hash from its encrypted blob.
func decryptHash(data []byte, pek [][]byte, rid uint32) ([]byte, error) {
	if len(data) < 24 {
		return nil, fmt.Errorf("hash data too short")
	}

	ch, err := parseCryptedHash(data)
	if err != nil {
		return nil, err
	}

	var tmpHash []byte
	if bytes.Equal(ch.header[:4], []byte{0x13, 0, 0, 0}) {
		// Windows 2016+ AES-encrypted hash.
		pekIdx := ch.header[4]
		if int(pekIdx) >= len(pek) {
			return nil, fmt.Errorf("PEK index out of range")
		}
		// For W16, encrypted hash is at fixed offset: skip header(8)+keyMaterial(16)+unknown(4) = 28.
		if len(data) < 44 {
			return nil, fmt.Errorf("W16 hash data too short")
		}
		encHash := data[28:44] // 16 bytes of encrypted hash
		tmpHash, err = descrypto.DecryptAES(pek[pekIdx], encHash, ch.keyMaterial[:])
		if err != nil {
			return nil, err
		}
	} else {
		// RC4-encrypted hash.
		tmpHash, err = removeRC4(pek, ch)
		if err != nil {
			return nil, err
		}
	}

	if len(tmpHash) < 16 {
		return nil, fmt.Errorf("decrypted hash too short: %d bytes", len(tmpHash))
	}
	return descrypto.RemoveDES(tmpHash[:16], rid)
}

// decryptHashHistory decrypts password history hashes.
func decryptHashHistory(data []byte, pek [][]byte, rid uint32) ([][]byte, error) {
	if len(data) < 24 {
		return nil, nil
	}

	ch, err := parseCryptedHash(data)
	if err != nil {
		return nil, err
	}

	var plainHist []byte
	if bytes.Equal(ch.header[:4], []byte{0x13, 0, 0, 0}) {
		// W16 AES history.
		pekIdx := ch.header[4]
		if int(pekIdx) >= len(pek) {
			return nil, fmt.Errorf("PEK index out of range")
		}
		// History: header(8) + keyMaterial(16) + unknown(4) = 28, rest is encrypted.
		if len(data) < 28 {
			return nil, nil
		}
		plainHist, err = descrypto.DecryptAES(pek[pekIdx], data[28:], ch.keyMaterial[:])
		if err != nil {
			return nil, err
		}
	} else {
		plainHist, err = removeRC4(pek, ch)
		if err != nil {
			return nil, err
		}
	}

	var hashes [][]byte
	// Skip first 16 bytes (current hash), then each 16 bytes is a historical hash.
	for i := 16; i+16 <= len(plainHist); i += 16 {
		h, err := descrypto.RemoveDES(plainHist[i:i+16], rid)
		if err != nil {
			continue
		}
		hashes = append(hashes, h)
	}
	return hashes, nil
}

// parseSID extracts the RID from an objectSid binary value.
func parseSID(data []byte) (uint32, error) {
	if len(data) < 8 {
		return 0, fmt.Errorf("SID too short: %d bytes", len(data))
	}
	subAuthorityCount := data[1]
	ridOffset := 8 + (int(subAuthorityCount)-1)*4
	if ridOffset+4 > len(data) {
		return 0, fmt.Errorf("SID too short for RID")
	}
	return binary.BigEndian.Uint32(data[ridOffset : ridOffset+4]), nil
}

// decryptSupplementalCredentials extracts Kerberos keys and cleartext passwords
// from the supplementalCredentials attribute.
func decryptSupplementalCredentials(data []byte, pek [][]byte, username string) ([]KerberosKey, string, error) {
	if len(data) < 24 {
		return nil, "", nil
	}

	ch, err := parseCryptedHash(data)
	if err != nil {
		return nil, "", err
	}

	var plainBytes []byte
	if bytes.Equal(ch.header[:4], []byte{0x13, 0, 0, 0}) {
		pekIdx := binary.LittleEndian.Uint16(ch.header[4:6])
		if int(pekIdx) >= len(pek) {
			return nil, "", fmt.Errorf("PEK index out of range")
		}
		plainBytes, err = descrypto.DecryptAES(pek[pekIdx], ch.encryptedHash[4:], ch.keyMaterial[:])
		if err != nil {
			return nil, "", err
		}
	} else {
		plainBytes, err = removeRC4(pek, ch)
		if err != nil {
			return nil, "", err
		}
	}

	if len(plainBytes) < 112 {
		return nil, "", nil
	}

	return parseUserProperties(plainBytes, username)
}

// parseUserProperties parses the USER_PROPERTIES structure.
func parseUserProperties(data []byte, username string) ([]KerberosKey, string, error) {
	if len(data) < 112 {
		return nil, "", nil
	}

	// Skip: Reserved1(4) + Length(4) + Reserved2(2) + Reserved3(2) + Reserved4(96) + PropertySignature(2) = 110
	cursor := 110
	if cursor+2 > len(data) {
		return nil, "", nil
	}
	propCount := binary.LittleEndian.Uint16(data[cursor : cursor+2])
	cursor += 2

	utf16Dec := utfenc.UTF16(utfenc.LittleEndian, utfenc.IgnoreBOM).NewDecoder()

	var kerbKeys []KerberosKey
	var cleartext string

	for i := uint16(0); i < propCount && cursor+6 <= len(data); i++ {
		nameLen := int(binary.LittleEndian.Uint16(data[cursor : cursor+2]))
		cursor += 2
		valueLen := int(binary.LittleEndian.Uint16(data[cursor : cursor+2]))
		cursor += 2
		_ = binary.LittleEndian.Uint16(data[cursor : cursor+2]) // reserved
		cursor += 2

		if cursor+nameLen > len(data) {
			break
		}
		propNameRaw := data[cursor : cursor+nameLen]
		cursor += nameLen

		if cursor+valueLen > len(data) {
			break
		}
		propValueRaw := data[cursor : cursor+valueLen]
		cursor += valueLen

		propName, err := utf16Dec.String(string(propNameRaw))
		if err != nil {
			continue
		}

		switch propName {
		case "Primary:Kerberos-Newer-Keys":
			nhex, err := hex.DecodeString(string(propValueRaw))
			if err != nil {
				continue
			}
			keys := parseKerberosKeys(nhex, username)
			kerbKeys = append(kerbKeys, keys...)

		case "Primary:CLEARTEXT":
			nhex, err := hex.DecodeString(string(propValueRaw))
			if err != nil {
				continue
			}
			s, err := utf16Dec.String(string(nhex))
			if err != nil {
				continue
			}
			if isASCII(s) {
				cleartext = s
			} else {
				cleartext = string(propValueRaw)
			}
		}
	}

	return kerbKeys, cleartext, nil
}

// parseKerberosKeys extracts Kerberos keys from a KERB_STORED_CREDENTIAL_NEW structure.
func parseKerberosKeys(data []byte, _ string) []KerberosKey {
	if len(data) < 24 {
		return nil
	}

	credCount := binary.LittleEndian.Uint16(data[4:6])
	cursor := 24 // Fixed header size.

	var keys []KerberosKey
	for i := uint16(0); i < credCount; i++ {
		if cursor+24 > len(data) {
			break
		}
		keyType := binary.LittleEndian.Uint32(data[cursor+12 : cursor+16])
		keyLen := binary.LittleEndian.Uint32(data[cursor+16 : cursor+20])
		keyOff := binary.LittleEndian.Uint32(data[cursor+20 : cursor+24])
		cursor += 24

		if int(keyOff+keyLen) > len(data) {
			continue
		}
		keyVal := make([]byte, keyLen)
		copy(keyVal, data[keyOff:keyOff+keyLen])

		keys = append(keys, KerberosKey{
			Type:  int32(keyType),
			Value: keyVal,
		})
	}

	return keys
}

func isASCII(s string) bool {
	for _, r := range s {
		if r > unicode.MaxASCII {
			return false
		}
	}
	return true
}

func isAccountEnabled(uac int32) bool {
	return uac&uacAccountDisable == 0
}

// extractDomain extracts the domain from a userPrincipalName (user@domain).
func extractDomain(upn string) string {
	if pos := strings.LastIndex(upn, "@"); pos != -1 {
		return upn[pos+1:]
	}
	return ""
}
