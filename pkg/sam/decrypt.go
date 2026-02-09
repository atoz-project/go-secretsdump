package sam

import (
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"fmt"

	"github.com/atoz-project/go-secretsdump/internal/crypto"
)

// Constants for SAM key derivation.
var (
	qwertyConst = []byte("!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\x00")
	digitConst  = []byte("0123456789012345678901234567890123456789\x00")
)

// samKeyDataAES is the AES-based SAM key header (revision 3).
type samKeyDataAES struct {
	Revision uint32
	Length   uint32
	CheckLen uint32
	DataLen  uint32
	Salt     [16]byte
	Data     [32]byte
}

// samKeyDataRC4 is the RC4-based SAM key header (revision 2).
type samKeyDataRC4 struct {
	Revision uint32
	Length   uint32
	Salt     [16]byte
	Key      [16]byte
	Checksum [16]byte
	Reserved [2]uint32
}

// samHashAESInfo is the AES hash header.
type samHashAESInfo struct {
	PekID      uint16
	Revision   uint16
	DataOffset uint32
	Salt       [16]byte
}

// deriveSysKey derives the SAM system key from the boot key and the F value.
func deriveSysKey(fData, bootKey []byte) ([]byte, error) {
	if len(fData) < 4 {
		return nil, fmt.Errorf("F value too short")
	}

	revision := binary.LittleEndian.Uint16(fData[:2])

	// Skip the fixed header portion to get to the key data.
	// The header (f_Details) is 104 bytes, followed by key data.
	headerSize := 104
	if len(fData) < headerSize {
		return nil, fmt.Errorf("F value too short for header: %d bytes", len(fData))
	}
	keyData := fData[headerSize:]

	switch revision {
	case 3:
		// AES-based (Vista+).
		if len(keyData) < 56 {
			return nil, fmt.Errorf("AES key data too short")
		}
		var aesKey samKeyDataAES
		aesKey.Revision = binary.LittleEndian.Uint32(keyData[0:4])
		aesKey.Length = binary.LittleEndian.Uint32(keyData[4:8])
		aesKey.CheckLen = binary.LittleEndian.Uint32(keyData[8:12])
		aesKey.DataLen = binary.LittleEndian.Uint32(keyData[12:16])
		copy(aesKey.Salt[:], keyData[16:32])
		copy(aesKey.Data[:], keyData[32:64])

		cipherData := aesKey.Data[:aesKey.DataLen]
		dec, err := crypto.DecryptAES(bootKey, cipherData, aesKey.Salt[:])
		if err != nil {
			return nil, fmt.Errorf("AES decrypt sys key: %w", err)
		}
		if len(dec) < 16 {
			return nil, fmt.Errorf("decrypted sys key too short")
		}
		return dec[:16], nil

	case 2:
		// RC4-based (XP/2003).
		if len(keyData) < 56 {
			return nil, fmt.Errorf("RC4 key data too short")
		}
		var rc4Key samKeyDataRC4
		rc4Key.Revision = binary.LittleEndian.Uint32(keyData[0:4])
		rc4Key.Length = binary.LittleEndian.Uint32(keyData[4:8])
		copy(rc4Key.Salt[:], keyData[8:24])
		copy(rc4Key.Key[:], keyData[24:40])
		copy(rc4Key.Checksum[:], keyData[40:56])

		hashData := append(rc4Key.Salt[:], qwertyConst...)
		hashData = append(hashData, bootKey...)
		hashData = append(hashData, digitConst...)
		rc4KeyHash := md5.Sum(hashData)

		c, err := rc4.NewCipher(rc4KeyHash[:])
		if err != nil {
			return nil, fmt.Errorf("RC4 cipher: %w", err)
		}
		combined := append(rc4Key.Key[:], rc4Key.Checksum[:]...)
		dec := make([]byte, len(combined))
		c.XORKeyStream(dec, combined)
		return dec[:16], nil

	default:
		return nil, fmt.Errorf("unsupported SAM F revision: %d", revision)
	}
}

// decryptSAMHash decrypts a SAM user hash using the system key and RID.
func decryptSAMHash(hashData, sysKey []byte, rid uint32) ([]byte, error) {
	if len(hashData) < 4 {
		return nil, fmt.Errorf("hash data too short")
	}

	if hashData[0] != 2 {
		// RC4-based hash (revision 1).
		if len(hashData) == 20 {
			return hashData[4:20], nil
		}
		return nil, nil
	}

	// AES-based hash.
	if len(hashData) < 24 {
		return nil, fmt.Errorf("AES hash data too short")
	}
	var info samHashAESInfo
	info.PekID = binary.LittleEndian.Uint16(hashData[0:2])
	info.Revision = binary.LittleEndian.Uint16(hashData[2:4])
	info.DataOffset = binary.LittleEndian.Uint32(hashData[4:8])
	copy(info.Salt[:], hashData[8:24])
	encHash := hashData[24:]

	if len(encHash) == 0 {
		return nil, nil
	}

	raw, err := crypto.DecryptAES(sysKey, encHash, info.Salt[:])
	if err != nil {
		return nil, fmt.Errorf("AES decrypt hash: %w", err)
	}
	if len(raw) < 16 {
		return nil, fmt.Errorf("decrypted hash too short")
	}
	return raw[:16], nil
}

