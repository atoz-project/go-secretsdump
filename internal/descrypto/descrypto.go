package descrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"encoding/binary"
	"fmt"
)

// RemoveDES performs the final DES two-key decryption using the RID.
// The input must be at least 16 bytes.
func RemoveDES(data []byte, rid uint32) ([]byte, error) {
	if len(data) < 16 {
		return nil, fmt.Errorf("DES input too short: %d bytes", len(data))
	}

	k1, k2 := deriveKey(rid)
	c1, err := des.NewCipher(k1)
	if err != nil {
		return nil, err
	}
	c2, err := des.NewCipher(k2)
	if err != nil {
		return nil, err
	}

	result := make([]byte, 16)
	c1.Decrypt(result[:8], data[:8])
	c2.Decrypt(result[8:], data[8:16])
	return result, nil
}

// deriveKey derives two 8-byte DES keys from a RID.
func deriveKey(rid uint32) (k1, k2 []byte) {
	key := make([]byte, 4)
	binary.LittleEndian.PutUint32(key, rid)
	key1 := []byte{key[0], key[1], key[2], key[3], key[0], key[1], key[2]}
	key2 := []byte{key[3], key[0], key[1], key[2], key[3], key[0], key[1]}
	return transformKey(key1), transformKey(key2)
}

// transformKey converts a 7-byte key into an 8-byte DES key with parity bits.
func transformKey(in []byte) []byte {
	out := make([]byte, 8)
	out[0] = in[0] >> 1
	out[1] = ((in[0] & 0x01) << 6) | (in[1] >> 2)
	out[2] = ((in[1] & 0x03) << 5) | (in[2] >> 3)
	out[3] = ((in[2] & 0x07) << 4) | (in[3] >> 4)
	out[4] = ((in[3] & 0x0f) << 3) | (in[4] >> 5)
	out[5] = ((in[4] & 0x1f) << 2) | (in[5] >> 6)
	out[6] = ((in[5] & 0x3f) << 1) | (in[6] >> 7)
	out[7] = in[6] & 0x7f
	for i := range out {
		out[i] = (out[i] << 1) & 0xfe
	}
	return out
}

// DecryptAES decrypts data using AES-CBC with the given key and IV.
func DecryptAES(key, data, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	dst := make([]byte, len(data))
	mode.CryptBlocks(dst, data)
	return dst, nil
}
