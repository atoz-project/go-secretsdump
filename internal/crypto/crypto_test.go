package crypto

import (
	"bytes"
	"testing"
)

func TestRemoveDES(t *testing.T) {
	// Test with known input: 16 bytes of data + a RID.
	data := make([]byte, 16)
	for i := range data {
		data[i] = byte(i + 1)
	}

	result, err := RemoveDES(data, 500)
	if err != nil {
		t.Fatal("RemoveDES:", err)
	}
	if len(result) != 16 {
		t.Fatalf("expected 16-byte result, got %d", len(result))
	}

	// Verify determinism: same input produces same output.
	result2, err := RemoveDES(data, 500)
	if err != nil {
		t.Fatal("RemoveDES second call:", err)
	}
	if !bytes.Equal(result, result2) {
		t.Fatal("RemoveDES not deterministic")
	}

	// Different RID should produce different output.
	result3, err := RemoveDES(data, 501)
	if err != nil {
		t.Fatal("RemoveDES different RID:", err)
	}
	if bytes.Equal(result, result3) {
		t.Fatal("different RIDs produced same output")
	}
}

func TestRemoveDESTooShort(t *testing.T) {
	_, err := RemoveDES(make([]byte, 15), 500)
	if err == nil {
		t.Fatal("expected error for short input")
	}
}

func TestDecryptAES(t *testing.T) {
	// AES-CBC requires key=16/24/32 bytes, IV=16 bytes, data=multiple of 16.
	key := make([]byte, 16)
	iv := make([]byte, 16)
	data := make([]byte, 16)

	result, err := DecryptAES(key, data, iv)
	if err != nil {
		t.Fatal("DecryptAES:", err)
	}
	if len(result) != 16 {
		t.Fatalf("expected 16-byte result, got %d", len(result))
	}

	// Deterministic.
	result2, err := DecryptAES(key, data, iv)
	if err != nil {
		t.Fatal("DecryptAES second call:", err)
	}
	if !bytes.Equal(result, result2) {
		t.Fatal("DecryptAES not deterministic")
	}
}

func TestDecryptAESInvalidKey(t *testing.T) {
	_, err := DecryptAES([]byte{1, 2, 3}, make([]byte, 16), make([]byte, 16))
	if err == nil {
		t.Fatal("expected error for invalid key size")
	}
}

func TestEmptyHashConstants(t *testing.T) {
	if len(EmptyLM) != 16 {
		t.Fatalf("EmptyLM length: got %d, want 16", len(EmptyLM))
	}
	if len(EmptyNT) != 16 {
		t.Fatalf("EmptyNT length: got %d, want 16", len(EmptyNT))
	}

	expectedLM := []byte{0xaa, 0xd3, 0xb4, 0x35, 0xb5, 0x14, 0x04, 0xee, 0xaa, 0xd3, 0xb4, 0x35, 0xb5, 0x14, 0x04, 0xee}
	expectedNT := []byte{0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31, 0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0, 0x89, 0xc0}

	if !bytes.Equal(EmptyLM, expectedLM) {
		t.Fatal("EmptyLM value mismatch")
	}
	if !bytes.Equal(EmptyNT, expectedNT) {
		t.Fatal("EmptyNT value mismatch")
	}
}
