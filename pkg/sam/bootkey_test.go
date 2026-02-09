package sam_test

import (
	"os"
	"testing"

	"github.com/atoz-project/go-secretsdump/pkg/sam"
)

func TestExtractBootKey(t *testing.T) {
	systemData, err := os.ReadFile("../../testdata/system")
	if err != nil {
		t.Skip("testdata/system not found:", err)
	}

	bootKey, err := sam.ExtractBootKey(systemData)
	if err != nil {
		t.Fatal("ExtractBootKey:", err)
	}

	if len(bootKey) != 16 {
		t.Fatalf("expected 16-byte boot key, got %d bytes", len(bootKey))
	}

	// Verify the boot key is not all zeros.
	allZero := true
	for _, b := range bootKey {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("boot key is all zeros")
	}
}

func TestExtractBootKeyEmpty(t *testing.T) {
	_, err := sam.ExtractBootKey(nil)
	if err == nil {
		t.Fatal("expected error for nil input")
	}

	_, err = sam.ExtractBootKey([]byte{})
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestExtractBootKeyInvalid(t *testing.T) {
	_, err := sam.ExtractBootKey([]byte{0x01, 0x02, 0x03})
	if err == nil {
		t.Fatal("expected error for invalid input")
	}
}
