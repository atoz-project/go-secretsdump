package secretsdump_test

import (
	"context"
	"encoding/hex"
	"io"
	"os"
	"testing"

	"github.com/atoz-project/go-secretsdump/pkg/ntds"
	"github.com/atoz-project/go-secretsdump/pkg/sam"
)

func TestEndToEnd(t *testing.T) {
	systemData, err := os.ReadFile("testdata/system")
	if err != nil {
		t.Skip("testdata/system not found:", err)
	}

	ditFile, err := os.Open("testdata/ntds.dit")
	if err != nil {
		t.Skip("testdata/ntds.dit not found:", err)
	}
	defer ditFile.Close()

	// Step 1: Extract boot key using the exported sam.ExtractBootKey.
	bootKey, err := sam.ExtractBootKey(systemData)
	if err != nil {
		t.Fatal("ExtractBootKey:", err)
	}
	if len(bootKey) != 16 {
		t.Fatalf("expected 16-byte boot key, got %d", len(bootKey))
	}

	// Step 2: Open NTDS.dit with the boot key.
	reader, err := ntds.Open(ditFile, bootKey)
	if err != nil {
		t.Fatal("ntds.Open:", err)
	}
	defer reader.Close()

	// Step 3: Iterate all domain hashes.
	ctx := context.Background()
	count := 0
	for {
		hash, err := reader.Next(ctx)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal("Next:", err)
		}
		t.Logf("%s:%d:%s:%s",
			hash.Username, hash.RID,
			hex.EncodeToString(hash.LMHash),
			hex.EncodeToString(hash.NTHash))
		count++
	}

	// Acceptance criteria: at least 39 domain hashes.
	if count < 39 {
		t.Errorf("expected at least 39 domain hashes, got %d", count)
	}
	t.Logf("end-to-end: %d domain hashes extracted", count)
}
