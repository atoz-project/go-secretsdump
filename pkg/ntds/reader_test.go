package ntds_test

import (
	"context"
	"encoding/hex"
	"io"
	"os"
	"testing"

	"github.com/atoz-project/go-secretsdump/pkg/ntds"
	"github.com/atoz-project/go-secretsdump/pkg/sam"
)

func TestNTDSReader(t *testing.T) {
	ditFile, err := os.Open("testdata/ntds.dit")
	if err != nil {
		t.Skip("testdata/ntds.dit not found:", err)
	}
	defer ditFile.Close()

	systemData, err := os.ReadFile("testdata/system")
	if err != nil {
		t.Skip("testdata/system not found:", err)
	}

	bootKey, err := sam.ExtractBootKey(systemData)
	if err != nil {
		t.Fatal("extract boot key:", err)
	}

	reader, err := ntds.Open(ditFile, bootKey)
	if err != nil {
		t.Fatal("Open:", err)
	}
	defer reader.Close()

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

	if count == 0 {
		t.Fatal("expected domain hashes, got 0")
	}
	t.Logf("total domain hashes: %d", count)

	// Verify we got a reasonable number of records.
	// The test dataset contains 45 user/machine/trust accounts.
	if count < 39 {
		t.Errorf("expected at least 39 domain hashes, got %d", count)
	}
}
