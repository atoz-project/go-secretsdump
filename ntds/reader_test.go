package ntds_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/atoz-project/go-secretsdump/ntds"
	"www.velocidex.com/golang/regparser"
)

func TestNTDSReader(t *testing.T) {
	ditFile, err := os.Open("../testdata/ntds.dit")
	if err != nil {
		t.Skip("testdata/ntds.dit not found:", err)
	}
	defer ditFile.Close()

	systemData, err := os.ReadFile("../testdata/system")
	if err != nil {
		t.Skip("testdata/system not found:", err)
	}

	bootKey, err := testExtractBootKey(systemData)
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

// testExtractBootKey extracts boot key from SYSTEM hive using regparser.
func testExtractBootKey(systemData []byte) ([]byte, error) {
	reg, err := regparser.NewRegistry(bytes.NewReader(systemData))
	if err != nil {
		return nil, fmt.Errorf("parse SYSTEM: %w", err)
	}

	controlSet := "ControlSet001"
	selectKey := reg.OpenKey("Select")
	if selectKey != nil {
		for _, v := range selectKey.Values() {
			if strings.EqualFold(v.ValueName(), "Current") {
				vd := v.ValueData()
				if vd != nil && vd.Error == nil && vd.Uint64 > 0 && vd.Uint64 < 10 {
					controlSet = fmt.Sprintf("ControlSet%03d", vd.Uint64)
				}
			}
		}
	}

	lsaPath := controlSet + "\\Control\\Lsa"
	var scrambled []byte
	for _, name := range []string{"JD", "Skew1", "GBG", "Data"} {
		key := reg.OpenKey(lsaPath + "\\" + name)
		if key == nil {
			return nil, fmt.Errorf("key not found: %s\\%s", lsaPath, name)
		}
		classLen := key.ClassLength()
		classOff := key.Class()
		if classLen == 0 {
			return nil, fmt.Errorf("empty class for %s", name)
		}
		className := regparser.ParseUTF16String(reg.Reader, int64(classOff)+4096+4, int64(classLen))
		decoded, err := hex.DecodeString(className)
		if err != nil {
			return nil, err
		}
		scrambled = append(scrambled, decoded...)
	}

	perm := []int{8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7}
	bootKey := make([]byte, 16)
	for i, p := range perm {
		bootKey[i] = scrambled[p]
	}
	return bootKey, nil
}
