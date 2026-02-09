package sam

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"

	"www.velocidex.com/golang/regparser"
)

// ExtractBootKey extracts the 16-byte boot key from raw SYSTEM hive data.
// The boot key is required by both SAM and NTDS.dit decryption.
func ExtractBootKey(systemData []byte) ([]byte, error) {
	if len(systemData) == 0 {
		return nil, fmt.Errorf("SYSTEM hive data is empty")
	}

	reg, err := regparser.NewRegistry(bytes.NewReader(systemData))
	if err != nil {
		return nil, fmt.Errorf("parse SYSTEM hive: %w", err)
	}

	// Find current control set.
	controlSet := "ControlSet001"
	selectKey := reg.OpenKey("Select")
	if selectKey != nil {
		for _, v := range selectKey.Values() {
			if strings.EqualFold(v.ValueName(), "Current") {
				vd := v.ValueData()
				if vd != nil && vd.Error == nil {
					num := vd.Uint64
					if num > 0 && num < 10 {
						controlSet = fmt.Sprintf("ControlSet%03d", num)
					}
				}
			}
		}
	}

	lsaPath := controlSet + "\\Control\\Lsa"
	keyNames := []string{"JD", "Skew1", "GBG", "Data"}

	var scrambledKey []byte
	for _, name := range keyNames {
		path := lsaPath + "\\" + name
		key := reg.OpenKey(path)
		if key == nil {
			return nil, fmt.Errorf("LSA key not found: %s", path)
		}
		classLen := key.ClassLength()
		classOff := key.Class()
		if classLen == 0 {
			return nil, fmt.Errorf("empty class name for %s", path)
		}
		className := regparser.ParseUTF16String(reg.Reader, int64(classOff)+4096+4, int64(classLen))
		decoded, err := hex.DecodeString(className)
		if err != nil {
			return nil, fmt.Errorf("decode class name for %s: %w", name, err)
		}
		scrambledKey = append(scrambledKey, decoded...)
	}

	if len(scrambledKey) < 16 {
		return nil, fmt.Errorf("boot key too short: %d bytes", len(scrambledKey))
	}

	perm := []int{8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7}
	bootKey := make([]byte, 16)
	for i, p := range perm {
		bootKey[i] = scrambledKey[p]
	}
	return bootKey, nil
}
