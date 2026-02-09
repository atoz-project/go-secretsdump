// Package sam extracts local user hashes from Windows SAM and SYSTEM
// registry hive files. It uses velocidex/regparser for registry parsing.
//
// Originally derived from github.com/C-Sto/gosecretsdump (GPL-3.0).
package sam

// LocalHash represents a parsed local Windows user credential.
type LocalHash struct {
	Username string
	RID      uint32
	LMHash   []byte // 16 bytes
	NTHash   []byte // 16 bytes
	Enabled  bool
}
