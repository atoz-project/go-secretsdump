// Package ntds extracts domain user hashes from NTDS.dit (Active Directory)
// database files. It requires the boot key from the SYSTEM registry hive
// to decrypt the PEK (Password Encryption Key) and user credentials.
//
// Originally derived from github.com/C-Sto/gosecretsdump (GPL-3.0).
package ntds

// NTDS.dit column name constants (ATT* format).
const (
	colObjectSid               = "ATTr589970"
	colSAMAccountName          = "ATTm590045"
	colSAMAccountType          = "ATTj590126"
	colUserPrincipalName       = "ATTm590480"
	colUnicodePwd              = "ATTk589914"
	colDBCSPwd                 = "ATTk589879"
	colNTPwdHistory            = "ATTk589918"
	colLMPwdHistory            = "ATTk589984"
	colPekList                 = "ATTk590689"
	colSupplementalCredentials = "ATTk589949"
	colUserAccountControl      = "ATTj589832"
)

// SAM account types that represent user-like accounts.
var accountTypes = map[int32]bool{
	0x30000000: true, // SAM_NORMAL_USER_ACCOUNT
	0x30000001: true, // SAM_MACHINE_ACCOUNT
	0x30000002: true, // SAM_TRUST_ACCOUNT
}

// DomainHash represents a single Active Directory user's credentials.
type DomainHash struct {
	Username string
	Domain   string
	RID      uint32
	LMHash   []byte // 16 bytes
	NTHash   []byte // 16 bytes
	Enabled  bool
	History  *PasswordHistory
	Kerberos []KerberosKey
	Cleartext string
}

// PasswordHistory holds historical LM and NT hashes.
type PasswordHistory struct {
	LMHistory [][]byte
	NTHistory [][]byte
}

// KerberosKey holds a single Kerberos key.
type KerberosKey struct {
	Type  int32
	Value []byte
}

// UAC flags for userAccountControl.
const (
	uacAccountDisable = 0x2
)
