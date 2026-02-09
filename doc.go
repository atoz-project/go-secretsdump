// Package secretsdump provides Go libraries for parsing Windows credential
// stores: SAM registry hives (local accounts) and NTDS.dit databases
// (Active Directory domain accounts).
//
// Sub-packages:
//   - ese: Extensible Storage Engine (JET Blue) database reader
//   - sam: SAM/SYSTEM registry hive parser for local account hashes
//   - ntds: NTDS.dit parser for domain account hashes
package secretsdump
