package ntds

import (
	"context"
	"fmt"
	"io"

	"github.com/atoz-project/go-secretsdump/internal/crypto"
	"github.com/atoz-project/go-secretsdump/pkg/ese"
)

// Reader reads NTDS.dit databases and iterates over domain user hashes.
type Reader struct {
	db     *ese.DB
	cursor *ese.Cursor
	pek    [][]byte

	// bufferedRecords holds records encountered before PEK was found.
	bufferedRecords []*ese.Record
	bufferIdx       int
}

// Open opens an NTDS.dit database and extracts the PEK using the provided boot key.
// The bootKey should be 16 bytes, extracted from the SYSTEM registry hive.
func Open(r io.ReadSeeker, bootKey []byte) (*Reader, error) {
	if len(bootKey) != 16 {
		return nil, fmt.Errorf("boot key must be 16 bytes, got %d", len(bootKey))
	}

	db, err := ese.Open(r)
	if err != nil {
		return nil, fmt.Errorf("open ESE database: %w", err)
	}

	cursor, err := db.OpenTable("datatable")
	if err != nil {
		return nil, fmt.Errorf("open datatable: %w", err)
	}

	rd := &Reader{
		db:     db,
		cursor: cursor,
	}

	// Find and decrypt the PEK.
	if err := rd.findPEK(context.Background(), bootKey); err != nil {
		return nil, fmt.Errorf("find PEK: %w", err)
	}

	if len(rd.pek) == 0 {
		return nil, fmt.Errorf("no PEK found in NTDS.dit")
	}

	return rd, nil
}

// findPEK iterates through records to find the pekList, buffering user records
// encountered along the way.
func (rd *Reader) findPEK(ctx context.Context, bootKey []byte) error {
	for {
		rec, err := rd.cursor.Next(ctx)
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read record: %w", err)
		}

		// Check for PEK list.
		pekData := rec.Bytes(colPekList)
		if len(pekData) > 0 {
			pek, err := decryptPEK(pekData, bootKey)
			if err != nil {
				return fmt.Errorf("decrypt PEK: %w", err)
			}
			rd.pek = pek
			return nil
		}

		// Buffer user records found before PEK.
		if rec.HasColumn(colSAMAccountType) {
			rd.bufferedRecords = append(rd.bufferedRecords, rec)
		}
	}
	return nil
}

// Next returns the next domain user hash. Returns io.EOF when done.
func (rd *Reader) Next(ctx context.Context) (*DomainHash, error) {
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		rec, err := rd.nextRecord(ctx)
		if err != nil {
			return nil, err
		}

		// Check if this is a user account record.
		accType, ok := rec.Int32(colSAMAccountType)
		if !ok {
			continue
		}
		if !accountTypes[accType] {
			continue
		}

		dh, err := rd.decryptRecord(rec)
		if err != nil {
			// Skip records that fail to decrypt.
			continue
		}

		return dh, nil
	}
}

// nextRecord returns the next ESE record, first draining the buffer, then reading from the cursor.
func (rd *Reader) nextRecord(ctx context.Context) (*ese.Record, error) {
	if rd.bufferIdx < len(rd.bufferedRecords) {
		rec := rd.bufferedRecords[rd.bufferIdx]
		rd.bufferIdx++
		return rec, nil
	}
	return rd.cursor.Next(ctx)
}

// decryptRecord decrypts a single user record into a DomainHash.
func (rd *Reader) decryptRecord(rec *ese.Record) (*DomainHash, error) {
	dh := &DomainHash{}

	// Extract RID from objectSid.
	sidData := rec.Bytes(colObjectSid)
	if len(sidData) == 0 {
		return nil, fmt.Errorf("no objectSid")
	}
	rid, err := parseSID(sidData)
	if err != nil {
		return nil, fmt.Errorf("parse SID: %w", err)
	}
	dh.RID = rid

	dh.LMHash = decryptHashOrDefault(rec.Bytes(colDBCSPwd), rd.pek, rid, crypto.EmptyLM)
	dh.NTHash = decryptHashOrDefault(rec.Bytes(colUnicodePwd), rd.pek, rid, crypto.EmptyNT)

	// Account name.
	accountName := rec.String(colSAMAccountName)

	// Username with domain.
	upn := rec.String(colUserPrincipalName)
	if domain := extractDomain(upn); domain != "" {
		dh.Username = fmt.Sprintf("%s\\%s", domain, accountName)
		dh.Domain = domain
	} else {
		dh.Username = accountName
	}

	ntHist := decryptHistoryOrNil(rec.Bytes(colNTPwdHistory), rd.pek, rid)
	lmHist := decryptHistoryOrNil(rec.Bytes(colLMPwdHistory), rd.pek, rid)
	if ntHist != nil || lmHist != nil {
		dh.History = &PasswordHistory{
			NTHistory: ntHist,
			LMHistory: lmHist,
		}
	}

	// User account control — enabled/disabled.
	uac, ok := rec.Int32(colUserAccountControl)
	if ok {
		dh.Enabled = isAccountEnabled(uac)
	} else {
		dh.Enabled = true
	}

	// Supplemental credentials (Kerberos keys + cleartext).
	suppData := rec.Bytes(colSupplementalCredentials)
	if len(suppData) > 24 {
		kerbKeys, cleartext, err := decryptSupplementalCredentials(suppData, rd.pek, dh.Username)
		if err == nil {
			dh.Kerberos = kerbKeys
			dh.Cleartext = cleartext
		}
	}

	return dh, nil
}

func decryptHashOrDefault(data []byte, pek [][]byte, rid uint32, empty []byte) []byte {
	if len(data) == 0 {
		return empty
	}
	h, err := decryptHash(data, pek, rid)
	if err != nil {
		return empty
	}
	return h
}

func decryptHistoryOrNil(data []byte, pek [][]byte, rid uint32) [][]byte {
	if len(data) == 0 {
		return nil
	}
	hist, err := decryptHashHistory(data, pek, rid)
	if err != nil || len(hist) == 0 {
		return nil
	}
	return hist
}

// Close is a no-op provided for interface compatibility.
func (rd *Reader) Close() error {
	return nil
}
