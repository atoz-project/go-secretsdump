// Package ese implements a reader for the Extensible Storage Engine (ESE)
// database format (also known as JET Blue). It supports on-demand page reading
// from an io.ReadSeeker, avoiding full file loading into memory.
//
// Originally derived from github.com/C-Sto/gosecretsdump (GPL-3.0).
package ese

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/encoding/unicode"
)

// Page flags.
const (
	flagRoot      = 0x1
	flagLeaf      = 0x2
	flagParent    = 0x4
	flagEmpty     = 0x8
	flagSpaceTree = 0x20
	flagIndex     = 0x40
	flagLongValue = 0x80
)

// Tag flags.
const (
	tagCommon = 0x4
)

// Catalog types.
const (
	catalogTypeTable    = 1
	catalogTypeColumn   = 2
	catalogTypeIndex    = 3
	catalogTypeLongVal  = 4
	catalogTypeCallback = 5
)

// Column types (JET_coltyp).
const (
	coltypNil          = 0
	coltypBit          = 1
	coltypUnsignedByte = 2
	coltypShort        = 3
	coltypLong         = 4
	coltypCurrency     = 5
	coltypIEEESingle   = 6
	coltypIEEEDouble   = 7
	coltypDateTime     = 8
	coltypBinary       = 9
	coltypText         = 10
	coltypLongBinary   = 11
	coltypLongText     = 12
	coltypSLV          = 13
	coltypUnsignedLong = 14
	coltypLongLong     = 15
	coltypGUID         = 16
	coltypUnsignedShort = 17
)

// Tagged data type flags.
const (
	taggedDataCompressed = 2
	taggedDataMultiValue = 8
)

// Fixed page numbers.
const (
	catalogPageNumber = 4
)

// Default page size (before reading header).
const defaultPageSize = 8192

// dbHeader is the on-disk database header structure.
type dbHeader struct {
	CheckSum                   uint32
	Signature                  [4]byte
	Version                    uint32
	FileType                   uint32
	DBTime                     uint64
	DBSignature                jetSignature
	DBState                    uint32
	ConsistentPosition         uint64
	ConsistentTime             uint64
	AttachTime                 uint64
	AttachPosition             uint64
	DetachTime                 uint64
	DetachPosition             uint64
	LogSignature               jetSignature
	Unknown                    uint32
	PreviousBackup             [24]byte
	PreviousIncBackup          [24]byte
	CurrentFullBackup          [24]byte
	ShadowingDisables          uint32
	LastObjectID               uint32
	WindowsMajorVersion        uint32
	WindowsMinorVersion        uint32
	WindowsBuildNumber         uint32
	WindowsServicePackNumber   uint32
	FileFormatRevision         uint32
	PageSize                   uint32
	RepairCount                uint32
	RepairTime                 uint64
	Unknown2                   [28]byte
	ScrubTime                  uint64
	RequiredLog                uint64
	UpgradeExchangeFormat      uint32
	UpgradeFreePages           uint32
	UpgradeSpaceMapPages       uint32
	CurrentShadowBackup        [24]byte
	CreationFileFormatVersion  uint32
	CreationFileFormatRevision uint32
	Unknown3                   [16]byte
	OldRepairCount             uint32
	ECCCount                   uint32
	LastECCTime                uint64
	OldECCFixSuccessCount      uint32
	ECCFixErrorCount           uint32
	LastECCFixErrorTime        uint64
	OldECCFixErrorCount        uint32
	BadCheckSumErrorCount      uint32
	LastBadCheckSumTime        uint64
	OldCheckSumErrorCount      uint32
	CommittedLog               uint32
	PreviousShadowCopy         [24]byte
	PreviousDifferentialBackup [24]byte
	Unknown4                   [40]byte
	NLSMajorVersion            uint32
	NLSMinorVersion            uint32
	Unknown5                   [148]byte
	UnknownFlags               uint32
}

type jetSignature struct {
	Random       uint32
	CreationTime uint64
	NetBiosName  [16]byte
}

// pageHeader stores the parsed page header fields.
type pageHeader struct {
	CheckSum                     uint64
	ECCCheckSum                  uint32
	LastModificationTime         uint64
	PreviousPageNumber           uint32
	NextPageNumber               uint32
	FatherDataPage               uint32
	AvailableDataSize            uint16
	AvailableUncommittedDataSize uint16
	FirstAvailableDataOffset     uint16
	FirstAvailablePageTag        uint16
	PageFlags                    uint32
	PageNumber                   uint64
	headerLen                    uint16
}

// dataDefinitionHeader is the per-record header.
type dataDefinitionHeader struct {
	LastFixedSize        uint8
	LastVariableDataType uint8
	VariableSizeOffset   uint16
}

// catalogEntry holds parsed catalog entry data.
type catalogEntry struct {
	fixed   fixedCatalogEntry
	columns columnsCatalogEntry
	other   otherCatalogEntry
}

type fixedCatalogEntry struct {
	FatherDataPageID uint32
	Type             uint16
	Identifier       uint32
}

type columnsCatalogEntry struct {
	ColumnType  uint32
	SpaceUsage  uint32
	ColumnFlags uint32
	CodePage    uint32
}

type otherCatalogEntry struct {
	FatherDataPageNumber uint32
}

// column holds column metadata for a table.
type column struct {
	name       string
	identifier uint32
	colType    uint32
	spaceUsage uint32
	codePage   uint32
}

// table represents an ESE table with its columns.
type table struct {
	leafEntry leafEntry
	columns   []column
}

// Cursor is used to iterate over records in a table.
type Cursor struct {
	db                   *DB
	table                *table
	fatherDataPageNumber uint32
	currentPage          *page
	currentTag           int
}

// page represents a parsed ESE page with raw data.
type page struct {
	header   pageHeader
	data     []byte
	dbHeader dbHeader
}

// leafEntry holds parsed leaf entry data.
type leafEntry struct {
	commonPageKeySize uint16
	localPageKeySize  uint16
	localPageKey      []byte
	entryData         []byte
}

// branchEntry holds parsed branch entry data.
type branchEntry struct {
	commonPageKeySize uint16
	localPageKeySize  uint16
	localPageKey      []byte
	childPageNumber   uint32
}

// Record represents a single database record with typed column values.
type Record struct {
	values map[string]recordValue
}

type recordValue struct {
	data     []byte
	codePage uint32
	isString bool
}

// String returns the string value of a column, decoding from the appropriate code page.
func (r *Record) String(col string) string {
	v, ok := r.values[col]
	if !ok || len(v.data) == 0 {
		return ""
	}
	if !v.isString {
		return ""
	}
	s, err := decodeString(v.data, v.codePage)
	if err != nil {
		return ""
	}
	return s
}

// Bytes returns the raw bytes of a column.
func (r *Record) Bytes(col string) []byte {
	v, ok := r.values[col]
	if !ok {
		return nil
	}
	return v.data
}

// Int32 returns a column value as int32.
func (r *Record) Int32(col string) (int32, bool) {
	v, ok := r.values[col]
	if !ok || len(v.data) < 4 {
		return 0, false
	}
	return int32(binary.LittleEndian.Uint32(v.data)), true
}

// Uint32 returns a column value as uint32.
func (r *Record) Uint32(col string) (uint32, bool) {
	v, ok := r.values[col]
	if !ok || len(v.data) < 4 {
		return 0, false
	}
	return binary.LittleEndian.Uint32(v.data), true
}

// HasColumn returns true if the column exists and has data.
func (r *Record) HasColumn(col string) bool {
	v, ok := r.values[col]
	return ok && len(v.data) > 0
}

var utf16Decoder = unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder()

func decodeString(data []byte, codePage uint32) (string, error) {
	switch codePage {
	case 20127: // ASCII
		return string(data), nil
	case 1200: // UTF-16LE
		b, err := utf16Decoder.Bytes(data)
		if err != nil {
			return "", err
		}
		return string(b), nil
	case 1252: // Windows-1252
		b, err := charmap.Windows1252.NewDecoder().Bytes(data)
		if err != nil {
			return "", err
		}
		return string(b), nil
	default:
		return "", fmt.Errorf("unsupported code page: %d", codePage)
	}
}
