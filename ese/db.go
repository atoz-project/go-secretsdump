package ese

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
)

// DB represents an open ESE database, reading pages on demand from an io.ReadSeeker.
type DB struct {
	r            io.ReadSeeker
	header       dbHeader
	pageSize     uint32
	headerSize   int64 // Size of the file header (1 page).
	tables       map[string]*table
	currentTable string
}

// Open opens an ESE database from r.
// Pages are read on demand; the entire file is NOT loaded into memory.
func Open(r io.ReadSeeker) (*DB, error) {
	db := &DB{
		r:        r,
		pageSize: defaultPageSize,
		tables:   make(map[string]*table),
	}

	// Read the first page as the database header.
	hdrBuf := make([]byte, defaultPageSize)
	if _, err := io.ReadFull(r, hdrBuf); err != nil {
		return nil, fmt.Errorf("read db header: %w", err)
	}

	buf := bytes.NewBuffer(hdrBuf)
	if err := binary.Read(buf, binary.LittleEndian, &db.header); err != nil {
		return nil, fmt.Errorf("parse db header: %w", err)
	}

	db.pageSize = db.header.PageSize
	if db.pageSize == 0 {
		db.pageSize = defaultPageSize
	}
	db.headerSize = int64(db.pageSize)

	// Parse the catalog to discover tables and columns.
	if err := db.parseCatalogPages(catalogPageNumber); err != nil {
		return nil, fmt.Errorf("parse catalog: %w", err)
	}

	return db, nil
}

// OpenTable opens a named table and returns a Cursor for iteration.
func (db *DB) OpenTable(name string) (*Cursor, error) {
	t, ok := db.tables[name]
	if !ok {
		return nil, fmt.Errorf("table %q not found", name)
	}

	// Parse the table's leaf entry to find the father data page.
	if len(t.leafEntry.entryData) < 4 {
		return nil, fmt.Errorf("table %q has no entry data", name)
	}

	ce, err := parseCatalogEntry(t.leafEntry.entryData[4:])
	if err != nil {
		return nil, fmt.Errorf("parse table catalog entry: %w", err)
	}

	pageNum := ce.other.FatherDataPageNumber

	// Walk down to the first leaf page.
	p, err := db.descendToLeaf(pageNum)
	if err != nil {
		return nil, err
	}

	return &Cursor{
		db:                   db,
		table:                t,
		fatherDataPageNumber: ce.other.FatherDataPageNumber,
		currentPage:          p,
		currentTag:           0,
	}, nil
}

// descendToLeaf reads pages starting from pageNum, following branch entries
// until a leaf page is found.
func (db *DB) descendToLeaf(pageNum uint32) (*page, error) {
	for {
		p, err := db.readPage(pageNum)
		if err != nil {
			return nil, fmt.Errorf("read page %d: %w", pageNum, err)
		}
		if p.header.FirstAvailablePageTag <= 1 || p.header.PageFlags&flagLeaf != 0 {
			return p, nil
		}

		childPage, ok := firstBranchChild(p)
		if !ok {
			return p, nil
		}
		pageNum = childPage
	}
}

// firstBranchChild returns the child page number from the first valid branch
// entry on the page, or false if none is found.
func firstBranchChild(p *page) (uint32, bool) {
	for i := 1; i < int(p.header.FirstAvailablePageTag); i++ {
		flags, data, err := p.getTag(i)
		if err != nil {
			continue
		}
		be, err := parseBranchEntry(flags, data)
		if err != nil {
			continue
		}
		return be.childPageNumber, true
	}
	return 0, false
}

// readPage reads a single page by its logical page number.
// Page 0 is the first page after the header.
func (db *DB) readPage(pageNum uint32) (*page, error) {
	// Pages are 1-indexed in the file (page 0 is conceptually after header).
	// Offset = headerSize + pageNum * pageSize
	offset := db.headerSize + int64(pageNum)*int64(db.pageSize)
	if _, err := db.r.Seek(offset, io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek page %d at offset %d: %w", pageNum, offset, err)
	}

	data := make([]byte, db.pageSize)
	if _, err := io.ReadFull(db.r, data); err != nil {
		return nil, fmt.Errorf("read page %d: %w", pageNum, err)
	}

	hdr, err := parsePageHeader(data, db.header)
	if err != nil {
		return nil, fmt.Errorf("parse page %d header: %w", pageNum, err)
	}

	return &page{
		header:   hdr,
		data:     data,
		dbHeader: db.header,
	}, nil
}

// Next returns the next record from the cursor.
// Returns io.EOF when no more records are available.
func (c *Cursor) Next(ctx context.Context) (*Record, error) {
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		c.currentTag++
		p := c.currentPage

		// Check if we need to advance to the next page.
		if p == nil || c.currentTag >= int(p.header.FirstAvailablePageTag) || !isDataLeaf(p) {
			if p == nil || p.header.NextPageNumber == 0 {
				return nil, io.EOF
			}
			var err error
			c.currentPage, err = c.db.readPage(p.header.NextPageNumber)
			if err != nil {
				return nil, fmt.Errorf("read next page: %w", err)
			}
			c.currentTag = 0
			continue
		}

		flags, data, err := p.getTag(c.currentTag)
		if err != nil {
			return nil, fmt.Errorf("get tag %d: %w", c.currentTag, err)
		}

		leaf, err := parseLeafEntry(flags, data)
		if err != nil {
			return nil, fmt.Errorf("parse leaf entry: %w", err)
		}

		rec, err := tagToRecord(c, leaf.entryData)
		if err != nil {
			return nil, fmt.Errorf("tag to record: %w", err)
		}

		return rec, nil
	}
}

// isDataLeaf returns true if the page is a data leaf (not space tree, index, or long value).
func isDataLeaf(p *page) bool {
	if p.header.PageFlags&flagLeaf == 0 {
		return false
	}
	return p.header.PageFlags&(flagSpaceTree|flagIndex|flagLongValue) == 0
}
