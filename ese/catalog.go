package ese

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// parseCatalogEntry parses an esent_catalog_data_definition_entry from raw data.
func parseCatalogEntry(data []byte) (catalogEntry, error) {
	if len(data) < 10 {
		return catalogEntry{}, fmt.Errorf("catalog entry data too short: %d bytes", len(data))
	}

	ce := catalogEntry{}
	cursor := 0

	// Fixed portion (10 bytes).
	ce.fixed.FatherDataPageID = binary.LittleEndian.Uint32(data[cursor : cursor+4])
	cursor += 4
	ce.fixed.Type = binary.LittleEndian.Uint16(data[cursor : cursor+2])
	cursor += 2
	ce.fixed.Identifier = binary.LittleEndian.Uint32(data[cursor : cursor+4])
	cursor += 4

	switch ce.fixed.Type {
	case catalogTypeColumn:
		if cursor+16 > len(data) {
			return ce, fmt.Errorf("catalog column data too short")
		}
		buf := bytes.NewBuffer(data[cursor : cursor+16])
		if err := binary.Read(buf, binary.LittleEndian, &ce.columns); err != nil {
			return ce, fmt.Errorf("parse catalog columns: %w", err)
		}
	case catalogTypeTable, catalogTypeIndex, catalogTypeLongVal:
		if cursor+4 > len(data) {
			return ce, fmt.Errorf("catalog other data too short")
		}
		ce.other.FatherDataPageNumber = binary.LittleEndian.Uint32(data[cursor : cursor+4])
	case catalogTypeCallback:
		return ce, fmt.Errorf("unexpected catalog type: callback")
	default:
		return ce, fmt.Errorf("unknown catalog type: %d", ce.fixed.Type)
	}

	return ce, nil
}

// parseItemName extracts the item name from a leaf entry's data definition.
func parseItemName(entryData []byte) (string, error) {
	if len(entryData) < 4 {
		return "", fmt.Errorf("entry data too short for data definition header")
	}

	ddh := dataDefinitionHeader{
		LastFixedSize:        entryData[0],
		LastVariableDataType: entryData[1],
		VariableSizeOffset:   binary.LittleEndian.Uint16(entryData[2:4]),
	}

	var entries uint8
	if ddh.LastVariableDataType > 127 {
		entries = ddh.LastVariableDataType - 127
	} else {
		entries = ddh.LastVariableDataType
	}

	vsOff := int(ddh.VariableSizeOffset)
	if vsOff+2 > len(entryData) {
		return "", fmt.Errorf("variable size offset out of bounds")
	}

	nameLen := int(binary.LittleEndian.Uint16(entryData[vsOff : vsOff+2]))
	nameStart := vsOff + int(entries)*2
	if nameStart+nameLen > len(entryData) {
		return "", fmt.Errorf("item name out of bounds")
	}

	return string(entryData[nameStart : nameStart+nameLen]), nil
}

// parseCatalogPages recursively parses catalog pages to build table metadata.
func (db *DB) parseCatalogPages(pageNum uint32) error {
	p, err := db.readPage(pageNum)
	if err != nil {
		return fmt.Errorf("read catalog page %d: %w", pageNum, err)
	}

	// Process leaf entries on this page.
	if err := db.processLeafPage(p); err != nil {
		return err
	}

	// Recurse into branch entries.
	if p.header.PageFlags&flagLeaf == 0 {
		for i := 1; i < int(p.header.FirstAvailablePageTag); i++ {
			flags, data, err := p.getTag(i)
			if err != nil {
				return err
			}
			be, err := parseBranchEntry(flags, data)
			if err != nil {
				return err
			}
			if err := db.parseCatalogPages(be.childPageNumber); err != nil {
				return err
			}
		}
	}

	return nil
}

// processLeafPage extracts table and column metadata from a leaf page.
func (db *DB) processLeafPage(p *page) error {
	if p.header.PageFlags&flagLeaf == 0 {
		return nil // Not a leaf page.
	}
	if p.header.PageFlags&(flagSpaceTree|flagIndex|flagLongValue) != 0 {
		return nil // Not a data page.
	}

	for tagNum := 1; tagNum < int(p.header.FirstAvailablePageTag); tagNum++ {
		flags, data, err := p.getTag(tagNum)
		if err != nil {
			return err
		}
		leaf, err := parseLeafEntry(flags, data)
		if err != nil {
			return err
		}

		if err := db.addCatalogLeaf(leaf); err != nil {
			// Non-fatal: skip entries we can't parse.
			continue
		}
	}

	return nil
}

// addCatalogLeaf processes a leaf entry from the catalog.
func (db *DB) addCatalogLeaf(leaf leafEntry) error {
	if len(leaf.entryData) < 4 {
		return fmt.Errorf("leaf entry data too short")
	}

	ce, err := parseCatalogEntry(leaf.entryData[4:])
	if err != nil {
		return err
	}

	name, err := parseItemName(leaf.entryData)
	if err != nil {
		return err
	}

	switch ce.fixed.Type {
	case catalogTypeTable:
		t := &table{
			leafEntry: leaf,
		}
		db.tables[name] = t
		db.currentTable = name
	case catalogTypeColumn:
		if db.currentTable == "" {
			return nil
		}
		t := db.tables[db.currentTable]
		if t == nil {
			return nil
		}
		col := column{
			name:       name,
			identifier: ce.fixed.Identifier,
			colType:    ce.columns.ColumnType,
			spaceUsage: ce.columns.SpaceUsage,
			codePage:   ce.columns.CodePage,
		}
		t.columns = append(t.columns, col)
	case catalogTypeIndex, catalogTypeLongVal:
		// Ignored — not needed for record reading.
	}

	return nil
}
