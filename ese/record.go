package ese

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// tagItem stores offset/length info for tagged items in a record.
type tagItem struct {
	taggedOffset uint16
	tagLen       uint16
	flags        uint16
}

// tagToRecord converts raw tag data into a Record using the cursor's column metadata.
func tagToRecord(c *Cursor, tag []byte) (*Record, error) {
	if len(tag) < 4 {
		return nil, fmt.Errorf("tag data too short: %d bytes", len(tag))
	}

	rec := &Record{values: make(map[string]recordValue, len(c.table.columns))}

	ddh := dataDefinitionHeader{
		LastFixedSize:        tag[0],
		LastVariableDataType: tag[1],
		VariableSizeOffset:   binary.LittleEndian.Uint16(tag[2:4]),
	}

	vDataBytesProcessed := uint16(0)
	if ddh.LastVariableDataType > 127 {
		vDataBytesProcessed = uint16(ddh.LastVariableDataType-127) * 2
	}
	prevItemLen := uint16(0)
	fixedOffset := uint32(4) // sizeof dataDefinitionHeader
	vsOffset := ddh.VariableSizeOffset

	var taggedItems []tagItem
	var taggedIdents []uint16
	taggedParsed := false

	for i := range c.table.columns {
		col := &c.table.columns[i]
		ident := col.identifier

		if ident <= uint32(ddh.LastFixedSize) {
			// Fixed-size column.
			start := fixedOffset
			end := start + col.spaceUsage
			if int(end) > len(tag) {
				fixedOffset = end
				continue
			}
			data := make([]byte, col.spaceUsage)
			copy(data, tag[start:end])
			rv := recordValue{data: data}
			applyColumnType(&rv, col)
			rec.values[col.name] = rv
			fixedOffset = end

		} else if ident > 127 && ident <= uint32(ddh.LastVariableDataType) {
			// Variable-size column.
			idx := ident - 127 - 1
			itemLenOff := int(vsOffset) + int(idx)*2
			if itemLenOff+2 > len(tag) {
				continue
			}
			itemLen := binary.LittleEndian.Uint16(tag[itemLenOff : itemLenOff+2])
			if itemLen&0x8000 != 0 {
				// Empty item.
				itemLen = prevItemLen
			} else {
				dataStart := int(vsOffset) + int(vDataBytesProcessed)
				dataLen := int(itemLen - prevItemLen)
				if dataStart+dataLen > len(tag) || dataLen < 0 {
					continue
				}
				data := make([]byte, dataLen)
				copy(data, tag[dataStart:dataStart+dataLen])
				rv := recordValue{data: data}
				applyColumnType(&rv, col)
				rec.values[col.name] = rv
				vDataBytesProcessed += uint16(dataLen)
				prevItemLen = itemLen
			}

		} else if ident > 255 {
			// Tagged column.
			if !taggedParsed {
				taggedStart := int(vDataBytesProcessed) + int(vsOffset)
				if taggedStart < len(tag) {
					taggedItems, taggedIdents = parseTaggedItems(tag, taggedStart, c.db.header)
					taggedParsed = true
				}
			}

			ti := findTaggedItem(taggedItems, taggedIdents, uint16(ident))
			if ti == nil {
				continue
			}

			baseOffset := int(vDataBytesProcessed) + int(vsOffset)
			offsetItem := baseOffset + int(ti.taggedOffset)
			itemSize := int(ti.tagLen)

			if offsetItem >= len(tag) {
				continue
			}

			itemFlag := int16(0)
			if ti.flags > 0 {
				if offsetItem < len(tag) {
					itemFlag = int16(tag[offsetItem])
				}
				offsetItem++
				itemSize--
			}

			if itemFlag&taggedDataCompressed != 0 {
				continue
			}

			if offsetItem+itemSize > len(tag) {
				itemSize = len(tag) - offsetItem
			}
			if itemSize <= 0 {
				continue
			}

			var data []byte
			if itemFlag&taggedDataMultiValue != 0 {
				// Multi-value: store as hex-encoded bytes.
				raw := tag[offsetItem : offsetItem+itemSize]
				hexData := make([]byte, len(raw)*2)
				hex.Encode(hexData, raw)
				data = hexData
			} else {
				data = make([]byte, itemSize)
				copy(data, tag[offsetItem:offsetItem+itemSize])
			}

			rv := recordValue{data: data}
			applyColumnType(&rv, col)
			rec.values[col.name] = rv
		}
	}

	return rec, nil
}

// parseTaggedItems parses tagged items from the tag data starting at index.
func parseTaggedItems(tag []byte, index int, dbHdr dbHeader) ([]tagItem, []uint16) {
	var items []tagItem
	var idents []uint16

	if index+4 > len(tag) {
		return items, idents
	}

	firstOffsetTag := int(binary.LittleEndian.Uint16(tag[index+2:index+4])&0x3fff) + index

	for {
		if index+4 > len(tag) {
			break
		}

		taggedIdent := binary.LittleEndian.Uint16(tag[index : index+2])
		index += 2
		taggedOffset := binary.LittleEndian.Uint16(tag[index:index+2]) & 0x3fff

		var flagsPresent uint16
		if dbHdr.Version == 0x620 && dbHdr.FileFormatRevision >= 17 && dbHdr.PageSize > 8192 {
			flagsPresent = 1
		} else {
			flagsPresent = binary.LittleEndian.Uint16(tag[index:index+2]) & 0x4000
		}
		index += 2

		ti := tagItem{
			taggedOffset: taggedOffset,
			tagLen:       uint16(len(tag)), // Will be adjusted below.
			flags:        flagsPresent,
		}

		items = append(items, ti)
		idents = append(idents, taggedIdent)

		// Adjust previous item's length.
		if n := len(items); n > 1 {
			items[n-2].tagLen = items[n-1].taggedOffset - items[n-2].taggedOffset
		}

		if index >= firstOffsetTag {
			break
		}
	}

	return items, idents
}

func findTaggedItem(items []tagItem, idents []uint16, ident uint16) *tagItem {
	for i, id := range idents {
		if id == ident {
			return &items[i]
		}
	}
	return nil
}

func applyColumnType(rv *recordValue, col *column) {
	if col.colType == coltypText || col.colType == coltypLongText {
		rv.isString = true
		rv.codePage = col.codePage
	}
}
