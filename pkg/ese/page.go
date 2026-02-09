package ese

import (
	"encoding/binary"
	"fmt"
)

// parsePageHeader reads the page header from raw page data.
func parsePageHeader(data []byte, dbHdr dbHeader) (pageHeader, error) {
	if len(data) < 40 {
		return pageHeader{}, fmt.Errorf("page data too short: %d bytes", len(data))
	}

	h := pageHeader{headerLen: 40}
	cursor := 0

	if dbHdr.Version < 0x620 || (dbHdr.Version == 0x620 && dbHdr.FileFormatRevision < 0x0b) {
		// Windows XP / Server 2003 SP0
		h.CheckSum = uint64(binary.LittleEndian.Uint32(data[cursor : cursor+4]))
		cursor += 4
		h.PageNumber = uint64(binary.LittleEndian.Uint32(data[cursor : cursor+4]))
		cursor += 4
	} else if dbHdr.Version == 0x620 && dbHdr.FileFormatRevision < 0x11 {
		// Server 2003 SP1+
		h.CheckSum = uint64(binary.LittleEndian.Uint32(data[cursor : cursor+4]))
		cursor += 4
		h.ECCCheckSum = binary.LittleEndian.Uint32(data[cursor : cursor+4])
		cursor += 4
	} else {
		// Windows 7+
		h.CheckSum = binary.LittleEndian.Uint64(data[cursor : cursor+8])
		cursor += 8
	}

	h.LastModificationTime = binary.LittleEndian.Uint64(data[cursor : cursor+8])
	cursor += 8
	h.PreviousPageNumber = binary.LittleEndian.Uint32(data[cursor : cursor+4])
	cursor += 4
	h.NextPageNumber = binary.LittleEndian.Uint32(data[cursor : cursor+4])
	cursor += 4
	h.FatherDataPage = binary.LittleEndian.Uint32(data[cursor : cursor+4])
	cursor += 4
	h.AvailableDataSize = binary.LittleEndian.Uint16(data[cursor : cursor+2])
	cursor += 2
	h.AvailableUncommittedDataSize = binary.LittleEndian.Uint16(data[cursor : cursor+2])
	cursor += 2
	h.FirstAvailableDataOffset = binary.LittleEndian.Uint16(data[cursor : cursor+2])
	cursor += 2
	h.FirstAvailablePageTag = binary.LittleEndian.Uint16(data[cursor : cursor+2])
	cursor += 2
	h.PageFlags = binary.LittleEndian.Uint32(data[cursor : cursor+4])

	if dbHdr.PageSize > 8192 {
		// Extended page header for large pages.
		h.headerLen = 80
	}

	return h, nil
}

// getTag retrieves the tag at position i from the page.
// Tags are stored at the end of the page, 4 bytes each, growing backwards.
func (p *page) getTag(i int) (flags uint16, tagData []byte, err error) {
	if int(p.header.FirstAvailablePageTag) < i {
		return 0, nil, fmt.Errorf("tag index %d exceeds available tags %d", i, p.header.FirstAvailablePageTag)
	}

	startIndex := len(p.data) - 4*(i+1)
	if startIndex < 0 || startIndex+4 > len(p.data) {
		return 0, nil, fmt.Errorf("tag index %d out of bounds", i)
	}
	tag := p.data[startIndex : startIndex+4]

	valSize := binary.LittleEndian.Uint16(tag[:2]) & 0x1fff
	flags = (binary.LittleEndian.Uint16(tag[2:]) & 0xe000) >> 13
	valueOffset := binary.LittleEndian.Uint16(tag[2:]) & 0x1fff

	start := int(p.header.headerLen) + int(valueOffset)
	end := start + int(valSize)
	if start > len(p.data) || end > len(p.data) {
		return 0, nil, fmt.Errorf("tag data out of bounds: [%d:%d] in page of size %d", start, end, len(p.data))
	}

	tagData = p.data[start:end]
	return flags, tagData, nil
}

// parseBranchEntry parses a branch entry from tag data.
func parseBranchEntry(flags uint16, data []byte) (branchEntry, error) {
	b := branchEntry{}
	cursor := 0

	if flags&tagCommon > 0 {
		if len(data) < 2 {
			return b, fmt.Errorf("branch data too short for common key")
		}
		b.commonPageKeySize = binary.LittleEndian.Uint16(data[:2])
		cursor += 2
	}

	if cursor+2 > len(data) {
		return b, fmt.Errorf("branch data too short for key size")
	}
	b.localPageKeySize = binary.LittleEndian.Uint16(data[cursor : cursor+2])
	cursor += 2

	end := cursor + int(b.localPageKeySize)
	if end > len(data) {
		return b, fmt.Errorf("branch key exceeds data")
	}
	b.localPageKey = data[cursor:end]
	cursor = end

	if cursor+4 > len(data) {
		return b, fmt.Errorf("branch data too short for child page number")
	}
	b.childPageNumber = binary.LittleEndian.Uint32(data[cursor:])
	return b, nil
}

// parseLeafEntry parses a leaf entry from tag data.
func parseLeafEntry(flags uint16, data []byte) (leafEntry, error) {
	l := leafEntry{}
	cursor := 0

	if flags&tagCommon > 0 {
		if len(data) < 2 {
			return l, fmt.Errorf("leaf data too short for common key")
		}
		l.commonPageKeySize = binary.LittleEndian.Uint16(data[:2])
		cursor += 2
	}

	if cursor+2 > len(data) {
		return l, fmt.Errorf("leaf data too short for key size")
	}
	l.localPageKeySize = binary.LittleEndian.Uint16(data[cursor : cursor+2])
	cursor += 2

	end := cursor + int(l.localPageKeySize)
	if end > len(data) {
		return l, fmt.Errorf("leaf key exceeds data")
	}
	l.localPageKey = data[cursor:end]
	cursor = end

	l.entryData = data[cursor:]
	return l, nil
}
