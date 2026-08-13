package pe

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// putResourceDir writes a resource directory header declaring a single ID entry, followed by that
// entry pointing at offsetToData. isDir sets the high bit, which marks the target as a subdirectory.
func putResourceDir(buf []byte, at int, offsetToData uint32, isDir bool) {
	le := binary.LittleEndian
	le.PutUint16(buf[at+12:], 0) // NumberOfNamedEntries
	le.PutUint16(buf[at+14:], 1) // NumberOfIDEntries

	entry := at + 16
	le.PutUint32(buf[entry:], 1) // Name (ID, not a string)
	if isDir {
		offsetToData |= 0x80000000
	}
	le.PutUint32(buf[entry+4:], offsetToData)
}

const (
	testSectionRVA  = 0x1000
	testSectionSize = 0x400
)

func testResourceSection(data []byte) *extractedSection {
	return &extractedSection{
		RVA:    testSectionRVA,
		Size:   testSectionSize,
		Reader: bytes.NewReader(data),
	}
}

func TestParseResourceDirectory_DataEntryPastSectionIsRejected(t *testing.T) {
	// OffsetToData and Size are user-controlled uint32s. A data entry may only describe bytes its
	// section actually holds, otherwise the size drives the allocation in parseResourceDataEntry.
	buf := make([]byte, testSectionSize)
	putResourceDir(buf, 0x000, 0x100, false) // root -> data entry at 0x100

	le := binary.LittleEndian
	le.PutUint32(buf[0x100:], testSectionRVA) // OffsetToData, resolves to section offset 0
	le.PutUint32(buf[0x104:], 256*1024*1024)  // a size far past the 1KB section

	err := parseResourceDataEntry(bytes.NewReader(buf), testSectionRVA, testSectionRVA+0x100, testSectionSize, map[string]string{})
	require.ErrorContains(t, err, "extends past its section size")
}

func TestParseResourceDataEntry_OffsetBeforeSectionBaseIsRejected(t *testing.T) {
	// OffsetToData is independent of baseRVA, so it can name an RVA before the section starts. The
	// subtraction that turns it into a section offset would otherwise underflow to near 4GB.
	buf := make([]byte, testSectionSize)
	le := binary.LittleEndian
	le.PutUint32(buf[0x100:], testSectionRVA-1) // OffsetToData, one byte before the section base
	le.PutUint32(buf[0x104:], 16)

	err := parseResourceDataEntry(bytes.NewReader(buf), testSectionRVA, testSectionRVA+0x100, testSectionSize, map[string]string{})
	require.ErrorContains(t, err, "precedes its section base")
}

func TestParseResourceDirectory_WalkIsBudgeted(t *testing.T) {
	// every individual offset here is inside the section, so nothing but the budget stops the walk
	buf := make([]byte, testSectionSize)
	const step = 0x40
	for at := 0; at+step < testSectionSize; at += step {
		putResourceDir(buf, at, uint32(at+step), true)
	}

	w := newResourceWalk()
	w.budget = 3

	_ = parseResourceDirectory(testResourceSection(buf), w)

	assert.Zero(t, w.budget, "the walk must stop once the entry budget is spent, not run the tree to completion")
}
