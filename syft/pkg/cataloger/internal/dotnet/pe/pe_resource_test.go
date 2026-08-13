package pe

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

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

// buildVersionResource returns a well-formed VS_VERSION_INFO blob whose last child is a VarFileInfo
// block, which is the layout real toolchains emit. It ends exactly on a struct boundary. When
// withFileVersionString is set, a StringFileInfo table supplies FileVersion directly.
func buildVersionResource(withFileVersionString bool) []byte {
	buf := new(bytes.Buffer)
	le := binary.LittleEndian

	putHeader := func(length, valueLength, typ uint16) {
		_ = binary.Write(buf, le, [3]uint16{length, valueLength, typ})
	}
	putUTF16 := func(s string) {
		for _, r := range s {
			_ = binary.Write(buf, le, uint16(r))
		}
		_ = binary.Write(buf, le, uint16(0))
	}
	pad := func() {
		for buf.Len()%4 != 0 {
			buf.WriteByte(0)
		}
	}

	putHeader(0, 52, 0)
	putUTF16("VS_VERSION_INFO")
	pad()

	// peVsFixedFileInfo, with FileVersionMS/LS encoding 1.2.3.4
	ffi := make([]byte, 52)
	le.PutUint32(ffi[0:], 0xFEEF04BD)  // signature
	le.PutUint32(ffi[4:], 0x00010000)  // strucVersion
	le.PutUint32(ffi[8:], 0x00010002)  // FileVersionMS -> 1.2
	le.PutUint32(ffi[12:], 0x00030004) // FileVersionLS -> 3.4
	buf.Write(ffi)

	if withFileVersionString {
		pad()
		putHeader(0, 0, 1)
		putUTF16("StringFileInfo")
		pad()
		putHeader(38, 0, 1)
		putUTF16("040904b0")
		pad()
		putHeader(0, 8, 1)
		putUTF16("FileVersion")
		pad()
		putUTF16("9.9.9.9")
	}

	// the final child: VarFileInfo -> Var("Translation") with a 4 byte value
	pad()
	putHeader(0, 0, 1)
	putUTF16("VarFileInfo")
	pad()
	putHeader(0, 4, 0)
	putUTF16("Translation")
	pad()
	_ = binary.Write(buf, le, uint32(0x04b00409))

	return buf.Bytes()
}

func TestParseVersionResourceSection_FileVersionFallback(t *testing.T) {
	// a resource ending on a struct boundary is normal termination, not a parse failure. Treating it as
	// an error skips the VS_FIXEDFILEINFO fallback below, which is the only source of a version for
	// binaries that carry no FileVersion string entry.
	tests := []struct {
		name                  string
		withFileVersionString bool
		want                  string
	}{
		{
			name: "derived from fixed file info when no string entry exists",
			want: "1.2.3.4",
		},
		{
			name:                  "string entry wins when present",
			withFileVersionString: true,
			want:                  "9.9.9.9",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fields := map[string]string{}
			require.NoError(t, parseVersionResourceSection(bytes.NewReader(buildVersionResource(tt.withFileVersionString)), fields))
			assert.Equal(t, tt.want, fields["FileVersion"])
		})
	}
}

// buildTruncatedStringTable returns version resource bytes that end exactly on a struct boundary while
// the string table header still claims 0xFFFF bytes remain. Landing precisely at EOF is the case that
// matters: one to five trailing bytes yield io.ErrUnexpectedEOF, which was always handled.
func buildTruncatedStringTable() []byte {
	buf := new(bytes.Buffer)
	putHeader := func() {
		_ = binary.Write(buf, binary.LittleEndian, [3]uint16{}) // Length, ValueLength, Type
	}
	putUTF16 := func(s string) {
		for _, r := range s {
			_ = binary.Write(buf, binary.LittleEndian, uint16(r))
		}
		_ = binary.Write(buf, binary.LittleEndian, uint16(0)) // null terminator
	}

	putHeader()
	putUTF16("VS_VERSION_INFO") // offset 38
	buf.Write([]byte{0, 0})     // pad to the DWORD boundary at 40
	buf.Write(make([]byte, 52)) // peVsFixedFileInfo -> 92

	putHeader()
	putUTF16("StringFileInfo") // -> 128

	// the string table header claims far more content than the file carries
	_ = binary.Write(buf, binary.LittleEndian, [3]uint16{0xFFFF, 0, 0})
	putUTF16("040904b0") // -> 152, then EOF

	return buf.Bytes()
}

func TestParseVersionResourceSection_TruncatedStringTableTerminates(t *testing.T) {
	data := buildTruncatedStringTable()

	done := make(chan error, 1)
	go func() {
		done <- parseVersionResourceSection(bytes.NewReader(data), map[string]string{})
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		// a reader parked at EOF used to be reported as a successful read of a zeroed struct, so the
		// string table loop consumed nothing, advanced nothing, and never reached its length bound
		require.FailNow(t, "parseVersionResourceSection did not terminate",
			"a %d-byte resource blob must not spin forever", len(data))
	}
}
