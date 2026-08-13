package bundle

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// readSeekCloser adapts a *bytes.Reader to the unionreader.UnionReader interface (adds Close).
type readSeekCloser struct {
	*bytes.Reader
}

func (readSeekCloser) Close() error { return nil }

// buildELFWithHugeFilesz returns a minimal, parseable ELF64 whose single program header
// declares a p_filesz far past the real file. calculateELFEndOffset will compute a huge end
// offset; the bound in FindSignatureOffset must keep the allocation tied to the real file.
func buildELFWithHugeFilesz() []byte {
	return buildELFWithProgHeader(0, 1<<60)
}

// buildELFWithProgHeader returns a minimal, parseable ELF64 with a single PT_LOAD program header
// carrying the given p_offset and p_filesz. debug/elf does not validate either field.
func buildELFWithProgHeader(pOffset, pFilesz uint64) []byte {
	const (
		ehSize  = 64
		phSize  = 56
		phOff   = ehSize
		phCount = 1
	)
	buf := make([]byte, ehSize+phSize)

	// e_ident
	copy(buf[0:4], []byte{0x7f, 'E', 'L', 'F'})
	buf[4] = 2 // ELFCLASS64
	buf[5] = 1 // ELFDATA2LSB
	buf[6] = 1 // EV_CURRENT

	le := binary.LittleEndian
	le.PutUint16(buf[16:], 2)       // e_type = ET_EXEC
	le.PutUint16(buf[18:], 0x3e)    // e_machine = x86-64
	le.PutUint32(buf[20:], 1)       // e_version
	le.PutUint64(buf[32:], phOff)   // e_phoff
	le.PutUint16(buf[52:], ehSize)  // e_ehsize
	le.PutUint16(buf[54:], phSize)  // e_phentsize
	le.PutUint16(buf[56:], phCount) // e_phnum
	// e_shoff/e_shnum left zero so no sections are parsed

	ph := buf[phOff:]
	le.PutUint32(ph[0:], 1)        // p_type = PT_LOAD
	le.PutUint64(ph[8:], pOffset)  // p_offset (user-controlled)
	le.PutUint64(ph[32:], pFilesz) // p_filesz (user-controlled)
	le.PutUint64(ph[40:], pFilesz) // p_memsz
	return buf
}

func TestExtractDepsJSONFromELFBundle_EndOffsetOverflowDoesNotPanic(t *testing.T) {
	// calculateELFEndOffset sums these two uint64 header fields into an int64 and adds 4096, which
	// overflows to a negative search limit. A negative is not greater than the file size, so it slips
	// unnoticed into the search window unless a non-positive limit reads nothing.
	data := buildELFWithProgHeader(0x7FFFFFFFFFFFF000, 0)
	require.Negative(t, calculateELFEndOffset(mustParseELF(t, data)),
		"expected these header values to overflow the end offset; the guard below is what this test pins")

	r := readSeekCloser{bytes.NewReader(data)}

	content, err := ExtractDepsJSONFromELFBundle(r)
	require.NoError(t, err)
	assert.Empty(t, content)
}

func mustParseELF(t *testing.T, data []byte) *elf.File {
	t.Helper()
	f, err := elf.NewFile(bytes.NewReader(data))
	require.NoError(t, err)
	return f
}

func TestExtractDepsJSONFromELFBundle_MalformedFileszDoesNotOverAllocate(t *testing.T) {
	data := buildELFWithHugeFilesz()
	r := readSeekCloser{bytes.NewReader(data)}

	// must not over-allocate or panic on the oversized p_filesz, and find no bundle signature
	content, err := ExtractDepsJSONFromELFBundle(r)
	require.NoError(t, err)
	assert.Empty(t, content)
}
