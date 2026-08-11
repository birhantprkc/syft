package golang

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ulikunitz/xz/lzma"
)

// buildUPXLZMAStream encodes data into the compressed-block form decompressLZMA expects: UPX's custom
// 2-byte props header followed by the raw LZMA range-coded stream (the standard 13-byte .lzma header is
// stripped because decompressLZMA reconstructs its own). Uses the default lc=3/lp=0/pb=2 properties and a
// 64KB dictionary so the size math in decompressLZMA lines up for the small payloads used in tests.
func buildUPXLZMAStream(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := lzma.WriterConfig{
		Properties:   &lzma.Properties{LC: 3, LP: 0, PB: 2},
		DictCap:      1 << 16,
		SizeInHeader: true,
		Size:         int64(len(data)),
	}.NewWriter(&buf)
	require.NoError(t, err)
	_, err = w.Write(data)
	require.NoError(t, err)
	require.NoError(t, w.Close())

	raw := buf.Bytes()[13:] // strip standard 13-byte lzma header
	// UPX 2-byte header: byte 0 low 3 bits carry pb; byte 1 is (lp<<4)|lc
	return append([]byte{0x02, 0x03}, raw...)
}

// buildUPXHeader assembles the l_info + p_info prefix common to every crafted fixture below.
func buildUPXHeader(originalSize, blockSize uint32) []byte {
	lInfo := []byte{
		0, 0, 0, 0, // l_checksum
		'U', 'P', 'X', '!', // magic
		0, 0, // l_lsize
		14, 22, // l_version, l_format
	}
	pInfo := make([]byte, 12)
	binary.LittleEndian.PutUint32(pInfo[4:8], originalSize) // p_filesize
	binary.LittleEndian.PutUint32(pInfo[8:12], blockSize)   // p_blocksize
	return append(lInfo, pInfo...)
}

// buildUPXFile assembles a minimal but structurally valid UPX container: l_info + p_info followed by one
// b_info + compressed stream per payload, terminated by a zero end-marker block. declaredSizes, when
// non-nil, overrides each block's sz_unc so a fixture can lie about what its stream decompresses to.
func buildUPXFile(t *testing.T, originalSize, blockSize uint32, payloads [][]byte, declaredSizes []uint32) []byte {
	t.Helper()
	data := buildUPXHeader(originalSize, blockSize)
	for i, p := range payloads {
		stream := buildUPXLZMAStream(t, p)
		szUnc := uint32(len(p))
		if declaredSizes != nil {
			szUnc = declaredSizes[i]
		}
		b := make([]byte, 12)
		binary.LittleEndian.PutUint32(b[0:4], szUnc)               // sz_unc
		binary.LittleEndian.PutUint32(b[4:8], uint32(len(stream))) // sz_cpr
		b[8] = 14                                                  // b_method = LZMA
		data = append(data, b...)
		data = append(data, stream...)
	}
	return append(data, make([]byte, 12)...) // end marker: sz_unc == 0
}

func TestDecompressUPX_BlockExceedsDeclaredBlockSize(t *testing.T) {
	// a block claiming more than the packer's own p_blocksize is malformed. This is the value the
	// reporter's proof-of-concept drove to 0x80000000 to size an unbounded allocation.
	data := buildUPXFile(t, 4096, 256, [][]byte{bytes.Repeat([]byte("A"), 32)}, []uint32{512})

	_, err := decompressUPX(bytes.NewReader(data))
	require.Error(t, err)
	assert.ErrorIs(t, err, errUPXBlockTooLarge)
}

func TestDecompressUPX_MaxUint32BlockSizeRejected(t *testing.T) {
	// the reporter's exact shape: sz_unc spanning the full uint32 range.
	data := buildUPXFile(t, 4096, 4096, [][]byte{bytes.Repeat([]byte("A"), 32)}, []uint32{0xFFFFFFFF})

	_, err := decompressUPX(bytes.NewReader(data))
	require.Error(t, err)
	assert.ErrorIs(t, err, errUPXBlockTooLarge)
}

func TestDecompressUPX_CumulativeExceedsOriginalSize(t *testing.T) {
	// each block individually fits within p_blocksize, but together they claim more than the file's
	// declared original size. Without the running remainder every block may claim the full size and the
	// total decompression work becomes (block count x original size). The streams are real 2048-byte
	// payloads so the failure below is the budget and not a short decode.
	payload := bytes.Repeat([]byte("A"), 2048)
	data := buildUPXFile(t, 4096, 2048, [][]byte{payload, payload, payload}, nil) // 3 x 2048 > 4096

	_, err := decompressUPX(bytes.NewReader(data))
	require.Error(t, err)
	assert.ErrorIs(t, err, errUPXOutputExceeded)
}

func TestDecompressUPX_BudgetAllowsExactlyOriginalSize(t *testing.T) {
	// the bound must not reject a file whose blocks sum to exactly the declared original size, which is
	// what a well-formed UPX binary does.
	payload := bytes.Repeat([]byte("A"), 2048)
	data := buildUPXFile(t, 4096, 2048, [][]byte{payload, payload}, nil)

	_, err := decompressUPX(bytes.NewReader(data))
	require.NoError(t, err)
}

// buildELF64 assembles a minimal ELF64 header followed by the given program-header bytes.
func buildELF64(phoff uint64, phentsize, phnum uint16, phdrs []byte) []byte {
	hdr := make([]byte, 64)
	copy(hdr, []byte{0x7f, 'E', 'L', 'F'})
	hdr[4] = 2 // ELFCLASS64
	binary.LittleEndian.PutUint64(hdr[0x20:0x28], phoff)
	binary.LittleEndian.PutUint16(hdr[0x36:0x38], phentsize)
	binary.LittleEndian.PutUint16(hdr[0x38:0x3a], phnum)
	return append(hdr, phdrs...)
}

func TestParseELFPTLoadOffsets_ShortPhentsizeNoPanic(t *testing.T) {
	// a program-header entry smaller than an ELF64 phdr would let the fixed-offset p_offset read run past
	// the entry; the parser must reject it rather than index out of range.
	phdr := []byte{1, 0, 0, 0, 0, 0, 0, 0} // ptype = PT_LOAD, only 8 bytes
	elf := buildELF64(64, 8, 1, phdr)

	require.NotPanics(t, func() {
		assert.Empty(t, parseELFPTLoadOffsets(elf))
	})
}

func TestParseELFPTLoadOffsets_OverflowPhoffNoPanic(t *testing.T) {
	// a phoff near the top of the uint64 range must not overflow the bounds check into a huge slice index.
	phdr := make([]byte, 56)
	binary.LittleEndian.PutUint32(phdr[0:4], 1) // PT_LOAD
	elf := buildELF64(0xFFFFFFFFFFFFFFF0, 56, 1, phdr)

	require.NotPanics(t, func() {
		assert.Empty(t, parseELFPTLoadOffsets(elf))
	})
}

// buildPoisonELF returns an ELF whose second PT_LOAD segment declares p_offset at the top of the uint64
// range, along with the payload set that drives block 3 to that offset.
func buildPoisonELF(t *testing.T) []byte {
	t.Helper()
	phdrs := make([]byte, 112) // two ELF64 program headers
	binary.LittleEndian.PutUint32(phdrs[0:4], 1)                    // phdr[0] PT_LOAD
	binary.LittleEndian.PutUint64(phdrs[8:16], 0)                   // p_offset 0
	binary.LittleEndian.PutUint32(phdrs[56:60], 1)                  // phdr[1] PT_LOAD
	binary.LittleEndian.PutUint64(phdrs[64:72], 0xFFFFFFFFFFFFFFFF) // p_offset at the uint64 ceiling
	elf := buildELF64(64, 56, 2, phdrs)

	// sanity: the crafted offset really is parsed out, so the tests below exercise the placement guard
	require.Equal(t, []uint64{0, 0xFFFFFFFFFFFFFFFF}, parseELFPTLoadOffsets(elf))
	return elf
}

func TestDecompressUPX_OutOfRangePlacementRejected(t *testing.T) {
	// block 3 is directed at a p_offset past the end of the output buffer. That means the file does not
	// describe the layout it claims, so decompression must fail rather than silently drop the block.
	elf := buildPoisonELF(t)
	payloads := [][]byte{elf, bytes.Repeat([]byte("B"), 32), bytes.Repeat([]byte("C"), 32)}
	data := buildUPXFile(t, 8192, 8192, payloads, nil)

	_, err := decompressUPX(bytes.NewReader(data))
	require.Error(t, err)
	assert.ErrorIs(t, err, errUPXBlockOutOfRange)
}

func TestDecompressUPX_OutOfRangePlacementDoesNotPoisonLaterBlocks(t *testing.T) {
	// regression: the placement guard used to skip the copy and fall through, but outputOffset is derived
	// from the rejected destOffset. With p_offset at the uint64 ceiling and a 1-byte block 3, outputOffset
	// wrapped to 0, and block 4 was then copied over the reconstructed ELF header at offset 0.
	elf := buildPoisonELF(t)
	attacker := bytes.Repeat([]byte{0xDE, 0xAD, 0xBE, 0xEF}, 8)
	payloads := [][]byte{elf, bytes.Repeat([]byte("B"), 32), {0x41}, attacker}
	data := buildUPXFile(t, 8192, 8192, payloads, nil)

	out, err := decompressUPX(bytes.NewReader(data))
	require.Error(t, err, "must not report success on a file whose layout was rejected")
	assert.ErrorIs(t, err, errUPXBlockOutOfRange)
	require.Nil(t, out)
}

func TestNextPowerOf2(t *testing.T) {
	cases := []struct{ in, want uint32 }{
		{0, 1},
		{1, 1},
		{3, 4},
		{1 << 20, 1 << 20},
		{(1 << 20) + 1, 1 << 21},
		{1 << 31, 1 << 31},
		{(1 << 31) + 1, 1 << 31}, // saturates rather than wrapping to 0
		{0xFFFFFFFF, 1 << 31},    // saturates rather than wrapping to 0
	}
	for _, c := range cases {
		assert.Equalf(t, c.want, nextPowerOf2(c.in), "nextPowerOf2(%d)", c.in)
	}
}

func TestDecompressLZMA_RoundTrip(t *testing.T) {
	// happy path: a stream built with valid LZMA parameters round-trips (and confirms the parameter
	// validation does not reject legitimate values).
	data := bytes.Repeat([]byte("hello UPX "), 16)
	got, err := decompressLZMA(buildUPXLZMAStream(t, data), uint32(len(data)))
	require.NoError(t, err)
	assert.Equal(t, data, got)
}

func TestDecompressLZMA_InvalidParams(t *testing.T) {
	// pb encoded as 7 is outside the LZMA-permitted range; it must be rejected rather than wrapped into a
	// bogus props byte via uint8 arithmetic.
	stream := []byte{0x07, 0x03, 0x00, 0x00} // byte 0 low bits => pb = 7
	_, err := decompressLZMA(stream, 32)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid LZMA parameters")
}

func TestParseUPXInfo_ImplausibleHeader(t *testing.T) {
	// a coincidental "UPX!" match surrounded by zeroed fields must not be accepted as a real UPX header.
	build := func(version, format byte, blockSize uint32) []byte {
		lInfo := []byte{0, 0, 0, 0, 'U', 'P', 'X', '!', 0, 0, version, format}
		pInfo := make([]byte, 12)
		binary.LittleEndian.PutUint32(pInfo[4:8], 0x1000) // plausible p_filesize
		binary.LittleEndian.PutUint32(pInfo[8:12], blockSize)
		return append(append(append([]byte{}, lInfo...), pInfo...), make([]byte, 32)...)
	}

	cases := map[string][]byte{
		"zero version":    build(0, 22, 0x1000),
		"zero format":     build(14, 0, 0x1000),
		"zero block size": build(14, 22, 0),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := parseUPXInfo(bytes.NewReader(data))
			require.Error(t, err)
		})
	}
}

func TestParseUPXInfo_OriginalSizeBoundedByInputSize(t *testing.T) {
	// the absolute ceiling is unrelated to the file on disk, so on its own a few dozen header bytes can
	// claim it. This is the amplification the reporter measured, expressed as a ratio rather than an
	// absolute size.
	data := append(buildUPXHeader(maxUPXOriginalSize, 4096), make([]byte, 32)...)

	_, err := parseUPXInfo(bytes.NewReader(data))
	require.Error(t, err)
	assert.ErrorIs(t, err, errUPXImplausibleSize)
}

func TestParseUPXInfo_RatioAllowsRealisticExpansion(t *testing.T) {
	// a claim within the ratio must still parse. The real fixture expands 1.96x; 4x here stays well inside
	// the bound so a legitimately compressible binary is not rejected.
	data := append(buildUPXHeader(4096, 4096), make([]byte, 1024)...)
	require.Greater(t, len(data), 4096/maxUPXExpansionRatio)

	info, err := parseUPXInfo(bytes.NewReader(data))
	require.NoError(t, err)
	assert.Equal(t, uint32(4096), info.originalSize)
}
