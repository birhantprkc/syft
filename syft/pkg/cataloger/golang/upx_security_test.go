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
	// total decompression work becomes (block count x original size).
	// real 2048-byte streams, so the failure below is the budget and not a short decode
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
