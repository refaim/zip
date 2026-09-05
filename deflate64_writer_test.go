package zip

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// cutoffWriter accepts limit bytes and fails every write past that, the way a
// full disk does. The bit writer buffers a megabyte before it touches the
// underlying writer, so a test that wants to see a write error at all has to
// push more than that through the encoder.
type cutoffWriter struct {
	limit   int
	written int
	err     error
}

func (cw *cutoffWriter) Write(p []byte) (int, error) {
	room := cw.limit - cw.written
	if len(p) <= room {
		cw.written += len(p)
		return len(p), nil
	}
	cw.written += room
	return room, cw.err
}

func TestDeflate64Encoder_Roundtrip(t *testing.T) {
	// Full cycle roundtrip testing (compression -> decompression)

	// Generate pseudorandom data with repetitions to verify LZ77
	srcData := make([]byte, 150000) // 150 KB (larger than 64KB window)
	rand.Read(srcData[:50000])
	// Duplicate blocks
	copy(srcData[50000:100000], srcData[:50000])
	copy(srcData[100000:150000], srcData[:50000])

	// 1. Compress into buffer
	compressedBuf := new(bytes.Buffer)
	encoder := newDeflate64Writer(compressedBuf)

	n, err := encoder.Write(srcData)
	if err != nil {
		t.Fatalf("Encoder write failed: %v", err)
	}
	if n != len(srcData) {
		t.Fatalf("Expected to write %d bytes, wrote %d", len(srcData), n)
	}

	if err := encoder.Close(); err != nil {
		t.Fatalf("Encoder close failed: %v", err)
	}

	t.Logf("Original size: %d, Compressed size: %d, Ratio: %.2f%%",
		len(srcData), compressedBuf.Len(), float64(compressedBuf.Len())/float64(len(srcData))*100)

	// 2. Decompress using our Deflate64 decoder
	decoder := decodeDeflate64(compressedBuf)
	closeAt(t, decoder)

	decompressedData, err := io.ReadAll(decoder)
	if err != nil {
		t.Fatalf("Decompression failed: %v", err)
	}

	// 3. Verify exact match
	if !bytes.Equal(decompressedData, srcData) {
		t.Fatal("Roundtrip failed! Decompressed data does not match original srcData")
	}
}

func TestDeflate64Encoder_Empty(t *testing.T) {
	// Verify correct handling of an empty stream
	buf := new(bytes.Buffer)
	encoder := newDeflate64Writer(buf)
	if err := encoder.Close(); err != nil {
		t.Fatal(err)
	}

	decoder := decodeDeflate64(buf)
	closeAt(t, decoder)

	data, err := io.ReadAll(decoder)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 0 {
		t.Errorf("Expected empty output, got %d bytes", len(data))
	}
}

func TestDeflate64_External7zBidirectional(t *testing.T) {
	p7zPath, err := exec.LookPath("7z")
	if err != nil {
		t.Skip("7z utility not found, skipping bidirectional external validation")
	}

	tmpDir := t.TempDir()

	// Generate highly structured repeating text
	srcData := []byte("highly structured data repeating many times for compression testing. ")
	for i := 0; i < 6; i++ {
		srcData = append(srcData, srcData...)
	}

	// Scenario A: Compress with our encoder -> Decompress with external 7z
	zipPath := filepath.Join(tmpDir, "go_compressed.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, f)
	zw := NewWriter(f)
	w, err := zw.CreateHeader(&FileHeader{
		Name:   "test.txt",
		Method: Deflate64,
	})
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, w, srcData)
	if err := zw.Close(); err != nil {
		t.Fatalf("Writer close failed: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", zipPath, err)
	}

	extractedDir := filepath.Join(tmpDir, "7z_extracted")
	cmd := exec.Command(p7zPath, "x", "-o"+extractedDir, zipPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("7z failed to extract Go-compressed Deflate64 archive: %v, output: %s", err, string(output))
	}

	decompressed, err := os.ReadFile(filepath.Join(extractedDir, "test.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decompressed, srcData) {
		t.Error("7z extracted data does not match original Go-compressed data")
	}
}

func TestDeflate64_ExtremeAllZeros(t *testing.T) {
	// Stress-test long matches (up to 65538 bytes) and Huffman RLE
	srcData := make([]byte, 250000) // 250 KB of pure zeros

	buf := new(bytes.Buffer)
	encoder := newDeflate64Writer(buf)
	n, err := encoder.Write(srcData)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(srcData) {
		t.Fatalf("Expected %d bytes written, got %d", len(srcData), n)
	}
	if err := encoder.Close(); err != nil {
		t.Fatalf("Encoder close failed: %v", err)
	}

	decoder := decodeDeflate64(buf)
	closeAt(t, decoder)

	decompressed, err := io.ReadAll(decoder)
	if err != nil {
		t.Fatalf("Decompression of zeros stream failed: %v", err)
	}
	if !bytes.Equal(decompressed, srcData) {
		t.Error("Decompressed zeros do not match original data")
	}
}

func TestDeflate64_BoundaryDistances(t *testing.T) {
	// Stress-test the exact window size boundary.
	// Fill 65536 bytes with 'A', then one separator 'B',
	// and then another 10 'A's. The last 10 bytes should match
	// at a distance of exactly 65536 + 1 (the absolute sliding window limit).
	srcData := make([]byte, 65536+1+10)
	for i := 0; i < 65536; i++ {
		srcData[i] = 'A'
	}
	srcData[65536] = 'B'
	for i := 65537; i < len(srcData); i++ {
		srcData[i] = 'A'
	}

	buf := new(bytes.Buffer)
	encoder := newDeflate64Writer(buf)
	mustWrite(t, encoder, srcData)
	if err := encoder.Close(); err != nil {
		t.Fatalf("Encoder close failed: %v", err)
	}

	decoder := decodeDeflate64(buf)
	closeAt(t, decoder)

	decompressed, err := io.ReadAll(decoder)
	if err != nil {
		t.Fatalf("Decompression of boundary stream failed: %v", err)
	}
	if !bytes.Equal(decompressed, srcData) {
		t.Error("Decompressed boundary stream do not match original data")
	}
}

// TestBitWriter_LatchesWriteError pins that a byte the bit writer cannot hand
// to the output stream is not lost silently: the first error is kept and
// reported to whoever flushes.
func TestBitWriter_LatchesWriteError(t *testing.T) {
	want := errors.New("no space left on device")
	bw := newBitWriter(&cutoffWriter{err: want})

	// The bit writer buffers a megabyte, so write two before expecting the
	// underlying writer to have been touched at all.
	for i := 0; i < 1<<19; i++ {
		bw.writeBits(0xFFFFFFFF, 32)
	}
	if !errors.Is(bw.err, want) {
		t.Fatalf("writeBits swallowed the write error, latched %v", bw.err)
	}

	// Leave a partial byte behind so the flush has one more byte to emit, and
	// check the error still comes back from it.
	bw.writeBits(1, 3)
	if err := bw.flushBits(); !errors.Is(err, want) {
		t.Fatalf("flushBits returned %v, want %v", err, want)
	}
}

// TestDeflate64Writer_CloseReportsWriteError covers the small stream case,
// where nothing reaches the output until Close flushes it.
func TestDeflate64Writer_CloseReportsWriteError(t *testing.T) {
	want := errors.New("no space left on device")
	encoder := newDeflate64Writer(&cutoffWriter{err: want})

	mustWrite(t, encoder, []byte("a block small enough to sit in the buffer"))

	if err := encoder.Close(); !errors.Is(err, want) {
		t.Fatalf("Close returned %v, want %v", err, want)
	}
}

// TestDeflate64Writer_WriteReportsWriteError covers the streaming case: the
// output dies part way through, and the caller of Write has to hear about it
// rather than get a corrupt archive with no error.
func TestDeflate64Writer_WriteReportsWriteError(t *testing.T) {
	want := errors.New("no space left on device")
	sink := &cutoffWriter{limit: 1 << 20, err: want}
	encoder := newDeflate64Writer(sink)

	// Incompressible data, so the encoder has to push past both the megabyte
	// the sink accepts and the megabyte the bit writer buffers.
	srcData := make([]byte, 3<<20)
	if _, err := rand.Read(srcData); err != nil {
		t.Fatalf("fill source data: %v", err)
	}

	n, err := encoder.Write(srcData)
	if !errors.Is(err, want) {
		t.Fatalf("Write reported %d bytes and error %v, want %v", n, err, want)
	}
	if err := encoder.Close(); !errors.Is(err, want) {
		t.Fatalf("Close returned %v, want %v", err, want)
	}
}
