package zip

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	mathrand "math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/klauspost/compress/flate"
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

// deflate64RoundTrip compresses src and reads it back through this package's
// own decoder, reporting what came out.
func deflate64RoundTrip(t *testing.T, src []byte) ([]byte, error) {
	t.Helper()
	comp := new(bytes.Buffer)
	enc := newDeflate64Writer(comp)
	if _, err := enc.Write(src); err != nil {
		t.Fatalf("compressing %d bytes: %v", len(src), err)
	}
	if err := enc.Close(); err != nil {
		t.Fatalf("finishing the stream for %d bytes: %v", len(src), err)
	}
	dec := decodeDeflate64(bytes.NewReader(comp.Bytes()))
	got, err := io.ReadAll(dec)
	if cerr := dec.Close(); err == nil {
		err = cerr
	}
	return got, err
}

// TestDeflate64Encoder_ShortInputsWithARepeatedPrefix: thirteen bytes were
// enough to produce a stream nothing could read back. The header named the
// code lengths correctly and the codes the entry was then written with were
// generated from a different alphabet, so the decoder read a length symbol as
// a literal and everything after it was another file.
func TestDeflate64Encoder_ShortInputsWithARepeatedPrefix(t *testing.T) {
	for _, src := range []string{
		"0000100020000",
		"0000100020001",
		"aaaabaaacaaaa",
		"xxxxyxxxzxxxx",
		"000010002000",
		"00001000200000",
	} {
		t.Run(src, func(t *testing.T) {
			got, err := deflate64RoundTrip(t, []byte(src))
			if err != nil {
				t.Fatalf("what the encoder produced cannot be read back: %v", err)
			}
			if string(got) != src {
				t.Errorf("read back %q, wrote %q", got, src)
			}
		})
	}
}

// TestDeflate64Encoder_CorpusRoundTrips walks a corpus of the shapes that
// decide how a block is coded -- runs, alternations, matches that reach the
// end of a block, random bytes -- because the defect above showed itself on
// one input in a handful and not on the one beside it.
func TestDeflate64Encoder_CorpusRoundTrips(t *testing.T) {
	// #nosec G404 -- a fixed seed is the point: the corpus has to be the same corpus on every run
	rng := mathrand.New(mathrand.NewSource(20240907))

	corpus := make([][]byte, 0, 4200)
	// Every input up to six bytes over a two letter alphabet: the smallest
	// inputs that can carry a match at all, exhaustively.
	for n := 1; n <= 6; n++ {
		for v := 0; v < 1<<n; v++ {
			word := make([]byte, n)
			for i := range word {
				word[i] = byte('a' + (v>>i)&1)
			}
			corpus = append(corpus, word)
		}
	}
	// Structured inputs: a repeated prefix broken by single bytes, at every
	// length and every break point, which is the shape that failed.
	for n := 8; n <= 40; n++ {
		for b := 1; b < n; b++ {
			word := bytes.Repeat([]byte("0"), n)
			word[b] = '1'
			if b+4 < n {
				word[b+4] = '2'
			}
			corpus = append(corpus, word)
		}
	}
	// Random bytes over alphabets of a few sizes, so that the frequency
	// tables come out with very different numbers of live symbols.
	for _, alphabet := range []int{2, 3, 5, 17, 256} {
		for i := 0; i < 400; i++ {
			word := make([]byte, 1+rng.Intn(300))
			for j := range word {
				// #nosec G115 -- the largest alphabet here is 256, so the value is a byte by construction
				word[j] = byte(rng.Intn(alphabet))
			}
			corpus = append(corpus, word)
		}
	}

	for _, src := range corpus {
		got, err := deflate64RoundTrip(t, src)
		if err != nil {
			t.Fatalf("what the encoder produced for %q cannot be read back: %v", src, err)
		}
		if !bytes.Equal(got, src) {
			t.Fatalf("read back %q, wrote %q", got, src)
		}
	}
	t.Logf("%d inputs round tripped", len(corpus))
}

// TestDeflate64Encoder_PlainDeflateStreamsAreReadableByFlate: what the encoder
// writes for an input that needs none of the Deflate64 extensions is an
// ordinary deflate stream, so the standard library's decoder has to read it
// too. It is the second opinion on the encoder: a stream only one decoder
// accepts is a stream the encoder and that decoder agree to be wrong about.
func TestDeflate64Encoder_PlainDeflateStreamsAreReadableByFlate(t *testing.T) {
	// #nosec G404 -- as above: the corpus is the same on every run by design
	rng := mathrand.New(mathrand.NewSource(20240908))

	corpus := [][]byte{
		[]byte("0000100020000"),
		[]byte("0000100020001"),
		[]byte("aaaabaaacaaaa"),
		[]byte("xxxxyxxxzxxxx"),
	}
	for i := 0; i < 600; i++ {
		// Held under the 258 byte maximum match of plain deflate and
		// well inside its 32 KiB window, so nothing here can need a
		// Deflate64 length or distance code.
		word := make([]byte, 1+rng.Intn(200))
		for j := range word {
			// #nosec G115 -- four letters starting at 'a' is a byte by construction
			word[j] = byte('a' + rng.Intn(4))
		}
		corpus = append(corpus, word)
	}

	for _, src := range corpus {
		comp := new(bytes.Buffer)
		enc := newDeflate64Writer(comp)
		if _, err := enc.Write(src); err != nil {
			t.Fatalf("compressing %q: %v", src, err)
		}
		if err := enc.Close(); err != nil {
			t.Fatalf("finishing the stream for %q: %v", src, err)
		}

		fr := flate.NewReader(bytes.NewReader(comp.Bytes()))
		got, err := io.ReadAll(fr)
		if cerr := fr.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			t.Fatalf("the standard library's decoder refuses what the encoder wrote for %q: %v", src, err)
		}
		if !bytes.Equal(got, src) {
			t.Fatalf("the standard library's decoder read back %q, want %q", got, src)
		}
	}
}

// TestDeflate64_LengthTablesAreNotAliased: the Deflate64 length tables are
// built from the Deflate ones, and building them by appending to a slice of an
// array wrote into the array behind it. Code 285 is where the two differ, and
// it is exactly the slot that was overwritten: the Deflate table lost its 258
// byte maximum match and its zero extra bits.
func TestDeflate64_LengthTablesAreNotAliased(t *testing.T) {
	if got := lengthBase32[28]; got != 258 {
		t.Errorf("the Deflate length base for code 285 is %d, want 258", got)
	}
	if got := lengthExtraBits32[28]; got != 0 {
		t.Errorf("the Deflate length code 285 carries %d extra bits, want 0", got)
	}
	if got := lengthBase64[28]; got != 3 {
		t.Errorf("the Deflate64 length base for code 285 is %d, want 3", got)
	}
	if got := lengthExtraBits64[28]; got != 16 {
		t.Errorf("the Deflate64 length code 285 carries %d extra bits, want 16", got)
	}
}

// TestDeflate64_EntryRoundTripsThroughAnArchive is the same defect where a
// caller meets it: an entry written with Method Deflate64. Plain, the checksum
// caught the corruption and the entry failed to read; under WinZip AES it did
// not, because AE-2 stores a zero checksum and the authentication code is over
// the ciphertext rather than the plaintext -- so thirteen bytes went in, other
// bytes came out, and both the read and the close reported success.
func TestDeflate64_EntryRoundTripsThroughAnArchive(t *testing.T) {
	body := []byte("0000100020000")

	t.Run("plain", func(t *testing.T) {
		buf := new(bytes.Buffer)
		zw := NewWriter(buf)
		mustWrite(t, mustCreateHeader(t, zw, &FileHeader{Name: "a.bin", Method: Deflate64}), body)
		if err := zw.Close(); err != nil {
			t.Fatalf("closing the writer: %v", err)
		}

		zr, err := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
		if err != nil {
			t.Fatalf("reading the archive back: %v", err)
		}
		rc, err := zr.File[0].Open()
		if err != nil {
			t.Fatalf("opening the entry: %v", err)
		}
		closeAt(t, rc)
		got, err := io.ReadAll(rc)
		if err != nil {
			t.Fatalf("reading the entry: %v", err)
		}
		if err := rc.Close(); err != nil {
			t.Fatalf("closing the entry: %v", err)
		}
		if !bytes.Equal(got, body) {
			t.Errorf("the entry holds %q, want %q", got, body)
		}
	})

	t.Run("under WinZip AES", func(t *testing.T) {
		const password = "pw"
		buf := new(bytes.Buffer)
		zw := NewWriter(buf)
		mustWrite(t, mustCreateHeader(t, zw, &FileHeader{
			Name:        "a.bin",
			Method:      Deflate64,
			Password:    password,
			AESStrength: 3,
		}), body)
		if err := zw.Close(); err != nil {
			t.Fatalf("closing the writer: %v", err)
		}

		zr, err := NewReaderWithPassword(bytes.NewReader(buf.Bytes()), int64(buf.Len()), password)
		if err != nil {
			t.Fatalf("reading the archive back: %v", err)
		}
		rc, err := zr.File[0].Open()
		if err != nil {
			t.Fatalf("opening the entry: %v", err)
		}
		closeAt(t, rc)
		got, err := io.ReadAll(rc)
		if err != nil {
			t.Fatalf("reading the entry: %v", err)
		}
		if err := rc.Close(); err != nil {
			t.Fatalf("closing the entry: %v", err)
		}
		if !bytes.Equal(got, body) {
			t.Errorf("the entry holds %q, want %q -- and nothing reported the difference", got, body)
		}
	})
}
