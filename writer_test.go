package zip

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWriter_ZIP64Forced(t *testing.T) {
	buf := new(bytes.Buffer)
	w := NewWriter(buf)

	// Simulate a huge file via the header, without writing terabytes of data
	fh := &FileHeader{
		Name:               "huge.txt",
		Method:             Store,
		UncompressedSize64: uint64(uint32max) + 1, // More than 4GB
		CompressedSize64:   uint64(uint32max) + 1,
	}

	// CreateRaw allows us to write the data "as is"
	wr, err := w.CreateRaw(fh)
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, wr, []byte("fake data"))
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	// Now read and check that the zip64 flag was set
	zr, err := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}

	if !zr.File[0].zip64 {
		t.Error("expected ZIP64 header for file > 4GB, but it was not set")
	}

	if zr.File[0].UncompressedSize64 != uint64(uint32max)+1 {
		t.Errorf("size mismatch in ZIP64: got %d", zr.File[0].UncompressedSize64)
	}
}
func TestWriter_ZIP64LocalHeaderExtra(t *testing.T) {
	buf := new(bytes.Buffer)
	w := NewWriter(buf)

	fh := &FileHeader{
		Name:               "huge.txt",
		Method:             Store,
		UncompressedSize64: uint64(uint32max) + 1,
		CompressedSize64:   uint64(uint32max) + 1,
	}

	wr, err := w.CreateRaw(fh)
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, wr, []byte("fake data"))
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	raw := buf.Bytes()
	if !bytes.Equal(raw[:4], []byte{0x50, 0x4b, 0x03, 0x04}) {
		t.Fatal("invalid local header signature")
	}

	// Read lengths to parse extra fields dynamically
	filenameLen := binary.LittleEndian.Uint16(raw[26:28])
	extraLen := binary.LittleEndian.Uint16(raw[28:30])

	if filenameLen != uint16(len("huge.txt")) {
		t.Fatalf("unexpected filename length: %d", filenameLen)
	}

	extraStart := 30 + int(filenameLen)
	extraBytes := raw[extraStart : extraStart+int(extraLen)]

	foundZip64 := false
	for len(extraBytes) >= 4 {
		tag := binary.LittleEndian.Uint16(extraBytes[:2])
		size := binary.LittleEndian.Uint16(extraBytes[2:4])
		if tag == zip64ExtraID {
			foundZip64 = true
			if size != 16 {
				t.Errorf("expected ZIP64 size in local header to be 16, got %d", size)
			}
			uncomp := binary.LittleEndian.Uint64(extraBytes[4:12])
			comp := binary.LittleEndian.Uint64(extraBytes[12:20])
			if uncomp != uint64(uint32max)+1 || comp != uint64(uint32max)+1 {
				t.Errorf("incorrect sizes in local header ZIP64: uncomp=%d, comp=%d", uncomp, comp)
			}
			break
		}
		extraBytes = extraBytes[4+size:]
	}

	if !foundZip64 {
		t.Error("ZIP64 extra block (0x0001) was not found in the Local Header of a file > 4GB")
	}
}

func TestWriter_ZIP64LargeCount(t *testing.T) {
	buf := new(bytes.Buffer)
	w := NewWriter(buf)

	// Simulate a situation where there are more than 65535 files (uint16 limit)
	// To save time and memory, we will modify the counter directly in the test
	for i := 0; i < 10; i++ {
		mustCreate(t, w, fmt.Sprintf("file_%d.txt", i))
	}

	// Hack for the test: substitute the number of records before closing
	// to trigger writing of ZIP64 headers
	originalDir := w.dir
	fakeDir := make([]*header, uint16max+1)
	for i := range fakeDir {
		fakeDir[i] = &header{FileHeader: &FileHeader{Name: "f.txt"}}
	}
	w.dir = fakeDir

	err := w.Close()
	if err != nil {
		t.Fatalf("Close failed on large count simulation: %v", err)
	}

	// Check that the EOCD structure contains the 0xFFFF markers,
	// which indicates the presence of the ZIP64 Locator
	data := buf.Bytes()
	// EOCD signature: 0x06054b50 in Little Endian
	if !bytes.Contains(data, []byte{0x50, 0x4b, 0x05, 0x06}) {
		t.Error("EOCD signature not found")
	}

	// Restore as it was for proper completion
	w.dir = originalDir
}
func TestWriter_SetOffsetPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected panic when calling SetOffset after writes")
		}
	}()
	w := NewWriter(new(bytes.Buffer))
	mustCreate(t, w, "test.txt")
	w.SetOffset(100) // Should cause a panic
}

func TestWriter_LongCommentError(t *testing.T) {
	w := NewWriter(new(bytes.Buffer))
	longComment := make([]byte, uint16max+1)
	err := w.SetComment(string(longComment))
	if err == nil {
		t.Error("expected error for long comment, got nil")
	}
}

func TestWriter_AddFS(t *testing.T) {
	tmp := t.TempDir()
	mustWriteFile(t, filepath.Join(tmp, "fs.txt"), []byte("fs data"), 0644)

	buf := new(bytes.Buffer)
	w := NewWriter(buf)

	// Use the standard os.DirFS
	err := w.AddFS(os.DirFS(tmp))
	if err != nil {
		t.Fatalf("AddFS failed: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	zr, _ := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if len(zr.File) != 1 || zr.File[0].Name != "fs.txt" {
		t.Errorf("AddFS did not package file correctly")
	}
}

func TestLZMA_Decompression(t *testing.T) {
	// This test requires a valid LZMA stream.
	// We will simply verify the method registration.
	dcomp := decompressor(LZMA)
	if dcomp == nil {
		t.Fatal("LZMA decompressor not registered")
	}
}

func TestWriter_AutoExtrasInjection(t *testing.T) {
	buf := new(bytes.Buffer)
	zw := NewWriter(buf)

	now := time.Now().Truncate(time.Second)
	fh := &FileHeader{
		Name:     "meta.txt",
		Modified: now,
		Accessed: now.Add(-time.Hour),
		Created:  now.Add(-24 * time.Hour),
		Uid:      501,
		Gid:      20,
		OwnerSet: true,
	}

	w := mustCreateHeader(t, zw, fh)
	mustWrite(t, w, []byte("metadata test"))
	if err := zw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	zr, _ := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	f := zr.File[0]

	// 1. Checking timestamps via 0x5455 (Extended Timestamp)
	if f.Modified.Unix() != fh.Modified.Unix() {
		t.Errorf("Modified time mismatch: got %v, want %v", f.Modified, fh.Modified)
	}
	if f.Accessed.Unix() != fh.Accessed.Unix() {
		t.Errorf("Accessed time mismatch: got %v, want %v", f.Accessed, fh.Accessed)
	}

	// 2. Verifying UNIX ID via 0x7875 (Info-ZIP New Unix)
	uid, gid, ok := parseUnixExtra(f.Extra)
	if !ok {
		t.Fatal("Unix extra field (0x7875) not found in output")
	}
	if uid != 501 || gid != 20 {
		t.Errorf("UID/GID mismatch: got %d:%d, want 501:20", uid, gid)
	}
}
func TestWriter_MetadataIdempotency(t *testing.T) {
	// Verifying that multiple calls to the injector do not duplicate Extra Fields.
	now := time.Now().Truncate(time.Second)
	fh := &FileHeader{
		Name:     "idempotent.txt",
		Modified: now,
		Uid:      1000,
		OwnerSet: true,
	}

	// First Call (via Creation)
	buf := new(bytes.Buffer)
	zw := NewWriter(buf)
	mustCreateHeader(t, zw, fh)
	if err := zw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	initialExtraLen := len(fh.Extra)

	// Simulating a repeated injection (for example, when reusing a header).
	fh.injectAutoExtras()
	fh.injectAutoExtras()

	if len(fh.Extra) != initialExtraLen {
		t.Errorf("Extra fields bloated! initial %d, current %d. Likely duplicate tags.", initialExtraLen, len(fh.Extra))
	}
}
func TestWriter_CDE(t *testing.T) {
	password := "cd-secret"
	buf := new(bytes.Buffer)

	// 1. Create an archive with an encrypted central directory
	zw := NewWriter(buf)
	zw.SetEncryptCentralDirectory(true, password)
	w := mustCreate(t, zw, "hidden.txt")
	mustWrite(t, w, []byte("can you see me?"))
	if err := zw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	raw := buf.Bytes()

	// 2. Try to open without a password — it should fail when reading headers
	_, err := NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err == nil {
		t.Error("expected error when opening CDE archive without password")
	}

	// 2.1 Try to open with an INCORRECT password
	zrWrongPass := new(Reader)
	zrWrongPass.SetPassword("wrong-password")
	err = zrWrongPass.init(bytes.NewReader(raw), int64(len(raw)))
	if err == nil || err.Error() != "zip: incorrect password" {
		t.Errorf("expected 'incorrect password' error, got: %v", err)
	}

	// 3. Open with the correct password
	zr := new(Reader)
	zr.SetPassword(password)
	// Direct init call, as NewReader does not take a password in the constructor immediately
	err = zr.init(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatalf("failed to open CDE archive with password: %v", err)
	}

	if len(zr.File) != 1 || zr.File[0].Name != "hidden.txt" {
		t.Errorf("failed to recover file list from CDE")
	}
}

func TestWriter_StreamingForced(t *testing.T) {
	buf := new(bytes.Buffer)
	zw := NewWriter(buf)

	// Simulating streaming using SetOffset
	zw.SetOffset(0)

	fh := &FileHeader{Name: "stream.txt", Method: Store}
	// Even for a Store, we can force a descriptor if we want absolute streaming.
	w := mustCreateHeader(t, zw, fh)
	mustWrite(t, w, []byte("streaming data"))
	if err := zw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	// We verify that flag 0x8 (Data Descriptor) is set.
	zr, _ := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if zr.File[0].Flags&0x8 == 0 {
		t.Error("Data Descriptor flag not set in streaming mode")
	}
}

// seekChunkPayload builds n bytes of data that compresses but is not uniform,
// so that a chunk read back through the index can be told from its neighbour.
func seekChunkPayload(n int) []byte {
	p := make([]byte, n)
	for i := range p {
		p[i] = byte('a' + (i/7+i/113)%23)
	}
	return p
}

// TestWriter_SeekIndexChunkedRoundTrip pins what the seek index is for: an
// entry written with one has to come back byte for byte when it is read from
// the middle rather than from the start. Building it walks the chunk boundary
// code -- closing and reopening the compressor for ZSTD, flushing it for
// deflate -- and reading it back says the offsets recorded there are the ones
// the chunks really start at.
func TestWriter_SeekIndexChunkedRoundTrip(t *testing.T) {
	const chunkSize = 1024
	withTail := seekChunkPayload(chunkSize*5 + 256)
	wholeChunks := seekChunkPayload(chunkSize * 4)

	for _, tc := range []struct {
		name string
		// continuous picks the index format: SOZip when false, where
		// every chunk is an independent stream, GZIDX when true, where
		// the stream runs on and each point carries a window.
		method     uint16
		continuous bool
		chunk      uint32
		payload    []byte
	}{
		{"sozip over deflate", Deflate, false, chunkSize, withTail},
		{"sozip over zstd", ZSTD, false, chunkSize, withTail},
		{"gzidx over deflate", Deflate, true, chunkSize, withTail},
		{"sozip over a whole number of chunks", Deflate, false, chunkSize, wholeChunks},
		// Past 32 KiB of input the window a point carries is the tail
		// of what came before it rather than all of it, and that is the
		// dictionary the entry has to decompress against.
		{"gzidx past the window a point carries", Deflate, true, 16384, seekChunkPayload(40960)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buf := new(bytes.Buffer)
			zw := NewWriter(buf)
			w := mustCreateHeader(t, zw, &FileHeader{
				Name:               "chunked.bin",
				Method:             tc.method,
				SeekChunkSize:      tc.chunk,
				SeekContinuous:     tc.continuous,
				UncompressedSize64: uint64(len(tc.payload)),
			})
			mustWrite(t, w, tc.payload)
			if err := zw.Close(); err != nil {
				t.Fatalf("close writer: %v", err)
			}

			zr, err := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
			if err != nil {
				t.Fatalf("reopen the archive: %v", err)
			}
			f := zr.File[0]
			rs, err := f.OpenSeekable()
			if err != nil {
				t.Fatalf("OpenSeekable: %v", err)
			}

			all, err := io.ReadAll(rs)
			if err != nil {
				t.Fatalf("read the whole entry: %v", err)
			}
			if !bytes.Equal(all, tc.payload) {
				t.Fatalf("the entry reads back as %d bytes, want %d", len(all), len(tc.payload))
			}

			// One offset per interesting place: the start, a chunk
			// boundary, the middle of a chunk, and the tail.
			for _, off := range []int{0, int(tc.chunk), int(tc.chunk)*2 + 7, len(tc.payload) - 100} {
				if _, err := rs.Seek(int64(off), io.SeekStart); err != nil {
					t.Fatalf("seek to %d: %v", off, err)
				}
				got := make([]byte, 100)
				if _, err := io.ReadFull(rs, got); err != nil {
					t.Fatalf("read 100 bytes at %d: %v", off, err)
				}
				if !bytes.Equal(got, tc.payload[off:off+100]) {
					t.Fatalf("100 bytes read at %d are not the 100 bytes written there: the index points at the wrong place", off)
				}
			}
		})
	}
}

// stubChunkCompressor stands in for a real compressor so that a test can fail
// the exact call chunkSeekWriter makes when it reaches a chunk boundary.
type stubChunkCompressor struct {
	w        io.Writer
	writeErr error
	closeErr error
	flushErr error
}

func (c *stubChunkCompressor) Write(p []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return c.w.Write(p)
}
func (c *stubChunkCompressor) Close() error { return c.closeErr }
func (c *stubChunkCompressor) Flush() error { return c.flushErr }

// TestWriter_SeekIndexChunkBoundaryErrors covers the ways compressing a chunk
// can fail. Each of them used to be dropped, and dropping any of them records
// an index point at an offset the compressor never reached, which is an entry
// that reads back as garbage from every offset but the first.
func TestWriter_SeekIndexChunkBoundaryErrors(t *testing.T) {
	for _, tc := range []struct {
		name       string
		method     uint16
		writeErr   bool
		closeErr   bool
		factoryErr bool
		flushErr   bool
	}{
		{"handing the chunk to the compressor", Deflate, true, false, false, false},
		{"closing the zstd frame that ends the chunk", ZSTD, false, true, false, false},
		{"opening the zstd frame that starts the next one", ZSTD, false, false, true, false},
		{"flushing the compressor at the boundary", Deflate, false, false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := errors.New("the compressor gave up")
			zw := NewWriter(new(bytes.Buffer))
			created := 0
			zw.RegisterCompressor(tc.method, func(w io.Writer) (io.WriteCloser, error) {
				created++
				if tc.factoryErr && created > 1 {
					return nil, want
				}
				c := &stubChunkCompressor{w: w}
				if tc.writeErr {
					c.writeErr = want
				}
				if tc.closeErr {
					c.closeErr = want
				}
				if tc.flushErr {
					c.flushErr = want
				}
				return c, nil
			})

			w := mustCreateHeader(t, zw, &FileHeader{
				Name:          "chunked.bin",
				Method:        tc.method,
				SeekChunkSize: 8,
			})
			// The archive is left unfinished on purpose: the
			// compressor under it is broken, so all Close could say
			// is that same error over again.
			if _, err := w.Write(make([]byte, 32)); !errors.Is(err, want) {
				t.Fatalf("writing past a chunk boundary returned %v, want the compressor's error", err)
			}
		})
	}
}

// stubPlainCompressor is a compressor with no Flush of its own, the way LZMA
// and the store method have none.
type stubPlainCompressor struct{ w io.Writer }

func (c *stubPlainCompressor) Write(p []byte) (int, error) { return c.w.Write(p) }
func (c *stubPlainCompressor) Close() error                { return nil }

// TestWriter_SeekIndexWithoutAFlush covers the chunk boundary for a compressor
// that cannot be flushed: there is nothing to push out, and the index point is
// recorded all the same rather than the boundary being skipped.
func TestWriter_SeekIndexWithoutAFlush(t *testing.T) {
	zw := NewWriter(new(bytes.Buffer))
	zw.RegisterCompressor(Deflate, func(w io.Writer) (io.WriteCloser, error) {
		return &stubPlainCompressor{w: w}, nil
	})

	fh := &FileHeader{Name: "chunked.bin", Method: Deflate, SeekChunkSize: 8}
	w := mustCreateHeader(t, zw, fh)
	mustWrite(t, w, make([]byte, 32))

	// The index opens with the zero offset the format skips in the payload,
	// then one point per chunk boundary crossed.
	if len(fh.SeekIndex) != 5 {
		t.Errorf("the index holds %d offsets for four chunk boundaries, want 5", len(fh.SeekIndex))
	}
}

// TestWriter_ZIP64ExtraIsNotDuplicated covers the writer's search for a zip64
// record already in the caller's extra field. Appending a second one leaves
// two records with the same tag in one header, and which of them a reader
// believes is its own business.
func TestWriter_ZIP64ExtraIsNotDuplicated(t *testing.T) {
	huge := uint64(uint32max) + 1

	own := make([]byte, 20)
	binary.LittleEndian.PutUint16(own[0:2], zip64ExtraID)
	binary.LittleEndian.PutUint16(own[2:4], 16)
	binary.LittleEndian.PutUint64(own[4:12], huge)
	binary.LittleEndian.PutUint64(own[12:20], huge)

	// An extra field whose first record says it is longer than what is left
	// of the field is one this writer cannot read past, so it stops looking
	// and writes its own record.
	truncated := make([]byte, 8)
	binary.LittleEndian.PutUint16(truncated[0:2], 0x5455)
	binary.LittleEndian.PutUint16(truncated[2:4], 0xffff)

	for _, tc := range []struct {
		name  string
		extra []byte
		want  int
	}{
		{"the caller brought its own zip64 record", own, len(own)},
		{"a record longer than the field holding it", truncated, len(truncated) + 20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buf := new(bytes.Buffer)
			zw := NewWriter(buf)
			if _, err := zw.CreateRaw(&FileHeader{
				Name:               "huge.bin",
				Method:             Store,
				CompressedSize64:   huge,
				UncompressedSize64: huge,
				Extra:              tc.extra,
			}); err != nil {
				t.Fatalf("create the entry: %v", err)
			}
			if err := zw.Close(); err != nil {
				t.Fatalf("close writer: %v", err)
			}

			raw := buf.Bytes()
			if got := int(binary.LittleEndian.Uint16(raw[28:30])); got != tc.want {
				t.Errorf("the local header carries %d bytes of extra field, want %d", got, tc.want)
			}
		})
	}
}

// TestWriter_GZIDXShortWindowIsPadded covers a GZIDX point whose window is
// shorter than the 32 KiB one the format keeps for every point. The window
// has to be right aligned in the padding, because a decompressor primed with
// it treats the last byte as the one immediately before the point.
func TestWriter_GZIDXShortWindowIsPadded(t *testing.T) {
	const windowSize = 32768
	window := []byte("the tail of the stream so far")

	fw := &fileWriter{header: &header{FileHeader: &FileHeader{
		Name:               "padded.bin",
		Method:             Deflate,
		SeekChunkSize:      1024,
		SeekContinuous:     true,
		CompressedSize64:   64,
		UncompressedSize64: 4096,
		GzidxPoints: []gzPoint{
			{compOffset: 0, uncompOffset: 0, hasData: 0},
			{compOffset: 16, uncompOffset: 1024, hasData: 1, window: window},
		},
	}}}

	payload := fw.buildGZIDX()

	// Five bytes of magic, a version and a flag byte, two sizes, the chunk
	// size, the window size and the point count, then eighteen bytes per
	// point, then the window of every point that has one.
	const headerLen = 35
	const pointLen = 18
	windowStart := headerLen + 2*pointLen
	if len(payload) != windowStart+windowSize {
		t.Fatalf("the index is %d bytes, want %d: a short window was not padded to the full window size", len(payload), windowStart+windowSize)
	}
	stored := payload[windowStart:]
	if !bytes.Equal(stored[windowSize-len(window):], window) {
		t.Errorf("the window is not at the end of the padding: %q", stored[windowSize-len(window):])
	}
	for i, b := range stored[:windowSize-len(window)] {
		if b != 0 {
			t.Fatalf("byte %d of the padding is %#x, want a zero", i, b)
		}
	}
}

// requireFieldTooLong fails the test unless err says the named field is over
// the length the format keeps it in.
func requireFieldTooLong(t *testing.T, err error, field string) {
	t.Helper()
	if err == nil {
		t.Fatalf("a %s over the format limit was written without an error: the header now carries a length that has wrapped", field)
	}
	if !strings.Contains(err.Error(), field) {
		t.Fatalf("error %q does not name the %q the caller has to shorten", err, field)
	}
}

// TestWriter_HeaderFieldsOverTheFormatLimit covers the length the format keeps
// each of the three variable fields in: two bytes. A longer one cannot be
// written at all -- what used to go out was a header announcing len&0xffff
// bytes followed by the whole string, an archive no reader can make sense of
// and every reader mistakes for something else. Each field is checked where it
// is written, which for the comment is not until the central directory.
func TestWriter_HeaderFieldsOverTheFormatLimit(t *testing.T) {
	long := strings.Repeat("n", uint16max+1)

	t.Run("name in the local header", func(t *testing.T) {
		zw := NewWriter(new(bytes.Buffer))
		_, err := zw.Create(long)
		requireFieldTooLong(t, err, "file name")
	})

	t.Run("extra field in the local header", func(t *testing.T) {
		zw := NewWriter(new(bytes.Buffer))
		_, err := zw.CreateHeader(&FileHeader{
			Name:   "extra.bin",
			Method: Store,
			Extra:  make([]byte, uint16max+1),
		})
		requireFieldTooLong(t, err, "extra field")
	})

	t.Run("the zip64 extra the writer adds itself counts toward the limit", func(t *testing.T) {
		// The caller's own extra field fits. The writer appends a
		// twenty byte zip64 record to it for an entry this size, and
		// what goes in the header is the length of both together.
		zw := NewWriter(new(bytes.Buffer))
		_, err := zw.CreateRaw(&FileHeader{
			Name:               "huge.bin",
			Method:             Store,
			CompressedSize64:   uint64(uint32max) + 1,
			UncompressedSize64: uint64(uint32max) + 1,
			Extra:              make([]byte, uint16max-8),
		})
		requireFieldTooLong(t, err, "extra field")
	})

	t.Run("comment in the central directory", func(t *testing.T) {
		// A comment is not part of the local header, so nothing has
		// looked at it until the directory is written.
		zw := NewWriter(new(bytes.Buffer))
		mustCreateHeader(t, zw, &FileHeader{Name: "commented.txt", Method: Store, Comment: long})
		requireFieldTooLong(t, zw.Close(), "file comment")
	})

	t.Run("name in the central directory", func(t *testing.T) {
		// The writer holds on to the caller's own FileHeader, so a name
		// that fitted when the local header went out can be over the
		// limit by the time the directory is written from it.
		fh := &FileHeader{Name: "short.txt", Method: Store}
		zw := NewWriter(new(bytes.Buffer))
		mustCreateHeader(t, zw, fh)
		fh.Name = long
		requireFieldTooLong(t, zw.Close(), "file name")
	})

	t.Run("extra field in the central directory", func(t *testing.T) {
		fh := &FileHeader{Name: "short.txt", Method: Store}
		zw := NewWriter(new(bytes.Buffer))
		mustCreateHeader(t, zw, fh)
		fh.Extra = make([]byte, uint16max+1)
		requireFieldTooLong(t, zw.Close(), "extra field")
	})
}
