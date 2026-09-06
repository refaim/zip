package zip

// The tests here cover the archive-writing surface: what Writer puts on the
// wire for an entry, what it refuses to write at all, what it reports when the
// destination stops accepting bytes, and the header conversions FileHeader
// offers around it.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

// WriterCovStamp is the modification time every fixture entry carries. The
// sink tests below build the same archive once per byte offset in it, so the
// bytes have to come out the same every time and a timestamp off the clock
// would not.
var WriterCovStamp = time.Date(2021, 6, 7, 8, 9, 10, 0, time.UTC)

// errWriterCovSink is what the cut-off sinks in these tests report once
// they stop taking bytes.
var errWriterCovSink = errors.New("the sink stopped taking bytes")

// errWriterCovBoom stands for a failure coming from outside the writer: a
// filesystem that will not answer, a compressor that will not start.
var errWriterCovBoom = errors.New("the call failed")

// WriterCovEachSinkFailure writes the archive build describes once over a sink
// that takes everything, then once for every byte offset in it over a sink
// that stops there. Every one of those runs has to hand the failure back: a
// swallowed one leaves the caller holding an archive that is short of what it
// was told had been written, with no sign that anything went wrong.
func WriterCovEachSinkFailure(t *testing.T, build func(zw *Writer) error) {
	t.Helper()
	var complete bytes.Buffer
	if err := build(writerWithBufferSize(&complete, 1)); err != nil {
		t.Fatalf("the archive did not write over a sink that takes everything: %v", err)
	}
	total := complete.Len()
	if total == 0 {
		t.Fatal("the archive came out empty, so there is no write to fail")
	}
	for limit := 0; limit < total; limit++ {
		sink := &cutoffWriter{limit: limit, err: errWriterCovSink}
		err := build(writerWithBufferSize(sink, 1))
		if !errors.Is(err, errWriterCovSink) {
			t.Fatalf("with the sink taking only %d of the %d bytes, writing the archive reported %v, want the sink's failure", limit, total, err)
		}
	}
}

// WriterCovSourceArchive is a small two entry archive, used as the thing being
// copied entry for entry into another one.
func WriterCovSourceArchive(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := NewWriter(&buf)
	for _, name := range []string{"first.txt", "second.txt"} {
		w := mustCreateHeader(t, zw, &FileHeader{Name: name, Method: Deflate, Modified: WriterCovStamp})
		mustWrite(t, w, bytes.Repeat([]byte(name+" "), 8))
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close the source archive: %v", err)
	}
	return buf.Bytes()
}

// WriterCovStubCompressor is a compressor that hands its bytes straight on and
// fails its Close on request. Closing the compressor is what flushes the last
// of an entry, so a failure there is a failure to write the entry.
type WriterCovStubCompressor struct {
	w        io.Writer
	closeErr error
}

func (c *WriterCovStubCompressor) Write(p []byte) (int, error) { return c.w.Write(p) }
func (c *WriterCovStubCompressor) Close() error                { return c.closeErr }

// TestWriterCov_FlushPushesTheBufferedArchiveOut checks that Flush hands the
// bytes written so far to the destination. A Writer buffers 64 KiB, so a small
// archive is still entirely in memory until something flushes it.
func TestWriterCov_FlushPushesTheBufferedArchiveOut(t *testing.T) {
	var buf bytes.Buffer
	zw := NewWriter(&buf)
	w := mustCreateHeader(t, zw, &FileHeader{Name: "buffered.txt", Method: Store, Modified: WriterCovStamp})
	mustWrite(t, w, []byte("contents"))
	if buf.Len() != 0 {
		t.Fatalf("%d bytes reached the destination before any flush", buf.Len())
	}
	if err := zw.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("Flush left the whole archive in the buffer")
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
}

// TestWriterCov_TheSameHeaderTwiceIsRejected covers the duplicate check. The
// same FileHeader value handed in twice in a row would describe two entries
// that share every field, including the one the writer fills in as it goes.
func TestWriterCov_TheSameHeaderTwiceIsRejected(t *testing.T) {
	t.Run("through CreateHeader", func(t *testing.T) {
		zw := NewWriter(new(bytes.Buffer))
		fh := &FileHeader{Name: "twice.txt", Method: Store, Modified: WriterCovStamp}
		w, err := zw.CreateHeader(fh)
		if err != nil {
			t.Fatalf("create the entry: %v", err)
		}
		mustWrite(t, w, []byte("contents"))
		if _, err := zw.CreateHeader(fh); err == nil {
			t.Fatal("the second CreateHeader with the same header was accepted")
		} else if !strings.Contains(err.Error(), "duplicate") {
			t.Errorf("CreateHeader reported %v, want a duplicate header error", err)
		}
	})

	t.Run("through CreateRaw", func(t *testing.T) {
		zw := NewWriter(new(bytes.Buffer))
		fh := &FileHeader{Name: "twice.txt", Method: Store, Modified: WriterCovStamp}
		w, err := zw.CreateRaw(fh)
		if err != nil {
			t.Fatalf("create the entry: %v", err)
		}
		mustWrite(t, w, []byte("contents"))
		if _, err := zw.CreateRaw(fh); err == nil {
			t.Fatal("the second CreateRaw with the same header was accepted")
		} else if !strings.Contains(err.Error(), "duplicate") {
			t.Errorf("CreateRaw reported %v, want a duplicate header error", err)
		}
	})
}

// TestWriterCov_NonUTF8ClearsTheUnicodeFlag checks that a header marked as not
// being UTF-8 comes out with the unicode flag off, whatever it was set to
// before: the flag says the name is UTF-8, and this header says it is not.
func TestWriterCov_NonUTF8ClearsTheUnicodeFlag(t *testing.T) {
	zw := NewWriter(new(bytes.Buffer))
	fh := &FileHeader{
		Name:     "\xff\xfe.txt",
		Method:   Store,
		NonUTF8:  true,
		Flags:    0x800,
		Modified: WriterCovStamp,
	}
	mustCreateHeader(t, zw, fh)
	if fh.Flags&0x800 != 0 {
		t.Errorf("flags are %#04x, want the unicode bit cleared", fh.Flags)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
}

// TestWriterCov_DirectoryEntryTakesNoContents checks what the writer hands
// back for a directory entry: an empty write is nothing to store and is
// accepted, and anything else is a caller writing file contents into a
// directory.
func TestWriterCov_DirectoryEntryTakesNoContents(t *testing.T) {
	zw := NewWriter(new(bytes.Buffer))
	w := mustCreateHeader(t, zw, &FileHeader{Name: "folder/", Modified: WriterCovStamp})
	n, err := w.Write(nil)
	if n != 0 || err != nil {
		t.Errorf("the empty write returned (%d, %v), want (0, nil)", n, err)
	}
	n, err = w.Write([]byte("contents"))
	if err == nil {
		t.Fatal("contents written to a directory entry were accepted")
	}
	if n != 0 {
		t.Errorf("the refused write reported %d bytes stored", n)
	}
	if !strings.Contains(err.Error(), "directory") {
		t.Errorf("the write reported %v, want a write-to-directory error", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
}

// TestWriterCov_DirectoryEntryHasItsOwnLocalHeader checks that a directory
// entry is a whole entry: the central directory record for it has to point at
// a local file header of its own, the way every other entry does. Without one
// the record points at whatever the archive happens to hold at that offset --
// the next entry's header, or the central directory itself for a directory
// written last -- and a reader following the offset reads that instead.
func TestWriterCov_DirectoryEntryHasItsOwnLocalHeader(t *testing.T) {
	var buf bytes.Buffer
	zw := NewWriter(&buf)
	for _, name := range []string{"folder/", "folder/nested/"} {
		if _, err := zw.CreateHeader(&FileHeader{Name: name, Modified: WriterCovStamp}); err != nil {
			t.Fatalf("create the directory entry %q: %v", name, err)
		}
	}
	w := mustCreateHeader(t, zw, &FileHeader{Name: "folder/nested/file.txt", Method: Deflate, Modified: WriterCovStamp})
	mustWrite(t, w, []byte("contents"))
	if err := zw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	raw := buf.Bytes()
	zr, err := NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatalf("read the archive back: %v", err)
	}
	if len(zr.File) != 3 {
		t.Fatalf("the archive holds %d entries, want 3", len(zr.File))
	}
	for _, f := range zr.File {
		at := f.headerOffset
		if at+fileHeaderLen > int64(len(raw)) {
			t.Fatalf("%s is said to start at offset %d, past the end of the %d byte archive", f.Name, at, len(raw))
		}
		if got := raw[at : at+4]; !bytes.Equal(got, []byte{'P', 'K', 0x03, 0x04}) {
			t.Fatalf("%s is said to start at offset %d, where the archive holds %x rather than a local file header", f.Name, at, got)
		}
		nameLen := int64(binary.LittleEndian.Uint16(raw[at+26 : at+28]))
		if at+fileHeaderLen+nameLen > int64(len(raw)) {
			t.Fatalf("the header at offset %d names %d bytes, past the end of the %d byte archive", at, nameLen, len(raw))
		}
		if got := string(raw[at+fileHeaderLen : at+fileHeaderLen+nameLen]); got != f.Name {
			t.Errorf("the header %s points at names %q", f.Name, got)
		}
	}
}

// TestWriterCov_WritingToAFinishedEntry checks that an entry left behind by
// starting the next one refuses further contents. Taking them would append
// bytes to a stream whose sizes and checksum have already been written out.
func TestWriterCov_WritingToAFinishedEntry(t *testing.T) {
	zw := NewWriter(new(bytes.Buffer))
	first := mustCreateHeader(t, zw, &FileHeader{Name: "first.txt", Method: Store, Modified: WriterCovStamp})
	mustWrite(t, first, []byte("contents"))
	mustCreateHeader(t, zw, &FileHeader{Name: "second.txt", Method: Store, Modified: WriterCovStamp})

	if _, err := first.Write([]byte("more")); err == nil {
		t.Fatal("the finished entry took more contents")
	} else if !strings.Contains(err.Error(), "closed") {
		t.Errorf("the write reported %v, want a write-to-closed-file error", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
}

// TestWriterCov_FinishingAnEntryTwice checks the guard on the entry's own
// close. The second call would write a second data descriptor after the one
// the entry already has, which a reader walking the entries would take for the
// start of whatever comes next.
func TestWriterCov_FinishingAnEntryTwice(t *testing.T) {
	zw := NewWriter(new(bytes.Buffer))
	w := mustCreateHeader(t, zw, &FileHeader{Name: "once.txt", Method: Store, Modified: WriterCovStamp})
	mustWrite(t, w, []byte("contents"))

	fw, ok := w.(*fileWriter)
	if !ok {
		t.Fatalf("a file entry handed back a %T", w)
	}
	if err := fw.close(); err != nil {
		t.Fatalf("finish the entry: %v", err)
	}
	if err := fw.close(); err == nil {
		t.Fatal("the entry was finished twice without complaint")
	} else if !strings.Contains(err.Error(), "closed twice") {
		t.Errorf("the second close reported %v, want a closed-twice error", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
}

// TestWriterCov_CompressorThatWillNotStart checks that a compressor which
// refuses to open a stream stops the entry there, rather than leaving a local
// header with nothing behind it.
func TestWriterCov_CompressorThatWillNotStart(t *testing.T) {
	zw := NewWriter(new(bytes.Buffer))
	zw.RegisterCompressor(Store, func(io.Writer) (io.WriteCloser, error) {
		return nil, errWriterCovBoom
	})
	_, err := zw.CreateHeader(&FileHeader{Name: "entry.txt", Method: Store, Modified: WriterCovStamp})
	if !errors.Is(err, errWriterCovBoom) {
		t.Fatalf("CreateHeader reported %v, want the compressor's failure", err)
	}
}

// TestWriterCov_CompressorThatWillNotClose checks that a compressor failing on
// close is reported. Closing it is what puts the tail of the entry into the
// archive, so the failure means the entry is short.
func TestWriterCov_CompressorThatWillNotClose(t *testing.T) {
	zw := NewWriter(new(bytes.Buffer))
	zw.RegisterCompressor(Store, func(w io.Writer) (io.WriteCloser, error) {
		return &WriterCovStubCompressor{w: w, closeErr: errWriterCovBoom}, nil
	})
	w := mustCreateHeader(t, zw, &FileHeader{Name: "entry.txt", Method: Store, Modified: WriterCovStamp})
	mustWrite(t, w, []byte("contents"))
	if err := zw.Close(); !errors.Is(err, errWriterCovBoom) {
		t.Fatalf("Close reported %v, want the compressor's failure", err)
	}
}

// TestWriterCov_DeflateLevelIsHonoured checks that an entry asking for a
// compression level goes through a deflate stream set to it and still reads
// back byte for byte.
func TestWriterCov_DeflateLevelIsHonoured(t *testing.T) {
	body := bytes.Repeat([]byte("compressible payload "), 64)
	var buf bytes.Buffer
	zw := NewWriter(&buf)
	w := mustCreateHeader(t, zw, &FileHeader{
		Name:     "levelled.txt",
		Method:   Deflate,
		Level:    9,
		Modified: WriterCovStamp,
	})
	mustWrite(t, w, body)
	if err := zw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	zr, err := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("read the archive back: %v", err)
	}
	if len(zr.File) != 1 {
		t.Fatalf("the archive holds %d entries, want 1", len(zr.File))
	}
	rc, err := zr.File[0].Open()
	if err != nil {
		t.Fatalf("open the entry: %v", err)
	}
	closeAt(t, rc)
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read the entry: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("the entry came back as %d bytes, want the %d written", len(got), len(body))
	}
	if zr.File[0].CompressedSize64 >= uint64(len(body)) {
		t.Errorf("the entry is %d bytes compressed against %d written, so nothing was compressed", zr.File[0].CompressedSize64, len(body))
	}
}

// TestWriterCov_EntryOverFourGigabytes checks the sizes an entry too large for
// the 32-bit fields comes out with: both fields carry the zip64 sentinel, the
// entry asks for a reader that understands zip64, and the data descriptor
// behind it is the 24 byte form that can hold the real numbers. The byte count
// is set on the entry's own counter rather than written, so that the test does
// not have to push four gigabytes through a compressor.
func TestWriterCov_EntryOverFourGigabytes(t *testing.T) {
	var buf bytes.Buffer
	zw := NewWriter(&buf)
	fh := &FileHeader{Name: "huge.bin", Method: Deflate, Modified: WriterCovStamp}
	w := mustCreateHeader(t, zw, fh)
	mustWrite(t, w, []byte("contents"))

	fw, ok := w.(*fileWriter)
	if !ok {
		t.Fatalf("a file entry handed back a %T", w)
	}
	fw.rawCount.count = uint32max

	if err := zw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	if fh.UncompressedSize != uint32max || fh.CompressedSize != uint32max {
		t.Errorf("the 32-bit fields hold %d and %d, want the %d sentinel in both", fh.CompressedSize, fh.UncompressedSize, uint32(uint32max))
	}
	if fh.ReaderVersion != zipVersion45 {
		t.Errorf("the entry asks for reader version %d, want %d", fh.ReaderVersion, zipVersion45)
	}

	raw := buf.Bytes()
	dirAt := bytes.Index(raw, []byte{'P', 'K', 0x01, 0x02})
	if dirAt < dataDescriptor64Len {
		t.Fatalf("the central directory starts at %d, too early to hold a data descriptor before it", dirAt)
	}
	desc := raw[dirAt-dataDescriptor64Len : dirAt]
	if got := binary.LittleEndian.Uint32(desc[0:4]); got != uint32(dataDescriptorSignature) {
		t.Fatalf("the 24 bytes before the central directory start with %#08x, want a data descriptor", got)
	}
	if got := binary.LittleEndian.Uint64(desc[16:24]); got != uint32max {
		t.Errorf("the data descriptor says the entry is %d bytes, want %d", got, uint64(uint32max))
	}
}

// TestWriterCov_EntryPastTheFourGigabyteMark checks an entry whose local
// header sits beyond what the 32-bit offset field can hold: the directory
// carries the sentinel there and the real offset goes in the zip64 record. The
// offset is set on the writer rather than written, so no four gigabytes of
// padding are needed to get there.
func TestWriterCov_EntryPastTheFourGigabyteMark(t *testing.T) {
	var buf bytes.Buffer
	zw := NewWriter(&buf)
	zw.SetOffset(int64(uint32max) + 1)
	w := mustCreateHeader(t, zw, &FileHeader{Name: "far.txt", Method: Store, Modified: WriterCovStamp})
	mustWrite(t, w, []byte("contents"))
	if err := zw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	raw := buf.Bytes()
	dirAt := bytes.Index(raw, []byte{'P', 'K', 0x01, 0x02})
	if dirAt < 0 || dirAt+46 > len(raw) {
		t.Fatalf("no central directory header in the %d byte archive", len(raw))
	}
	if got := binary.LittleEndian.Uint32(raw[dirAt+42 : dirAt+46]); got != uint32max {
		t.Errorf("the directory puts the entry at offset %d, want the %d sentinel", got, uint32(uint32max))
	}
	endAt := bytes.Index(raw, []byte{'P', 'K', 0x05, 0x06})
	if endAt < 0 || endAt+20 > len(raw) {
		t.Fatalf("no end of central directory record in the %d byte archive", len(raw))
	}
	if got := binary.LittleEndian.Uint32(raw[endAt+16 : endAt+20]); got != uint32max {
		t.Errorf("the end record puts the directory at offset %d, want the %d sentinel", got, uint32(uint32max))
	}
	if !bytes.Contains(raw, []byte{'P', 'K', 0x06, 0x06}) {
		t.Error("the archive has no zip64 end record, which is where the real offsets live")
	}
}

// TestWriterCov_TorrentZipDirectoryEntries checks the shape a directory entry
// takes in torrentzip mode, where it is a deflate entry holding the two byte
// empty deflate block rather than a stored entry of nothing.
func TestWriterCov_TorrentZipDirectoryEntries(t *testing.T) {
	for _, tc := range []struct {
		name   string
		create func(zw *Writer, fh *FileHeader) (io.Writer, error)
	}{
		{"through CreateHeader", (*Writer).CreateHeader},
		{"through CreateRaw", (*Writer).CreateRaw},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			zw := NewWriter(&buf)
			zw.SetTorrentZip(true)
			fh := &FileHeader{Name: "folder/"}
			if _, err := tc.create(zw, fh); err != nil {
				t.Fatalf("create the directory entry: %v", err)
			}
			if err := zw.Close(); err != nil {
				t.Fatalf("close writer: %v", err)
			}
			if fh.Method != Deflate {
				t.Errorf("the directory entry uses method %d, want %d", fh.Method, Deflate)
			}
			if fh.Flags != 2 {
				t.Errorf("the directory entry carries flags %#04x, want 0x0002", fh.Flags)
			}
			if fh.CompressedSize64 != 2 || fh.UncompressedSize64 != 0 || fh.CRC32 != 0 {
				t.Errorf("the directory entry is %d bytes over %d with checksum %#08x, want 2 over 0 with 0",
					fh.CompressedSize64, fh.UncompressedSize64, fh.CRC32)
			}
			entry, ok := findLocalEntry(t, buf.Bytes(), "folder/")
			if !ok {
				t.Fatalf("the archive holds no folder/ entry")
			}
			if !bytes.Equal(entry.payload, []byte{0x03, 0x00}) {
				t.Errorf("the directory entry holds %x, want the empty deflate block 0300", entry.payload)
			}
		})
	}
}

// TestWriterCov_CopyTakesEntriesAsTheyStand checks copying entries from one
// archive into another: the compressed bytes are moved across untouched and
// the result reads back as the original did.
func TestWriterCov_CopyTakesEntriesAsTheyStand(t *testing.T) {
	source := WriterCovSourceArchive(t)
	zr, err := NewReader(bytes.NewReader(source), int64(len(source)))
	if err != nil {
		t.Fatalf("read the source archive: %v", err)
	}

	var buf bytes.Buffer
	zw := NewWriter(&buf)
	for _, f := range zr.File {
		if err := zw.Copy(f); err != nil {
			t.Fatalf("copy %s: %v", f.Name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	copied, err := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("read the copy back: %v", err)
	}
	if len(copied.File) != len(zr.File) {
		t.Fatalf("the copy holds %d entries, want %d", len(copied.File), len(zr.File))
	}
	for i, f := range copied.File {
		want := zr.File[i]
		if f.Name != want.Name || f.CRC32 != want.CRC32 || f.CompressedSize64 != want.CompressedSize64 {
			t.Errorf("entry %d came out as %s (%#08x, %d bytes), want %s (%#08x, %d bytes)",
				i, f.Name, f.CRC32, f.CompressedSize64, want.Name, want.CRC32, want.CompressedSize64)
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open %s in the copy: %v", f.Name, err)
		}
		got, err := io.ReadAll(rc)
		if cerr := rc.Close(); cerr != nil {
			t.Errorf("close %s in the copy: %v", f.Name, cerr)
		}
		if err != nil {
			t.Fatalf("read %s in the copy: %v", f.Name, err)
		}
		if wantBody := bytes.Repeat([]byte(f.Name+" "), 8); !bytes.Equal(got, wantBody) {
			t.Errorf("%s came back as %q", f.Name, got)
		}
	}
}

// TestWriterCov_CopyingAnEntryWithNoArchiveBehindIt checks the error Copy
// reports for an entry that is not backed by an archive at all: there are no
// compressed bytes to take from it.
func TestWriterCov_CopyingAnEntryWithNoArchiveBehindIt(t *testing.T) {
	zw := NewWriter(new(bytes.Buffer))
	if err := zw.Copy(&File{FileHeader: FileHeader{Name: "detached.txt"}}); err == nil {
		t.Fatal("an entry with no archive behind it was copied")
	}
	if err := zw.Copy(nil); err == nil {
		t.Fatal("a nil entry was copied")
	}
}

// TestWriterCov_ASinkThatStopsIsAlwaysReported walks every byte offset of a
// handful of archives and requires the writer to report a destination that
// stops taking bytes there. The shapes differ in which writes they make: an
// ordinary entry with an extra field and comments, an entry beyond the four
// gigabyte mark, an encrypted one, the torrentzip directory entries, an entry
// carrying a seek index, and entries copied from another archive.
func TestWriterCov_ASinkThatStopsIsAlwaysReported(t *testing.T) {
	source := WriterCovSourceArchive(t)

	for _, tc := range []struct {
		name  string
		build func(zw *Writer) error
	}{
		{"entries with extra fields and comments", func(zw *Writer) error {
			if err := zw.SetComment("archive comment"); err != nil {
				return err
			}
			for _, name := range []string{"alpha.txt", "beta.txt"} {
				w, err := zw.CreateHeader(&FileHeader{
					Name:     name,
					Comment:  "entry comment",
					Method:   Deflate,
					Modified: WriterCovStamp,
				})
				if err != nil {
					return err
				}
				if _, err := w.Write([]byte("contents of " + name)); err != nil {
					return err
				}
			}
			return zw.Close()
		}},
		{"a directory entry and a file inside it", func(zw *Writer) error {
			if _, err := zw.CreateHeader(&FileHeader{Name: "folder/", Modified: WriterCovStamp}); err != nil {
				return err
			}
			w, err := zw.CreateHeader(&FileHeader{Name: "folder/file.txt", Method: Deflate, Modified: WriterCovStamp})
			if err != nil {
				return err
			}
			if _, err := w.Write([]byte("contents")); err != nil {
				return err
			}
			return zw.Close()
		}},
		{"an entry past the four gigabyte mark", func(zw *Writer) error {
			zw.SetOffset(int64(uint32max) + 1)
			w, err := zw.CreateHeader(&FileHeader{Name: "far.txt", Method: Store, Modified: WriterCovStamp})
			if err != nil {
				return err
			}
			if _, err := w.Write([]byte("contents")); err != nil {
				return err
			}
			return zw.Close()
		}},
		{"an encrypted entry", func(zw *Writer) error {
			w, err := zw.CreateHeader(&FileHeader{
				Name:     "secret.txt",
				Method:   Deflate,
				Password: "entry secret",
				Modified: WriterCovStamp,
			})
			if err != nil {
				return err
			}
			if _, err := w.Write([]byte("contents")); err != nil {
				return err
			}
			return zw.Close()
		}},
		{"a torrentzip directory entry", func(zw *Writer) error {
			zw.SetTorrentZip(true)
			if _, err := zw.CreateHeader(&FileHeader{Name: "folder/"}); err != nil {
				return err
			}
			return zw.Close()
		}},
		{"a torrentzip directory entry written raw", func(zw *Writer) error {
			zw.SetTorrentZip(true)
			if _, err := zw.CreateRaw(&FileHeader{Name: "folder/"}); err != nil {
				return err
			}
			return zw.Close()
		}},
		{"an entry carrying a seek index", func(zw *Writer) error {
			w, err := zw.CreateHeader(&FileHeader{
				Name:          "indexed.bin",
				Method:        Deflate,
				SeekChunkSize: 1024,
				Modified:      WriterCovStamp,
			})
			if err != nil {
				return err
			}
			if _, err := w.Write(bytes.Repeat([]byte("indexed payload "), 256)); err != nil {
				return err
			}
			return zw.Close()
		}},
		{"entries copied from another archive", func(zw *Writer) error {
			zr, err := NewReader(bytes.NewReader(source), int64(len(source)))
			if err != nil {
				return err
			}
			for _, f := range zr.File {
				if err := zw.Copy(f); err != nil {
					return err
				}
			}
			return zw.Close()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			WriterCovEachSinkFailure(t, tc.build)
		})
	}
}

// WriterCovFileInfo describes a file that need not exist, so that a test can
// hand the writer sizes and modes no filesystem here would produce.
type WriterCovFileInfo struct {
	name string
	size int64
	mode fs.FileMode
	mod  time.Time
}

func (fi WriterCovFileInfo) Name() string       { return fi.name }
func (fi WriterCovFileInfo) Size() int64        { return fi.size }
func (fi WriterCovFileInfo) Mode() fs.FileMode  { return fi.mode }
func (fi WriterCovFileInfo) ModTime() time.Time { return fi.mod }
func (fi WriterCovFileInfo) IsDir() bool        { return fi.mode.IsDir() }
func (fi WriterCovFileInfo) Sys() any           { return nil }

// WriterCovDirEntry is a directory entry that either refuses to describe what
// it names or describes it as a file of a size no file has.
type WriterCovDirEntry struct {
	fs.DirEntry
	infoErr error
	badSize bool
}

func (d WriterCovDirEntry) Info() (fs.FileInfo, error) {
	if d.infoErr != nil {
		return nil, d.infoErr
	}
	info, err := d.DirEntry.Info()
	if err != nil {
		return nil, err
	}
	if d.badSize {
		return WriterCovFileInfo{name: info.Name(), size: -1, mode: info.Mode(), mod: info.ModTime()}, nil
	}
	return info, nil
}

// WriterCovHookFS is a small in-memory tree whose failures the test chooses:
// which name refuses to open, which entry refuses to describe itself, and
// which one reports a size no file has.
type WriterCovHookFS struct {
	fstest.MapFS
	openErr map[string]error
	infoErr map[string]error
	badSize map[string]bool
}

func (f WriterCovHookFS) Open(name string) (fs.File, error) {
	if err := f.openErr[name]; err != nil {
		return nil, err
	}
	return f.MapFS.Open(name)
}

func (f WriterCovHookFS) ReadDir(name string) ([]fs.DirEntry, error) {
	entries, err := f.MapFS.ReadDir(name)
	if err != nil {
		return nil, err
	}
	for i, e := range entries {
		full := path.Join(name, e.Name())
		switch {
		case f.infoErr[full] != nil:
			entries[i] = WriterCovDirEntry{DirEntry: e, infoErr: f.infoErr[full]}
		case f.badSize[full]:
			entries[i] = WriterCovDirEntry{DirEntry: e, badSize: true}
		}
	}
	return entries, nil
}

// WriterCovBrokenFS is a filesystem where nothing can be opened at all, not
// even the root the walk starts from.
type WriterCovBrokenFS struct{ err error }

func (f WriterCovBrokenFS) Open(string) (fs.File, error) { return nil, f.err }

// TestWriterCov_AddFSFailures covers what stops a whole directory tree from
// being packed. Each of these used to end the walk, and each has to reach the
// caller rather than leaving a half-written archive reported as complete.
func TestWriterCov_AddFSFailures(t *testing.T) {
	regular := fstest.MapFS{"plain.txt": &fstest.MapFile{Data: []byte("contents"), Mode: 0o644}}

	t.Run("the walk cannot start", func(t *testing.T) {
		zw := NewWriter(new(bytes.Buffer))
		if err := zw.AddFS(WriterCovBrokenFS{err: errWriterCovBoom}); !errors.Is(err, errWriterCovBoom) {
			t.Fatalf("AddFS reported %v, want the filesystem's failure", err)
		}
	})

	t.Run("an entry will not describe itself", func(t *testing.T) {
		zw := NewWriter(new(bytes.Buffer))
		fsys := WriterCovHookFS{MapFS: regular, infoErr: map[string]error{"plain.txt": errWriterCovBoom}}
		if err := zw.AddFS(fsys); !errors.Is(err, errWriterCovBoom) {
			t.Fatalf("AddFS reported %v, want the filesystem's failure", err)
		}
	})

	t.Run("an entry that is neither a file nor a directory", func(t *testing.T) {
		zw := NewWriter(new(bytes.Buffer))
		fsys := fstest.MapFS{"pipe": &fstest.MapFile{Mode: fs.ModeNamedPipe | 0o644}}
		err := zw.AddFS(fsys)
		if err == nil {
			t.Fatal("a named pipe was packed as if it were a file")
		}
		if !strings.Contains(err.Error(), "non-regular") {
			t.Errorf("AddFS reported %v, want a non-regular file error", err)
		}
	})

	t.Run("an entry of a size no file has", func(t *testing.T) {
		zw := NewWriter(new(bytes.Buffer))
		fsys := WriterCovHookFS{MapFS: regular, badSize: map[string]bool{"plain.txt": true}}
		err := zw.AddFS(fsys)
		if err == nil {
			t.Fatal("an entry reporting a negative size was packed")
		}
		if !strings.Contains(err.Error(), "size") {
			t.Errorf("AddFS reported %v, want a size error", err)
		}
	})

	t.Run("the entry cannot be started", func(t *testing.T) {
		sink := &cutoffWriter{err: errWriterCovSink}
		zw := writerWithBufferSize(sink, 1)
		if err := zw.AddFS(regular); !errors.Is(err, errWriterCovSink) {
			t.Fatalf("AddFS reported %v, want the sink's failure", err)
		}
	})

	t.Run("the file cannot be read", func(t *testing.T) {
		zw := NewWriter(new(bytes.Buffer))
		fsys := WriterCovHookFS{MapFS: regular, openErr: map[string]error{"plain.txt": errWriterCovBoom}}
		if err := zw.AddFS(fsys); !errors.Is(err, errWriterCovBoom) {
			t.Fatalf("AddFS reported %v, want the filesystem's failure", err)
		}
	})
}

// TestWriterCov_AddFSKeepsDirectories checks that a tree comes across with its
// directories: they are entries of their own, named with the trailing slash
// that marks them, and they hold nothing.
func TestWriterCov_AddFSKeepsDirectories(t *testing.T) {
	fsys := fstest.MapFS{
		"top.txt":           &fstest.MapFile{Data: []byte("top"), Mode: 0o644},
		"folder/inner.txt":  &fstest.MapFile{Data: []byte("inner"), Mode: 0o644},
		"folder/deeper/x.b": &fstest.MapFile{Data: []byte("deep"), Mode: 0o644},
	}
	var buf bytes.Buffer
	zw := NewWriter(&buf)
	if err := zw.AddFS(fsys); err != nil {
		t.Fatalf("AddFS: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	zr, err := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("read the archive back: %v", err)
	}
	got := make(map[string]bool, len(zr.File))
	for _, f := range zr.File {
		got[f.Name] = true
	}
	for _, want := range []string{"top.txt", "folder/", "folder/inner.txt", "folder/deeper/", "folder/deeper/x.b"} {
		if !got[want] {
			t.Errorf("the archive has no %q entry, it holds %v", want, got)
		}
	}
}

// TestWriterCov_EncapsulateXCryptZip checks the exported wrapper around the
// encapsulation step: a staged archive goes in and an archive whose contents
// are hidden behind the stub comes out.
func TestWriterCov_EncapsulateXCryptZip(t *testing.T) {
	dir := t.TempDir()
	staged := filepath.Join(dir, "staged.zip")
	f, err := os.Create(staged)
	if err != nil {
		t.Fatalf("create %s: %v", staged, err)
	}
	closeAt(t, f)
	zw := NewWriter(f)
	w := mustCreateHeader(t, zw, &FileHeader{Name: "inside.txt", Method: Store, Modified: WriterCovStamp})
	mustWrite(t, w, []byte("staged contents"))
	if err := zw.Close(); err != nil {
		t.Fatalf("close the staged archive: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", staged, err)
	}

	final := filepath.Join(dir, "final.zip")
	if err := EncapsulateXCryptZip(final, staged, "a password"); err != nil {
		t.Fatalf("encapsulate: %v", err)
	}

	zr, err := OpenReader(final)
	if err != nil {
		t.Fatalf("open %s: %v", final, err)
	}
	closeAt(t, zr)
	names := make([]string, 0, len(zr.File))
	for _, entry := range zr.File {
		names = append(names, entry.Name)
	}
	want := []string{"README_ENCRYPTED.txt", ".zipext/xcrypt/payload.enc", ".zipext/xcrypt/crypto.hdr"}
	if len(names) != len(want) {
		t.Fatalf("the encapsulated archive holds %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("the encapsulated archive holds %v, want %v", names, want)
		}
	}
	raw, err := os.ReadFile(final)
	if err != nil {
		t.Fatalf("read %s: %v", final, err)
	}
	if bytes.Contains(raw, []byte("staged contents")) {
		t.Error("the staged contents are in the clear in the encapsulated archive")
	}
}

// TestWriterCov_EncapsulateAStagedArchiveThatCannotBeRead checks the report
// when the staged archive is there to be looked at but not to be read: it is
// the payload of the archive being produced, so an encapsulation that carried
// on would write out an archive with nothing inside it.
func TestWriterCov_EncapsulateAStagedArchiveThatCannotBeRead(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a file's permission bits do not stop a read on Windows")
	}
	dir := t.TempDir()
	staged := filepath.Join(dir, "staged.zip")
	mustWriteFile(t, staged, []byte("PK\x05\x06"), 0o000)
	if f, err := os.Open(staged); err == nil {
		if cerr := f.Close(); cerr != nil {
			t.Errorf("close %s: %v", staged, cerr)
		}
		t.Skip("this user can read a file with no permission bits set")
	}

	final := filepath.Join(dir, "final.zip")
	if err := EncapsulateXCryptZip(final, staged, "a password"); err == nil {
		t.Fatal("a staged archive that cannot be read was encapsulated all the same")
	} else if !errors.Is(err, fs.ErrPermission) {
		t.Errorf("encapsulate reported %v, want the refused read", err)
	}
}

// TestWriterCov_HeaderFileInfo checks what a FileHeader says about itself when
// it is asked to stand in for a file: the name without its directory, the size
// from whichever of the two fields carries it, and the mode, type and
// modification time the entry was given.
func TestWriterCov_HeaderFileInfo(t *testing.T) {
	for _, tc := range []struct {
		name string
		fh   *FileHeader
		size int64
	}{
		{
			name: "the 64-bit size when it is set",
			fh: &FileHeader{
				Name:               "folder/big.bin",
				UncompressedSize:   7,
				UncompressedSize64: uint64(uint32max) + 9,
			},
			size: int64(uint32max) + 9,
		},
		{
			name: "the 32-bit size when the other one is not",
			fh: &FileHeader{
				Name:             "folder/small.bin",
				UncompressedSize: 11,
			},
			size: 11,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.fh.SetComment("a comment")
			if tc.fh.Comment != "a comment" {
				t.Errorf("the comment came out as %q", tc.fh.Comment)
			}
			tc.fh.Modified = WriterCovStamp
			tc.fh.SetMode(0o640)

			fi := tc.fh.FileInfo()
			if got := fi.Name(); got != path.Base(tc.fh.Name) {
				t.Errorf("the name is %q, want %q", got, path.Base(tc.fh.Name))
			}
			if got := fi.Size(); got != tc.size {
				t.Errorf("the size is %d, want %d", got, tc.size)
			}
			if got := fi.ModTime(); !got.Equal(WriterCovStamp) {
				t.Errorf("the modification time is %v, want %v", got, WriterCovStamp)
			}
			if fi.IsDir() {
				t.Error("a file entry says it is a directory")
			}
			if got := fi.Mode().Perm(); got != 0o640 {
				t.Errorf("the permissions are %v, want %v", got, fs.FileMode(0o640))
			}
			de, ok := fi.(fs.DirEntry)
			if !ok {
				t.Fatalf("the file info is a %T, which is not a directory entry", fi)
			}
			if got := de.Type(); got != fi.Mode().Type() {
				t.Errorf("the entry type is %v, want %v", got, fi.Mode().Type())
			}
			again, err := de.Info()
			if err != nil {
				t.Fatalf("the entry would not describe itself: %v", err)
			}
			if again.Size() != tc.size {
				t.Errorf("the entry describes itself as %d bytes, want %d", again.Size(), tc.size)
			}
			if got, ok := fi.Sys().(*FileHeader); !ok || got != tc.fh {
				t.Errorf("the underlying value is %T, want the header itself", fi.Sys())
			}
			if got, ok := fi.(interface{ String() string }); !ok {
				t.Error("the file info does not format itself")
			} else if !strings.Contains(got.String(), path.Base(tc.fh.Name)) {
				t.Errorf("the formatted entry is %q, which does not name the file", got.String())
			}
		})
	}
}

// TestWriterCov_FileInfoHeaderAboveTheThirtyTwoBitField checks that a file too
// large for the 32-bit size field is described with the sentinel there and the
// real size in the 64-bit one.
func TestWriterCov_FileInfoHeaderAboveTheThirtyTwoBitField(t *testing.T) {
	const size = int64(uint32max) + 5
	fh, err := FileInfoHeader(WriterCovFileInfo{
		name: "huge.bin",
		size: size,
		mode: 0o644,
		mod:  WriterCovStamp,
	})
	if err != nil {
		t.Fatalf("FileInfoHeader: %v", err)
	}
	if fh.UncompressedSize != uint32max {
		t.Errorf("the 32-bit size is %d, want the %d sentinel", fh.UncompressedSize, uint32(uint32max))
	}
	if fh.UncompressedSize64 != uint64(size) {
		t.Errorf("the 64-bit size is %d, want %d", fh.UncompressedSize64, size)
	}
}

// TestWriterCov_TimeZoneOutOfRange checks the zone an out of range offset
// produces. Offsets read out of an archive are whatever the bytes say, and no
// place on earth is sixteen hours from UTC, so those fall back to UTC.
func TestWriterCov_TimeZoneOutOfRange(t *testing.T) {
	for _, tc := range []struct {
		name    string
		offset  time.Duration
		seconds int
	}{
		{"two hours east", 2 * time.Hour, 2 * 60 * 60},
		{"further east than any zone", 16 * time.Hour, 0},
		{"further west than any zone", -13 * time.Hour, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, got := time.Now().In(timeZone(tc.offset)).Zone()
			if got != tc.seconds {
				t.Errorf("the zone is %d seconds from UTC, want %d", got, tc.seconds)
			}
		})
	}
}

// TestWriterCov_ModTimeFromTheMSDOSFields checks the deprecated accessor that
// reads the modification time back out of the two MS-DOS fields, which is all
// an archive written without an extended timestamp carries.
func TestWriterCov_ModTimeFromTheMSDOSFields(t *testing.T) {
	fh := &FileHeader{}
	fh.SetModTime(WriterCovStamp)
	// The MS-DOS time field counts in two second units, so it holds every
	// stamp used here exactly.
	if got := fh.ModTime(); !got.Equal(WriterCovStamp) {
		t.Errorf("the modification time came back as %v, want %v", got, WriterCovStamp)
	}
}

// TestWriterCov_ExtraFieldWalkStopsAtATruncatedTag covers what the extra field
// walks do with a tag whose declared length runs past the end of the field.
// Such a field is not readable beyond that point, so the walk stops there
// rather than reading whatever follows in memory.
func TestWriterCov_ExtraFieldWalkStopsAtATruncatedTag(t *testing.T) {
	// A readable tag, then one that claims 255 bytes of payload with none
	// behind it. The first is walked over, the second stops both the walk
	// looking for the encryption tag and the one looking for a timestamp.
	extra := []byte{
		0x01, 0x00, 0x02, 0x00, 0xaa, 0xbb,
		0x01, 0x99, 0xff, 0x00,
	}
	fh := &FileHeader{
		Name:     "truncated.txt",
		Method:   winzipAesExtraID,
		Modified: WriterCovStamp,
		Extra:    append([]byte(nil), extra...),
	}
	if got := fh.injectAutoExtras(); got != winzipAesExtraID {
		t.Errorf("the original method came back as %d, want %d: nothing in the truncated field says what it was", got, winzipAesExtraID)
	}
	if !bytes.HasPrefix(fh.Extra, extra) {
		t.Errorf("the extra field came out as %x, which is not the one that went in", fh.Extra)
	}
	if len(fh.Extra) <= len(extra) {
		t.Error("no timestamp tag was appended, so the truncated field was taken to hold one")
	}
	if got := binary.LittleEndian.Uint16(fh.Extra[len(extra) : len(extra)+2]); got != extTimeExtraID {
		t.Errorf("the appended tag is %#04x, want the extended timestamp %#04x", got, extTimeExtraID)
	}
}

// TestWriterCov_MSDOSAttributesToMode covers the mode an entry written by a
// DOS or Windows archiver comes back with, where all there is to go on is the
// directory and read-only attribute bits.
func TestWriterCov_MSDOSAttributesToMode(t *testing.T) {
	for _, tc := range []struct {
		name    string
		creator uint16
		attrs   uint32
		want    fs.FileMode
	}{
		{"a plain file", creatorFAT, 0, 0o666},
		{"a read-only file", creatorFAT, msdosReadOnly, 0o444},
		{"a directory", creatorVFAT, msdosDir, fs.ModeDir | 0o777},
		{"a read-only directory", creatorNTFS, msdosDir | msdosReadOnly, fs.ModeDir | 0o555},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fh := &FileHeader{
				Name:           "entry",
				CreatorVersion: tc.creator << 8,
				ExternalAttrs:  tc.attrs,
			}
			if got := fh.Mode(); got != tc.want {
				t.Errorf("the mode is %v, want %v", got, tc.want)
			}
		})
	}
}

// TestWriterCov_ModeRoundTripThroughUnixAttributes covers the two halves of
// the unix mode mapping against each other: what SetMode puts in the external
// attributes and what Mode reads back out of them, for the file types and the
// setuid, setgid and sticky bits that a header can carry. The mapping is
// arithmetic on the mode bits, so it is the same wherever it runs.
func TestWriterCov_ModeRoundTripThroughUnixAttributes(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode fs.FileMode
		want uint32
	}{
		{"a regular file", 0o644, s_IFREG | 0o644},
		{"a directory", fs.ModeDir | 0o755, s_IFDIR | 0o755},
		{"a symbolic link", fs.ModeSymlink | 0o777, s_IFLNK | 0o777},
		{"a named pipe", fs.ModeNamedPipe | 0o644, s_IFIFO | 0o644},
		{"a socket", fs.ModeSocket | 0o644, s_IFSOCK | 0o644},
		{"a block device", fs.ModeDevice | 0o660, s_IFBLK | 0o660},
		{"a character device", fs.ModeDevice | fs.ModeCharDevice | 0o620, s_IFCHR | 0o620},
		{"a set-user-id program", fs.ModeSetuid | 0o755, s_IFREG | s_ISUID | 0o755},
		{"a set-group-id program", fs.ModeSetgid | 0o755, s_IFREG | s_ISGID | 0o755},
		{"a sticky directory", fs.ModeDir | fs.ModeSticky | 0o777, s_IFDIR | s_ISVTX | 0o777},
		{"all three of them at once", fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky | 0o700, s_IFREG | s_ISUID | s_ISGID | s_ISVTX | 0o700},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fh := &FileHeader{Name: "entry"}
			fh.SetMode(tc.mode)
			if got := fh.ExternalAttrs >> 16; got != tc.want {
				t.Errorf("the external attributes hold %#o, want %#o", got, tc.want)
			}
			if got := fh.Mode(); got != tc.mode {
				t.Errorf("the mode came back as %v, want %v", got, tc.mode)
			}
		})
	}
}
