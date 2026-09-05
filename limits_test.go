package zip

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// negativeSizeInfo is an fs.FileInfo that reports a size no file has. The
// interface lets any implementation say anything, and FileInfoHeader is a
// public entry point that takes one from the caller.
type negativeSizeInfo struct{ name string }

func (n negativeSizeInfo) Name() string       { return n.name }
func (n negativeSizeInfo) Size() int64        { return -1 }
func (n negativeSizeInfo) Mode() fs.FileMode  { return 0644 }
func (n negativeSizeInfo) ModTime() time.Time { return time.Unix(0, 0) }
func (n negativeSizeInfo) IsDir() bool        { return false }
func (n negativeSizeInfo) Sys() any           { return nil }

func TestFileInfoHeaderRejectsANegativeSize(t *testing.T) {
	fh, err := FileInfoHeader(negativeSizeInfo{name: "impossible.txt"})
	if err == nil {
		t.Fatalf("FileInfoHeader accepted a size of -1 and produced %+v", fh)
	}
	if fh != nil {
		t.Fatalf("FileInfoHeader returned a header alongside the error: %+v", fh)
	}
	if !strings.Contains(err.Error(), "impossible.txt") {
		t.Errorf("error %q does not name the file", err)
	}
}

// findExtraTag returns the payload of the first extra field carrying id, and
// whether it is there at all.
func findExtraTag(extra []byte, id uint16) ([]byte, bool) {
	for len(extra) >= 4 {
		tag := binary.LittleEndian.Uint16(extra[0:2])
		size := int(binary.LittleEndian.Uint16(extra[2:4]))
		extra = extra[4:]
		if size > len(extra) {
			return nil, false
		}
		if tag == id {
			return extra[:size], true
		}
		extra = extra[size:]
	}
	return nil, false
}

func TestInjectAutoExtrasWritesTheUnicodeComment(t *testing.T) {
	fh := &FileHeader{Name: "note.txt", Comment: "a comment that is not ASCII: что-то"}
	fh.injectAutoExtras()

	payload, ok := findExtraTag(fh.Extra, unicodeCommentExtraID)
	if !ok {
		t.Fatal("no Unicode comment extra field was written")
	}
	if len(payload) < 5 {
		t.Fatalf("the Unicode comment payload is %d bytes, too short for its own header", len(payload))
	}
	if payload[0] != 1 {
		t.Errorf("version byte is %d, want 1", payload[0])
	}
	if got := string(payload[5:]); got != fh.Comment {
		t.Errorf("payload holds %q, want %q", got, fh.Comment)
	}
}

func TestInjectAutoExtrasLeavesOutACommentTooLongForTheTag(t *testing.T) {
	// The tag's length is two bytes and it has to cover five bytes of its
	// own header as well as the comment, so this one has no spelling in
	// the field at all. Writing it anyway would announce a length that had
	// wrapped, and every extra field after this one would be read out of
	// the middle of the comment.
	fh := &FileHeader{Name: "note.txt", Comment: strings.Repeat("x", uint16max)}
	fh.injectAutoExtras()

	if _, ok := findExtraTag(fh.Extra, unicodeCommentExtraID); ok {
		t.Fatal("a comment too long for the tag was written into it anyway")
	}
}

func TestAppendNtfsAclLeavesOutADescriptorTooLongForTheTag(t *testing.T) {
	base := []byte{0xAA, 0xBB}

	short := appendNtfsAcl(base, []byte{1, 2, 3})
	if _, ok := findExtraTag(short[2:], ntfsAclExtraID); !ok {
		t.Fatal("a descriptor that fits was not written")
	}

	long := appendNtfsAcl(base, make([]byte, uint16max+1))
	if !bytes.Equal(long, base) {
		t.Fatalf("a descriptor too long for the tag changed the extra field: %d bytes", len(long))
	}
}

func TestAppendNtfsAclIgnoresAnEmptyDescriptor(t *testing.T) {
	base := []byte{0xAA}
	if got := appendNtfsAcl(base, nil); !bytes.Equal(got, base) {
		t.Fatalf("an empty descriptor changed the extra field: %v", got)
	}
}

func TestEncodeMappedStringRoundTrip(t *testing.T) {
	raw := []byte{0x66, 0x80, 0x81, 0xFF, 0x00}
	mapped := decodeUTF8OrMap(raw)
	if !strings.HasPrefix(mapped, MappedStringMarkStr) {
		t.Fatalf("bytes that are not UTF-8 were not mapped: %q", mapped)
	}
	if got := encodeMappedString(mapped); !bytes.Equal(got, raw) {
		t.Fatalf("round trip gave %v, want %v", got, raw)
	}
}

func TestEncodeMappedStringLeavesAnEditedNameAlone(t *testing.T) {
	// The mark says the rest is one private-use rune per byte. A name that
	// carries the mark but has been edited since -- renamed in a file
	// manager, say -- holds runes that stand for no byte, and narrowing
	// one anyway would put a byte of its low bits into the name.
	edited := MappedStringMarkStr + "plain text"
	got := encodeMappedString(edited)
	if !bytes.Equal(got, []byte(edited)) {
		t.Fatalf("an edited name was mapped anyway: %v", got)
	}
}

func TestEncodeMappedStringPassesThroughAnUnmarkedName(t *testing.T) {
	if got := encodeMappedString("plain.txt"); string(got) != "plain.txt" {
		t.Fatalf("an unmarked name came back as %q", got)
	}
}

func TestEncodeUTF16LEWritesSurrogatePairs(t *testing.T) {
	// The G clef is past the basic plane, so UTF-16 spells it as two code
	// units. Keeping the low sixteen bits of the rune instead would write
	// one unit and lose the character.
	got := encodeUTF16LE("\U0001D11E")
	want := []byte{0xFF, 0xFE, 0x34, 0xD8, 0x1E, 0xDD}
	if !bytes.Equal(got, want) {
		t.Fatalf("encodeUTF16LE gave % x, want % x", got, want)
	}
}

func TestNewZstdReaderReportsAStreamThatIsNotZstd(t *testing.T) {
	// Resetting the decoder onto a new stream reports nothing about the
	// stream; what is not zstd is found out on the first read of it.
	rc := newZstdReader(bytes.NewReader([]byte("this is not a zstd frame at all")))
	closeAt(t, rc)
	if _, err := rc.Read(make([]byte, 4)); err == nil {
		t.Fatal("a stream that is not zstd was accepted")
	}
}

func TestTrimToWritten(t *testing.T) {
	// preallocate may leave the file longer than the entry it holds, so
	// what was written has to become its length. A tail of zeros left
	// behind is a file bigger than the archive said and nothing further
	// down would notice.
	path := filepath.Join(t.TempDir(), "entry.bin")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		t.Fatalf("creating the file: %v", err)
	}
	closeAt(t, f)
	if err := f.Truncate(4096); err != nil {
		t.Fatalf("growing the file: %v", err)
	}
	mustWrite(t, f, []byte("nine byte"))

	if err := trimToWritten(f); err != nil {
		t.Fatalf("trimToWritten: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Size() != 9 {
		t.Fatalf("the file is %d bytes, want the 9 that were written", fi.Size())
	}
}

func TestTrimToWrittenReportsAFileThatWillNotTakeIt(t *testing.T) {
	// A handle opened only for reading can say where it is and cannot be
	// shortened, which is the one failure this has to report rather than
	// leave the file longer than it should be.
	path := filepath.Join(t.TempDir(), "entry.bin")
	mustWriteFile(t, path, []byte("already there"), 0600)

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("opening the file: %v", err)
	}
	closeAt(t, f)
	if err := trimToWritten(f); err == nil {
		t.Fatal("a file that cannot be shortened was reported as shortened")
	}
}

func TestTrimToWrittenReportsAHandleThatIsGone(t *testing.T) {
	// Nothing can be asked of a closed handle, the position included.
	path := filepath.Join(t.TempDir(), "entry.bin")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("creating the file: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("closing the file: %v", err)
	}
	if err := trimToWritten(f); err == nil {
		t.Fatal("a closed handle was reported as shortened")
	}
}

// failingReaderAt reports the same error for every read, which is how a
// truncated or unreadable archive behaves at a fixed offset.
type failingReaderAt struct{ err error }

func (f failingReaderAt) ReadAt([]byte, int64) (int, error) { return 0, f.err }

func TestF4RecoveryIgnoresAFooterItCannotRead(t *testing.T) {
	sentinel := errors.New("the tail of the file could not be read")
	ra := failingReaderAt{err: sentinel}
	got, size := checkF4Recovery(ra, 1024)
	if size != 1024 {
		t.Fatalf("size came back as %d, want 1024", size)
	}
	if _, ok := got.(failingReaderAt); !ok {
		t.Fatalf("the reader was replaced by %T", got)
	}
}
