package zip

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// memFile is an in-memory io.ReadWriteSeeker with a Truncate, which is all the
// Updater asks of what it is handed.
type memFile struct {
	data []byte
	off  int64
}

func (m *memFile) Read(p []byte) (int, error) {
	if m.off >= int64(len(m.data)) {
		return 0, io.EOF
	}
	n := copy(p, m.data[m.off:])
	m.off += int64(n)
	return n, nil
}

func (m *memFile) Write(p []byte) (int, error) {
	if need := m.off + int64(len(p)); need > int64(len(m.data)) {
		if need > int64(cap(m.data)) {
			grown := make([]byte, need, 2*need)
			copy(grown, m.data)
			m.data = grown
		}
		m.data = m.data[:need]
	}
	n := copy(m.data[m.off:], p)
	m.off += int64(n)
	return n, nil
}

func (m *memFile) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
		m.off = offset
	case io.SeekCurrent:
		m.off += offset
	case io.SeekEnd:
		m.off = int64(len(m.data)) + offset
	default:
		return 0, errors.New("bad whence")
	}
	if m.off < 0 {
		return 0, errors.New("negative position")
	}
	return m.off, nil
}

func (m *memFile) Truncate(size int64) error {
	if size < int64(len(m.data)) {
		m.data = m.data[:size]
	}
	return nil
}

// seekFailer counts Seek calls and fails the nth one, leaving everything else
// to the file underneath.
type seekFailer struct {
	inner  *memFile
	fail   int
	nSeeks int
	err    error
}

func (s *seekFailer) Read(p []byte) (int, error)  { return s.inner.Read(p) }
func (s *seekFailer) Write(p []byte) (int, error) { return s.inner.Write(p) }
func (s *seekFailer) Seek(offset int64, whence int) (int64, error) {
	s.nSeeks++
	if s.nSeeks == s.fail {
		return 0, s.err
	}
	return s.inner.Seek(offset, whence)
}

// negativeEnd reports a negative length for itself, which no file has but any
// io.ReadWriteSeeker may.
type negativeEnd struct{ memFile }

func (n *negativeEnd) Seek(offset int64, whence int) (int64, error) {
	if whence == io.SeekEnd {
		return -1, nil
	}
	return n.memFile.Seek(offset, whence)
}

// oneEntryArchive returns an archive holding a single stored entry.
func oneEntryArchive(t *testing.T, name string, data []byte) []byte {
	t.Helper()
	buf := new(bytes.Buffer)
	zw := NewWriter(buf)
	w, err := zw.CreateHeader(&FileHeader{Name: name, Method: Store})
	if err != nil {
		t.Fatalf("creating %q: %v", name, err)
	}
	mustWrite(t, w, data)
	if err := zw.Close(); err != nil {
		t.Fatalf("closing the writer: %v", err)
	}
	return buf.Bytes()
}

func TestNewUpdaterRefusesANegativeSize(t *testing.T) {
	// Everything the updater does measures against the size the handle
	// reports: the offsets the central directory gives are checked against
	// it, and a buffer for the end record is made from it.
	_, err := NewUpdater(&negativeEnd{})
	if err == nil {
		t.Fatal("a handle reporting a negative length was accepted")
	}
	if !strings.Contains(err.Error(), "negative") {
		t.Errorf("error %q does not say what is wrong", err)
	}
}

func TestUpdaterRefusesAnEntryOffsetPastTheDirectory(t *testing.T) {
	// RemoveFile shifts the bytes between two entries down and writes them
	// at the offset the central directory gave for the first of them, and
	// AppendHeader overwrites an entry in place at that same offset. An
	// entry that claims to start after the central directory would send
	// those writes into the middle of the file the caller handed over.
	raw := oneEntryArchive(t, "file.txt", []byte("content"))
	cd := centralHeaderOffset(t, raw, "file.txt")

	// Far past the end of a fixture of a few hundred bytes, and short of
	// the uint32max that would send the reader looking for a zip64 extra
	// instead.
	const pastTheEnd = 0xFFFFFF00

	patched := append([]byte{}, raw...)
	binary.LittleEndian.PutUint32(patched[cd+42:], pastTheEnd)

	_, err := NewUpdater(&memFile{data: patched})
	if !errors.Is(err, ErrFormat) {
		t.Fatalf("an entry offset past the central directory gave %v, want ErrFormat", err)
	}
	if err != nil && !strings.Contains(err.Error(), "file.txt") {
		t.Errorf("error %q does not name the entry", err)
	}
}

func TestUpdaterAcceptsAnEntryOffsetInsideTheArchive(t *testing.T) {
	raw := oneEntryArchive(t, "file.txt", []byte("content"))
	u, err := NewUpdater(&memFile{data: raw})
	if err != nil {
		t.Fatalf("a sound archive was refused: %v", err)
	}
	if got := u.Entries(); len(got) != 1 || got[0].Name != "file.txt" {
		t.Fatalf("the updater holds %d entries", len(got))
	}
	if err := u.Close(); err != nil {
		t.Fatalf("closing the updater: %v", err)
	}
}

func TestSectionReaderWriterReportsAFailedRestoreOnRead(t *testing.T) {
	// Everything else using this handle reads and writes at the position
	// it was left at, so a restore that did not happen silently moves all
	// of them.
	inner := &memFile{data: []byte("0123456789")}
	sentinel := errors.New("the handle would not seek back")
	// Calls: 1 reads the position, 2 goes to the offset, 3 restores.
	s := newSectionReaderWriter(&seekFailer{inner: inner, fail: 3, err: sentinel})

	buf := make([]byte, 4)
	n, err := s.ReadAt(buf, 2)
	if !errors.Is(err, sentinel) {
		t.Fatalf("ReadAt gave %v, want the restore error", err)
	}
	if n != 4 || string(buf) != "2345" {
		t.Errorf("ReadAt returned %q, %d: the bytes it did read should still come back", buf[:n], n)
	}
}

func TestSectionReaderWriterReportsAFailedRestoreOnWrite(t *testing.T) {
	inner := &memFile{data: []byte("0123456789")}
	sentinel := errors.New("the handle would not seek back")
	s := newSectionReaderWriter(&seekFailer{inner: inner, fail: 3, err: sentinel})

	if _, err := s.WriteAt([]byte("ab"), 1); !errors.Is(err, sentinel) {
		t.Fatalf("WriteAt gave %v, want the restore error", err)
	}
	if string(inner.data) != "0ab3456789" {
		t.Errorf("the write itself did not land: %q", inner.data)
	}
}

func TestSectionReaderWriterRestoresThePosition(t *testing.T) {
	inner := &memFile{data: []byte("0123456789")}
	s := newSectionReaderWriter(inner)
	if _, err := inner.Seek(7, io.SeekStart); err != nil {
		t.Fatalf("seeking: %v", err)
	}

	buf := make([]byte, 3)
	if _, err := s.ReadAt(buf, 0); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if inner.off != 7 {
		t.Errorf("the position is %d after a ReadAt, want it back at 7", inner.off)
	}

	if _, err := s.WriteAt([]byte("z"), 0); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	if inner.off != 7 {
		t.Errorf("the position is %d after a WriteAt, want it back at 7", inner.off)
	}
}

func TestUpdaterRefusesAFieldTooLongForItsHeader(t *testing.T) {
	// The name, the extra field and the comment each have a two-byte
	// length in the central directory. A longer one used to be written
	// under a length that had wrapped, which is a directory no reader can
	// walk; now it is a write error naming the field. Entries hands back
	// the headers themselves, so a caller can put an over-long value into
	// one after the entry has been appended.
	for _, tc := range []struct {
		field string
		set   func(fh *FileHeader)
	}{
		{"file name", func(fh *FileHeader) { fh.Name = strings.Repeat("n", uint16max+1) }},
		{"extra field", func(fh *FileHeader) { fh.Extra = make([]byte, uint16max+1) }},
		{"file comment", func(fh *FileHeader) { fh.Comment = strings.Repeat("c", uint16max+1) }},
	} {
		t.Run(tc.field, func(t *testing.T) {
			raw := oneEntryArchive(t, "file.txt", []byte("content"))
			u, err := NewUpdater(&memFile{data: raw})
			if err != nil {
				t.Fatalf("opening the updater: %v", err)
			}
			entries := u.Entries()
			if len(entries) != 1 {
				t.Fatalf("the updater holds %d entries", len(entries))
			}
			tc.set(entries[0])

			err = u.Close()
			if err == nil {
				t.Fatalf("a %s of %d bytes was written into a two-byte length", tc.field, uint16max+1)
			}
			if !strings.Contains(err.Error(), tc.field) {
				t.Errorf("error %q does not name the field", err)
			}
		})
	}
}

func TestUpdaterWritesAZip64EndRecordForManyEntries(t *testing.T) {
	// The end record counts entries in two bytes, so an archive with more
	// than that has to carry a zip64 end record and a locator naming it.
	raw := oneEntryArchive(t, "file.txt", []byte("content"))
	mem := &memFile{data: raw}
	u, err := NewUpdater(mem)
	if err != nil {
		t.Fatalf("opening the updater: %v", err)
	}

	base := u.dir[0]
	for len(u.dir) <= uint16max {
		clone := *base.FileHeader
		clone.Name = "e"
		u.dir = append(u.dir, &header{FileHeader: &clone, offset: base.offset})
	}
	if err := u.Close(); err != nil {
		t.Fatalf("closing the updater: %v", err)
	}

	var sig [4]byte
	binary.LittleEndian.PutUint32(sig[:], directory64EndSignature)
	if !bytes.Contains(mem.data, sig[:]) {
		t.Error("no zip64 end record was written for an archive of more than 65535 entries")
	}
	binary.LittleEndian.PutUint32(sig[:], directory64LocSignature)
	if !bytes.Contains(mem.data, sig[:]) {
		t.Error("no zip64 end locator was written")
	}
}

func TestUpdaterRoundTripThroughAFile(t *testing.T) {
	// The in-memory cases above leave the on-disk path untested; this one
	// walks it end to end so the two cannot drift apart.
	dir := t.TempDir()
	path := filepath.Join(dir, "round.zip")
	mustWriteFile(t, path, oneEntryArchive(t, "first.txt", []byte("one")), 0600)

	fRW, err := os.OpenFile(path, os.O_RDWR, 0600)
	if err != nil {
		t.Fatalf("opening the archive: %v", err)
	}
	closeAt(t, fRW)
	u, err := NewUpdater(fRW)
	if err != nil {
		t.Fatalf("opening the updater: %v", err)
	}
	w, err := u.Append("second.txt", APPEND_MODE_KEEP_ORIGINAL)
	if err != nil {
		t.Fatalf("appending: %v", err)
	}
	mustWrite(t, w, []byte("two"))
	if err := u.Close(); err != nil {
		t.Fatalf("closing the updater: %v", err)
	}
	if err := fRW.Close(); err != nil {
		t.Fatalf("closing the file: %v", err)
	}

	rc, err := OpenReader(path)
	if err != nil {
		t.Fatalf("reading the archive back: %v", err)
	}
	closeAt(t, rc)
	got := map[string]string{}
	for _, f := range rc.File {
		r, oerr := f.Open()
		if oerr != nil {
			t.Fatalf("opening %q: %v", f.Name, oerr)
		}
		data, rerr := io.ReadAll(r)
		_ = r.Close()
		if rerr != nil {
			t.Fatalf("reading %q: %v", f.Name, rerr)
		}
		got[f.Name] = string(data)
	}
	if got["first.txt"] != "one" || got["second.txt"] != "two" {
		t.Fatalf("the updated archive holds %v", got)
	}
}
