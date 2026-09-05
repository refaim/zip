package zip

import (
	"encoding/binary"
	"io"
	"os"
	"testing"
)

// The helpers below exist so that a test's setup step cannot fail silently and
// so that a handle a test opens is released even when the test stops at a
// t.Fatal in the middle.

// closeAt registers c to be closed when the test ends. It is the safety net
// for a handle the test owns, not the test's statement that the handle closed
// cleanly: the close error is dropped because the net also runs after the test
// already closed the handle itself, where a second close reports an error that
// says nothing about the archive. Call it on the line after the open
// succeeded, never on a nil closer -- cleanups run in reverse order of
// registration, so a net registered at the open runs before the removal of the
// t.TempDir the opened path lives in, while one registered earlier would run
// after it and leave the handle open across the removal.
func closeAt(t *testing.T, c io.Closer) {
	t.Helper()
	t.Cleanup(func() { _ = c.Close() })
}

// mustWrite writes data to w and fails the test if the write is short or
// errors.
func mustWrite(t *testing.T, w io.Writer, data []byte) {
	t.Helper()
	n, err := w.Write(data)
	if err != nil {
		t.Fatalf("write %d bytes: %v", len(data), err)
	}
	if n != len(data) {
		t.Fatalf("wrote %d of %d bytes and reported no error", n, len(data))
	}
}

// mustBinaryWrite writes v to w in the given byte order.
func mustBinaryWrite(t *testing.T, w io.Writer, order binary.ByteOrder, v any) {
	t.Helper()
	if err := binary.Write(w, order, v); err != nil {
		t.Fatalf("write %T: %v", v, err)
	}
}

// mustWriteFile creates path with the given contents and mode.
func mustWriteFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// mustMkdirAll creates dir and every missing parent of it.
func mustMkdirAll(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir -p %s: %v", dir, err)
	}
}

// mustMkdir creates dir, whose parent must already exist.
func mustMkdir(t *testing.T, dir string) {
	t.Helper()
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
}

// mustCreate adds an entry named name to zw and returns the writer for its
// contents.
func mustCreate(t *testing.T, zw *Writer, name string) io.Writer {
	t.Helper()
	w, err := zw.Create(name)
	if err != nil {
		t.Fatalf("create entry %q: %v", name, err)
	}
	return w
}

// mustCreateHeader adds the entry fh describes to zw and returns the writer
// for its contents.
func mustCreateHeader(t *testing.T, zw *Writer, fh *FileHeader) io.Writer {
	t.Helper()
	w, err := zw.CreateHeader(fh)
	if err != nil {
		t.Fatalf("create entry %q: %v", fh.Name, err)
	}
	return w
}
