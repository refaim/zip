package zip

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// safeWritesArchive returns an archive of one stored entry under the given
// name. It is spelled out here rather than shared so that the tests below
// stand on their own.
func safeWritesArchive(t *testing.T, name string, body []byte) []byte {
	t.Helper()
	buf := new(bytes.Buffer)
	zw := NewWriter(buf)
	w, err := zw.CreateHeader(&FileHeader{Name: name, Method: Store})
	if err != nil {
		t.Fatalf("creating %q: %v", name, err)
	}
	mustWrite(t, w, body)
	if err := zw.Close(); err != nil {
		t.Fatalf("closing the writer: %v", err)
	}
	return buf.Bytes()
}

// extractSafely extracts raw into dst with safe writes turned on and returns
// the extractor so the caller can ask what it counted.
func extractSafely(t *testing.T, raw []byte, dst string) (*Extractor, error) {
	t.Helper()
	e, err := NewExtractorFromReader(bytes.NewReader(raw), int64(len(raw)), dst,
		WithExtractorSafeWrites(true))
	if err != nil {
		t.Fatalf("building the extractor: %v", err)
	}
	closeAt(t, e)
	return e, e.Extract(context.Background())
}

func TestExtractor_SafeWritesMovesTheEntryIntoPlace(t *testing.T) {
	// The entry is written beside its name and moved onto it once it is
	// whole. The move happens after the handle that wrote the file has
	// been let go of: Windows will not rename a file it still has open,
	// and doing it the other way round made this option fail there for
	// every entry of every archive, with the temporary file left behind
	// because the sweep could not remove an open file either.
	body := []byte("written safely")
	raw := safeWritesArchive(t, "entry.bin", body)

	dst := t.TempDir()
	if _, err := extractSafely(t, raw, dst); err != nil {
		t.Fatalf("extraction failed: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dst, "entry.bin"))
	if err != nil {
		t.Fatalf("the entry was not extracted: %v", err)
	}
	if !bytes.Equal(data, body) {
		t.Errorf("entry.bin holds %q, want %q", data, body)
	}
	if _, err := os.Lstat(filepath.Join(dst, "entry.bin.tmp")); !os.IsNotExist(err) {
		t.Errorf("the temporary file was left behind: %v", err)
	}
}

func TestExtractor_SafeWritesKeepsANameWindowsCannotSpell(t *testing.T) {
	// A name ending in a dot is a name Windows reaches only through its
	// extended form, and the move has to be given the same form as every
	// other step of the extraction or it puts the file somewhere else.
	body := []byte("trailing dot")
	raw := safeWritesArchive(t, "awkward.", body)

	dst := t.TempDir()
	if _, err := extractSafely(t, raw, dst); err != nil {
		t.Fatalf("extraction failed: %v", err)
	}

	data, err := os.ReadFile(fixOSPath(filepath.Join(dst, "awkward.")))
	if err != nil {
		t.Fatalf("the entry was not extracted under its own name: %v", err)
	}
	if !bytes.Equal(data, body) {
		t.Errorf("the entry holds %q, want %q", data, body)
	}
	if _, err := os.Lstat(fixOSPath(filepath.Join(dst, "awkward..tmp"))); !os.IsNotExist(err) {
		t.Errorf("the temporary file was left behind: %v", err)
	}
}

func TestExtractor_SafeWritesSweepsUpAFailedMove(t *testing.T) {
	// The move is the last step and the only one with nothing of its own
	// to go wrong by then, so the test makes it fail. What has to follow
	// is that the extraction reports the failure, that the entry is not
	// counted as extracted, and that the temporary file does not survive.
	moveFailed := errors.New("the entry could not be moved into place")
	original := rename
	t.Cleanup(func() { rename = original })
	rename = func(string, string) error { return moveFailed }

	raw := safeWritesArchive(t, "entry.bin", []byte("contents"))

	dst := t.TempDir()
	e, err := extractSafely(t, raw, dst)
	if !errors.Is(err, moveFailed) {
		t.Fatalf("extraction reported %v, want the failed move", err)
	}
	if _, entries := e.Written(); entries != 0 {
		t.Errorf("the extractor counted %d entries, want none: the file never reached its name", entries)
	}
	if _, serr := os.Lstat(filepath.Join(dst, "entry.bin.tmp")); !os.IsNotExist(serr) {
		t.Errorf("the temporary file was left behind: %v", serr)
	}
	if _, serr := os.Lstat(filepath.Join(dst, "entry.bin")); !os.IsNotExist(serr) {
		t.Errorf("the entry appeared under its final name although the move failed: %v", serr)
	}
}
