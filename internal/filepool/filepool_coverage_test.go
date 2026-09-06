package filepool

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestPlatformCovCloseErrorFindsEveryFailure covers what a caller can learn
// from a close that went wrong in more than one way. Closing the pool closes
// and removes every file it holds, so more than one of those can fail at once
// and the answer to "did this run into that particular failure" has to be yes
// for each of them, whichever position it ended up in.
func TestPlatformCovCloseErrorFindsEveryFailure(t *testing.T) {
	first := errors.New("the handle would not close")
	second := errors.New("the file would not go away")

	single := filePoolCloseError{first}
	if !errors.Is(single, first) {
		t.Error("the only failure of a close could not be found in what it reported")
	}
	if errors.Is(single, second) {
		t.Error("a failure that did not happen was found in what the close reported")
	}

	pair := filePoolCloseError{first, second}
	if !errors.Is(pair, first) {
		t.Error("the first of two failures could not be found")
	}
	if !errors.Is(pair, second) {
		t.Error("the second of two failures could not be found")
	}

	if got := (filePoolCloseError{}).Unwrap(); got != nil {
		t.Errorf("a list with no failures in it gave %v, want nothing", got)
	}
}

// TestPlatformCovClosePoolReportsEveryFailure covers what closing the pool
// says when a file cannot be let go of. Letting go of one is two steps -- the
// handle and the name on disk -- and either can fail on its own, so both are
// collected and the caller is told about all of them rather than the first.
func TestPlatformCovClosePoolReportsEveryFailure(t *testing.T) {
	dir := t.TempDir()
	fp, err := New(dir, 1, 4)
	if err != nil {
		t.Fatalf("new pool: %v", err)
	}

	f := fp.Get()
	if _, err := f.Write([]byte("longer than the four byte buffer, so a file is made")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if f.f == nil {
		t.Fatal("the write did not spill into a file")
	}
	name := f.f.Name()

	// A handle already let go of cannot be let go of a second time.
	if err := f.f.Close(); err != nil {
		t.Fatalf("close the pool's file: %v", err)
	}
	// And a name that is a directory with something in it cannot be
	// unlinked either -- which is a failure to remove that is not the
	// harmless "it was already gone".
	if err := os.Remove(name); err != nil {
		t.Fatalf("remove %s: %v", name, err)
	}
	if err := os.Mkdir(name, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", name, err)
	}
	if err := os.WriteFile(filepath.Join(name, "occupant"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write into %s: %v", name, err)
	}

	cerr := fp.Close()
	if cerr == nil {
		t.Fatal("closing the pool reported success although neither the handle nor the name could be released")
	}
	var failures filePoolCloseError
	if !errors.As(cerr, &failures) {
		t.Fatalf("closing the pool gave a %T, want the collected failures: %v", cerr, cerr)
	}
	if failures.Len() != 2 {
		t.Errorf("closing the pool reported %d failures, want the close and the removal: %v", failures.Len(), cerr)
	}
}

// TestPlatformCovWriteReportsAFailedSpill covers the error return of the spill.
// Once the memory buffer is full the rest of an entry goes to a file, and a
// write to that file that does not happen has to be reported: the bytes are
// not anywhere, and a caller told otherwise would go on to record a length the
// pool cannot read back.
func TestPlatformCovWriteReportsAFailedSpill(t *testing.T) {
	f := newFile(t.TempDir(), 0, 4)

	if _, err := f.Write([]byte("longer than the four byte buffer, so a file is made")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if f.f == nil {
		t.Fatal("the write did not spill into a file")
	}
	// Let go of the handle behind the pool's back: every later write to it
	// fails the same way on every platform.
	if err := f.f.Close(); err != nil {
		t.Fatalf("close the spill file: %v", err)
	}

	n, err := f.Write([]byte("and this has nowhere left to go"))
	if err == nil {
		t.Fatal("a write through a released handle reported success")
	}
	if n != 0 {
		t.Errorf("a write that failed reported %d bytes stored, want 0", n)
	}
}
