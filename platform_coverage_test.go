package zip

import (
	"os"
	"path/filepath"
	"testing"
)

// TestPlatformCovPreallocateSizesTheFileItIsGiven covers the reservation an
// extraction makes before it writes an entry's bytes out. The reservation is a
// hint about where the bytes will go and never about what the file holds, so
// a size not worth reserving leaves the file exactly as it was, and a size
// worth reserving leaves a file that long and empty. Every platform reserves
// differently -- one asks the filesystem for the blocks, one asks the kernel,
// one simply sets the length -- and all three have to agree about the length
// the caller is left with, because that is the only part an extraction reads.
func TestPlatformCovPreallocateSizesTheFileItIsGiven(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reserved")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	closeAt(t, f)

	// Nothing at all is reserved for an entry with no bytes in it.
	if err := preallocate(f, 0); err != nil {
		t.Fatalf("preallocate(0): %v", err)
	}
	if fi, err := f.Stat(); err != nil {
		t.Fatalf("stat %s: %v", path, err)
	} else if fi.Size() != 0 {
		t.Errorf("reserving nothing left a file of %d bytes", fi.Size())
	}

	const size = 2 * 1024 * 1024
	if err := preallocate(f, size); err != nil {
		t.Fatalf("preallocate(%d): %v", size, err)
	}
	fi, err := f.Stat()
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if fi.Size() != size {
		t.Errorf("reserving %d bytes left a file of %d", size, fi.Size())
	}
}
