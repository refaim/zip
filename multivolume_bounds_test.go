package zip

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewMultiVolumeWriterRefusesASizeThatIsNotASize(t *testing.T) {
	// Write fills the current volume, opens the next one and carries on.
	// A volume that holds nothing is a volume it opens for ever: with a
	// split size of zero it made a new empty part on every turn of the
	// loop and never wrote a byte of what it was given, so the call is
	// refused where the size arrives instead.
	dir := t.TempDir()
	for _, size := range []int64{0, -1} {
		path := filepath.Join(dir, "vol.zip")
		w, err := NewMultiVolumeWriter(path, size)
		if err == nil {
			if cerr := w.Close(); cerr != nil {
				t.Errorf("closing the writer: %v", cerr)
			}
			t.Fatalf("a volume size of %d was accepted", size)
		}
		if !strings.Contains(err.Error(), "not a size") {
			t.Errorf("error %q does not say what is wrong", err)
		}
		if entries, rerr := os.ReadDir(dir); rerr != nil {
			t.Fatalf("reading the directory: %v", rerr)
		} else if len(entries) != 0 {
			t.Fatalf("a refused volume size left %d files behind", len(entries))
		}
	}
}
