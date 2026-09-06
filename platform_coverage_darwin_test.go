//go:build darwin
// +build darwin

package zip

import (
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// TestPlatformCovSysXattrsStopsWhenTheNamesChange covers the second read of an
// entry's attribute names. The names are asked for twice, once to learn how
// much room they need and once to read them, and a file whose attributes are
// being changed underneath answers the second call with a refusal because the
// room measured by the first is no longer enough. Attributes are decoration on
// the entry and its data does not depend on them, so what that costs is the
// attributes and never the entry.
func TestPlatformCovSysXattrsStopsWhenTheNamesChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "entry")
	mustWriteFile(t, path, []byte("data"), 0600)

	orig := llistxattr
	t.Cleanup(func() { llistxattr = orig })
	calls := 0
	llistxattr = func(link string, dest []byte) (int, error) {
		calls++
		if dest == nil {
			return len("platformcov.one\x00"), nil
		}
		return 0, unix.ERANGE
	}

	hdr := &FileHeader{Name: "entry"}
	if err := sysXattrs(path, hdr); err != nil {
		t.Fatalf("reading the attributes of a file being changed: %v", err)
	}
	if calls != 2 {
		t.Errorf("the names were asked for %d times, want twice", calls)
	}
	if len(hdr.Xattrs) != 0 {
		t.Errorf("names that could not be read still produced %v", hdr.Xattrs)
	}
}

// TestPlatformCovSysXattrsSkipsAnEmptyValue covers an attribute that is
// present and holds nothing. Asking for its length is how the value is read
// here, and a length of nothing leaves no value to store, so the attribute is
// passed over and the rest of them are still read: one empty attribute must
// not cost the entry the attributes that come after it.
func TestPlatformCovSysXattrsSkipsAnEmptyValue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "entry")
	mustWriteFile(t, path, []byte("data"), 0600)

	const empty = "platformcov_empty"
	const filled = "platformcov_filled"
	if err := unix.Lsetxattr(path, empty, nil, 0); err != nil {
		t.Skipf("this filesystem keeps no extended attributes: %v", err)
	}
	if err := unix.Lsetxattr(path, filled, []byte("value"), 0); err != nil {
		t.Skipf("this filesystem keeps no extended attributes: %v", err)
	}

	hdr := &FileHeader{Name: "entry"}
	if err := sysXattrs(path, hdr); err != nil {
		t.Fatalf("reading the attributes: %v", err)
	}
	if got, ok := hdr.Xattrs[empty]; ok {
		t.Errorf("an attribute holding nothing was archived as %q", got)
	}
	if got := hdr.Xattrs[filled]; got != "value" {
		t.Errorf("the attribute after the empty one came back as %q, want %q", got, "value")
	}
}
