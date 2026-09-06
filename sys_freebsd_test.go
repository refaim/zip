//go:build freebsd
// +build freebsd

package zip

import (
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// freebsdDeviceInfo reports a block device with the number given. A block
// device cannot be made without privilege and none of the ones a system ships
// is at a path every machine has, so the header pass is handed the stat the
// kernel would have produced rather than a node on disk.
type freebsdDeviceInfo struct {
	fs.FileInfo
	mode fs.FileMode
	stat syscall.Stat_t
}

func (d *freebsdDeviceInfo) Mode() fs.FileMode { return d.mode }
func (d *freebsdDeviceInfo) Sys() any          { return &d.stat }

// TestFreeBSDPlatformExtraBlockDevice covers the block-device arm of the
// header pass. A character device is read from /dev/null elsewhere; a block
// device carries its number in the same field and takes the other arm.
func TestFreeBSDPlatformExtraBlockDevice(t *testing.T) {
	info := &freebsdDeviceInfo{mode: fs.ModeDevice, stat: syscall.Stat_t{Rdev: unix.Mkdev(7, 11)}}

	var hdr FileHeader
	sysPlatformExtra(info, &hdr)

	if hdr.Devmajor != 7 || hdr.Devminor != 11 {
		t.Errorf("device number came back as %d:%d, want 7:11", hdr.Devmajor, hdr.Devminor)
	}
}

// freebsdListStub answers the two attribute-list calls: the first, which asks
// only for a size, is told the list is len(list) long, and the second is
// handed the bytes to copy in -- or an error, when one is given.
func freebsdListStub(t *testing.T, list []byte, second error) {
	t.Helper()
	real := extattrListLink
	t.Cleanup(func() { extattrListLink = real })
	extattrListLink = func(path string, ns int, buf []byte) (int, error) {
		if len(buf) == 0 {
			return len(list), nil
		}
		if second != nil {
			return 0, second
		}
		return copy(buf, list), nil
	}
}

// TestFreeBSDXattrsListFailsOnSecondCall covers the arm where the list is
// sized and then cannot be read. The two calls are adjacent statements, so
// only an attribute set that changes between them makes the second fail, and
// nothing a test can do to the file decides that.
func TestFreeBSDXattrsListFailsOnSecondCall(t *testing.T) {
	freebsdListStub(t, make([]byte, 4), unix.EPERM)

	var hdr FileHeader
	if err := sysXattrs(freebsdTempFile(t), &hdr); err != nil {
		t.Fatalf("sysXattrs: %v", err)
	}
	if hdr.Xattrs != nil {
		t.Errorf("a list that could not be read still produced attributes: %v", hdr.Xattrs)
	}
}

// TestFreeBSDXattrsListNameOverrunsBuffer covers the bound inside the walk. A
// name is stored as a length byte and that many bytes after it, and a length
// that runs past the end of the list stops the walk rather than reading on.
func TestFreeBSDXattrsListNameOverrunsBuffer(t *testing.T) {
	freebsdListStub(t, []byte{200, 'a', 'b', 'c'}, nil)

	var hdr FileHeader
	if err := sysXattrs(freebsdTempFile(t), &hdr); err != nil {
		t.Fatalf("sysXattrs: %v", err)
	}
	if len(hdr.Xattrs) != 0 {
		t.Errorf("a name running past the list still produced attributes: %v", hdr.Xattrs)
	}
}

// TestFreeBSDXattrsValueUnreadable covers the arm where a name comes back in
// the list but its value cannot be sized -- the attribute was removed between
// the two calls, which is what a name that was never set stands in for here.
func TestFreeBSDXattrsValueUnreadable(t *testing.T) {
	freebsdListStub(t, []byte{5, 'g', 'h', 'o', 's', 't'}, nil)

	var hdr FileHeader
	if err := sysXattrs(freebsdTempFile(t), &hdr); err != nil {
		t.Fatalf("sysXattrs: %v", err)
	}
	if len(hdr.Xattrs) != 0 {
		t.Errorf("an attribute with no value was still recorded: %v", hdr.Xattrs)
	}
}

// TestFreeBSDApplyXattrsSystemNamespace covers the namespace split in the
// applying half: a name under system. is set in the system namespace with the
// prefix taken off, and one under user. in the user namespace.
func TestFreeBSDApplyXattrsSystemNamespace(t *testing.T) {
	path := freebsdTempFile(t)
	hdr := &FileHeader{Name: "attrs.txt", Xattrs: map[string]string{
		"system.zip_test": "system value",
		"user.zip_test":   "user value",
		"bare":            "",
	}}
	if err := applyXattrs(path, hdr); err != nil {
		t.Fatalf("applyXattrs: %v", err)
	}
}

func freebsdTempFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "attrs.txt")
	if err := os.WriteFile(path, []byte("body"), 0600); err != nil {
		t.Fatalf("writing the file the attributes hang off: %v", err)
	}
	return path
}
