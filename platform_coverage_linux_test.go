//go:build linux
// +build linux

package zip

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// platformCovNodeInfo describes a node the test names itself. A block device
// is the one kind of entry whose device number the header pass reads that no
// machine is guaranteed to have at a path a test could stat.
type platformCovNodeInfo struct {
	mode os.FileMode
	stat *syscall.Stat_t
}

func (platformCovNodeInfo) Name() string         { return "node" }
func (platformCovNodeInfo) Size() int64          { return 0 }
func (fi platformCovNodeInfo) Mode() os.FileMode { return fi.mode }
func (platformCovNodeInfo) ModTime() time.Time   { return time.Time{} }
func (platformCovNodeInfo) IsDir() bool          { return false }
func (fi platformCovNodeInfo) Sys() any          { return fi.stat }

// TestPlatformCovSysPlatformExtraReadsADeviceNumber covers the device arm of
// the header pass for both kinds of node. A block device and a character
// device carry the number the same way, and an archive that recorded either
// has to be able to say which device the entry was, so both halves are split
// out of the number the kernel reports rather than left as the packed form,
// which no other system decodes the same way.
func TestPlatformCovSysPlatformExtraReadsADeviceNumber(t *testing.T) {
	const major, minor = 8, 17

	for _, tc := range []struct {
		what string
		mode os.FileMode
	}{
		{"a block device", os.ModeDevice | 0660},
		{"a character device", os.ModeDevice | os.ModeCharDevice | 0660},
	} {
		t.Run(tc.what, func(t *testing.T) {
			st := &syscall.Stat_t{}
			platformCovSetRdev(&st.Rdev, unix.Mkdev(major, minor))

			var hdr FileHeader
			sysPlatformExtra(platformCovNodeInfo{mode: tc.mode, stat: st}, &hdr)

			if hdr.Devmajor != major || hdr.Devminor != minor {
				t.Errorf("the entry was recorded as device %d:%d, want %d:%d",
					hdr.Devmajor, hdr.Devminor, major, minor)
			}
		})
	}
}

// TestPlatformCovPreallocateReportsAFailedReservation covers a reservation the
// kernel refuses for a reason that is about this file rather than about the
// filesystem. A handle opened only for reading cannot have space reserved
// through it, and that is not a refusal an extraction can shrug off: it says
// the handle it is about to write an entry through is not one it can write to.
func TestPlatformCovPreallocateReportsAFailedReservation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "entry")
	mustWriteFile(t, path, []byte("data"), 0600)

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	closeAt(t, f)

	err = preallocate(f, 2*1024*1024)
	if err == nil {
		t.Fatal("space was reserved through a handle opened only for reading")
	}
	if !errors.Is(err, unix.EBADF) {
		t.Errorf("reserving through a read-only handle gave %v, want the kernel's refusal", err)
	}
	if fi, serr := os.Stat(path); serr != nil {
		t.Fatalf("stat %s: %v", path, serr)
	} else if fi.Size() != 4 {
		t.Errorf("a refused reservation left a file of %d bytes, want the 4 it held", fi.Size())
	}
}

// TestPlatformCovPreallocateIgnoresAnUnsupportedReservation covers the
// refusals that say nothing about the entry. Reserving space is a hint, and a
// filesystem with no way to act on it -- FAT, exFAT, SMB, an old kernel --
// answers that it cannot rather than that the file is bad. Failing an
// extraction there would refuse to write archives onto whole classes of volume
// over an optimisation, so those answers are dropped and the write goes ahead.
func TestPlatformCovPreallocateIgnoresAnUnsupportedReservation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "entry")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	closeAt(t, f)

	orig := fallocate
	t.Cleanup(func() { fallocate = orig })

	for _, refusal := range []error{unix.EOPNOTSUPP, unix.ENOSYS, unix.ENOTTY, unix.EINVAL} {
		t.Run(refusal.Error(), func(t *testing.T) {
			fallocate = func(fd int, mode uint32, off, length int64) error { return refusal }
			if err := preallocate(f, 2*1024*1024); err != nil {
				t.Errorf("a filesystem that answered %v failed the entry with %v", refusal, err)
			}
		})
	}

	// Any other refusal is about this file and is still reported.
	fallocate = func(fd int, mode uint32, off, length int64) error { return unix.ENOSPC }
	if err := preallocate(f, 2*1024*1024); !errors.Is(err, unix.ENOSPC) {
		t.Errorf("a full filesystem gave %v, want the refusal reported", err)
	}
}

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
			return len("user.one\x00"), nil
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

// platformCovSetXattr puts an extended attribute on path, or skips the test
// when the filesystem underneath has nowhere to keep one -- which is the
// normal answer on tmpfs, FAT and SMB, and says nothing about the code.
func platformCovSetXattr(t *testing.T, path, name string, value []byte) {
	t.Helper()
	if err := unix.Lsetxattr(path, name, value, 0); err != nil {
		t.Skipf("this filesystem keeps no extended attributes: %v", err)
	}
}

// TestPlatformCovSysXattrsSkipsAValueItCannotRead covers an attribute whose
// name comes back but whose value does not. Listing the names of a file's
// attributes needs no permission on the file itself while reading a value
// does, so a file nothing may read has attributes that can be named and not
// fetched. The entry is archived with the attributes that could be read and
// without the ones that could not, rather than failing over decoration.
func TestPlatformCovSysXattrsSkipsAValueItCannotRead(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a mode of zero keeps nothing from root, so both the name and the value come back")
	}
	path := filepath.Join(t.TempDir(), "entry")
	mustWriteFile(t, path, []byte("data"), 0600)
	platformCovSetXattr(t, path, "user.platformcov_secret", []byte("value"))

	if err := os.Chmod(path, 0); err != nil {
		t.Fatalf("chmod %s: %v", path, err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0600) })

	hdr := &FileHeader{Name: "entry"}
	if err := sysXattrs(path, hdr); err != nil {
		t.Fatalf("reading the attributes of a file nothing may read: %v", err)
	}
	if got, ok := hdr.Xattrs["user.platformcov_secret"]; ok {
		t.Errorf("a value that could not be read was archived as %q", got)
	}
}

// TestPlatformCovSysXattrsReadsAnEmptyValue covers an attribute that is
// present and holds nothing. The name is the whole of what it says, and an
// archive that dropped it would be an archive of a different file, so it is
// carried with the empty value it has.
func TestPlatformCovSysXattrsReadsAnEmptyValue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "entry")
	mustWriteFile(t, path, []byte("data"), 0600)
	platformCovSetXattr(t, path, "user.platformcov_empty", nil)

	hdr := &FileHeader{Name: "entry"}
	if err := sysXattrs(path, hdr); err != nil {
		t.Fatalf("reading an empty attribute: %v", err)
	}
	got, ok := hdr.Xattrs["user.platformcov_empty"]
	if !ok {
		t.Fatalf("an attribute holding nothing was dropped; the entry carries %v", hdr.Xattrs)
	}
	if got != "" {
		t.Errorf("an attribute holding nothing came back as %q", got)
	}
}

// TestPlatformCovSysXattrsLeavesAFileWithNoneAlone covers the early answer for
// the ordinary case, which is a file with no extended attributes at all: there
// is nothing to record and no map is made for it.
func TestPlatformCovSysXattrsLeavesAFileWithNoneAlone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "entry")
	mustWriteFile(t, path, []byte("data"), 0600)

	hdr := &FileHeader{Name: "entry"}
	if err := sysXattrs(path, hdr); err != nil {
		t.Fatalf("reading the attributes of a plain file: %v", err)
	}
	if hdr.Xattrs != nil {
		t.Errorf("a file with no attributes produced %v", hdr.Xattrs)
	}
	if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) {
		t.Error("reading the attributes took the file away")
	}
}

// platformCovSetRdev writes a device number into the field a Stat_t keeps it
// in. Linux spells dev_t as thirty-two bits on some architectures and
// sixty-four on others, and this suite is built for both, so the width comes
// from the field rather than from the call that made the number.
func platformCovSetRdev[T ~uint32 | ~uint64 | ~int32 | ~int64](field *T, dev uint64) {
	// #nosec G115 -- the caller's device number is one it chose itself, small
	// enough for either width; nothing here comes out of an archive
	*field = T(dev)
}
