//go:build windows
// +build windows

package zip

import (
	"errors"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
)

// TestPlatformCovGetFileSecurityRejectsAPathItCannotSpell covers a name that
// cannot be handed to Windows at all. A Win32 path is a run of characters
// ending at the first zero, so a name with a zero inside it would reach the
// kernel cut short at that point and would name a different object than the
// one asked about. It is refused instead.
func TestPlatformCovGetFileSecurityRejectsAPathItCannotSpell(t *testing.T) {
	acl, err := getFileSecurity("entry\x00hidden")
	if err == nil {
		t.Fatalf("a name with a zero inside it was read, giving %d bytes", len(acl))
	}
	if !errors.Is(err, syscall.EINVAL) {
		t.Errorf("a name with a zero inside it gave %v, want it refused as malformed", err)
	}
	if acl != nil {
		t.Errorf("a refused name still produced %d bytes of descriptor", len(acl))
	}
}

// TestPlatformCovGetFileSecurityReportsAPathItCannotRead covers the ordinary
// failure: there is nothing at the path, so there is no descriptor, and the
// answer says so rather than passing an empty one off as the object's.
func TestPlatformCovGetFileSecurityReportsAPathItCannotRead(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing", "entry")

	acl, err := getFileSecurity(missing)
	if err == nil {
		t.Fatalf("a descriptor of %d bytes came back for a path with nothing at it", len(acl))
	}
	if acl != nil {
		t.Errorf("a path with nothing at it still produced %d bytes of descriptor", len(acl))
	}
}

// TestPlatformCovGetFileSecurityWithNothingToRead covers an object that has no
// descriptor to report. Asking with no buffer is how the length is learned,
// and a length of nothing means there is nothing to come back for: the second
// read is not made, because a buffer of no bytes has no first byte to write
// into and asking for one would be the end of the process rather than of the
// entry.
func TestPlatformCovGetFileSecurityWithNothingToRead(t *testing.T) {
	orig := getFileSecurityW
	t.Cleanup(func() { getFileSecurityW = orig })

	reads := 0
	getFileSecurityW = func(path *uint16, secInfo uint32, buf []byte) (uint32, error) {
		reads++
		return 0, nil
	}

	acl, err := getFileSecurity(filepath.Join(t.TempDir(), "entry"))
	if err != nil {
		t.Fatalf("an object with no descriptor was reported as a failure: %v", err)
	}
	if acl != nil {
		t.Errorf("an object with no descriptor produced %d bytes", len(acl))
	}
	if reads != 1 {
		t.Errorf("the descriptor was asked for %d times, want once", reads)
	}
}

// TestPlatformCovGetFileSecurityReportsAFailedSecondRead covers the read that
// fails after the length was already learned, which is what an object being
// changed underneath looks like from here. The length is stale by then and the
// bytes never arrived, so the failure is passed on: a short or empty
// descriptor handed back as the object's own would be recorded in the archive
// as the permissions of that entry.
func TestPlatformCovGetFileSecurityReportsAFailedSecondRead(t *testing.T) {
	orig := getFileSecurityW
	t.Cleanup(func() { getFileSecurityW = orig })

	const length = 64
	var asked []int
	getFileSecurityW = func(path *uint16, secInfo uint32, buf []byte) (uint32, error) {
		asked = append(asked, len(buf))
		if len(buf) == 0 {
			return length, windows.ERROR_INSUFFICIENT_BUFFER
		}
		return 0, windows.ERROR_ACCESS_DENIED
	}

	acl, err := getFileSecurity(filepath.Join(t.TempDir(), "entry"))
	if err == nil {
		t.Fatalf("a descriptor of %d bytes came back although reading it failed", len(acl))
	}
	if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Errorf("the failed read gave %v, want the refusal it was given", err)
	}
	if acl != nil {
		t.Errorf("a failed read still produced %d bytes of descriptor", len(acl))
	}
	if len(asked) != 2 || asked[0] != 0 || asked[1] != length {
		t.Errorf("the descriptor was asked for with buffers of %v, want none and then %d", asked, length)
	}
}

// TestPlatformCovApplyNtfsAclWithNothingToApply covers an entry that carries
// no descriptor, which is every entry written by anything but a Windows
// archiver. There is nothing to write, so nothing is written and the extracted
// file keeps the permissions it inherited from the directory it landed in.
func TestPlatformCovApplyNtfsAclWithNothingToApply(t *testing.T) {
	path := filepath.Join(t.TempDir(), "entry")
	mustWriteFile(t, path, []byte("data"), 0600)

	if err := applyNtfsAcl(path, nil); err != nil {
		t.Errorf("an entry carrying no descriptor: %v", err)
	}
	if err := applyNtfsAcl(path, []byte{}); err != nil {
		t.Errorf("an entry carrying an empty descriptor: %v", err)
	}
}

// TestPlatformCovApplyNtfsAclRejectsAPathItCannotSpell is the writing side of
// the malformed name: a name cut short at a zero inside it would have its
// permissions written onto whatever object the shortened name happens to
// reach, so it is refused before the call is made.
func TestPlatformCovApplyNtfsAclRejectsAPathItCannotSpell(t *testing.T) {
	err := applyNtfsAcl("entry\x00hidden", []byte{1, 0, 4, 0x80})
	if err == nil {
		t.Fatal("permissions were written through a name with a zero inside it")
	}
	if !errors.Is(err, syscall.EINVAL) {
		t.Errorf("a name with a zero inside it gave %v, want it refused as malformed", err)
	}
}

// TestPlatformCovApplyNtfsAclReportsAFailedWrite covers a descriptor that
// cannot be written where it was aimed. The descriptor here is a real one,
// read off a real file, so what fails is the destination and not the bytes --
// and an extraction told that succeeded would leave an entry whose permissions
// are whatever the destination directory handed down, without saying so.
func TestPlatformCovApplyNtfsAclReportsAFailedWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "entry")
	mustWriteFile(t, path, []byte("data"), 0600)

	acl, err := getFileSecurity(path)
	if err != nil {
		t.Fatalf("reading the descriptor of %s: %v", path, err)
	}
	if len(acl) == 0 {
		t.Skip("this volume keeps no security descriptors to write back")
	}

	missing := filepath.Join(dir, "missing", "entry")
	if err := applyNtfsAcl(missing, acl); err == nil {
		t.Fatal("a descriptor was written to a path with nothing at it")
	}
}
