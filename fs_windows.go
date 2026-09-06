//go:build windows
// +build windows

package zip

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func lchmod(name string, mode os.FileMode) error {
	if mode&os.ModeSymlink != 0 {
		return nil
	}
	return os.Chmod(fixOSPath(name), mode)
}

func lchtimes(name string, mode os.FileMode, atime, mtime time.Time) error {
	if mode&os.ModeSymlink != 0 {
		return nil
	}
	return os.Chtimes(fixOSPath(name), atime, mtime)
}

// symbolicLinkFlagAllowUnprivilegedCreate lets a process that holds no
// SeCreateSymbolicLinkPrivilege make a symlink when the machine is in
// Developer Mode. x/sys/windows does not name it.
const symbolicLinkFlagAllowUnprivilegedCreate = 0x2

// createSymbolicLink and createHardLink are the two kernel32 calls behind
// names a test can take over. Which of them succeeds is a property of the
// machine -- the privilege, or Developer Mode -- rather than of the archive,
// and every rung of the ladder below has to be exercised somewhere that does
// not depend on which machine is running.
var (
	createSymbolicLink = windows.CreateSymbolicLink
	createHardLink     = windows.CreateHardLink
)

// createSymbolicLinkUnprivileged makes a symlink the way os.Symlink does.
//
// CreateSymbolicLink wants SeCreateSymbolicLinkPrivilege, which no ordinary
// account holds, so without the flag the call fails on every desktop and on
// every runner that is not elevated -- and each symlink entry then quietly
// became a hard link, a copy or a bare directory, even on a machine where
// os.Symlink works. The flag is what Developer Mode answers to. Windows before
// 10 1703 does not know it and says ERROR_INVALID_PARAMETER, and only that
// answer is worth asking again without it: a refusal is a refusal.
func createSymbolicLinkUnprivileged(link, target *uint16, flags uint32) error {
	err := createSymbolicLink(link, target, flags|symbolicLinkFlagAllowUnprivilegedCreate)
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		err = createSymbolicLink(link, target, flags)
	}
	return err
}

// createWindowsSymlink makes link point at target.
//
// The archive says symlink, so a symlink is what this produces wherever the
// machine allows one, and the rest of the ladder is there for the machines
// that do not: a hard link for a file, and failing that a copy of it, and a
// plain directory for a directory. Those were once tried first, back when the
// symlink call could not succeed without a privilege no ordinary account
// holds; now that it can, they belong where their reason still applies, which
// is underneath. An absent target is not a reason to fall through either --
// a link that dangles is what the archive asked for, and only a symlink can
// express it.
//
// It takes the target twice on purpose. A symlink stores the text it was given
// and resolves it against its own directory when it is followed, so target is
// passed to CreateSymbolicLink exactly as the archive spelled it and a
// relative link stays relative -- the extracted tree can then be moved as a
// whole. The two fallbacks store nothing and open the target here and now,
// and a relative path handed to either of them is resolved against the process
// working directory instead, which is a directory neither the archive nor the
// chroot check has anything to do with. resolved is the same target already
// anchored at the link's own directory, and it is what those two must use.
// The copy at the bottom of the ladder puts the target's bytes in a file of
// its own, which makes it a destination file like any other: eb is the budget
// those bytes are accounted against, so an extraction that would refuse to
// write a file that size refuses this one too.
func createWindowsSymlink(target, resolved, link string, isDir bool, eb *entryBudget) error {
	// A reparse point holds a Win32 path and nothing else: a forward slash in
	// it is not a separator, and the link resolves to nothing. An archive
	// spells its targets with forward slashes, so the separators are turned
	// round here -- which changes the spelling and not the path, so the link
	// is still as relative as the archive made it. os.Symlink does the same,
	// for the same reason.
	targetPath, _ := syscall.UTF16PtrFromString(filepath.FromSlash(target))
	resolvedPath, _ := syscall.UTF16PtrFromString(resolved)
	linkPath, _ := syscall.UTF16PtrFromString(link)

	if isDir {
		if err := createSymbolicLinkUnprivileged(linkPath, targetPath, windows.SYMBOLIC_LINK_FLAG_DIRECTORY); err != nil {
			// A directory has no hard link to fall back on, and the entries
			// that go into this one are extracted by name and do not need the
			// link to exist. Make the directory outright.
			return os.MkdirAll(link, 0755)
		}
		return nil
	}

	if err := createSymbolicLinkUnprivileged(linkPath, targetPath, 0); err != nil {
		if err := createHardLink(linkPath, resolvedPath, 0); err != nil {
			return copyFileContents(resolved, link, eb)
		}
	}
	return nil
}

// copyFileContents copies src to dst, counting the bytes against eb.
//
// The destination is closed before this returns and the close is part of the
// answer: the tail of a copy sits in the operating system's buffers until the
// handle is let go of, so a close that fails is a file short by whatever was
// still in flight, and reporting success there would hand back a truncated
// file as if it were the target the archive named.
func copyFileContents(src, dst string, eb *entryBudget) (err error) {
	in, err := os.Open(fixOSPath(src))
	if err != nil {
		return err
	}
	// Nothing was written through in, so closing it can only repeat what
	// the reads already reported.
	defer func() { _ = in.Close() }()

	out, err := os.Create(fixOSPath(dst))
	if err != nil {
		return err
	}
	// A copy that stops part way leaves a truncated regular file where the
	// archive asked for a link, and nothing about it says it is not the
	// target. It is taken away again rather than left to be read as one.
	// Deferred calls run in reverse, so this runs after the close below,
	// because Windows does not unlink a file that is still open. The error
	// that caused the removal is the one worth reporting, so a removal that
	// fails does not replace it.
	defer func() {
		if err != nil {
			_ = os.Remove(fixOSPath(dst))
		}
	}()
	defer dclose(out, &err)

	if _, err = io.CopyBuffer(eb.file(out), in, make([]byte, 1024*1024)); err != nil {
		return err
	}
	return out.Sync()
}

func lchown(name string, uid, gid int) error {
	return nil
}

var (
	modadvapi32                    = syscall.NewLazyDLL("advapi32.dll")
	procGetFileSecurityW           = modadvapi32.NewProc("GetFileSecurityW")
	procSetFileSecurityW           = modadvapi32.NewProc("SetFileSecurityW")
	modkernel32                    = syscall.NewLazyDLL("kernel32.dll")
	procFindFirstStreamW           = modkernel32.NewProc("FindFirstStreamW")
	procFindNextStreamW            = modkernel32.NewProc("FindNextStreamW")
	procFindClose                  = modkernel32.NewProc("FindClose")
	procSetFileInformationByHandle = modkernel32.NewProc("SetFileInformationByHandle")
)

type win32FindStreamData struct {
	StreamSize int64
	StreamName [260 + 36]uint16
}

// getFileSecurityW is the GetFileSecurityW call behind a name a test can take
// over. It fills buf with the security descriptor of path and reports the
// length that descriptor needs, which is how a caller holding no buffer learns
// how large a one to come back with. The addresses stay on this side of the
// name: what is taken over is the answer the object gives, never the place it
// was written to.
var getFileSecurityW = func(path *uint16, secInfo uint32, buf []byte) (needed uint32, err error) {
	var descriptor unsafe.Pointer
	if len(buf) > 0 {
		descriptor = unsafe.Pointer(&buf[0])
	}
	r1, _, err := procGetFileSecurityW.Call(
		uintptr(unsafe.Pointer(path)),
		uintptr(secInfo),
		uintptr(descriptor),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&needed)),
	)
	// The call reports what went wrong through the thread's last error,
	// which says nothing at all until the returned handle has been looked
	// at: a zero there is the only thing that makes the error an error.
	if r1 == 0 {
		return needed, err
	}
	return needed, nil
}

func getFileSecurity(path string) ([]byte, error) {
	pathPtr, err := syscall.UTF16PtrFromString(fixOSPath(path))
	if err != nil {
		return nil, err
	}
	const secInfo = 7 // OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
	// Asking with no buffer is how the length is learned, so the refusal
	// that says the buffer was too small is the answer here and not a
	// failure. Anything else is one.
	needed, err := getFileSecurityW(pathPtr, secInfo, nil)
	if err != nil && err != windows.ERROR_INSUFFICIENT_BUFFER {
		return nil, err
	}
	if needed == 0 {
		return nil, nil
	}
	buf := make([]byte, needed)
	if _, err := getFileSecurityW(pathPtr, secInfo, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func applyNtfsAcl(path string, acl []byte) error {
	if len(acl) == 0 {
		return nil
	}
	pathPtr, err := syscall.UTF16PtrFromString(fixOSPath(path))
	if err != nil {
		return err
	}
	const secInfo = 7 // OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
	r1, _, err := procSetFileSecurityW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(secInfo),
		uintptr(unsafe.Pointer(&acl[0])),
	)
	if r1 == 0 {
		return err
	}
	return nil
}

func getAlternativeDataStreams(path string) ([]string, error) {
	pathPtr, err := syscall.UTF16PtrFromString(fixOSPath(path))
	if err != nil {
		return nil, err
	}
	var data win32FindStreamData
	const findStreamInfoStandard = 0
	h, _, err := procFindFirstStreamW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(findStreamInfoStandard),
		uintptr(unsafe.Pointer(&data)),
		0,
	)
	// LazyProc.Call always hands back a syscall.Errno, zero when the call
	// succeeded, so err says nothing until the handle it came with has been
	// looked at. FindFirstStreamW answers INVALID_HANDLE_VALUE both for a
	// path it could not open and for one that simply has no streams to
	// enumerate, and only the errno tells the two apart.
	if h == uintptr(syscall.InvalidHandle) {
		if errors.Is(err, windows.ERROR_HANDLE_EOF) {
			// Nothing to list: a directory, or a file on a volume
			// that keeps no streams. Not a failure.
			return nil, nil
		}
		// The path could not be read at all. An empty list here would
		// be indistinguishable from a file that has no extra streams,
		// which is the one thing this must not say.
		return nil, err
	}
	defer func() {
		// The streams have been read by the time this runs and the
		// answer is already in hand: FindClose only lets go of the
		// enumeration handle, and nothing about a failure to let go of
		// it changes what was read.
		_, _, _ = procFindClose.Call(h)
	}()

	var streams []string
	for {
		name := syscall.UTF16ToString(data.StreamName[:])
		if name != "::$DATA" && name != "" {
			// A stream is enumerated as ":name:$DATA"; the archive
			// entry that carries it is named for the stream alone.
			streams = append(streams, strings.TrimSuffix(name, ":$DATA"))
		}

		r1, _, _ := procFindNextStreamW.Call(
			h,
			uintptr(unsafe.Pointer(&data)),
		)
		if r1 == 0 {
			break
		}
	}
	return streams, nil
}

func appendPlatformExtra(fi os.FileInfo, hdr *FileHeader, force bool) {
	// Not applicable on Windows for standard ZIP UID/GID fields
}
func preallocate(f *os.File, size int64) error {
	if size <= 1024*1024 {
		return nil
	}
	// Reserve the clusters on disk first. This is a hint and nothing more:
	// what the caller is told about is the logical size set below, and a
	// refused reservation costs a fragmented file rather than a wrong one,
	// which is not worth failing an extraction over.
	var allocInfo = size
	_, _, _ = procSetFileInformationByHandle.Call(
		f.Fd(),
		5, // FileAllocationInfo
		uintptr(unsafe.Pointer(&allocInfo)),
		8, // sizeof(int64)
	)

	// Set the logical end of file.
	return f.Truncate(size)
}

// removeHeldElsewhere reports whether err is Windows refusing to unlink a file
// because another process still has it open: a file just written and not yet
// let go of, which is what a scanner reading everything that lands on disk
// leaves behind for a moment. ERROR_ACCESS_DENIED is the coarser of the two
// and also answers for a read-only file, which no amount of waiting changes;
// waiting for it anyway costs a second on a path that is failing regardless,
// and is what testing's own temp directory cleanup does for the same reason.
func removeHeldElsewhere(err error) bool {
	return errors.Is(err, windows.ERROR_SHARING_VIOLATION) || errors.Is(err, windows.ERROR_ACCESS_DENIED)
}
