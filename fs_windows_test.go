//go:build windows

package zip

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// TestCreateWindowsSymlink_FallbacksUseTheAnchoredTarget covers the two ways
// out of createWindowsSymlink that store nothing and open the target on the
// spot.
//
// A symlink keeps the text it was given and resolves it when it is followed,
// so it is the one form that can be handed the archive's own relative
// spelling. A hard link and a copy resolve their argument here and now,
// against the process working directory, which has nothing to do with the
// directory the link is going into -- so they get the target already anchored
// there.
//
// The bottom of the ladder is reached here with the real calls rather than
// through the seams, and without depending on what the machine grants: a link
// path that already exists makes CreateSymbolicLink and then CreateHardLink
// fail alike, and the copy is what is left.
func TestCreateWindowsSymlink_FallbacksUseTheAnchoredTarget(t *testing.T) {
	tmp := t.TempDir()

	// The spelling the archive used, and what it would name from anywhere
	// else. Neither the hard link nor the copy may go looking for this one.
	if err := os.WriteFile(filepath.Join(tmp, "data.txt"), []byte("WRONG"), 0600); err != nil {
		t.Fatal(err)
	}
	tree := filepath.Join(tmp, "tree")
	if err := os.MkdirAll(tree, 0755); err != nil {
		t.Fatal(err)
	}
	resolved := filepath.Join(tree, "data.txt")
	if err := os.WriteFile(resolved, []byte("RIGHT"), 0600); err != nil {
		t.Fatal(err)
	}

	link := filepath.Join(tree, "link")
	if err := os.WriteFile(link, []byte("stale"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := createWindowsSymlink("../data.txt", resolved, link, false, noLimitBudget("link")); err != nil {
		t.Fatalf("createWindowsSymlink: %v", err)
	}
	got, err := os.ReadFile(link)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "RIGHT" {
		t.Errorf("the link carries %q, want %q", got, "RIGHT")
	}
}

// symlinkAllowed reports whether this machine lets the process make a symlink
// at all, by making one and taking it away again. Whether it does is a
// property of the machine -- the privilege, or Developer Mode -- and not of
// anything the package can arrange.
func symlinkAllowed(t *testing.T, dir string) bool {
	t.Helper()
	probe := filepath.Join(dir, "symlink_probe")
	if err := os.Symlink("nothing", probe); err != nil {
		t.Logf("no symlink can be made here: %v", err)
		return false
	}
	if err := os.Remove(probe); err != nil {
		t.Fatal(err)
	}
	return true
}

// TestCreateWindowsSymlink_MakesARealSymlink pins that a symlink entry becomes
// a symlink wherever one can be made, whether or not the target is there yet.
//
// CreateSymbolicLink wants SeCreateSymbolicLinkPrivilege, which an ordinary
// account does not hold, and refuses without it -- so on every desktop and
// every runner that is not elevated the call failed and the entry quietly
// became a hard link, a copy, or a bare directory, even where os.Symlink
// works. SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE is what makes the
// difference, and it is what os.Symlink passes. This is the real-syscall
// proof; the rungs beneath are driven through the seams below.
func TestCreateWindowsSymlink_MakesARealSymlink(t *testing.T) {
	tests := []struct {
		name    string
		present bool
	}{
		// The ordinary case: the entry the link names was extracted a moment
		// ago and is sitting there. A hard link would also work here, which
		// is exactly why it used to be made instead.
		{"the target is there", true},
		// Only a symlink can name what is not there.
		{"the target is not there", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmp := t.TempDir()
			if !symlinkAllowed(t, tmp) {
				t.Skip("this machine grants neither the privilege nor Developer Mode")
			}

			sub := filepath.Join(tmp, "sub")
			if err := os.MkdirAll(sub, 0755); err != nil {
				t.Fatal(err)
			}
			resolved := filepath.Join(tmp, "data.txt")
			if tt.present {
				if err := os.WriteFile(resolved, []byte("payload"), 0600); err != nil {
					t.Fatal(err)
				}
			}

			link := filepath.Join(sub, "link")
			if err := createWindowsSymlink("../data.txt", resolved, link, false, noLimitBudget("link")); err != nil {
				t.Fatalf("createWindowsSymlink: %v", err)
			}
			fi, err := os.Lstat(link)
			if err != nil {
				t.Fatal(err)
			}
			if fi.Mode()&os.ModeSymlink == 0 {
				t.Fatalf("%s came out as %v, not as a symlink", link, fi.Mode())
			}
			// A reparse point holds a Win32 path: the separators are turned
			// round, and nothing else about the archive's text is.
			if got, err := os.Readlink(link); err != nil || got != `..\data.txt` {
				t.Errorf("Readlink = %q, %v; want %q", got, err, `..\data.txt`)
			}
			if !tt.present {
				return
			}
			data, err := os.ReadFile(link)
			if err != nil {
				t.Fatalf("following the link: %v", err)
			}
			if string(data) != "payload" {
				t.Errorf("the link carries %q, want %q", data, "payload")
			}
		})
	}
}

// TestCreateWindowsSymlink_LadderRungs drives the two rungs beneath the
// symlink, which no machine that can make a symlink will ever reach on its
// own. Refusing the calls in turn is the only way to exercise the ladder
// without depending on how the machine running the test is configured.
//
// Both rungs get the anchored target rather than the archive's text: they
// resolve their argument here and now, against the process working directory,
// which the chroot check had nothing to do with.
func TestCreateWindowsSymlink_LadderRungs(t *testing.T) {
	t.Run("a machine that refuses symlinks makes a hard link", func(t *testing.T) {
		origSym := createSymbolicLink
		t.Cleanup(func() { createSymbolicLink = origSym })
		createSymbolicLink = func(link, target *uint16, flags uint32) error {
			return windows.ERROR_PRIVILEGE_NOT_HELD
		}

		tmp := t.TempDir()
		sub := filepath.Join(tmp, "sub")
		if err := os.MkdirAll(sub, 0755); err != nil {
			t.Fatal(err)
		}
		resolved := filepath.Join(tmp, "data.txt")
		if err := os.WriteFile(resolved, []byte("payload"), 0600); err != nil {
			t.Fatal(err)
		}

		link := filepath.Join(sub, "link")
		if err := createWindowsSymlink("../data.txt", resolved, link, false, noLimitBudget("link")); err != nil {
			t.Fatalf("createWindowsSymlink: %v", err)
		}
		fi, err := os.Lstat(link)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			t.Errorf("%s is a symlink, want the hard link the machine can make", link)
		}
		// One file under two names: a write through one is a write to both.
		if err := os.WriteFile(resolved, []byte("rewritten"), 0600); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(link)
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != "rewritten" {
			t.Errorf("the entry did not follow a write through the target: got %q", data)
		}
	})

	t.Run("a machine that refuses both copies the bytes", func(t *testing.T) {
		origSym, origHard := createSymbolicLink, createHardLink
		t.Cleanup(func() { createSymbolicLink, createHardLink = origSym, origHard })
		createSymbolicLink = func(link, target *uint16, flags uint32) error {
			return windows.ERROR_PRIVILEGE_NOT_HELD
		}
		var hardTarget string
		createHardLink = func(link, target *uint16, reserved uintptr) error {
			hardTarget = windows.UTF16PtrToString(target)
			return windows.ERROR_INVALID_FUNCTION
		}

		tmp := t.TempDir()
		sub := filepath.Join(tmp, "sub")
		if err := os.MkdirAll(sub, 0755); err != nil {
			t.Fatal(err)
		}
		resolved := filepath.Join(tmp, "data.txt")
		if err := os.WriteFile(resolved, []byte("payload"), 0600); err != nil {
			t.Fatal(err)
		}

		link := filepath.Join(sub, "link")
		if err := createWindowsSymlink("../data.txt", resolved, link, false, noLimitBudget("link")); err != nil {
			t.Fatalf("createWindowsSymlink: %v", err)
		}
		if hardTarget != resolved {
			t.Errorf("the hard link was offered %q, want the anchored %q", hardTarget, resolved)
		}
		fi, err := os.Lstat(link)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			t.Errorf("%s is a symlink, want a copy", link)
		}
		data, err := os.ReadFile(link)
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != "payload" {
			t.Errorf("the copy carries %q, want %q", data, "payload")
		}
		// A copy is its own file, so a write to the source does not reach it.
		if err := os.WriteFile(resolved, []byte("rewritten"), 0600); err != nil {
			t.Fatal(err)
		}
		if data, err := os.ReadFile(link); err != nil || string(data) != "payload" {
			t.Errorf("the copy followed a write through the source: %q, %v", data, err)
		}
	})
}

// TestCreateWindowsSymlink_Directory covers the other half of the function: a
// directory link is made as one where the machine allows it, and the
// directory is made outright where it does not, because the entries that go
// into it are extracted by name and do not need the link to exist.
func TestCreateWindowsSymlink_Directory(t *testing.T) {
	tmp := t.TempDir()
	target := filepath.Join(tmp, "real")
	if err := os.MkdirAll(target, 0755); err != nil {
		t.Fatal(err)
	}
	allowed := symlinkAllowed(t, tmp)
	link := filepath.Join(tmp, "as_dir")

	if err := createWindowsSymlink("real", target, link, true, noLimitBudget("link")); err != nil {
		t.Fatalf("createWindowsSymlink: %v", err)
	}
	fi, err := os.Stat(link)
	if err != nil {
		t.Fatalf("stat of the directory link: %v", err)
	}
	if !fi.IsDir() {
		t.Errorf("%s is not a directory", link)
	}
	li, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if got := li.Mode()&os.ModeSymlink != 0; got != allowed {
		t.Errorf("%s is a symlink = %v, want %v on this machine", link, got, allowed)
	}
}

// TestCreateWindowsSymlink_DirectoryFallback pins the answer for a machine
// that refuses, whichever machine this is: the directory is made instead and
// nothing is reported.
func TestCreateWindowsSymlink_DirectoryFallback(t *testing.T) {
	orig := createSymbolicLink
	t.Cleanup(func() { createSymbolicLink = orig })
	createSymbolicLink = func(link, target *uint16, flags uint32) error {
		return windows.ERROR_PRIVILEGE_NOT_HELD
	}

	tmp := t.TempDir()
	link := filepath.Join(tmp, "as_dir")
	if err := createWindowsSymlink("real", filepath.Join(tmp, "real"), link, true, noLimitBudget("link")); err != nil {
		t.Fatalf("createWindowsSymlink: %v", err)
	}
	fi, err := os.Lstat(link)
	if err != nil {
		t.Fatalf("stat of the substituted directory: %v", err)
	}
	if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		t.Errorf("%s came out as %v, want a plain directory", link, fi.Mode())
	}
}

// TestCreateSymbolicLinkUnprivileged covers the retry.
//
// SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE arrived in Windows 10 1703;
// anything older answers ERROR_INVALID_PARAMETER for a flag it does not know,
// and the call has to be made again without it or the package would refuse to
// make symlinks on exactly the systems where the privilege is the only way to
// get one. Only that answer is retried: a refusal is a refusal.
func TestCreateSymbolicLinkUnprivileged(t *testing.T) {
	orig := createSymbolicLink
	t.Cleanup(func() { createSymbolicLink = orig })

	var flags []uint32
	answers := []error{windows.ERROR_INVALID_PARAMETER, nil}
	createSymbolicLink = func(link, target *uint16, f uint32) error {
		flags = append(flags, f)
		answer := answers[0]
		answers = answers[1:]
		return answer
	}
	if err := createSymbolicLinkUnprivileged(nil, nil, windows.SYMBOLIC_LINK_FLAG_DIRECTORY); err != nil {
		t.Fatalf("the retry did not happen: %v", err)
	}
	want := []uint32{
		windows.SYMBOLIC_LINK_FLAG_DIRECTORY | symbolicLinkFlagAllowUnprivilegedCreate,
		windows.SYMBOLIC_LINK_FLAG_DIRECTORY,
	}
	if len(flags) != len(want) || flags[0] != want[0] || flags[1] != want[1] {
		t.Errorf("flags = %v, want %v", flags, want)
	}

	// Any other refusal is the machine's answer and stands.
	answers = []error{windows.ERROR_PRIVILEGE_NOT_HELD}
	flags = nil
	if err := createSymbolicLinkUnprivileged(nil, nil, 0); !errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD) {
		t.Errorf("err = %v, want it passed through", err)
	}
	if len(flags) != 1 {
		t.Errorf("the call was made %d times, want once", len(flags))
	}
}

// TestCreateWindowsSymlink_CopyRungIsBudgeted: the bottom rung of the ladder
// puts the target's bytes in a file of its own, which makes it a write like
// any other -- an extraction that would refuse to write a file that size has
// to refuse this one too, rather than copying without a bound and without
// counting what it copied.
func TestCreateWindowsSymlink_CopyRungIsBudgeted(t *testing.T) {
	origSym, origHard := createSymbolicLink, createHardLink
	t.Cleanup(func() { createSymbolicLink, createHardLink = origSym, origHard })
	createSymbolicLink = func(link, target *uint16, flags uint32) error {
		return windows.ERROR_PRIVILEGE_NOT_HELD
	}
	createHardLink = func(link, target *uint16, reserved uintptr) error {
		return windows.ERROR_INVALID_FUNCTION
	}

	tmp := t.TempDir()
	sub := filepath.Join(tmp, "sub")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatal(err)
	}
	resolved := filepath.Join(tmp, "data.txt")
	if err := os.WriteFile(resolved, bytes.Repeat([]byte("x"), 4096), 0600); err != nil {
		t.Fatal(err)
	}

	var written int64
	b := newExtractBudget(&extractorOptions{maxFileSize: 1024}, &written)
	link := filepath.Join(sub, "link")
	err := createWindowsSymlink("../data.txt", resolved, link, false, b.duplicate("link"))
	if !errors.Is(err, ErrSizeLimit) {
		t.Fatalf("copying a 4096 byte target under a 1024 byte limit: got %v, want ErrSizeLimit", err)
	}
	if written > 1024 {
		t.Errorf("the copy wrote %d bytes past a limit of 1024", written)
	}
	// A copy that stopped part way is a truncated regular file where the
	// archive asked for a link, and nothing about it says it is not the
	// target it was supposed to name.
	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Errorf("the refused copy was left behind at %s (%v)", link, err)
	}
}

// TestCopyFileContents covers the last resort on its own, including the three
// ways it can fail.
func TestCopyFileContents(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "src.txt")
	if err := os.WriteFile(src, []byte("payload"), 0600); err != nil {
		t.Fatal(err)
	}

	dst := filepath.Join(tmp, "dst.txt")
	if err := copyFileContents(src, dst, noLimitBudget("dst.txt")); err != nil {
		t.Fatalf("copyFileContents: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "payload" {
		t.Errorf("copied %q, want %q", got, "payload")
	}

	if err := copyFileContents(filepath.Join(tmp, "no_such_file"), dst, noLimitBudget("dst.txt")); err == nil {
		t.Error("copying a source that is not there succeeded")
	}
	if err := copyFileContents(src, filepath.Join(tmp, "no_such_dir", "dst.txt"), noLimitBudget("dst.txt")); err == nil {
		t.Error("copying into a directory that is not there succeeded")
	}
	// A directory opens and refuses to be read, which is the read half of the
	// copy failing after both files are open.
	if err := copyFileContents(tmp, filepath.Join(tmp, "from_dir.txt"), noLimitBudget("from_dir.txt")); err == nil {
		t.Error("copying a directory's contents succeeded")
	}
}

// TestRemoveHeldElsewhere covers the two spellings Windows uses for a file
// another process still has open, and the ones it does not: a scratch file
// that is simply gone, or a path the caller got wrong, is not something to
// wait for.
func TestRemoveHeldElsewhere(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"sharing violation", &os.PathError{Op: "remove", Path: "x", Err: windows.ERROR_SHARING_VIOLATION}, true},
		{"access denied", &os.PathError{Op: "remove", Path: "x", Err: windows.ERROR_ACCESS_DENIED}, true},
		{"not found", &os.PathError{Op: "remove", Path: "x", Err: windows.ERROR_FILE_NOT_FOUND}, false},
		{"not a syscall error", errors.New("something else"), false},
		{"no error", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := removeHeldElsewhere(tc.err); got != tc.want {
				t.Errorf("removeHeldElsewhere(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestGetAlternativeDataStreams_NoHandle covers the two things
// FindFirstStreamW means by INVALID_HANDLE_VALUE, which the handle alone
// cannot tell apart.
//
// The errno decides, and it is worth reading only once the handle has been
// found invalid: the call hands one back whatever happened. ERROR_HANDLE_EOF
// is a path with no streams to list, which is an answer rather than a failure.
// Anything else is a path that could not be read at all, and an empty list
// there would be indistinguishable from a file that carries no extra streams.
func TestGetAlternativeDataStreams_NoHandle(t *testing.T) {
	tmp := t.TempDir()

	t.Run("a directory has nothing to enumerate", func(t *testing.T) {
		dir := filepath.Join(tmp, "sub")
		mustMkdirAll(t, dir)

		streams, err := getAlternativeDataStreams(dir)
		if err != nil {
			t.Fatalf("getAlternativeDataStreams(%s): %v", dir, err)
		}
		if len(streams) != 0 {
			t.Errorf("streams = %v, want none", streams)
		}
	})

	t.Run("a path that cannot be read is reported", func(t *testing.T) {
		missing := filepath.Join(tmp, "no_such_file.txt")

		streams, err := getAlternativeDataStreams(missing)
		if err == nil {
			t.Fatalf("streams = %v and no error for a file that is not there", streams)
		}
		if !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			t.Errorf("err = %v, want ERROR_FILE_NOT_FOUND", err)
		}
		if streams != nil {
			t.Errorf("streams = %v, want none", streams)
		}
	})

	t.Run("a path that cannot be handed to Windows at all", func(t *testing.T) {
		// A wide string ends at its first NUL, so a name that contains
		// one cannot be passed to any Win32 call: it would arrive cut
		// short and the answer would be about a different file.
		streams, err := getAlternativeDataStreams(filepath.Join(tmp, "na\x00me"))
		if err == nil {
			t.Fatalf("streams = %v and no error for a name with a NUL in it", streams)
		}
		if streams != nil {
			t.Errorf("streams = %v, want none", streams)
		}
	})
}

// TestPreallocate covers the room the extractor makes for a file whose size
// the archive already declared.
//
// It is two calls on Windows: a hint to NTFS to keep the clusters together,
// which the file system is free to refuse and which changes nothing about the
// file if it does, and the logical end of file, which is what the caller is
// actually told about and is what is checked here.
func TestPreallocate(t *testing.T) {
	tmp := t.TempDir()

	t.Run("a file worth reserving gets its size up front", func(t *testing.T) {
		f, err := os.Create(filepath.Join(tmp, "big.bin"))
		if err != nil {
			t.Fatal(err)
		}
		closeAt(t, f)

		const size = 2 * 1024 * 1024
		if err := preallocate(f, size); err != nil {
			t.Fatalf("preallocate: %v", err)
		}
		fi, err := f.Stat()
		if err != nil {
			t.Fatal(err)
		}
		if fi.Size() != size {
			t.Errorf("the file is %d bytes, want the %d that were reserved", fi.Size(), size)
		}
	})

	t.Run("a file too small to be worth it is left alone", func(t *testing.T) {
		f, err := os.Create(filepath.Join(tmp, "small.bin"))
		if err != nil {
			t.Fatal(err)
		}
		closeAt(t, f)

		if err := preallocate(f, 1024*1024); err != nil {
			t.Fatalf("preallocate: %v", err)
		}
		fi, err := f.Stat()
		if err != nil {
			t.Fatal(err)
		}
		if fi.Size() != 0 {
			t.Errorf("the file grew to %d bytes for a reservation not worth making", fi.Size())
		}
	})
}
