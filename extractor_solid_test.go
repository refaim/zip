package zip

import (
	"bytes"
	"context"
	"errors"
	"hash/crc32"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// The tests here are about extractSolidStream, the pass that unpacks a solid
// archive by reading the inner archive's local headers as they arrive, and
// about the two overwrite policies -- unlinkFirst and safeWrites -- on the
// ordinary path beside it.

// storedHeader is the header of an inner entry the streaming pass can read:
// Store, with the sizes and the checksum in the local header rather than
// deferred to a data descriptor.
func storedHeader(name string, data []byte) *FileHeader {
	fh := &FileHeader{
		Name:               name,
		Method:             Store,
		CRC32:              crc32.ChecksumIEEE(data),
		CompressedSize64:   uint64(len(data)),
		UncompressedSize64: uint64(len(data)),
	}
	fh.SetMode(0644)
	return fh
}

// storedDirHeader is storedHeader for a directory entry.
func storedDirHeader(name string) *FileHeader {
	fh := storedHeader(name, nil)
	fh.SetMode(fs.ModeDir | 0755)
	return fh
}

// withOwner puts an Info-ZIP uid/gid field on the header. It is what makes an
// extraction try to set the entry's ownership, which is the one step of
// applying metadata a test can make fail on demand.
func withOwner(fh *FileHeader, uid, gid int) *FileHeader {
	fh.Extra = appendUnixExtra(fh.Extra, uid, gid)
	return fh
}

// rawSolidEntry writes fh and its data into the inner archive of a solid
// archive, header exactly as given.
func rawSolidEntry(t *testing.T, zw *Writer, fh *FileHeader, data []byte) {
	t.Helper()
	w, err := zw.CreateRaw(fh)
	if err != nil {
		t.Fatalf("create entry %q: %v", fh.Name, err)
	}
	if len(data) > 0 {
		mustWrite(t, w, data)
	}
}

// extractSolidInto extracts an in-memory archive over a destination the test
// has already prepared, which is what extractArchiveTo cannot do.
func extractSolidInto(t *testing.T, raw []byte, dst string, opts ...ExtractorOption) error {
	t.Helper()
	e, err := NewExtractorFromReader(bytes.NewReader(raw), int64(len(raw)), dst, opts...)
	if err != nil {
		t.Fatalf("building the extractor: %v", err)
	}
	closeAt(t, e)
	return e.Extract(context.Background())
}

// failingOwnership returns the option pair that makes applying an entry's
// metadata fail, and skips the test where it cannot be made to.
//
// Ownership is the only step of updateFileMetadata a test can fail on demand:
// the times and the mode always take on a file that was just written, while
// an ordinary user is refused a change of owner. Windows applies no ownership
// at all, and root is refused nothing.
func failingOwnership(t *testing.T) (ExtractorOption, error) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("ownership is not applied here, so applying metadata cannot be made to fail")
	}
	if os.Geteuid() == 0 {
		t.Skip("this user can give a file any owner it likes")
	}
	refused := errors.New("the owner could not be set")
	return WithExtractorChownErrorHandler(func(string, error) error { return refused }), refused
}

// TestExtractSolid_DirectoryEntry covers a solid archive that carries a
// directory of its own: the streaming pass makes the directory and gives it
// the entry's metadata, rather than leaving it to be synthesized as some other
// entry's parent.
func TestExtractSolid_DirectoryEntry(t *testing.T) {
	raw := solidArchive(t, Store, func(inner *Writer) {
		rawSolidEntry(t, inner, storedDirHeader("dir/"), nil)
		rawSolidEntry(t, inner, storedHeader("dir/inner.txt", []byte("inside")), []byte("inside"))
	})

	_, dst, err := extractArchiveTo(t, raw)
	if err != nil {
		t.Fatalf("extraction failed: %v", err)
	}

	fi, err := os.Stat(filepath.Join(dst, "dir"))
	if err != nil {
		t.Fatalf("the directory entry was not extracted: %v", err)
	}
	if !fi.IsDir() {
		t.Errorf("dir came out as %v, want a directory", fi.Mode())
	}
	data, err := os.ReadFile(filepath.Join(dst, "dir", "inner.txt"))
	if err != nil {
		t.Fatalf("the file inside the directory was not extracted: %v", err)
	}
	if string(data) != "inside" {
		t.Errorf("dir/inner.txt = %q, want %q", data, "inside")
	}
}

// TestExtractSolid_DirectoryMetadataFailure pins that metadata a solid archive
// asks for and the destination refuses is the extraction's failure, exactly as
// it is for an archive that is not solid. It used to be dropped on the floor
// here whatever the extractor's tolerance was set to, so a strict extraction
// reported success over a directory it had not finished.
func TestExtractSolid_DirectoryMetadataFailure(t *testing.T) {
	handler, refused := failingOwnership(t)
	raw := solidArchive(t, Store, func(inner *Writer) {
		rawSolidEntry(t, inner, withOwner(storedDirHeader("dir/"), 12345, 12345), nil)
	})

	t.Run("tolerant", func(t *testing.T) {
		_, dst, err := extractArchiveTo(t, raw, handler, WithExtractorTolerant(true))
		if err != nil {
			t.Fatalf("a tolerant extraction failed: %v", err)
		}
		if fi, serr := os.Stat(filepath.Join(dst, "dir")); serr != nil || !fi.IsDir() {
			t.Errorf("the directory was not left in place: %v", serr)
		}
	})

	t.Run("strict", func(t *testing.T) {
		if err := extractArchive(t, raw, handler); !errors.Is(err, refused) {
			t.Fatalf("extraction returned %v, want %v", err, refused)
		}
	})
}

// TestExtractSolid_FileMetadataFailure is the same for a file entry: what the
// destination refuses is skipped with a message when the extractor is tolerant
// and is the extraction's answer when it is not.
func TestExtractSolid_FileMetadataFailure(t *testing.T) {
	handler, refused := failingOwnership(t)
	body := []byte("contents")
	raw := solidArchive(t, Store, func(inner *Writer) {
		rawSolidEntry(t, inner, withOwner(storedHeader("entry.bin", body), 12345, 12345), body)
	})

	t.Run("tolerant", func(t *testing.T) {
		_, dst, err := extractArchiveTo(t, raw, handler, WithExtractorTolerant(true))
		if err != nil {
			t.Fatalf("a tolerant extraction failed: %v", err)
		}
		data, rerr := os.ReadFile(filepath.Join(dst, "entry.bin"))
		if rerr != nil {
			t.Fatalf("the entry was not extracted: %v", rerr)
		}
		if !bytes.Equal(data, body) {
			t.Errorf("entry.bin = %q, want %q", data, body)
		}
	})

	t.Run("strict", func(t *testing.T) {
		if err := extractArchive(t, raw, handler); !errors.Is(err, refused) {
			t.Fatalf("extraction returned %v, want %v", err, refused)
		}
	})
}

// makeUnremovable arranges for the file at path to refuse removal, and reports
// whether it could. As with a directory, the two platforms have to be asked
// differently: taking the write bit off the directory holding the file is what
// stops the removal on unix, and an open handle on the file itself is what
// stops it on Windows.
func makeUnremovable(t *testing.T, path string) bool {
	t.Helper()
	if runtime.GOOS == "windows" {
		held, err := os.Open(filepath.Clean(path))
		if err != nil {
			t.Fatalf("open %s: %v", path, err)
		}
		closeAt(t, held)
		return true
	}
	dir := filepath.Dir(path)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod %s: %v", dir, err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	return os.Geteuid() != 0
}

// blockedParentDestination returns a destination in which "held/blocker" is a
// file that cannot be taken away, so that nothing under "held/blocker/" can be
// made into a directory.
func blockedParentDestination(t *testing.T) (string, bool) {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "dst")
	held := filepath.Join(dst, "held")
	mustMkdirAll(t, held)
	blocker := filepath.Join(held, "blocker")
	mustWriteFile(t, blocker, []byte("in the way"), 0o600)
	return dst, makeUnremovable(t, blocker)
}

// TestExtractSolid_DirectoryCannotBeCreated covers a directory entry whose
// name cannot be made into a directory, because a file the extraction cannot
// take away stands where one of its parents would go. Reporting it is the
// point: the entries after it are extracted under a tree that is not the one
// the archive describes.
func TestExtractSolid_DirectoryCannotBeCreated(t *testing.T) {
	raw := solidArchive(t, Store, func(inner *Writer) {
		rawSolidEntry(t, inner, storedDirHeader("held/blocker/dir/"), nil)
	})

	dst, ok := blockedParentDestination(t)
	if !ok {
		t.Skip("this user can remove the file whatever the directory permissions say")
	}
	if err := extractSolidInto(t, raw, dst); err == nil {
		t.Fatal("a directory entry that could not be created was reported as extracted")
	}
}

// TestExtractSolid_FileParentCannotBeCreated is the same for a file entry: the
// directory it goes in cannot be made, so the entry is not written and the
// extraction says so.
func TestExtractSolid_FileParentCannotBeCreated(t *testing.T) {
	body := []byte("contents")
	raw := solidArchive(t, Store, func(inner *Writer) {
		rawSolidEntry(t, inner, storedHeader("held/blocker/entry.bin", body), body)
	})

	dst, ok := blockedParentDestination(t)
	if !ok {
		t.Skip("this user can remove the file whatever the directory permissions say")
	}
	if err := extractSolidInto(t, raw, dst); err == nil {
		t.Fatal("an entry whose directory could not be created was reported as extracted")
	}
}

// TestExtractSolid_FileCannotBeOpened covers the entry's own open failing,
// which is what a destination already holding a directory under that name
// comes to.
func TestExtractSolid_FileCannotBeOpened(t *testing.T) {
	body := []byte("contents")
	raw := solidArchive(t, Store, func(inner *Writer) {
		rawSolidEntry(t, inner, storedHeader("entry.bin", body), body)
	})

	dst := filepath.Join(t.TempDir(), "dst")
	occupied := filepath.Join(dst, "entry.bin")
	mustMkdirAll(t, occupied)
	mustWriteFile(t, filepath.Join(occupied, "child.txt"), []byte("in the way"), 0o600)

	if err := extractSolidInto(t, raw, dst); err == nil {
		t.Fatal("an entry that could not be opened for writing was reported as extracted")
	}
}

// TestExtractSolid_UnlinkFirstReplacesWhatIsThere covers the overwrite policy
// inside the solid path. The point of unlinkFirst is that nothing of the old
// name survives to be written into, so the name is taken away before the entry
// is opened.
func TestExtractSolid_UnlinkFirstReplacesWhatIsThere(t *testing.T) {
	body := []byte("from the archive")
	raw := solidArchive(t, Store, func(inner *Writer) {
		rawSolidEntry(t, inner, storedHeader("entry.bin", body), body)
	})

	dst := filepath.Join(t.TempDir(), "dst")
	mustMkdirAll(t, dst)
	mustWriteFile(t, filepath.Join(dst, "entry.bin"), []byte("from an earlier run"), 0o600)

	if err := extractSolidInto(t, raw, dst, WithExtractorUnlinkFirst(true)); err != nil {
		t.Fatalf("extraction failed: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dst, "entry.bin"))
	if err != nil {
		t.Fatalf("the entry was not extracted: %v", err)
	}
	if !bytes.Equal(data, body) {
		t.Errorf("entry.bin = %q, want %q", data, body)
	}
}

// TestExtractSolid_UnlinkFirstReturnsARemovalFailure covers the other half:
// a name that would not go away is the file the write below would have gone
// into, so the extraction stops rather than writing into whatever is there.
// A name that was simply not there is the ordinary case and is no failure at
// all, which the test above is.
func TestExtractSolid_UnlinkFirstReturnsARemovalFailure(t *testing.T) {
	body := []byte("from the archive")
	raw := solidArchive(t, Store, func(inner *Writer) {
		rawSolidEntry(t, inner, storedHeader("entry.bin", body), body)
	})

	dst := filepath.Join(t.TempDir(), "dst")
	occupied := filepath.Join(dst, "entry.bin")
	mustMkdirAll(t, occupied)
	mustWriteFile(t, filepath.Join(occupied, "child.txt"), []byte("in the way"), 0o600)
	if !makeUndeletable(t, occupied) {
		t.Skip("this user can remove the directory whatever its permissions say")
	}

	if err := extractSolidInto(t, raw, dst, WithExtractorUnlinkFirst(true)); err == nil {
		t.Fatal("a name that could not be removed was extracted over anyway")
	}
}

// TestExtractSolid_SafeWritesRenamesIntoPlace covers safeWrites inside the
// solid path: the entry is written beside its name and moved onto it, so a
// reader never sees a half-written file under the real name.
func TestExtractSolid_SafeWritesRenamesIntoPlace(t *testing.T) {
	body := []byte("written safely")
	raw := solidArchive(t, Store, func(inner *Writer) {
		rawSolidEntry(t, inner, storedHeader("entry.bin", body), body)
	})

	_, dst, err := extractArchiveTo(t, raw, WithExtractorSafeWrites(true))
	if err != nil {
		t.Fatalf("extraction failed: %v", err)
	}
	data, rerr := os.ReadFile(filepath.Join(dst, "entry.bin"))
	if rerr != nil {
		t.Fatalf("the entry was not extracted: %v", rerr)
	}
	if !bytes.Equal(data, body) {
		t.Errorf("entry.bin = %q, want %q", data, body)
	}
	if _, serr := os.Lstat(filepath.Join(dst, "entry.bin.tmp")); !os.IsNotExist(serr) {
		t.Errorf("the temporary file was left behind: %v", serr)
	}
}

// TestExtractSolid_SafeWritesSweepsUpAFailedRename covers the move failing.
// The rename is the error the caller gets, and the temporary file it left
// beside the name goes with it rather than being left in the destination.
func TestExtractSolid_SafeWritesSweepsUpAFailedRename(t *testing.T) {
	body := []byte("written safely")
	raw := solidArchive(t, Store, func(inner *Writer) {
		rawSolidEntry(t, inner, storedHeader("entry.bin", body), body)
	})

	dst := filepath.Join(t.TempDir(), "dst")
	// A non-empty directory under the entry's name: the temporary file is
	// written beside it without trouble, and nothing can be renamed onto it.
	occupied := filepath.Join(dst, "entry.bin")
	mustMkdirAll(t, occupied)
	mustWriteFile(t, filepath.Join(occupied, "child.txt"), []byte("in the way"), 0o600)

	if err := extractSolidInto(t, raw, dst, WithExtractorSafeWrites(true)); err == nil {
		t.Fatal("an entry that could not be renamed into place was reported as extracted")
	}
	if _, err := os.Lstat(filepath.Join(dst, "entry.bin.tmp")); !os.IsNotExist(err) {
		t.Errorf("the temporary file was left behind: %v", err)
	}
}

// TestExtractSolid_ChecksumMismatch covers the close-and-check step at the end
// of an inner entry. An entry whose bytes do not match the checksum its own
// header carries is not extracted, and the partial file it produced does not
// stay in the destination.
func TestExtractSolid_ChecksumMismatch(t *testing.T) {
	body := []byte("the bytes that are actually there")
	raw := solidArchive(t, Store, func(inner *Writer) {
		fh := storedHeader("entry.bin", body)
		fh.CRC32 ^= 0xffffffff
		rawSolidEntry(t, inner, fh, body)
	})

	_, dst, err := extractArchiveTo(t, raw)
	if err == nil {
		t.Fatal("an entry whose checksum does not match was extracted")
	}
	if !errors.Is(err, ErrChecksum) {
		t.Fatalf("extraction returned %v, want %v", err, ErrChecksum)
	}
	if _, serr := os.Lstat(filepath.Join(dst, "entry.bin")); !os.IsNotExist(serr) {
		t.Errorf("the entry was left in the destination: %v", serr)
	}
}

// plainArchive returns an ordinary archive -- one entry, not solid -- for the
// tests about the overwrite policies on the path beside the solid one.
func plainArchive(t *testing.T, name string, data []byte) []byte {
	t.Helper()
	buf := new(bytes.Buffer)
	zw := NewWriter(buf)
	fh := &FileHeader{Name: name, Method: Store}
	fh.SetMode(0644)
	mustWrite(t, mustCreateHeader(t, zw, fh), data)
	if err := zw.Close(); err != nil {
		t.Fatalf("closing the writer: %v", err)
	}
	return buf.Bytes()
}

// TestExtractor_UnlinkFirstOnAFreshDestination covers the ordinary case of the
// option on the path beside the solid one: a name that is not there is what
// unlinkFirst is asking for, and no failure at all.
func TestExtractor_UnlinkFirstOnAFreshDestination(t *testing.T) {
	body := []byte("contents")
	raw := plainArchive(t, "entry.bin", body)

	_, dst, err := extractArchiveTo(t, raw, WithExtractorUnlinkFirst(true))
	if err != nil {
		t.Fatalf("extraction failed: %v", err)
	}
	data, rerr := os.ReadFile(filepath.Join(dst, "entry.bin"))
	if rerr != nil {
		t.Fatalf("the entry was not extracted: %v", rerr)
	}
	if !bytes.Equal(data, body) {
		t.Errorf("entry.bin = %q, want %q", data, body)
	}
}

// TestExtractor_UnlinkFirstReturnsARemovalFailure covers the failure the
// option used to swallow. A name the caller asked to have removed and that is
// still there is a directory, a symlink or a read-only file the write would
// otherwise have followed or gone into, so it is the extraction's answer.
func TestExtractor_UnlinkFirstReturnsARemovalFailure(t *testing.T) {
	raw := plainArchive(t, "entry.bin", []byte("contents"))

	dst := filepath.Join(t.TempDir(), "dst")
	occupied := filepath.Join(dst, "entry.bin")
	mustMkdirAll(t, occupied)
	mustWriteFile(t, filepath.Join(occupied, "child.txt"), []byte("in the way"), 0o600)
	if !makeUndeletable(t, occupied) {
		t.Skip("this user can remove the directory whatever its permissions say")
	}

	if err := extractSolidInto(t, raw, dst, WithExtractorUnlinkFirst(true)); err == nil {
		t.Fatal("a name that could not be removed was extracted over anyway")
	}
}

// The ordinary path's own safeWrites cases live in
// extractor_safewrites_test.go, where the move and its failure are driven
// through the rename seam and run on every platform.
