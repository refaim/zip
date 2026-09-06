package zip

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The tests here are about the incremental mode: the archiver writes a
// .zip_dumpdir listing of every file the archive still holds, and an
// incremental extraction uses that listing to take away what the destination
// has and the archive no longer names.

// walkFilesFor returns the map Archive takes, holding every entry under root
// except root itself.
func walkFilesFor(t *testing.T, root string) map[string]os.FileInfo {
	t.Helper()
	files := make(map[string]os.FileInfo)
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if path == root {
			return nil
		}
		files[path] = info
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	return files
}

// incrementalArchiveFile writes a solid, incremental archive of everything
// under srcDir and returns its path.
func incrementalArchiveFile(t *testing.T, srcDir string) string {
	t.Helper()
	zipPath := filepath.Join(t.TempDir(), "incremental.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("create %s: %v", zipPath, err)
	}
	closeAt(t, f)

	a, err := NewArchiver(f, srcDir,
		WithArchiverSolid(true),
		WithArchiverIncremental(true),
		WithArchiverMethod(Store))
	if err != nil {
		t.Fatalf("building the archiver: %v", err)
	}
	closeAt(t, a)

	if err := a.Archive(context.Background(), walkFilesFor(t, srcDir)); err != nil {
		t.Fatalf("archiving %s: %v", srcDir, err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("closing the archiver: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("closing %s: %v", zipPath, err)
	}
	return zipPath
}

// extractIncrementalInto runs an incremental extraction of zipPath over dst.
func extractIncrementalInto(t *testing.T, zipPath, dst string) error {
	t.Helper()
	e, err := NewExtractor(zipPath, dst, WithExtractorIncremental(true))
	if err != nil {
		t.Fatalf("building the extractor: %v", err)
	}
	closeAt(t, e)
	return e.Extract(context.Background())
}

// mustReadFile returns the contents of path, failing the test if it is not
// there.
func mustReadFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

// TestArchiver_IncrementalRoundTrip is the whole of the feature in one pass:
// what the archiver puts in the listing is what the extraction keeps, and
// everything else at the destination goes.
//
// The two stale things are deliberately of different kinds. A stale file is
// one removal; a stale directory is a removal that takes a subtree with it and
// that the walk has to carry on past. A listing that named directories without
// their trailing slash, or an extraction that compared the two spellings as
// they stand, would delete the directory the archive still holds.
func TestArchiver_IncrementalRoundTrip(t *testing.T) {
	srcDir := t.TempDir()
	mustMkdir(t, filepath.Join(srcDir, "sub"))
	mustWriteFile(t, filepath.Join(srcDir, "keep.txt"), []byte("kept"), 0o600)
	mustWriteFile(t, filepath.Join(srcDir, "sub", "nested.txt"), []byte("nested"), 0o600)

	zipPath := incrementalArchiveFile(t, srcDir)
	dst := filepath.Join(t.TempDir(), "dst")

	if err := extractIncrementalInto(t, zipPath, dst); err != nil {
		t.Fatalf("the first extraction failed: %v", err)
	}

	// The listing is what the second extraction reads back, so it is worth
	// pinning down what went into it. A directory is named with a trailing
	// slash; a file is not.
	listing := mustReadFile(t, filepath.Join(dst, ".zip_dumpdir"))
	for _, want := range []string{"keep.txt\n", "sub/\n", "sub/nested.txt\n"} {
		if !strings.Contains(listing, want) {
			t.Errorf("the listing %q does not name %q", listing, want)
		}
	}

	// What an earlier, larger version of the same tree left behind.
	mustWriteFile(t, filepath.Join(dst, "stale.txt"), []byte("stale"), 0o600)
	mustMkdirAll(t, filepath.Join(dst, "stale_dir", "deeper"))
	mustWriteFile(t, filepath.Join(dst, "stale_dir", "deeper", "child.txt"), []byte("stale"), 0o600)

	if err := extractIncrementalInto(t, zipPath, dst); err != nil {
		t.Fatalf("the second extraction failed: %v", err)
	}

	if got := mustReadFile(t, filepath.Join(dst, "keep.txt")); got != "kept" {
		t.Errorf("keep.txt = %q, want %q", got, "kept")
	}
	if got := mustReadFile(t, filepath.Join(dst, "sub", "nested.txt")); got != "nested" {
		t.Errorf("sub/nested.txt = %q, want %q", got, "nested")
	}
	for _, name := range []string{"stale.txt", "stale_dir"} {
		if _, err := os.Lstat(filepath.Join(dst, name)); !os.IsNotExist(err) {
			t.Errorf("the sweep left %s behind: %v", name, err)
		}
	}
}

// TestArchiver_IncrementalListingNeedsAnAbsolutePath covers the archiver
// giving up on a name it cannot make absolute. Every line of the listing is a
// path relative to the archive's root, and the only way to get there is
// through the absolute spelling of the name.
func TestArchiver_IncrementalListingNeedsAnAbsolutePath(t *testing.T) {
	srcDir := t.TempDir()
	scratch := t.TempDir()

	var buf bytes.Buffer
	a, err := NewArchiver(&buf, srcDir,
		WithArchiverSolid(true),
		WithArchiverIncremental(true),
		WithArchiverMethod(Store))
	if err != nil {
		t.Fatalf("building the archiver: %v", err)
	}
	closeAt(t, a)

	var name string
	if runtime.GOOS == "windows" {
		// GetFullPathName, which is what filepath.Abs goes through on
		// Windows, refuses a path past 32767 characters outright.
		name = strings.Repeat("a", 33000)
	} else {
		// Everywhere else filepath.Abs only joins the name onto the
		// working directory, and the one way it has no answer is for
		// that directory to have been unlinked out from under the
		// process.
		gone := filepath.Join(scratch, "gone")
		mustMkdir(t, gone)
		t.Chdir(gone)
		if err := os.Remove(gone); err != nil {
			t.Skipf("the working directory could not be unlinked: %v", err)
		}
		name = "some_name"
	}

	files := map[string]os.FileInfo{name: mockFileInfo{name: "some_name", mode: 0o644}}
	if err := a.Archive(context.Background(), files); err == nil {
		t.Fatal("a name with no absolute spelling was accepted into the listing")
	}
}

// TestArchiver_IncrementalListingNeedsARootToBeRelativeTo covers the other
// half of building a line of the listing: an archive root that no absolute
// path can be made relative to leaves the archiver with nothing to write.
func TestArchiver_IncrementalListingNeedsARootToBeRelativeTo(t *testing.T) {
	srcDir := t.TempDir()

	var buf bytes.Buffer
	a, err := NewArchiver(&buf, srcDir,
		WithArchiverSolid(true),
		WithArchiverIncremental(true),
		WithArchiverMethod(Store))
	if err != nil {
		t.Fatalf("building the archiver: %v", err)
	}
	closeAt(t, a)

	// filepath.Rel has no answer for an absolute path against a root that
	// is not absolute itself, whichever platform it runs on.
	a.chroot = filepath.Join("not", "an", "absolute", "root")

	files := map[string]os.FileInfo{
		filepath.Join(srcDir, "some_name"): mockFileInfo{name: "some_name", mode: 0o644},
	}
	if err := a.Archive(context.Background(), files); err == nil {
		t.Fatal("a root that nothing can be made relative to was accepted")
	}
}

// TestArchiver_IncrementalListingHeaderFailureIsReturned covers the archiver
// giving up when the listing's own entry cannot be started.
//
// The listing is written with Store, so taking Store out of the compressor
// registry for the length of the test is what leaves CreateHeader with no
// compressor to hand the entry to. The outer entry uses Deflate and is created
// before that ever matters.
func TestArchiver_IncrementalListingHeaderFailureIsReturned(t *testing.T) {
	original, ok := compressors.Load(Store)
	if !ok {
		t.Fatal("Store has no registered compressor to take away")
	}
	compressors.Delete(Store)
	t.Cleanup(func() { compressors.Store(Store, original) })

	srcDir := t.TempDir()
	var buf bytes.Buffer
	a, err := NewArchiver(&buf, srcDir,
		WithArchiverSolid(true),
		WithArchiverIncremental(true),
		WithArchiverMethod(Deflate))
	if err != nil {
		t.Fatalf("building the archiver: %v", err)
	}
	closeAt(t, a)

	files := map[string]os.FileInfo{
		filepath.Join(srcDir, "some_name"): mockFileInfo{name: "some_name", mode: 0o644},
	}
	err = a.Archive(context.Background(), files)
	if !errors.Is(err, ErrAlgorithm) {
		t.Fatalf("Archive returned %v, want %v", err, ErrAlgorithm)
	}
}

// TestArchiver_IncrementalListingWriteFailureIsReturned covers a listing that
// cannot be written out.
//
// The listing is the only thing that tells an incremental extraction which
// files the archive still has. A short write leaves an entry whose header
// promises bytes that are not in the archive, so the write has to be the
// archiver's answer rather than something it carries on past. The fixture
// names enough files for the listing to be larger than the 64 KiB the writers
// buffer, which is what makes it reach the failing sink at all.
func TestArchiver_IncrementalListingWriteFailureIsReturned(t *testing.T) {
	srcDir := t.TempDir()
	sink := errWriter{errors.New("the disk went away")}

	a, err := NewArchiver(sink, srcDir,
		WithArchiverSolid(true),
		WithArchiverIncremental(true),
		WithArchiverXattrs(false),
		WithArchiverMethod(Store))
	if err != nil {
		t.Fatalf("building the archiver: %v", err)
	}
	closeAt(t, a)

	files := make(map[string]os.FileInfo)
	for i := 0; i < 1000; i++ {
		name := fmt.Sprintf("%s_%090d", "listed", i)
		files[filepath.Join(srcDir, name)] = mockFileInfo{name: name, mode: 0o644}
	}

	if err := a.Archive(context.Background(), files); !errors.Is(err, sink.err) {
		t.Fatalf("Archive returned %v, want the sink's %v", err, sink.err)
	}
}

// TestArchiver_SolidInnerCloseFailureIsReturned covers the inner archive's
// central directory failing to be written.
//
// Closing the inner writer is what writes that directory. Dropping its error
// handed back an outer archive holding an inner one with no directory at all,
// and reported it as a success. The fixture is made of directory entries,
// which the writer records in the central directory and writes nothing else
// for, so nothing at all reaches the sink until the close; there are enough of
// them for that directory to be larger than the 64 KiB the writers buffer,
// which is what makes it reach the sink rather than sit in the buffer. The
// entry count checked below is what says the archiving itself got all the way
// through first.
func TestArchiver_SolidInnerCloseFailureIsReturned(t *testing.T) {
	srcDir := t.TempDir()
	sink := errWriter{errors.New("the disk went away")}

	a, err := NewArchiver(sink, srcDir,
		WithArchiverSolid(true),
		WithArchiverXattrs(false),
		WithArchiverMethod(Store))
	if err != nil {
		t.Fatalf("building the archiver: %v", err)
	}
	closeAt(t, a)

	// The archiver never looks at the directories themselves, so this is a
	// central directory of a known size with no filesystem behind it.
	const dirs = 1400
	files := make(map[string]os.FileInfo)
	for i := 0; i < dirs; i++ {
		name := fmt.Sprintf("d%04d", i)
		files[filepath.Join(srcDir, name)] = mockFileInfo{name: name, mode: os.ModeDir | 0o755}
	}

	if err := a.Archive(context.Background(), files); !errors.Is(err, sink.err) {
		t.Fatalf("Archive returned %v, want the sink's %v", err, sink.err)
	}
	if _, entries := a.Written(); entries != dirs {
		t.Fatalf("the inner archive wrote %d of %d entries, so the failure was not the close", entries, dirs)
	}
}

// TestArchiver_SolidInnerCloseKeepsTheEarlierFailure covers the other side of
// that: when the archiving itself failed, what closing the inner writer says
// afterwards is not the answer the caller gets.
func TestArchiver_SolidInnerCloseKeepsTheEarlierFailure(t *testing.T) {
	srcDir := t.TempDir()
	var buf bytes.Buffer

	a, err := NewArchiver(&buf, srcDir, WithArchiverSolid(true), WithArchiverMethod(Store))
	if err != nil {
		t.Fatalf("building the archiver: %v", err)
	}
	closeAt(t, a)

	// A regular file that is not on disk: the inner archive fails on
	// opening it, and the inner writer closes cleanly afterwards.
	missing := filepath.Join(srcDir, "not_there.txt")
	files := map[string]os.FileInfo{missing: mockFileInfo{name: "not_there.txt", mode: 0o644}}

	err = a.Archive(context.Background(), files)
	if err == nil {
		t.Fatal("archiving a file that is not on disk was reported as a success")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Archive returned %v, want the missing file's error", err)
	}
}

// dumpdirArchive returns an archive holding a .zip_dumpdir listing and the
// entries the listing names, for the extraction-side tests that need a
// destination prepared before the extraction runs.
func dumpdirArchive(t *testing.T, listing string, entries ...[2]string) []byte {
	t.Helper()
	buf := new(bytes.Buffer)
	zw := NewWriter(buf)
	all := append([][2]string{{".zip_dumpdir", listing}}, entries...)
	for _, ent := range all {
		fh := &FileHeader{Name: ent[0], Method: Store}
		fh.SetMode(0644)
		mustWrite(t, mustCreateHeader(t, zw, fh), []byte(ent[1]))
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("closing the writer: %v", err)
	}
	return buf.Bytes()
}

// extractIncrementalBytesInto runs an incremental extraction of an in-memory
// archive over a destination the test has already prepared.
func extractIncrementalBytesInto(t *testing.T, raw []byte, dst string) error {
	t.Helper()
	e, err := NewExtractorFromReader(bytes.NewReader(raw), int64(len(raw)), dst,
		WithExtractorIncremental(true))
	if err != nil {
		t.Fatalf("building the extractor: %v", err)
	}
	closeAt(t, e)
	return e.Extract(context.Background())
}

// makeUndeletable arranges for dir, which must already hold a child, to refuse
// removal, and reports whether it could. The two platforms have to be asked
// differently: a directory's own permissions are what stop the removal on
// unix, and an open handle on something inside it is what stops it on Windows.
func makeUndeletable(t *testing.T, dir string) bool {
	t.Helper()
	if runtime.GOOS == "windows" {
		held, err := os.Open(filepath.Join(dir, "child.txt"))
		if err != nil {
			t.Fatalf("open the child of %s: %v", dir, err)
		}
		closeAt(t, held)
		return true
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod %s: %v", dir, err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	return os.Geteuid() != 0
}

// TestExtractor_IncrementalSweepRemovesAStaleSymlinkAsALink is what the sweep
// going through a root is for. A symlink the archive no longer names is taken
// away as a link: a removal that followed it would empty out whatever it
// points at, which is a tree the caller never named as the destination.
func TestExtractor_IncrementalSweepRemovesAStaleSymlinkAsALink(t *testing.T) {
	tmp := t.TempDir()
	dst := filepath.Join(tmp, "dst")
	outside := filepath.Join(tmp, "outside")
	mustMkdirAll(t, outside)
	mustWriteFile(t, filepath.Join(outside, "precious.txt"), []byte("not the archive's"), 0o600)

	mustMkdirAll(t, dst)
	mustWriteFile(t, filepath.Join(dst, ".zip_dumpdir"), []byte("keep.txt\n"), 0o600)
	if err := os.Symlink(outside, filepath.Join(dst, "stale_link")); err != nil {
		t.Skipf("symlinks are not available here: %v", err)
	}

	raw := dumpdirArchive(t, "keep.txt\n", [2]string{"keep.txt", "kept"})
	if err := extractIncrementalBytesInto(t, raw, dst); err != nil {
		t.Fatalf("extraction failed: %v", err)
	}

	if _, err := os.Lstat(filepath.Join(dst, "stale_link")); !os.IsNotExist(err) {
		t.Errorf("the sweep left the stale link behind: %v", err)
	}
	if got := mustReadFile(t, filepath.Join(outside, "precious.txt")); got != "not the archive's" {
		t.Errorf("what the link pointed at was changed: %q", got)
	}
	if _, err := os.Stat(outside); err != nil {
		t.Errorf("the sweep followed the link out of the destination: %v", err)
	}
}

// TestExtractor_IncrementalSweepReturnsARemovalFailure covers the sweep giving
// up rather than reporting a destination it could not tidy as a clean
// extraction. Directory permissions are what stop the removal on unix and an
// open handle is what stops it on Windows, so the answer is pinned on both
// rather than only where permissions are enforced.
func TestExtractor_IncrementalSweepReturnsARemovalFailure(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "dst")
	stale := filepath.Join(dst, "stale_dir")
	mustMkdirAll(t, stale)
	mustWriteFile(t, filepath.Join(dst, ".zip_dumpdir"), []byte("keep.txt\n"), 0o600)
	mustWriteFile(t, filepath.Join(stale, "child.txt"), []byte("stale"), 0o600)
	if !makeUndeletable(t, stale) {
		t.Skip("this user can remove the directory whatever its permissions say")
	}

	raw := dumpdirArchive(t, "keep.txt\n", [2]string{"keep.txt", "kept"})
	if err := extractIncrementalBytesInto(t, raw, dst); err == nil {
		t.Fatal("a sweep that could not remove a stale directory was reported as a success")
	}
}

// TestExtractor_IncrementalSweepReturnsAnUnopenableDestination covers the
// sweep's root failing to open. The root is what keeps every removal inside
// the destination, so an extraction that could not open one has no safe way to
// sweep and says so instead of sweeping without it.
//
// The failure is injected rather than staged from the filesystem. By the time
// the sweep runs, a listing inside the destination has already been opened and
// read, so nothing short of the directory being taken away underneath the
// extraction makes this fail -- and permissions do not do it on Windows, which
// would have left the line covered on one platform only.
func TestExtractor_IncrementalSweepReturnsAnUnopenableDestination(t *testing.T) {
	rootFailed := errors.New("the destination could not be opened as a root")
	original := openRoot
	t.Cleanup(func() { openRoot = original })
	openRoot = func(string) (*os.Root, error) { return nil, rootFailed }

	dst := filepath.Join(t.TempDir(), "dst")
	mustMkdirAll(t, dst)

	raw := dumpdirArchive(t, "keep.txt\n", [2]string{"keep.txt", "kept"})
	if err := extractIncrementalBytesInto(t, raw, dst); !errors.Is(err, rootFailed) {
		t.Fatalf("the sweep reported %v, want the root that would not open", err)
	}
}
