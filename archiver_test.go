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
	"time"
)

func TestArchiverAndExtractor(t *testing.T) {
	srcDir := t.TempDir()
	dstDir := t.TempDir()
	zipPath := filepath.Join(t.TempDir(), "fast.zip")

	// 1. Prepare source structure
	filesToCreate := map[string]string{
		"file1.txt":      "hello parallel world",
		"dir1/file2.txt": "inside a directory",
	}

	for path, content := range filesToCreate {
		fullPath := filepath.Join(srcDir, path)
		mustMkdirAll(t, filepath.Dir(fullPath))
		if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}
	}

	// Create symlink (skip on Windows unless running with admin privileges)
	if runtime.GOOS != "windows" {
		symlinkTarget := "file1.txt"
		symlinkPath := filepath.Join(srcDir, "symlink.txt")
		if err := os.Symlink(symlinkTarget, symlinkPath); err != nil {
			t.Fatalf("failed to create symlink: %v", err)
		}
	}

	// 2. Gather files for Archiver
	filesMap := make(map[string]os.FileInfo)
	err := filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if path == srcDir {
			return nil // skip root
		}
		filesMap[path] = info
		return nil
	})
	if err != nil {
		t.Fatalf("walk failed: %v", err)
	}

	// 3. Archive files (Testing multi-threading)
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("failed to create zip file: %v", err)
	}
	closeAt(t, f)
	archiver, err := NewArchiver(f, srcDir, WithArchiverConcurrency(4), WithArchiverMethod(Deflate))
	if err != nil {
		t.Fatalf("failed to init archiver: %v", err)
	}
	closeAt(t, archiver)

	if err := archiver.Archive(context.Background(), filesMap); err != nil {
		t.Fatalf("archive failed: %v", err)
	}
	if err := archiver.Close(); err != nil {
		t.Fatalf("failed to close archiver: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close %s: %v", zipPath, err)
	}

	// 4. Extract files (Testing multi-threading)
	extractor, err := NewExtractor(zipPath, dstDir, WithExtractorConcurrency(4))
	if err != nil {
		t.Fatalf("failed to init extractor: %v", err)
	}
	closeAt(t, extractor)
	if err := extractor.Extract(context.Background()); err != nil {
		t.Fatalf("extract failed: %v", err)
	}
	if err := extractor.Close(); err != nil {
		t.Fatalf("failed to close extractor: %v", err)
	}

	// 5. Verify extracted content
	for path, expectedContent := range filesToCreate {
		fullPath := filepath.Join(dstDir, path)
		content, err := os.ReadFile(fullPath)
		if err != nil {
			t.Errorf("extracted file %s is missing: %v", path, err)
			continue
		}
		if !bytes.Equal(content, []byte(expectedContent)) {
			t.Errorf("extracted file %s content mismatch. Expected %q, got %q", path, expectedContent, string(content))
		}
	}

	if runtime.GOOS != "windows" {
		symlinkPath := filepath.Join(dstDir, "symlink.txt")
		target, err := os.Readlink(symlinkPath)
		if err != nil {
			t.Errorf("symlink was not extracted properly: %v", err)
		} else if target != "file1.txt" {
			t.Errorf("symlink target mismatch. Expected 'file1.txt', got %q", target)
		}
	}
}

func TestArchiver_OutsideChrootNormalization(t *testing.T) {
	tmp := t.TempDir()
	chroot := filepath.Join(tmp, "inside")
	mustMkdir(t, chroot)

	outsideFile := filepath.Join(tmp, "outside.txt")
	mustWriteFile(t, outsideFile, []byte("safe"), 0644)

	zipPath := filepath.Join(tmp, "test.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, f)

	a, err := NewArchiver(f, chroot)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, a)
	info, _ := os.Stat(outsideFile)
	files := map[string]os.FileInfo{
		outsideFile: info,
	}

	if err := a.Archive(context.Background(), files); err != nil {
		t.Fatalf("expected successful archive with normalized path, got: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("close archiver: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", zipPath, err)
	}

	zr, err := OpenReader(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, zr)

	if len(zr.File) != 1 {
		t.Fatalf("expected 1 file, got %d", len(zr.File))
	}

	if filepath.IsAbs(zr.File[0].Name) || strings.HasPrefix(zr.File[0].Name, "../") {
		t.Errorf("path was not safely normalized: %s", zr.File[0].Name)
	}
}
func TestArchiver_SkipIrregularFiles(t *testing.T) {
	tmp := t.TempDir()
	fPath := filepath.Join(tmp, "normal.txt")
	mustWriteFile(t, fPath, []byte("data"), 0644)

	zipPath := filepath.Join(tmp, "out.zip")
	zipF, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, zipF)

	a, err := NewArchiver(zipF, tmp)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, a)

	// Simulate FileInfo for a socket (irregular file)
	files := make(map[string]os.FileInfo)
	info, _ := os.Stat(fPath)
	files[fPath] = info

	// Manually add a file with socket mode (FileInfo is an interface)
	files["/tmp/socket"] = mockFileInfo{name: "socket", mode: os.ModeSocket}

	if err := a.Archive(context.Background(), files); err != nil {
		t.Fatalf("archiver failed: %v", err)
	}

	// Verify that the archive contains only 1 file (the socket was skipped)
	if err := a.Close(); err != nil {
		t.Fatalf("close archiver: %v", err)
	}
	if err := zipF.Close(); err != nil {
		t.Fatalf("close %s: %v", zipPath, err)
	}
	zr, err := OpenReader(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, zr)
	if len(zr.File) != 1 {
		t.Errorf("expected 1 file (socket should be skipped), got %d", len(zr.File))
	}
}
func TestArchiver_EmptyEntries(t *testing.T) {
	tmp := t.TempDir()

	// Create an empty directory and an empty file
	mustMkdir(t, filepath.Join(tmp, "empty_dir"))
	mustWriteFile(t, filepath.Join(tmp, "empty_file.txt"), []byte{}, 0644)

	zipPath := filepath.Join(tmp, "empty.zip")
	zipF, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, zipF)

	a, err := NewArchiver(zipF, tmp)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, a)

	files := make(map[string]os.FileInfo)
	if err := filepath.Walk(tmp, func(p string, info os.FileInfo, err error) error {
		if p != tmp && p != zipPath {
			files[p] = info
		}
		return nil
	}); err != nil {
		t.Fatalf("walk failed: %v", err)
	}

	if err := a.Archive(context.Background(), files); err != nil {
		t.Fatalf("failed to archive empty entries: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("close archiver: %v", err)
	}
	if err := zipF.Close(); err != nil {
		t.Fatalf("close %s: %v", zipPath, err)
	}

	zr, err := OpenReader(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, zr)

	foundFile := false
	foundDir := false
	for _, f := range zr.File {
		if f.Name == "empty_file.txt" && f.UncompressedSize64 == 0 {
			foundFile = true
		}
		if f.Name == "empty_dir/" {
			foundDir = true
		}
	}
	if !foundFile || !foundDir {
		t.Errorf("archiver missed empty entries: file=%v, dir=%v", foundFile, foundDir)
	}
}
func TestArchiver_MetadataPreservation(t *testing.T) {
	tmp := t.TempDir()
	srcDir := filepath.Join(tmp, "src")
	mustMkdir(t, srcDir)

	filePath := filepath.Join(srcDir, "meta.txt")
	mustWriteFile(t, filePath, []byte("metadata preservation"), 0644)

	now := time.Now().Truncate(time.Second)
	if err := os.Chtimes(filePath, now.Add(-time.Hour), now); err != nil {
		t.Fatal(err)
	}

	zipPath := filepath.Join(tmp, "meta.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, f)

	// Enable metadata support via Archiver option
	a, err := NewArchiver(f, srcDir, WithArchiverPlatformMetadata(true))
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, a)
	info, _ := os.Stat(filePath)

	// Manually add OwnerSet to simulate a successful pull (since tests might not run as root)
	fh := &FileHeader{
		Name:     "meta.txt",
		Uid:      123,
		Gid:      456,
		Uname:    "testuser",
		Gname:    "testgroup",
		OwnerSet: true,
		Modified: now,
	}

	if err := a.createFile(context.Background(), filePath, info, fh, nil); err != nil {
		t.Fatalf("createFile failed: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("close archiver: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", zipPath, err)
	}

	zr, err := OpenReader(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, zr)
	file := zr.File[0]

	uid, gid, ok := parseUnixExtra(file.Extra)
	if !ok || uid != 123 || gid != 456 {
		t.Errorf("Unix metadata not preserved in Archiver: %d:%d (ok=%v)", uid, gid, ok)
	}
	if file.Uname != "testuser" || file.Gname != "testgroup" {
		t.Errorf("Unix owner name strings not preserved in Archiver: %q:%q", file.Uname, file.Gname)
	}
}
func TestArchiver_ZstdParallel(t *testing.T) {
	tmp := t.TempDir()
	srcDir := filepath.Join(tmp, "src")
	mustMkdir(t, srcDir)

	// Generate multiple files for parallel processing
	filesMap := make(map[string]os.FileInfo)
	for i := 0; i < 20; i++ {
		p := filepath.Join(srcDir, fmt.Sprintf("file_%d.bin", i))
		mustWriteFile(t, p, make([]byte, 1024), 0644)
		info, _ := os.Stat(p)
		filesMap[p] = info
	}

	zipPath := filepath.Join(tmp, "zstd_para.zip")
	zipF, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, zipF)

	// Use ZSTD in parallel mode
	a, err := NewArchiver(zipF, srcDir, WithArchiverMethod(ZSTD), WithArchiverConcurrency(4))
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, a)
	if err := a.Archive(context.Background(), filesMap); err != nil {
		t.Fatalf("parallel ZSTD archive failed: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("close archiver: %v", err)
	}
	if err := zipF.Close(); err != nil {
		t.Fatalf("close %s: %v", zipPath, err)
	}

	// Verify that files are readable
	zr, err := OpenReader(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, zr)
	if len(zr.File) != 20 || zr.File[0].Method != ZSTD {
		t.Errorf("ZSTD parallel archive error: count=%d, method=%d", len(zr.File), zr.File[0].Method)
	}
}

func TestArchiver_ContextCancellation(t *testing.T) {
	tmp := t.TempDir()
	srcDir := filepath.Join(tmp, "src")
	mustMkdir(t, srcDir)

	p := filepath.Join(srcDir, "large.bin")
	mustWriteFile(t, p, make([]byte, 1024*1024), 0644)
	info, _ := os.Stat(p)

	zipF, err := os.Create(filepath.Join(tmp, "cancel.zip"))
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, zipF)

	ctx, cancel := context.WithCancel(context.Background())
	a, err := NewArchiver(zipF, srcDir)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, a)

	// Cancel immediately
	cancel()

	err = a.Archive(ctx, map[string]os.FileInfo{p: info})
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}
func TestArchiver_InvalidStageDir(t *testing.T) {
	tmp := t.TempDir()
	srcDir := filepath.Join(tmp, "src")
	mustMkdirAll(t, srcDir)
	// Create two files to force the Archiver to use FilePool (since concurrency=2)
	mustWriteFile(t, filepath.Join(srcDir, "test1.txt"), make([]byte, 5*1024*1024), 0644)
	mustWriteFile(t, filepath.Join(srcDir, "test2.txt"), make([]byte, 5*1024*1024), 0644)

	zipF, err := os.Create(filepath.Join(tmp, "test.zip"))
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, zipF)

	// Provide a non-existent path as the directory for buffers.
	// Set BufferSize(0) so that data does not stay in memory,
	// but goes directly to the file system (triggering a path error).
	a, err := NewArchiver(zipF, srcDir,
		WithArchiverConcurrency(2),
		WithArchiverBufferSize(0),
		WithStageDirectory(filepath.Join(tmp, "non-existent-path")))
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, a)

	files := make(map[string]os.FileInfo)
	i1, _ := os.Stat(filepath.Join(srcDir, "test1.txt"))
	i2, _ := os.Stat(filepath.Join(srcDir, "test2.txt"))
	files[filepath.Join(srcDir, "test1.txt")] = i1
	files[filepath.Join(srcDir, "test2.txt")] = i2

	err = a.Archive(context.Background(), files)
	if err == nil {
		t.Error("expected error due to invalid stage directory, got nil")
	}
}
func TestArchiver_WrittenStats(t *testing.T) {
	srcDir := t.TempDir()
	zipPath := filepath.Join(t.TempDir(), "stats.zip")

	// Create multiple files
	mustWriteFile(t, filepath.Join(srcDir, "f1.txt"), []byte("data1"), 0644)
	mustWriteFile(t, filepath.Join(srcDir, "f2.txt"), []byte("data22"), 0644)

	filesMap := make(map[string]os.FileInfo)
	if err := filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if path != srcDir {
			filesMap[path] = info
		}
		return nil
	}); err != nil {
		t.Fatalf("walk failed: %v", err)
	}

	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, f)
	archiver, err := NewArchiver(f, srcDir, WithArchiverSolid(true), WithArchiverMethod(Deflate))
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, archiver)
	if err := archiver.Archive(context.Background(), filesMap); err != nil {
		t.Fatalf("solid archiving failed: %v", err)
	}
	if err := archiver.Close(); err != nil {
		t.Fatalf("close archiver: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", zipPath, err)
	}

	bytes, entries := archiver.Written()
	// 2 entries (f1.txt and f2.txt) + 1 outer Solid.zip entry = 3 entries total
	if entries != 3 {
		t.Errorf("expected 3 entries total (2 inner + 1 outer), got %d", entries)
	}
	if bytes <= 0 {
		t.Errorf("expected positive bytes written, got %d", bytes)
	}
}

type mockFileInfo struct {
	name string
	mode os.FileMode
}

func (m mockFileInfo) Name() string       { return m.name }
func (m mockFileInfo) Size() int64        { return 0 }
func (m mockFileInfo) Mode() os.FileMode  { return m.mode }
func (m mockFileInfo) ModTime() time.Time { return time.Now() }
func (m mockFileInfo) IsDir() bool        { return m.mode.IsDir() }
func (m mockFileInfo) Sys() interface{}   { return nil }

func TestArchiver_SolidSeekIndex(t *testing.T) {
	tmpDir := t.TempDir()
	srcDir := filepath.Join(tmpDir, "src")
	mustMkdirAll(t, srcDir)
	mustWriteFile(t, filepath.Join(srcDir, "test.txt"), []byte("solid seek index test data"), 0644)

	archivePath := filepath.Join(tmpDir, "solid.zip")
	f, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, f)

	a, err := NewArchiver(f, srcDir,
		WithArchiverSolid(true),
		WithArchiverMethod(Deflate),
		WithArchiverSeekIndex(1024, true),
	)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, a)

	files := make(map[string]os.FileInfo)
	if err := filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if path != srcDir {
			files[path] = info
		}
		return nil
	}); err != nil {
		t.Fatalf("walk failed: %v", err)
	}

	if err := a.Archive(context.Background(), files); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("close archiver: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", archivePath, err)
	}

	zr, err := OpenReader(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, zr)

	if len(zr.File) != 1 || zr.File[0].Name != "Solid.zip" {
		t.Fatalf("Expected Solid.zip, got %v", zr.File[0].Name)
	}

	rs, err := zr.File[0].OpenSeekable()
	if err != nil {
		t.Fatalf("OpenSeekable failed on Solid archive: %v", err)
	}

	buf := make([]byte, 5)
	n, _ := rs.Read(buf)
	if n == 0 {
		t.Fatalf("Read from seekable stream failed")
	}
}
func TestArchiver_DifferentDrivesWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only test")
	}

	tmp := t.TempDir()
	archivePath := filepath.Join(tmp, "different_drives.zip")
	f, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, f)

	a, err := NewArchiver(f, tmp)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, a)

	currentDrive := filepath.VolumeName(tmp)
	targetDrive := "D:"
	if currentDrive == "D:" || currentDrive == "d:" {
		targetDrive = "C:"
	}

	targetPath := targetDrive + `\dummy_dir`

	files := map[string]os.FileInfo{
		targetPath: mockFileInfo{name: "dummy_dir", mode: os.ModeDir | 0755},
	}

	err = a.Archive(context.Background(), files)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
}
func TestArchiver_CompressionHeuristics(t *testing.T) {
	tmpDir := t.TempDir()
	srcDir := filepath.Join(tmpDir, "src")
	mustMkdirAll(t, srcDir)

	// 1. Тест на эффективность сжатия мелкого текста (раньше было 104%, теперь должно быть < 100%)
	// Генерируем текст с высокой энтропией Хаффмана, но плохим LZ77 (короткий, без повторов строк)
	textPath := filepath.Join(srcDir, "small_text.txt")
	var textBuf bytes.Buffer
	for i := 0; i < 500; i++ {
		textBuf.WriteString(fmt.Sprintf("line %d: some unique text content here\n", i))
	}
	mustWriteFile(t, textPath, textBuf.Bytes(), 0644)

	// 2. Тест на защиту нулей (не должны сжиматься через HuffmanOnly, иначе ratio будет ~12%)
	zeroPath := filepath.Join(srcDir, "zeros.bin")
	mustWriteFile(t, zeroPath, make([]byte, 1024*10), 0644)

	zipPath := filepath.Join(tmpDir, "heuristics.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, f)

	// Используем уровень 1 (BestSpeed), на котором раньше были аномалии
	a, err := NewArchiver(f, srcDir, WithArchiverLevel(1), WithArchiverMethod(Deflate))
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, a)

	files := make(map[string]os.FileInfo)
	if err := filepath.Walk(srcDir, func(p string, info os.FileInfo, err error) error {
		if p != srcDir {
			files[p] = info
		}
		return nil
	}); err != nil {
		t.Fatalf("walk failed: %v", err)
	}

	if err := a.Archive(context.Background(), files); err != nil {
		t.Fatalf("Archive failed: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("close archiver: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", zipPath, err)
	}

	zr, err := OpenReader(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, zr)

	for _, file := range zr.File {
		ratio := float64(file.CompressedSize64) / float64(file.UncompressedSize64) * 100
		if file.Name == "small_text.txt" {
			if ratio >= 100 {
				t.Errorf("Small text anomaly: ratio is %.2f%%, expected < 100%%", ratio)
			}
			t.Logf("Small text ratio: %.2f%% (OK)", ratio)
		}
		if file.Name == "zeros.bin" {
			// LZ77 сожмет 10КБ нулей почти в ноль (десятки байт).
			// Хаффман сожмет 10КБ нулей до ~1.2КБ (12.5%).
			if ratio > 5 {
				t.Errorf("Zeros bloat anomaly: ratio is %.2f%%, expected < 5%% (LZ77 should be used)", ratio)
			}
			t.Logf("Zeros ratio: %.2f%% (OK)", ratio)
		}
	}
}

func TestArchiver_TorrentZipConsistencyWithHeuristics(t *testing.T) {
	tmpDir := t.TempDir()
	srcDir := filepath.Join(tmpDir, "src")
	mustMkdirAll(t, srcDir)

	// Создаем "идеальный" файл для Хаффмана (много уникальных символов, мало повторов)
	// Эвристика analyzeBlock захотела бы включить HuffmanOnly (Level -2)
	path := filepath.Join(srcDir, "huffman_bait.txt")
	data := make([]byte, 8192)
	for i := range data {
		data[i] = byte(i % 256)
	}
	mustWriteFile(t, path, data, 0644)

	zipPath := filepath.Join(tmpDir, "tz_test.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, f)

	// В режиме TorrentZip уровень ВСЕГДА должен оставаться 9 (LZ77)
	a, err := NewArchiver(f, srcDir, WithArchiverTorrentZip(true))
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, a)
	info, _ := os.Stat(path)
	if err := a.Archive(context.Background(), map[string]os.FileInfo{path: info}); err != nil {
		t.Fatalf("archive failed: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("close archiver: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", zipPath, err)
	}

	zr, err := OpenReader(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, zr)

	// На уровне 9 LZ77 на таком паттерне (0..255 повторяется) сработает идеально.
	// Если бы включился HuffmanOnly, размер был бы точно 8192 + оверхед Хаффмана.
	if zr.File[0].CompressedSize64 > 500 {
		t.Errorf("TorrentZip likely used HuffmanOnly instead of Level 9 LZ77: comp size %d", zr.File[0].CompressedSize64)
	}
}
func TestArchiver_ParallelEncryption(t *testing.T) {
	tmpDir := t.TempDir()
	srcDir := filepath.Join(tmpDir, "src")
	dstDir := filepath.Join(tmpDir, "dst")
	mustMkdirAll(t, srcDir)

	password := "parallel-password-123"

	// Create multiple files to force concurrency > 1
	filesToCreate := map[string]string{
		"file1.txt": "parallel encrypted content 1",
		"file2.txt": "parallel encrypted content 2",
		"file3.txt": "parallel encrypted content 3",
		"file4.txt": "parallel encrypted content 4",
		"file5.txt": "parallel encrypted content 5",
	}

	for path, content := range filesToCreate {
		fullPath := filepath.Join(srcDir, path)
		mustMkdirAll(t, filepath.Dir(fullPath))
		if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}
	}

	zipPath := filepath.Join(tmpDir, "parallel_enc.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("failed to create zip file: %v", err)
	}
	closeAt(t, f)

	// Use WithArchiverConcurrency(4) to ensure multiple goroutines process files in parallel
	a, err := NewArchiver(f, srcDir, WithArchiverConcurrency(4), WithArchiverPassword(password))
	if err != nil {
		t.Fatalf("failed to init archiver: %v", err)
	}
	closeAt(t, a)

	filesMap := make(map[string]os.FileInfo)
	err = filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if path != srcDir {
			filesMap[path] = info
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk failed: %v", err)
	}

	if err := a.Archive(context.Background(), filesMap); err != nil {
		t.Fatalf("archive failed: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("failed to close archiver: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close %s: %v", zipPath, err)
	}

	// Extract and verify using multiple goroutines as well
	mustMkdirAll(t, dstDir)
	e, err := NewExtractor(zipPath, dstDir, WithExtractorPassword(password), WithExtractorConcurrency(4))
	if err != nil {
		t.Fatalf("failed to init extractor: %v", err)
	}
	closeAt(t, e)

	if err := e.Extract(context.Background()); err != nil {
		t.Fatalf("extract failed: %v", err)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("failed to close extractor: %v", err)
	}

	// Verify the extracted files contents
	for path, expectedContent := range filesToCreate {
		fullPath := filepath.Join(dstDir, path)
		content, err := os.ReadFile(fullPath)
		if err != nil {
			t.Errorf("extracted file %s is missing: %v", path, err)
			continue
		}
		if !bytes.Equal(content, []byte(expectedContent)) {
			t.Errorf("extracted file %s content mismatch. Expected %q, got %q", path, expectedContent, string(content))
		}
	}
}

// symlinkModeInfo is a real file's FileInfo with the symlink bit set on top.
//
// Archive is handed the FileInfo along with the path, so an entry can claim to
// be a symlink while the path names an ordinary file. That is exactly what a
// caller does when the tree changed under it between the walk and the archive,
// and it makes os.Readlink fail for a reason no platform disagrees about --
// EINVAL on Unix, "the file or directory is not a reparse point" on Windows --
// without needing the privilege that creating a real symlink on Windows wants.
type symlinkModeInfo struct{ os.FileInfo }

func (s symlinkModeInfo) Mode() os.FileMode { return s.FileInfo.Mode() | os.ModeSymlink }

// TestArchiver_ErrorWithIdleWorkersReturns pins every exit from Archive
// against the worker channel being left open.
//
// The workers sit in `for task := range taskCh`, so only the close lets them
// out, and the errgroup is waited on in a deferred call. Any return from the
// middle of the submit loop therefore hangs that wait on every worker that has
// nothing left to do, unless the channel is closed on the path actually taken.
//
// The window is forced rather than raced for. The eight regular entries sort
// ahead of the ninth and all succeed, so by the time the loop reaches the
// symlink entry the pool is idle by construction; the symlink is archived
// inline, on the loop's own goroutine, and its Readlink failure returns
// straight out of the loop -- without cancelling the context, so no worker
// notices anything and all four stay parked. Against a close that happens at
// the bottom of the function this hangs every time, not one run in four.
func TestArchiver_ErrorWithIdleWorkersReturns(t *testing.T) {
	tmp := t.TempDir()
	srcDir := filepath.Join(tmp, "src")
	if err := os.MkdirAll(srcDir, 0755); err != nil {
		t.Fatal(err)
	}

	files := make(map[string]os.FileInfo)
	add := func(name string, wrap bool) {
		p := filepath.Join(srcDir, name)
		if err := os.WriteFile(p, []byte("payload"), 0644); err != nil {
			t.Fatal(err)
		}
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if wrap {
			fi = symlinkModeInfo{fi}
		}
		files[p] = fi
	}
	for i := 0; i < 8; i++ {
		add(fmt.Sprintf("a%02d.txt", i), false)
	}
	// Sorts last, so every worker has drained its task and gone idle before
	// the loop gets here.
	add("zz_link", true)

	zipF, err := os.Create(filepath.Join(tmp, "out.zip"))
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, zipF)

	a, err := NewArchiver(zipF, srcDir, WithArchiverConcurrency(4))
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, a)

	done := make(chan error, 1)
	go func() { done <- a.Archive(context.Background(), files) }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected the unreadable link to be reported")
		}
	case <-time.After(30 * time.Second):
		buf := make([]byte, 1<<16)
		n := runtime.Stack(buf, true)
		t.Fatalf("Archive did not return within 30s, workers are still waiting on the task channel:\n%s", buf[:n])
	}
}
