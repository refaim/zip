package zip

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestUpdater(t *testing.T) {
	tempDir := t.TempDir()
	zipPath := filepath.Join(tempDir, "test.zip")

	// 1. Create a basic zip archive
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("failed to create zip: %v", err)
	}
	closeAt(t, f)
	zw := NewWriter(f)
	w, err := zw.Create("file1.txt")
	if err != nil {
		t.Fatalf("failed to create file1.txt: %v", err)
	}
	mustWrite(t, w, []byte("version1"))
	if err := zw.Close(); err != nil {
		t.Fatalf("failed to close writer: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close zip: %v", err)
	}

	// 2. Open with Updater and APPEND file2.txt
	fRW, err := os.OpenFile(zipPath, os.O_RDWR, 0644)
	if err != nil {
		t.Fatalf("failed to open zip for update: %v", err)
	}
	closeAt(t, fRW)
	updater, err := NewUpdater(fRW)
	if err != nil {
		t.Fatalf("failed to init updater: %v", err)
	}

	w2, err := updater.Append("file2.txt", APPEND_MODE_KEEP_ORIGINAL)
	if err != nil {
		t.Fatalf("failed to append file2.txt: %v", err)
	}
	mustWrite(t, w2, []byte("file2-content"))

	if err := updater.SetComment("Test comment"); err != nil {
		t.Fatalf("failed to set comment: %v", err)
	}
	if err := updater.Close(); err != nil {
		t.Fatalf("failed to close updater: %v", err)
	}
	if err := fRW.Close(); err != nil {
		t.Fatalf("failed to close zip after update: %v", err)
	}

	// 3. Verify content
	zr, err := OpenReader(zipPath)
	if err != nil {
		t.Fatalf("failed to open reader: %v", err)
	}
	closeAt(t, zr)
	if len(zr.File) != 2 {
		t.Fatalf("expected 2 files, got %d", len(zr.File))
	}
	if zr.Comment != "Test comment" {
		t.Errorf("expected comment 'Test comment', got %q", zr.Comment)
	}
	if err := zr.Close(); err != nil {
		t.Fatalf("failed to close reader: %v", err)
	}

	// 4. Open with Updater and OVERWRITE file1.txt
	fRW, err = os.OpenFile(zipPath, os.O_RDWR, 0644)
	if err != nil {
		t.Fatalf("failed to open zip for overwrite: %v", err)
	}
	closeAt(t, fRW)
	updater, err = NewUpdater(fRW)
	if err != nil {
		t.Fatalf("failed to init updater: %v", err)
	}

	w1, err := updater.Append("file1.txt", APPEND_MODE_OVERWRITE)
	if err != nil {
		t.Fatalf("failed to overwrite file1.txt: %v", err)
	}
	mustWrite(t, w1, []byte("version2-overwritten"))

	if err := updater.Close(); err != nil {
		t.Fatalf("failed to close updater after overwrite: %v", err)
	}
	if err := fRW.Close(); err != nil {
		t.Fatalf("failed to close zip after overwrite: %v", err)
	}

	// 5. Verify overwritten content
	zr, err = OpenReader(zipPath)
	if err != nil {
		t.Fatalf("failed to open reader: %v", err)
	}
	closeAt(t, zr)

	if len(zr.File) != 2 {
		t.Fatalf("expected 2 files after overwrite, got %d", len(zr.File))
	}

	for _, f := range zr.File {
		if f.Name == "file1.txt" {
			rc, err := f.Open()
			if err != nil {
				t.Fatalf("failed to open file1.txt: %v", err)
			}
			closeAt(t, rc)
			content, err := io.ReadAll(rc)
			if err != nil {
				t.Fatalf("failed to read file1.txt: %v", err)
			}
			if err := rc.Close(); err != nil {
				t.Fatalf("failed to close file1.txt: %v", err)
			}
			if !bytes.Equal(content, []byte("version2-overwritten")) {
				t.Errorf("file1.txt was not overwritten properly, got %q", string(content))
			}
		}
	}
}

func TestUpdater_RemoveFirstFile(t *testing.T) {
	tempDir := t.TempDir()
	zipPath := filepath.Join(tempDir, "remove.zip")

	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("failed to create zip: %v", err)
	}
	closeAt(t, f)
	zw := NewWriter(f)
	mustCreate(t, zw, "file1.txt") // will be removed
	w := mustCreate(t, zw, "file2.txt")
	mustWrite(t, w, []byte("keep-me"))
	if err := zw.Close(); err != nil {
		t.Fatalf("failed to close writer: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close zip: %v", err)
	}

	fRW, err := os.OpenFile(zipPath, os.O_RDWR, 0644)
	if err != nil {
		t.Fatalf("failed to open zip for update: %v", err)
	}
	closeAt(t, fRW)
	u, err := NewUpdater(fRW)
	if err != nil {
		t.Fatalf("failed to init updater: %v", err)
	}
	// Overwrite file1.txt to trigger removal and shift of file2.txt
	w1, err := u.Append("file1.txt", APPEND_MODE_OVERWRITE)
	if err != nil {
		t.Fatalf("failed to overwrite file1.txt: %v", err)
	}
	mustWrite(t, w1, []byte("new-file1-is-shorter"))
	if err := u.Close(); err != nil {
		t.Fatalf("failed to close updater: %v", err)
	}
	if err := fRW.Close(); err != nil {
		t.Fatalf("failed to close zip after update: %v", err)
	}

	zr, err := OpenReader(zipPath)
	if err != nil {
		t.Fatalf("failed to open reader: %v", err)
	}
	closeAt(t, zr)
	if len(zr.File) != 2 {
		t.Fatalf("expected 2 files, got %d", len(zr.File))
	}
}
func TestUpdater_LargeDataShift(t *testing.T) {
	// bufferSize in updater.go is 1MB. Let's create a 2MB file and replace a small file before it.
	tempDir := t.TempDir()
	zipPath := filepath.Join(tempDir, "largeshift.zip")

	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("failed to create zip: %v", err)
	}
	closeAt(t, f)
	zw := NewWriter(f)

	// File 1: small
	w1 := mustCreate(t, zw, "small.txt")
	mustWrite(t, w1, []byte("small"))

	// File 2: > 1MB
	w2 := mustCreate(t, zw, "large.bin")
	largeData := make([]byte, 1024*1024*2) // 2MB
	mustWrite(t, w2, largeData)

	if err := zw.Close(); err != nil {
		t.Fatalf("failed to close writer: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close zip: %v", err)
	}

	// Replace "small.txt" with something else of different size to force shift of 2MB
	fRW, err := os.OpenFile(zipPath, os.O_RDWR, 0644)
	if err != nil {
		t.Fatalf("failed to open zip for update: %v", err)
	}
	closeAt(t, fRW)
	u, err := NewUpdater(fRW)
	if err != nil {
		t.Fatalf("failed to init updater: %v", err)
	}
	w, err := u.Append("small.txt", APPEND_MODE_OVERWRITE)
	if err != nil {
		t.Fatalf("failed to overwrite small.txt: %v", err)
	}
	mustWrite(t, w, []byte("now-larger-than-before"))
	if err := u.Close(); err != nil {
		t.Fatalf("failed to close updater: %v", err)
	}
	if err := fRW.Close(); err != nil {
		t.Fatalf("failed to close zip after update: %v", err)
	}

	// Verify
	zr, err := OpenReader(zipPath)
	if err != nil {
		t.Fatalf("failed to open reader: %v", err)
	}
	closeAt(t, zr)
	if len(zr.File) != 2 {
		t.Errorf("expected 2 files, got %d", len(zr.File))
	}
}
func TestUpdater_SameSize(t *testing.T) {
	tempDir := t.TempDir()
	zipPath := filepath.Join(tempDir, "samesize.zip")

	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("failed to create zip: %v", err)
	}
	closeAt(t, f)
	zw := NewWriter(f)
	w := mustCreate(t, zw, "data.txt")
	mustWrite(t, w, []byte("12345"))
	if err := zw.Close(); err != nil {
		t.Fatalf("failed to close writer: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close zip: %v", err)
	}

	fRW, err := os.OpenFile(zipPath, os.O_RDWR, 0644)
	if err != nil {
		t.Fatalf("failed to open zip for update: %v", err)
	}
	closeAt(t, fRW)
	u, err := NewUpdater(fRW)
	if err != nil {
		t.Fatalf("failed to init updater: %v", err)
	}
	w, err = u.Append("data.txt", APPEND_MODE_OVERWRITE)
	if err != nil {
		t.Fatalf("failed to overwrite data.txt: %v", err)
	}
	mustWrite(t, w, []byte("abcde")) // Same size
	if err := u.Close(); err != nil {
		t.Fatalf("failed to close updater: %v", err)
	}
	if err := fRW.Close(); err != nil {
		t.Fatalf("failed to close zip after update: %v", err)
	}

	zr, err := OpenReader(zipPath)
	if err != nil {
		t.Fatalf("failed to open reader: %v", err)
	}
	closeAt(t, zr)
	rc, err := zr.File[0].Open()
	if err != nil {
		t.Fatalf("failed to open data.txt: %v", err)
	}
	closeAt(t, rc)
	b, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("failed to read data.txt: %v", err)
	}
	if string(b) != "abcde" {
		t.Errorf("expected 'abcde', got %q", string(b))
	}
}

func TestUpdater_ReplaceLastFile(t *testing.T) {
	tempDir := t.TempDir()
	zipPath := filepath.Join(tempDir, "last.zip")

	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("failed to create zip: %v", err)
	}
	closeAt(t, f)
	zw := NewWriter(f)
	mustCreate(t, zw, "file1.txt")
	w := mustCreate(t, zw, "file2.txt")
	mustWrite(t, w, []byte("old"))
	if err := zw.Close(); err != nil {
		t.Fatalf("failed to close writer: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close zip: %v", err)
	}

	fRW, err := os.OpenFile(zipPath, os.O_RDWR, 0644)
	if err != nil {
		t.Fatalf("failed to open zip for update: %v", err)
	}
	closeAt(t, fRW)
	u, err := NewUpdater(fRW)
	if err != nil {
		t.Fatalf("failed to init updater: %v", err)
	}
	w, err = u.Append("file2.txt", APPEND_MODE_OVERWRITE)
	if err != nil {
		t.Fatalf("failed to overwrite file2.txt: %v", err)
	}
	mustWrite(t, w, []byte("new-much-longer-content"))
	if err := u.Close(); err != nil {
		t.Fatalf("failed to close updater: %v", err)
	}
	if err := fRW.Close(); err != nil {
		t.Fatalf("failed to close zip after update: %v", err)
	}

	zr, err := OpenReader(zipPath)
	if err != nil {
		t.Fatalf("failed to open reader: %v", err)
	}
	closeAt(t, zr)
	if len(zr.File) != 2 {
		t.Fatalf("expected 2 files, got %d", len(zr.File))
	}
}

func TestUpdater_DuplicateHeaderError(t *testing.T) {
	tmp := t.TempDir()
	zipPath := filepath.Join(tmp, "dup.zip")

	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("failed to create zip: %v", err)
	}
	closeAt(t, f)
	zw := NewWriter(f)
	mustCreate(t, zw, "file.txt")
	if err := zw.Close(); err != nil {
		t.Fatalf("failed to close writer: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close zip: %v", err)
	}

	fRW, err := os.OpenFile(zipPath, os.O_RDWR, 0644)
	if err != nil {
		t.Fatalf("failed to open zip for update: %v", err)
	}
	closeAt(t, fRW)
	u, err := NewUpdater(fRW)
	if err != nil {
		t.Fatalf("failed to init updater: %v", err)
	}

	fh := &FileHeader{Name: "new.txt"}
	if _, err := u.AppendHeader(fh, APPEND_MODE_KEEP_ORIGINAL); err != nil {
		t.Fatalf("failed to append new.txt: %v", err)
	}

	// Attempting to add THE SAME header a second time without closing the stream
	_, err = u.AppendHeader(fh, APPEND_MODE_KEEP_ORIGINAL)
	if err == nil {
		t.Error("expected error when appending duplicate FileHeader object, got nil")
	}
}
func TestUpdater_OverwriteWithEmpty(t *testing.T) {
	tmp := t.TempDir()
	zipPath := filepath.Join(tmp, "to_empty.zip")

	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("failed to create zip: %v", err)
	}
	closeAt(t, f)
	zw := NewWriter(f)
	w := mustCreate(t, zw, "data.txt")
	mustWrite(t, w, []byte("some substantial data"))
	if err := zw.Close(); err != nil {
		t.Fatalf("failed to close writer: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close zip: %v", err)
	}

	// Overwrite with an empty file
	fRW, err := os.OpenFile(zipPath, os.O_RDWR, 0644)
	if err != nil {
		t.Fatalf("failed to open zip for update: %v", err)
	}
	closeAt(t, fRW)
	u, err := NewUpdater(fRW)
	if err != nil {
		t.Fatalf("failed to init updater: %v", err)
	}
	// Write nothing to the new entry
	if _, err := u.Append("data.txt", APPEND_MODE_OVERWRITE); err != nil {
		t.Fatalf("failed to overwrite data.txt: %v", err)
	}
	if err := u.Close(); err != nil {
		t.Fatalf("failed to close updater: %v", err)
	}
	if err := fRW.Close(); err != nil {
		t.Fatalf("failed to close zip after update: %v", err)
	}

	zr, err := OpenReader(zipPath)
	if err != nil {
		t.Fatalf("failed to open reader: %v", err)
	}
	closeAt(t, zr)
	if zr.File[0].UncompressedSize64 != 0 {
		t.Errorf("expected size 0, got %d", zr.File[0].UncompressedSize64)
	}
}
func TestUpdater_PhysicalTruncate(t *testing.T) {
	tmp := t.TempDir()
	zipPath := filepath.Join(tmp, "shrink.zip")

	// 1. Create a large archive. Use Method Store so zeros are not compressed.
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("failed to create zip: %v", err)
	}
	closeAt(t, f)
	zw := NewWriter(f)
	w := mustCreateHeader(t, zw, &FileHeader{
		Name:   "large.txt",
		Method: Store,
	})
	mustWrite(t, w, make([]byte, 100*1024)) // 100KB
	if err := zw.Close(); err != nil {
		t.Fatalf("failed to close writer: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close zip: %v", err)
	}

	initialInfo, err := os.Stat(zipPath)
	if err != nil {
		t.Fatalf("failed to stat zip: %v", err)
	}
	initialSize := initialInfo.Size()

	// 2. Overwrite with a small file
	fRW, err := os.OpenFile(zipPath, os.O_RDWR, 0644)
	if err != nil {
		t.Fatalf("failed to open zip for update: %v", err)
	}
	closeAt(t, fRW)
	u, err := NewUpdater(fRW)
	if err != nil {
		t.Fatalf("failed to init updater: %v", err)
	}
	w, err = u.Append("large.txt", APPEND_MODE_OVERWRITE)
	if err != nil {
		t.Fatalf("failed to overwrite large.txt: %v", err)
	}
	mustWrite(t, w, []byte("small"))
	if err := u.Close(); err != nil {
		t.Fatalf("failed to close updater: %v", err)
	}
	if err := fRW.Close(); err != nil {
		t.Fatalf("failed to close zip after update: %v", err)
	}

	// 3. Check file size on disk
	finalInfo, err := os.Stat(zipPath)
	if err != nil {
		t.Fatalf("failed to stat updated zip: %v", err)
	}
	if finalInfo.Size() >= initialSize {
		t.Errorf("file was not truncated! old size %d, new size %d", initialSize, finalInfo.Size())
	}
}
func TestUpdater_NonZipFile(t *testing.T) {
	tmp := t.TempDir()
	badFile := filepath.Join(tmp, "not_a_zip.txt")
	mustWriteFile(t, badFile, []byte("this is just text"), 0644)

	fRW, err := os.OpenFile(badFile, os.O_RDWR, 0644)
	if err != nil {
		t.Fatalf("failed to open %s: %v", badFile, err)
	}
	closeAt(t, fRW)

	_, err = NewUpdater(fRW)
	if err == nil {
		t.Error("expected error when opening non-zip file for update, got nil")
	}
}
func TestUpdater_CDEArchive(t *testing.T) {
	tmp := t.TempDir()
	zipPath := filepath.Join(tmp, "cde.zip")

	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("failed to create zip: %v", err)
	}
	closeAt(t, f)
	zw := NewWriter(f)
	zw.SetEncryptCentralDirectory(true, "pass")
	w := mustCreate(t, zw, "test.txt")
	mustWrite(t, w, []byte("data"))
	if err := zw.Close(); err != nil {
		t.Fatalf("failed to close writer: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close zip: %v", err)
	}

	fRW, err := os.OpenFile(zipPath, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("failed to open zip for update: %v", err)
	}
	closeAt(t, fRW)

	_, err = NewUpdater(fRW)
	if err == nil || err.Error() != "zip: updating archives with encrypted central directory is not supported" {
		t.Errorf("Expected CDE unsupported error, got: %v", err)
	}
}
func TestUpdater_WithPrefixStub(t *testing.T) {
	tmp := t.TempDir()
	zipPath := filepath.Join(tmp, "stub.exe")

	// 1. Create a file with a prefix (simulating an SFX archive)
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("failed to create zip: %v", err)
	}
	closeAt(t, f)
	stub := []byte("#!/bin/bash\necho SFX\n") // Exactly 21 bytes
	mustWrite(t, f, stub)

	zw := NewWriter(f)
	// SetOffset tells the ZIP writer that the logical start of data is after the prefix.
	zw.SetOffset(int64(len(stub)))
	w := mustCreate(t, zw, "internal.txt")
	mustWrite(t, w, []byte("inside zip"))
	if err := zw.Close(); err != nil {
		t.Fatalf("failed to close writer: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close zip: %v", err)
	}

	// 2. Update this file using the Updater
	fRW, err := os.OpenFile(zipPath, os.O_RDWR, 0644)
	if err != nil {
		t.Fatalf("failed to open zip for update: %v", err)
	}
	closeAt(t, fRW)
	u, err := NewUpdater(fRW)
	if err != nil {
		t.Fatalf("failed to open updater: %v", err)
	}

	// If the ZIP was created with SetOffset, internal offsets already include the prefix size.
	// In this case, the calculated baseOffset for the reader will be 0. Both variants (0 and 21) are valid.
	if u.baseOffset != 0 && u.baseOffset != int64(len(stub)) {
		t.Errorf("unexpected baseOffset: got %d", u.baseOffset)
	}

	w2, err := u.Append("new.txt", APPEND_MODE_KEEP_ORIGINAL)
	if err != nil {
		t.Fatalf("failed to append new.txt: %v", err)
	}
	mustWrite(t, w2, []byte("added later"))
	if err := u.Close(); err != nil {
		t.Fatalf("failed to close updater: %v", err)
	}
	if err := fRW.Close(); err != nil {
		t.Fatalf("failed to close zip after update: %v", err)
	}

	// 3. Verify that the prefix is in place and the data is readable
	zr, err := OpenReader(zipPath)
	if err != nil {
		t.Fatalf("failed to open updated sfx: %v", err)
	}
	closeAt(t, zr)
	// When using SetOffset, the writer creates absolute offsets.
	// The Reader detects this and sets baseOffset to 0. This is correct.
	if zr.baseOffset != 0 && zr.baseOffset != int64(len(stub)) {
		t.Errorf("Reader reported unexpected baseOffset: got %d", zr.baseOffset)
	}
	if len(zr.File) != 2 {
		t.Errorf("expected 2 files, got %d", len(zr.File))
	}
	if err := zr.Close(); err != nil {
		t.Fatalf("failed to close reader: %v", err)
	}

	// Check the physical start of the file
	head := make([]byte, 11)
	fRead, err := os.Open(zipPath)
	if err != nil {
		t.Fatalf("failed to open updated sfx for reading: %v", err)
	}
	closeAt(t, fRead)
	if _, err := io.ReadFull(fRead, head); err != nil {
		t.Fatalf("failed to read prefix stub: %v", err)
	}
	if err := fRead.Close(); err != nil {
		t.Fatalf("failed to close updated sfx: %v", err)
	}
	if string(head) != "#!/bin/bash" {
		t.Errorf("Prefix stub corrupted! got %q", string(head))
	}
}
func TestUpdater_AESEncryption(t *testing.T) {
	tmp := t.TempDir()
	zipPath := filepath.Join(tmp, "update_aes.zip")

	// 1. Create a regular archive
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("failed to create zip: %v", err)
	}
	closeAt(t, f)
	zw := NewWriter(f)
	mustCreate(t, zw, "plain.txt")
	if err := zw.Close(); err != nil {
		t.Fatalf("failed to close writer: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close zip: %v", err)
	}

	// 2. Add an encrypted file via Updater
	fRW, err := os.OpenFile(zipPath, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("failed to open zip for update: %v", err)
	}
	closeAt(t, fRW)
	u, err := NewUpdater(fRW)
	if err != nil {
		t.Fatalf("failed to init updater: %v", err)
	}
	fh := &FileHeader{
		Name:     "encrypted.txt",
		Password: "updater-pass",
	}
	w, err := u.AppendHeader(fh, APPEND_MODE_KEEP_ORIGINAL)
	if err != nil {
		t.Fatalf("AppendHeader failed: %v", err)
	}
	mustWrite(t, w, []byte("secret content"))
	if err := u.Close(); err != nil {
		t.Fatalf("failed to close updater: %v", err)
	}
	if err := fRW.Close(); err != nil {
		t.Fatalf("failed to close zip after update: %v", err)
	}

	// 3. Verify readability
	zr, err := OpenReader(zipPath)
	if err != nil {
		t.Fatalf("failed to open reader: %v", err)
	}
	closeAt(t, zr)
	zr.SetPassword("updater-pass")

	found := false
	for _, file := range zr.File {
		if file.Name == "encrypted.txt" {
			found = true
			rc, err := file.Open()
			if err != nil {
				t.Fatalf("failed to open encrypted file from updater: %v", err)
			}
			closeAt(t, rc)
			data, err := io.ReadAll(rc)
			if err != nil {
				t.Fatalf("failed to read encrypted file from updater: %v", err)
			}
			if err := rc.Close(); err != nil {
				t.Fatalf("failed to close encrypted file from updater: %v", err)
			}
			if string(data) != "secret content" {
				t.Errorf("data corruption in updater AES: got %q", string(data))
			}
		}
	}
	if !found {
		t.Error("encrypted file not found in updated archive")
	}
}
