package zip

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestZipIndexingOptimization_Threshold(t *testing.T) {
	// Временно подменяем os.Args, чтобы убрать "-test." и активировать порог 4МБ
	oldArgs := os.Args
	os.Args = []string{"zipper"}
	defer func() { os.Args = oldArgs }()

	tmpDir := t.TempDir()
	srcDir := filepath.Join(tmpDir, "src")
	mustMkdirAll(t, srcDir)

	// 1. Тест: Маленький файл (1МБ) -> Скрытого индекса быть НЕ должно
	smallFile := filepath.Join(srcDir, "small.bin")
	mustWriteFile(t, smallFile, bytes.Repeat([]byte("A"), 1024*1024), 0644)

	arcSmall := filepath.Join(tmpDir, "small.zip")
	f1, err := os.Create(arcSmall)
	if err != nil {
		t.Fatalf("create %s: %v", arcSmall, err)
	}
	closeAt(t, f1)
	a1, err := NewArchiver(f1, tmpDir, WithArchiverMethod(Deflate), WithArchiverSeekIndex(1024*1024, false))
	if err != nil {
		t.Fatalf("new archiver for %s: %v", arcSmall, err)
	}
	closeAt(t, a1)
	fi1, err := os.Stat(smallFile)
	if err != nil {
		t.Fatalf("stat %s: %v", smallFile, err)
	}
	if err := a1.Archive(context.Background(), map[string]os.FileInfo{smallFile: fi1}); err != nil {
		t.Fatalf("archive %s: %v", smallFile, err)
	}
	if err := a1.Close(); err != nil {
		t.Fatalf("close archiver for %s: %v", arcSmall, err)
	}
	if err := f1.Close(); err != nil {
		t.Fatalf("close %s: %v", arcSmall, err)
	}

	zr1, err := OpenReader(arcSmall)
	if err != nil {
		t.Fatalf("open %s: %v", arcSmall, err)
	}
	closeAt(t, zr1)
	idxType1, _, _ := zr1.File[0].findHiddenIndex()
	if err := zr1.Close(); err != nil {
		t.Fatalf("close %s: %v", arcSmall, err)
	}
	if idxType1 != 0 {
		t.Errorf("Expected no hidden index for 1MB file, but found index type %d", idxType1)
	}

	// 2. Тест: Большой файл (5МБ) -> Скрытый индекс ДОЛЖЕН быть
	largeFile := filepath.Join(srcDir, "large.bin")
	mustWriteFile(t, largeFile, bytes.Repeat([]byte("B"), 5*1024*1024), 0644)

	arcLarge := filepath.Join(tmpDir, "large.zip")
	f2, err := os.Create(arcLarge)
	if err != nil {
		t.Fatalf("create %s: %v", arcLarge, err)
	}
	closeAt(t, f2)
	a2, err := NewArchiver(f2, tmpDir, WithArchiverMethod(Deflate), WithArchiverSeekIndex(1024*1024, false))
	if err != nil {
		t.Fatalf("new archiver for %s: %v", arcLarge, err)
	}
	closeAt(t, a2)
	fi2, err := os.Stat(largeFile)
	if err != nil {
		t.Fatalf("stat %s: %v", largeFile, err)
	}
	if err := a2.Archive(context.Background(), map[string]os.FileInfo{largeFile: fi2}); err != nil {
		t.Fatalf("archive %s: %v", largeFile, err)
	}
	if err := a2.Close(); err != nil {
		t.Fatalf("close archiver for %s: %v", arcLarge, err)
	}
	if err := f2.Close(); err != nil {
		t.Fatalf("close %s: %v", arcLarge, err)
	}

	zr2, err := OpenReader(arcLarge)
	if err != nil {
		t.Fatalf("open %s: %v", arcLarge, err)
	}
	closeAt(t, zr2)
	idxType, payload, err2 := zr2.File[0].findHiddenIndex()
	if err := zr2.Close(); err != nil {
		t.Fatalf("close %s: %v", arcLarge, err)
	}
	if err2 != nil || idxType == 0 || len(payload) == 0 {
		t.Errorf("Expected hidden index for 5MB file, but it was missing: %v", err2)
	}
}
