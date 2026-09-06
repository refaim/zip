package filepool

import (
	"errors"
	"io"
	"os"
	"testing"
	"time"
)

func TestFilePool_Basic(t *testing.T) {
	tmpDir := t.TempDir()

	fp, err := New(tmpDir, 2, 1024)
	if err != nil {
		t.Fatalf("Failed to create file pool: %v", err)
	}

	f1 := fp.Get()
	if f1 == nil {
		t.Fatal("Expected non-nil file from pool")
	}

	n, err := f1.Write([]byte("hello pool"))
	if err != nil || n != 10 {
		t.Errorf("Failed to write to pool file: %d, %v", n, err)
	}

	if f1.Written() != 10 {
		t.Errorf("Expected 10 written bytes, got %d", f1.Written())
	}

	if _, err := f1.Hasher().Write([]byte("hello pool")); err != nil {
		t.Fatalf("Failed to write to the pool file's hasher: %v", err)
	}
	if f1.Checksum() == 0 {
		t.Error("Expected non-zero checksum")
	}

	buf := make([]byte, 10)
	n, err = f1.Read(buf)
	if err != nil && err != io.EOF {
		t.Errorf("Failed to read from pool file: %d, %v", n, err)
	}
	if string(buf[:n]) != "hello pool" {
		t.Errorf("Expected 'hello pool', got %q", string(buf[:n]))
	}

	if err := fp.Put(f1); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Verify that the file was reset
	f2 := fp.Get()
	if f2.Written() != 0 {
		t.Errorf("Expected file to be reset, but written size is %d", f2.Written())
	}
	if err := fp.Put(f2); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	err = fp.Close()
	if err != nil {
		t.Fatalf("Failed to close file pool: %v", err)
	}
}

func TestFilePool_ZeroSize(t *testing.T) {
	_, err := New(".", 0, 1024)
	if err != ErrPoolSizeLessThanZero {
		t.Errorf("Expected ErrPoolSizeLessThanZero, got %v", err)
	}
}

func TestFilePool_WritePastBuffer(t *testing.T) {
	tmpDir := t.TempDir()

	// Create pool with extremely small buffer to force writing to temp file
	fp, err := New(tmpDir, 1, 4)
	if err != nil {
		t.Fatal(err)
	}
	// The pool owns the temp file the write below forces it to create, and
	// this is the only close of it: a t.Fatal in the middle would otherwise
	// leave the handle open across the removal of tmpDir. The helpers of
	// package zip are not visible here, so the net is spelled out.
	t.Cleanup(func() {
		if err := fp.Close(); err != nil {
			t.Errorf("Failed to close file pool: %v", err)
		}
	})

	f := fp.Get()
	t.Cleanup(func() {
		if err := fp.Put(f); err != nil {
			t.Errorf("Put failed: %v", err)
		}
	})

	data := []byte("this data exceeds the small buffer size of 4 bytes")
	n, err := f.Write(data)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != len(data) {
		t.Errorf("Expected %d bytes written, got %d", len(data), n)
	}

	if f.f == nil {
		t.Error("Expected backing file to be created, but it's nil")
	}

	readBuf := make([]byte, len(data))
	n, err = f.Read(readBuf)
	if err != nil && err != io.EOF {
		t.Fatalf("Read failed: %v", err)
	}
	if n != len(data) {
		t.Errorf("Expected %d bytes read, got %d", len(data), n)
	}

	if string(readBuf) != string(data) {
		t.Errorf("Data mismatch. Got %q, want %q", string(readBuf), string(data))
	}
}

func TestFilePoolCloseError(t *testing.T) {
	errs := filePoolCloseError{errors.New("error 1"), errors.New("error 2")}

	if errs.Len() != 2 {
		t.Errorf("Expected length 2, got %d", errs.Len())
	}

	str := errs.Error()
	if str != "error 1\nerror 2\n" {
		t.Errorf("Unexpected error string: %q", str)
	}

	unwrapped := errs.Unwrap()
	if unwrapped == nil {
		t.Errorf("Expected unwrapped error, got nil")
	}

	singleErr := filePoolCloseError{errors.New("single error")}
	if singleErr.Error() != "single error" {
		t.Errorf("Unexpected single error string: %q", singleErr.Error())
	}
}

func TestFilePool_CleanupOnClose(t *testing.T) {
	tmpDir := t.TempDir()

	fp, err := New(tmpDir, 1, 4)
	if err != nil {
		t.Fatal(err)
	}
	// The test closes the pool itself below -- that close is what it asserts
	// on. This is only the net for the physical file the write creates, so
	// that a t.Fatal before that point still releases it; closing an already
	// closed pool is a no-op.
	t.Cleanup(func() {
		if err := fp.Close(); err != nil {
			t.Errorf("Failed to close file pool: %v", err)
		}
	})

	f := fp.Get()
	if _, err := f.Write([]byte("exceed buffer size to create physical file")); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	physicalName := f.f.Name()
	if _, err := os.Stat(physicalName); os.IsNotExist(err) {
		t.Fatalf("Physical file %s was not created", physicalName)
	}

	if err := fp.Put(f); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	err = fp.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	if _, err := os.Stat(physicalName); err == nil {
		t.Errorf("Physical file %s was not deleted during cleanup", physicalName)
	}
}

// TestFilePool_PutReportsAFailedTruncate covers the one thing Put does that
// can fail. Returning a file to the pool empties it; when the emptying does
// not happen the file still carries the bytes of the entry before it, and the
// caller that hands it back is the last one in a position to notice.
func TestFilePool_PutReportsAFailedTruncate(t *testing.T) {
	tmpDir := t.TempDir()
	fp, err := New(tmpDir, 1, 4)
	if err != nil {
		t.Fatalf("Failed to create file pool: %v", err)
	}

	f := fp.Get()
	if _, err := f.Write([]byte("more than four bytes, so a file is made")); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if f.f == nil {
		t.Fatal("expected the write to spill into a file")
	}
	name := f.f.Name()

	// Closing the handle is the cheapest way to make a truncate fail on
	// every platform the pool runs on.
	if err := f.f.Close(); err != nil {
		t.Fatalf("closing the pool file failed: %v", err)
	}

	if err := fp.Put(f); err == nil {
		t.Fatal("Put reported success although the pool file was not emptied")
	}

	// The file still has to go back to the pool: a caller that stops using
	// the pool because one file misbehaved would deadlock on the next Get.
	done := make(chan struct{})
	go func() {
		defer close(done)
		fp.Get()
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Put did not return the file to the pool")
	}

	if err := os.Remove(name); err != nil && !os.IsNotExist(err) {
		t.Errorf("removing the pool file failed: %v", err)
	}
}
