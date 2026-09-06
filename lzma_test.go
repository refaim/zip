package zip

import (
	"bytes"
	"io"
	"testing"
)

func TestLZMA_Writer_Roundtrip(t *testing.T) {
	data := []byte("LZMA compression roundtrip test data. This should be compressed effectively.")
	// Repeat data to make it worth compressing
	for i := 0; i < 5; i++ {
		data = append(data, data...)
	}

	buf := new(bytes.Buffer)
	zw := NewWriter(buf)

	w, err := zw.CreateHeader(&FileHeader{
		Name:   "test_lzma.txt",
		Method: LZMA,
	})
	if err != nil {
		t.Fatalf("Failed to create LZMA header: %v", err)
	}

	if _, err := w.Write(data); err != nil {
		t.Fatalf("Failed to write LZMA data: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("Failed to close LZMA writer: %v", err)
	}

	// Read back
	zr, err := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("Failed to create reader: %v", err)
	}

	if len(zr.File) != 1 {
		t.Fatal("Expected 1 file in archive")
	}

	f := zr.File[0]
	if f.Method != LZMA {
		t.Errorf("Expected method LZMA (14), got %v", f.Method)
	}

	rc, err := f.Open()
	if err != nil {
		t.Fatalf("Failed to open LZMA file: %v", err)
	}
	closeAt(t, rc)

	decompressed, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("Failed to read LZMA data: %v", err)
	}

	if !bytes.Equal(decompressed, data) {
		t.Error("Decompressed data mismatch")
	}
}

// lzmaUnusablePropertiesZip is a hundred byte archive holding one entry named
// "a" that declares method 14 and carries no data at all, so the properties
// header the method promises is not there to read.
var lzmaUnusablePropertiesZip = []byte{
	0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x61, 0x50, 0x4b, 0x01, 0x02, 0x14,
	0x00, 0x14, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x61, 0x50, 0x4b, 0x05, 0x06, 0x00, 0x00,
	0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x2f, 0x00, 0x00, 0x00, 0x1f, 0x00,
	0x00, 0x00, 0x00, 0x00,
}

// TestLZMA_EntryWithUnusablePropertiesIsRefused: an entry whose LZMA
// properties header does not parse has to come back as an error on the entry.
// The constructor used to answer such a header with a nil io.ReadCloser, which
// Open wrapped without looking, so the first read and the close dereferenced
// it instead of reporting anything.
func TestLZMA_EntryWithUnusablePropertiesIsRefused(t *testing.T) {
	zr, err := NewReader(bytes.NewReader(lzmaUnusablePropertiesZip), int64(len(lzmaUnusablePropertiesZip)))
	if err != nil {
		t.Fatalf("open the archive: %v", err)
	}
	if len(zr.File) != 1 {
		t.Fatalf("archive holds %d entries, want 1", len(zr.File))
	}

	rc, err := zr.File[0].Open()
	if err != nil {
		return
	}
	closeAt(t, rc)
	if _, err := io.Copy(io.Discard, rc); err == nil {
		t.Fatal("an entry with no LZMA properties read as if it held data")
	}
	if err := rc.Close(); err != nil {
		t.Errorf("close the refused entry: %v", err)
	}
}
