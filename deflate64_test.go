package zip

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestDeflate64_Registration(t *testing.T) {
	// Verify that the method is registered in the global map
	dcomp := decompressor(Deflate64)
	if dcomp == nil {
		t.Fatal("Deflate64 decompressor not registered")
	}
}

func TestDeflate64_External7z(t *testing.T) {
	p7zPath, err := exec.LookPath("7z")
	if err != nil {
		t.Skip("7z utility not found, skipping external Deflate64 compression test")
	}

	tmpDir := t.TempDir()
	srcFile := filepath.Join(tmpDir, "test.txt")

	// Create content with repeating patterns to test huffman/LZ references
	var content bytes.Buffer
	for i := 0; i < 1000; i++ {
		content.WriteString("Deflate64 compression test data repeating multiple times to verify backreferences on larger streams. ")
	}
	err = os.WriteFile(srcFile, content.Bytes(), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	zipPath := filepath.Join(tmpDir, "deflate64_7z.zip")

	// Run 7z to compress to Deflate64 method
	cmd := exec.Command(p7zPath, "a", "-tzip", "-m0=deflate64", zipPath, srcFile)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("7z compression failed: %v, output: %s", err, string(output))
	}

	// Open with our library
	zr, err := OpenReader(zipPath)
	if err != nil {
		t.Fatalf("failed to open generated zip: %v", err)
	}
	closeAt(t, zr)

	if len(zr.File) == 0 {
		t.Fatal("no files in the zip archive")
	}

	f := zr.File[0]
	if f.Method != Deflate64 {
		t.Errorf("expected compression method Deflate64 (%d), got %d", Deflate64, f.Method)
	}

	rc, err := f.Open()
	if err != nil {
		t.Fatalf("failed to open file inside zip: %v", err)
	}
	closeAt(t, rc)

	decompressed, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("decompression failed: %v", err)
	}

	if !bytes.Equal(decompressed, content.Bytes()) {
		t.Error("decompressed content mismatch with original")
	}
}

// TestDeflate64_StoredBlock decodes an uncompressed (stored) block, the block
// type the encoder in this package never produces, and checks that a header
// whose length and one's complement disagree is rejected instead of being
// decoded as whatever the length happens to say.
func TestDeflate64_StoredBlock(t *testing.T) {
	payload := []byte("stored blocks carry their bytes verbatim")
	const payloadLen = 40
	if len(payload) != payloadLen {
		t.Fatalf("payload is %d bytes, the header below says %d", len(payload), payloadLen)
	}

	// First byte: bfinal = 1, btype = 00 (stored). The header is byte aligned
	// from there: LEN little endian, then its one's complement, then the bytes.
	storedBlock := func(nlenLo, nlenHi byte) io.Reader {
		return bytes.NewReader(append([]byte{0x01, payloadLen, 0x00, nlenLo, nlenHi}, payload...))
	}

	decoded, err := io.ReadAll(decodeDeflate64(storedBlock(0xD7, 0xFF)))
	if err != nil {
		t.Fatalf("decoding a stored block failed: %v", err)
	}
	if !bytes.Equal(decoded, payload) {
		t.Errorf("decoded %q, want %q", decoded, payload)
	}

	if _, err := io.ReadAll(decodeDeflate64(storedBlock(0xD8, 0xFF))); !errors.Is(err, errDataError) {
		t.Errorf("a stored block whose length complement is off by one decoded with error %v, want %v", err, errDataError)
	}
}

// TestInputBuffer_CopyToDrainsBitBuffer covers the byte accurate hand off in
// copyTo. A block that ends on a byte boundary can leave whole bytes sitting
// in the bit accumulator, and the bytes a stored block copies out have to
// start with those rather than with the next unread input byte.
func TestInputBuffer_CopyToDrainsBitBuffer(t *testing.T) {
	in := newInputBuffer(bitsBuffer{}, []byte{0x11, 0x22, 0x33, 0x44})

	in.tryLoad16Bits() // pulls 0x11 and 0x22 into the accumulator
	if got := in.availableBits(); got != 16 {
		t.Fatalf("availableBits() = %d, want 16", got)
	}

	out := make([]byte, 4)
	if n := in.copyTo(out); n != len(out) {
		t.Fatalf("copyTo copied %d bytes, want %d", n, len(out))
	}
	if want := []byte{0x11, 0x22, 0x33, 0x44}; !bytes.Equal(out, want) {
		t.Errorf("copyTo produced %x, want %x", out, want)
	}
	if in.availableBits() != 0 {
		t.Errorf("copyTo left %d bits behind, want none", in.availableBits())
	}
	if in.readBytes != 4 {
		t.Errorf("copyTo accounted for %d read bytes, want 4", in.readBytes)
	}
}
