package zip

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// The encapsulation stores an authentication code over the payload it writes,
// and nothing used to look at it. A modified archive therefore decrypted into
// whatever the modification made of it, and a wrong password decrypted into
// bytes that are not an archive and were reported as a broken archive rather
// than as a password. TestXCrypt_RoundTrip covers the passwords; the tests
// below cover a payload and a code that do not match.

// xcryptEntryDataOffset returns where the named entry's data begins in the
// archive.
func xcryptEntryDataOffset(t *testing.T, archive []byte, name string) int64 {
	t.Helper()
	zr, err := NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		t.Fatalf("read the outer archive: %v", err)
	}
	for _, f := range zr.File {
		if f.Name == name {
			off, err := f.DataOffset()
			if err != nil {
				t.Fatalf("offset of the data of %q: %v", name, err)
			}
			return off
		}
	}
	t.Fatalf("the archive holds no entry named %q", name)
	return 0
}

// xcryptFlipPayloadByte flips a bit of the first byte of the encrypted payload
// of the XCrypt archive at path, in the file itself, so that everything around
// it stays exactly what the encapsulation wrote.
func xcryptFlipPayloadByte(t *testing.T, path string) {
	t.Helper()
	zr, err := OpenReader(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	at := int64(-1)
	for _, f := range zr.File {
		if f.Name == xcryptPayloadName {
			if at, err = f.DataOffset(); err != nil {
				t.Fatalf("offset of the payload data: %v", err)
			}
		}
	}
	if err := zr.Close(); err != nil {
		t.Fatalf("close %s: %v", path, err)
	}
	if at < 0 {
		t.Fatalf("%s holds no XCrypt payload entry", path)
	}

	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("reopen %s: %v", path, err)
	}
	// The net for the paths below that stop at a t.Fatal; the close that
	// matters is the explicit one at the end.
	closeAt(t, f)
	var b [1]byte
	if _, err := f.ReadAt(b[:], at); err != nil {
		t.Fatalf("read the payload byte: %v", err)
	}
	b[0] ^= 0x01
	if _, err := f.WriteAt(b[:], at); err != nil {
		t.Fatalf("write the payload byte: %v", err)
	}
	// The write has to be on disk before the archive is opened again.
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", path, err)
	}
}

// TestXCrypt_RefusesATamperedPayload takes an archive the encapsulation
// itself wrote, changes one byte of the encrypted payload, and opens it with
// the password it was written with.
func TestXCrypt_RefusesATamperedPayload(t *testing.T) {
	dir := t.TempDir()
	staged := filepath.Join(dir, "staged.zip")
	xcryptStageInner(t, staged)
	final := filepath.Join(dir, "encrypted.zip")
	const password = "correct horse battery staple"
	if err := EncapsulateXCryptZip(final, staged, password); err != nil {
		t.Fatalf("encapsulate: %v", err)
	}
	xcryptFlipPayloadByte(t, final)

	zr, err := OpenReaderWithPassword(final, password)
	if err == nil {
		closeAt(t, zr)
		t.Fatalf("a tampered archive opened with %d entries", len(zr.File))
	}
	if !errors.Is(err, ErrChecksum) || !errors.Is(err, ErrPassword) {
		t.Errorf("a tampered archive reported %v, want the authentication code refused", err)
	}
}

// TestCheckXCryptZip_ReportsACodeThatDoesNotCoverThePayload covers the same
// ground with a key derivation cheap enough to run many times over, from both
// sides -- a payload the code does not cover and a code that covers no payload
// -- plus the archive that stops answering part way through the check.
func TestCheckXCryptZip_ReportsACodeThatDoesNotCoverThePayload(t *testing.T) {
	dir := t.TempDir()
	inner := xcryptStageInner(t, filepath.Join(dir, "staged.zip"))
	const password = "a password"

	t.Run("a flipped payload byte", func(t *testing.T) {
		archive := xcryptSealed(t, inner, password, nil)
		archive[xcryptEntryDataOffset(t, archive, xcryptPayloadName)] ^= 0x01

		got, size, err := checkXCryptZip(bytes.NewReader(archive), int64(len(archive)), password)
		if !errors.Is(err, ErrChecksum) || !errors.Is(err, ErrPassword) {
			t.Fatalf("the check reported %v, want the authentication code refused", err)
		}
		if got != nil || size != 0 {
			t.Errorf("a failed check handed back a reader of size %d", size)
		}
	})

	t.Run("a code of zeros in the header", func(t *testing.T) {
		hdr := (&XCryptHeader{
			Version: 1, KdfAlgo: 1, Cipher: 1, Iterations: 1000,
			Salt: bytes.Repeat([]byte{1}, 32), IV: bytes.Repeat([]byte{2}, 16), MAC: make([]byte, 32),
		}).Encode()
		archive := xcryptOuterArchive(t, xcryptOuterSpec{
			header:       hdr,
			payload:      []byte("encrypted"),
			payloadExtra: xcryptTagExtra(),
		})

		got, size, err := checkXCryptZip(bytes.NewReader(archive), int64(len(archive)), password)
		if !errors.Is(err, ErrChecksum) || !errors.Is(err, ErrPassword) {
			t.Fatalf("the check reported %v, want the authentication code refused", err)
		}
		if got != nil || size != 0 {
			t.Errorf("a failed check handed back a reader of size %d", size)
		}
	})

	t.Run("an archive that stops answering during the check", func(t *testing.T) {
		archive := xcryptSealed(t, inner, password, nil)
		at := xcryptEntryDataOffset(t, archive, xcryptPayloadName)

		ra := &readerCovFailingAt{data: archive, fail: func(off int64, _ int) bool { return off == at }}
		got, size, err := checkXCryptZip(ra, int64(len(archive)), password)
		if !errors.Is(err, errReaderCovDevice) {
			t.Fatalf("the check reported %v, want the read failure", err)
		}
		if got != nil || size != 0 {
			t.Errorf("a failed check handed back a reader of size %d", size)
		}
	})
}
