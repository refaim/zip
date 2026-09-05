package zip

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"testing"
)

// buildZipCryptoStored hand-assembles a single-entry ZipCrypto archive with
// a Store payload (the Writer cannot produce traditional encryption) and
// returns its bytes. checkByte is what the decryptor compares against the
// high byte of the CRC, so passing the real one makes a valid archive and
// passing another byte simulates a wrong password that the one-byte check
// does not catch.
func buildZipCryptoStored(t *testing.T, name string, data []byte, password string, checkByte byte) []byte {
	t.Helper()
	crc := crc32.ChecksumIEEE(data)
	header := make([]byte, 12)
	for i := range header[:11] {
		header[i] = byte(0x40 + i)
	}
	header[11] = checkByte
	plain := append(header, data...)
	enc := make([]byte, len(plain))
	c := newZipCrypto([]byte(password))
	for i, v := range plain {
		enc[i] = v ^ c.decryptByte()
		c.updateKeys(v)
	}
	var buf bytes.Buffer
	le := binary.LittleEndian
	put16 := func(v uint16) { mustBinaryWrite(t, &buf, le, v) }
	put32 := func(v uint32) { mustBinaryWrite(t, &buf, le, v) }
	// Local file header.
	put32(0x04034b50)
	put16(20)
	put16(1) // encrypted
	put16(Store)
	put16(0)
	put16(0)
	put32(crc)
	put32(uint32(len(enc)))
	put32(uint32(len(data)))
	put16(uint16(len(name)))
	put16(0)
	buf.WriteString(name)
	buf.Write(enc)
	cdOffset := buf.Len()
	// Central directory.
	put32(0x02014b50)
	put16(20)
	put16(20)
	put16(1)
	put16(Store)
	put16(0)
	put16(0)
	put32(crc)
	put32(uint32(len(enc)))
	put32(uint32(len(data)))
	put16(uint16(len(name)))
	put16(0)
	put16(0)
	put16(0)
	put16(0)
	put32(0)
	put32(0)
	buf.WriteString(name)
	cdSize := buf.Len() - cdOffset
	// End of central directory.
	put32(0x06054b50)
	put16(0)
	put16(0)
	put16(1)
	put16(1)
	put32(uint32(cdSize))
	put32(uint32(cdOffset))
	put16(0)
	return buf.Bytes()
}

func openSingle(t *testing.T, archive []byte, password string) *File {
	t.Helper()
	r, err := NewReaderWithPassword(bytes.NewReader(archive), int64(len(archive)), password)
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	if len(r.File) != 1 {
		t.Fatalf("got %d entries, want 1", len(r.File))
	}
	return r.File[0]
}

func TestZipCrypto_CorrectPasswordReads(t *testing.T) {
	data := []byte("secret data")
	crc := crc32.ChecksumIEEE(data)
	archive := buildZipCryptoStored(t, "s.txt", data, "Correct", byte(crc>>24))
	rc, err := openSingle(t, archive, "Correct").Open()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	closeAt(t, rc)
	got, err := io.ReadAll(rc)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("ReadAll = %q, %v", got, err)
	}
}

func TestZipCrypto_WrongPasswordCaughtByCheckByte(t *testing.T) {
	data := []byte("secret data")
	crc := crc32.ChecksumIEEE(data)
	archive := buildZipCryptoStored(t, "s.txt", data, "Correct", byte(crc>>24))
	// Find a password the check byte rejects (almost every one does).
	for _, pw := range []string{"Wrong", "Wrong2", "Wrong3", "Wrong4", "Wrong5"} {
		_, err := openSingle(t, archive, pw).Open()
		if err == nil {
			continue
		}
		if !errors.Is(err, ErrPassword) || err != ErrPassword {
			t.Fatalf("check-byte rejection must be exactly ErrPassword, got %v", err)
		}
		return
	}
	t.Fatal("no candidate password was rejected by the check byte")
}

// TestZipCrypto_WrongPasswordPastCheckByte simulates the 1-in-256 case: the
// check byte matches the wrong password, so only the CRC reveals it. The
// error must identify as a password error and still carry ErrChecksum.
func TestZipCrypto_WrongPasswordPastCheckByte(t *testing.T) {
	data := []byte("secret data")
	crc := crc32.ChecksumIEEE(data)
	// Build a valid archive for "Correct", learn what "Wrong" decrypts the
	// header's check byte to, and patch the stored CRC's high byte to that
	// value: the check byte then accepts "Wrong" and the CRC (now wrong for
	// the data) fails afterwards, exactly the situation under test.
	probe := buildZipCryptoStored(t, "s.txt", data, "Correct", byte(crc>>24))
	f := openSingle(t, probe, "Wrong")
	// Decrypt the 12-byte header with "Wrong" to learn its last byte.
	raw, err := f.OpenRaw()
	if err != nil {
		t.Fatal(err)
	}
	head := make([]byte, 12)
	if _, err := io.ReadFull(raw, head); err != nil {
		t.Fatal(err)
	}
	c := newZipCrypto([]byte("Wrong"))
	c.decrypt(head)
	archive := append([]byte(nil), probe...)
	wantCRC := (crc & 0x00ffffff) | uint32(head[11])<<24
	if wantCRC == crc {
		t.Skip("check bytes coincide; nothing to test")
	}
	patchCRC := func(sig uint32, off int) {
		for i := 0; i+4 <= len(archive); i++ {
			if binary.LittleEndian.Uint32(archive[i:]) == sig {
				binary.LittleEndian.PutUint32(archive[i+off:], wantCRC)
				return
			}
		}
		t.Fatalf("signature %#x not found", sig)
	}
	patchCRC(0x04034b50, 14)
	patchCRC(0x02014b50, 16)

	rc, err := openSingle(t, archive, "Wrong").Open()
	if err != nil {
		t.Fatalf("check byte should now accept \"Wrong\", got %v", err)
	}
	closeAt(t, rc)
	_, err = io.ReadAll(rc)
	if err == nil {
		t.Fatal("reading with the wrong password must fail")
	}
	var ede *EncryptedDataError
	if !errors.As(err, &ede) {
		t.Fatalf("want *EncryptedDataError, got %T: %v", err, err)
	}
	if !errors.Is(err, ErrPassword) || !errors.Is(err, ErrChecksum) {
		t.Errorf("must match both ErrPassword and ErrChecksum: %v", err)
	}
	if rc2, err := openSingle(t, archive, "Correct").Open(); err == nil {
		closeAt(t, rc2)
		t.Errorf("the patched archive must now reject the real password at the check byte")
	}
}

// A checksum failure on an unencrypted entry is corruption, not a password
// problem, and must stay a bare ErrChecksum.
func TestUnencrypted_ChecksumStaysPlain(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)
	fw, err := w.CreateHeader(&FileHeader{Name: "a.txt", Method: Store})
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, fw, []byte("hello world"))
	if err := w.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	archive := buf.Bytes()
	// Corrupt a payload byte.
	idx := bytes.Index(archive, []byte("hello world"))
	archive[idx] ^= 0xff
	rc, err := openSingle(t, archive, "").Open()
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, rc)
	_, err = io.ReadAll(rc)
	if err != ErrChecksum {
		t.Fatalf("want bare ErrChecksum, got %v", err)
	}
	if errors.Is(err, ErrPassword) {
		t.Error("unencrypted checksum failure must not look like a password error")
	}
}
