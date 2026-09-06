package zip

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	mathrand "math/rand"
	"testing"
)

// A WinZip AES entry is protected by an authentication code over its
// ciphertext, and by nothing else: the CRC of such an entry is zero by design,
// and AES-CTR is malleable, so a flipped bit in the archive is a flipped bit
// in the plaintext. Open checks that code when it reaches the end of the
// entry. The random-access path did not check it at all, and the tests below
// are what say that it does now.

// #nosec G101 -- not a credential: the literal the fixtures below are written
// with and then read back with, so it has to be in the source
const aesIntegrityPassword = "seek-integrity"

// aesIntegrityName is the entry every fixture here holds.
const aesIntegrityName = "secret.bin"

// aesIntegritySaltLen is the salt of an AES-256 entry, which is what all the
// fixtures are written as. The ciphertext begins behind it and behind the
// two-byte password verifier.
const aesIntegritySaltLen = 16

// aesIntegrityBody returns n bytes that do not compress away, so that the
// compressed entry a seek index is built over is about as long as its
// contents and a pass over it is visible in what a reader reads.
func aesIntegrityBody(n int) []byte {
	body := make([]byte, n)
	// #nosec G404 -- a fixed seed is the point: the fixture has to be the same archive on every run
	rng := mathrand.New(mathrand.NewSource(20260906))
	// Rand.Read fills the whole slice and reports no error, ever.
	_, _ = rng.Read(body)
	return body
}

// aesIntegrityArchive writes an archive holding one AES-256 entry with the
// contents body; fh carries the method and whatever seek index the fixture
// wants.
func aesIntegrityArchive(t *testing.T, fh *FileHeader, body []byte) []byte {
	t.Helper()
	fh.Name = aesIntegrityName
	fh.Password = aesIntegrityPassword
	fh.AESStrength = 3
	buf := new(bytes.Buffer)
	zw := NewWriter(buf)
	mustWrite(t, mustCreateHeader(t, zw, fh), body)
	if err := zw.Close(); err != nil {
		t.Fatalf("closing the writer: %v", err)
	}
	return buf.Bytes()
}

// aesIntegrityEntry reads the archive back with the fixture password and
// returns its first entry.
func aesIntegrityEntry(t *testing.T, ra io.ReaderAt, size int64) *File {
	t.Helper()
	zr, err := NewReaderWithPassword(ra, size, aesIntegrityPassword)
	if err != nil {
		t.Fatalf("reading the archive back: %v", err)
	}
	return zr.File[0]
}

// aesIntegrityFlipCiphertext flips a bit of the first ciphertext byte of the
// archive's entry.
func aesIntegrityFlipCiphertext(t *testing.T, raw []byte) {
	t.Helper()
	off, err := aesIntegrityEntry(t, bytes.NewReader(raw), int64(len(raw))).DataOffset()
	if err != nil {
		t.Fatalf("offset of the entry data: %v", err)
	}
	raw[off+aesIntegritySaltLen+2] ^= 0x01
}

// aesIntegrityCounter serves an archive through ReadAt and counts the reads
// that ask for the whole ciphertext of the entry in one go. That read is the
// authentication pass and nothing else: the decompressor asks for a few
// kilobytes at a time. Counting it is how a test says the pass ran once.
type aesIntegrityCounter struct {
	data []byte
	at   int64 // where the entry's ciphertext begins in the archive
	size int   // how long it is
	full int   // reads of exactly that range
}

func (c *aesIntegrityCounter) ReadAt(p []byte, off int64) (int, error) {
	if off == c.at && len(p) == c.size {
		c.full++
	}
	return bytes.NewReader(c.data).ReadAt(p, off)
}

// aesIntegrityCiphertext returns where the entry's ciphertext begins in raw
// and how long it is: the salt and the two-byte verifier come first, and the
// ten-byte authentication code follows.
func aesIntegrityCiphertext(t *testing.T, raw []byte) (at int64, size int) {
	t.Helper()
	f := aesIntegrityEntry(t, bytes.NewReader(raw), int64(len(raw)))
	off, err := f.DataOffset()
	if err != nil {
		t.Fatalf("offset of the entry data: %v", err)
	}
	comp, err := u64toi64(f.CompressedSize64)
	if err != nil {
		t.Fatalf("compressed size of the entry: %v", err)
	}
	return off + aesIntegritySaltLen + 2, int(comp - aesIntegritySaltLen - 2 - 10)
}

// TestWinZipAES_SeekableAuthenticatesTheEntry: the stored entry goes through
// the direct random-access path, where the check runs before a reader is
// handed back at all.
func TestWinZipAES_SeekableAuthenticatesTheEntry(t *testing.T) {
	body := aesIntegrityBody(8192)

	t.Run("an untouched entry reads through seeks", func(t *testing.T) {
		raw := aesIntegrityArchive(t, &FileHeader{Method: Store}, body)
		rs, err := aesIntegrityEntry(t, bytes.NewReader(raw), int64(len(raw))).OpenSeekable()
		if err != nil {
			t.Fatalf("OpenSeekable: %v", err)
		}
		for _, off := range []int64{0, 17, 4095, int64(len(body)) - 16} {
			if _, err := rs.Seek(off, io.SeekStart); err != nil {
				t.Fatalf("seek to %d: %v", off, err)
			}
			got := make([]byte, 16)
			if _, err := io.ReadFull(rs, got); err != nil {
				t.Fatalf("read at %d: %v", off, err)
			}
			if !bytes.Equal(got, body[off:off+16]) {
				t.Fatalf("at %d the entry reads %x, want %x", off, got, body[off:off+16])
			}
		}
	})

	t.Run("an entry with nothing in it", func(t *testing.T) {
		// The shortest entry the format has: salt, verifier and a code
		// over no bytes at all. The pass has to answer that as a pass.
		raw := aesIntegrityArchive(t, &FileHeader{Method: Store}, nil)
		rs, err := aesIntegrityEntry(t, bytes.NewReader(raw), int64(len(raw))).OpenSeekable()
		if err != nil {
			t.Fatalf("OpenSeekable on an empty entry: %v", err)
		}
		got, err := io.ReadAll(rs)
		if err != nil {
			t.Fatalf("reading an empty entry: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("an empty entry read back %d bytes", len(got))
		}
	})

	t.Run("a flipped ciphertext bit is refused", func(t *testing.T) {
		raw := aesIntegrityArchive(t, &FileHeader{Method: Store}, body)
		aesIntegrityFlipCiphertext(t, raw)
		rs, err := aesIntegrityEntry(t, bytes.NewReader(raw), int64(len(raw))).OpenSeekable()
		if err == nil {
			t.Fatalf("a tampered entry opened, and reads %d bytes", mustSeekEnd(t, rs))
		}
		if !errors.Is(err, ErrChecksum) || !errors.Is(err, ErrPassword) {
			t.Fatalf("a tampered entry reported %v, want the checksum error the sequential path reports", err)
		}
	})

	t.Run("the unverified variant hands the tampered bytes over", func(t *testing.T) {
		raw := aesIntegrityArchive(t, &FileHeader{Method: Store}, body)
		aesIntegrityFlipCiphertext(t, raw)
		rs, err := aesIntegrityEntry(t, bytes.NewReader(raw), int64(len(raw))).OpenSeekableUnverified()
		if err != nil {
			t.Fatalf("OpenSeekableUnverified on a tampered entry: %v", err)
		}
		got, err := io.ReadAll(rs)
		if err != nil {
			t.Fatalf("reading the tampered entry: %v", err)
		}
		// Nothing on this path looks at the authentication code, which is
		// the whole of what the variant is for: the bytes come back
		// without an error and they are not the bytes that were written.
		if bytes.Equal(got, body) {
			t.Fatal("a flipped ciphertext bit left the plaintext unchanged")
		}
	})
}

// mustSeekEnd reports how long rs is, for a failure message about a reader
// that should never have been handed back.
func mustSeekEnd(t *testing.T, rs io.ReadSeeker) int64 {
	t.Helper()
	n, err := rs.Seek(0, io.SeekEnd)
	if err != nil {
		t.Fatalf("sizing the reader: %v", err)
	}
	return n
}

// aesIntegrityIndexed returns the header of an AES entry carrying a seek
// index, chunked when continuous is false and continuous when it is. Both
// kinds reach the same reader by a different route through OpenSeekable.
func aesIntegrityIndexed(continuous bool) *FileHeader {
	return &FileHeader{Method: Deflate, SeekChunkSize: 4096, SeekContinuous: continuous}
}

// TestWinZipAES_SolidSeekableAuthenticatesTheEntry: the index-driven path
// builds its decrypter on the first read, so that is where a tampered entry
// stops -- with nothing handed over, whether or not the caller seeks first,
// and with the error the stored path gives.
func TestWinZipAES_SolidSeekableAuthenticatesTheEntry(t *testing.T) {
	for _, index := range []struct {
		name       string
		continuous bool
	}{
		{"a chunked index", false},
		{"a continuous index", true},
	} {
		t.Run(index.name, func(t *testing.T) {
			for _, tc := range []struct {
				name string
				seek int64
			}{
				{"read from the start", -1},
				{"seek and then read", 32768},
			} {
				t.Run(tc.name, func(t *testing.T) {
					raw := aesIntegrityArchive(t, aesIntegrityIndexed(index.continuous), aesIntegrityBody(65536))
					aesIntegrityFlipCiphertext(t, raw)

					rs, err := aesIntegrityEntry(t, bytes.NewReader(raw), int64(len(raw))).OpenSeekable()
					if err != nil {
						t.Fatalf("OpenSeekable: %v", err)
					}
					if tc.seek >= 0 {
						if _, err := rs.Seek(tc.seek, io.SeekStart); err != nil {
							t.Fatalf("seek to %d: %v", tc.seek, err)
						}
					}
					n, err := rs.Read(make([]byte, 16))
					if !errors.Is(err, ErrChecksum) || !errors.Is(err, ErrPassword) {
						t.Fatalf("reading a tampered entry reported %v, want the checksum error", err)
					}
					// Not one byte of an entry that does not authenticate.
					if n != 0 {
						t.Errorf("the failed read handed over %d bytes", n)
					}
				})
			}

			t.Run("the unverified variant reads it anyway", func(t *testing.T) {
				body := aesIntegrityBody(65536)
				raw := aesIntegrityArchive(t, aesIntegrityIndexed(index.continuous), body)
				aesIntegrityFlipCiphertext(t, raw)

				rs, err := aesIntegrityEntry(t, bytes.NewReader(raw), int64(len(raw))).OpenSeekableUnverified()
				if err != nil {
					t.Fatalf("OpenSeekableUnverified: %v", err)
				}
				got, err := io.ReadAll(rs)
				if err != nil {
					t.Fatalf("reading the tampered entry: %v", err)
				}
				if bytes.Equal(got, body) {
					t.Fatal("a flipped ciphertext bit left the plaintext unchanged")
				}
			})
		})
	}
}

// TestWinZipAES_SolidSeekableChecksTheEntryOnce: a seek drops the
// decompressor, and the decrypter behind it used to be rebuilt along with it
// -- a key derivation per seek before, and a pass over the whole entry per
// seek now. It is built once and kept.
func TestWinZipAES_SolidSeekableChecksTheEntryOnce(t *testing.T) {
	for _, index := range []struct {
		name       string
		continuous bool
	}{
		{"a chunked index", false},
		{"a continuous index", true},
	} {
		t.Run(index.name, func(t *testing.T) {
			const bodyLen = 65536
			body := aesIntegrityBody(bodyLen)
			raw := aesIntegrityArchive(t, aesIntegrityIndexed(index.continuous), body)

			at, size := aesIntegrityCiphertext(t, raw)
			// The read the counter picks out is the one that asks for
			// the whole ciphertext at once. That is the pass and
			// nothing else only while the ciphertext is longer than
			// the decompressor's own buffer and shorter than the
			// pass's, so the fixture has to stay between the two.
			if size <= 4096 || size >= 1<<20 {
				t.Fatalf("the fixture's ciphertext is %d bytes, which no longer tells the pass apart from a read of the entry", size)
			}
			counter := &aesIntegrityCounter{data: raw, at: at, size: size}
			rs, err := aesIntegrityEntry(t, counter, int64(len(raw))).OpenSeekable()
			if err != nil {
				t.Fatalf("OpenSeekable: %v", err)
			}

			const seeks = 16
			for i := 0; i < seeks; i++ {
				off := int64(i) * (bodyLen / seeks)
				if _, err := rs.Seek(off, io.SeekStart); err != nil {
					t.Fatalf("seek to %d: %v", off, err)
				}
				got := make([]byte, 16)
				if _, err := io.ReadFull(rs, got); err != nil {
					t.Fatalf("read at %d: %v", off, err)
				}
				if !bytes.Equal(got, body[off:off+16]) {
					t.Fatalf("at %d the entry reads %x, want %x", off, got, body[off:off+16])
				}
			}

			// One pass over the ciphertext for sixteen seeks; a
			// decrypter rebuilt per seek would make sixteen.
			if counter.full != 1 {
				t.Fatalf("%d seeks went over the whole ciphertext %d times, want once", seeks, counter.full)
			}
		})
	}
}

// TestWinZipAES_SeekableReportsATrailerThatIsNotThere: where the
// authentication code sits is worked out from the size the central directory
// declares, and an entry that claims more than the archive holds has no code
// to check. That is a failure, not a reason to skip the check.
func TestWinZipAES_SeekableReportsATrailerThatIsNotThere(t *testing.T) {
	raw := aesIntegrityArchive(t, &FileHeader{Method: Store}, aesIntegrityBody(1024))
	// The compressed size, twenty bytes into the central directory record.
	// A gigabyte is far more than the fixture holds and is not the
	// saturated value that would send the reader to the zip64 extra.
	cd := centralHeaderOffset(t, raw, aesIntegrityName)
	binary.LittleEndian.PutUint32(raw[cd+20:], 1<<30)

	rs, err := aesIntegrityEntry(t, bytes.NewReader(raw), int64(len(raw))).OpenSeekable()
	if err == nil {
		t.Fatalf("an entry whose authentication code is past the end of the archive opened, and reads %d bytes",
			mustSeekEnd(t, rs))
	}
	// Not io.EOF: a caller reading through the index-driven path would take
	// that for the clean end of the entry.
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("an entry that stops short of its authentication code reported %v, want io.ErrUnexpectedEOF", err)
	}
}

// TestWinZipAES_SeekableReportsAReadFailureDuringTheCheck: the check reads the
// entry, and an archive that stops answering part way through has not been
// authenticated, whatever the code computed over what did arrive.
func TestWinZipAES_SeekableReportsAReadFailureDuringTheCheck(t *testing.T) {
	raw := aesIntegrityArchive(t, &FileHeader{Method: Store}, aesIntegrityBody(1024))
	f := aesIntegrityEntry(t, bytes.NewReader(raw), int64(len(raw)))
	off, err := f.DataOffset()
	if err != nil {
		t.Fatalf("offset of the entry data: %v", err)
	}
	comp, err := u64toi64(f.CompressedSize64)
	if err != nil {
		t.Fatalf("compressed size of the entry: %v", err)
	}
	entry := raw[off : off+comp]

	for _, tc := range []struct {
		name string
		at   int64
	}{
		{"reading the ciphertext", aesIntegritySaltLen + 2},
		{"reading the authentication code", comp - 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ra := &readerCovFailingAt{data: entry, fail: func(at int64, _ int) bool { return at == tc.at }}
			_, err := newWinZipAesReaderAt(ra, aesIntegrityPassword, f.aesInfo, comp, true)
			if !errors.Is(err, errReaderCovDevice) {
				t.Fatalf("the check reported %v, want the read failure", err)
			}
		})
	}
}
