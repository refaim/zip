package zip

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// XCrypt encrypts a whole archive rather than its entries: the archive that
// was staged becomes one AES-CTR encrypted entry inside an outer archive that
// also carries a plaintext README and the parameters the key is derived from.
// A reader handed the password sees the staged archive; a reader without one
// sees the outer archive as it stands. The tests below cover that round trip,
// each piece it is built from, and what every one of them does with input it
// cannot use.

const (
	xcryptStubName    = "README_ENCRYPTED.txt"
	xcryptPayloadName = ".zipext/xcrypt/payload.enc"
	xcryptHeaderName  = ".zipext/xcrypt/crypto.hdr"

	// The text encapsulateXCryptZip leaves in the clear for whoever opens
	// the archive without a password.
	xcryptStubMessage = "This is an encrypted archive. Please use f4 or an AXS-compatible tool to extract it.\n"
)

// xcryptStageInner writes the archive XCrypt is asked to protect to path and
// returns the bytes that landed there. It holds a stored entry, a deflated one
// and one of binary content, so that "the staged archive comes back" is a
// claim about more than one kind of entry.
func xcryptStageInner(t *testing.T, path string) []byte {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	zw := NewWriter(f)
	mustWrite(t, mustCreateHeader(t, zw, &FileHeader{Name: "hello.txt", Method: Store}), []byte("hello, world"))
	mustWrite(t, mustCreateHeader(t, zw, &FileHeader{Name: "docs/notes.md", Method: Deflate}),
		bytes.Repeat([]byte("compressible text "), 64))
	blob := make([]byte, 256)
	for i := range blob {
		blob[i] = byte(i)
	}
	mustWrite(t, mustCreateHeader(t, zw, &FileHeader{Name: "raw.bin", Method: Store}), blob)
	if err := zw.Close(); err != nil {
		t.Fatalf("finish the staged archive: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", path, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back %s: %v", path, err)
	}
	return data
}

// xcryptEntry is one entry of an archive, read out in full.
type xcryptEntry struct {
	name   string
	method uint16
	crc    uint32
	body   []byte
}

// xcryptEntries reads every entry of r so that two archives can be compared
// entry for entry instead of by their bytes. Reading an entry to its end is
// what makes the reader check its CRC, so a decryption that produced a
// plausible structure out of the wrong bytes is caught here rather than
// silently compared.
func xcryptEntries(t *testing.T, r *Reader) []xcryptEntry {
	t.Helper()
	out := make([]xcryptEntry, 0, len(r.File))
	for _, f := range r.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open entry %q: %v", f.Name, err)
		}
		body, rerr := io.ReadAll(rc)
		if cerr := rc.Close(); cerr != nil {
			t.Fatalf("close entry %q: %v", f.Name, cerr)
		}
		if rerr != nil {
			t.Fatalf("read entry %q: %v", f.Name, rerr)
		}
		out = append(out, xcryptEntry{name: f.Name, method: f.Method, crc: f.CRC32, body: body})
	}
	return out
}

// xcryptCompareArchives fails the test unless got and want hold the same
// entries in the same order, with the same contents.
func xcryptCompareArchives(t *testing.T, got, want []xcryptEntry) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("archive holds %d entries, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].name != want[i].name {
			t.Errorf("entry %d is named %q, want %q", i, got[i].name, want[i].name)
			continue
		}
		if got[i].method != want[i].method {
			t.Errorf("entry %q uses method %d, want %d", got[i].name, got[i].method, want[i].method)
		}
		if got[i].crc != want[i].crc {
			t.Errorf("entry %q has CRC %08x, want %08x", got[i].name, got[i].crc, want[i].crc)
		}
		if !bytes.Equal(got[i].body, want[i].body) {
			t.Errorf("entry %q came back with %d bytes of different content, want %d bytes",
				got[i].name, len(got[i].body), len(want[i].body))
		}
	}
}

// xcryptStream is the transformation the payload is stored under, written out
// by hand: AES-CTR from the start of the stream. Encryption and decryption are
// the same operation, so this doubles as the reference for both directions.
func xcryptStream(t *testing.T, key, iv, data []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes cipher: %v", err)
	}
	out := make([]byte, len(data))
	cipher.NewCTR(block, iv).XORKeyStream(out, data)
	return out
}

// xcryptTagExtra is the extra field that marks an entry as the XCrypt payload:
// the id and a length of zero.
func xcryptTagExtra() []byte {
	extra := make([]byte, 4)
	binary.LittleEndian.PutUint16(extra[0:2], xcryptExtraID)
	binary.LittleEndian.PutUint16(extra[2:4], 0)
	return extra
}

// xcryptOuterSpec describes an outer archive to assemble by hand. Each field
// is a piece checkXCryptZip looks for, so a test can leave one out, or break
// exactly one of them, and have everything around it stay a real archive.
type xcryptOuterSpec struct {
	// header is the content of the crypto header entry; a nil header
	// leaves that entry out of the archive altogether.
	header []byte
	// headerMethod is the compression method that entry claims.
	headerMethod uint16
	// headerBreakCRC stores a checksum the header content does not match.
	headerBreakCRC bool
	// payload is the content of the payload entry; a nil payload leaves
	// that entry out.
	payload []byte
	// payloadExtra is the extra field of the payload entry, where the
	// XCrypt tag is normally found.
	payloadExtra []byte
}

// xcryptOuterArchive assembles the outer archive spec describes. The two
// XCrypt entries go in through CreateRaw, which stores the sizes and checksum
// it is handed rather than the ones the bytes have, so the fixture can carry a
// broken one on purpose.
func xcryptOuterArchive(t *testing.T, spec xcryptOuterSpec) []byte {
	t.Helper()
	buf := new(bytes.Buffer)
	zw := NewWriter(buf)
	mustWrite(t, mustCreateHeader(t, zw, &FileHeader{Name: xcryptStubName, Method: Store}), []byte(xcryptStubMessage))

	if spec.payload != nil {
		fh := &FileHeader{Name: xcryptPayloadName, Method: Store}
		fh.UncompressedSize64 = uint64(len(spec.payload))
		fh.CompressedSize64 = fh.UncompressedSize64
		fh.CRC32 = crc32.ChecksumIEEE(spec.payload)
		fh.Flags |= 0x1
		fh.Extra = append(fh.Extra, spec.payloadExtra...)
		w, err := zw.CreateRaw(fh)
		if err != nil {
			t.Fatalf("create the payload entry: %v", err)
		}
		mustWrite(t, w, spec.payload)
	}

	if spec.header != nil {
		fh := &FileHeader{Name: xcryptHeaderName, Method: spec.headerMethod}
		fh.UncompressedSize64 = uint64(len(spec.header))
		fh.CompressedSize64 = fh.UncompressedSize64
		fh.CRC32 = crc32.ChecksumIEEE(spec.header)
		if spec.headerBreakCRC {
			fh.CRC32++
		}
		w, err := zw.CreateRaw(fh)
		if err != nil {
			t.Fatalf("create the crypto header entry: %v", err)
		}
		mustWrite(t, w, spec.header)
	}

	if err := zw.Close(); err != nil {
		t.Fatalf("finish the outer archive: %v", err)
	}
	return buf.Bytes()
}

// xcryptSealed builds an outer archive around inner the way an encapsulation
// would, but with a key derivation cheap enough to run many times over. The
// extra field of the payload entry carries prefix ahead of the XCrypt tag, so
// a test can put another field in front of the one checkXCryptZip is looking
// for.
func xcryptSealed(t *testing.T, inner []byte, password string, prefix []byte) []byte {
	t.Helper()
	hdr, key, err := generateXCryptHeader(password, 1000)
	if err != nil {
		t.Fatalf("generate a crypto header: %v", err)
	}
	buf := new(bytes.Buffer)
	cw, err := newXCryptWriter(buf, key, hdr.IV)
	if err != nil {
		t.Fatalf("start the payload writer: %v", err)
	}
	mustWrite(t, cw, inner)
	hdr.MAC = cw.MAC()

	extra := make([]byte, 0, len(prefix)+4)
	extra = append(extra, prefix...)
	extra = append(extra, xcryptTagExtra()...)
	return xcryptOuterArchive(t, xcryptOuterSpec{
		header:       hdr.Encode(),
		payload:      buf.Bytes(),
		payloadExtra: extra,
	})
}

// TestXCrypt_RoundTrip is the whole feature in one test: an archive is staged,
// encapsulated, and then read back both ways. Without a password the outer
// archive is what a reader sees, with the stub in the clear and the staged
// archive nowhere in it; with the password the staged archive comes back entry
// for entry. A wrong password has to fail rather than hand back whatever the
// wrong key produced.
func TestXCrypt_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	staged := filepath.Join(dir, "staged.zip")
	inner := xcryptStageInner(t, staged)
	final := filepath.Join(dir, "encrypted.zip")
	const password = "correct horse battery staple"

	if err := encapsulateXCryptZip(final, staged, password); err != nil {
		t.Fatalf("encapsulate: %v", err)
	}
	outer, err := os.ReadFile(final)
	if err != nil {
		t.Fatalf("read back the encapsulated archive: %v", err)
	}

	innerReader, err := NewReader(bytes.NewReader(inner), int64(len(inner)))
	if err != nil {
		t.Fatalf("read the staged archive: %v", err)
	}
	want := xcryptEntries(t, innerReader)

	// What a reader without the password gets is the outer archive as it
	// stands. Its three entries are read here once, and the checks below
	// say what each of them has to be.
	outerReader, err := OpenReader(final)
	if err != nil {
		t.Fatalf("open without a password: %v", err)
	}
	closeAt(t, outerReader)
	names := make([]string, 0, len(outerReader.File))
	for _, f := range outerReader.File {
		names = append(names, f.Name)
	}
	wantNames := []string{xcryptStubName, xcryptPayloadName, xcryptHeaderName}
	if len(names) != len(wantNames) {
		t.Fatalf("the outer archive holds %v, want %v", names, wantNames)
	}
	for i := range wantNames {
		if names[i] != wantNames[i] {
			t.Fatalf("the outer archive holds %v, want %v", names, wantNames)
		}
	}
	// The payload is read raw: the entry is marked encrypted, so this is
	// the only way to get at the bytes without a password, and they are the
	// bytes that were stored rather than anything the reader made of them.
	rawPayload, err := outerReader.File[1].OpenRaw()
	if err != nil {
		t.Fatalf("open the payload: %v", err)
	}
	payloadBytes, err := io.ReadAll(rawPayload)
	if err != nil {
		t.Fatalf("read the payload: %v", err)
	}

	t.Run("the stub is there in the clear", func(t *testing.T) {
		rc, err := outerReader.File[0].Open()
		if err != nil {
			t.Fatalf("open the stub: %v", err)
		}
		closeAt(t, rc)
		stub, err := io.ReadAll(rc)
		if err != nil {
			t.Fatalf("read the stub: %v", err)
		}
		if string(stub) != xcryptStubMessage {
			t.Errorf("the stub reads %q, want %q", stub, xcryptStubMessage)
		}
	})

	t.Run("the staged archive is not there in the clear", func(t *testing.T) {
		if len(payloadBytes) != len(inner) {
			t.Fatalf("the payload is %d bytes, want the %d of the staged archive", len(payloadBytes), len(inner))
		}
		if bytes.Equal(payloadBytes, inner) {
			t.Fatal("the staged archive was stored in the clear")
		}
		if bytes.Contains(payloadBytes, []byte("hello, world")) {
			t.Error("the payload still holds the contents of the staged archive")
		}
		// The entry is marked encrypted, so a reader without a password
		// refuses it rather than handing over ciphertext as content.
		if rc, err := outerReader.File[1].Open(); err == nil {
			closeAt(t, rc)
			t.Error("the payload opened as an ordinary entry without a password")
		}
	})

	t.Run("the crypto header describes the payload that is there", func(t *testing.T) {
		rc, err := outerReader.File[2].Open()
		if err != nil {
			t.Fatalf("open the crypto header: %v", err)
		}
		closeAt(t, rc)
		headerBytes, err := io.ReadAll(rc)
		if err != nil {
			t.Fatalf("read the crypto header: %v", err)
		}
		hdr, err := parseXCryptHeader(headerBytes)
		if err != nil {
			t.Fatalf("parse the crypto header: %v", err)
		}
		if hdr.Iterations != 600000 {
			t.Errorf("the header records %d iterations, want 600000", hdr.Iterations)
		}
		key := hdr.DeriveKey(password)

		// The MAC in the header has to be the MAC of the bytes that were
		// stored, or nothing downstream can tell a payload that was
		// tampered with from one that was not.
		mac := hmac.New(sha256.New, key)
		mustWrite(t, mac, payloadBytes)
		if !hmac.Equal(hdr.MAC, mac.Sum(nil)) {
			t.Errorf("the header records MAC %x, want %x", hdr.MAC, mac.Sum(nil))
		}

		// And the salt and IV in the header have to be the ones the
		// payload was encrypted under.
		if !bytes.Equal(xcryptStream(t, key, hdr.IV, payloadBytes), inner) {
			t.Error("decrypting the payload with the header's own key and IV does not give the staged archive")
		}
	})

	t.Run("with the password the staged archive comes back", func(t *testing.T) {
		zr, err := OpenReaderWithPassword(final, password)
		if err != nil {
			t.Fatalf("open with the password: %v", err)
		}
		closeAt(t, zr)
		xcryptCompareArchives(t, xcryptEntries(t, &zr.Reader), want)
	})

	t.Run("and the same from a reader over the bytes", func(t *testing.T) {
		zr, err := NewReaderWithPassword(bytes.NewReader(outer), int64(len(outer)), password)
		if err != nil {
			t.Fatalf("read with the password: %v", err)
		}
		xcryptCompareArchives(t, xcryptEntries(t, zr), want)
	})

	t.Run("a wrong password is refused", func(t *testing.T) {
		// The wrong key decrypts to bytes that are not an archive. What
		// matters is that this is reported: handing back a reader over
		// them would make a wrong password look like a corrupt archive
		// to everything upstream.
		zr, err := OpenReaderWithPassword(final, "hunter2")
		if err == nil {
			closeAt(t, zr)
			t.Fatalf("a wrong password opened the archive with %d entries", len(zr.File))
		}
		if !errors.Is(err, ErrFormat) {
			t.Errorf("a wrong password reported %v, want %v", err, ErrFormat)
		}
	})
}

// TestXCrypt_GenerateHeaderDescribesItsOwnKey pins the one thing the round
// trip depends on: the key generateXCryptHeader hands the writer is the key
// DeriveKey reproduces from the header that was stored alongside it.
func TestXCrypt_GenerateHeaderDescribesItsOwnKey(t *testing.T) {
	const password = "a password"
	hdr, key, err := generateXCryptHeader(password, 1000)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if hdr.Version != 1 || hdr.KdfAlgo != 1 || hdr.Cipher != 1 {
		t.Errorf("header says version %d, kdf %d, cipher %d, want 1, 1, 1", hdr.Version, hdr.KdfAlgo, hdr.Cipher)
	}
	if hdr.Iterations != 1000 {
		t.Errorf("header records %d iterations, want the 1000 it was asked for", hdr.Iterations)
	}
	if len(hdr.Salt) != 32 || len(hdr.IV) != 16 || len(hdr.MAC) != 32 {
		t.Fatalf("header carries a %d byte salt, a %d byte IV and a %d byte MAC, want 32, 16 and 32",
			len(hdr.Salt), len(hdr.IV), len(hdr.MAC))
	}
	if !bytes.Equal(hdr.MAC, make([]byte, 32)) {
		t.Errorf("a fresh header carries MAC %x, want it left at zero until the payload is written", hdr.MAC)
	}
	if len(key) != 32 {
		t.Fatalf("the key is %d bytes, want the 32 AES-256 takes", len(key))
	}
	if !bytes.Equal(key, hdr.DeriveKey(password)) {
		t.Error("the key handed to the caller is not the one the header derives")
	}

	// Two archives encrypted under the same password must not share a key
	// stream, which is what the salt and the IV being fresh each time buys.
	other, otherKey, err := generateXCryptHeader(password, 1000)
	if err != nil {
		t.Fatalf("generate a second header: %v", err)
	}
	if bytes.Equal(hdr.Salt, other.Salt) {
		t.Error("two headers were generated with the same salt")
	}
	if bytes.Equal(hdr.IV, other.IV) {
		t.Error("two headers were generated with the same IV")
	}
	if bytes.Equal(key, otherKey) {
		t.Error("two headers under the same password produced the same key")
	}
}

// TestXCrypt_GenerateHeaderDefaultsTheIterationCount: an iteration count of
// zero is not "no stretching at all", it is the default the format was written
// for.
func TestXCrypt_GenerateHeaderDefaultsTheIterationCount(t *testing.T) {
	hdr, _, err := generateXCryptHeader("a password", 0)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if hdr.Iterations != 600000 {
		t.Errorf("header records %d iterations, want the default 600000", hdr.Iterations)
	}
}

// xcryptStingyRandom hands out left bytes of randomness and then refuses,
// which is what a reader of the system entropy pool does when it is taken
// away mid-call.
type xcryptStingyRandom struct{ left int }

func (r *xcryptStingyRandom) Read(p []byte) (int, error) {
	if r.left <= 0 {
		return 0, errors.New("out of entropy")
	}
	if len(p) > r.left {
		p = p[:r.left]
	}
	for i := range p {
		p[i] = 0x5A
	}
	r.left -= len(p)
	return len(p), nil
}

// xcryptUseRandom replaces the source of randomness for the duration of the
// test and puts the real one back afterwards. Tests that do this must not run
// in parallel with anything, which is why none of them call t.Parallel.
func xcryptUseRandom(t *testing.T, r io.Reader) {
	t.Helper()
	saved := crand.Reader
	crand.Reader = r
	t.Cleanup(func() { crand.Reader = saved })
}

// TestXCrypt_GenerateHeaderReportsExhaustedRandomness: a salt or an IV that
// could not be filled must stop the encryption, not go ahead with whatever
// happened to be in the buffer.
func TestXCrypt_GenerateHeaderReportsExhaustedRandomness(t *testing.T) {
	for _, tc := range []struct {
		name string
		left int
	}{
		{"no randomness for the salt", 0},
		{"enough for the salt but not the IV", 32},
	} {
		t.Run(tc.name, func(t *testing.T) {
			xcryptUseRandom(t, &xcryptStingyRandom{left: tc.left})
			hdr, key, err := generateXCryptHeader("a password", 1000)
			if err == nil {
				t.Fatal("a header was generated without the randomness to fill it")
			}
			if hdr != nil || key != nil {
				t.Error("a failed generation still handed back a header or a key")
			}
		})
	}
}

// TestXCrypt_HeaderEncodeParseRoundTrip pins the 93 byte on-disk form: what
// Encode writes is what parseXCryptHeader reads back, field for field.
func TestXCrypt_HeaderEncodeParseRoundTrip(t *testing.T) {
	hdr := &XCryptHeader{
		Version:    1,
		KdfAlgo:    1,
		Cipher:     1,
		Iterations: 600000,
		Salt:       bytes.Repeat([]byte{0xA1}, 32),
		IV:         bytes.Repeat([]byte{0xB2}, 16),
		MAC:        bytes.Repeat([]byte{0xC3}, 32),
	}
	encoded := hdr.Encode()
	if len(encoded) != 93 {
		t.Fatalf("the encoded header is %d bytes, want 93", len(encoded))
	}
	if string(encoded[0:6]) != "XCRYPT" {
		t.Errorf("the header starts with %q, want the XCRYPT magic", encoded[0:6])
	}
	if got := binary.LittleEndian.Uint32(encoded[9:13]); got != 600000 {
		t.Errorf("the header records %d iterations, want 600000", got)
	}

	got, err := parseXCryptHeader(encoded)
	if err != nil {
		t.Fatalf("parse what Encode wrote: %v", err)
	}
	if got.Version != hdr.Version || got.KdfAlgo != hdr.KdfAlgo || got.Cipher != hdr.Cipher {
		t.Errorf("parsed version %d, kdf %d, cipher %d, want 1, 1, 1", got.Version, got.KdfAlgo, got.Cipher)
	}
	if got.Iterations != hdr.Iterations {
		t.Errorf("parsed %d iterations, want %d", got.Iterations, hdr.Iterations)
	}
	if !bytes.Equal(got.Salt, hdr.Salt) {
		t.Errorf("parsed salt %x, want %x", got.Salt, hdr.Salt)
	}
	if !bytes.Equal(got.IV, hdr.IV) {
		t.Errorf("parsed IV %x, want %x", got.IV, hdr.IV)
	}
	if !bytes.Equal(got.MAC, hdr.MAC) {
		t.Errorf("parsed MAC %x, want %x", got.MAC, hdr.MAC)
	}

	// The parsed header keeps its own copy of the three byte strings: a
	// caller that goes on to reuse the buffer it parsed from must not be
	// able to change the key the header derives.
	encoded[13]++
	encoded[45]++
	encoded[61]++
	if got.Salt[0] != hdr.Salt[0] || got.IV[0] != hdr.IV[0] || got.MAC[0] != hdr.MAC[0] {
		t.Error("the parsed header aliases the buffer it was parsed from")
	}
}

// TestParseXCryptHeader_RejectsMalformedHeaders walks every reason the parser
// has to refuse. A header it accepts decides the key and the IV of the whole
// archive, so each of these is a case where carrying on would decrypt with
// parameters nobody wrote.
func TestParseXCryptHeader_RejectsMalformedHeaders(t *testing.T) {
	valid := (&XCryptHeader{
		Version:    1,
		KdfAlgo:    1,
		Cipher:     1,
		Iterations: 1000,
		Salt:       bytes.Repeat([]byte{1}, 32),
		IV:         bytes.Repeat([]byte{2}, 16),
		MAC:        bytes.Repeat([]byte{3}, 32),
	}).Encode()

	mutate := func(f func(b []byte)) []byte {
		b := append([]byte(nil), valid...)
		f(b)
		return b
	}

	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"nothing at all", nil},
		{"one byte short", valid[:92]},
		{"one byte long", append(append([]byte(nil), valid...), 0)},
		{"the wrong magic", mutate(func(b []byte) { copy(b[0:6], "XCRYPS") })},
		{"a version from the future", mutate(func(b []byte) { b[6] = 2 })},
		{"an unknown key derivation", mutate(func(b []byte) { b[7] = 2 })},
		{"an unknown cipher", mutate(func(b []byte) { b[8] = 2 })},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hdr, err := parseXCryptHeader(tc.data)
			if err == nil {
				t.Fatalf("the parser accepted %d bytes it should not have", len(tc.data))
			}
			if hdr != nil {
				t.Error("a rejected header was still handed back")
			}
		})
	}
}

// TestXCrypt_WriterEncryptsAndAuthenticates: what the writer passes on is the
// AES-CTR stream of what it was given, and the MAC it ends with is the MAC of
// those same bytes. The second, shorter write is there on purpose: the writer
// keeps one buffer around between calls, and a shorter write that forgot to
// reslice it would append the tail of the previous one.
func TestXCrypt_WriterEncryptsAndAuthenticates(t *testing.T) {
	key := bytes.Repeat([]byte{0x2B}, 32)
	iv := bytes.Repeat([]byte{0x7E}, 16)

	first := make([]byte, 4096)
	for i := range first {
		first[i] = byte(i * 7 & 0xFF)
	}
	second := []byte("a short tail")

	sink := new(bytes.Buffer)
	cw, err := newXCryptWriter(sink, key, iv)
	if err != nil {
		t.Fatalf("start the writer: %v", err)
	}
	mustWrite(t, cw, first)
	mustWrite(t, cw, second)

	plain := append(append([]byte(nil), first...), second...)
	want := xcryptStream(t, key, iv, plain)
	if !bytes.Equal(sink.Bytes(), want) {
		t.Fatalf("the writer wrote %d bytes that are not the AES-CTR stream of its input", sink.Len())
	}

	mac := hmac.New(sha256.New, key)
	mustWrite(t, mac, want)
	if !hmac.Equal(cw.MAC(), mac.Sum(nil)) {
		t.Errorf("the writer reports MAC %x, want %x over what it wrote", cw.MAC(), mac.Sum(nil))
	}

	// And the reader half undoes it, which is the property the payload
	// entry rests on.
	back := make([]byte, len(plain))
	ra := newXCryptReaderAt(bytes.NewReader(sink.Bytes()), key, iv)
	if _, err := ra.ReadAt(back, 0); err != nil {
		t.Fatalf("read the stream back: %v", err)
	}
	if !bytes.Equal(back, plain) {
		t.Error("the stream did not decrypt to what was written")
	}
}

// TestXCrypt_NewWriterRejectsAnUnusableKey: AES takes 16, 24 or 32 byte keys,
// and a writer started with anything else has to say so rather than hand back
// something that writes plaintext.
func TestXCrypt_NewWriterRejectsAnUnusableKey(t *testing.T) {
	cw, err := newXCryptWriter(new(bytes.Buffer), []byte("far too short"), make([]byte, 16))
	if err == nil {
		t.Fatal("a writer was started with a key AES cannot take")
	}
	if cw != nil {
		t.Error("a failed writer was still handed back")
	}
}

// xcryptReadAtFixture is a stream of known plaintext, its ciphertext, and a
// reader over the ciphertext, for the random access tests.
func xcryptReadAtFixture(t *testing.T, key, iv []byte, size int) (plain []byte, ra *xCryptReaderAt) {
	t.Helper()
	plain = make([]byte, size)
	for i := range plain {
		plain[i] = byte((i*31 + 11) & 0xFF)
	}
	return plain, newXCryptReaderAt(bytes.NewReader(xcryptStream(t, key, iv, plain)), key, iv)
}

// TestXCrypt_ReaderAtDecryptsAtAnyOffset is the seekable half of the feature.
// Every read of an entry inside an encrypted archive comes through here, at
// whatever offset the entry happens to start at, and AES-CTR only gives the
// right bytes back if the counter is wound forward to the block the offset
// lands in and the leading bytes of that block are dropped.
func TestXCrypt_ReaderAtDecryptsAtAnyOffset(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 32)
	iv := bytes.Repeat([]byte{0x22}, 16)
	const size = 700
	plain, ra := xcryptReadAtFixture(t, key, iv, size)

	for _, tc := range []struct {
		name string
		off  int64
		n    int
	}{
		{"a whole block from the start", 0, 16},
		{"inside the first block", 3, 5},
		{"across a block boundary", 14, 8},
		{"a whole block from an unaligned offset", 17, 16},
		{"many blocks from an unaligned offset", 33, 200},
		{"the last byte", size - 1, 1},
		{"the last block", size - 16, 16},
		{"everything at once", 0, size},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buf := make([]byte, tc.n)
			n, err := ra.ReadAt(buf, tc.off)
			if err != nil {
				t.Fatalf("read %d bytes at %d: %v", tc.n, tc.off, err)
			}
			if n != tc.n {
				t.Fatalf("read %d bytes at %d, want %d", n, tc.off, tc.n)
			}
			if !bytes.Equal(buf, plain[tc.off:tc.off+int64(tc.n)]) {
				t.Errorf("the %d bytes at %d are not the ones the sequential stream has", tc.n, tc.off)
			}
		})
	}
}

// TestXCrypt_ReaderAtCarriesTheCounter: the counter is the IV plus the block
// number, added by hand a byte at a time. An IV of all ones makes every one of
// those additions carry into the byte in front of it, and an offset far enough
// in makes the block number itself more than one byte wide -- both are cases
// where an addition that stopped early would decrypt with a counter no
// encryption ever used.
func TestXCrypt_ReaderAtCarriesTheCounter(t *testing.T) {
	key := bytes.Repeat([]byte{0x33}, 32)
	iv := bytes.Repeat([]byte{0xFF}, 16)
	const size = 9000
	plain, ra := xcryptReadAtFixture(t, key, iv, size)

	for _, off := range []int64{0, 15, 16, 17, 4080, 4096, 4111, 8192, size - 32} {
		buf := make([]byte, 32)
		n, err := ra.ReadAt(buf, off)
		if err != nil {
			t.Fatalf("read at %d: %v", off, err)
		}
		if n != len(buf) {
			t.Fatalf("read %d bytes at %d, want %d", n, off, len(buf))
		}
		if !bytes.Equal(buf, plain[off:off+int64(len(buf))]) {
			t.Errorf("the block at %d decrypts to something the sequential stream does not have", off)
		}
	}
}

// TestXCrypt_ReaderAtAtTheEnd covers what a caller sees at the far end of the
// payload: a read that runs past it comes back short with io.EOF rather than
// with padding, and a read that starts past it reads nothing at all.
func TestXCrypt_ReaderAtAtTheEnd(t *testing.T) {
	key := bytes.Repeat([]byte{0x44}, 32)
	iv := bytes.Repeat([]byte{0x55}, 16)
	const size = 700
	plain, ra := xcryptReadAtFixture(t, key, iv, size)

	t.Run("a read that runs off the end comes back short", func(t *testing.T) {
		buf := make([]byte, 10)
		n, err := ra.ReadAt(buf, size-5)
		if !errors.Is(err, io.EOF) {
			t.Fatalf("read past the end reported %v, want io.EOF", err)
		}
		if n != 5 {
			t.Fatalf("read %d bytes of the 5 that are there", n)
		}
		if !bytes.Equal(buf[:n], plain[size-5:]) {
			t.Error("the last bytes of the payload are not the ones the sequential stream has")
		}
	})

	t.Run("a read that starts past the end reads nothing", func(t *testing.T) {
		// Two ways of being past the end: an offset inside the last
		// block, where the payload still has bytes to hand over but
		// none of them are the caller's, and one past that block, where
		// the read underneath comes back with nothing at all.
		for _, off := range []int64{size, size + 16, size * 2} {
			n, err := ra.ReadAt(make([]byte, 8), off)
			if !errors.Is(err, io.EOF) {
				t.Errorf("read at %d reported %v, want io.EOF", off, err)
			}
			if n != 0 {
				t.Errorf("read %d bytes from %d, past the end", n, off)
			}
		}
	})

	t.Run("an empty read is not an error anywhere", func(t *testing.T) {
		// An empty read is answered without going near the underlying
		// reader, so it is not an error even past the end.
		for _, off := range []int64{0, 13, size, size * 4} {
			n, err := ra.ReadAt(nil, off)
			if n != 0 || err != nil {
				t.Errorf("an empty read at %d returned %d, %v, want 0, nil", off, n, err)
			}
		}
	})
}

// xcryptEagerEOFReaderAt answers a read that reaches the end of its data with
// io.EOF alongside the bytes, which io.ReaderAt allows and os.File does not
// do. A caller that asked for a full buffer and got one must not be told the
// stream ended.
type xcryptEagerEOFReaderAt struct{ data []byte }

func (r xcryptEagerEOFReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(r.data)) {
		return 0, io.EOF
	}
	n := copy(p, r.data[off:])
	if off+int64(n) >= int64(len(r.data)) {
		return n, io.EOF
	}
	return n, nil
}

// TestXCrypt_ReaderAtSwallowsAFullReadsEOF pins that convention: a full read
// that the underlying reader flagged as the end is a full read, and the caller
// hears about the end on the next one.
func TestXCrypt_ReaderAtSwallowsAFullReadsEOF(t *testing.T) {
	key := bytes.Repeat([]byte{0x66}, 32)
	iv := bytes.Repeat([]byte{0x77}, 16)
	plain := []byte("sixteen bytes...and sixteen more")
	enc := xcryptStream(t, key, iv, plain)
	ra := newXCryptReaderAt(xcryptEagerEOFReaderAt{data: enc}, key, iv)

	buf := make([]byte, 16)
	n, err := ra.ReadAt(buf, int64(len(plain)-16))
	if err != nil {
		t.Fatalf("a full read at the end reported %v, want no error", err)
	}
	if n != len(buf) {
		t.Fatalf("read %d bytes, want %d", n, len(buf))
	}
	if !bytes.Equal(buf, plain[len(plain)-16:]) {
		t.Error("the last block did not decrypt to what was encrypted")
	}
}

// TestXCrypt_ReaderAtRejectsAnUnusableKey: a key AES cannot take is reported
// on the read rather than at construction, since that is where the cipher is
// built.
func TestXCrypt_ReaderAtRejectsAnUnusableKey(t *testing.T) {
	ra := newXCryptReaderAt(bytes.NewReader(make([]byte, 64)), []byte("far too short"), make([]byte, 16))
	n, err := ra.ReadAt(make([]byte, 16), 0)
	if err == nil {
		t.Fatal("a read succeeded with a key AES cannot take")
	}
	if n != 0 {
		t.Errorf("a failed read reported %d bytes", n)
	}
}

// TestCheckXCryptZip_LeavesOtherArchivesAlone: the check runs on every archive
// that is opened, so everything that is not an XCrypt archive has to come back
// exactly as it went in. Each case here is one of the reasons it has to
// decide that.
func TestCheckXCryptZip_LeavesOtherArchivesAlone(t *testing.T) {
	inner := xcryptOuterArchive(t, xcryptOuterSpec{}) // any real archive will do
	hdr := (&XCryptHeader{
		Version: 1, KdfAlgo: 1, Cipher: 1, Iterations: 1000,
		Salt: bytes.Repeat([]byte{1}, 32), IV: bytes.Repeat([]byte{2}, 16), MAC: bytes.Repeat([]byte{3}, 32),
	}).Encode()

	otherExtra := make([]byte, 8)
	binary.LittleEndian.PutUint16(otherExtra[0:2], 0xCAFE)
	binary.LittleEndian.PutUint16(otherExtra[2:4], 4)

	truncatedExtra := make([]byte, 8)
	binary.LittleEndian.PutUint16(truncatedExtra[0:2], 0xCAFE)
	binary.LittleEndian.PutUint16(truncatedExtra[2:4], 200)
	truncatedExtra = append(truncatedExtra, xcryptTagExtra()...)

	for _, tc := range []struct {
		name     string
		archive  []byte
		password string
	}{
		{"too short to be an archive at all", []byte("PK\x05\x06 short"), "a password"},
		{"not an archive", bytes.Repeat([]byte("not a zip file "), 4), "a password"},
		{"an ordinary archive", inner, "a password"},
		{
			"a payload entry with no crypto header",
			xcryptOuterArchive(t, xcryptOuterSpec{payload: []byte("encrypted"), payloadExtra: xcryptTagExtra()}),
			"a password",
		},
		{
			"a crypto header with no payload entry",
			xcryptOuterArchive(t, xcryptOuterSpec{header: hdr}),
			"a password",
		},
		{
			"a payload entry that is not tagged as one",
			xcryptOuterArchive(t, xcryptOuterSpec{header: hdr, payload: []byte("encrypted")}),
			"a password",
		},
		{
			"a payload entry whose extra field ends mid-field",
			xcryptOuterArchive(t, xcryptOuterSpec{header: hdr, payload: []byte("encrypted"), payloadExtra: truncatedExtra}),
			"a password",
		},
		{
			"an XCrypt archive opened without a password",
			xcryptSealed(t, inner, "a password", nil),
			"",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := bytes.NewReader(tc.archive)
			got, size, err := checkXCryptZip(in, int64(len(tc.archive)), tc.password)
			if err != nil {
				t.Fatalf("the check reported %v on an archive it should have passed through", err)
			}
			if got != io.ReaderAt(in) {
				t.Error("the check replaced the reader of an archive it should have passed through")
			}
			if size != int64(len(tc.archive)) {
				t.Errorf("the check reported size %d, want the archive's own %d", size, len(tc.archive))
			}
		})
	}
}

// TestCheckXCryptZip_UnwrapsThePayload: with all three pieces in place and the
// right password, what comes back is a reader over the archive that was
// encrypted, sized to it, whatever else the outer archive holds.
func TestCheckXCryptZip_UnwrapsThePayload(t *testing.T) {
	dir := t.TempDir()
	inner := xcryptStageInner(t, filepath.Join(dir, "staged.zip"))
	const password = "a password"

	// The XCrypt tag is looked for in a walk over the extra field, so it
	// has to be found behind another field as well as at the front of one.
	otherExtra := make([]byte, 8)
	binary.LittleEndian.PutUint16(otherExtra[0:2], 0xCAFE)
	binary.LittleEndian.PutUint16(otherExtra[2:4], 4)

	for _, tc := range []struct {
		name   string
		prefix []byte
	}{
		{"tagged", nil},
		{"tagged behind another extra field", otherExtra},
	} {
		t.Run(tc.name, func(t *testing.T) {
			archive := xcryptSealed(t, inner, password, tc.prefix)
			in := bytes.NewReader(archive)
			got, size, err := checkXCryptZip(in, int64(len(archive)), password)
			if err != nil {
				t.Fatalf("the check reported %v on an XCrypt archive: %v", err, err)
			}
			if size != int64(len(inner)) {
				t.Fatalf("the check reported size %d, want the staged archive's %d", size, len(inner))
			}
			decrypted, err := io.ReadAll(io.NewSectionReader(got, 0, size))
			if err != nil {
				t.Fatalf("read the decrypted view: %v", err)
			}
			if !bytes.Equal(decrypted, inner) {
				t.Fatal("the decrypted view is not the archive that was encrypted")
			}

			// And the same archive read through the public entry
			// point lists the entries of the staged archive.
			zr, err := NewReaderWithPassword(bytes.NewReader(archive), int64(len(archive)), password)
			if err != nil {
				t.Fatalf("read the archive with the password: %v", err)
			}
			innerReader, err := NewReader(bytes.NewReader(inner), int64(len(inner)))
			if err != nil {
				t.Fatalf("read the staged archive: %v", err)
			}
			xcryptCompareArchives(t, xcryptEntries(t, zr), xcryptEntries(t, innerReader))
		})
	}
}

// TestCheckXCryptZip_ReportsABrokenCryptoHeader: the crypto header entry is
// the only place the key derivation parameters exist. An archive that has one
// the reader cannot get at is not an ordinary archive to fall back to reading
// -- it is an encrypted archive that cannot be opened, and saying so is the
// difference between a clear failure and a reader over the stub.
func TestCheckXCryptZip_ReportsABrokenCryptoHeader(t *testing.T) {
	valid := (&XCryptHeader{
		Version: 1, KdfAlgo: 1, Cipher: 1, Iterations: 1000,
		Salt: bytes.Repeat([]byte{1}, 32), IV: bytes.Repeat([]byte{2}, 16), MAC: bytes.Repeat([]byte{3}, 32),
	}).Encode()

	for _, tc := range []struct {
		name string
		spec xcryptOuterSpec
	}{
		{
			"stored with a method the reader does not have",
			xcryptOuterSpec{header: valid, headerMethod: 42, payload: []byte("encrypted"), payloadExtra: xcryptTagExtra()},
		},
		{
			"stored with a checksum its bytes do not match",
			xcryptOuterSpec{header: valid, headerBreakCRC: true, payload: []byte("encrypted"), payloadExtra: xcryptTagExtra()},
		},
		{
			"holding something that is not a crypto header",
			xcryptOuterSpec{header: []byte("XCRYPT but far too short"), payload: []byte("encrypted"), payloadExtra: xcryptTagExtra()},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			archive := xcryptOuterArchive(t, tc.spec)
			got, size, err := checkXCryptZip(bytes.NewReader(archive), int64(len(archive)), "a password")
			if err == nil {
				t.Fatal("a crypto header that cannot be read was passed over in silence")
			}
			if got != nil || size != 0 {
				t.Errorf("a failed check handed back a reader of size %d", size)
			}
		})
	}
}

// TestCheckXCryptZip_ReportsAPayloadWithoutALocalHeader: the payload is read
// from the offset its local header ends at, and an archive whose central
// directory points at something that is not a local header has no such offset.
// Guessing one would decrypt from the wrong place.
func TestCheckXCryptZip_ReportsAPayloadWithoutALocalHeader(t *testing.T) {
	dir := t.TempDir()
	inner := xcryptStageInner(t, filepath.Join(dir, "staged.zip"))
	archive := xcryptSealed(t, inner, "a password", nil)

	// Find the local header first, then take its signature away: the
	// lookup goes by that signature.
	off := localHeaderOffset(t, archive, xcryptPayloadName)
	binary.LittleEndian.PutUint32(archive[off:off+4], 0)

	got, size, err := checkXCryptZip(bytes.NewReader(archive), int64(len(archive)), "a password")
	if err == nil {
		t.Fatal("a payload with no local header was decrypted anyway")
	}
	if got != nil || size != 0 {
		t.Errorf("a failed check handed back a reader of size %d", size)
	}
}

// TestXCrypt_EncapsulateReportsAnUncreatableDestination: the destination is
// the archive the caller was promised. If it cannot be created there is
// nothing to write into and the caller has to hear about it.
func TestXCrypt_EncapsulateReportsAnUncreatableDestination(t *testing.T) {
	dir := t.TempDir()
	staged := filepath.Join(dir, "staged.zip")
	mustWriteFile(t, staged, []byte("staged bytes"), 0o600)

	final := filepath.Join(dir, "no-such-directory", "encrypted.zip")
	if err := encapsulateXCryptZip(final, staged, "a password"); err == nil {
		t.Fatal("encapsulating into a directory that does not exist reported success")
	}
	if _, err := os.Stat(final); err == nil {
		t.Error("a destination was left behind by a failed encapsulation")
	}
}

// TestXCrypt_EncapsulateReportsAMissingStagedArchive: the staged archive is
// the whole content of the payload, and its size goes into the payload entry's
// header before a byte of it is read.
func TestXCrypt_EncapsulateReportsAMissingStagedArchive(t *testing.T) {
	dir := t.TempDir()
	final := filepath.Join(dir, "encrypted.zip")
	if err := encapsulateXCryptZip(final, filepath.Join(dir, "not-there.zip"), "a password"); err == nil {
		t.Fatal("encapsulating an archive that does not exist reported success")
	}
}

// TestXCrypt_EncapsulateReportsAnUnreadableStagedArchive: a staged archive
// that stats but does not open would otherwise leave an outer archive whose
// payload entry promises bytes that were never copied into it.
func TestXCrypt_EncapsulateReportsAnUnreadableStagedArchive(t *testing.T) {
	dir := t.TempDir()
	staged, ok := xcryptUnreadableStaged(t, dir)
	if !ok {
		t.Skip("this account cannot be denied read access to its own file here")
	}

	final := filepath.Join(dir, "encrypted.zip")
	if err := encapsulateXCryptZip(final, staged, "a password"); err == nil {
		t.Fatal("encapsulating an unreadable staged archive reported success")
	}
}

// TestXCrypt_EncapsulateReportsAnUnreadableCopy: a staged path that opens but
// cannot be read through is the same failure one step later, and it is the
// copy of the whole encrypted archive -- a short one leaves an entry whose
// header promises bytes that are not there.
func TestXCrypt_EncapsulateReportsAnUnreadableCopy(t *testing.T) {
	dir := t.TempDir()
	staged := filepath.Join(dir, "staged")
	mustMkdir(t, staged)

	final := filepath.Join(dir, "encrypted.zip")
	if err := encapsulateXCryptZip(final, staged, "a password"); err == nil {
		t.Fatal("encapsulating a directory as the staged archive reported success")
	}
}

// TestXCrypt_EncapsulateReportsExhaustedRandomness: without a salt and an IV
// there is no encryption to do, and going on would write the payload under
// whatever was in those buffers.
func TestXCrypt_EncapsulateReportsExhaustedRandomness(t *testing.T) {
	dir := t.TempDir()
	staged := filepath.Join(dir, "staged.zip")
	mustWriteFile(t, staged, []byte("staged bytes"), 0o600)
	final := filepath.Join(dir, "encrypted.zip")

	xcryptUseRandom(t, &xcryptStingyRandom{})
	if err := encapsulateXCryptZip(final, staged, "a password"); err == nil {
		t.Fatal("encapsulating without randomness reported success")
	}
}

// TestXCrypt_EncapsulateWritesToStdout: a destination of "-" is the stream the
// process was started with rather than a file, and the archive that comes out
// of it is the same archive. Stdout belongs to the caller, so it also has to
// still be open afterwards.
func TestXCrypt_EncapsulateWritesToStdout(t *testing.T) {
	dir := t.TempDir()
	staged := filepath.Join(dir, "staged.zip")
	inner := xcryptStageInner(t, staged)
	const password = "a password"

	captured := filepath.Join(dir, "stdout.zip")
	f, err := os.Create(captured)
	if err != nil {
		t.Fatalf("create the capture file: %v", err)
	}
	saved := os.Stdout
	t.Cleanup(func() { os.Stdout = saved })
	os.Stdout = f
	err = encapsulateXCryptZip("-", staged, password)
	os.Stdout = saved
	if err != nil {
		t.Fatalf("encapsulate to stdout: %v", err)
	}
	// A close that fails here is the encapsulation having closed a stdout
	// it was only lent.
	if err := f.Close(); err != nil {
		t.Fatalf("close the capture file: %v", err)
	}

	zr, err := OpenReaderWithPassword(captured, password)
	if err != nil {
		t.Fatalf("open what went to stdout: %v", err)
	}
	closeAt(t, zr)
	innerReader, err := NewReader(bytes.NewReader(inner), int64(len(inner)))
	if err != nil {
		t.Fatalf("read the staged archive: %v", err)
	}
	xcryptCompareArchives(t, xcryptEntries(t, &zr.Reader), xcryptEntries(t, innerReader))
}

// xcryptWriterBuffer is the size of the buffer the zip writer keeps in front
// of whatever it is writing to. Nothing reaches the destination until it
// fills, which is what decides which step of an encapsulation is the one that
// notices a destination it cannot write to.
const xcryptWriterBuffer = 64 * 1024

// xcryptLayout performs one encapsulation and reads back out of it how many
// bytes it wrote before the payload data, and how many between the end of the
// payload data and the start of the crypto header data. Both are fixed by the
// names and the extra fields of those entries rather than by the size of what
// is staged, so they can be measured once here and used to place a staged
// archive of any size against the writer's buffer.
func xcryptLayout(t *testing.T) (beforePayload, betweenPayloadAndHeader int64) {
	t.Helper()
	dir := t.TempDir()
	staged := filepath.Join(dir, "staged.zip")
	const stagedSize = 1024
	mustWriteFile(t, staged, make([]byte, stagedSize), 0o600)
	final := filepath.Join(dir, "encrypted.zip")
	if err := encapsulateXCryptZip(final, staged, "a password"); err != nil {
		t.Fatalf("encapsulate: %v", err)
	}

	zr, err := OpenReader(final)
	if err != nil {
		t.Fatalf("open the encapsulated archive: %v", err)
	}
	closeAt(t, zr)

	var payload, header *File
	for _, f := range zr.File {
		switch f.Name {
		case xcryptPayloadName:
			payload = f
		case xcryptHeaderName:
			header = f
		}
	}
	if payload == nil || header == nil {
		t.Fatalf("the encapsulated archive is missing its XCrypt entries")
	}
	payloadOffset, err := payload.DataOffset()
	if err != nil {
		t.Fatalf("offset of the payload data: %v", err)
	}
	headerOffset, err := header.DataOffset()
	if err != nil {
		t.Fatalf("offset of the crypto header data: %v", err)
	}
	return payloadOffset, headerOffset - payloadOffset - stagedSize
}

// TestXCrypt_EncapsulateReportsAWriteFailure: every step of the encapsulation
// writes into the same buffered archive, and any of them can be the one whose
// write reaches a destination that is gone. None of them may swallow it: an
// encapsulation that returned nil after a failed write would leave the caller
// believing an archive exists that does not.
//
// The staged sizes below decide which step that is. They are worked out from a
// real encapsulation rather than assumed, so they follow the layout of the
// entries around the payload if it changes; what they cannot follow is a
// change to the size of the writer's own buffer, which would move the failure
// to a different step while leaving every case here still failing.
func TestXCrypt_EncapsulateReportsAWriteFailure(t *testing.T) {
	before, between := xcryptLayout(t)
	if before <= 0 || between <= 0 || before+between >= xcryptWriterBuffer {
		t.Fatalf("the encapsulation writes %d bytes before the payload and %d after it, "+
			"which no staged size can place against a %d byte buffer", before, between, xcryptWriterBuffer)
	}

	for _, tc := range []struct {
		name       string
		stagedSize int64
	}{
		{"while copying the payload", xcryptWriterBuffer - before + 1},
		{"while starting the crypto header entry", xcryptWriterBuffer - before},
		{"while writing the crypto header", xcryptWriterBuffer - before - between},
		{"while closing the archive", 16},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			staged := filepath.Join(dir, "staged.zip")
			mustWriteFile(t, staged, make([]byte, tc.stagedSize), 0o600)

			// A pipe whose reading end is gone fails every write
			// made to it, and it is a real file handle, which is
			// what the destination has to be.
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatalf("open a pipe: %v", err)
			}
			if err := r.Close(); err != nil {
				t.Fatalf("close the reading end: %v", err)
			}
			closeAt(t, w)
			saved := os.Stdout
			t.Cleanup(func() { os.Stdout = saved })
			os.Stdout = w
			err = encapsulateXCryptZip("-", staged, "a password")
			os.Stdout = saved
			if err == nil {
				t.Fatal("encapsulating into a destination that refuses every write reported success")
			}
		})
	}
}

// xcryptUnreadableStaged stages a small archive in dir and takes read access
// to it away from this process, reporting the path to it and whether it
// managed to. Whether the file can be opened is the only thing that changes:
// its directory entry still answers a stat either way, which is what puts
// encapsulateXCryptZip between the two calls it makes on the staged archive.
//
// The file is worked on under a fixed name from inside dir rather than through
// a path put together at run time, because the Windows half of this runs
// icacls: a command line assembled out of variables is one nobody reading it
// can check. S-1-1-0 is Everyone, which includes whoever is running the test,
// and a deny entry beats every grant.
func xcryptUnreadableStaged(t *testing.T, dir string) (string, bool) {
	t.Helper()
	t.Chdir(dir)
	const name = "staged.zip"
	mustWriteFile(t, name, []byte("staged bytes"), 0o600)

	if runtime.GOOS == "windows" {
		if out, err := exec.Command("icacls", name, "/deny", "*S-1-1-0:(R)").CombinedOutput(); err != nil {
			t.Logf("icacls could not deny read access: %v: %s", err, out)
			return "", false
		}
		t.Cleanup(func() {
			if out, err := exec.Command("icacls", name, "/remove:d", "*S-1-1-0").CombinedOutput(); err != nil {
				t.Logf("icacls could not restore access to %s: %v: %s", name, err, out)
			}
		})
	} else {
		if os.Geteuid() == 0 {
			return "", false
		}
		if err := os.Chmod(name, 0); err != nil {
			t.Fatalf("chmod %s: %v", name, err)
		}
		t.Cleanup(func() {
			if err := os.Chmod(name, 0o600); err != nil {
				t.Logf("could not restore access to %s: %v", name, err)
			}
		})
	}

	// Whatever was asked for above, what matters is the result.
	f, err := os.Open(name)
	if err == nil {
		if cerr := f.Close(); cerr != nil {
			t.Fatalf("close %s: %v", name, cerr)
		}
		return "", false
	}
	return filepath.Join(dir, name), true
}
