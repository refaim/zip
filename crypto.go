package zip

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"os"
	"sync"

	"golang.org/x/crypto/pbkdf2"
)

// F4CryptHeader represents the 93-byte binary header for encrypted streams
type XCryptHeader struct {
	Version    uint8
	KdfAlgo    uint8
	Cipher     uint8
	Iterations uint32
	Salt       []byte
	IV         []byte
	MAC        []byte
}

func generateXCryptHeader(password string, iterations int) (*XCryptHeader, []byte, error) {
	if iterations == 0 {
		iterations = 600000
	}

	salt := make([]byte, 32)
	iv := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, nil, err
	}
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, nil, err
	}

	key := pbkdf2.Key([]byte(password), salt, iterations, 32, sha256.New)

	hdr := &XCryptHeader{
		Version:    1,
		KdfAlgo:    1,
		Cipher:     1,
		Iterations: uint32(iterations),
		Salt:       salt,
		IV:         iv,
		MAC:        make([]byte, 32),
	}
	return hdr, key, nil
}

func parseXCryptHeader(data []byte) (*XCryptHeader, error) {
	if len(data) != 93 {
		return nil, errors.New("zip: invalid XCrypt header size")
	}
	if string(data[0:6]) != "XCRYPT" {
		return nil, errors.New("zip: invalid XCrypt magic signature")
	}
	if data[6] != 1 || data[7] != 1 || data[8] != 1 {
		return nil, errors.New("zip: unsupported XCrypt algorithms")
	}

	hdr := &XCryptHeader{
		Version:    data[6],
		KdfAlgo:    data[7],
		Cipher:     data[8],
		Iterations: binary.LittleEndian.Uint32(data[9:13]),
		Salt:       make([]byte, 32),
		IV:         make([]byte, 16),
		MAC:        make([]byte, 32),
	}
	copy(hdr.Salt, data[13:45])
	copy(hdr.IV, data[45:61])
	copy(hdr.MAC, data[61:93])

	return hdr, nil
}

func (h *XCryptHeader) Encode() []byte {
	b := make([]byte, 93)
	copy(b[0:6], "XCRYPT")
	b[6] = h.Version
	b[7] = h.KdfAlgo
	b[8] = h.Cipher
	binary.LittleEndian.PutUint32(b[9:13], h.Iterations)
	copy(b[13:45], h.Salt)
	copy(b[45:61], h.IV)
	copy(b[61:93], h.MAC)
	return b
}

func (h *XCryptHeader) DeriveKey(password string) []byte {
	return pbkdf2.Key([]byte(password), h.Salt, int(h.Iterations), 32, sha256.New)
}

type xCryptWriter struct {
	mu     sync.Mutex
	w      io.Writer
	stream cipher.Stream
	mac    hash.Hash
	buf    []byte
}

func newXCryptWriter(w io.Writer, key, iv []byte) (*xCryptWriter, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(block, iv)
	mac := hmac.New(sha256.New, key)

	return &xCryptWriter{
		w:      w,
		stream: stream,
		mac:    mac,
	}, nil
}

func (cw *xCryptWriter) Write(p []byte) (int, error) {
	cw.mu.Lock()
	defer cw.mu.Unlock()
	// Переиспользуем буфер, чтобы избежать аллокации (например, 2 МБ) на каждую запись
	if cap(cw.buf) < len(p) {
		cw.buf = make([]byte, len(p))
	}
	enc := cw.buf[:len(p)]
	cw.stream.XORKeyStream(enc, p)
	cw.mac.Write(enc)
	return cw.w.Write(enc)
}

func (cw *xCryptWriter) MAC() []byte {
	return cw.mac.Sum(nil)
}

type xCryptReaderAt struct {
	r   io.ReaderAt
	key []byte
	iv  []byte
}

func newXCryptReaderAt(r io.ReaderAt, key, iv []byte) *xCryptReaderAt {
	return &xCryptReaderAt{r: r, key: key, iv: iv}
}

func (cr *xCryptReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	// #nosec G115 -- ReadAt is not called with a negative offset, and the block index is the offset divided by the cipher's block size
	blockOffset := uint64(off / 16)
	rem := int(off % 16)

	readSize := len(p) + rem
	encBuf := make([]byte, readSize)

	n, err := cr.r.ReadAt(encBuf, off-int64(rem))
	if n == 0 && err != nil {
		return 0, err
	}

	encBuf = encBuf[:n]

	c, errC := aes.NewCipher(cr.key)
	if errC != nil {
		return 0, errC
	}

	iv := make([]byte, 16)
	copy(iv, cr.iv)
	var carry = blockOffset
	for i := 15; i >= 0 && carry > 0; i-- {
		sum := uint64(iv[i]) + (carry & 0xFF)
		// #nosec G115 -- sum is one IV byte plus one byte of the carry, so it is at most 0x1FE and this keeps the low byte while the line below carries the rest
		iv[i] = byte(sum)
		carry = (carry >> 8) + (sum >> 8)
	}

	stream := cipher.NewCTR(c, iv)

	decBuf := make([]byte, n)
	stream.XORKeyStream(decBuf, encBuf)

	copied := copy(p, decBuf[rem:])

	if err == io.EOF && copied == len(p) {
		return copied, nil
	}

	return copied, err
}

func encapsulateXCryptZip(finalPath, tempPath, password string) (err error) {
	var out *os.File
	if finalPath == "-" {
		out = os.Stdout
	} else {
		out, err = os.Create(finalPath)
		if err != nil {
			return err
		}
		// This is the archive being produced. A close that failed
		// means the last of it never reached the disk, so the file the
		// caller is handed is not the archive it was told about.
		defer func() {
			if cerr := out.Close(); err == nil {
				err = cerr
			}
		}()
	}

	zw := NewWriter(out)

	// Stub. NewWriter puts a 64 KiB buffer in front of the destination and
	// this entry and the payload entry below are both started inside the
	// first few hundred bytes of the archive, so neither call has a write
	// behind it that could have failed and neither can hand back a nil
	// writer. Nothing is lost either way: a buffered writer keeps the first
	// failure it meets and answers with it from then on, so a write that
	// fails is reported again by the Close at the end of this function.
	stubMsg := []byte("This is an encrypted archive. Please use f4 or an AXS-compatible tool to extract it.\n")
	w, _ := zw.CreateHeader(&FileHeader{Name: "README_ENCRYPTED.txt", Method: Store})
	_, _ = w.Write(stubMsg)

	cHdr, key, err := generateXCryptHeader(password, 600000)
	if err != nil {
		return err
	}

	tempFi, err := os.Stat(tempPath)
	if err != nil {
		return err
	}

	// Payload
	pHdr := &FileHeader{Name: ".zipext/xcrypt/payload.enc", Method: Store}
	// #nosec G115 -- the size comes from the operating system for the file this call just staged
	pHdr.UncompressedSize64 = uint64(tempFi.Size())
	pHdr.CompressedSize64 = pHdr.UncompressedSize64
	pHdr.Flags |= 0x1 // Mark as encrypted

	// Add standard Extra Field 0x7819 to identify it as XCrypt payload
	xcryptExtra := make([]byte, 4)
	binary.LittleEndian.PutUint16(xcryptExtra[0:2], xcryptExtraID)
	binary.LittleEndian.PutUint16(xcryptExtra[2:4], 0)
	pHdr.Extra = append(pHdr.Extra, xcryptExtra...)

	// Still inside the first few hundred bytes; see the stub above.
	pw, _ := zw.CreateRaw(pHdr)

	in, err := os.Open(tempPath)
	if err != nil {
		return err
	}
	// The key is the 32 bytes PBKDF2 produced, which is a length AES takes,
	// so there is no cipher here that could fail to be made.
	cw, _ := newXCryptWriter(pw, key, cHdr.IV)
	// Используем 1МБ буфер вместо дефолтных 32КБ для инкапсуляции
	// This is the whole of the encrypted archive. A short copy leaves an
	// entry whose header promises bytes that are not there, and the caller
	// was told the archive was written.
	_, copyErr := io.CopyBuffer(cw, in, make([]byte, 1024*1024))
	// The staged archive is only being read from here.
	_ = in.Close()
	if copyErr != nil {
		return copyErr
	}

	cHdr.MAC = cw.MAC()

	// Metadata
	mHdr := &FileHeader{Name: ".zipext/xcrypt/crypto.hdr", Method: Store}
	mHdr.UncompressedSize64 = 93
	mHdr.CompressedSize64 = 93
	// The third entry is not like the first two: the payload has gone
	// through the buffer by now, so this is the first call in the function
	// with a write behind it that can already have failed.
	mw, err := zw.CreateRaw(mHdr)
	if err != nil {
		return err
	}
	// Without the crypto header the payload cannot be decrypted at all.
	if _, err := mw.Write(cHdr.Encode()); err != nil {
		return err
	}

	return zw.Close()
}

func checkXCryptZip(ra io.ReaderAt, size int64, password string) (io.ReaderAt, int64, error) {
	if size < 22 {
		return ra, size, nil
	}

	zr := new(Reader)
	if err := zr.init(ra, size); err != nil {
		return ra, size, nil
	}

	var cHdr *XCryptHeader
	var payloadFile *File
	hasXcryptTag := false

	for _, file := range zr.File {
		if file.Name == ".zipext/xcrypt/crypto.hdr" {
			rc, oerr := file.Open()
			if oerr != nil {
				return nil, 0, oerr
			}
			data, rerr := io.ReadAll(rc)
			// The entry was read to its end, so its checksum has
			// already been checked and this handle has nothing
			// left to say.
			_ = rc.Close()
			if rerr != nil {
				return nil, 0, rerr
			}
			var err error
			cHdr, err = parseXCryptHeader(data)
			if err != nil {
				return nil, 0, err
			}
		} else if file.Name == ".zipext/xcrypt/payload.enc" {
			payloadFile = file
			for extra := readBuf(file.Extra); len(extra) >= 4; {
				tag := extra.uint16()
				sz := int(extra.uint16())
				if tag == xcryptExtraID {
					hasXcryptTag = true
					break
				}
				if len(extra) < sz {
					break
				}
				extra = extra[sz:]
			}
		}
	}

	if cHdr == nil || payloadFile == nil || !hasXcryptTag {
		return ra, size, nil
	}

	if password == "" {
		return ra, size, nil // Return legacy unencrypted view of the stub (README)
	}

	key := cHdr.DeriveKey(password)

	// Open the payload stream directly
	pOff, err := payloadFile.DataOffset()
	if err != nil {
		return nil, 0, err
	}
	// #nosec G115 -- readDirectoryHeader and salvage both refuse an entry whose CompressedSize64 is above MaxInt64
	payloadSection := io.NewSectionReader(ra, pOff, int64(payloadFile.CompressedSize64))
	decReader := newXCryptReaderAt(payloadSection, key, cHdr.IV)

	// #nosec G115 -- readDirectoryHeader and salvage both refuse an entry whose CompressedSize64 is above MaxInt64
	return decReader, int64(payloadFile.CompressedSize64), nil
}
