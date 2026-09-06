package zip

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	// #nosec G505 -- WinZip AES (APPNOTE 6.3.x) requires PBKDF2-HMAC-SHA1 and an HMAC-SHA1 authentication code; changing the algorithm breaks the format
	"crypto/sha1"
	"errors"
	"hash"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

// winzipAesInfo stores parameters from Extra Field 0x9901
type winzipAesInfo struct {
	version      uint16
	strength     byte // 1=128, 2=192, 3=256
	actualMethod uint16
}

type aesReader struct {
	r         io.Reader
	baseR     io.Reader
	decrypter cipher.Stream
	mac       hash.Hash
	err       error
}

func (ar *aesReader) Read(p []byte) (int, error) {
	if ar.err != nil {
		return 0, ar.err
	}
	n, err := ar.r.Read(p)
	if n > 0 {
		ar.mac.Write(p[:n])
		ar.decrypter.XORKeyStream(p[:n], p[:n])
	}
	if err == io.EOF {
		expectedMAC := make([]byte, 10)
		if _, macErr := io.ReadFull(ar.baseR, expectedMAC); macErr != nil {
			ar.err = macErr
			return n, macErr
		}
		calculatedMAC := ar.mac.Sum(nil)[:10]
		if !hmac.Equal(calculatedMAC, expectedMAC) {
			ar.err = ErrChecksum
			return n, ErrChecksum
		}
		ar.err = io.EOF
	}
	return n, err
}

func newWinZipAesReader(r io.Reader, password string, info *winzipAesInfo, compressedSize int64) (io.Reader, uint16, error) {
	if info == nil {
		return nil, 0, errors.New("zip: AES info missing")
	}
	var keyLen, saltLen int
	switch info.strength {
	case 1:
		keyLen, saltLen = 16, 8
	case 2:
		keyLen, saltLen = 24, 12
	case 3:
		keyLen, saltLen = 32, 16
	default:
		return nil, 0, errors.New("zip: unknown AES strength")
	}

	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(r, salt); err != nil {
		return nil, 0, err
	}

	// Key derivation (1000 iterations per specification)
	keys := pbkdf2.Key([]byte(password), salt, 1000, keyLen*2+2, sha1.New)
	encKey := keys[:keyLen]
	authKey := keys[keyLen : 2*keyLen]
	pwVerif := keys[2*keyLen : 2*keyLen+2]

	// Password verification
	verifBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, verifBuf); err != nil {
		return nil, 0, err
	}
	if !hmac.Equal(verifBuf, pwVerif) {
		return nil, 0, ErrPassword
	}

	// The key is the keyLen bytes PBKDF2 produced, and keyLen is 16, 24 or 32
	// by the switch above, which are the three lengths AES takes, so there is
	// no cipher here that could fail to be made.
	block, _ := aes.NewCipher(encKey)

	// WinZip AES uses CTR mode with IV=1 (per 16-byte blocks)
	iv := make([]byte, 16)
	for i := range iv {
		iv[i] = 0
	}
	iv[0] = 1

	decrypter := cipher.NewCTR(block, iv)

	// Limit the reader to avoid overrunning onto the HMAC (10 bytes at the end)
	dataSize := compressedSize - int64(saltLen) - 2 - 10
	if dataSize < 0 {
		return nil, 0, errors.New("zip: encrypted data too short")
	}
	limitedR := io.LimitReader(r, dataSize)

	return &aesReader{
		r:         limitedR,
		baseR:     r,
		decrypter: decrypter,
		mac:       hmac.New(sha1.New, authKey),
	}, info.actualMethod, nil
}

// addIVBigEndian adds a block offset to a 128-bit big-endian IV
func addIVBigEndian(baseIV []byte, offset uint64) []byte {
	iv := make([]byte, 16)
	copy(iv, baseIV)
	var carry = offset
	for i := 15; i >= 0 && carry > 0; i-- {
		sum := uint64(iv[i]) + (carry & 0xFF)
		// #nosec G115 -- sum is one IV byte plus one byte of the carry, so it is at most 0x1FE and this keeps the low byte while the line below carries the rest
		iv[i] = byte(sum)
		carry = (carry >> 8) + (sum >> 8)
	}
	return iv
}

type winZipAesReaderAt struct {
	r          io.ReaderAt
	baseOffset int64
	encKey     []byte
	limit      int64
	iv         []byte
}

// verifyWinZipAesCode checks the authentication code an entry carries behind
// its ciphertext against the code the ciphertext that is there produces. The
// code covers the ciphertext rather than the plaintext, so one sequential pass
// answers it with nothing decrypted and nothing held: the entry goes through a
// fixed buffer whatever its size. dataOffset and limit are where the
// ciphertext begins in r and how long it is; the ten byte code follows it.
func verifyWinZipAesCode(r io.ReaderAt, authKey []byte, dataOffset, limit int64) error {
	mac := hmac.New(sha1.New, authKey)
	// A megabyte at a time rather than the 32 KiB io.Copy would use on its
	// own: this is a whole entry going past, and the entries the seekable
	// path exists for are the large ones.
	n, err := io.CopyBuffer(mac, io.NewSectionReader(r, dataOffset, limit), make([]byte, 1024*1024))
	if err != nil {
		return err
	}
	stored := make([]byte, 10)
	_, codeErr := io.ReadFull(io.NewSectionReader(r, dataOffset+limit, 10), stored)
	if n != limit || codeErr != nil {
		// The entry stops before the code its header says is behind it,
		// so there is nothing to check it against. Neither half of this
		// says so on its own: io.Copy calls a section that ended early a
		// finished copy, and a code read back from nothing at all comes
		// out as io.EOF, which a caller reading through this would take
		// for the clean end of the entry.
		if codeErr == nil || codeErr == io.EOF {
			return io.ErrUnexpectedEOF
		}
		return codeErr
	}
	if !hmac.Equal(mac.Sum(nil)[:10], stored) {
		// The same failure the sequential reader reports when it reaches
		// the end of an entry that does not authenticate.
		return &EncryptedDataError{Err: ErrChecksum}
	}
	return nil
}

// newWinZipAesReaderAt prepares random access to a WinZip AES entry. When
// verify is set the entry's authentication code is checked before the reader
// is handed back, which costs one sequential pass over the ciphertext; without
// it the bytes this reader produces are decrypted but never authenticated, and
// AES-CTR being malleable, a tampered entry then reads back as whatever the
// change made of it.
func newWinZipAesReaderAt(r io.ReaderAt, password string, info *winzipAesInfo, compressedSize int64, verify bool) (*winZipAesReaderAt, error) {
	if info == nil {
		return nil, errors.New("zip: AES info missing")
	}
	var keyLen, saltLen int
	switch info.strength {
	case 1:
		keyLen, saltLen = 16, 8
	case 2:
		keyLen, saltLen = 24, 12
	case 3:
		keyLen, saltLen = 32, 16
	default:
		return nil, errors.New("zip: unknown AES strength")
	}

	salt := make([]byte, saltLen)
	if _, err := r.ReadAt(salt, 0); err != nil {
		return nil, err
	}

	keys := pbkdf2.Key([]byte(password), salt, 1000, keyLen*2+2, sha1.New)
	encKey := keys[:keyLen]
	pwVerif := keys[2*keyLen : 2*keyLen+2]

	verifBuf := make([]byte, 2)
	if _, err := r.ReadAt(verifBuf, int64(saltLen)); err != nil {
		return nil, err
	}
	if !hmac.Equal(verifBuf, pwVerif) {
		return nil, ErrPassword
	}

	limit := compressedSize - int64(saltLen) - 2 - 10
	if limit < 0 {
		return nil, errors.New("zip: encrypted data too short")
	}

	// After the password verifier, so a wrong password is still answered
	// by the two bytes the format put there for it rather than by a read
	// of the whole entry.
	if verify {
		authKey := keys[keyLen : 2*keyLen]
		if err := verifyWinZipAesCode(r, authKey, int64(saltLen)+2, limit); err != nil {
			return nil, err
		}
	}

	iv := make([]byte, 16)
	for i := range iv {
		iv[i] = 0
	}
	iv[0] = 1

	return &winZipAesReaderAt{
		r:          r,
		baseOffset: int64(saltLen + 2),
		encKey:     encKey,
		limit:      limit,
		iv:         iv,
	}, nil
}

func (ar *winZipAesReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= ar.limit {
		return 0, io.EOF
	}

	avail := ar.limit - off
	if int64(len(p)) > avail {
		p = p[:avail]
	}
	if len(p) == 0 {
		return 0, nil
	}

	blockOffset := uint64(off / 16)
	rem := int(off % 16)

	readSize := len(p) + rem
	encBuf := make([]byte, readSize)

	n, err := ar.r.ReadAt(encBuf, ar.baseOffset+off-int64(rem))
	if n == 0 && err != nil {
		return 0, err
	}

	encBuf = encBuf[:n]

	block, errC := aes.NewCipher(ar.encKey)
	if errC != nil {
		return 0, errC
	}

	ctrIV := addIVBigEndian(ar.iv, blockOffset)

	stream := cipher.NewCTR(block, ctrIV)
	decBuf := make([]byte, n)
	stream.XORKeyStream(decBuf, encBuf)

	copied := copy(p, decBuf[rem:])

	if err == io.EOF && copied == len(p) {
		return copied, nil
	}

	return copied, err
}

type aesWriter struct {
	w         io.Writer
	encrypter cipher.Stream
	mac       hash.Hash
	buf       []byte
}

func newWinZipAesWriter(w io.Writer, password string, strength byte) (io.WriteCloser, error) {
	var keyLen, saltLen int
	switch strength {
	case 1:
		keyLen, saltLen = 16, 8
	case 2:
		keyLen, saltLen = 24, 12
	case 3:
		keyLen, saltLen = 32, 16
	default:
		return nil, errors.New("zip: unknown AES strength")
	}

	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	keys := pbkdf2.Key([]byte(password), salt, 1000, keyLen*2+2, sha1.New)
	encKey := keys[:keyLen]
	authKey := keys[keyLen : 2*keyLen]
	pwVerif := keys[2*keyLen : 2*keyLen+2]

	if _, err := w.Write(salt); err != nil {
		return nil, err
	}
	if _, err := w.Write(pwVerif); err != nil {
		return nil, err
	}

	// The same key PBKDF2 produced at one of the three lengths AES takes; see
	// the reader above.
	block, _ := aes.NewCipher(encKey)

	iv := make([]byte, 16)
	for i := range iv {
		iv[i] = 0
	}
	iv[0] = 1

	decrypter := cipher.NewCTR(block, iv)

	return &aesWriter{
		w:         w,
		encrypter: decrypter,
		mac:       hmac.New(sha1.New, authKey),
	}, nil
}

func (aw *aesWriter) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	if cap(aw.buf) < len(p) {
		aw.buf = make([]byte, len(p))
	} else {
		aw.buf = aw.buf[:len(p)]
	}
	aw.encrypter.XORKeyStream(aw.buf, p)
	aw.mac.Write(aw.buf)
	return aw.w.Write(aw.buf)
}

func (aw *aesWriter) Close() error {
	macBytes := aw.mac.Sum(nil)[:10] // WinZip AES uses 10-byte MAC
	_, err := aw.w.Write(macBytes)
	return err
}
