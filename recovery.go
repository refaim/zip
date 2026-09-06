package zip

import (
	"encoding/binary"
	"io"
)

var magicF4Recovery = []byte("F4RECOVERY\x00\x00\x00\x00\x00\x00")

// checkF4Recovery unwraps an archive that carries an F4 recovery footer,
// returning the reader and the length of the archive proper. Anything that is
// not one of these -- too short, unreadable at the footer, no magic, a size the
// footer states that the file cannot hold -- is simply not such an archive, and
// the reader is handed back untouched. There is no failure to report, which is
// why nothing is returned to report it with.
func checkF4Recovery(ra io.ReaderAt, size int64) (io.ReaderAt, int64) {
	if size < 32 {
		return ra, size
	}
	var footer [32]byte
	if _, err := ra.ReadAt(footer[:], size-32); err != nil {
		return ra, size
	}
	if string(footer[16:32]) == string(magicF4Recovery) {
		// #nosec G115 -- the next line is the bound: a value above MaxInt64 arrives here negative and the footer is then ignored
		origSize := int64(binary.LittleEndian.Uint64(footer[8:16]))
		if origSize < 0 || origSize > size {
			return ra, size
		}
		return io.NewSectionReader(ra, 0, origSize), origSize
	}
	return ra, size
}
