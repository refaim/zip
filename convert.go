package zip

import (
	"fmt"
	"math"
)

// u64toi64 narrows a size or an offset read out of an archive to the int64 the
// io interfaces take. Sizes and offsets are eight unsigned bytes in the zip
// format and nothing bounds them on the way in, so the value can be one no
// int64 holds; converting it anyway turns it negative, and a negative length
// handed to io.NewSectionReader is not an empty reader but an unbounded one.
// Only a corrupt or a hostile archive carries such a number, so it is refused
// as a format error rather than narrowed.
func u64toi64(v uint64) (int64, error) {
	if v > math.MaxInt64 {
		return 0, fmt.Errorf("zip: size or offset %d does not fit in an int64: %w", v, ErrFormat)
	}
	return int64(v), nil
}

// fitUint16 narrows a length to the uint16 the format keeps it in. The name,
// the extra field and the comment of an entry each have a two-byte length in
// the header, so a longer one cannot be written: what would go on disk is a
// header announcing len&0xffff bytes followed by the whole string, which is an
// archive no reader can make sense of. The caller is the program using this
// package, so this is a write error and not a panic, and what is named is the
// field the caller can shorten.
func fitUint16(n int, what string) (uint16, error) {
	if n < 0 || n > uint16max {
		return 0, fmt.Errorf("zip: %s is %d bytes, over the %d bytes the format allows", what, n, uint16max)
	}
	return uint16(n), nil
}
