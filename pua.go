package zip

import (
	"runtime"
	"strings"
	"unicode/utf8"
)

const MappedStringMark = '\uFFFE'
const MappedStringMarkStr = "\uFFFE"

// privateUseBase is where the mapping puts byte 0x00; the 256 byte values run
// from there to privateUseBase+0xFF.
const privateUseBase = rune(0xE000)

func decodeUTF8OrMap(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	var sb strings.Builder
	sb.WriteRune(MappedStringMark)
	for _, c := range b {
		sb.WriteRune(privateUseBase + rune(c))
	}
	return sb.String()
}

func encodeMappedString(s string) []byte {
	runes := []rune(s)
	if len(runes) > 0 && runes[0] == MappedStringMark {
		b := make([]byte, len(runes)-1)
		for i, r := range runes[1:] {
			// The mark says the rest is one private-use rune per byte,
			// but the string may have been edited since it was mapped.
			// A rune outside the 256 the mapping uses stands for no
			// byte, and narrowing it anyway would put a byte of its low
			// bits into the name, so the string is taken at face value
			// instead.
			if r < privateUseBase || r > privateUseBase+0xFF {
				return []byte(s)
			}
			b[i] = byte(r - privateUseBase)
		}
		return b
	}
	return []byte(s)
}

// osFileName spells an archive entry name the way the running platform's file
// API is able to take it.
//
// decodeUTF8OrMap turns a name that is not valid UTF-8 into a marked,
// all-in-the-private-use-area spelling so that it survives as a Go string.
// Handing the original bytes back to the filesystem is right only where a file
// name is a byte string, which is Linux and the BSDs. Windows converts every
// path through syscall.UTF16FromString, which replaces each byte that is not
// valid UTF-8 with U+FFFD, so the bytes never arrive and two entries differing
// only in those bytes collide on one name. macOS refuses such a name outright,
// with EILSEQ.
//
// On those two the undecodable bytes alone are escaped, and everything that
// was already valid UTF-8 is left as it is -- so "bad_\xff_name.txt" keeps its
// text and its extension instead of becoming a row of boxes. The escape is one
// private-use character per byte, which both platforms accept. What macOS
// refuses is narrow and specific: xnu's utf8_decodestr and utf8_validatestr
// in bsd/vfs/vfs_utfconv.c reject a name outright for `ch == 0xFFFE ||
// ch == 0xFFFF` and for the surrogate range, and nothing else in the
// private-use area. Measured on macos-latest and macos-15-intel, U+E000,
// U+E0FF and U+F8FF all go to disk while U+FFFE, U+FFFF and U+FDD0 come back
// EILSEQ -- which is also why the mark decodeUTF8OrMap prepends can never
// travel to disk itself, and why nothing here prepends it. Windows takes
// every one of them.
func osFileName(name string) string {
	if !strings.Contains(name, MappedStringMarkStr) {
		return name
	}
	return osRawBytes(encodeMappedString(name))
}

// osRawBytes spells bytes that came out of an archive the way the running
// platform's file API is able to take them.
//
// It is the whole of the platform decision, and the invariant to keep is this:
// every name taken from archive content is spelled by this function before it
// meets the filesystem -- whether it is handed to the OS as a path (entry
// names, link targets, hard link targets, the solid stream's inner names) or
// compared against a name the OS handed back (the incremental listing). A name
// that skips it either fails on Windows and macOS or silently collides.
//
// Most of them arrive by way of osFileName, which takes the mapped form back
// apart first. A symlink target does not: it is read from the entry's body as
// bytes and carries no mark for osFileName to notice, so it would be handed
// straight back and the link would point at bytes no file on Windows or macOS
// was written under. Everything downstream of a spelled path -- the times, the
// mode, the ownership, the extended attributes -- is given the path that came
// out of here.
func osRawBytes(raw []byte) string {
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		return escapeInvalidUTF8(raw)
	}
	return string(raw)
}

// escapeInvalidUTF8 rewrites every byte that is not part of a valid UTF-8
// sequence as the private-use character U+E000 plus that byte's value, and
// copies each valid sequence through untouched.
//
// The mapping is one code point per bad byte, so two undecodable names that
// differ in such a byte still differ on disk, which is the property that keeps
// them from overwriting one another.
//
// It is not injective over all names, and does not need to be. Only bytes that
// are not part of a valid UTF-8 sequence are touched, so a well-formed name is
// written exactly as it reads -- and a well-formed name that already carries a
// private-use rune in U+E080-U+E0FF where an undecodable name carries the
// escape of the corresponding byte lands on the same spelling as that name.
// The range stops short of U+E080 because every byte below 0x80 is a valid
// UTF-8 sequence of its own and is never escaped.
// Nothing in the package reads an on-disk name back through the mapping: the
// writer does not unmap private-use runes, and encodeMappedString runs only on
// what the reader produced. Escaping such runes as well would buy the missing
// injectivity by rewriting well-formed names, which is a cost the archives
// that are not malformed would pay for the ones that are.
func escapeInvalidUTF8(b []byte) string {
	var sb strings.Builder
	sb.Grow(len(b))
	for i := 0; i < len(b); {
		// DecodeRune answers RuneError with a width of one only for a byte
		// that cannot begin a sequence; a genuine U+FFFD comes back with its
		// own width of three.
		r, size := utf8.DecodeRune(b[i:])
		if r == utf8.RuneError && size == 1 {
			sb.WriteRune(privateUseBase + rune(b[i]))
			i++
			continue
		}
		sb.Write(b[i : i+size])
		i += size
	}
	return sb.String()
}
