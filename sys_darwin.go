//go:build darwin
// +build darwin

package zip

import (
	"fmt"
	"math"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func sysPlatformExtra(fi os.FileInfo, hdr *FileHeader) {
	sys, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}

	// A block device and a character device carry their number the same way,
	// so the two mode cases share one arm.
	switch fi.Mode() & os.ModeType {
	case os.ModeDevice | os.ModeCharDevice, os.ModeDevice:
		// #nosec G115 -- darwin's dev_t is a signed thirty-two-bit number and unix.Major reads only bits 24 to 31 of what it is handed, so the sign extension, which lands above bit 31, changes nothing it looks at
		hdr.Devmajor = int64(unix.Major(uint64(sys.Rdev)))
		// #nosec G115 -- the same conversion as the major above, and unix.Minor reads only bits 0 to 23, which the sign extension leaves alone
		hdr.Devminor = int64(unix.Minor(uint64(sys.Rdev)))
	}
}

func mknod(name string, mode uint32, dev uint64) error {
	// #nosec G115 -- extractSpecialFile bounds each half to a uint32 before unix.Mkdev, and darwin's makedev is the major shifted up by 24 with the minor below it, so the number never passes 2^56 and always fits the int unix.Mknod takes
	return unix.Mknod(name, mode, int(dev))
}

func extractSpecialFile(path string, hdr *FileHeader) error {
	// The two halves of the device number come out of the archive as int64
	// and nothing on the way in bounds them, but unix.Mkdev takes a uint32
	// of each. A major or a minor wider than that would be cut down and the
	// entry would become a different device than the one it named, and a
	// negative one would wrap to a large device the same way. Neither is a
	// device any system names, so such an entry is refused rather than
	// created as something else.
	if hdr.Devmajor < 0 || hdr.Devmajor > math.MaxUint32 ||
		hdr.Devminor < 0 || hdr.Devminor > math.MaxUint32 {
		return fmt.Errorf("zip: device number %d:%d does not fit in two uint32s: %w",
			hdr.Devmajor, hdr.Devminor, ErrFormat)
	}
	// The node is being replaced. If it survives this removal it is still
	// there when mknod runs, and mknod fails with EEXIST on a path that
	// already exists, so a removal that fails is never a failure that goes
	// unreported -- and nothing is written over the surviving node either.
	_ = os.Remove(path)
	mode := uint32(hdr.Mode()) & 0777
	if hdr.Mode()&os.ModeCharDevice != 0 {
		mode |= unix.S_IFCHR
	} else if hdr.Mode()&os.ModeDevice != 0 {
		mode |= unix.S_IFBLK
	} else if hdr.Mode()&os.ModeNamedPipe != 0 {
		mode |= unix.S_IFIFO
	}
	dev := unix.Mkdev(uint32(hdr.Devmajor), uint32(hdr.Devminor))
	return mknod(path, mode, dev)
}

// llistxattr is unix.Llistxattr behind a name a test can take over. The names
// have to be asked for twice, once for their length and once for themselves,
// and the second answer failing after the first succeeded is a state only
// something changing the file's attributes between the two calls produces.
var llistxattr = unix.Llistxattr

func sysXattrs(path string, hdr *FileHeader) error {
	sz, err := llistxattr(path, nil)
	if err != nil || sz <= 0 {
		return nil
	}
	buf := make([]byte, sz)
	sz, err = llistxattr(path, buf)
	if err != nil {
		return nil
	}

	var keys []string
	for i, j := 0, 0; i < sz; i++ {
		if buf[i] == 0 {
			keys = append(keys, string(buf[j:i]))
			j = i + 1
		}
	}

	if len(keys) > 0 && hdr.Xattrs == nil {
		hdr.Xattrs = make(map[string]string)
	}

	for _, key := range keys {
		valSz, err := unix.Lgetxattr(path, key, nil)
		if err != nil || valSz <= 0 {
			continue
		}
		val := make([]byte, valSz)
		sz, err = unix.Lgetxattr(path, key, val)
		if err == nil {
			hdr.Xattrs[key] = string(val[:sz])
		}
	}
	return nil
}

func applyXattrs(path string, hdr *FileHeader) error {
	if len(hdr.Xattrs) == 0 {
		return nil
	}
	for k, v := range hdr.Xattrs {
		// Extended attributes are best effort whatever the extractor's
		// tolerant setting is. Setting one fails with ENOTSUP on every
		// filesystem that has nowhere to keep it -- FAT, exFAT, SMB,
		// tmpfs -- so treating the failure as fatal would break strict
		// extraction onto any of them, for metadata the entry's data
		// does not depend on.
		_ = unix.Lsetxattr(path, k, []byte(v), 0)
	}
	return nil
}
