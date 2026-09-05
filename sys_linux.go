//go:build linux
// +build linux

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

	switch fi.Mode() & os.ModeType {
	case os.ModeDevice | os.ModeCharDevice:
		hdr.Devmajor = int64(unix.Major(uint64(sys.Rdev)))
		hdr.Devminor = int64(unix.Minor(uint64(sys.Rdev)))
	case os.ModeDevice:
		hdr.Devmajor = int64(unix.Major(uint64(sys.Rdev)))
		hdr.Devminor = int64(unix.Minor(uint64(sys.Rdev)))
	}
}

// mknod creates the node. unix.Mknod takes the device number as an int, and
// the number unix.Mkdev builds is a uint64: the linux encoding puts the top
// twenty bits of the major above bit 44, so a major near the end of its
// thirty-two bits produces a number past the largest int64. Converting that
// would turn it negative and name a device the archive did not, so it is
// refused instead.
func mknod(name string, mode uint32, dev uint64) error {
	if dev > math.MaxInt {
		return fmt.Errorf("zip: device number %d does not fit in an int: %w", dev, ErrFormat)
	}
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

func sysXattrs(path string, hdr *FileHeader) error {
	sz, err := unix.Llistxattr(path, nil)
	if err != nil || sz <= 0 {
		return nil
	}
	buf := make([]byte, sz)
	sz, err = unix.Llistxattr(path, buf)
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
		if err != nil || valSz < 0 {
			continue
		}
		val := make([]byte, valSz)
		_, err = unix.Lgetxattr(path, key, val)
		if err == nil {
			hdr.Xattrs[key] = string(val)
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
