//go:build freebsd
// +build freebsd

package zip

import (
	"fmt"
	"math"
	"os"
	"runtime"
	"syscall"
	"unsafe"

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

func mknod(name string, mode uint32, dev uint64) error {
	return unix.Mknod(name, mode, dev)
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

// extattrListLink is the boundary the attribute list crosses. The listing is
// read twice, once for its size and once for its content, and the second call
// is what a test has to be able to fail or answer with a malformed list: the
// two calls sit next to each other, so nothing an archive or a filesystem can
// be put into decides what happens between them. The buffer is passed as a
// slice rather than as the address and length the syscall wants, so that the
// one place that has to reach for unsafe is this line and not both callers.
var extattrListLink = func(path string, ns int, buf []byte) (int, error) {
	if len(buf) == 0 {
		return unix.ExtattrListLink(path, ns, 0, 0)
	}
	return unix.ExtattrListLink(path, ns, uintptr(unsafe.Pointer(&buf[0])), len(buf))
}

func sysXattrs(path string, hdr *FileHeader) error {
	namespaces := []struct {
		ns     int
		prefix string
	}{
		{unix.EXTATTR_NAMESPACE_USER, "user."},
		{unix.EXTATTR_NAMESPACE_SYSTEM, "system."},
	}

	for _, n := range namespaces {
		// 1. Query size of list (passing 0 and 0 under FreeBSD API)
		sz, err := extattrListLink(path, n.ns, nil)
		if err != nil || sz <= 0 {
			continue
		}

		buf := make([]byte, sz)
		sz, err = extattrListLink(path, n.ns, buf)
		if err != nil {
			continue
		}

		if hdr.Xattrs == nil {
			hdr.Xattrs = make(map[string]string)
		}

		for i := 0; i < sz; {
			l := int(buf[i])
			i++
			if i+l > sz {
				break
			}
			key := string(buf[i : i+l])
			i += l

			// 2. Query size of attribute value
			valSz, err := unix.ExtattrGetLink(path, n.ns, key, 0, 0)
			if err != nil || valSz <= 0 {
				continue
			}

			val := make([]byte, valSz)
			valSz, err = unix.ExtattrGetLink(path, n.ns, key, uintptr(unsafe.Pointer(&val[0])), len(val))
			if err == nil {
				hdr.Xattrs[n.prefix+key] = string(val[:valSz])
			}
		}
	}
	return nil
}

func applyXattrs(path string, hdr *FileHeader) error {
	if len(hdr.Xattrs) == 0 {
		return nil
	}
	for k, v := range hdr.Xattrs {
		ns := unix.EXTATTR_NAMESPACE_USER
		attrName := k
		if len(k) > 7 && k[:7] == "system." {
			ns = unix.EXTATTR_NAMESPACE_SYSTEM
			attrName = k[7:]
		} else if len(k) > 5 && k[:5] == "user." {
			attrName = k[5:]
		}

		var ptr uintptr
		var bytesVal []byte
		if len(v) > 0 {
			bytesVal = []byte(v)
			ptr = uintptr(unsafe.Pointer(&bytesVal[0]))
		}

		// Extended attributes are best effort whatever the extractor's
		// tolerant setting is. Setting one fails on every filesystem that
		// has nowhere to keep it, and the system namespace needs a
		// privilege the extraction as a whole does not, so treating the
		// failure as fatal would break strict extraction onto any of them,
		// for metadata the entry's data does not depend on.
		_, _ = unix.ExtattrSetLink(path, ns, attrName, ptr, len(v))
		if len(bytesVal) > 0 {
			runtime.KeepAlive(bytesVal)
		}
	}
	return nil
}
