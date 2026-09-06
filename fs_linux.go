//go:build linux
// +build linux

package zip

import (
	"golang.org/x/sys/unix"
	"os"
)

// fallocate is unix.Fallocate behind a name a test can take over. Whether the
// filesystem an entry is being written onto can reserve space for it at all is
// a property of the mount and not of the archive -- a FAT or an SMB volume
// simply says it cannot -- and that answer is the one preallocate exists to
// keep going after.
var fallocate = unix.Fallocate

func preallocate(f *os.File, size int64) error {
	if size <= 1024*1024 {
		return nil
	}
	err := fallocate(int(f.Fd()), 0, 0, size)
	if err != nil {
		// Ignore filesystem-unsupported errors as preallocation is a performance optimization
		if err == unix.EOPNOTSUPP || err == unix.ENOSYS || err == unix.ENOTTY || err == unix.EINVAL {
			return nil
		}
	}
	return err
}
