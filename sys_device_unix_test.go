//go:build linux || darwin || freebsd
// +build linux darwin freebsd

package zip

import (
	"errors"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// deviceHeader is an entry naming a character device with the number given.
// Both halves are int64 in the header because that is how they come out of the
// archive, where nothing bounds them.
func deviceHeader(major, minor int64) *FileHeader {
	hdr := &FileHeader{Name: "node", Devmajor: major, Devminor: minor}
	hdr.SetMode(fs.ModeDevice | fs.ModeCharDevice | 0600)
	return hdr
}

// TestExtractSpecialFileRejectsWideDeviceNumber is the adversarial side of the
// bound in extractSpecialFile. unix.Mkdev takes a uint32 of each half, so
// without the check the first case below is created as device 1:3, which is
// /dev/null, rather than as the device the entry named -- and the ones with a
// negative half wrap to the top of their thirty-two bits the same way.
func TestExtractSpecialFileRejectsWideDeviceNumber(t *testing.T) {
	tests := []struct {
		name         string
		major, minor int64
	}{
		{"a major past thirty-two bits", math.MaxUint32 + 2, 3},
		{"a minor past thirty-two bits", 1, math.MaxUint32 + 4},
		{"a negative major", -1, 3},
		{"a negative minor", 1, -1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "node")
			err := extractSpecialFile(path, deviceHeader(tt.major, tt.minor))
			if !errors.Is(err, ErrFormat) {
				t.Fatalf("extractSpecialFile(%d:%d) = %v, want ErrFormat", tt.major, tt.minor, err)
			}
			if _, serr := os.Lstat(path); !errors.Is(serr, fs.ErrNotExist) {
				t.Errorf("a refused device number still left something at %s: %v", path, serr)
			}
		})
	}
}

// TestExtractSpecialFileModes covers the file type each kind of node is
// created under. The path names a directory that does not exist, so mknod
// fails the same way whether or not the test has the privilege to make a
// device node -- what is asserted is that the device number got through the
// bound and the call was made, not that a node appeared.
func TestExtractSpecialFileModes(t *testing.T) {
	tests := []struct {
		name string
		mode fs.FileMode
	}{
		{"a character device", fs.ModeDevice | fs.ModeCharDevice | 0600},
		{"a block device", fs.ModeDevice | 0600},
		{"a named pipe", fs.ModeNamedPipe | 0600},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hdr := &FileHeader{Name: "node", Devmajor: 1, Devminor: 3}
			hdr.SetMode(tt.mode)
			path := filepath.Join(t.TempDir(), "missing", "node")
			err := extractSpecialFile(path, hdr)
			if err == nil {
				t.Fatal("a node was made under a directory that does not exist")
			}
			if errors.Is(err, ErrFormat) {
				t.Fatalf("the device number 1:3 was refused: %v", err)
			}
		})
	}
}

// TestMknodRejectsDeviceNumberWiderThanAnInt is the second bound: both halves
// fit a uint32 here, but the linux encoding puts the top twenty bits of the
// major above bit 44, so the number Mkdev builds from this major is past the
// largest int64. Without the check unix.Mknod is handed that number as a
// negative int.
func TestMknodRejectsDeviceNumberWiderThanAnInt(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("only the linux encoding scatters the major high enough to overrun an int")
	}
	path := filepath.Join(t.TempDir(), "node")
	err := extractSpecialFile(path, deviceHeader(0xfffff000, 0))
	if !errors.Is(err, ErrFormat) {
		t.Fatalf("extractSpecialFile = %v, want ErrFormat", err)
	}
	if _, serr := os.Lstat(path); !errors.Is(serr, fs.ErrNotExist) {
		t.Errorf("a refused device number still left something at %s: %v", path, serr)
	}
}
