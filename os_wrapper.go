package zip

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// fixOSPath adds the \\?\ prefix on Windows to prevent the Win32 API
// from automatically stripping trailing dots and spaces from file names.
func fixOSPath(p string) string {
	if runtime.GOOS != "windows" {
		return p
	}
	if p == "" {
		return p
	}
	abs, ok := absKeepTrailing(p)
	if !ok {
		// There is no absolute spelling to prefix, and `\\?\` in front of a
		// path that is still relative is one the kernel refuses outright.
		// The plain Win32 spelling still resolves the way it always has: what
		// is given up is what the prefix buys, not the path.
		return p
	}
	if strings.HasPrefix(abs, `\\?\`) {
		return abs
	}
	if strings.HasPrefix(abs, `\\`) {
		return `\\?\UNC\` + abs[2:]
	}
	return `\\?\` + abs
}

// getwd is os.Getwd behind a name a test can take over. It fails only when the
// working directory has been unlinked out from under the process, which no
// test can arrange portably, and the branch it guards decides whether a path
// reaches the kernel at all.
var getwd = os.Getwd

// absKeepTrailing is filepath.Abs with the Win32 path normalisation left out,
// and reports whether it had an answer.
//
// filepath.Abs goes through GetFullPathName on Windows, and GetFullPathName is
// precisely the API that eats trailing dots and spaces -- the one thing the
// \\?\ prefix exists to defeat. Running a path through it first therefore
// throws away the characters the prefix is added to preserve, and "folder."
// reaches CreateDirectoryW as "folder". Resolving a relative path against the
// working directory by hand keeps the name intact; filepath.Clean handles the
// rest of what \\?\ requires (no "." or ".." elements, backslash separators)
// and leaves a trailing dot alone, because it only ever recognises "." and
// ".." as whole path elements.
//
// It parts company with filepath.Abs in one other respect, for inputs that
// never reach it: Windows resolves a drive-relative "C:x" against that drive's
// own working directory and a rooted "\x" against the current drive, while
// this joins both onto the process working directory. Every link target has
// been through isAbsArchiveTarget, which refuses both spellings, and every
// entry name through absPath, which refuses a rooted name and cannot produce a
// drive-relative one.
func absKeepTrailing(p string) (string, bool) {
	if filepath.IsAbs(p) {
		return filepath.Clean(p), true
	}
	wd, err := getwd()
	if err != nil {
		return "", false
	}
	return filepath.Join(wd, p), true
}
