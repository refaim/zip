//go:build !windows
// +build !windows

package zip

import (
	"os"
	"os/user"
	"strconv"
	"sync"
	"syscall"
)

type hardlinkKey struct {
	dev uint64
	ino uint64
}

func getHardLinkTarget(fi os.FileInfo, seen map[hardlinkKey]string) string {
	sys, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || sys.Nlink <= 1 {
		return ""
	}
	// #nosec G115 -- the pair is only a map key: dev is put in the same way at every call site and the result is never read as a number, only compared with another key built here, so what the bits mean is immaterial
	key := hardlinkKey{dev: uint64(sys.Dev), ino: uint64(sys.Ino)}
	if target, exists := seen[key]; exists {
		return target
	}
	return ""
}

func rememberHardLink(fi os.FileInfo, relPath string, seen map[hardlinkKey]string) {
	sys, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || sys.Nlink <= 1 {
		return
	}
	// #nosec G115 -- the pair is only a map key: dev is put in the same way at every call site and the result is never read as a number, only compared with another key built here, so what the bits mean is immaterial
	key := hardlinkKey{dev: uint64(sys.Dev), ino: uint64(sys.Ino)}
	if _, exists := seen[key]; !exists {
		seen[key] = relPath
	}
}

func resolveIds(hdr *FileHeader, numericOwner bool) (int, int) {
	uid, gid := hdr.Uid, hdr.Gid
	if !numericOwner {
		if hdr.Uname != "" {
			if u, err := lookupUser(hdr.Uname); err == nil {
				uid = u
			}
		}
		if hdr.Gname != "" {
			if g, err := lookupGroup(hdr.Gname); err == nil {
				gid = g
			}
		}
	}
	return uid, gid
}

var (
	uidCache   = make(map[string]int)
	gidCache   = make(map[string]int)
	resolveMut sync.RWMutex
)

// lookupUserByName and lookupGroupByName are the account database behind names
// a test can take over. Everything it answers with is text, the id included,
// and an id that is not a number is a database these lookups have no number to
// hand back from.
var (
	lookupUserByName  = user.Lookup
	lookupGroupByName = user.LookupGroup
)

func lookupUser(name string) (int, error) {
	resolveMut.RLock()
	id, ok := uidCache[name]
	resolveMut.RUnlock()
	if ok {
		return id, nil
	}

	u, err := lookupUserByName(name)
	if err != nil {
		return -1, err
	}
	id, err = strconv.Atoi(u.Uid)
	if err != nil {
		return -1, err
	}

	resolveMut.Lock()
	uidCache[name] = id
	resolveMut.Unlock()
	return id, nil
}

func lookupGroup(name string) (int, error) {
	resolveMut.RLock()
	id, ok := gidCache[name]
	resolveMut.RUnlock()
	if ok {
		return id, nil
	}

	g, err := lookupGroupByName(name)
	if err != nil {
		return -1, err
	}
	id, err = strconv.Atoi(g.Gid)
	if err != nil {
		return -1, err
	}

	resolveMut.Lock()
	gidCache[name] = id
	resolveMut.Unlock()
	return id, nil
}
func createWindowsSymlink(target, resolved, link string, isDir bool, eb *entryBudget) error {
	return nil // No-op on Unix, never called due to runtime.GOOS check
}
