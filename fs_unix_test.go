//go:build !windows

package zip

import (
	"errors"
	"os"
	"syscall"
	"testing"
)

// TestRemoveHeldElsewhere covers the answer off Windows, which is the same for
// every error: unlink takes the name away whoever else is reading the file, so
// a failed removal is never something waiting will fix.
func TestRemoveHeldElsewhere(t *testing.T) {
	for _, err := range []error{
		nil,
		errors.New("something else"),
		&os.PathError{Op: "remove", Path: "x", Err: syscall.EACCES},
		&os.PathError{Op: "remove", Path: "x", Err: syscall.ENOENT},
	} {
		if removeHeldElsewhere(err) {
			t.Errorf("removeHeldElsewhere(%v) = true, want false", err)
		}
	}
}
