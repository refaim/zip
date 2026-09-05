package zip

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestTrailingDotsSupport(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Trailing dots issue is primarily a Windows API quirk")
	}

	tempDir := t.TempDir()

	dotDirPath := filepath.Join(tempDir, "folder.")
	err := os.Mkdir(fixOSPath(dotDirPath), 0755)
	if err != nil {
		t.Fatalf("Failed to MkDir with trailing dot: %v", err)
	}

	entries, err := os.ReadDir(tempDir)
	if err != nil {
		t.Fatalf("Failed to read temp dir: %v", err)
	}
	foundDir := false
	for _, e := range entries {
		if e.Name() == "folder." {
			foundDir = true
			break
		}
	}
	if !foundDir {
		t.Fatalf("Could not find 'folder.' in directory listing")
	}

	dotFilePath := filepath.Join(dotDirPath, "file.")
	f, err := os.Create(fixOSPath(dotFilePath))
	if err != nil {
		t.Fatalf("Failed to Create file with trailing dot: %v", err)
	}
	closeAt(t, f)
	mustWrite(t, f, []byte("test"))
	if err := f.Close(); err != nil {
		t.Fatalf("Failed to close file with trailing dot: %v", err)
	}

	_, err = os.Stat(fixOSPath(dotFilePath))
	if err != nil {
		t.Fatalf("Failed to Stat file with trailing dot: %v", err)
	}
}

// TestTrailingSpaceSupport is the other half of what the \\?\ prefix buys:
// GetFullPathName eats trailing spaces exactly like it eats trailing dots.
func TestTrailingSpaceSupport(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Trailing spaces are stripped by the Win32 path parser only")
	}

	tempDir := t.TempDir()

	spaceFilePath := filepath.Join(tempDir, "name ")
	f, err := os.Create(fixOSPath(spaceFilePath))
	if err != nil {
		t.Fatalf("Failed to Create file with trailing space: %v", err)
	}
	closeAt(t, f)
	if err := f.Close(); err != nil {
		t.Fatalf("Failed to close file with trailing space: %v", err)
	}

	entries, err := os.ReadDir(tempDir)
	if err != nil {
		t.Fatalf("Failed to read temp dir: %v", err)
	}
	found := false
	for _, e := range entries {
		if e.Name() == "name " {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("Could not find 'name ' in directory listing")
	}
}

func TestFixOSPath(t *testing.T) {
	if runtime.GOOS != "windows" {
		// The Unix build is the identity, and the table below is written in
		// Win32 spelling, so there is nothing to assert but the identity.
		for _, p := range []string{"", "relative/name.", "/absolute/name."} {
			if got := fixOSPath(p); got != p {
				t.Errorf("fixOSPath(%q) = %q, want it unchanged off Windows", p, got)
			}
		}
		return
	}

	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"absolute keeps the trailing dot", `C:\tmp\folder.`, `\\?\C:\tmp\folder.`},
		{"absolute keeps the trailing space", `C:\tmp\folder `, `\\?\C:\tmp\folder `},
		{"absolute is still cleaned", `C:\tmp\a\..\folder.`, `\\?\C:\tmp\folder.`},
		{"forward slashes are normalised", `C:/tmp/folder.`, `\\?\C:\tmp\folder.`},
		{"already prefixed is left alone", `\\?\C:\tmp\folder.`, `\\?\C:\tmp\folder.`},
		{"unc gets the unc spelling", `\\server\share\folder.`, `\\?\UNC\server\share\folder.`},
		{"relative resolves against the working directory", `folder.`, `\\?\` + filepath.Join(wd, "folder.")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := fixOSPath(tt.in); got != tt.want {
				t.Errorf("fixOSPath(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestAbsKeepTrailing covers absKeepTrailing directly rather than through
// fixOSPath, which returns early off Windows and would leave the helper
// unexercised there. Both of its branches are platform-independent.
func TestAbsKeepTrailing(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	sep := string(filepath.Separator)

	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			// Clean removes the ".." element and leaves the trailing dot,
			// which it never treats as an element of its own.
			name: "an absolute path is cleaned and keeps its trailing dot",
			in:   wd + sep + "a" + sep + ".." + sep + "folder.",
			want: filepath.Join(wd, "folder."),
		},
		{
			name: "a relative path resolves against the working directory",
			in:   "folder.",
			want: filepath.Join(wd, "folder."),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := absKeepTrailing(tt.in)
			if !ok {
				t.Fatalf("absKeepTrailing(%q) gave no answer", tt.in)
			}
			if got != tt.want {
				t.Errorf("absKeepTrailing(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestAbsKeepTrailing_NoWorkingDirectory covers the one way absKeepTrailing
// has no answer, and what fixOSPath does with it.
//
// The working directory can be unlinked out from under a process, and then
// there is no absolute spelling of a relative path to be had. Prefixing what
// is still a relative path with \\?\ produces something the kernel refuses
// outright -- the prefix turns off the parsing that would have resolved it --
// so fixOSPath hands back the plain Win32 spelling instead, which still names
// the same file. os.Getwd cannot be made to fail portably, so the seam is
// taken over here.
func TestAbsKeepTrailing_NoWorkingDirectory(t *testing.T) {
	orig := getwd
	abs, err := orig()
	if err != nil {
		t.Fatal(err)
	}
	abs = filepath.Join(abs, "folder.")
	t.Cleanup(func() { getwd = orig })
	getwd = func() (string, error) { return "", errors.New("working directory is gone") }

	if got, ok := absKeepTrailing("folder."); ok {
		t.Errorf("absKeepTrailing = (%q, true), want no answer", got)
	}
	// An absolute path never asks for the working directory, so it is still
	// answered.
	if got, ok := absKeepTrailing(abs); !ok || got != filepath.Clean(abs) {
		t.Errorf("absKeepTrailing(%q) = (%q, %v), want (%q, true)", abs, got, ok, filepath.Clean(abs))
	}

	if got := fixOSPath("folder."); got != "folder." {
		t.Errorf("fixOSPath(%q) = %q, want it unchanged when there is no working directory", "folder.", got)
	}
}
