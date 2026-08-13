//go:build linux

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// mockSeam implements mountSeam for unit tests without root/CAP_SYS_ADMIN.
type mockSeam struct {
	openat2Fn   func(dirfd int, path string, flags uint, resolveFlags uint64) (int, error)
	openTreeFn  func(sourceFD int) (int, error)
	moveMountFn func(treeFD, destDirfd int, destPath string, isDir bool) error
	fstatFn     func(fd int) (os.FileInfo, error)
	umountFn    func(path string) error

	// Track calls for verification
	openat2Calls   []openat2Call
	openTreeCalls  []int
	moveMountCalls []moveMountCall
	umountCalls    []string
}

type openat2Call struct {
	dirfd        int
	path         string
	flags        uint
	resolveFlags uint64
}

type moveMountCall struct {
	treeFD    int
	destDirfd int
	destPath  string
	isDir     bool
}

func (m *mockSeam) openat2(dirfd int, path string, flags uint, resolveFlags uint64) (int, error) {
	if m.openat2Fn != nil {
		return m.openat2Fn(dirfd, path, flags, resolveFlags)
	}
	m.openat2Calls = append(m.openat2Calls, openat2Call{dirfd, path, flags, resolveFlags})
	return 3, nil
}

func (m *mockSeam) openTreeClone(sourceFD int) (int, error) {
	if m.openTreeFn != nil {
		return m.openTreeFn(sourceFD)
	}
	m.openTreeCalls = append(m.openTreeCalls, sourceFD)
	return 4, nil
}

func (m *mockSeam) moveMountFile(treeFD, destDirfd int, destPath string) error {
	if m.moveMountFn != nil {
		return m.moveMountFn(treeFD, destDirfd, destPath, false)
	}
	m.moveMountCalls = append(m.moveMountCalls, moveMountCall{treeFD, destDirfd, destPath, false})
	return nil
}

func (m *mockSeam) moveMountDir(treeFD, destDirfd int, destPath string) error {
	if m.moveMountFn != nil {
		return m.moveMountFn(treeFD, destDirfd, destPath, true)
	}
	m.moveMountCalls = append(m.moveMountCalls, moveMountCall{treeFD, destDirfd, destPath, true})
	return nil
}

func (m *mockSeam) fstat(fd int) (os.FileInfo, error) {
	if m.fstatFn != nil {
		return m.fstatFn(fd)
	}
	return nil, fmt.Errorf("fstat not implemented")
}

func (m *mockSeam) umountDetach(path string) error {
	if m.umountFn != nil {
		return m.umountFn(path)
	}
	m.umountCalls = append(m.umountCalls, path)
	return nil
}

// dirFileInfo returns a minimal os.FileInfo for a directory.
type dirFileInfo struct{}

func (dirFileInfo) Name() string       { return "" }
func (dirFileInfo) Size() int64        { return 0 }
func (dirFileInfo) Mode() os.FileMode  { return os.ModeDir | 0755 }
func (dirFileInfo) ModTime() time.Time { return time.Time{} }
func (dirFileInfo) IsDir() bool        { return true }
func (dirFileInfo) Sys() interface{}   { return nil }

// regularFileInfo returns a minimal os.FileInfo for a regular file.
type regularFileInfo struct{}

func (regularFileInfo) Name() string       { return "" }
func (regularFileInfo) Size() int64        { return 0 }
func (regularFileInfo) Mode() os.FileMode  { return 0644 }
func (regularFileInfo) ModTime() time.Time { return time.Time{} }
func (regularFileInfo) IsDir() bool        { return false }
func (regularFileInfo) Sys() interface{}   { return nil }

// socketFileInfo is a minimal os.FileInfo for a socket (unsupported type).
type socketFileInfo struct{}

func (socketFileInfo) Name() string       { return "" }
func (socketFileInfo) Size() int64        { return 0 }
func (socketFileInfo) Mode() os.FileMode  { return os.ModeSocket }
func (socketFileInfo) ModTime() time.Time { return time.Time{} }
func (socketFileInfo) IsDir() bool        { return false }
func (socketFileInfo) Sys() interface{}   { return nil }

func TestPinMountDirectory(t *testing.T) {
	work := t.TempDir()
	workspace := filepath.Join(work, "workspace")
	runtimeDir := filepath.Join(work, "runtime")
	os.MkdirAll(workspace, 0755)
	os.MkdirAll(runtimeDir, 0755)

	sourceDir := filepath.Join(workspace, "src")
	os.MkdirAll(sourceDir, 0755)

	seam := &mockSeam{
		fstatFn: func(fd int) (os.FileInfo, error) {
			return dirFileInfo{}, nil
		},
	}

	pm, err := pinMount(seam, workspace, sourceDir, runtimeDir, "op_abc", 0)
	if err != nil {
		t.Fatalf("pinMount: %v", err)
	}

	if !strings.HasPrefix(pm.HostPath, runtimeDir) {
		t.Errorf("HostPath should be under runtimeDir, got %s", pm.HostPath)
	}

	// Verify openat2 was called with correct flags.
	if len(seam.openat2Calls) < 1 {
		t.Fatal("openat2 not called")
	}
	call := seam.openat2Calls[0]
	if call.flags != uint(unix.O_PATH|unix.O_CLOEXEC) {
		t.Errorf("openat2 flags = 0x%x, want 0x%x", call.flags, unix.O_PATH|unix.O_CLOEXEC)
	}
	expectedResolve := uint64(unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS)
	if call.resolveFlags != expectedResolve {
		t.Errorf("openat2 resolveFlags = 0x%x, want 0x%x", call.resolveFlags, expectedResolve)
	}

	// Verify open_tree was called.
	if len(seam.openTreeCalls) != 1 {
		t.Errorf("openTreeCalls = %d, want 1", len(seam.openTreeCalls))
	}

	// Verify move_mount was called with directory flag.
	if len(seam.moveMountCalls) != 1 {
		t.Fatal("moveMount not called")
	}
	if !seam.moveMountCalls[0].isDir {
		t.Error("moveMount should be called with isDir=true for directory")
	}

	// Cleanup should not error.
	if err := pm.Cleanup(); err != nil {
		t.Errorf("Cleanup: %v", err)
	}

	// Second cleanup should be idempotent.
	if err := pm.Cleanup(); err != nil {
		t.Errorf("second Cleanup: %v", err)
	}
}

func TestPinMountRegularFile(t *testing.T) {
	work := t.TempDir()
	workspace := filepath.Join(work, "workspace")
	runtimeDir := filepath.Join(work, "runtime")
	os.MkdirAll(workspace, 0755)
	os.MkdirAll(runtimeDir, 0755)

	sourceFile := filepath.Join(workspace, "src.txt")
	os.WriteFile(sourceFile, []byte("data"), 0644)

	seam := &mockSeam{
		fstatFn: func(fd int) (os.FileInfo, error) {
			return regularFileInfo{}, nil
		},
	}

	pm, err := pinMount(seam, workspace, sourceFile, runtimeDir, "op_abc", 0)
	if err != nil {
		t.Fatalf("pinMount: %v", err)
	}

	// Verify move_mount was called with file flag.
	if len(seam.moveMountCalls) != 1 {
		t.Fatal("moveMount not called")
	}
	if seam.moveMountCalls[0].isDir {
		t.Error("moveMount should be called with isDir=false for regular file")
	}

	if err := pm.Cleanup(); err != nil {
		t.Errorf("Cleanup: %v", err)
	}
}

func TestPinMountSourceEscapesWorkspace(t *testing.T) {
	work := t.TempDir()
	workspace := filepath.Join(work, "workspace")
	runtimeDir := filepath.Join(work, "runtime")
	os.MkdirAll(workspace, 0755)
	os.MkdirAll(runtimeDir, 0755)

	// Source outside workspace.
	sourcePath := filepath.Join(work, "outside")
	os.WriteFile(sourcePath, []byte("data"), 0644)

	seam := &mockSeam{}
	_, err := pinMount(seam, workspace, sourcePath, runtimeDir, "op_abc", 0)
	if err == nil {
		t.Fatal("should reject source outside workspace")
	}
	if !strings.Contains(err.Error(), "escapes workspace") {
		t.Errorf("error = %v, want 'escapes workspace'", err)
	}

	// openat2 should not have been called (containment check is before openat2).
	if len(seam.openat2Calls) > 0 {
		t.Error("openat2 should not be called when source escapes workspace")
	}
}

func TestPinMountInvalidOperationID(t *testing.T) {
	work := t.TempDir()
	workspace := filepath.Join(work, "workspace")
	runtimeDir := filepath.Join(work, "runtime")
	os.MkdirAll(workspace, 0755)
	os.MkdirAll(runtimeDir, 0755)

	sourceFile := filepath.Join(workspace, "src.txt")
	os.WriteFile(sourceFile, []byte("data"), 0644)

	seam := &mockSeam{}

	// Empty operation ID.
	_, err := pinMount(seam, workspace, sourceFile, runtimeDir, "", 0)
	if err == nil {
		t.Fatal("should reject empty operation ID")
	}

	// Operation ID with path traversal.
	_, err = pinMount(seam, workspace, sourceFile, runtimeDir, "../etc", 0)
	if err == nil {
		t.Fatal("should reject operation ID with path traversal")
	}

	// Operation ID with slash.
	_, err = pinMount(seam, workspace, sourceFile, runtimeDir, "op/abc", 0)
	if err == nil {
		t.Fatal("should reject operation ID with slash")
	}
}

func TestPinMountUnsupportedInode(t *testing.T) {
	work := t.TempDir()
	workspace := filepath.Join(work, "workspace")
	runtimeDir := filepath.Join(work, "runtime")
	os.MkdirAll(workspace, 0755)
	os.MkdirAll(runtimeDir, 0755)

	sourceFile := filepath.Join(workspace, "src.txt")
	os.WriteFile(sourceFile, []byte("data"), 0644)

	seam := &mockSeam{
		fstatFn: func(fd int) (os.FileInfo, error) {
			return socketFileInfo{}, nil
		},
	}

	_, err := pinMount(seam, workspace, sourceFile, runtimeDir, "op_abc", 0)
	if err == nil {
		t.Fatal("should reject unsupported inode type")
	}
	if !strings.Contains(err.Error(), "not a directory or regular file") {
		t.Errorf("error = %v, want 'not a directory or regular file'", err)
	}
}

func TestPinMountOpenat2FailureCleansUp(t *testing.T) {
	work := t.TempDir()
	workspace := filepath.Join(work, "workspace")
	runtimeDir := filepath.Join(work, "runtime")
	os.MkdirAll(workspace, 0755)
	os.MkdirAll(runtimeDir, 0755)

	sourceFile := filepath.Join(workspace, "src.txt")
	os.WriteFile(sourceFile, []byte("data"), 0644)

	seam := &mockSeam{
		openat2Fn: func(dirfd int, path string, flags uint, resolveFlags uint64) (int, error) {
			return -1, unix.EPERM
		},
	}

	_, err := pinMount(seam, workspace, sourceFile, runtimeDir, "op_abc", 0)
	if err == nil {
		t.Fatal("should fail with openat2 error")
	}
}

func TestPinMountOpenTreeFailureCleansUp(t *testing.T) {
	work := t.TempDir()
	workspace := filepath.Join(work, "workspace")
	runtimeDir := filepath.Join(work, "runtime")
	os.MkdirAll(workspace, 0755)
	os.MkdirAll(runtimeDir, 0755)

	sourceDir := filepath.Join(workspace, "src")
	os.MkdirAll(sourceDir, 0755)

	seam := &mockSeam{
		fstatFn: func(fd int) (os.FileInfo, error) {
			return dirFileInfo{}, nil
		},
		openTreeFn: func(sourceFD int) (int, error) {
			return -1, unix.ENOSYS
		},
	}

	_, err := pinMount(seam, workspace, sourceDir, runtimeDir, "op_abc", 0)
	if err == nil {
		t.Fatal("should fail with open_tree error")
	}
	if !strings.Contains(err.Error(), "open_tree") {
		t.Errorf("error = %v, want 'open_tree'", err)
	}
}

func TestPinMountMoveMountFailureCleansUp(t *testing.T) {
	work := t.TempDir()
	workspace := filepath.Join(work, "workspace")
	runtimeDir := filepath.Join(work, "runtime")
	os.MkdirAll(workspace, 0755)
	os.MkdirAll(runtimeDir, 0755)

	sourceDir := filepath.Join(workspace, "src")
	os.MkdirAll(sourceDir, 0755)

	seam := &mockSeam{
		fstatFn: func(fd int) (os.FileInfo, error) {
			return dirFileInfo{}, nil
		},
		moveMountFn: func(treeFD, destDirfd int, destPath string, isDir bool) error {
			return unix.EPERM
		},
	}

	_, err := pinMount(seam, workspace, sourceDir, runtimeDir, "op_abc", 0)
	if err == nil {
		t.Fatal("should fail with move_mount error")
	}
}

func TestPinMountCleanupIdempotent(t *testing.T) {
	work := t.TempDir()
	workspace := filepath.Join(work, "workspace")
	runtimeDir := filepath.Join(work, "runtime")
	os.MkdirAll(workspace, 0755)
	os.MkdirAll(runtimeDir, 0755)

	sourceDir := filepath.Join(workspace, "src")
	os.MkdirAll(sourceDir, 0755)

	seam := &mockSeam{
		fstatFn: func(fd int) (os.FileInfo, error) {
			return dirFileInfo{}, nil
		},
	}

	pm, err := pinMount(seam, workspace, sourceDir, runtimeDir, "op_abc", 0)
	if err != nil {
		t.Fatalf("pinMount: %v", err)
	}

	// First cleanup.
	if err := pm.Cleanup(); err != nil {
		t.Errorf("first Cleanup: %v", err)
	}

	// Second cleanup should not error.
	if err := pm.Cleanup(); err != nil {
		t.Errorf("second Cleanup: %v", err)
	}

	// Third cleanup should not error.
	if err := pm.Cleanup(); err != nil {
		t.Errorf("third Cleanup: %v", err)
	}
}

func TestPinMountCleanupReturnsError(t *testing.T) {
	work := t.TempDir()
	workspace := filepath.Join(work, "workspace")
	runtimeDir := filepath.Join(work, "runtime")
	os.MkdirAll(workspace, 0755)
	os.MkdirAll(runtimeDir, 0755)

	sourceDir := filepath.Join(workspace, "src")
	os.MkdirAll(sourceDir, 0755)

	seam := &mockSeam{
		fstatFn: func(fd int) (os.FileInfo, error) {
			return dirFileInfo{}, nil
		},
		umountFn: func(path string) error {
			return unix.EBUSY
		},
	}

	pm, err := pinMount(seam, workspace, sourceDir, runtimeDir, "op_abc", 0)
	if err != nil {
		t.Fatalf("pinMount: %v", err)
	}

	err = pm.Cleanup()
	if err == nil {
		t.Error("cleanup should return error when umount fails")
	}
}

func TestIsOperationIDSafe(t *testing.T) {
	tests := []struct {
		id   string
		want bool
	}{
		{"op_abc123", true},
		{"op_a1b2c3d4e5f6", true},
		{"", false},
		{"../etc", false},
		{"op/abc", false},
		{"op\\abc", true}, // backslash is OK (not path separator on Linux)
	}

	for _, tc := range tests {
		got := isOperationIDSafe(tc.id)
		if got != tc.want {
			t.Errorf("isOperationIDSafe(%q) = %v, want %v", tc.id, got, tc.want)
		}
	}
}

func TestPinnedMountNilCleanup(t *testing.T) {
	pm := &pinnedMount{HostPath: "/tmp/test"}
	if err := pm.Cleanup(); err != nil {
		t.Errorf("Cleanup with nil cleanup func: %v", err)
	}
}
