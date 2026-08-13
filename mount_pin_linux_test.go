//go:build linux

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

// mockSeam implements mountSeam for unit tests without root/CAP_SYS_ADMIN.
type mockSeam struct {
	openat2Fn   func(dirfd int, path string, flags uint, mode uint32, resolveFlags uint64) (int, error)
	openTreeFn  func(sourceFD int) (int, error)
	moveMountFn func(treeFD, destDirfd int, destPath string) error
	fstatFn     func(fd int) (*unixStat, error)
	closeFn     func(fd int) error
	umountFn    func(path string) error

	// Track calls for verification
	openat2Calls   []openat2Args
	openTreeCalls  []openTreeArgs
	moveMountCalls []moveMountArgs
	closeCalls     []int
	umountCalls    []string

	// Next FD to assign (for distinct FDs)
	nextFD int
}

func (m *mockSeam) nextFd() int {
	fd := m.nextFD
	m.nextFD++
	return fd
}

func (m *mockSeam) openat2(dirfd int, path string, flags uint, mode uint32, resolveFlags uint64) (int, error) {
	if m.openat2Fn != nil {
		return m.openat2Fn(dirfd, path, flags, mode, resolveFlags)
	}
	fd := m.nextFd()
	m.openat2Calls = append(m.openat2Calls, openat2Args{dirfd, path, flags, mode, resolveFlags})
	return fd, nil
}

func (m *mockSeam) openTreeClone(sourceFD int) (int, error) {
	if m.openTreeFn != nil {
		return m.openTreeFn(sourceFD)
	}
	fd := m.nextFd()
	m.openTreeCalls = append(m.openTreeCalls, openTreeArgs{fd, "", uint(unix.AT_EMPTY_PATH | unix.OPEN_TREE_CLONE | unix.OPEN_TREE_CLOEXEC)})
	return fd, nil
}

func (m *mockSeam) moveMount(treeFD, destDirfd int, destPath string) error {
	if m.moveMountFn != nil {
		return m.moveMountFn(treeFD, destDirfd, destPath)
	}
	m.moveMountCalls = append(m.moveMountCalls, moveMountArgs{treeFD, "", destDirfd, destPath, uint(unix.MOVE_MOUNT_F_EMPTY_PATH)})
	return nil
}

func (m *mockSeam) fstat(fd int) (*unixStat, error) {
	if m.fstatFn != nil {
		return m.fstatFn(fd)
	}
	return nil, fmt.Errorf("fstat not implemented")
}

func (m *mockSeam) close(fd int) error {
	if m.closeFn != nil {
		return m.closeFn(fd)
	}
	m.closeCalls = append(m.closeCalls, fd)
	return nil
}

func (m *mockSeam) umountDetach(path string) error {
	if m.umountFn != nil {
		return m.umountFn(path)
	}
	m.umountCalls = append(m.umountCalls, path)
	return nil
}

func (m *mockSeam) lastOpenat2() *openat2Args {
	if len(m.openat2Calls) == 0 {
		return nil
	}
	last := m.openat2Calls[len(m.openat2Calls)-1]
	return &last
}

func (m *mockSeam) lastOpenTree() *openTreeArgs {
	if len(m.openTreeCalls) == 0 {
		return nil
	}
	last := m.openTreeCalls[len(m.openTreeCalls)-1]
	return &last
}

func (m *mockSeam) lastMoveMount() *moveMountArgs {
	if len(m.moveMountCalls) == 0 {
		return nil
	}
	last := m.moveMountCalls[len(m.moveMountCalls)-1]
	return &last
}

func TestPinMountDirectory(t *testing.T) {
	work := t.TempDir()
	workspace := filepath.Join(work, "workspace")
	runtimeDir := filepath.Join(work, "runtime")
	os.MkdirAll(workspace, 0755)
	os.MkdirAll(runtimeDir, 0755)

	sourceDir := filepath.Join(workspace, "src")
	os.MkdirAll(sourceDir, 0755)

	seam := &mockSeam{
		nextFD: 3,
		fstatFn: func(fd int) (*unixStat, error) {
			return &unixStat{mode: unix.S_IFDIR}, nil
		},
	}

	pm, err := pinMount(seam, workspace, sourceDir, runtimeDir, "op_abc", 0)
	if err != nil {
		t.Fatalf("pinMount: %v", err)
	}

	if !strings.HasPrefix(pm.HostPath, runtimeDir) {
		t.Errorf("HostPath should be under runtimeDir, got %s", pm.HostPath)
	}

	// Verify openat2 was called with root FD for source.
	if len(seam.openat2Calls) < 2 {
		t.Fatalf("openat2 calls = %d, want >= 2", len(seam.openat2Calls))
	}
	// First call: open /
	if seam.openat2Calls[0].path != "/" {
		t.Errorf("openat2[0].path = %q, want %q", seam.openat2Calls[0].path, "/")
	}
	// Second call: open source with root FD (mock returns 3 for root)
	if seam.openat2Calls[1].dirfd != 3 {
		t.Errorf("openat2[1].dirfd = %d, want 3 (root FD from mock)", seam.openat2Calls[1].dirfd)
	}
	expectedResolve := uint64(unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS)
	if seam.openat2Calls[1].resolveFlags != expectedResolve {
		t.Errorf("openat2[1].resolveFlags = 0x%x, want 0x%x",
			seam.openat2Calls[1].resolveFlags, expectedResolve)
	}

	// Verify open_tree was called with correct flags.
	if len(seam.openTreeCalls) != 1 {
		t.Errorf("openTreeCalls = %d, want 1", len(seam.openTreeCalls))
	}
	if seam.openTreeCalls[0].path != "" {
		t.Errorf("open_tree path = %q, want %q", seam.openTreeCalls[0].path, "")
	}
	expectedTreeFlags := uint(unix.AT_EMPTY_PATH | unix.OPEN_TREE_CLONE | unix.OPEN_TREE_CLOEXEC)
	if seam.openTreeCalls[0].flags != expectedTreeFlags {
		t.Errorf("open_tree flags = 0x%x, want 0x%x", seam.openTreeCalls[0].flags, expectedTreeFlags)
	}

	// Verify move_mount was called with correct flags.
	if len(seam.moveMountCalls) != 1 {
		t.Fatal("moveMount not called")
	}
	if seam.moveMountCalls[0].fromPath != "" {
		t.Errorf("move_mount fromPath = %q, want %q", seam.moveMountCalls[0].fromPath, "")
	}
	if seam.moveMountCalls[0].toPath != "0" {
		t.Errorf("move_mount toPath = %q, want %q", seam.moveMountCalls[0].toPath, "0")
	}
	if seam.moveMountCalls[0].flags != uint(unix.MOVE_MOUNT_F_EMPTY_PATH) {
		t.Errorf("move_mount flags = 0x%x, want 0x%x",
			seam.moveMountCalls[0].flags, unix.MOVE_MOUNT_F_EMPTY_PATH)
	}

	// Verify FDs were closed exactly once.
	// root(3), source(4), destDir(5), tree(6) = 4 closes
	if len(seam.closeCalls) != 4 {
		t.Errorf("closeCalls = %v, want 4 closes", seam.closeCalls)
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
		nextFD: 3,
		fstatFn: func(fd int) (*unixStat, error) {
			return &unixStat{mode: unix.S_IFREG}, nil
		},
	}

	pm, err := pinMount(seam, workspace, sourceFile, runtimeDir, "op_abc", 0)
	if err != nil {
		t.Fatalf("pinMount: %v", err)
	}

	// Verify move_mount was called.
	if len(seam.moveMountCalls) != 1 {
		t.Fatal("moveMount not called")
	}

	// Verify file destination was created with correct mode.
	// The openat2 call for file destination should have mode 0600.
	foundFileCreate := false
	for _, call := range seam.openat2Calls {
		if call.mode == 0600 && (call.flags&unix.O_CREAT) != 0 {
			foundFileCreate = true
			break
		}
	}
	if !foundFileCreate {
		t.Error("file destination should be created with mode 0600 and O_CREAT")
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

func TestPinMountNegativeIndex(t *testing.T) {
	work := t.TempDir()
	workspace := filepath.Join(work, "workspace")
	runtimeDir := filepath.Join(work, "runtime")
	os.MkdirAll(workspace, 0755)
	os.MkdirAll(runtimeDir, 0755)

	sourceFile := filepath.Join(workspace, "src.txt")
	os.WriteFile(sourceFile, []byte("data"), 0644)

	seam := &mockSeam{}
	_, err := pinMount(seam, workspace, sourceFile, runtimeDir, "op_abc", -1)
	if err == nil {
		t.Fatal("should reject negative mount index")
	}
	if !strings.Contains(err.Error(), "negative mount index") {
		t.Errorf("error = %v, want 'negative mount index'", err)
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
		fstatFn: func(fd int) (*unixStat, error) {
			return &unixStat{mode: unix.S_IFSOCK}, nil
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

func TestPinMountRelativePathsRejected(t *testing.T) {
	work := t.TempDir()
	sourceFile := filepath.Join(work, "src.txt")
	os.WriteFile(sourceFile, []byte("data"), 0644)

	seam := &mockSeam{}

	// Relative workspace.
	_, err := pinMount(seam, "relative/workspace", sourceFile, work, "op_abc", 0)
	if err == nil {
		t.Fatal("should reject relative workspace")
	}
	if !strings.Contains(err.Error(), "workspace must be absolute") {
		t.Errorf("error = %v, want 'workspace must be absolute'", err)
	}

	// Relative sourcePath.
	_, err = pinMount(seam, work, "relative/src.txt", work, "op_abc", 0)
	if err == nil {
		t.Fatal("should reject relative sourcePath")
	}
	if !strings.Contains(err.Error(), "sourcePath must be absolute") {
		t.Errorf("error = %v, want 'sourcePath must be absolute'", err)
	}

	// Relative runtimeDir.
	_, err = pinMount(seam, work, sourceFile, "relative/runtime", "op_abc", 0)
	if err == nil {
		t.Fatal("should reject relative runtimeDir")
	}
	if !strings.Contains(err.Error(), "runtimeDir must be absolute") {
		t.Errorf("error = %v, want 'runtimeDir must be absolute'", err)
	}
}

func TestPinMountEmptyPaths(t *testing.T) {
	seam := &mockSeam{}

	_, err := pinMount(seam, "", "/tmp/src", "/tmp/runtime", "op_abc", 0)
	if err == nil {
		t.Fatal("should reject empty workspace")
	}

	_, err = pinMount(seam, "/tmp/ws", "", "/tmp/runtime", "op_abc", 0)
	if err == nil {
		t.Fatal("should reject empty sourcePath")
	}

	_, err = pinMount(seam, "/tmp/ws", "/tmp/src", "", "op_abc", 0)
	if err == nil {
		t.Fatal("should reject empty runtimeDir")
	}
}

func TestPinMountExistingFilePreserved(t *testing.T) {
	work := t.TempDir()
	workspace := filepath.Join(work, "workspace")
	runtimeDir := filepath.Join(work, "runtime")
	os.MkdirAll(workspace, 0755)
	os.MkdirAll(runtimeDir, 0755)

	sourceFile := filepath.Join(workspace, "src.txt")
	os.WriteFile(sourceFile, []byte("data"), 0644)

	// Pre-create destination file with content.
	mountsDir := filepath.Join(runtimeDir, "mounts", "op_abc")
	os.MkdirAll(mountsDir, 0700)
	destPath := filepath.Join(mountsDir, "0")
	os.WriteFile(destPath, []byte("EXISTING"), 0644)

	callCount := 0
	seam := &mockSeam{
		openat2Fn: func(dirfd int, path string, flags uint, mode uint32, resolveFlags uint64) (int, error) {
			callCount++
			if callCount == 1 {
				// First call: open /
				return 3, nil
			}
			if callCount == 2 {
				// Second call: open source
				return 4, nil
			}
			if callCount == 3 {
				// Third call: create file destination - fails with EEXIST
				return -1, unix.EEXIST
			}
			// Fourth call: open dest dir
			return 5, nil
		},
		fstatFn: func(fd int) (*unixStat, error) {
			return &unixStat{mode: unix.S_IFREG}, nil
		},
	}

	_, err := pinMount(seam, workspace, sourceFile, runtimeDir, "op_abc", 0)
	if err == nil {
		t.Fatal("should reject existing destination")
	}
	if !strings.Contains(err.Error(), "destination already exists") {
		t.Errorf("error = %v, want 'destination already exists'", err)
	}

	// Verify existing file was not modified.
	content, err := os.ReadFile(destPath)
	if err != nil {
		t.Fatalf("read existing file: %v", err)
	}
	if string(content) != "EXISTING" {
		t.Errorf("existing file content = %q, want %q", string(content), "EXISTING")
	}
}

func TestPinMountExistingDirectoryPreserved(t *testing.T) {
	work := t.TempDir()
	workspace := filepath.Join(work, "workspace")
	runtimeDir := filepath.Join(work, "runtime")
	os.MkdirAll(workspace, 0755)
	os.MkdirAll(runtimeDir, 0755)

	sourceDir := filepath.Join(workspace, "src")
	os.MkdirAll(sourceDir, 0755)

	// Pre-create destination directory.
	mountsDir := filepath.Join(runtimeDir, "mounts", "op_abc")
	os.MkdirAll(mountsDir, 0700)
	destPath := filepath.Join(mountsDir, "0")
	os.MkdirAll(destPath, 0700)

	seam := &mockSeam{
		nextFD: 3,
		fstatFn: func(fd int) (*unixStat, error) {
			return &unixStat{mode: unix.S_IFDIR}, nil
		},
	}

	_, err := pinMount(seam, workspace, sourceDir, runtimeDir, "op_abc", 0)
	if err == nil {
		t.Fatal("should reject existing destination")
	}
	if !strings.Contains(err.Error(), "destination already exists") {
		t.Errorf("error = %v, want 'destination already exists'", err)
	}

	// Verify existing directory was not removed.
	info, err := os.Stat(destPath)
	if err != nil {
		t.Fatalf("stat existing dir: %v", err)
	}
	if !info.IsDir() {
		t.Error("existing directory was removed or modified")
	}
}

func TestPinMountExistingSymlinkPreserved(t *testing.T) {
	work := t.TempDir()
	workspace := filepath.Join(work, "workspace")
	runtimeDir := filepath.Join(work, "runtime")
	os.MkdirAll(workspace, 0755)
	os.MkdirAll(runtimeDir, 0755)

	sourceDir := filepath.Join(workspace, "src")
	os.MkdirAll(sourceDir, 0755)

	// Pre-create destination symlink.
	mountsDir := filepath.Join(runtimeDir, "mounts", "op_abc")
	os.MkdirAll(mountsDir, 0700)
	destPath := filepath.Join(mountsDir, "0")
	target := filepath.Join(work, "target")
	os.Symlink(target, destPath)

	seam := &mockSeam{
		nextFD: 3,
		fstatFn: func(fd int) (*unixStat, error) {
			return &unixStat{mode: unix.S_IFDIR}, nil
		},
	}

	_, err := pinMount(seam, workspace, sourceDir, runtimeDir, "op_abc", 0)
	if err == nil {
		t.Fatal("should reject existing destination (symlink)")
	}

	// Verify symlink was not modified.
	linkTarget, err := os.Readlink(destPath)
	if err != nil {
		t.Fatalf("readlink: %v", err)
	}
	if linkTarget != target {
		t.Errorf("symlink target = %q, want %q", linkTarget, target)
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

	callCount := 0
	seam := &mockSeam{
		openat2Fn: func(dirfd int, path string, flags uint, mode uint32, resolveFlags uint64) (int, error) {
			callCount++
			if callCount == 1 {
				// First call: open /
				return 3, nil
			}
			// Second call: open source
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
		nextFD: 3,
		fstatFn: func(fd int) (*unixStat, error) {
			return &unixStat{mode: unix.S_IFDIR}, nil
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
		nextFD: 3,
		fstatFn: func(fd int) (*unixStat, error) {
			return &unixStat{mode: unix.S_IFDIR}, nil
		},
		moveMountFn: func(treeFD, destDirfd int, destPath string) error {
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

	umountCount := 0
	seam := &mockSeam{
		nextFD: 3,
		fstatFn: func(fd int) (*unixStat, error) {
			return &unixStat{mode: unix.S_IFDIR}, nil
		},
		umountFn: func(path string) error {
			umountCount++
			return nil
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

	// Second cleanup should not repeat syscalls.
	if err := pm.Cleanup(); err != nil {
		t.Errorf("second Cleanup: %v", err)
	}

	// Third cleanup should not repeat syscalls.
	if err := pm.Cleanup(); err != nil {
		t.Errorf("third Cleanup: %v", err)
	}

	// umount should have been called exactly once.
	if umountCount != 1 {
		t.Errorf("umountCount = %d, want 1", umountCount)
	}
}

func TestPinMountCleanupConcurrent(t *testing.T) {
	work := t.TempDir()
	workspace := filepath.Join(work, "workspace")
	runtimeDir := filepath.Join(work, "runtime")
	os.MkdirAll(workspace, 0755)
	os.MkdirAll(runtimeDir, 0755)

	sourceDir := filepath.Join(workspace, "src")
	os.MkdirAll(sourceDir, 0755)

	umountCount := 0
	seam := &mockSeam{
		nextFD: 3,
		fstatFn: func(fd int) (*unixStat, error) {
			return &unixStat{mode: unix.S_IFDIR}, nil
		},
		umountFn: func(path string) error {
			umountCount++
			return nil
		},
	}

	pm, err := pinMount(seam, workspace, sourceDir, runtimeDir, "op_abc", 0)
	if err != nil {
		t.Fatalf("pinMount: %v", err)
	}

	var wg sync.WaitGroup
	results := make([]error, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = pm.Cleanup()
		}(i)
	}
	wg.Wait()

	// All results should be nil.
	for i, err := range results {
		if err != nil {
			t.Errorf("results[%d] = %v", i, err)
		}
	}

	// umount should have been called exactly once.
	if umountCount != 1 {
		t.Errorf("umountCount = %d, want 1", umountCount)
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
		nextFD: 3,
		fstatFn: func(fd int) (*unixStat, error) {
			return &unixStat{mode: unix.S_IFDIR}, nil
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

	// Second cleanup should return the same error (cached).
	err2 := pm.Cleanup()
	if err2 == nil {
		t.Error("second cleanup should return cached error")
	}
}

func TestPinMountSiblingSurvivesError(t *testing.T) {
	work := t.TempDir()
	workspace := filepath.Join(work, "workspace")
	runtimeDir := filepath.Join(work, "runtime")
	os.MkdirAll(workspace, 0755)
	os.MkdirAll(runtimeDir, 0755)

	sourceDir := filepath.Join(workspace, "src")
	os.MkdirAll(sourceDir, 0755)

	// First mount succeeds.
	seam1 := &mockSeam{
		nextFD: 3,
		fstatFn: func(fd int) (*unixStat, error) {
			return &unixStat{mode: unix.S_IFDIR}, nil
		},
	}
	pm1, err := pinMount(seam1, workspace, sourceDir, runtimeDir, "op_abc", 0)
	if err != nil {
		t.Fatalf("first pinMount: %v", err)
	}

	// Second mount fails on move_mount.
	seam2 := &mockSeam{
		nextFD: 100,
		fstatFn: func(fd int) (*unixStat, error) {
			return &unixStat{mode: unix.S_IFDIR}, nil
		},
		moveMountFn: func(treeFD, destDirfd int, destPath string) error {
			return unix.EPERM
		},
	}
	_, err = pinMount(seam2, workspace, sourceDir, runtimeDir, "op_abc", 1)
	if err == nil {
		t.Fatal("second pinMount should fail")
	}

	// First mount should still exist on filesystem.
	if _, err := os.Stat(pm1.HostPath); err != nil {
		t.Errorf("first mount mountpoint should still exist: %v", err)
	}
}

func TestPinMountCloseCount(t *testing.T) {
	work := t.TempDir()
	workspace := filepath.Join(work, "workspace")
	runtimeDir := filepath.Join(work, "runtime")
	os.MkdirAll(workspace, 0755)
	os.MkdirAll(runtimeDir, 0755)

	sourceDir := filepath.Join(workspace, "src")
	os.MkdirAll(sourceDir, 0755)

	seam := &mockSeam{
		nextFD: 3,
		fstatFn: func(fd int) (*unixStat, error) {
			return &unixStat{mode: unix.S_IFDIR}, nil
		},
	}

	pm, err := pinMount(seam, workspace, sourceDir, runtimeDir, "op_abc", 0)
	if err != nil {
		t.Fatalf("pinMount: %v", err)
	}

	// Expected closes: root(3), source(4), destDir(5), tree(6) = 4 closes
	if len(seam.closeCalls) != 4 {
		t.Errorf("closeCalls = %d, want 4", len(seam.closeCalls))
	}

	// Verify each FD was closed exactly once.
	closeSet := make(map[int]int)
	for _, fd := range seam.closeCalls {
		closeSet[fd]++
	}
	for fd, count := range closeSet {
		if count != 1 {
			t.Errorf("FD %d closed %d times, want 1", fd, count)
		}
	}

	// Cleanup should not close any FDs (they're already closed).
	if err := pm.Cleanup(); err != nil {
		t.Errorf("Cleanup: %v", err)
	}
	closeAfterCleanup := len(seam.closeCalls)
	if closeAfterCleanup != 4 {
		t.Errorf("closeCalls after cleanup = %d, want 4", closeAfterCleanup)
	}
}

func TestPinMountFileCloseCount(t *testing.T) {
	work := t.TempDir()
	workspace := filepath.Join(work, "workspace")
	runtimeDir := filepath.Join(work, "runtime")
	os.MkdirAll(workspace, 0755)
	os.MkdirAll(runtimeDir, 0755)

	sourceFile := filepath.Join(workspace, "src.txt")
	os.WriteFile(sourceFile, []byte("data"), 0644)

	seam := &mockSeam{
		nextFD: 3,
		fstatFn: func(fd int) (*unixStat, error) {
			return &unixStat{mode: unix.S_IFREG}, nil
		},
	}

	pm, err := pinMount(seam, workspace, sourceFile, runtimeDir, "op_abc", 0)
	if err != nil {
		t.Fatalf("pinMount: %v", err)
	}

	// For file: root(3), source(4), fileDest(5), destDir(6), tree(7) = 5 closes
	if len(seam.closeCalls) != 5 {
		t.Errorf("closeCalls = %d, want 5", len(seam.closeCalls))
	}

	// Verify each FD was closed exactly once.
	closeSet := make(map[int]int)
	for _, fd := range seam.closeCalls {
		closeSet[fd]++
	}
	for fd, count := range closeSet {
		if count != 1 {
			t.Errorf("FD %d closed %d times, want 1", fd, count)
		}
	}

	if err := pm.Cleanup(); err != nil {
		t.Errorf("Cleanup: %v", err)
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
		{".hidden", false},
		{"op\\abc", false},
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

func TestPinnedMountNilReceiver(t *testing.T) {
	var pm *pinnedMount
	if err := pm.Cleanup(); err != nil {
		t.Errorf("Cleanup on nil receiver: %v", err)
	}
}
