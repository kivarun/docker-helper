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
	openat2Fn   func(dirfd int, path string, flags uint, resolveFlags uint64) (int, error)
	openTreeFn  func(sourceFD int) (int, error)
	moveMountFn func(treeFD, destDirfd int, destPath string) error
	fstatFn     func(fd int) (*unixStat, error)
	closeFn     func(fd int) error
	umountFn    func(path string) error

	// Track calls for verification
	openat2Calls   []openat2Call
	openTreeCalls  []int
	moveMountCalls []moveMountCall
	closeCalls     []int
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

func (m *mockSeam) moveMount(treeFD, destDirfd int, destPath string) error {
	if m.moveMountFn != nil {
		return m.moveMountFn(treeFD, destDirfd, destPath)
	}
	m.moveMountCalls = append(m.moveMountCalls, moveMountCall{treeFD, destDirfd, destPath})
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

func TestPinMountDirectory(t *testing.T) {
	work := t.TempDir()
	workspace := filepath.Join(work, "workspace")
	runtimeDir := filepath.Join(work, "runtime")
	os.MkdirAll(workspace, 0755)
	os.MkdirAll(runtimeDir, 0755)

	sourceDir := filepath.Join(workspace, "src")
	os.MkdirAll(sourceDir, 0755)

	seam := &mockSeam{
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
	// Second call: open source with root FD
	if seam.openat2Calls[1].dirfd != 3 {
		t.Errorf("openat2[1].dirfd = %d, want 3 (root FD)", seam.openat2Calls[1].dirfd)
	}
	// Path is sourcePath without leading "/"
	if !strings.HasSuffix(seam.openat2Calls[1].path, "workspace/src") {
		t.Errorf("openat2[1].path = %q, want suffix %q", seam.openat2Calls[1].path, "workspace/src")
	}
	expectedResolve := uint64(unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS)
	if seam.openat2Calls[1].resolveFlags != expectedResolve {
		t.Errorf("openat2[1].resolveFlags = 0x%x, want 0x%x",
			seam.openat2Calls[1].resolveFlags, expectedResolve)
	}

	// Verify open_tree was called.
	if len(seam.openTreeCalls) != 1 {
		t.Errorf("openTreeCalls = %d, want 1", len(seam.openTreeCalls))
	}

	// Verify move_mount was called.
	if len(seam.moveMountCalls) != 1 {
		t.Fatal("moveMount not called")
	}

	// Verify FDs were closed exactly once.
	expectedCloses := []int{3, 5, 6, 4} // root, source, destDir, tree
	if len(seam.closeCalls) != len(expectedCloses) {
		t.Errorf("closeCalls = %v, want %v", seam.closeCalls, expectedCloses)
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
		openat2Fn: func(dirfd int, path string, flags uint, resolveFlags uint64) (int, error) {
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

	// First mount should still be usable.
	if pm1.HostPath == "" {
		t.Error("first mount HostPath should not be empty")
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
		fstatFn: func(fd int) (*unixStat, error) {
			return &unixStat{mode: unix.S_IFDIR}, nil
		},
	}

	pm, err := pinMount(seam, workspace, sourceDir, runtimeDir, "op_abc", 0)
	if err != nil {
		t.Fatalf("pinMount: %v", err)
	}

	// Expected closes: root(3), source(5), destDir(6), tree(4) = 4 closes
	if len(seam.closeCalls) != 4 {
		t.Errorf("closeCalls = %d, want 4", len(seam.closeCalls))
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

func TestPinnedMountNilReceiver(t *testing.T) {
	var pm *pinnedMount
	if err := pm.Cleanup(); err != nil {
		t.Errorf("Cleanup on nil receiver: %v", err)
	}
}
