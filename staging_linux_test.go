//go:build linux

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"syscall"
)

func setupStagingTest(t *testing.T) (workspace string, runtimeDir string) {
	t.Helper()
	dir := t.TempDir()
	workspace = filepath.Join(dir, "workspace")
	runtimeDir = filepath.Join(dir, "runtime")
	if err := os.MkdirAll(workspace, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(runtimeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	return
}

func createBuildContext(t *testing.T, workspace string) string {
	t.Helper()
	ctxDir := filepath.Join(workspace, "buildctx")
	if err := os.MkdirAll(ctxDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ctxDir, "Dockerfile"), []byte("FROM alpine:3.24\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ctxDir, "app.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return ctxDir
}

func abs(t *testing.T, path string) string {
	t.Helper()
	abs, err := filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	return abs
}

func TestStageBuildContextBasic(t *testing.T) {
	workspace, runtimeDir := setupStagingTest(t)
	ctxDir := createBuildContext(t, workspace)

	staged, err := StageBuildContext(context.Background(), workspace, abs(t, ctxDir), "Dockerfile", runtimeDir, "op1")
	if err != nil {
		t.Fatalf("StageBuildContext: %v", err)
	}
	defer staged.Cleanup()

	if _, err := os.Stat(staged.ContextPath); err != nil {
		t.Fatalf("staging directory does not exist: %v", err)
	}
	if _, err := os.Stat(staged.DockerfilePath); err != nil {
		t.Fatalf("Dockerfile not found in staging: %v", err)
	}

	content, err := os.ReadFile(staged.DockerfilePath)
	if err != nil {
		t.Fatalf("cannot read Dockerfile: %v", err)
	}
	if string(content) != "FROM alpine:3.24\n" {
		t.Fatalf("unexpected Dockerfile content: %q", string(content))
	}
}

func TestStageBuildContextOperationIDUnsafe(t *testing.T) {
	workspace, runtimeDir := setupStagingTest(t)
	ctxDir := createBuildContext(t, workspace)
	absCtx := abs(t, ctxDir)

	for _, id := range []string{"../escape", "op/with/slash", `op\with\backslash`, ""} {
		_, err := StageBuildContext(context.Background(), workspace, absCtx, "Dockerfile", runtimeDir, id)
		if err == nil {
			t.Errorf("expected error for operation ID %q, got nil", id)
		}
	}
}

func TestStageBuildContextSymlinkInContext(t *testing.T) {
	workspace, runtimeDir := setupStagingTest(t)
	ctxDir := createBuildContext(t, workspace)

	symlinkPath := filepath.Join(ctxDir, "link")
	os.Symlink("target", symlinkPath)

	staged, err := StageBuildContext(context.Background(), workspace, abs(t, ctxDir), "Dockerfile", runtimeDir, "op1")
	if err != nil {
		t.Fatalf("StageBuildContext: %v", err)
	}
	defer staged.Cleanup()

	stagedLink := filepath.Join(staged.ContextPath, "link")
	linkTarget, err := os.Readlink(stagedLink)
	if err != nil {
		t.Fatalf("cannot read symlink in staging: %v", err)
	}
	if linkTarget != "target" {
		t.Errorf("symlink target mismatch: got %q, want %q", linkTarget, "target")
	}
}

func TestStageBuildContextHardlink(t *testing.T) {
	workspace, runtimeDir := setupStagingTest(t)
	ctxDir := createBuildContext(t, workspace)

	originalFile := filepath.Join(ctxDir, "original.txt")
	os.WriteFile(originalFile, []byte("content\n"), 0o644)
	hardlinkFile := filepath.Join(ctxDir, "hardlink.txt")
	os.Link(originalFile, hardlinkFile)

	staged, err := StageBuildContext(context.Background(), workspace, abs(t, ctxDir), "Dockerfile", runtimeDir, "op1")
	if err != nil {
		t.Fatalf("StageBuildContext: %v", err)
	}
	defer staged.Cleanup()

	origInfo, _ := os.Stat(filepath.Join(staged.ContextPath, "original.txt"))
	linkInfo, _ := os.Stat(filepath.Join(staged.ContextPath, "hardlink.txt"))

	origIno := origInfo.Sys().(*syscall.Stat_t).Ino
	linkIno := linkInfo.Sys().(*syscall.Stat_t).Ino
	if origIno != linkIno {
		t.Errorf("hardlink not preserved: inodes %d != %d", origIno, linkIno)
	}
}

func TestStageBuildContextHardlinkAcrossDirectories(t *testing.T) {
	workspace, runtimeDir := setupStagingTest(t)
	ctxDir := createBuildContext(t, workspace)

	dir1 := filepath.Join(ctxDir, "dir1")
	dir2 := filepath.Join(ctxDir, "dir2")
	os.MkdirAll(dir1, 0o755)
	os.MkdirAll(dir2, 0o755)

	originalFile := filepath.Join(dir1, "original.txt")
	os.WriteFile(originalFile, []byte("content\n"), 0o644)
	hardlinkFile := filepath.Join(dir2, "hardlink.txt")
	os.Link(originalFile, hardlinkFile)

	staged, err := StageBuildContext(context.Background(), workspace, abs(t, ctxDir), "Dockerfile", runtimeDir, "op1")
	if err != nil {
		t.Fatalf("StageBuildContext: %v", err)
	}
	defer staged.Cleanup()

	origInfo, _ := os.Stat(filepath.Join(staged.ContextPath, "dir1", "original.txt"))
	linkInfo, _ := os.Stat(filepath.Join(staged.ContextPath, "dir2", "hardlink.txt"))

	origIno := origInfo.Sys().(*syscall.Stat_t).Ino
	linkIno := linkInfo.Sys().(*syscall.Stat_t).Ino
	if origIno != linkIno {
		t.Errorf("hardlink not preserved across directories: inodes %d != %d", origIno, linkIno)
	}
}

func TestStageBuildContextModePreserved(t *testing.T) {
	workspace, runtimeDir := setupStagingTest(t)
	ctxDir := createBuildContext(t, workspace)

	specialFile := filepath.Join(ctxDir, "special.go")
	os.WriteFile(specialFile, []byte("package main\n"), 0o755)

	staged, err := StageBuildContext(context.Background(), workspace, abs(t, ctxDir), "Dockerfile", runtimeDir, "op1")
	if err != nil {
		t.Fatalf("StageBuildContext: %v", err)
	}
	defer staged.Cleanup()

	info, _ := os.Stat(filepath.Join(staged.ContextPath, "special.go"))
	if info.Mode().Perm() != 0o755 {
		t.Errorf("mode mismatch: got %o, want %o", info.Mode().Perm(), 0o755)
	}
}

func TestStageBuildContextMtimePreserved(t *testing.T) {
	workspace, runtimeDir := setupStagingTest(t)
	ctxDir := createBuildContext(t, workspace)

	specialFile := filepath.Join(ctxDir, "timed.go")
	os.WriteFile(specialFile, []byte("package main\n"), 0o644)
	oldTime := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	os.Chtimes(specialFile, oldTime, oldTime)

	staged, err := StageBuildContext(context.Background(), workspace, abs(t, ctxDir), "Dockerfile", runtimeDir, "op1")
	if err != nil {
		t.Fatalf("StageBuildContext: %v", err)
	}
	defer staged.Cleanup()

	info, _ := os.Stat(filepath.Join(staged.ContextPath, "timed.go"))
	if !info.ModTime().Equal(oldTime) {
		t.Errorf("mtime mismatch: got %v, want %v", info.ModTime(), oldTime)
	}
}

func TestStageBuildContextCancellation(t *testing.T) {
	workspace, runtimeDir := setupStagingTest(t)
	ctxDir := createBuildContext(t, workspace)

	for i := 0; i < 100; i++ {
		os.WriteFile(filepath.Join(ctxDir, "file"+string(rune('0'+i%10))+".txt"), []byte("content\n"), 0o644)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := StageBuildContext(ctx, workspace, abs(t, ctxDir), "Dockerfile", runtimeDir, "op1")
	if err == nil {
		t.Error("expected error for cancelled context, got nil")
	}
}

func TestStageBuildContextFIFO(t *testing.T) {
	workspace, runtimeDir := setupStagingTest(t)
	ctxDir := createBuildContext(t, workspace)

	fifoPath := filepath.Join(ctxDir, "myfifo")
	if err := unix.Mknod(fifoPath, unix.S_IFIFO|0o644, 0); err != nil {
		t.Skipf("mknod not available: %v", err)
	}

	_, err := StageBuildContext(context.Background(), workspace, abs(t, ctxDir), "Dockerfile", runtimeDir, "op1")
	if err == nil {
		t.Error("expected error for FIFO, got nil")
	}
	if !strings.Contains(err.Error(), "FIFO") {
		t.Errorf("expected FIFO error, got: %v", err)
	}

	opDir := filepath.Join(runtimeDir, "builds", "op1")
	if _, err := os.Stat(opDir); err == nil {
		t.Error("operation directory should be cleaned up after error")
	}
}

func TestStageBuildContextCleanupOnce(t *testing.T) {
	workspace, runtimeDir := setupStagingTest(t)
	ctxDir := createBuildContext(t, workspace)

	staged, err := StageBuildContext(context.Background(), workspace, abs(t, ctxDir), "Dockerfile", runtimeDir, "op1")
	if err != nil {
		t.Fatalf("StageBuildContext: %v", err)
	}

	staged.Cleanup()
	staged.Cleanup()
	staged.Cleanup()

	if _, err := os.Stat(staged.ContextPath); err == nil {
		t.Error("staging directory should be removed after Cleanup")
	}
}

func TestStageBuildContextENOSYS(t *testing.T) {
	workspace, runtimeDir := setupStagingTest(t)
	ctxDir := createBuildContext(t, workspace)
	absCtx := abs(t, ctxDir)

	sy := stagingSyscall{Openat2: nil}
	_, err := stageBuildContextInternal(context.Background(), workspace, absCtx, "Dockerfile", runtimeDir, "op1", sy, nil)
	if err == nil {
		t.Error("expected error for nil Openat2, got nil")
	}
}

func TestStageBuildContextEPERM(t *testing.T) {
	workspace, runtimeDir := setupStagingTest(t)
	ctxDir := createBuildContext(t, workspace)
	absCtx := abs(t, ctxDir)

	sy := stagingSyscall{
		Openat2: func(dirfd int, path string, how *unix.OpenHow) (int, error) {
			return -1, unix.EPERM
		},
	}
	_, err := stageBuildContextInternal(context.Background(), workspace, absCtx, "Dockerfile", runtimeDir, "op1", sy, nil)
	if err == nil {
		t.Error("expected error for EPERM, got nil")
	}
	if !strings.Contains(err.Error(), "not permitted") && !strings.Contains(err.Error(), "fail closed") {
		t.Errorf("expected fail closed or permission error, got: %v", err)
	}
}

func TestStageBuildContextExistingOperationDir(t *testing.T) {
	workspace, runtimeDir := setupStagingTest(t)
	ctxDir := createBuildContext(t, workspace)

	// Create existing empty operation directory.
	opDir := filepath.Join(runtimeDir, "builds", "op_existing")
	os.MkdirAll(opDir, 0o700)

	_, err := StageBuildContext(context.Background(), workspace, abs(t, ctxDir), "Dockerfile", runtimeDir, "op_existing")
	if err == nil {
		t.Error("expected error for existing operation directory, got nil")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("expected 'already exists' error, got: %v", err)
	}
	// Directory should remain unchanged.
	if _, err := os.Stat(opDir); err != nil {
		t.Error("existing operation directory should remain")
	}
}

func TestStageBuildContextExistingOperationDirWithContent(t *testing.T) {
	workspace, runtimeDir := setupStagingTest(t)
	ctxDir := createBuildContext(t, workspace)

	// Create existing operation directory with content.
	opDir := filepath.Join(runtimeDir, "builds", "op_existing")
	os.MkdirAll(filepath.Join(opDir, "context"), 0o700)
	os.WriteFile(filepath.Join(opDir, "context", "marker"), []byte("marker\n"), 0o644)

	_, err := StageBuildContext(context.Background(), workspace, abs(t, ctxDir), "Dockerfile", runtimeDir, "op_existing")
	if err == nil {
		t.Error("expected error for existing operation directory, got nil")
	}
	// Marker and directory should remain unchanged.
	if _, err := os.Stat(filepath.Join(opDir, "context", "marker")); err != nil {
		t.Error("marker file should remain")
	}
}

func TestStageBuildContextExistingSymlinkOperationID(t *testing.T) {
	workspace, runtimeDir := setupStagingTest(t)
	ctxDir := createBuildContext(t, workspace)

	// Create symlink where operationID would go.
	buildsDir := filepath.Join(runtimeDir, "builds")
	os.MkdirAll(buildsDir, 0o700)
	symlinkPath := filepath.Join(buildsDir, "op_symlink")
	os.Symlink("/tmp/escape", symlinkPath)

	_, err := StageBuildContext(context.Background(), workspace, abs(t, ctxDir), "Dockerfile", runtimeDir, "op_symlink")
	if err == nil {
		t.Error("expected error for existing symlink operation ID, got nil")
	}
	// Symlink should remain unchanged.
	info, err := os.Lstat(symlinkPath)
	if err != nil {
		t.Fatalf("symlink should remain: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Error("symlink should remain a symlink")
	}
}

func TestStageBuildContextExistingFileOperationID(t *testing.T) {
	workspace, runtimeDir := setupStagingTest(t)
	ctxDir := createBuildContext(t, workspace)

	// Create file where operationID would go.
	buildsDir := filepath.Join(runtimeDir, "builds")
	os.MkdirAll(buildsDir, 0o700)
	filePath := filepath.Join(buildsDir, "op_file")
	os.WriteFile(filePath, []byte("file\n"), 0o644)

	_, err := StageBuildContext(context.Background(), workspace, abs(t, ctxDir), "Dockerfile", runtimeDir, "op_file")
	if err == nil {
		t.Error("expected error for existing file operation ID, got nil")
	}
	// File should remain unchanged.
	if _, err := os.Stat(filePath); err != nil {
		t.Error("file should remain")
	}
}

func TestStageBuildContextDockerfileViaSymlink(t *testing.T) {
	workspace, runtimeDir := setupStagingTest(t)
	ctxDir := createBuildContext(t, workspace)

	realFile := filepath.Join(ctxDir, "real.Dockerfile")
	os.WriteFile(realFile, []byte("FROM alpine:3.24\n"), 0o644)
	os.Remove(filepath.Join(ctxDir, "Dockerfile"))
	os.Symlink("real.Dockerfile", filepath.Join(ctxDir, "Dockerfile"))

	_, err := StageBuildContext(context.Background(), workspace, abs(t, ctxDir), "Dockerfile", runtimeDir, "op1")
	if err == nil {
		t.Error("expected error for symlink Dockerfile, got nil")
	}
}

func TestStageBuildContextCleanupAfterMissingDockerfile(t *testing.T) {
	workspace, runtimeDir := setupStagingTest(t)
	ctxDir := createBuildContext(t, workspace)
	os.Remove(filepath.Join(ctxDir, "Dockerfile"))

	_, err := StageBuildContext(context.Background(), workspace, abs(t, ctxDir), "Dockerfile", runtimeDir, "op1")
	if err == nil {
		t.Error("expected error for missing Dockerfile, got nil")
	}

	opDir := filepath.Join(runtimeDir, "builds", "op1")
	if _, err := os.Stat(opDir); err == nil {
		t.Error("operation directory should be cleaned up after missing Dockerfile")
	}
}

func TestStageBuildContextSymlinkDestination(t *testing.T) {
	workspace, runtimeDir := setupStagingTest(t)
	ctxDir := createBuildContext(t, workspace)

	opDir := filepath.Join(runtimeDir, "builds", "op_symlink")
	os.MkdirAll(filepath.Dir(opDir), 0o700)
	os.Symlink("/tmp/escape", opDir)

	_, err := StageBuildContext(context.Background(), workspace, abs(t, ctxDir), "Dockerfile", runtimeDir, "op_symlink")
	if err == nil {
		t.Error("expected error for symlink operation directory, got nil")
	}
}

func TestStageBuildContextParallelCleanup(t *testing.T) {
	workspace, runtimeDir := setupStagingTest(t)
	ctxDir := createBuildContext(t, workspace)

	staged, err := StageBuildContext(context.Background(), workspace, abs(t, ctxDir), "Dockerfile", runtimeDir, "op1")
	if err != nil {
		t.Fatalf("StageBuildContext: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			staged.Cleanup()
		}()
	}
	wg.Wait()

	if _, err := os.Stat(staged.ContextPath); err == nil {
		t.Error("staging directory should be removed after parallel Cleanup")
	}
}

func TestStageBuildContextContextOutsideWorkspace(t *testing.T) {
	workspace, runtimeDir := setupStagingTest(t)

	outsideDir := t.TempDir()
	os.WriteFile(filepath.Join(outsideDir, "Dockerfile"), []byte("FROM alpine:3.24\n"), 0o644)

	_, err := StageBuildContext(context.Background(), workspace, outsideDir, "Dockerfile", runtimeDir, "op1")
	if err == nil {
		t.Error("expected error for context outside workspace, got nil")
	}
}

func TestStageBuildContextEmptyDirectory(t *testing.T) {
	workspace, runtimeDir := setupStagingTest(t)
	ctxDir := createBuildContext(t, workspace)

	emptyDir := filepath.Join(ctxDir, "empty")
	os.MkdirAll(emptyDir, 0o755)

	staged, err := StageBuildContext(context.Background(), workspace, abs(t, ctxDir), "Dockerfile", runtimeDir, "op1")
	if err != nil {
		t.Fatalf("StageBuildContext: %v", err)
	}
	defer staged.Cleanup()

	stagedEmpty := filepath.Join(staged.ContextPath, "empty")
	info, err := os.Stat(stagedEmpty)
	if err != nil {
		t.Fatalf("empty directory not found in staging: %v", err)
	}
	if !info.IsDir() {
		t.Error("staged empty path is not a directory")
	}
}

func TestStageBuildContextDeepNesting(t *testing.T) {
	workspace, runtimeDir := setupStagingTest(t)
	ctxDir := createBuildContext(t, workspace)

	deepDir := ctxDir
	for i := 0; i < 20; i++ {
		deepDir = filepath.Join(deepDir, "level"+string(rune('0'+i)))
	}
	os.MkdirAll(deepDir, 0o755)
	os.WriteFile(filepath.Join(deepDir, "deep.txt"), []byte("deep content\n"), 0o644)

	staged, err := StageBuildContext(context.Background(), workspace, abs(t, ctxDir), "Dockerfile", runtimeDir, "op1")
	if err != nil {
		t.Fatalf("StageBuildContext: %v", err)
	}
	defer staged.Cleanup()

	deepStaged := staged.ContextPath
	for i := 0; i < 20; i++ {
		deepStaged = filepath.Join(deepStaged, "level"+string(rune('0'+i)))
	}
	if _, err := os.Stat(filepath.Join(deepStaged, "deep.txt")); err != nil {
		t.Fatalf("deep.txt not found in staging: %v", err)
	}
}

func TestStageBuildContextDirectoryModeUmask(t *testing.T) {
	workspace, runtimeDir := setupStagingTest(t)
	ctxDir := createBuildContext(t, workspace)

	specialDir := filepath.Join(ctxDir, "specialdir")
	os.MkdirAll(specialDir, 0o750)
	os.WriteFile(filepath.Join(specialDir, "file.txt"), []byte("content\n"), 0o644)

	staged, err := StageBuildContext(context.Background(), workspace, abs(t, ctxDir), "Dockerfile", runtimeDir, "op1")
	if err != nil {
		t.Fatalf("StageBuildContext: %v", err)
	}
	defer staged.Cleanup()

	info, _ := os.Stat(filepath.Join(staged.ContextPath, "specialdir"))
	if info.Mode().Perm() != 0o750 {
		t.Errorf("directory mode mismatch: got %o, want %o", info.Mode().Perm(), 0o750)
	}
}

func TestStageBuildContextDirectoryMtime(t *testing.T) {
	workspace, runtimeDir := setupStagingTest(t)
	ctxDir := createBuildContext(t, workspace)

	subDir := filepath.Join(ctxDir, "subdir")
	os.MkdirAll(subDir, 0o755)
	os.WriteFile(filepath.Join(subDir, "file.txt"), []byte("content\n"), 0o644)

	oldTime := time.Date(2019, 6, 15, 12, 0, 0, 0, time.UTC)
	os.Chtimes(subDir, oldTime, oldTime)

	staged, err := StageBuildContext(context.Background(), workspace, abs(t, ctxDir), "Dockerfile", runtimeDir, "op1")
	if err != nil {
		t.Fatalf("StageBuildContext: %v", err)
	}
	defer staged.Cleanup()

	info, _ := os.Stat(filepath.Join(staged.ContextPath, "subdir"))
	if !info.ModTime().Equal(oldTime) {
		t.Errorf("directory mtime mismatch: got %v, want %v", info.ModTime(), oldTime)
	}
}

func TestStageBuildContextFileReplacement(t *testing.T) {
	workspace, runtimeDir := setupStagingTest(t)
	ctxDir := createBuildContext(t, workspace)

	targetFile := filepath.Join(ctxDir, "replace.go")
	os.WriteFile(targetFile, []byte("package main\n"), 0o644)

	replaced := atomic.Bool{}
	hooks := &stagingHooks{
		betweenStatAndOpen: func(name string) error {
			if name == "replace.go" {
				os.Remove(targetFile)
				os.Symlink("/tmp/escape", targetFile)
				replaced.Store(true)
			}
			return nil
		},
	}

	_, err := stageBuildContextInternal(context.Background(), workspace, abs(t, ctxDir), "Dockerfile", runtimeDir, "op1", defaultStagingSyscall(), hooks)
	if err == nil {
		t.Error("expected error for file replacement, got nil")
	}
	if !replaced.Load() {
		t.Error("hook was not called")
	}

	opDir := filepath.Join(runtimeDir, "builds", "op1")
	if _, err := os.Stat(opDir); err == nil {
		t.Error("operation directory should be cleaned up after error")
	}
}

func TestStageBuildContextDirectoryReplacement(t *testing.T) {
	workspace, runtimeDir := setupStagingTest(t)
	ctxDir := createBuildContext(t, workspace)

	subDir := filepath.Join(ctxDir, "subdir")
	os.MkdirAll(subDir, 0o755)
	os.WriteFile(filepath.Join(subDir, "file.txt"), []byte("content\n"), 0o644)

	replaced := atomic.Bool{}
	hooks := &stagingHooks{
		betweenStatAndOpen: func(name string) error {
			if name == "subdir" {
				os.RemoveAll(subDir)
				os.Symlink("/tmp/escape", subDir)
				replaced.Store(true)
			}
			return nil
		},
	}

	_, err := stageBuildContextInternal(context.Background(), workspace, abs(t, ctxDir), "Dockerfile", runtimeDir, "op1", defaultStagingSyscall(), hooks)
	if err == nil {
		t.Error("expected error for directory replacement, got nil")
	}
	if !replaced.Load() {
		t.Error("hook was not called")
	}

	opDir := filepath.Join(runtimeDir, "builds", "op1")
	if _, err := os.Stat(opDir); err == nil {
		t.Error("operation directory should be cleaned up after error")
	}
}

func TestStageBuildContextCancellationAfterCreate(t *testing.T) {
	workspace, runtimeDir := setupStagingTest(t)
	ctxDir := createBuildContext(t, workspace)

	for i := 0; i < 50; i++ {
		os.WriteFile(filepath.Join(ctxDir, "file"+string(rune('0'+i%10))+".txt"), []byte("content\n"), 0o644)
	}

	cancelled := atomic.Bool{}
	hooks := &stagingHooks{
		afterCreateDest: func(name string) error {
			if !cancelled.Load() && strings.HasSuffix(name, "file5.txt") {
				cancelled.Store(true)
				return fmt.Errorf("injected cancellation")
			}
			return nil
		},
	}

	_, err := stageBuildContextInternal(context.Background(), workspace, abs(t, ctxDir), "Dockerfile", runtimeDir, "op1", defaultStagingSyscall(), hooks)
	if err == nil {
		t.Error("expected error for cancellation after create, got nil")
	}

	opDir := filepath.Join(runtimeDir, "builds", "op1")
	if _, err := os.Stat(opDir); err == nil {
		t.Error("operation directory should be cleaned up after error")
	}
}

func TestStageBuildContextPartialCopy(t *testing.T) {
	workspace, runtimeDir := setupStagingTest(t)
	ctxDir := createBuildContext(t, workspace)

	largeFile := filepath.Join(ctxDir, "large.bin")
	data := make([]byte, 256*1024)
	for i := range data {
		data[i] = byte(i % 256)
	}
	os.WriteFile(largeFile, data, 0o644)

	hooks := &stagingHooks{
		duringCopy: func(name string, copied int64) error {
			if name == "large.bin" && copied > 0 {
				return fmt.Errorf("injected read error")
			}
			return nil
		},
	}

	_, err := stageBuildContextInternal(context.Background(), workspace, abs(t, ctxDir), "Dockerfile", runtimeDir, "op1", defaultStagingSyscall(), hooks)
	if err == nil {
		t.Error("expected error for partial copy, got nil")
	}

	opDir := filepath.Join(runtimeDir, "builds", "op1")
	if _, err := os.Stat(opDir); err == nil {
		t.Error("operation directory should be cleaned up after error")
	}
}

func TestStageBuildContextDockerfileRelTraversal(t *testing.T) {
	workspace, runtimeDir := setupStagingTest(t)
	ctxDir := createBuildContext(t, workspace)
	absCtx := abs(t, ctxDir)

	for _, rel := range []string{"../Dockerfile", "subdir/../../Dockerfile", "Dockerfile/.."} {
		_, err := StageBuildContext(context.Background(), workspace, absCtx, rel, runtimeDir, "op1")
		if err == nil {
			t.Errorf("expected error for dockerfileRel %q, got nil", rel)
		}
	}
}

func TestStageBuildContextContextPathEscape(t *testing.T) {
	workspace, runtimeDir := setupStagingTest(t)
	_ = createBuildContext(t, workspace)

	outsideDir := t.TempDir()
	os.WriteFile(filepath.Join(outsideDir, "Dockerfile"), []byte("FROM alpine:3.24\n"), 0o644)

	escapePath := filepath.Join(workspace, "escape")
	os.Symlink(outsideDir, escapePath)

	_, err := StageBuildContext(context.Background(), workspace, abs(t, escapePath), "Dockerfile", runtimeDir, "op1")
	if err == nil {
		t.Error("expected error for context path escape, got nil")
	}
}

func TestStageBuildContextBuildsSymlink(t *testing.T) {
	workspace, runtimeDir := setupStagingTest(t)
	ctxDir := createBuildContext(t, workspace)

	externalDir := t.TempDir()
	buildsPath := filepath.Join(runtimeDir, "builds")
	os.Symlink(externalDir, buildsPath)

	_, err := StageBuildContext(context.Background(), workspace, abs(t, ctxDir), "Dockerfile", runtimeDir, "op1")
	if err == nil {
		t.Error("expected error for symlink builds directory, got nil")
	}

	entries, _ := os.ReadDir(externalDir)
	if len(entries) > 0 {
		t.Errorf("external directory should be empty, got %d entries", len(entries))
	}
}

func TestStageBuildContextUnexpectedEOF(t *testing.T) {
	workspace, runtimeDir := setupStagingTest(t)
	ctxDir := createBuildContext(t, workspace)

	largeFile := filepath.Join(ctxDir, "truncate.bin")
	data := make([]byte, 256*1024)
	for i := range data {
		data[i] = byte(i % 256)
	}
	os.WriteFile(largeFile, data, 0o644)

	hooks := &stagingHooks{
		duringCopy: func(name string, copied int64) error {
			if name == "truncate.bin" && copied == 128*1024 {
				os.Truncate(largeFile, int64(copied))
			}
			return nil
		},
	}

	_, err := stageBuildContextInternal(context.Background(), workspace, abs(t, ctxDir), "Dockerfile", runtimeDir, "op1", defaultStagingSyscall(), hooks)
	if err == nil {
		t.Error("expected error for unexpected EOF, got nil")
	}
	if !strings.Contains(err.Error(), "unexpected EOF") {
		t.Errorf("expected unexpected EOF error, got: %v", err)
	}

	opDir := filepath.Join(runtimeDir, "builds", "op1")
	if _, err := os.Stat(opDir); err == nil {
		t.Error("operation directory should be cleaned up after error")
	}
}

func TestStageBuildContextContextReplacement(t *testing.T) {
	workspace, runtimeDir := setupStagingTest(t)
	ctxDir := createBuildContext(t, workspace)
	absCtx := abs(t, ctxDir)

	outsideDir := t.TempDir()
	os.WriteFile(filepath.Join(outsideDir, "secret.txt"), []byte("secret\n"), 0o644)

	replaced := atomic.Bool{}
	hooks := &stagingHooks{
		afterWorkspacePin: func() error {
			os.RemoveAll(ctxDir)
			os.Symlink(outsideDir, ctxDir)
			replaced.Store(true)
			return nil
		},
	}

	_, err := stageBuildContextInternal(context.Background(), workspace, absCtx, "Dockerfile", runtimeDir, "op1", defaultStagingSyscall(), hooks)
	if err == nil {
		t.Error("expected error for context replacement, got nil")
	}
	if !replaced.Load() {
		t.Error("hook was not called")
	}

	opDir := filepath.Join(runtimeDir, "builds", "op1")
	if _, err := os.Stat(opDir); err == nil {
		t.Error("operation directory should not exist after error")
	}
}

// TestStageBuildContextStripsSetUIDAndSetGID proves the staging privilege
// invariant: a helper-owned staged regular file carries the source's ordinary
// permission bits but never the SUID or SGID privilege bits. The staging
// copy is helper-owned (root-owned in system mode), so transferring a
// source privilege bit would hand a privilege-granting setuid/setgid binary
// to Docker's build context. The source file itself is never modified; the
// hardlink path stages the same invariant (the linked staged entry shares
// the first staged copy's inode and must not re-introduce privilege bits);
// normal rwx permissions are preserved.
func TestStageBuildContextStripsSetUIDAndSetGID(t *testing.T) {
	for _, tc := range []struct {
		name       string
		sourceMode os.FileMode
		wantStaged os.FileMode
	}{
		{"SUID executable", os.ModeSetuid | 0o755, 0o755},
		{"SGID executable", os.ModeSetgid | 0o755, 0o755},
		{"SUID+SGID executable", os.ModeSetuid | os.ModeSetgid | 0o755, 0o755},
		{"ordinary executable", 0o755, 0o755},
		{"ordinary file", 0o644, 0o644},
	} {
		t.Run(tc.name, func(t *testing.T) {
			workspace, runtimeDir := setupStagingTest(t)
			ctxDir := createBuildContext(t, workspace)

			source := filepath.Join(ctxDir, tc.name+".bin")
			if err := os.WriteFile(source, []byte("#!/bin/sh\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(source, tc.sourceMode); err != nil {
				t.Fatal(err)
			}

			staged, err := StageBuildContext(context.Background(), workspace, abs(t, ctxDir), "Dockerfile", runtimeDir, "op1")
			if err != nil {
				t.Fatalf("StageBuildContext: %v", err)
			}
			defer staged.Cleanup()

			sourceInfo, err := os.Stat(source)
			if err != nil {
				t.Fatal(err)
			}
			if sourceInfo.Mode() != tc.sourceMode {
				t.Errorf("source file changed: mode %o, want %o", sourceInfo.Mode(), tc.sourceMode)
			}

			stagedInfo, err := os.Stat(filepath.Join(staged.ContextPath, tc.name+".bin"))
			if err != nil {
				t.Fatal(err)
			}
			if stagedInfo.Mode() != tc.wantStaged {
				t.Errorf("staged file mode = %o (privilege bits %s present), want %o",
					stagedInfo.Mode(), privilegeBits(stagedInfo.Mode()), tc.wantStaged)
			}
		})
	}
}

// privilegeBits names the privilege bits still set on a staged mode, for a
// readable failure message.
func privilegeBits(mode os.FileMode) string {
	var names []string
	if mode&os.ModeSetuid != 0 {
		names = append(names, "S_ISUID")
	}
	if mode&os.ModeSetgid != 0 {
		names = append(names, "S_ISGID")
	}
	if mode&os.ModeSticky != 0 {
		names = append(names, "S_ISVTX")
	}
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, "+")
}

// TestStageBuildContextStripsSetUIDOnHardlinkedPair proves the hardlink
// staging path keeps the same invariant: both staged names share one inode
// and that staged inode carries no privilege bit, while the source hardlink
// pair keeps its bits.
func TestStageBuildContextStripsSetUIDOnHardlinkedPair(t *testing.T) {
	workspace, runtimeDir := setupStagingTest(t)
	ctxDir := createBuildContext(t, workspace)

	first := filepath.Join(ctxDir, "first.bin")
	if err := os.WriteFile(first, []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(first, os.ModeSetuid|0o755); err != nil {
		t.Fatal(err)
	}
	second := filepath.Join(ctxDir, "second.bin")
	if err := os.Link(first, second); err != nil {
		t.Fatal(err)
	}

	staged, err := StageBuildContext(context.Background(), workspace, abs(t, ctxDir), "Dockerfile", runtimeDir, "op1")
	if err != nil {
		t.Fatalf("StageBuildContext: %v", err)
	}
	defer staged.Cleanup()

	stagedFirst, err := os.Stat(filepath.Join(staged.ContextPath, "first.bin"))
	if err != nil {
		t.Fatal(err)
	}
	stagedSecond, err := os.Stat(filepath.Join(staged.ContextPath, "second.bin"))
	if err != nil {
		t.Fatal(err)
	}

	if stagedFirst.Sys().(*syscall.Stat_t).Ino != stagedSecond.Sys().(*syscall.Stat_t).Ino {
		t.Errorf("staged hardlink pair lost its single staged inode: %d != %d",
			stagedFirst.Sys().(*syscall.Stat_t).Ino, stagedSecond.Sys().(*syscall.Stat_t).Ino)
	}
	if stagedFirst.Mode() != 0o755 || stagedSecond.Mode() != 0o755 {
		t.Errorf("staged hardlink pair modes = %o/%o, want 755/755 (no privilege bits)", stagedFirst.Mode(), stagedSecond.Mode())
	}
}
