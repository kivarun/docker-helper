//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"math"
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
	_, err := stageBuildContextInternal(context.Background(), workspace, absCtx, "Dockerfile", runtimeDir, "op1", sy, nil, productionBuildStagingCeilings)
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
	_, err := stageBuildContextInternal(context.Background(), workspace, absCtx, "Dockerfile", runtimeDir, "op1", sy, nil, productionBuildStagingCeilings)
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

	_, err := stageBuildContextInternal(context.Background(), workspace, abs(t, ctxDir), "Dockerfile", runtimeDir, "op1", defaultStagingSyscall(), hooks, productionBuildStagingCeilings)
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

	_, err := stageBuildContextInternal(context.Background(), workspace, abs(t, ctxDir), "Dockerfile", runtimeDir, "op1", defaultStagingSyscall(), hooks, productionBuildStagingCeilings)
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

	_, err := stageBuildContextInternal(context.Background(), workspace, abs(t, ctxDir), "Dockerfile", runtimeDir, "op1", defaultStagingSyscall(), hooks, productionBuildStagingCeilings)
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

	_, err := stageBuildContextInternal(context.Background(), workspace, abs(t, ctxDir), "Dockerfile", runtimeDir, "op1", defaultStagingSyscall(), hooks, productionBuildStagingCeilings)
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

	_, err := stageBuildContextInternal(context.Background(), workspace, abs(t, ctxDir), "Dockerfile", runtimeDir, "op1", defaultStagingSyscall(), hooks, productionBuildStagingCeilings)
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

	_, err := stageBuildContextInternal(context.Background(), workspace, absCtx, "Dockerfile", runtimeDir, "op1", defaultStagingSyscall(), hooks, productionBuildStagingCeilings)
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

// --- H4 staging ceilings -----------------------------------------------------
//
// The staging resources that must be refused are measured against the
// proposed Release-2.2 production ceilings (128 MiB payload bytes, 50000
// entries, depth 64). The hostile fixtures below are cheap: the byte case
// uses a sparse source file (logical size only), the entry case uses
// zero-byte files, and the depth case is an ordinary nested chain.

// sparseHostileFile creates a sparse regular file with the given logical
// size (st_size) and near-zero physical allocation.
func sparseHostileFile(t *testing.T, path string, size int64) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(size); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() != size {
		t.Fatalf("sparse fixture has st_size %d, want %d", st.Size(), size)
	}
	if sys := st.Sys().(*syscall.Stat_t); sys.Blocks > 64 {
		t.Fatalf("sparse fixture is not sparse: %d blocks for st_size %d", sys.Blocks, size)
	}
}

// TestStageBuildContextSparsePayloadOverByteCeiling proves a single hostile
// build context cannot push its payload past the production byte ceiling:
// a sparse file whose logical size exceeds the ceiling must be refused
// before its destination payload is created or written, and the refusal
// must leave no operation tree. Pre-fix this staging operation succeeded and
// began materializing the sparse file's logical payload in the runtime
// filesystem (duringCopy/afterCreateDest ran for it).
func TestStageBuildContextSparsePayloadOverByteCeiling(t *testing.T) {
	workspace, runtimeDir := setupStagingTest(t)
	ctxDir := createBuildContext(t, workspace)

	const byteCeiling = 128 * 1024 * 1024 // proposed production byte ceiling
	sparseHostileFile(t, filepath.Join(ctxDir, "big.bin"), byteCeiling+1)

	duringCopy := map[string]int64{}
	created := map[string]bool{}
	hooks := &stagingHooks{
		duringCopy: func(name string, copiedBytes int64) error {
			duringCopy[name] = copiedBytes
			return nil
		},
		afterCreateDest: func(name string) error {
			created[name] = true
			return nil
		},
	}

	_, err := stageBuildContextInternal(context.Background(), workspace, abs(t, ctxDir), "Dockerfile", runtimeDir, "op1", defaultStagingSyscall(), hooks, productionBuildStagingCeilings)
	if err == nil {
		t.Fatal("expected the over-ceiling sparse payload to be refused, got success")
	}

	if _, ok := duringCopy["big.bin"]; ok {
		t.Errorf("over-ceiling payload began copying (duringCopy at offset %d); refusal must happen before any destination payload write", duringCopy["big.bin"])
	}
	if created["big.bin"] {
		t.Error("over-ceiling payload destination entry was created; refusal must happen before destination creation")
	}

	// The source file must remain untouched and sparse.
	st, err := os.Stat(filepath.Join(ctxDir, "big.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() != byteCeiling+1 {
		t.Errorf("source sparse file changed size: %d", st.Size())
	}
	if sys := st.Sys().(*syscall.Stat_t); sys.Blocks > 64 {
		t.Errorf("source sparse file was materialized: %d blocks", sys.Blocks)
	}

	// The refusal must leave no operation tree.
	if _, err := os.Stat(filepath.Join(runtimeDir, "builds", "op1")); err == nil {
		t.Error("operation directory should be cleaned up after the byte-ceiling refusal")
	}
}

// TestStageBuildContextEntriesOverCeiling proves a single hostile build
// context cannot push its entry count past the production entry ceiling.
// The refusal must happen while enumerating the over-ceiling directory —
// before any of its entries materialize — and must leave no operation tree.
// Pre-fix the whole directory was enumerated into an unbounded slice and
// every entry was staged successfully.
func TestStageBuildContextEntriesOverCeiling(t *testing.T) {
	workspace, runtimeDir := setupStagingTest(t)
	ctxDir := createBuildContext(t, workspace)

	const entryCeiling = 50000 // proposed production entry ceiling
	// Dockerfile plus entryCeiling zero-byte regular files: one entry over.
	for i := 0; i < entryCeiling; i++ {
		if err := os.WriteFile(filepath.Join(ctxDir, fmt.Sprintf("f%06d", i)), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	created := map[string]bool{}
	hooks := &stagingHooks{
		afterCreateDest: func(name string) error {
			created[name] = true
			return nil
		},
	}

	_, err := stageBuildContextInternal(context.Background(), workspace, abs(t, ctxDir), "Dockerfile", runtimeDir, "op1", defaultStagingSyscall(), hooks, productionBuildStagingCeilings)
	if err == nil {
		t.Fatal("expected the over-ceiling entry count to be refused, got success")
	}

	if created["f000000"] {
		t.Error("over-ceiling directory entries were materialized; the enumeration must refuse before any destination creation")
	}

	if _, err := os.Stat(filepath.Join(runtimeDir, "builds", "op1")); err == nil {
		t.Error("operation directory should be cleaned up after the entry-ceiling refusal")
	}
}

// TestStageBuildContextDepthOverCeiling proves a single hostile build
// context cannot descend past the production depth ceiling: the over-deep
// directory must be refused before its destination mkdir and before the
// recursive descent into it, and the refusal must leave no operation tree.
// Pre-fix the traversal recursed as deep as the source tree goes.
func TestStageBuildContextDepthOverCeiling(t *testing.T) {
	workspace, runtimeDir := setupStagingTest(t)
	ctxDir := createBuildContext(t, workspace)

	const depthCeiling = 64 // proposed production depth ceiling
	deepDir := ctxDir
	for i := 0; i < depthCeiling+1; i++ {
		deepDir = filepath.Join(deepDir, fmt.Sprintf("d%02d", i))
	}
	if err := os.MkdirAll(deepDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(deepDir, "deep.txt"), []byte("deep\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	visited := map[string]bool{}
	hooks := &stagingHooks{
		betweenStatAndOpen: func(name string) error {
			visited[name] = true
			return nil
		},
	}

	_, err := stageBuildContextInternal(context.Background(), workspace, abs(t, ctxDir), "Dockerfile", runtimeDir, "op1", defaultStagingSyscall(), hooks, productionBuildStagingCeilings)
	if err == nil {
		t.Fatal("expected the over-ceiling depth to be refused, got success")
	}

	if visited["deep.txt"] {
		t.Error("descent continued below the depth ceiling; the over-deep directory must be refused before recursive descent")
	}

	if _, err := os.Stat(filepath.Join(runtimeDir, "builds", "op1")); err == nil {
		t.Error("operation directory should be cleaned up after the depth-ceiling refusal")
	}
}

// --- H4 exact boundary semantics (injected tiny ceilings) --------------------
//
// The production ceilings are too large for exact boundary fixtures, so the
// boundary tests below inject tiny ceilings through stageBuildContextInternal
// and exercise the real descriptor-relative walker unchanged.

// stageWithCeilings runs the real staging walker with injected ceilings.
func stageWithCeilings(t *testing.T, workspace, ctxDir, dockerfileRel, runtimeDir, operationID string, ceilings buildStagingCeilings, hooks *stagingHooks) (*stagedBuildContext, error) {
	t.Helper()
	return stageBuildContextInternal(context.Background(), workspace, abs(t, ctxDir), dockerfileRel, runtimeDir, operationID, defaultStagingSyscall(), hooks, ceilings)
}

// requireCeilingError asserts the typed ceiling refusal and its dimension.
func requireCeilingError(t *testing.T, err error, resource string) *buildStagingCeilingError {
	t.Helper()
	if err == nil {
		t.Fatal("expected a staging ceiling refusal, got success")
	}
	var ceilingErr *buildStagingCeilingError
	if !errors.As(err, &ceilingErr) {
		t.Fatalf("expected typed staging ceiling error, got: %v", err)
	}
	if ceilingErr.Resource != resource {
		t.Errorf("ceiling resource = %q, want %q", ceilingErr.Resource, resource)
	}
	return ceilingErr
}

// requireNoOperationTree asserts the staging refusal left no operation tree
// under runtime/builds.
func requireNoOperationTree(t *testing.T, runtimeDir, operationID string) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(runtimeDir, "builds", operationID)); err == nil {
		t.Error("operation directory should be cleaned up after the ceiling refusal")
	}
}

// TestStagingBudgetBytesExactlyAtLimitSucceeds proves the byte ceiling
// accepts a context whose total staged payload is exactly at the ceiling.
func TestStagingBudgetBytesExactlyAtLimitSucceeds(t *testing.T) {
	workspace, runtimeDir := setupStagingTest(t)
	ctxDir := createBuildContext(t, workspace)
	if err := os.Remove(filepath.Join(ctxDir, "app.go")); err != nil {
		t.Fatal(err)
	}

	dfSt, err := os.Stat(filepath.Join(ctxDir, "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	const fileSize = 64
	if err := os.WriteFile(filepath.Join(ctxDir, "a.bin"), make([]byte, fileSize), 0o644); err != nil {
		t.Fatal(err)
	}

	ceilings := buildStagingCeilings{MaxBytes: dfSt.Size() + fileSize, MaxEntries: 2, MaxDepth: 4}
	staged, err := stageWithCeilings(t, workspace, ctxDir, "Dockerfile", runtimeDir, "op1", ceilings, nil)
	if err != nil {
		t.Fatalf("exactly-at-limit staging must succeed: %v", err)
	}
	defer staged.Cleanup()

	got, err := os.ReadFile(filepath.Join(staged.ContextPath, "a.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(got)) != fileSize {
		t.Errorf("staged payload = %d bytes, want %d", len(got), fileSize)
	}
}

// TestStagingBudgetBytesOneOverRefusedBeforeDestination proves one byte over
// the byte ceiling is refused before the over-ceiling payload's destination
// entry is created or written, and that the refusal leaves no operation
// tree or source modification.
func TestStagingBudgetBytesOneOverRefusedBeforeDestination(t *testing.T) {
	workspace, runtimeDir := setupStagingTest(t)
	ctxDir := createBuildContext(t, workspace)
	if err := os.Remove(filepath.Join(ctxDir, "app.go")); err != nil {
		t.Fatal(err)
	}

	dfSt, err := os.Stat(filepath.Join(ctxDir, "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	const fileSize = 64
	payload := make([]byte, fileSize)
	for i := range payload {
		payload[i] = byte(i)
	}
	if err := os.WriteFile(filepath.Join(ctxDir, "a.bin"), payload, 0o644); err != nil {
		t.Fatal(err)
	}

	copied := false
	created := false
	hooks := &stagingHooks{
		duringCopy: func(name string, copiedBytes int64) error {
			if name == "a.bin" {
				copied = true
			}
			return nil
		},
		afterCreateDest: func(name string) error {
			if name == "a.bin" {
				created = true
			}
			return nil
		},
	}

	ceilings := buildStagingCeilings{MaxBytes: dfSt.Size() + fileSize - 1, MaxEntries: 2, MaxDepth: 4}
	_, err = stageWithCeilings(t, workspace, ctxDir, "Dockerfile", runtimeDir, "op1", ceilings, hooks)
	requireCeilingError(t, err, "bytes")

	if copied {
		t.Error("over-ceiling payload began copying; refusal must happen before any destination payload write")
	}
	if created {
		t.Error("over-ceiling payload destination entry was created; refusal must happen before destination creation")
	}

	// The source payload must be unchanged.
	got, err := os.ReadFile(filepath.Join(ctxDir, "a.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != fileSize {
		t.Errorf("source file changed: %d bytes", len(got))
	}

	requireNoOperationTree(t, runtimeDir, "op1")
}

// TestStagingBudgetSparseLogicalSizeRefused proves a sparse source file is
// accounted by its logical size (st_size): a sparse file whose st_size
// exceeds the remaining byte budget is refused without materializing the
// hole, and the source stays sparse.
func TestStagingBudgetSparseLogicalSizeRefused(t *testing.T) {
	workspace, runtimeDir := setupStagingTest(t)
	ctxDir := createBuildContext(t, workspace)
	if err := os.Remove(filepath.Join(ctxDir, "app.go")); err != nil {
		t.Fatal(err)
	}

	dfSt, err := os.Stat(filepath.Join(ctxDir, "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	sparseHostileFile(t, filepath.Join(ctxDir, "sparse.bin"), dfSt.Size()+1024)

	copied := false
	hooks := &stagingHooks{
		duringCopy: func(name string, copiedBytes int64) error {
			if name == "sparse.bin" {
				copied = true
			}
			return nil
		},
	}

	ceilings := buildStagingCeilings{MaxBytes: dfSt.Size() + 1023, MaxEntries: 2, MaxDepth: 4}
	_, err = stageWithCeilings(t, workspace, ctxDir, "Dockerfile", runtimeDir, "op1", ceilings, hooks)
	requireCeilingError(t, err, "bytes")

	if copied {
		t.Error("sparse hole began materializing; the logical-size reservation must refuse before any copy")
	}

	st, err := os.Stat(filepath.Join(ctxDir, "sparse.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() != dfSt.Size()+1024 {
		t.Errorf("source sparse file changed size: %d", st.Size())
	}
	if sys := st.Sys().(*syscall.Stat_t); sys.Blocks > 64 {
		t.Errorf("source sparse file was materialized: %d blocks", sys.Blocks)
	}

	requireNoOperationTree(t, runtimeDir, "op1")
}

// TestStagingBudgetBytesOverflowRefused proves the byte admission arithmetic
// cannot overflow into acceptance: a sparse source file with a near-max
// st_size is refused by the before-comparison check, where a
// "used += requested" implementation would wrap int64 and accept.
func TestStagingBudgetBytesOverflowRefused(t *testing.T) {
	workspace, runtimeDir := setupStagingTest(t)
	ctxDir := createBuildContext(t, workspace)
	if err := os.Remove(filepath.Join(ctxDir, "app.go")); err != nil {
		t.Fatal(err)
	}

	sparseHostileFile(t, filepath.Join(ctxDir, "huge.bin"), math.MaxInt64)

	ceilings := buildStagingCeilings{MaxBytes: 4096, MaxEntries: 2, MaxDepth: 4}
	_, err := stageWithCeilings(t, workspace, ctxDir, "Dockerfile", runtimeDir, "op1", ceilings, nil)
	ceilingErr := requireCeilingError(t, err, "bytes")

	if ceilingErr.Attempted != math.MaxInt64 {
		t.Errorf("attempted reservation = %d, want math.MaxInt64 (the refused resource value)", ceilingErr.Attempted)
	}

	requireNoOperationTree(t, runtimeDir, "op1")
}

// TestStagingBudgetHardlinkPayloadCountedOnce proves a unique regular-file
// inode's payload is reserved exactly once: the byte ceiling only needs
// room for the first staged copy, and the hardlink name still stages
// correctly (same staged inode, same content).
func TestStagingBudgetHardlinkPayloadCountedOnce(t *testing.T) {
	workspace, runtimeDir := setupStagingTest(t)
	ctxDir := createBuildContext(t, workspace)
	if err := os.Remove(filepath.Join(ctxDir, "app.go")); err != nil {
		t.Fatal(err)
	}

	dfSt, err := os.Stat(filepath.Join(ctxDir, "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	const payloadSize = 128
	if err := os.WriteFile(filepath.Join(ctxDir, "original.bin"), make([]byte, payloadSize), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(ctxDir, "original.bin"), filepath.Join(ctxDir, "hardlink.bin")); err != nil {
		t.Fatal(err)
	}

	// Exactly enough bytes for the Dockerfile and ONE copy of the payload:
	// a double reservation would refuse.
	ceilings := buildStagingCeilings{MaxBytes: dfSt.Size() + payloadSize, MaxEntries: 3, MaxDepth: 4}
	staged, err := stageWithCeilings(t, workspace, ctxDir, "Dockerfile", runtimeDir, "op1", ceilings, nil)
	if err != nil {
		t.Fatalf("hardlink payload must be reserved once, not per name: %v", err)
	}
	defer staged.Cleanup()

	origInfo, err := os.Stat(filepath.Join(staged.ContextPath, "original.bin"))
	if err != nil {
		t.Fatal(err)
	}
	linkInfo, err := os.Stat(filepath.Join(staged.ContextPath, "hardlink.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if origInfo.Sys().(*syscall.Stat_t).Ino != linkInfo.Sys().(*syscall.Stat_t).Ino {
		t.Error("staged hardlink pair lost its single staged inode")
	}
}

// TestStagingBudgetHardlinkNameConsumesEntry proves a hardlink directory
// entry consumes its own entry slot even though it does not duplicate the
// file payload inode.
func TestStagingBudgetHardlinkNameConsumesEntry(t *testing.T) {
	workspace, runtimeDir := setupStagingTest(t)
	ctxDir := createBuildContext(t, workspace)
	if err := os.Remove(filepath.Join(ctxDir, "app.go")); err != nil {
		t.Fatal(err)
	}

	dfSt, err := os.Stat(filepath.Join(ctxDir, "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	const payloadSize = 16
	if err := os.WriteFile(filepath.Join(ctxDir, "original.bin"), make([]byte, payloadSize), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(ctxDir, "original.bin"), filepath.Join(ctxDir, "hardlink.bin")); err != nil {
		t.Fatal(err)
	}

	// The entry budget covers the Dockerfile and the first copy only: the
	// hardlink name is refused as its own entry.
	ceilings := buildStagingCeilings{MaxBytes: dfSt.Size() + payloadSize, MaxEntries: 2, MaxDepth: 4}
	_, err = stageWithCeilings(t, workspace, ctxDir, "Dockerfile", runtimeDir, "op1", ceilings, nil)
	requireCeilingError(t, err, "entries")

	requireNoOperationTree(t, runtimeDir, "op1")
}

// TestStagingBudgetSymlinkAccounting proves a staged symlink is accounted
// by its target payload bytes and consumes its own entry slot.
func TestStagingBudgetSymlinkAccounting(t *testing.T) {
	workspace, runtimeDir := setupStagingTest(t)
	ctxDir := createBuildContext(t, workspace)
	if err := os.Remove(filepath.Join(ctxDir, "app.go")); err != nil {
		t.Fatal(err)
	}

	dfSt, err := os.Stat(filepath.Join(ctxDir, "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	target := "some-target"
	if err := os.Symlink(target, filepath.Join(ctxDir, "link")); err != nil {
		t.Fatal(err)
	}

	t.Run("target payload bytes counted", func(t *testing.T) {
		ceilings := buildStagingCeilings{MaxBytes: dfSt.Size() + int64(len(target)), MaxEntries: 2, MaxDepth: 4}
		staged, err := stageWithCeilings(t, workspace, ctxDir, "Dockerfile", runtimeDir, "op1", ceilings, nil)
		if err != nil {
			t.Fatalf("symlink target bytes must be reserved exactly: %v", err)
		}
		staged.Cleanup()
	})

	t.Run("one target byte over refuses", func(t *testing.T) {
		ceilings := buildStagingCeilings{MaxBytes: dfSt.Size() + int64(len(target)) - 1, MaxEntries: 2, MaxDepth: 4}
		_, err := stageWithCeilings(t, workspace, ctxDir, "Dockerfile", runtimeDir, "op1", ceilings, nil)
		requireCeilingError(t, err, "bytes")
		requireNoOperationTree(t, runtimeDir, "op1")
	})

	t.Run("symlink consumes an entry", func(t *testing.T) {
		ceilings := buildStagingCeilings{MaxBytes: dfSt.Size() + int64(len(target)), MaxEntries: 1, MaxDepth: 4}
		_, err := stageWithCeilings(t, workspace, ctxDir, "Dockerfile", runtimeDir, "op1", ceilings, nil)
		requireCeilingError(t, err, "entries")
		requireNoOperationTree(t, runtimeDir, "op1")
	})
}

// entriesAtLimitFixture builds a five-entry context: Dockerfile, one
// directory, one regular file, one symlink, one hardlink name — every
// attacker-variable entry kind the walker materializes.
func entriesAtLimitFixture(t *testing.T, ctxDir string) {
	t.Helper()
	if err := os.Remove(filepath.Join(ctxDir, "app.go")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(ctxDir, "subdir"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ctxDir, "file.bin"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("file.bin", filepath.Join(ctxDir, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(ctxDir, "file.bin"), filepath.Join(ctxDir, "alias.bin")); err != nil {
		t.Fatal(err)
	}
}

// TestStagingBudgetEntriesExactlyAtLimitSucceeds proves the entry ceiling
// accepts a context with exactly the ceiling's number of entries, counting
// regular files, directories, symlinks and hardlink names alike.
func TestStagingBudgetEntriesExactlyAtLimitSucceeds(t *testing.T) {
	workspace, runtimeDir := setupStagingTest(t)
	ctxDir := createBuildContext(t, workspace)
	entriesAtLimitFixture(t, ctxDir)

	ceilings := buildStagingCeilings{MaxBytes: 1 << 20, MaxEntries: 5, MaxDepth: 4}
	staged, err := stageWithCeilings(t, workspace, ctxDir, "Dockerfile", runtimeDir, "op1", ceilings, nil)
	if err != nil {
		t.Fatalf("exactly-at-limit entry count must succeed: %v", err)
	}
	defer staged.Cleanup()

	for _, name := range []string{"subdir", "file.bin", "link", "alias.bin"} {
		if _, err := os.Lstat(filepath.Join(staged.ContextPath, name)); err != nil {
			t.Errorf("staged entry %s missing: %v", name, err)
		}
	}
}

// TestStagingBudgetEntriesOneOverRefused proves one entry over the ceiling
// is refused with the typed entries ceiling error and leaves no operation
// tree.
func TestStagingBudgetEntriesOneOverRefused(t *testing.T) {
	workspace, runtimeDir := setupStagingTest(t)
	ctxDir := createBuildContext(t, workspace)
	entriesAtLimitFixture(t, ctxDir)

	ceilings := buildStagingCeilings{MaxBytes: 1 << 20, MaxEntries: 4, MaxDepth: 4}
	_, err := stageWithCeilings(t, workspace, ctxDir, "Dockerfile", runtimeDir, "op1", ceilings, nil)
	requireCeilingError(t, err, "entries")

	requireNoOperationTree(t, runtimeDir, "op1")
}

// TestStagingBudgetEnumerationRefusesShallowSiblingsByEntries proves the
// enumeration itself is bounded: a directory with more entries than the
// remaining entry budget is refused during enumeration — before ANY of its
// entries is materialized — and a shallow tree with many siblings is
// governed by the entry ceiling, not the depth ceiling.
func TestStagingBudgetEnumerationRefusesShallowSiblingsByEntries(t *testing.T) {
	workspace, runtimeDir := setupStagingTest(t)
	ctxDir := createBuildContext(t, workspace)

	sub := filepath.Join(ctxDir, "sub")
	if err := os.Remove(filepath.Join(ctxDir, "app.go")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		if err := os.WriteFile(filepath.Join(sub, fmt.Sprintf("f%d", i)), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// Entry budget: Dockerfile + the sub directory itself + one sibling.
	// Depth ceiling 1 admits the shallow sub directory, so a depth refusal
	// would be wrong here: the refusal must come from the entry ceiling,
	// during the sub directory's enumeration.
	ceilings := buildStagingCeilings{MaxBytes: 1 << 20, MaxEntries: 3, MaxDepth: 1}

	created := map[string]bool{}
	hooks := &stagingHooks{
		afterCreateDest: func(name string) error {
			created[name] = true
			return nil
		},
	}

	_, err := stageWithCeilings(t, workspace, ctxDir, "Dockerfile", runtimeDir, "op1", ceilings, hooks)
	ceilingErr := requireCeilingError(t, err, "entries")

	if ceilingErr.Ceiling != 3 {
		t.Errorf("entries ceiling = %d, want 3", ceilingErr.Ceiling)
	}
	for i := 0; i < 10; i++ {
		if created[fmt.Sprintf("f%d", i)] {
			t.Errorf("sub directory entry f%d was materialized; the enumeration must refuse before any destination creation", i)
		}
	}

	requireNoOperationTree(t, runtimeDir, "op1")
}

// TestStagingBudgetDepthExactlyAtLimitSucceeds proves the depth ceiling
// accepts a directory chain that reaches exactly the ceiling: the context
// root is depth 0 and a direct child is depth 1, so directories up to
// MaxDepth stage successfully (files may sit one level deeper than the
// deepest directory).
func TestStagingBudgetDepthExactlyAtLimitSucceeds(t *testing.T) {
	workspace, runtimeDir := setupStagingTest(t)
	ctxDir := createBuildContext(t, workspace)

	const maxDepth = 8
	deepDir := ctxDir
	for i := 0; i < maxDepth; i++ {
		deepDir = filepath.Join(deepDir, fmt.Sprintf("d%02d", i))
	}
	if err := os.MkdirAll(deepDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(deepDir, "deep.txt"), []byte("deep\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	ceilings := buildStagingCeilings{MaxBytes: 1 << 20, MaxEntries: 1 << 20, MaxDepth: maxDepth}
	staged, err := stageWithCeilings(t, workspace, ctxDir, "Dockerfile", runtimeDir, "op1", ceilings, nil)
	if err != nil {
		t.Fatalf("exactly-at-limit depth must succeed: %v", err)
	}
	defer staged.Cleanup()

	deepStaged := staged.ContextPath
	for i := 0; i < maxDepth; i++ {
		deepStaged = filepath.Join(deepStaged, fmt.Sprintf("d%02d", i))
	}
	if _, err := os.Stat(filepath.Join(deepStaged, "deep.txt")); err != nil {
		t.Errorf("deep file missing from staging: %v", err)
	}
}

// TestStagingBudgetDepthOneOverRefusedBeforeDescent proves a directory one
// level deeper than the ceiling is refused before its destination mkdir and
// before the recursive descent into it: the file below the over-deep
// directory is never reached, and the refusal leaves no operation tree.
func TestStagingBudgetDepthOneOverRefusedBeforeDescent(t *testing.T) {
	workspace, runtimeDir := setupStagingTest(t)
	ctxDir := createBuildContext(t, workspace)

	const maxDepth = 8
	deepDir := ctxDir
	for i := 0; i < maxDepth+1; i++ {
		deepDir = filepath.Join(deepDir, fmt.Sprintf("d%02d", i))
	}
	if err := os.MkdirAll(deepDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(deepDir, "deep.txt"), []byte("deep\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	visited := map[string]bool{}
	hooks := &stagingHooks{
		betweenStatAndOpen: func(name string) error {
			visited[name] = true
			return nil
		},
	}

	ceilings := buildStagingCeilings{MaxBytes: 1 << 20, MaxEntries: 1 << 20, MaxDepth: maxDepth}
	_, err := stageWithCeilings(t, workspace, ctxDir, "Dockerfile", runtimeDir, "op1", ceilings, hooks)
	requireCeilingError(t, err, "depth")

	if visited["deep.txt"] {
		t.Error("descent continued into the over-deep directory; the depth refusal must happen before recursive descent")
	}

	requireNoOperationTree(t, runtimeDir, "op1")
}

// TestStagingBudgetDockerfileCounted proves the Dockerfile itself is inside
// the resource accounting: it consumes an entry slot and its payload bytes
// are reserved like any other staged file.
func TestStagingBudgetDockerfileCounted(t *testing.T) {
	workspace, runtimeDir := setupStagingTest(t)
	ctxDir := createBuildContext(t, workspace)
	if err := os.Remove(filepath.Join(ctxDir, "app.go")); err != nil {
		t.Fatal(err)
	}

	dfSt, err := os.Stat(filepath.Join(ctxDir, "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}

	// Exactly at the limit: one entry, exactly the Dockerfile's bytes.
	ceilings := buildStagingCeilings{MaxBytes: dfSt.Size(), MaxEntries: 1, MaxDepth: 4}
	staged, err := stageWithCeilings(t, workspace, ctxDir, "Dockerfile", runtimeDir, "op1", ceilings, nil)
	if err != nil {
		t.Fatalf("Dockerfile-only context at the exact ceilings must succeed: %v", err)
	}
	staged.Cleanup()

	// One byte under the ceiling: the Dockerfile payload is refused.
	ceilings = buildStagingCeilings{MaxBytes: dfSt.Size() - 1, MaxEntries: 1, MaxDepth: 4}
	_, err = stageWithCeilings(t, workspace, ctxDir, "Dockerfile", runtimeDir, "op1", ceilings, nil)
	requireCeilingError(t, err, "bytes")
	requireNoOperationTree(t, runtimeDir, "op1")
}

// TestStagingCeilingErrorSurvivesWrapping proves the typed ceiling refusal
// stays identifiable through error wrapping, as the build handler
// classification requires: errors.As recovers the typed fields and
// errors.Is matches any refusal of the same exhausted resource.
func TestStagingCeilingErrorSurvivesWrapping(t *testing.T) {
	sentinel := &buildStagingCeilingError{Resource: "entries", Ceiling: 3, Attempted: 4}
	wrapped := fmt.Errorf("cannot read directory: %w", fmt.Errorf("cannot copy directory sub: %w", sentinel))

	var ceilingErr *buildStagingCeilingError
	if !errors.As(wrapped, &ceilingErr) {
		t.Fatal("errors.As must find the ceiling error through wrapping")
	}
	if ceilingErr.Resource != "entries" || ceilingErr.Ceiling != 3 || ceilingErr.Attempted != 4 {
		t.Errorf("typed fields lost through wrapping: %+v", ceilingErr)
	}

	if !errors.Is(wrapped, &buildStagingCeilingError{Resource: "entries"}) {
		t.Error("errors.Is must match the same exhausted resource through wrapping")
	}
	if errors.Is(wrapped, &buildStagingCeilingError{Resource: "bytes"}) {
		t.Error("errors.Is must not match a different exhausted resource")
	}
}
