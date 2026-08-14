package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

// stagedBuildContext represents a successfully staged build context.
type stagedBuildContext struct {
	ContextPath    string
	DockerfilePath string
	cleanupOnce    sync.Once
}

// Cleanup removes the staging directory. It is idempotent and concurrency-safe.
func (s *stagedBuildContext) Cleanup() {
	s.cleanupOnce.Do(func() {
		os.RemoveAll(s.ContextPath)
	})
}

// stagingSyscall is a seam for testing ENOSYS/EPERM behavior.
type stagingSyscall struct {
	Openat2 func(dirfd int, path string, how *unix.OpenHow) (int, error)
}

// defaultStagingSyscall returns the real openat2 syscall.
func defaultStagingSyscall() stagingSyscall {
	return stagingSyscall{
		Openat2: unix.Openat2,
	}
}

// isTraversalPath checks if a path contains traversal elements.
func isTraversalPath(path string) bool {
	if path == "" {
		return true
	}
	if filepath.IsAbs(path) {
		return true
	}
	// Check for .. components before cleaning.
	for _, part := range strings.Split(path, string(filepath.Separator)) {
		if part == ".." {
			return true
		}
	}
	cleaned := filepath.Clean(path)
	if cleaned == ".." || cleaned == "." || cleaned == "/" {
		return true
	}
	return false
}

// StageBuildContext creates an isolated copy of the build context in a staging directory.
// It uses FD-based traversal to prevent TOCTOU and symlink escape attacks.
func StageBuildContext(
	ctx context.Context,
	workspace string,
	contextPath string,
	dockerfileRel string,
	runtimeDir string,
	operationID string,
) (*stagedBuildContext, error) {
	return stageBuildContextWithSyscall(ctx, workspace, contextPath, dockerfileRel, runtimeDir, operationID, defaultStagingSyscall())
}

func stageBuildContextWithSyscall(
	ctx context.Context,
	workspace string,
	contextPath string,
	dockerfileRel string,
	runtimeDir string,
	operationID string,
	sy stagingSyscall,
) (*stagedBuildContext, error) {
	// Validate inputs are absolute.
	if !filepath.IsAbs(workspace) {
		return nil, fmt.Errorf("workspace must be absolute: %s", workspace)
	}
	if !filepath.IsAbs(contextPath) {
		return nil, fmt.Errorf("context path must be absolute: %s", contextPath)
	}
	if !filepath.IsAbs(runtimeDir) {
		return nil, fmt.Errorf("runtime dir must be absolute: %s", runtimeDir)
	}

	// Validate operationID against traversal.
	if isTraversalPath(operationID) {
		return nil, fmt.Errorf("operation ID contains traversal: %s", operationID)
	}

	// Validate dockerfileRel against traversal.
	if dockerfileRel == "" || isTraversalPath(dockerfileRel) {
		return nil, fmt.Errorf("dockerfile relative path invalid: %s", dockerfileRel)
	}
	dockerfileRel = filepath.Clean(dockerfileRel)
	if filepath.IsAbs(dockerfileRel) {
		return nil, fmt.Errorf("dockerfile relative path must not be absolute: %s", dockerfileRel)
	}

	// Resolve workspace and context path.
	workspace, err := filepath.EvalSymlinks(workspace)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve workspace: %w", err)
	}
	contextPath, err = filepath.EvalSymlinks(contextPath)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve context path: %w", err)
	}

	// Validate contextPath is inside workspace.
	if !isInside(workspace, contextPath) {
		return nil, fmt.Errorf("context path escapes workspace: %s", contextPath)
	}

	// Create staging directory.
	stagingDir := filepath.Join(runtimeDir, "builds", operationID, "context")
	if err := os.MkdirAll(stagingDir, 0o700); err != nil {
		return nil, fmt.Errorf("cannot create staging directory: %w", err)
	}

	// Open source context with openat2.
	sourceFD, err := openSourceContext(ctx, contextPath, sy)
	if err != nil {
		os.RemoveAll(filepath.Dir(stagingDir))
		return nil, err
	}
	defer unix.Close(sourceFD)

	// Open staging directory for FD-based creation.
	stagingRoot, err := unix.Openat(unix.AT_FDCWD, stagingDir, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		unix.Close(sourceFD)
		os.RemoveAll(filepath.Dir(stagingDir))
		return nil, fmt.Errorf("cannot open staging directory: %w", err)
	}
	defer unix.Close(stagingRoot)

	// Track hardlinks by (dev, ino).
	hardlinkMap := make(map[devIno]string)

	// Walk and copy.
	err = walkAndCopy(ctx, sourceFD, "", stagingRoot, "", hardlinkMap)
	if err != nil {
		unix.Close(sourceFD)
		unix.Close(stagingRoot)
		os.RemoveAll(filepath.Dir(stagingDir))
		return nil, err
	}

	// Verify Dockerfile exists in staging and is a regular file.
	dockerfileStagingPath := filepath.Join(stagingDir, dockerfileRel)
	dockerfileInfo, err := os.Lstat(dockerfileStagingPath)
	if err != nil {
		return nil, fmt.Errorf("Dockerfile not found in staging: %w", err)
	}
	if dockerfileInfo.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("Dockerfile in staging is a symlink")
	}
	if dockerfileInfo.Mode()&os.ModeType != 0 {
		return nil, fmt.Errorf("Dockerfile in staging is not a regular file")
	}

	return &stagedBuildContext{
		ContextPath:    stagingDir,
		DockerfilePath: dockerfileStagingPath,
	}, nil
}

// openSourceContext opens the source context directory with openat2.
func openSourceContext(ctx context.Context, path string, sy stagingSyscall) (int, error) {
	if sy.Openat2 == nil {
		return -1, fmt.Errorf("openat2 not available")
	}

	// Open the parent directory first, then use openat2 with the parent FD
	// and a relative path. This avoids RESOLVE_BENEATH restrictions when
	// the target path is outside the current working directory subtree.
	parentDir := filepath.Dir(path)
	baseName := filepath.Base(path)

	parentFD, err := unix.Openat(unix.AT_FDCWD, parentDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("cannot open parent directory: %w", err)
	}

	how := &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Mode:    0,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	}

	fd, err := sy.Openat2(parentFD, baseName, how)
	unix.Close(parentFD)
	if err != nil {
		if err == unix.ENOSYS || err == unix.EPERM {
			return -1, fmt.Errorf("openat2 not supported: %w (fail closed, no fallback)", err)
		}
		return -1, fmt.Errorf("cannot open source context: %w", err)
	}

	// Verify the opened FD is actually a directory.
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("cannot stat source context: %w", err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		unix.Close(fd)
		return -1, fmt.Errorf("source context is not a directory")
	}

	return fd, nil
}

// devIno represents a (device, inode) pair for hardlink tracking.
type devIno struct {
	dev uint64
	ino uint64
}

// walkAndCopy recursively walks the source directory and copies entries to staging.
func walkAndCopy(
	ctx context.Context,
	sourceFD int,
	sourceName string,
	stagingFD int,
	stagingName string,
	hardlinkMap map[devIno]string,
) error {
	// Check context cancellation.
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Read directory entries.
	entries, err := readDirectoryEntries(sourceFD)
	if err != nil {
		return fmt.Errorf("cannot read directory: %w", err)
	}

	for _, entry := range entries {
		name := entry.name
		if name == "." || name == ".." {
			continue
		}

		// Check context cancellation between entries.
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err := copyEntry(ctx, sourceFD, name, stagingFD, hardlinkMap); err != nil {
			return err
		}
	}

	return nil
}

// dirEntry represents a directory entry.
type dirEntry struct {
	name string
	ino  uint64
}

// readDirectoryEntries reads all entries from a directory FD.
func readDirectoryEntries(fd int) ([]dirEntry, error) {
	buf := make([]byte, 4096)
	var entries []dirEntry

	for {
		n, err := unix.Getdents(fd, buf)
		if err != nil {
			return entries, fmt.Errorf("cannot read directory: %w", err)
		}
		if n == 0 {
			break
		}

		// Parse getdents64 entries manually.
		// getdents64 layout: d_ino(8) + d_off(8) + d_reclen(2) + d_type(1) + d_name(var)
		// Total fixed header: 19 bytes, then name padded to 8-byte alignment.
		off := 0
		for off < n {
			if off+20 > n {
				break
			}

			entryStart := off

			// Parse the dirent64 header.
			ino := *(*uint64)(unsafe.Pointer(&buf[off]))
			off += 8 // d_ino
			off += 8 // d_off
			reclen := *(*uint16)(unsafe.Pointer(&buf[off]))
			off += 2 // d_reclen
			off++    // d_type (skip, not needed)

			if reclen == 0 || int(entryStart)+int(reclen) > n {
				break
			}

			// Name starts at offset 19 from entry start.
			nameStart := entryStart + 19
			nameLen := int(reclen) - 19
			if nameLen <= 0 || nameStart >= n {
				off = entryStart + int(reclen)
				continue
			}

			// Find the actual name length (strip trailing null bytes).
			nameEnd := 0
			for nameEnd < nameLen && nameStart+nameEnd < n && buf[nameStart+nameEnd] != 0 {
				nameEnd++
			}
			name := unix.ByteSliceToString(buf[nameStart : nameStart+nameEnd])

			if name != "." && name != ".." {
				entries = append(entries, dirEntry{
					name: name,
					ino:  ino,
				})
			}

			off = entryStart + int(reclen)
		}
	}

	return entries, nil
}

// copyEntry copies a single directory entry from source to staging.
func copyEntry(
	ctx context.Context,
	sourceDirFD int,
	name string,
	stagingDirFD int,
	hardlinkMap map[devIno]string,
) error {
	// Get entry stat without following symlinks.
	var st unix.Stat_t
	if err := unix.Fstatat(sourceDirFD, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("cannot stat entry %s: %w", name, err)
	}

	mode := st.Mode

	// Handle symlinks first (before type check).
	if mode&unix.S_IFMT == unix.S_IFLNK {
		return copySymlink(sourceDirFD, name, stagingDirFD, &st)
	}

	// Handle regular files.
	if mode&unix.S_IFMT == unix.S_IFREG {
		di := devIno{dev: st.Dev, ino: st.Ino}
		if target, ok := hardlinkMap[di]; ok {
			// Hardlink to previously copied file.
			return unix.Linkat(unix.AT_FDCWD, target, stagingDirFD, name, 0)
		}
		destPath, err := copyRegularFile(ctx, sourceDirFD, name, stagingDirFD, &st)
		if err != nil {
			return err
		}
		hardlinkMap[di] = destPath
		return nil
	}

	// Handle directories.
	if mode&unix.S_IFMT == unix.S_IFDIR {
		return copyDirectory(ctx, sourceDirFD, name, stagingDirFD, &st)
	}

	// Special files: fail closed.
	switch mode & unix.S_IFMT {
	case unix.S_IFIFO:
		return fmt.Errorf("FIFO not supported: %s", name)
	case unix.S_IFSOCK:
		return fmt.Errorf("socket not supported: %s", name)
	case unix.S_IFBLK:
		return fmt.Errorf("block device not supported: %s", name)
	case unix.S_IFCHR:
		return fmt.Errorf("character device not supported: %s", name)
	default:
		return fmt.Errorf("unsupported file type: %s", name)
	}
}

// copySymlink copies a symlink from source to staging.
func copySymlink(sourceDirFD int, name string, stagingDirFD int, st *unix.Stat_t) error {
	// Read symlink target via FD.
	buf := make([]byte, 4096)
	n, err := unix.Readlinkat(sourceDirFD, name, buf)
	if err != nil {
		return fmt.Errorf("cannot read symlink %s: %w", name, err)
	}
	target := unix.ByteSliceToString(buf[:n])

	// Create symlink in staging.
	if err := unix.Symlinkat(target, stagingDirFD, name); err != nil {
		return fmt.Errorf("cannot create symlink %s: %w", name, err)
	}

	// Preserve mtime.
	setTimesFromStat(stagingDirFD, name, st)

	return nil
}

// copyRegularFile copies a regular file from source to staging.
func copyRegularFile(ctx context.Context, sourceDirFD int, name string, stagingDirFD int, st *unix.Stat_t) (string, error) {
	// Open source file with O_PATH|O_NOFOLLOW first.
	oPathFD, err := unix.Openat(sourceDirFD, name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", fmt.Errorf("cannot O_PATH open %s: %w", name, err)
	}
	defer unix.Close(oPathFD)

	// Verify identity: compare dev+ino of O_PATH FD with original stat.
	var oPathSt unix.Stat_t
	if err := unix.Fstat(oPathFD, &oPathSt); err != nil {
		return "", fmt.Errorf("cannot stat O_PATH FD for %s: %w", name, err)
	}
	if oPathSt.Dev != st.Dev || oPathSt.Ino != st.Ino {
		return "", fmt.Errorf("identity mismatch for %s: file changed between stat and open", name)
	}

	// Reopen for reading.
	readFD, err := unix.Openat(sourceDirFD, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", fmt.Errorf("cannot open %s for reading: %w", name, err)
	}
	defer unix.Close(readFD)

	// Verify identity again after reopen.
	var readSt unix.Stat_t
	if err := unix.Fstat(readFD, &readSt); err != nil {
		return "", fmt.Errorf("cannot stat read FD for %s: %w", name, err)
	}
	if readSt.Dev != st.Dev || readSt.Ino != st.Ino {
		return "", fmt.Errorf("identity mismatch for %s: file changed between O_PATH and reopen", name)
	}

	// Create destination file with O_EXCL|O_NOFOLLOW.
	createFD, err := unix.Openat(stagingDirFD, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(st.Mode&0o777))
	if err != nil {
		return "", fmt.Errorf("cannot create %s in staging: %w", name, err)
	}
	defer unix.Close(createFD)

	// Copy file contents.
	if err := copyFileContents(ctx, readFD, createFD, st.Size); err != nil {
		unix.Unlinkat(stagingDirFD, name, 0)
		unix.Close(createFD)
		return "", fmt.Errorf("cannot copy %s: %w", name, err)
	}

	// Preserve permissions.
	unix.Fchmod(createFD, uint32(st.Mode&0o7777))

	// Preserve mtime.
	setTimesFromStat(stagingDirFD, name, st)

	// Return the destination path for hardlink tracking.
	destPath := fmt.Sprintf("/proc/self/fd/%d/%s", stagingDirFD, name)
	return destPath, nil
}

// copyDirectory copies a directory from source to staging, recursively.
func copyDirectory(ctx context.Context, sourceDirFD int, name string, stagingDirFD int, st *unix.Stat_t) error {
	// Open source directory with O_PATH|O_NOFOLLOW first.
	oPathFD, err := unix.Openat(sourceDirFD, name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("cannot O_PATH open directory %s: %w", name, err)
	}
	defer unix.Close(oPathFD)

	// Verify identity.
	var oPathSt unix.Stat_t
	if err := unix.Fstat(oPathFD, &oPathSt); err != nil {
		return fmt.Errorf("cannot stat O_PATH FD for directory %s: %w", name, err)
	}
	if oPathSt.Dev != st.Dev || oPathSt.Ino != st.Ino {
		return fmt.Errorf("identity mismatch for directory %s: changed between stat and open", name)
	}

	// Create destination directory with O_EXCL.
	if err := unix.Mkdirat(stagingDirFD, name, uint32(st.Mode&0o777)); err != nil {
		return fmt.Errorf("cannot create directory %s in staging: %w", name, err)
	}

	// Open destination directory for recursive copy.
	destFD, err := unix.Openat(stagingDirFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		unix.Unlinkat(stagingDirFD, name, unix.AT_REMOVEDIR)
		return fmt.Errorf("cannot open destination directory %s: %w", name, err)
	}

	// Open source directory for reading entries.
	sourceReadFD, err := unix.Openat(sourceDirFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		unix.Close(destFD)
		unix.Unlinkat(stagingDirFD, name, unix.AT_REMOVEDIR)
		return fmt.Errorf("cannot open source directory %s for reading: %w", name, err)
	}

	// Verify identity again after reopen.
	var sourceReadSt unix.Stat_t
	if err := unix.Fstat(sourceReadFD, &sourceReadSt); err != nil {
		unix.Close(destFD)
		unix.Close(sourceReadFD)
		unix.Unlinkat(stagingDirFD, name, unix.AT_REMOVEDIR)
		return fmt.Errorf("cannot stat reopened source directory %s: %w", name, err)
	}
	if sourceReadSt.Dev != st.Dev || sourceReadSt.Ino != st.Ino {
		unix.Close(destFD)
		unix.Close(sourceReadFD)
		unix.Unlinkat(stagingDirFD, name, unix.AT_REMOVEDIR)
		return fmt.Errorf("identity mismatch for directory %s: changed between O_PATH and reopen", name)
	}

	// Recursively copy contents.
	hardlinkMap := make(map[devIno]string)
	err = walkAndCopy(ctx, sourceReadFD, name, destFD, name, hardlinkMap)

	unix.Close(sourceReadFD)
	unix.Close(destFD)

	if err != nil {
		// Remove partially created directory.
		removeAllAt(stagingDirFD, name)
		return fmt.Errorf("cannot copy directory %s: %w", name, err)
	}

	// Restore directory mtime after children are copied.
	setTimesFromStat(stagingDirFD, name, st)

	return nil
}

// copyFileContents copies file contents from srcFD to dstFD.
func copyFileContents(ctx context.Context, srcFD int, dstFD int, size int64) error {
	off := int64(0)
	const chunkSize = 128 * 1024 // 128 KiB chunks

	for off < size {
		// Check context cancellation.
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		chunk := int64(chunkSize)
		if off+chunk > size {
			chunk = size - off
		}

		// Try copy_file_range first.
		srcOff := off
		copied, err := unix.CopyFileRange(srcFD, &srcOff, dstFD, nil, int(chunk), 0)
		if err != nil {
			// Fallback to regular copy.
			buf := make([]byte, chunk)
			n, readErr := unix.Read(srcFD, buf)
			if readErr != nil {
				return fmt.Errorf("cannot read: %w", readErr)
			}
			if int64(n) != chunk {
				return fmt.Errorf("short read: expected %d, got %d", chunk, n)
			}

			// Write in chunks.
			wn := 0
			for wn < n {
				w, writeErr := unix.Write(dstFD, buf[wn:n])
				if writeErr != nil {
					return fmt.Errorf("cannot write: %w", writeErr)
				}
				wn += w
			}
			off += int64(n)
		} else if copied > 0 {
			off += int64(copied)
		} else {
			// copy_file_range returned 0, use fallback.
			buf := make([]byte, chunk)
			n, readErr := unix.Read(srcFD, buf)
			if readErr != nil {
				return fmt.Errorf("cannot read: %w", readErr)
			}
			if int64(n) != chunk {
				return fmt.Errorf("short read: expected %d, got %d", chunk, n)
			}

			wn := 0
			for wn < n {
				w, writeErr := unix.Write(dstFD, buf[wn:n])
				if writeErr != nil {
					return fmt.Errorf("cannot write: %w", writeErr)
				}
				wn += w
			}
			off += int64(n)
		}
	}

	return nil
}

// setTimesFromStat sets atime/mtime on a file referenced by dirFD/name.
func setTimesFromStat(dirFD int, name string, st *unix.Stat_t) {
	ts := []unix.Timespec{
		{Sec: st.Atim.Sec, Nsec: st.Atim.Nsec},
		{Sec: st.Mtim.Sec, Nsec: st.Mtim.Nsec},
	}
	unix.UtimesNanoAt(dirFD, name, ts, unix.AT_SYMLINK_NOFOLLOW)
}

// removeAllAt recursively removes a directory tree referenced by dirFD/name.
func removeAllAt(dirFD int, name string) {
	removeAllAtRecursive(dirFD, name)
	unix.Unlinkat(dirFD, name, unix.AT_REMOVEDIR)
}

func removeAllAtRecursive(dirFD int, name string) {
	// Open the directory.
	fd, err := unix.Openat(dirFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return
	}
	defer unix.Close(fd)

	// Read entries and remove them.
	entries, err := readDirectoryEntries(fd)
	if err != nil {
		return
	}

	for _, entry := range entries {
		entryName := entry.name

		// Stat the entry.
		var st unix.Stat_t
		if err := unix.Fstatat(fd, entryName, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			continue
		}

		if st.Mode&unix.S_IFMT == unix.S_IFDIR {
			removeAllAtRecursive(fd, entryName)
			unix.Unlinkat(fd, entryName, unix.AT_REMOVEDIR)
		} else {
			unix.Unlinkat(fd, entryName, 0)
		}
	}
}
