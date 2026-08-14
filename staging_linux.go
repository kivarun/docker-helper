//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

// stagedBuildContext represents a successfully staged build context.
type stagedBuildContext struct {
	ContextPath    string
	DockerfilePath string
	cleanupPath    string
	cleanupOnce    sync.Once
}

// Cleanup removes the staging directory. It is idempotent and concurrency-safe.
func (s *stagedBuildContext) Cleanup() {
	s.cleanupOnce.Do(func() {
		os.RemoveAll(s.cleanupPath)
	})
}

// stagingHooks allows tests to inject behavior between critical operations.
type stagingHooks struct {
	betweenStatAndOpen    func(name string) error
	betweenOPATHAndReopen func(name string) error
	afterCreateDest       func(name string) error
	duringCopy            func(name string, copied int64) error
}

// stagingSyscall is a seam for testing ENOSYS/EPERM behavior.
type stagingSyscall struct {
	Openat2 func(dirfd int, path string, how *unix.OpenHow) (int, error)
}

func defaultStagingSyscall() stagingSyscall {
	return stagingSyscall{Openat2: unix.Openat2}
}

// StageBuildContext creates an isolated copy of the build context in a staging directory.
func StageBuildContext(
	ctx context.Context,
	workspace string,
	contextPath string,
	dockerfileRel string,
	runtimeDir string,
	operationID string,
) (*stagedBuildContext, error) {
	return stageBuildContextInternal(ctx, workspace, contextPath, dockerfileRel, runtimeDir, operationID, defaultStagingSyscall(), nil)
}

func stageBuildContextInternal(
	ctx context.Context,
	workspace string,
	contextPath string,
	dockerfileRel string,
	runtimeDir string,
	operationID string,
	sy stagingSyscall,
	hooks *stagingHooks,
) (*stagedBuildContext, error) {
	if sy.Openat2 == nil {
		return nil, fmt.Errorf("openat2 not available")
	}

	if !filepath.IsAbs(workspace) {
		return nil, fmt.Errorf("workspace must be absolute: %s", workspace)
	}
	if !filepath.IsAbs(contextPath) {
		return nil, fmt.Errorf("context path must be absolute: %s", contextPath)
	}
	if !filepath.IsAbs(runtimeDir) {
		return nil, fmt.Errorf("runtime dir must be absolute: %s", runtimeDir)
	}

	if !isOperationIDSafe(operationID) {
		return nil, fmt.Errorf("invalid operation ID: %q", operationID)
	}

	if dockerfileRel == "" {
		return nil, fmt.Errorf("dockerfile relative path is required")
	}
	if filepath.IsAbs(dockerfileRel) {
		return nil, fmt.Errorf("dockerfile relative path must not be absolute: %s", dockerfileRel)
	}
	for _, part := range filepath.SplitList(dockerfileRel) {
		if part == ".." {
			return nil, fmt.Errorf("dockerfile relative path contains traversal: %s", dockerfileRel)
		}
	}
	dockerfileRel = filepath.Clean(dockerfileRel)

	// Open / with O_PATH | O_DIRECTORY | O_CLOEXEC.
	rootFD, err := sy.Openat2(unix.AT_FDCWD, "/", &unix.OpenHow{
		Flags: unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
	})
	if err != nil {
		return nil, fmt.Errorf("openat2(/): %w", err)
	}
	defer unix.Close(rootFD)

	// Pin workspace via openat2 with RESOLVE_NO_SYMLINKS.
	relWorkspace, err := filepath.Rel("/", workspace)
	if err != nil {
		return nil, fmt.Errorf("cannot compute workspace relative to /: %w", err)
	}
	workspaceFD, err := sy.Openat2(rootFD, relWorkspace, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		if err == unix.ENOSYS || err == unix.EPERM {
			return nil, fmt.Errorf("openat2 not supported: %w (fail closed, no fallback)", err)
		}
		return nil, fmt.Errorf("cannot pin workspace: %w", err)
	}
	defer unix.Close(workspaceFD)

	var wsSt unix.Stat_t
	if err := unix.Fstat(workspaceFD, &wsSt); err != nil {
		return nil, fmt.Errorf("cannot stat workspace: %w", err)
	}
	if wsSt.Mode&unix.S_IFMT != unix.S_IFDIR {
		return nil, fmt.Errorf("workspace is not a directory")
	}

	// Compute context path relative to workspace.
	relContext, err := filepath.Rel(workspace, contextPath)
	if err != nil {
		return nil, fmt.Errorf("cannot compute context relative to workspace: %w", err)
	}
	if relContext == ".." || filepath.IsAbs(relContext) {
		return nil, fmt.Errorf("context path escapes workspace: %s", contextPath)
	}
	for _, part := range filepath.SplitList(relContext) {
		if part == ".." {
			return nil, fmt.Errorf("context path escapes workspace: %s", contextPath)
		}
	}

	// Open source context via workspace FD with openat2.
	sourceFD, err := sy.Openat2(workspaceFD, relContext, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		if err == unix.ENOSYS || err == unix.EPERM {
			return nil, fmt.Errorf("openat2 not supported: %w (fail closed, no fallback)", err)
		}
		return nil, fmt.Errorf("cannot open source context: %w", err)
	}
	defer unix.Close(sourceFD)

	// Create operation directory exclusively.
	opDir := filepath.Join(runtimeDir, "builds", operationID)
	if err := os.MkdirAll(filepath.Dir(opDir), 0o700); err != nil {
		return nil, fmt.Errorf("cannot create parent directories: %w", err)
	}

	// Reject if opDir path already exists (including symlinks).
	if info, err := os.Lstat(opDir); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("operation directory is a symlink: %s", opDir)
		}
		return nil, fmt.Errorf("operation directory already exists: %s", opDir)
	}

	if err := os.Mkdir(opDir, 0o700); err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("operation directory already exists: %s", opDir)
		}
		return nil, fmt.Errorf("cannot create operation directory: %w", err)
	}

	// Create staging directory.
	stagingDir := filepath.Join(opDir, "context")
	if err := os.Mkdir(stagingDir, 0o700); err != nil {
		os.RemoveAll(opDir)
		return nil, fmt.Errorf("cannot create staging directory: %w", err)
	}

	stagingFD, err := unix.Openat(unix.AT_FDCWD, stagingDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		os.RemoveAll(opDir)
		return nil, fmt.Errorf("cannot open staging directory: %w", err)
	}

	hardlinkMap := make(map[devIno]string)

	err = walkAndCopy(ctx, sourceFD, stagingFD, stagingFD, "", hardlinkMap, hooks)
	unix.Close(stagingFD)
	if err != nil {
		os.RemoveAll(opDir)
		return nil, err
	}

	// Verify Dockerfile via openat2 with BENEATH|NO_SYMLINKS|NO_MAGICLINKS.
	stagingVerifyFD, err := unix.Openat(unix.AT_FDCWD, stagingDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		os.RemoveAll(opDir)
		return nil, fmt.Errorf("cannot open staging for verification: %w", err)
	}

	dockerfileFD, err := sy.Openat2(stagingVerifyFD, dockerfileRel, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	unix.Close(stagingVerifyFD)
	if err != nil {
		os.RemoveAll(opDir)
		return nil, fmt.Errorf("Dockerfile not found in staging: %w", err)
	}

	var dfSt unix.Stat_t
	if err := unix.Fstat(dockerfileFD, &dfSt); err != nil {
		unix.Close(dockerfileFD)
		os.RemoveAll(opDir)
		return nil, fmt.Errorf("cannot stat Dockerfile: %w", err)
	}
	if dfSt.Mode&unix.S_IFMT != unix.S_IFREG {
		unix.Close(dockerfileFD)
		os.RemoveAll(opDir)
		return nil, fmt.Errorf("Dockerfile is not a regular file")
	}
	unix.Close(dockerfileFD)

	dockerfileStagingPath := filepath.Join(stagingDir, dockerfileRel)

	return &stagedBuildContext{
		ContextPath:    stagingDir,
		DockerfilePath: dockerfileStagingPath,
		cleanupPath:    opDir,
	}, nil
}

type devIno struct {
	dev uint64
	ino uint64
}

func walkAndCopy(ctx context.Context, sourceFD int, stagingRootFD int, stagingFD int, relPrefix string, hardlinkMap map[devIno]string, hooks *stagingHooks) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	entries, err := readDirectoryEntries(sourceFD)
	if err != nil {
		return fmt.Errorf("cannot read directory: %w", err)
	}

	for _, entry := range entries {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err := copyEntry(ctx, sourceFD, entry.name, stagingRootFD, stagingFD, relPrefix, hardlinkMap, hooks); err != nil {
			return err
		}
	}

	return nil
}

type dirEntry struct {
	name string
	ino  uint64
}

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

		off := 0
		for off < n {
			if off+20 > n {
				break
			}

			entryStart := off
			ino := *(*uint64)(unsafe.Pointer(&buf[off]))
			off += 8 // d_ino
			off += 8 // d_off
			reclen := *(*uint16)(unsafe.Pointer(&buf[off]))
			off += 2 // d_reclen
			off++    // d_type

			if reclen == 0 || int(entryStart)+int(reclen) > n {
				break
			}

			nameStart := entryStart + 19
			nameLen := int(reclen) - 19
			if nameLen <= 0 || nameStart >= n {
				off = entryStart + int(reclen)
				continue
			}

			nameEnd := 0
			for nameEnd < nameLen && nameStart+nameEnd < n && buf[nameStart+nameEnd] != 0 {
				nameEnd++
			}
			name := unix.ByteSliceToString(buf[nameStart : nameStart+nameEnd])

			if name != "." && name != ".." {
				entries = append(entries, dirEntry{name: name, ino: ino})
			}

			off = entryStart + int(reclen)
		}
	}

	return entries, nil
}

func copyEntry(ctx context.Context, sourceDirFD int, name string, stagingRootFD int, stagingDirFD int, relPrefix string, hardlinkMap map[devIno]string, hooks *stagingHooks) error {
	oPathFD, err := unix.Openat(sourceDirFD, name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("cannot O_PATH open %s: %w", name, err)
	}

	var st unix.Stat_t
	if err := unix.Fstat(oPathFD, &st); err != nil {
		unix.Close(oPathFD)
		return fmt.Errorf("cannot stat %s: %w", name, err)
	}

	mode := st.Mode

	// Handle symlinks.
	if mode&unix.S_IFMT == unix.S_IFLNK {
		buf := make([]byte, 4096)
		n, err := unix.Readlinkat(oPathFD, "", buf)
		unix.Close(oPathFD)
		if err != nil {
			return fmt.Errorf("cannot read symlink %s: %w", name, err)
		}
		target := unix.ByteSliceToString(buf[:n])

		if err := unix.Symlinkat(target, stagingDirFD, name); err != nil {
			return fmt.Errorf("cannot create symlink %s: %w", name, err)
		}

		if err := setTimesFromStat(stagingDirFD, name, &st); err != nil {
			unix.Unlinkat(stagingDirFD, name, 0)
			return fmt.Errorf("cannot set symlink times %s: %w", name, err)
		}
		return nil
	}

	// Handle regular files.
	if mode&unix.S_IFMT == unix.S_IFREG {
		if hooks != nil && hooks.betweenStatAndOpen != nil {
			if err := hooks.betweenStatAndOpen(name); err != nil {
				unix.Close(oPathFD)
				return err
			}
		}

		di := devIno{dev: st.Dev, ino: st.Ino}
		if relPath, ok := hardlinkMap[di]; ok {
			unix.Close(oPathFD)
			if err := unix.Linkat(stagingRootFD, relPath, stagingDirFD, name, 0); err != nil {
				return fmt.Errorf("cannot create hardlink %s: %w", name, err)
			}
			return nil
		}

		readFD, err := unix.Openat(sourceDirFD, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			unix.Close(oPathFD)
			return fmt.Errorf("cannot open %s for reading: %w", name, err)
		}

		var readSt unix.Stat_t
		if err := unix.Fstat(readFD, &readSt); err != nil {
			unix.Close(readFD)
			unix.Close(oPathFD)
			return fmt.Errorf("cannot stat read FD for %s: %w", name, err)
		}
		if readSt.Dev != st.Dev || readSt.Ino != st.Ino || readSt.Mode&unix.S_IFMT != st.Mode&unix.S_IFMT {
			unix.Close(readFD)
			unix.Close(oPathFD)
			return fmt.Errorf("identity mismatch for %s: file changed between pin and reopen", name)
		}

		if hooks != nil && hooks.betweenOPATHAndReopen != nil {
			if err := hooks.betweenOPATHAndReopen(name); err != nil {
				unix.Close(readFD)
				unix.Close(oPathFD)
				return err
			}
		}

		unix.Close(oPathFD)

		createFD, err := unix.Openat(stagingDirFD, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			unix.Close(readFD)
			return fmt.Errorf("cannot create %s in staging: %w", name, err)
		}

		if err := copyFileContents(ctx, readFD, createFD, st.Size, name, hooks); err != nil {
			unix.Unlinkat(stagingDirFD, name, 0)
			unix.Close(createFD)
			unix.Close(readFD)
			return fmt.Errorf("cannot copy %s: %w", name, err)
		}
		unix.Close(readFD)
		unix.Close(createFD)

		unix.Fchmodat(stagingDirFD, name, uint32(st.Mode&0o7777), 0)

		if err := setTimesFromStat(stagingDirFD, name, &st); err != nil {
			unix.Unlinkat(stagingDirFD, name, 0)
			return fmt.Errorf("cannot set file times %s: %w", name, err)
		}

		hardlinkMap[di] = filepath.Join(relPrefix, name)

		if hooks != nil && hooks.afterCreateDest != nil {
			if err := hooks.afterCreateDest(name); err != nil {
				unix.Unlinkat(stagingDirFD, name, 0)
				delete(hardlinkMap, di)
				return err
			}
		}
		return nil
	}

	// Handle directories.
	if mode&unix.S_IFMT == unix.S_IFDIR {
		if hooks != nil && hooks.betweenStatAndOpen != nil {
			if err := hooks.betweenStatAndOpen(name); err != nil {
				unix.Close(oPathFD)
				return err
			}
		}

		sourceReadFD, err := unix.Openat(sourceDirFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			unix.Close(oPathFD)
			return fmt.Errorf("cannot open directory %s for reading: %w", name, err)
		}

		var dirSt unix.Stat_t
		if err := unix.Fstat(sourceReadFD, &dirSt); err != nil {
			unix.Close(sourceReadFD)
			unix.Close(oPathFD)
			return fmt.Errorf("cannot stat reopened directory %s: %w", name, err)
		}
		if dirSt.Dev != st.Dev || dirSt.Ino != st.Ino || dirSt.Mode&unix.S_IFMT != st.Mode&unix.S_IFMT {
			unix.Close(sourceReadFD)
			unix.Close(oPathFD)
			return fmt.Errorf("identity mismatch for directory %s: changed between pin and reopen", name)
		}

		unix.Close(oPathFD)

		if err := unix.Mkdirat(stagingDirFD, name, 0o700); err != nil {
			unix.Close(sourceReadFD)
			return fmt.Errorf("cannot create directory %s in staging: %w", name, err)
		}

		destFD, err := unix.Openat(stagingDirFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			unix.Close(sourceReadFD)
			unix.Unlinkat(stagingDirFD, name, unix.AT_REMOVEDIR)
			return fmt.Errorf("cannot open destination directory %s: %w", name, err)
		}

		err = walkAndCopy(ctx, sourceReadFD, stagingRootFD, destFD, filepath.Join(relPrefix, name), hardlinkMap, hooks)
		unix.Close(sourceReadFD)
		unix.Close(destFD)

		if err != nil {
			unix.Unlinkat(stagingDirFD, name, unix.AT_REMOVEDIR)
			return fmt.Errorf("cannot copy directory %s: %w", name, err)
		}

		unix.Fchmodat(stagingDirFD, name, uint32(st.Mode&0o7777), 0)

		if err := setTimesFromStat(stagingDirFD, name, &st); err != nil {
			unix.Unlinkat(stagingDirFD, name, unix.AT_REMOVEDIR)
			return fmt.Errorf("cannot set directory times %s: %w", name, err)
		}
		return nil
	}

	unix.Close(oPathFD)
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

func copyFileContents(ctx context.Context, srcFD int, dstFD int, size int64, name string, hooks *stagingHooks) error {
	off := int64(0)
	const chunkSize = 128 * 1024

	for off < size {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		chunk := int64(chunkSize)
		if off+chunk > size {
			chunk = size - off
		}

		buf := make([]byte, chunk)
		n, err := unix.Read(srcFD, buf)
		if err != nil {
			return fmt.Errorf("cannot read: %w", err)
		}
		if n == 0 {
			break
		}

		wn := 0
		for wn < n {
			w, writeErr := unix.Write(dstFD, buf[wn:n])
			if writeErr != nil {
				return fmt.Errorf("cannot write: %w", writeErr)
			}
			if w == 0 {
				return fmt.Errorf("short write: wrote 0 bytes")
			}
			wn += w
		}
		off += int64(n)

		if hooks != nil && hooks.duringCopy != nil {
			if err := hooks.duringCopy(name, off); err != nil {
				return err
			}
		}
	}
	return nil
}

func setTimesFromStat(dirFD int, name string, st *unix.Stat_t) error {
	ts := []unix.Timespec{
		{Sec: st.Atim.Sec, Nsec: st.Atim.Nsec},
		{Sec: st.Mtim.Sec, Nsec: st.Mtim.Nsec},
	}
	return unix.UtimesNanoAt(dirFD, name, ts, unix.AT_SYMLINK_NOFOLLOW)
}
