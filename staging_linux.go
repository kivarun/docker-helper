//go:build linux

package main

import (
	"context"
	"fmt"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/unix"
)

// stagingHooks allows tests to inject behavior between critical operations.
type stagingHooks struct {
	afterWorkspacePin     func() error
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

func isValidDockerfileRel(path string) bool {
	if path == "" || path == "." {
		return false
	}
	if filepath.IsAbs(path) {
		return false
	}
	if !filepath.IsLocal(path) {
		return false
	}
	if filepath.Clean(path) != path {
		return false
	}
	return true
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

	if !isValidDockerfileRel(dockerfileRel) {
		return nil, fmt.Errorf("invalid dockerfile relative path: %s", dockerfileRel)
	}

	// Validate contextPath is inside workspace.
	if !isInside(workspace, contextPath) {
		return nil, fmt.Errorf("context path escapes workspace: %s", contextPath)
	}

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

	// Hook: after workspace pin, before context open.
	if hooks != nil && hooks.afterWorkspacePin != nil {
		if err := hooks.afterWorkspacePin(); err != nil {
			return nil, err
		}
	}

	// Compute context path relative to workspace.
	relContext, err := filepath.Rel(workspace, contextPath)
	if err != nil {
		return nil, fmt.Errorf("cannot compute context relative to workspace: %w", err)
	}
	if relContext == ".." || filepath.IsAbs(relContext) {
		return nil, fmt.Errorf("context path escapes workspace: %s", contextPath)
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

	// Pin runtimeDir via rootFD with openat2.
	relRuntimeDir, err := filepath.Rel("/", runtimeDir)
	if err != nil {
		return nil, fmt.Errorf("cannot compute runtimeDir relative to /: %w", err)
	}
	runtimeDirFD, err := sy.Openat2(rootFD, relRuntimeDir, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		if err == unix.ENOSYS || err == unix.EPERM {
			return nil, fmt.Errorf("openat2 not supported: %w (fail closed, no fallback)", err)
		}
		return nil, fmt.Errorf("cannot pin runtimeDir: %w", err)
	}
	defer unix.Close(runtimeDirFD)

	// Create builds directory via mkdirat.
	var buildsFD int
	{
		buildsFD, err = sy.Openat2(runtimeDirFD, "builds", &unix.OpenHow{
			Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
			Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
		})
		if err != nil {
			if err == unix.ENOENT {
				if err := unix.Mkdirat(runtimeDirFD, "builds", 0o700); err != nil && err != unix.EEXIST {
					return nil, fmt.Errorf("cannot create builds directory: %w", err)
				}
				buildsFD, err = sy.Openat2(runtimeDirFD, "builds", &unix.OpenHow{
					Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
					Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
				})
				if err != nil {
					return nil, fmt.Errorf("cannot open builds directory: %w", err)
				}
			} else {
				return nil, fmt.Errorf("cannot open builds directory: %w", err)
			}
		}
		// Verify builds is a real directory (not symlink).
		var buildsSt unix.Stat_t
		if err := unix.Fstat(buildsFD, &buildsSt); err != nil {
			unix.Close(buildsFD)
			return nil, fmt.Errorf("cannot stat builds directory: %w", err)
		}
		if buildsSt.Mode&unix.S_IFMT != unix.S_IFDIR {
			unix.Close(buildsFD)
			return nil, fmt.Errorf("builds is not a directory")
		}
	}
	defer unix.Close(buildsFD)

	// Create operation directory exclusively via mkdirat.
	if err := unix.Mkdirat(buildsFD, operationID, 0o700); err != nil {
		if err == unix.EEXIST {
			return nil, fmt.Errorf("operation directory already exists: %s", operationID)
		}
		return nil, fmt.Errorf("cannot create operation directory: %w", err)
	}

	// We own this operation directory. Open it via openat2 to verify.
	opFD, err := sy.Openat2(buildsFD, operationID, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		removeAllAtRecursive(buildsFD, operationID)
		return nil, fmt.Errorf("cannot open operation directory: %w", err)
	}
	defer unix.Close(opFD)

	// We own operation directory; cleanup is safe on any subsequent error.

	// Create staging directory via mkdirat.
	if err := unix.Mkdirat(opFD, "context", 0o700); err != nil {
		removeAllAtRecursive(buildsFD, operationID)
		return nil, fmt.Errorf("cannot create staging directory: %w", err)
	}

	stagingFD, err := sy.Openat2(opFD, "context", &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		removeAllAtRecursive(buildsFD, operationID)
		return nil, fmt.Errorf("cannot open staging directory: %w", err)
	}

	hardlinkMap := make(map[devIno]string)

	err = walkAndCopy(ctx, sourceFD, stagingFD, stagingFD, "", hardlinkMap, hooks)
	unix.Close(stagingFD)
	if err != nil {
		removeAllAtRecursive(buildsFD, operationID)
		return nil, err
	}

	// Verify Dockerfile via openat2 with BENEATH|NO_SYMLINKS|NO_MAGICLINKS.
	stagingVerifyFD, err := sy.Openat2(opFD, "context", &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		removeAllAtRecursive(buildsFD, operationID)
		return nil, fmt.Errorf("cannot open staging for verification: %w", err)
	}

	dockerfileFD, err := sy.Openat2(stagingVerifyFD, dockerfileRel, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	unix.Close(stagingVerifyFD)
	if err != nil {
		removeAllAtRecursive(buildsFD, operationID)
		return nil, fmt.Errorf("Dockerfile not found in staging: %w", err)
	}

	var dfSt unix.Stat_t
	if err := unix.Fstat(dockerfileFD, &dfSt); err != nil {
		unix.Close(dockerfileFD)
		removeAllAtRecursive(buildsFD, operationID)
		return nil, fmt.Errorf("cannot stat Dockerfile: %w", err)
	}
	if dfSt.Mode&unix.S_IFMT != unix.S_IFREG {
		unix.Close(dockerfileFD)
		removeAllAtRecursive(buildsFD, operationID)
		return nil, fmt.Errorf("Dockerfile is not a regular file")
	}
	unix.Close(dockerfileFD)

	// Compute cleanup path from rootFD chain.
	cleanupPath := filepath.Join(runtimeDir, "builds", operationID)

	// Compute staging path.
	stagingPath := filepath.Join(cleanupPath, "context")

	dockerfileStagingPath := filepath.Join(stagingPath, dockerfileRel)

	return &stagedBuildContext{
		ContextPath:    stagingPath,
		DockerfilePath: dockerfileStagingPath,
		cleanupPath:    cleanupPath,
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

		// Preserve permissions via Fchmod on open FD.
		if err := unix.Fchmod(createFD, uint32(st.Mode&0o7777)); err != nil {
			unix.Unlinkat(stagingDirFD, name, 0)
			unix.Close(createFD)
			return fmt.Errorf("cannot chmod %s: %w", name, err)
		}
		unix.Close(createFD)

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

		if err != nil {
			unix.Close(destFD)
			unix.Unlinkat(stagingDirFD, name, unix.AT_REMOVEDIR)
			return fmt.Errorf("cannot copy directory %s: %w", name, err)
		}

		// Preserve directory permissions via Fchmod on open FD.
		if err := unix.Fchmod(destFD, uint32(st.Mode&0o7777)); err != nil {
			unix.Close(destFD)
			unix.Unlinkat(stagingDirFD, name, unix.AT_REMOVEDIR)
			return fmt.Errorf("cannot chmod directory %s: %w", name, err)
		}

		if err := setTimesFromStat(stagingDirFD, name, &st); err != nil {
			unix.Close(destFD)
			unix.Unlinkat(stagingDirFD, name, unix.AT_REMOVEDIR)
			return fmt.Errorf("cannot set directory times %s: %w", name, err)
		}
		unix.Close(destFD)
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
			if off < size {
				return fmt.Errorf("unexpected EOF at offset %d (expected %d)", off, size)
			}
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

// removeAllAtRecursive recursively removes a directory tree referenced by parentFD/name.
func removeAllAtRecursive(parentFD int, name string) {
	fd, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return
	}
	defer unix.Close(fd)

	entries, err := readDirectoryEntries(fd)
	if err != nil {
		return
	}

	for _, entry := range entries {
		var st unix.Stat_t
		if err := unix.Fstatat(fd, entry.name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			continue
		}
		if st.Mode&unix.S_IFMT == unix.S_IFDIR {
			removeAllAtRecursive(fd, entry.name)
			unix.Unlinkat(fd, entry.name, unix.AT_REMOVEDIR)
		} else {
			unix.Unlinkat(fd, entry.name, 0)
		}
	}

	unix.Unlinkat(parentFD, name, unix.AT_REMOVEDIR)
}
