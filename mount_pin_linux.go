//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// linuxMountPinSyscalls implements mountPinSyscalls using real Linux syscalls.
type linuxMountPinSyscalls struct{}

func (s *linuxMountPinSyscalls) openat2(dirfd int, path string, flags uint, mode uint32, resolveFlags uint64) (int, error) {
	how := &unix.OpenHow{
		Flags:   uint64(flags),
		Mode:    uint64(mode),
		Resolve: resolveFlags,
	}
	return unix.Openat2(dirfd, path, how)
}

func (s *linuxMountPinSyscalls) openTree(dirfd int, path string, flags uint) (int, error) {
	return unix.OpenTree(dirfd, path, flags)
}

func (s *linuxMountPinSyscalls) moveMount(fromFD int, fromPath string, toFD int, toPath string, flags int) error {
	return unix.MoveMount(fromFD, fromPath, toFD, toPath, flags)
}

func (s *linuxMountPinSyscalls) fstat(fd int) (*unixStat, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, err
	}
	return &unixStat{mode: uint32(stat.Mode)}, nil
}

func (s *linuxMountPinSyscalls) close(fd int) error {
	return unix.Close(fd)
}

func (s *linuxMountPinSyscalls) umountDetach(path string) error {
	return unix.Unmount(path, unix.MNT_DETACH)
}

// defaultMountPinSyscalls returns the real Linux syscall seam.
func defaultMountPinSyscalls() mountPinSyscalls {
	return &linuxMountPinSyscalls{}
}

// relToRoot returns the path relative to "/" or an error if not absolute.
func relToRoot(path string) (string, error) {
	rel, err := filepath.Rel("/", path)
	if err != nil {
		return "", fmt.Errorf("cannot compute path relative to /: %w", err)
	}
	return rel, nil
}

// pinWorkspaceMountSource opens the source path with openat2, verifies it is a
// directory or regular file, creates a helper-owned destination, and pins the
// inode via open_tree + move_mount.
//
// Parameters:
//   - workspace: canonical workspace root (for containment check)
//   - sourcePath: already-resolved absolute source path
//   - runtimeDir: helper runtime directory
//   - operationID: operation identifier (must be safe, no path traversal)
//   - mountIndex: numeric index for this mount within the operation
//
// Returns a pinnedMount with the stable PinnedPath and Cleanup, or an error
// with all resources cleaned up. No fallback to the original pathname.
func pinWorkspaceMountSource(workspace, sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
	return pinWorkspaceMountSourceWithSyscalls(defaultMountPinSyscalls(), workspace, sourcePath, runtimeDir, operationID, mountIndex)
}

func pinWorkspaceMountSourceWithSyscalls(seam mountPinSyscalls, workspace, sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
	// Validate operationID: must not allow path traversal.
	if !isOperationIDSafe(operationID) {
		return nil, fmt.Errorf("invalid operation ID: %q", operationID)
	}

	// Reject negative mount index.
	if mountIndex < 0 {
		return nil, fmt.Errorf("negative mount index: %d", mountIndex)
	}

	// Require absolute paths.
	if !filepath.IsAbs(workspace) {
		return nil, fmt.Errorf("workspace must be absolute: %q", workspace)
	}
	if !filepath.IsAbs(sourcePath) {
		return nil, fmt.Errorf("sourcePath must be absolute: %q", sourcePath)
	}
	if !filepath.IsAbs(runtimeDir) {
		return nil, fmt.Errorf("runtimeDir must be absolute: %q", runtimeDir)
	}

	// Verify sourcePath is still inside workspace.
	if !pathWithin(workspace, sourcePath) {
		return nil, fmt.Errorf("source escapes workspace: %s", sourcePath)
	}

	// Open / with O_PATH | O_DIRECTORY | O_CLOEXEC.
	rootFD, err := seam.openat2(unix.AT_FDCWD, "/", uint(unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC), 0, 0)
	if err != nil {
		return nil, fmt.Errorf("openat2(/): %w", err)
	}
	defer seam.close(rootFD)

	// Get relative path to root for source.
	relSource, err := relToRoot(sourcePath)
	if err != nil {
		return nil, err
	}

	// Open source via openat2 with root FD.
	openFlags := uint(unix.O_PATH | unix.O_CLOEXEC)
	resolveFlags := uint64(unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS)

	sourceFD, err := seam.openat2(rootFD, relSource, openFlags, 0, resolveFlags)
	if err != nil {
		return nil, fmt.Errorf("openat2(%s): %w", sourcePath, err)
	}
	defer seam.close(sourceFD)

	// Verify inode type via fstat.
	stat, err := seam.fstat(sourceFD)
	if err != nil {
		return nil, fmt.Errorf("fstat(sourceFD): %w", err)
	}

	isDir := stat.isDir()
	isRegular := stat.isRegular()
	if !isDir && !isRegular {
		return nil, fmt.Errorf("source is not a directory or regular file: %s", sourcePath)
	}

	// Build pinned path: <runtime-dir>/mounts/<operation-id>/<index>
	mountsDir := filepath.Join(runtimeDir, "mounts", operationID)
	index := fmt.Sprintf("%d", mountIndex)
	pinnedPath := filepath.Join(mountsDir, index)

	// Create parent directories with mode 0700.
	if err := os.MkdirAll(mountsDir, 0700); err != nil {
		return nil, fmt.Errorf("create mount directory: %w", err)
	}

	// Create destination: directory for directory source, regular file for file source.
	// Track whether we created the destination so we don't remove pre-existing objects.
	createdDest := false

	if isDir {
		if err := os.Mkdir(pinnedPath, 0700); err != nil {
			if errors.Is(err, os.ErrExist) {
				return nil, fmt.Errorf("destination already exists: %s", pinnedPath)
			}
			return nil, fmt.Errorf("create directory mountpoint: %w", err)
		}
		createdDest = true
	} else {
		// Get relative path for file destination.
		relDest, err := relToRoot(pinnedPath)
		if err != nil {
			return nil, err
		}

		fd, err := seam.openat2(rootFD, relDest,
			uint(unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_WRONLY), 0600, 0)
		if err != nil {
			if errors.Is(err, os.ErrExist) {
				return nil, fmt.Errorf("destination already exists: %s", pinnedPath)
			}
			return nil, fmt.Errorf("create file mountpoint: %w", err)
		}
		seam.close(fd)
		createdDest = true
	}

	// Open the parent directory of pinnedPath for move_mount.
	relMountsDir, err := relToRoot(mountsDir)
	if err != nil {
		cleanupErr := rollbackDest(createdDest, pinnedPath, mountsDir)
		return nil, errors.Join(err, cleanupErr)
	}

	destDirFD, err := seam.openat2(rootFD, relMountsDir, openFlags, 0, resolveFlags)
	if err != nil {
		cleanupErr := rollbackDest(createdDest, pinnedPath, mountsDir)
		return nil, errors.Join(fmt.Errorf("openat2(mountsDir): %w", err), cleanupErr)
	}
	defer seam.close(destDirFD)

	// Create detached cloned mount via open_tree.
	treeFD, err := seam.openTree(sourceFD, "", uint(unix.AT_EMPTY_PATH|unix.OPEN_TREE_CLONE|unix.OPEN_TREE_CLOEXEC))
	if err != nil {
		cleanupErr := rollbackDest(createdDest, pinnedPath, mountsDir)
		if e, ok := err.(unix.Errno); ok && (e == unix.ENOSYS || e == unix.EPERM || e == unix.EINVAL) {
			return nil, errors.Join(fmt.Errorf("open_tree not supported: %w", err), cleanupErr)
		}
		return nil, errors.Join(fmt.Errorf("open_tree: %w", err), cleanupErr)
	}

	// Move mount to destination.
	if err := seam.moveMount(treeFD, "", destDirFD, index, unix.MOVE_MOUNT_F_EMPTY_PATH); err != nil {
		seam.close(treeFD)
		cleanupErr := rollbackDest(createdDest, pinnedPath, mountsDir)
		if e, ok := err.(unix.Errno); ok && (e == unix.ENOSYS || e == unix.EPERM || e == unix.EINVAL) {
			return nil, errors.Join(fmt.Errorf("move_mount not supported: %w", err), cleanupErr)
		}
		return nil, errors.Join(fmt.Errorf("move_mount: %w", err), cleanupErr)
	}

	// Close treeFD — the mount is now at pinnedPath.
	seam.close(treeFD)

	// Return pinned mount with cleanup.
	return &pinnedMount{
		PinnedPath: pinnedPath,
		cleanup: func() error {
			return cleanupPinnedMount(seam, pinnedPath, mountsDir)
		},
	}, nil
}

// rollbackDest removes the destination if it was created by the current call
// and removes the operation directory if empty. Returns any cleanup errors.
func rollbackDest(createdDest bool, pinnedPath, mountsDir string) error {
	var errs []error

	if createdDest {
		if err := os.Remove(pinnedPath); err != nil && !os.IsNotExist(err) {
			errs = append(errs, fmt.Errorf("remove dest: %w", err))
		}
	}

	if err := os.Remove(mountsDir); err != nil && !os.IsNotExist(err) {
		// Ignore ENOTEMPTY; report other errors.
		if pathErr, ok := err.(*os.PathError); ok {
			if errno, ok := pathErr.Err.(syscall.Errno); errno == syscall.ENOTEMPTY || !ok {
				return errors.Join(errs...)
			}
		}
		errs = append(errs, fmt.Errorf("remove mounts dir: %w", err))
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// cleanupPinnedMount detaches the mount and removes the destination.
func cleanupPinnedMount(seam mountPinSyscalls, pinnedPath, mountsDir string) error {
	if err := seam.umountDetach(pinnedPath); err != nil && err != unix.EINVAL {
		return fmt.Errorf("umount2(%s): %w", pinnedPath, err)
	}

	if err := os.Remove(pinnedPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove(%s): %w", pinnedPath, err)
	}

	// Remove operation directory if empty.
	if err := os.Remove(mountsDir); err != nil && !os.IsNotExist(err) {
		if pathErr, ok := err.(*os.PathError); ok {
			if errno, ok := pathErr.Err.(syscall.Errno); errno != syscall.ENOTEMPTY && ok {
				return fmt.Errorf("remove mounts dir: %w", err)
			}
		}
	}

	return nil
}

// isOperationIDSafe checks that the operation ID cannot be used for path traversal.
func isOperationIDSafe(id string) bool {
	if id == "" {
		return false
	}
	if len(id) > 0 && (id[0] == '.' || id[0] == '/') {
		return false
	}
	for _, r := range id {
		if r == '/' || r == '\\' {
			return false
		}
	}
	return true
}

// Ensure linuxMountPinSyscalls implements mountPinSyscalls at compile time.
var _ mountPinSyscalls = (*linuxMountPinSyscalls)(nil)
