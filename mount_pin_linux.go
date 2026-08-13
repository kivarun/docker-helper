//go:build linux

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// linuxMountSeam implements mountSeam using real Linux syscalls.
type linuxMountSeam struct{}

func (s *linuxMountSeam) openat2(dirfd int, path string, flags uint, resolveFlags uint64) (int, error) {
	how := &unix.OpenHow{
		Flags:   uint64(flags),
		Mode:    0,
		Resolve: resolveFlags,
	}
	return unix.Openat2(dirfd, path, how)
}

func (s *linuxMountSeam) openTreeClone(sourceFD int) (int, error) {
	flags := unix.AT_EMPTY_PATH | unix.OPEN_TREE_CLONE | unix.OPEN_TREE_CLOEXEC
	return unix.OpenTree(sourceFD, "", uint(flags))
}

func (s *linuxMountSeam) moveMount(treeFD, destDirfd int, destPath string) error {
	flags := unix.MOVE_MOUNT_F_EMPTY_PATH
	return unix.MoveMount(treeFD, "", destDirfd, destPath, flags)
}

func (s *linuxMountSeam) fstat(fd int) (*unixStat, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, err
	}
	return &unixStat{mode: uint32(stat.Mode)}, nil
}

func (s *linuxMountSeam) close(fd int) error {
	return unix.Close(fd)
}

func (s *linuxMountSeam) umountDetach(path string) error {
	return unix.Unmount(path, unix.MNT_DETACH)
}

// defaultSeam returns the real Linux syscall seam.
func defaultSeam() mountSeam {
	return &linuxMountSeam{}
}

// PinMount opens the source path with openat2, verifies it is a directory or
// regular file, creates a helper-owned destination, and pins the inode via
// open_tree + move_mount.
//
// Parameters:
//   - workspace: canonical workspace root (for containment check)
//   - sourcePath: already-resolved absolute source path
//   - runtimeDir: helper runtime directory
//   - operationID: operation identifier (must be safe, no path traversal)
//   - mountIndex: numeric index for this mount within the operation
//
// Returns a pinnedMount with the stable HostPath and Cleanup, or an error
// with all resources cleaned up. No fallback to the original pathname.
func PinMount(workspace, sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
	return pinMount(defaultSeam(), workspace, sourcePath, runtimeDir, operationID, mountIndex)
}

func pinMount(seam mountSeam, workspace, sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
	// Validate operationID: must not allow path traversal.
	if !isOperationIDSafe(operationID) {
		return nil, fmt.Errorf("invalid operation ID: %q", operationID)
	}

	// Reject negative mount index.
	if mountIndex < 0 {
		return nil, fmt.Errorf("negative mount index: %d", mountIndex)
	}

	// Verify sourcePath is still inside workspace.
	if !isInside(workspace, sourcePath) {
		return nil, fmt.Errorf("source escapes workspace: %s", sourcePath)
	}

	// Open / with O_PATH | O_DIRECTORY | O_CLOEXEC.
	rootFD, err := seam.openat2(unix.AT_FDCWD, "/", uint(unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC), 0)
	if err != nil {
		return nil, fmt.Errorf("openat2(/): %w", err)
	}
	defer seam.close(rootFD)

	// Strip leading "/" to get relative path for openat2 with root FD.
	relPath := sourcePath[1:]

	// Open source via openat2 with root FD.
	openFlags := uint(unix.O_PATH | unix.O_CLOEXEC)
	resolveFlags := uint64(unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS)

	sourceFD, err := seam.openat2(rootFD, relPath, openFlags, resolveFlags)
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

	// Build destination path: <runtime-dir>/mounts/<operation-id>/<index>
	mountsDir := filepath.Join(runtimeDir, "mounts", operationID)
	index := fmt.Sprintf("%d", mountIndex)
	destPath := filepath.Join(mountsDir, index)

	// Create parent directories with mode 0700.
	if err := os.MkdirAll(mountsDir, 0700); err != nil {
		return nil, fmt.Errorf("create mount directory: %w", err)
	}

	// Create destination: directory for directory source, regular file for file source.
	if isDir {
		if err := os.Mkdir(destPath, 0700); err != nil {
			removeMountpoint(destPath)
			removeEmptyDir(mountsDir)
			return nil, fmt.Errorf("create directory mountpoint: %w", err)
		}
	} else {
		fd, err := seam.openat2(unix.AT_FDCWD, destPath,
			uint(unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_WRONLY), 0)
		if err != nil {
			removeMountpoint(destPath)
			removeEmptyDir(mountsDir)
			return nil, fmt.Errorf("create file mountpoint: %w", err)
		}
		seam.close(fd)
	}

	// Open the parent directory of destPath for move_mount.
	relMountsDir := mountsDir[1:]
	destDirFD, err := seam.openat2(rootFD, relMountsDir, openFlags, resolveFlags)
	if err != nil {
		removeMountpoint(destPath)
		removeEmptyDir(mountsDir)
		return nil, fmt.Errorf("openat2(mountsDir): %w", err)
	}
	defer seam.close(destDirFD)

	// Create detached cloned mount via open_tree.
	treeFD, err := seam.openTreeClone(sourceFD)
	if err != nil {
		removeMountpoint(destPath)
		removeEmptyDir(mountsDir)
		if e, ok := err.(unix.Errno); ok && (e == unix.ENOSYS || e == unix.EPERM || e == unix.EINVAL) {
			return nil, fmt.Errorf("open_tree not supported: %w", err)
		}
		return nil, fmt.Errorf("open_tree: %w", err)
	}

	// Move mount to destination.
	if err := seam.moveMount(treeFD, destDirFD, index); err != nil {
		seam.close(treeFD)
		removeMountpoint(destPath)
		removeEmptyDir(mountsDir)
		if e, ok := err.(unix.Errno); ok && (e == unix.ENOSYS || e == unix.EPERM || e == unix.EINVAL) {
			return nil, fmt.Errorf("move_mount not supported: %w", err)
		}
		return nil, fmt.Errorf("move_mount: %w", err)
	}

	// Close treeFD — the mount is now at destPath.
	seam.close(treeFD)

	// Return pinned mount with cleanup.
	return &pinnedMount{
		HostPath: destPath,
		cleanup: func() error {
			return cleanupPinnedMount(seam, destPath, mountsDir)
		},
	}, nil
}

// cleanupPinnedMount detaches the mount and removes the destination.
func cleanupPinnedMount(seam mountSeam, destPath, mountsDir string) error {
	var errs []error

	if err := seam.umountDetach(destPath); err != nil && err != unix.EINVAL {
		errs = append(errs, fmt.Errorf("umount2(%s): %w", destPath, err))
		return fmt.Errorf("cleanup: %v", errs)
	}

	if err := os.Remove(destPath); err != nil && !os.IsNotExist(err) {
		errs = append(errs, fmt.Errorf("remove(%s): %w", destPath, err))
	}

	// Remove operation directory if empty.
	removeEmptyDir(mountsDir)

	if len(errs) > 0 {
		return fmt.Errorf("cleanup: %v", errs)
	}
	return nil
}

// removeMountpoint removes the mountpoint if it exists.
func removeMountpoint(path string) {
	os.Remove(path)
}

// removeEmptyDir removes the directory if it exists and is empty.
func removeEmptyDir(path string) {
	os.Remove(path)
}

// isOperationIDSafe checks that the operation ID cannot be used for path traversal.
func isOperationIDSafe(id string) bool {
	if id == "" {
		return false
	}
	if strings.Contains(id, "..") {
		return false
	}
	if strings.Contains(id, "/") {
		return false
	}
	return true
}

// Ensure linuxMountSeam implements mountSeam at compile time.
var _ mountSeam = (*linuxMountSeam)(nil)
