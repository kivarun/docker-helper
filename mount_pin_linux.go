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

func (s *linuxMountSeam) moveMountFile(treeFD, destDirfd int, destPath string) error {
	flags := unix.MOVE_MOUNT_F_EMPTY_PATH
	return unix.MoveMount(treeFD, "", destDirfd, destPath, flags)
}

func (s *linuxMountSeam) moveMountDir(treeFD, destDirfd int, destPath string) error {
	flags := unix.MOVE_MOUNT_F_EMPTY_PATH | unix.MOVE_MOUNT_T_EMPTY_PATH
	return unix.MoveMount(treeFD, "", destDirfd, destPath, flags)
}

func (s *linuxMountSeam) fstat(fd int) (os.FileInfo, error) {
	return os.NewFile(uintptr(fd), "").Stat()
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
// with all resources cleaned up.
func PinMount(workspace, sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
	return pinMount(defaultSeam(), workspace, sourcePath, runtimeDir, operationID, mountIndex)
}

func pinMount(seam mountSeam, workspace, sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
	// Validate operationID: must not allow path traversal.
	if operationID == "" || strings.Contains(operationID, "..") || strings.Contains(operationID, "/") {
		return nil, fmt.Errorf("invalid operation ID: %q", operationID)
	}

	// Verify sourcePath is still inside workspace (post-openat2 check).
	if !isInside(workspace, sourcePath) {
		return nil, fmt.Errorf("source escapes workspace: %s", sourcePath)
	}

	// Open source via openat2 with / as directory fd.
	// O_PATH | O_CLOEXEC
	openFlags := uint(unix.O_PATH | unix.O_CLOEXEC)
	// RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS
	resolveFlags := uint64(unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS)

	sourceFD, err := seam.openat2(unix.AT_FDCWD, sourcePath, openFlags, resolveFlags)
	if err != nil {
		return nil, fmt.Errorf("openat2(%s): %w", sourcePath, err)
	}
	defer unix.Close(sourceFD)

	// Verify inode type via fstat.
	info, err := seam.fstat(sourceFD)
	if err != nil {
		return nil, fmt.Errorf("fstat(sourceFD): %w", err)
	}

	isDir := info.IsDir()
	isRegular := info.Mode().IsRegular()
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
		if err := os.MkdirAll(destPath, 0700); err != nil {
			cleanupMounts(mountsDir)
			return nil, fmt.Errorf("create directory mountpoint: %w", err)
		}
	} else {
		f, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			cleanupMounts(mountsDir)
			return nil, fmt.Errorf("create file mountpoint: %w", err)
		}
		f.Close()
	}

	// Verify destination is not a symlink (race check).
	destInfo, err := os.Lstat(destPath)
	if err != nil {
		cleanupMounts(mountsDir)
		return nil, fmt.Errorf("lstat destination: %w", err)
	}
	if destInfo.Mode()&os.ModeSymlink != 0 {
		cleanupMounts(mountsDir)
		return nil, fmt.Errorf("destination is a symlink: %s", destPath)
	}

	// Open the parent directory of destPath for move_mount.
	destDirFD, err := seam.openat2(unix.AT_FDCWD, mountsDir, openFlags, resolveFlags)
	if err != nil {
		cleanupMounts(mountsDir)
		return nil, fmt.Errorf("openat2(mountsDir): %w", err)
	}
	defer unix.Close(destDirFD)

	// Create detached cloned mount via open_tree.
	treeFD, err := seam.openTreeClone(sourceFD)
	if err != nil {
		cleanupMounts(mountsDir)
		if e, ok := err.(unix.Errno); ok && (e == unix.ENOSYS || e == unix.EPERM || e == unix.EINVAL) {
			return nil, fmt.Errorf("open_tree not supported: %w", err)
		}
		return nil, fmt.Errorf("open_tree: %w", err)
	}

	// Move mount to destination.
	if isDir {
		if err := seam.moveMountDir(treeFD, destDirFD, index); err != nil {
			unix.Close(treeFD)
			cleanupMounts(mountsDir)
			if e, ok := err.(unix.Errno); ok && (e == unix.ENOSYS || e == unix.EPERM || e == unix.EINVAL) {
				return nil, fmt.Errorf("move_mount not supported: %w", err)
			}
			return nil, fmt.Errorf("move_mount(dir): %w", err)
		}
	} else {
		if err := seam.moveMountFile(treeFD, destDirFD, index); err != nil {
			unix.Close(treeFD)
			cleanupMounts(mountsDir)
			if e, ok := err.(unix.Errno); ok && (e == unix.ENOSYS || e == unix.EPERM || e == unix.EINVAL) {
				return nil, fmt.Errorf("move_mount not supported: %w", err)
			}
			return nil, fmt.Errorf("move_mount(file): %w", err)
		}
	}

	// Close treeFD — the mount is now at destPath.
	unix.Close(treeFD)

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
	}

	if err := os.Remove(destPath); err != nil && !os.IsNotExist(err) {
		errs = append(errs, fmt.Errorf("remove(%s): %w", destPath, err))
	}

	// Remove operation directory if empty.
	if err := os.Remove(mountsDir); err != nil && !os.IsNotExist(err) {
		errs = append(errs, fmt.Errorf("remove(%s): %w", mountsDir, err))
	}

	if len(errs) > 0 {
		return fmt.Errorf("cleanup: %v", errs)
	}
	return nil
}

// cleanupMounts removes the entire mounts directory tree on error.
func cleanupMounts(mountsDir string) {
	os.RemoveAll(mountsDir)
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
