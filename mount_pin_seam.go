// mount_pin_seam.go — syscall interface for inode-pinning.
//
// The seam exists so unit tests can verify openat2 / open_tree / move_mount
// flag composition and error handling without requiring root or CAP_SYS_ADMIN.
package main

import "os"

// pinnedMount represents a successfully inode-pinned mount.
// HostPath is the stable helper-owned destination that Docker should bind-mount.
type pinnedMount struct {
	HostPath string
	cleanup  func() error
}

// Cleanup detaches and removes the mount. Idempotent: repeated calls are safe.
func (p *pinnedMount) Cleanup() error {
	if p.cleanup == nil {
		return nil
	}
	err := p.cleanup()
	p.cleanup = nil
	return err
}

// mountSeam abstracts the Linux syscalls used by the inode-pinning primitive.
type mountSeam interface {
	// openat2 opens path relative to dirfd with the given flags and resolve
	// flags, returning the fd.
	openat2(dirfd int, path string, flags uint, resolveFlags uint64) (int, error)

	// openTreeClone creates a detached cloned mount from sourceFD.
	openTreeClone(sourceFD int) (int, error)

	// moveMountFile moves a detached mount treeFD onto the regular file at
	// destPath (destDirfd is the parent directory fd).
	moveMountFile(treeFD, destDirfd int, destPath string) error

	// moveMountDir moves a detached mount treeFD onto the directory at
	// destPath (destDirfd is the parent directory fd).
	moveMountDir(treeFD, destDirfd int, destPath string) error

	// fstat returns the os.FileInfo for an open fd.
	fstat(fd int) (os.FileInfo, error)

	// umountDetach performs umount2(path, MNT_DETACH).
	umountDetach(path string) error
}
