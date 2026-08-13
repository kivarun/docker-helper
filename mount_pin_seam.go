// mount_pin_seam.go — syscall interface for inode-pinning.
//
// The seam exists so unit tests can verify openat2 / open_tree / move_mount
// flag composition and error handling without requiring root or CAP_SYS_ADMIN.
package main

import (
	"sync"
	"syscall"
)

// pinnedMount represents a successfully inode-pinned mount.
// HostPath is the stable helper-owned destination that Docker should bind-mount.
type pinnedMount struct {
	HostPath string
	cleanup  func() error
	once     sync.Once
	result   error
}

// Cleanup detaches and removes the mount. Idempotent and concurrency-safe:
// repeated or parallel calls execute syscalls exactly once and return the
// result of the first call.
func (p *pinnedMount) Cleanup() error {
	if p == nil {
		return nil
	}
	p.once.Do(func() {
		if p.cleanup == nil {
			p.result = nil
			return
		}
		p.result = p.cleanup()
	})
	return p.result
}

// openat2Args records the arguments passed to openat2.
type openat2Args struct {
	dirfd        int
	path         string
	flags        uint
	mode         uint32
	resolveFlags uint64
}

// openTreeArgs records the arguments passed to open_tree.
type openTreeArgs struct {
	dirfd int
	path  string
	flags uint
}

// moveMountArgs records the arguments passed to move_mount.
type moveMountArgs struct {
	fromFD   int
	fromPath string
	toFD     int
	toPath   string
	flags    int
}

// mountSeam abstracts the Linux syscalls used by the inode-pinning primitive.
type mountSeam interface {
	// openat2 opens path relative to dirfd with the given flags, mode, and
	// resolve flags, returning the fd.
	openat2(dirfd int, path string, flags uint, mode uint32, resolveFlags uint64) (int, error)

	// openTree creates a detached cloned mount.
	openTree(dirfd int, path string, flags uint) (int, error)

	// moveMount moves a detached mount.
	moveMount(fromFD int, fromPath string, toFD int, toPath string, flags int) error

	// fstat returns the stat result for an open fd.
	fstat(fd int) (*unixStat, error)

	// close closes an fd.
	close(fd int) error

	// umountDetach performs umount2(path, MNT_DETACH).
	umountDetach(path string) error
}

// unixStat holds the minimal stat fields needed for inode type checking.
type unixStat struct {
	mode uint32 // st_mode
}

// isDir returns true if the stat describes a directory.
func (s *unixStat) isDir() bool {
	return s.mode&syscall.S_IFMT == syscall.S_IFDIR
}

// isRegular returns true if the stat describes a regular file.
func (s *unixStat) isRegular() bool {
	return s.mode&syscall.S_IFMT == syscall.S_IFREG
}
