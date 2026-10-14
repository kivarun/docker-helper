package main

// peer_credentials_linux.go is the Linux implementation of the builder
// peer-credential reader: SO_PEERCRED over a *net.UnixConn. The untagged
// builder-manager code consumes it through the package seams only; the
// non-Linux contract stays "unsupported" (peer_credentials_stub.go), so
// the non-Linux compile gate stays closed.

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

// peerCredentialsUnix reads SO_PEERCRED for a *net.UnixConn.
func peerCredentialsUnix(conn *net.UnixConn) (uid, gid, pid int, err error) {
	rawConn, rawErr := conn.SyscallConn()
	if rawErr != nil {
		return 0, 0, 0, rawErr
	}
	var ucred *unix.Ucred
	var sockErr error
	ctrlErr := rawConn.Control(func(fd uintptr) {
		u, e := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if e != nil {
			sockErr = e
			return
		}
		ucred = u
	})
	if ctrlErr != nil {
		return 0, 0, 0, ctrlErr
	}
	if sockErr != nil {
		return 0, 0, 0, sockErr
	}
	if ucred == nil {
		return 0, 0, 0, errors.New("SO_PEERCRED returned no credentials")
	}
	return int(ucred.Uid), int(ucred.Gid), int(ucred.Pid), nil
}
