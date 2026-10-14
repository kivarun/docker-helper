//go:build !linux

package main

// peer_credentials_stub.go is the non-Linux contract of the builder
// peer-credential reader: unsupported. The builder manager and its
// client are Linux-only runtime surfaces; the untagged code consumes the
// reader through the package seams, so the stub keeps the non-Linux
// compile closed with an explicit runtime error.

import (
	"errors"
	"net"
)

// peerCredentialsUnix is unsupported outside Linux: SO_PEERCRED over a
// *net.UnixConn has no portable non-Linux form in this product.
func peerCredentialsUnix(conn *net.UnixConn) (uid, gid, pid int, err error) {
	_ = conn
	return 0, 0, 0, errors.New("peer credentials require Linux")
}
