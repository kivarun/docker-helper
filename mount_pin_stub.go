//go:build !linux

package main

import "fmt"

// pinWorkspaceMountSource is not supported on non-Linux platforms.
func pinWorkspaceMountSource(workspace, sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
	return nil, fmt.Errorf("inode pinning is not supported on this platform")
}
