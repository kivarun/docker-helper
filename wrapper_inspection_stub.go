//go:build !linux

package main

import "errors"

// wrapperInspectDevPrep is not supported on non-Linux platforms: the
// enforced readiness boundary depends on Linux procattr reads, inode
// types, and SELinux labeling.
func wrapperInspectDevPrep(_ string) error {
	return errors.New("the wrapper dev-prep inspection is not supported on this platform")
}
