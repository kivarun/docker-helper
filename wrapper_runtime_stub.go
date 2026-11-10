//go:build !linux

package main

import "errors"

// wrapperMain is not supported on non-Linux platforms: the runtime
// dispatch depends on Linux procattr reads, execve handoff, and the
// SELinux-labeled prepared tree.
func wrapperMain(_, _ []string) error {
	return errors.New("the wrapper runtime dispatch is not supported on this platform")
}
