//go:build !linux

package main

import (
	"context"
	"fmt"
)

// prepareTrustedDev is not supported on non-Linux platforms: the trusted
// /dev preparation depends on Linux device nodes, xattrs, and SELinux
// labeling.
func prepareTrustedDev(_ context.Context, _, _ string, _ builderCategory) error {
	return fmt.Errorf("trusted /dev preparation is not supported on this platform")
}
