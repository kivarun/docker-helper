//go:build !linux

package main

import (
	"context"
	"fmt"
)

// prepareTrustedDev is not supported on non-Linux platforms: the trusted
// /dev preparation depends on Linux device nodes, xattrs, and SELinux
// labeling. The disposal owner is likewise unreachable: no tree is ever
// prepared on this platform.
func prepareTrustedDev(_ context.Context, _ string, _ builderCategory) error {
	return fmt.Errorf("trusted /dev preparation is not supported on this platform")
}

func devPrepOccupiedCategories(context.Context, map[string]builderCategory) (builderCategorySet, error) {
	return builderCategorySet{}, fmt.Errorf("trusted /dev preparation is not supported on this platform")
}

// devPrepDisposeOperation is not supported on non-Linux platforms: the
// trusted tree it disposes never exists here.
func devPrepDisposeOperation(_ string) error {
	return fmt.Errorf("trusted /dev preparation is not supported on this platform")
}
