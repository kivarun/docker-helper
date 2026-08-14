//go:build !linux

package main

import (
	"context"
	"fmt"
)

// stagedBuildContext is a stub type for non-Linux platforms.
type stagedBuildContext struct{}

// Cleanup is a stub for non-Linux platforms.
func (s *stagedBuildContext) Cleanup() {}

// StageBuildContext is not supported on non-Linux platforms.
func StageBuildContext(
	ctx context.Context,
	workspace string,
	contextPath string,
	dockerfileRel string,
	runtimeDir string,
	operationID string,
) (*stagedBuildContext, error) {
	return nil, fmt.Errorf("staging build context is not supported on this platform")
}
