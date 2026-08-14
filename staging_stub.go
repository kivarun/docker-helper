//go:build !linux

package main

import (
	"context"
	"fmt"
)

// StageBuildContext is not supported on non-Linux platforms.
func StageBuildContext(ctx context.Context, workspace, contextPath, dockerfileRel, runtimeDir, operationID string) (*stagedBuildContext, error) {
	return nil, fmt.Errorf("build context staging is not supported on this platform")
}
