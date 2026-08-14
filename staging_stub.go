//go:build !linux

package main

import (
	"context"
	"fmt"
	"sync"
)

// stagedBuildContext is a stub type for non-Linux platforms.
type stagedBuildContext struct {
	ContextPath    string
	DockerfilePath string
	cleanupPath    string
	cleanupOnce    sync.Once
}

// Cleanup is a stub for non-Linux platforms.
func (s *stagedBuildContext) Cleanup() {
	s.cleanupOnce.Do(func() {})
}

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
