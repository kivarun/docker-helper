package main

import (
	"os"
	"sync"
)

// stagedBuildContext represents a successfully staged build context.
type stagedBuildContext struct {
	ContextPath    string
	DockerfilePath string
	cleanupPath    string
	cleanupOnce    sync.Once
	cleanupErr     error
	// removeAll is an optional test seam for deterministic cleanup testing.
	// When nil, os.RemoveAll is used.
	removeAll func(string) error
}

// Cleanup removes the staging directory. It is idempotent and concurrency-safe.
// The first invocation performs the deletion; subsequent invocations return
// the same result (nil or the error from the first attempt).
func (s *stagedBuildContext) Cleanup() error {
	s.cleanupOnce.Do(func() {
		rm := s.removeAll
		if rm == nil {
			rm = os.RemoveAll
		}
		s.cleanupErr = rm(s.cleanupPath)
	})
	return s.cleanupErr
}
