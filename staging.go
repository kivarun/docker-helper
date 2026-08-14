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
}

// Cleanup removes the staging directory. It is idempotent and concurrency-safe.
func (s *stagedBuildContext) Cleanup() {
	s.cleanupOnce.Do(func() {
		os.RemoveAll(s.cleanupPath)
	})
}
