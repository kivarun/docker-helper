package main

import (
	"fmt"
	"os"
	"sync"
)

// buildStagingCeilingError is the typed expected refusal of a build-staging
// ceiling. It names the exhausted dimension ("bytes", "entries" or "depth"),
// the fixed ceiling, and the attempted reservation, and carries no source
// path or file-name material. The build handler classifies it — and only it
// — into the single public build-context-limit response; every other
// staging failure stays internal_error. It is the untagged classification
// surface of the Linux staging ceilings; the ceilings, budget and walker
// mechanics stay in staging_linux.go, and non-Linux builds keep staging
// unsupported (staging_stub.go).
type buildStagingCeilingError struct {
	Resource  string
	Ceiling   int64
	Attempted int64
}

func (e *buildStagingCeilingError) Error() string {
	return fmt.Sprintf("build context exceeds the staging %s ceiling (attempted %d, ceiling %d)", e.Resource, e.Attempted, e.Ceiling)
}

// Is makes errors.Is match any staging ceiling refusal of the same
// resource through wrapping — the exhausted dimension is the refusal's
// identity, not the instance.
func (e *buildStagingCeilingError) Is(target error) bool {
	t, ok := target.(*buildStagingCeilingError)
	return ok && t != nil && e.Resource == t.Resource
}

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
