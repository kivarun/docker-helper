package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

// setupStagingSeam configures a fake staging function on the given app.
// The fake staging creates a minimal staging directory with the Dockerfile
// copied from the source context.
func setupStagingSeam(t *testing.T, app *App) {
	t.Helper()
	app.StageBuildContextFn = newStagingSeam(t, stagingSeamOptions{})
}

// newTestAppWithAdminTokenAndStaging creates an admin-authorized test app
// with a staging seam.
func newTestAppWithAdminTokenAndStaging(t *testing.T) *App {
	t.Helper()
	app := newTestAppWithAdminToken(t)
	setupStagingSeam(t, app)
	return app
}

// stagingSeamOptions controls the behavior of a staging seam.
type stagingSeamOptions struct {
	// Capture stores the dockerfileRel and cleanupPath if non-nil.
	Capture *capturedStaging
	// RemoveAllError is returned by Cleanup() when non-nil.
	RemoveAllError error
	// RemoveAllCount tracks how many times removeAll was invoked.
	RemoveAllCount *atomic.Int32
}

// capturedStaging holds the dockerfileRel value captured by a staging seam.
type capturedStaging struct {
	dockerfileRel string
	cleanupPath   string
}

// newStagingSeam creates a staging seam with the given options.
func newStagingSeam(t *testing.T, opts stagingSeamOptions) func(context.Context, string, string, string, string, string) (*stagedBuildContext, error) {
	t.Helper()
	return func(ctx context.Context, ws, cpath, dfrel, rdir, opID string) (*stagedBuildContext, error) {
		if opts.Capture != nil {
			opts.Capture.dockerfileRel = dfrel
		}
		stagingDir := t.TempDir()
		opDir := filepath.Join(stagingDir, opID)
		if err := os.MkdirAll(opDir, 0o700); err != nil {
			return nil, err
		}
		ctxDir := filepath.Join(opDir, "context")
		if err := os.MkdirAll(ctxDir, 0o700); err != nil {
			return nil, err
		}
		srcDockerfile := filepath.Join(cpath, dfrel)
		data, err := os.ReadFile(srcDockerfile)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(ctxDir, dfrel), data, 0o644); err != nil {
			return nil, err
		}
		if opts.Capture != nil {
			opts.Capture.cleanupPath = opDir
		}
		s := &stagedBuildContext{
			ContextPath:    ctxDir,
			DockerfilePath: filepath.Join(ctxDir, dfrel),
			cleanupPath:    opDir,
		}
		if opts.RemoveAllError != nil || opts.RemoveAllCount != nil {
			rmErr := opts.RemoveAllError
			rmCount := opts.RemoveAllCount
			s.removeAll = func(path string) error {
				if rmCount != nil {
					rmCount.Add(1)
				}
				return rmErr
			}
		}
		return s, nil
	}
}

// stagingSeamWithCapture creates a staging seam that captures the dockerfileRel
// argument and returns a real staged context.
func stagingSeamWithCapture(t *testing.T, capture *capturedStaging) func(context.Context, string, string, string, string, string) (*stagedBuildContext, error) {
	t.Helper()
	return newStagingSeam(t, stagingSeamOptions{Capture: capture})
}

// stagingSeamWithCleanupError creates a staging seam where Cleanup() returns
// the given error deterministically, without relying on filesystem permissions.
func stagingSeamWithCleanupError(t *testing.T, err error) func(context.Context, string, string, string, string, string) (*stagedBuildContext, error) {
	t.Helper()
	return newStagingSeam(t, stagingSeamOptions{RemoveAllError: err})
}

// newTestStagedContext creates a fake staged context in a temp directory
// with the given dockerfile relative path and optional removeAll injection.
func newTestStagedContext(t *testing.T, dfrel string, removeAll func(string) error) *stagedBuildContext {
	t.Helper()
	stagingDir := t.TempDir()
	opDir := filepath.Join(stagingDir, "opdir")
	if err := os.MkdirAll(opDir, 0o700); err != nil {
		t.Fatal(err)
	}
	ctxDir := filepath.Join(opDir, "context")
	if err := os.MkdirAll(ctxDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ctxDir, dfrel), []byte("FROM alpine"), 0o644); err != nil {
		t.Fatal(err)
	}
	return &stagedBuildContext{
		ContextPath:    ctxDir,
		DockerfilePath: filepath.Join(ctxDir, dfrel),
		cleanupPath:    opDir,
		removeAll:      removeAll,
	}
}

// sentinelCleanupErr is a sentinel error used in tests to verify that
// cleanup errors are propagated correctly.
var sentinelCleanupErr = errors.New("injected cleanup error")

// newOperationMux creates a mux with production routes registered for testing.
func newOperationMux(app *App) *http.ServeMux {
	mux := http.NewServeMux()
	registerRoutes(mux, app)
	return mux
}
