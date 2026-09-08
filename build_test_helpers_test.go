package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
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
	// Staged stores the staged context path if non-nil.
	Staged *string
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
	return func(ctx context.Context, ws, cpath, dfrel, rdir, stagingID string) (*stagedBuildContext, error) {
		if opts.Capture != nil {
			opts.Capture.dockerfileRel = dfrel
		}
		stagingDir := t.TempDir()
		opDir := filepath.Join(stagingDir, stagingID)
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
		if opts.Staged != nil {
			*opts.Staged = ctxDir
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

// stagingSeamWithCleanupCount creates a staging seam that captures the
// staging arguments and counts cleanup invocations.
func stagingSeamWithCleanupCount(t *testing.T, capture *capturedStaging, count *atomic.Int32) func(context.Context, string, string, string, string, string) (*stagedBuildContext, error) {
	t.Helper()
	return newStagingSeam(t, stagingSeamOptions{Capture: capture, RemoveAllCount: count})
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

// buildSeamOptions controls the fake Engine builder installed on the App.
type buildSeamOptions struct {
	// Output is the bounded build output the fake builder returns.
	Output string
	// Truncated is reported by the fake builder.
	Truncated bool
	// Err is the normalized Engine failure the fake builder returns.
	Err error
	// StreamBlock holds the build open until it is closed or the request
	// context is cancelled.
	StreamBlock chan struct{}
	// ConstructErr makes adapter construction itself fail.
	ConstructErr error
}

// capturedBuild records what the fake builder received.
type capturedBuild struct {
	mu         sync.Mutex
	spec       engineBuildSpec
	contextTar []byte
}

// reachedBuild reports whether the fake builder was invoked.
func (c *capturedBuild) reachedBuild() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.spec.Image != ""
}

// builderImage returns the image name the fake builder received.
func (c *capturedBuild) builderImage() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.spec.Image
}

// fakeEngineBuilder is the Engine builder test seam.
type fakeEngineBuilder struct {
	captured *capturedBuild
	opts     buildSeamOptions
}

func (b fakeEngineBuilder) imageBuild(ctx context.Context, spec engineBuildSpec, outputLimit int64) (engineBuildResult, error) {
	b.captured.mu.Lock()
	b.captured.spec = spec
	b.captured.mu.Unlock()
	blob, err := io.ReadAll(spec.Context)
	if err != nil {
		// The transport aborts the context upload on cancellation; the
		// cancellation signal surfaces through the request context, as the
		// real client does.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return engineBuildResult{}, &engineError{kind: engineErrClientCancelled, cause: ctxErr}
		}
		return engineBuildResult{}, err
	}
	b.captured.contextTar = blob
	if b.opts.StreamBlock != nil {
		select {
		case <-b.opts.StreamBlock:
		case <-ctx.Done():
			return engineBuildResult{Output: b.opts.Output, Truncated: b.opts.Truncated},
				&engineError{kind: engineErrClientCancelled, cause: ctx.Err()}
		}
	}
	return engineBuildResult{Output: b.opts.Output, Truncated: b.opts.Truncated}, b.opts.Err
}

// setupBuildSeam installs a fake Engine builder on the App and returns the
// capture handle.
func setupBuildSeam(t *testing.T, app *App, opts buildSeamOptions) *capturedBuild {
	t.Helper()
	captured := &capturedBuild{}
	app.NewEngineBuildFn = func() (engineImageBuilder, error) {
		if opts.ConstructErr != nil {
			return nil, opts.ConstructErr
		}
		return fakeEngineBuilder{captured: captured, opts: opts}, nil
	}
	return captured
}

// newOperationMux creates a mux with production routes registered for testing.
func newOperationMux(app *App) *http.ServeMux {
	mux := http.NewServeMux()
	registerRoutes(mux, app)
	return mux
}
