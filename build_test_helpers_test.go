package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// setupStagingSeam configures a fake staging function on the given app.
// The fake staging creates a minimal staging directory with the Dockerfile
// copied from the source context.
func setupStagingSeam(t *testing.T, app *App) {
	t.Helper()
	app.StageBuildContextFn = func(ctx context.Context, ws, cpath, dfrel, rdir, opID string) (*stagedBuildContext, error) {
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
		return &stagedBuildContext{
			ContextPath:    ctxDir,
			DockerfilePath: filepath.Join(ctxDir, dfrel),
			cleanupPath:    opDir,
		}, nil
	}
}

// newTestAppWithAuthAndStaging creates a test app with auth and staging seam.
func newTestAppWithAuthAndStaging(t *testing.T) *App {
	t.Helper()
	app := newTestAppWithAuth(t)
	setupStagingSeam(t, app)
	return app
}

// capturedStaging holds the dockerfileRel value captured by a staging seam.
type capturedStaging struct {
	dockerfileRel string
	cleanupPath   string
}

// stagingSeamWithCapture creates a staging seam that captures the dockerfileRel
// argument and returns a real staged context.
func stagingSeamWithCapture(t *testing.T, capture *capturedStaging) func(context.Context, string, string, string, string, string) (*stagedBuildContext, error) {
	t.Helper()
	return func(ctx context.Context, ws, cpath, dfrel, rdir, opID string) (*stagedBuildContext, error) {
		capture.dockerfileRel = dfrel
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
		capture.cleanupPath = opDir
		return &stagedBuildContext{
			ContextPath:    ctxDir,
			DockerfilePath: filepath.Join(ctxDir, dfrel),
			cleanupPath:    opDir,
		}, nil
	}
}

// newTestStagedContext creates a fake staged context in a temp directory
// with the given dockerfile relative path.
func newTestStagedContext(t *testing.T, dfrel string) *stagedBuildContext {
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
	}
}

// stagingSeamWithCleanupError creates a staging seam where Cleanup() will fail
// because the parent directory is made unwritable before cleanup runs.
// The parent permissions are restored after the staged context is created
// so that temp directory cleanup can proceed.
func stagingSeamWithCleanupError(t *testing.T) func(context.Context, string, string, string, string, string) (*stagedBuildContext, error) {
	t.Helper()
	return func(ctx context.Context, ws, cpath, dfrel, rdir, opID string) (*stagedBuildContext, error) {
		stagingDir := t.TempDir()
		opDir := filepath.Join(stagingDir, "opdir")
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
		// Make parent of opDir unwritable so RemoveAll fails,
		// then immediately restore so temp dir cleanup works.
		os.Chmod(stagingDir, 0o555)
		s := &stagedBuildContext{
			ContextPath:    ctxDir,
			DockerfilePath: filepath.Join(ctxDir, dfrel),
			cleanupPath:    opDir,
		}
		// Restore permissions after staging so test cleanup works.
		// The staged context still points to the unwritable dir,
		// so Cleanup() will fail when called.
		os.Chmod(stagingDir, 0o755)
		// Re-restrict so Cleanup() actually fails.
		// We use a channel to defer the restore until test end.
		restoreCh := make(chan struct{})
		go func() {
			<-restoreCh
			os.Chmod(stagingDir, 0o755)
		}()
		t.Cleanup(func() { close(restoreCh) })
		// Re-restrict for the actual test.
		os.Chmod(stagingDir, 0o555)
		return s, nil
	}
}
