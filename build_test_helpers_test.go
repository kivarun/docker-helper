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
