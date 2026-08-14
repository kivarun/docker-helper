//go:build linux

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestBuildDockerReceivesStagedPaths verifies Docker gets staged paths,
// not workspace paths.
func TestBuildDockerReceivesStagedPaths(t *testing.T) {
	app, _, token := setupBuildTest(t)

	var capturedArgs []string
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		capturedArgs = args
		return exec.CommandContext(ctx, "/bin/true")
	}

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	waitBuild(t, app, w)

	// --file should point to a staged path, not the workspace.
	var fileArg string
	for i, arg := range capturedArgs {
		if arg == "--file" && i+1 < len(capturedArgs) {
			fileArg = capturedArgs[i+1]
			break
		}
	}
	if fileArg == "" {
		t.Fatal("--file not found in args")
	}
	if fileArg == filepath.Join(app.Config.AllowedRoot, "Dockerfile") {
		t.Error("Docker should receive staged Dockerfile path, not workspace path")
	}

	// Last arg should be the staged context, not the workspace.
	lastArg := capturedArgs[len(capturedArgs)-1]
	if lastArg == app.Config.AllowedRoot {
		t.Error("Docker should receive staged context path, not workspace path")
	}
}

// TestBuildStagingErrorDoesNotRunDocker verifies that a staging error
// prevents Docker from running and does not register an operation.
func TestBuildStagingErrorDoesNotRunDocker(t *testing.T) {
	app, _, token := setupBuildTest(t)
	app.StageBuildContextFn = func(ctx context.Context, ws, cpath, dfrel, rdir, opID string) (*stagedBuildContext, error) {
		return nil, os.ErrInvalid
	}

	dockerCalled := false
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		dockerCalled = true
		return exec.CommandContext(ctx, name, args...)
	}

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected %d, got %d", http.StatusInternalServerError, w.Code)
	}
	if dockerCalled {
		t.Error("Docker should not be called when staging fails")
	}
}

// TestBuildTryCreateRejectCleansStaging verifies that when tryCreate
// rejects the operation, the staging directory is cleaned up.
func TestBuildTryCreateRejectCleansStaging(t *testing.T) {
	app, reg, token := setupBuildTest(t)

	var cleanupPath string
	app.StageBuildContextFn = func(ctx context.Context, ws, cpath, dfrel, rdir, opID string) (*stagedBuildContext, error) {
		d := t.TempDir()
		opDir := filepath.Join(d, opID)
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
		cleanupPath = opDir
		return &stagedBuildContext{
			ContextPath:    ctxDir,
			DockerfilePath: filepath.Join(ctxDir, dfrel),
			cleanupPath:    opDir,
		}, nil
	}

	reg.setShuttingDown()

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected %d, got %d", http.StatusServiceUnavailable, w.Code)
	}

	// Verify staging directory was cleaned up.
	if cleanupPath != "" {
		if _, err := os.Stat(cleanupPath); err == nil {
			t.Error("staging directory should be cleaned up after tryCreate rejection")
		}
	}
}

// TestBuildStartErrorCleansStaging verifies that a Docker start error
// triggers staging cleanup.
func TestBuildStartErrorCleansStaging(t *testing.T) {
	app, _, token := setupBuildTest(t)

	var cleanupPath string
	app.StageBuildContextFn = func(ctx context.Context, ws, cpath, dfrel, rdir, opID string) (*stagedBuildContext, error) {
		d := t.TempDir()
		opDir := filepath.Join(d, opID)
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
		cleanupPath = opDir
		return &stagedBuildContext{
			ContextPath:    ctxDir,
			DockerfilePath: filepath.Join(ctxDir, dfrel),
			cleanupPath:    opDir,
		}, nil
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/nonexistent/binary")
	}

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	opID, _ := resp["operation_id"].(string)
	op := app.OperationRegistry.get(opID)
	if op == nil {
		t.Fatal("operation not found")
	}
	op.Wait()

	if cleanupPath != "" {
		if _, err := os.Stat(cleanupPath); err == nil {
			t.Error("staging directory should be cleaned up after start error")
		}
	}
}

// TestBuildSuccessCleansStaging verifies that successful build completion
// triggers staging cleanup.
func TestBuildSuccessCleansStaging(t *testing.T) {
	app, _, token := setupBuildTest(t)

	var cleanupPath string
	app.StageBuildContextFn = func(ctx context.Context, ws, cpath, dfrel, rdir, opID string) (*stagedBuildContext, error) {
		d := t.TempDir()
		opDir := filepath.Join(d, opID)
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
		cleanupPath = opDir
		return &stagedBuildContext{
			ContextPath:    ctxDir,
			DockerfilePath: filepath.Join(ctxDir, dfrel),
			cleanupPath:    opDir,
		}, nil
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	waitBuild(t, app, w)

	if cleanupPath != "" {
		if _, err := os.Stat(cleanupPath); err == nil {
			t.Error("staging directory should be cleaned up after success")
		}
	}
}

// TestBuildWaitErrorCleansStaging verifies that a Docker wait error
// triggers staging cleanup.
func TestBuildWaitErrorCleansStaging(t *testing.T) {
	app, _, token := setupBuildTest(t)

	var cleanupPath string
	app.StageBuildContextFn = func(ctx context.Context, ws, cpath, dfrel, rdir, opID string) (*stagedBuildContext, error) {
		d := t.TempDir()
		opDir := filepath.Join(d, opID)
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
		cleanupPath = opDir
		return &stagedBuildContext{
			ContextPath:    ctxDir,
			DockerfilePath: filepath.Join(ctxDir, dfrel),
			cleanupPath:    opDir,
		}, nil
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/sh", "-c", "exit 1")
	}

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	waitBuild(t, app, w)

	if cleanupPath != "" {
		if _, err := os.Stat(cleanupPath); err == nil {
			t.Error("staging directory should be cleaned up after wait error")
		}
	}
}

// TestBuildShutdownCleansStaging verifies that shutdown/cancellation
// triggers staging cleanup.
func TestBuildShutdownCleansStaging(t *testing.T) {
	app, _, token := setupBuildTest(t)

	var cleanupPath string
	app.StageBuildContextFn = func(ctx context.Context, ws, cpath, dfrel, rdir, opID string) (*stagedBuildContext, error) {
		d := t.TempDir()
		opDir := filepath.Join(d, opID)
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
		cleanupPath = opDir
		return &stagedBuildContext{
			ContextPath:    ctxDir,
			DockerfilePath: filepath.Join(ctxDir, dfrel),
			cleanupPath:    opDir,
		}, nil
	}

	syncDir := t.TempDir()
	readyFile := filepath.Join(syncDir, "ready")
	releaseFile := filepath.Join(syncDir, "release")

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/sh", "-c",
			"touch "+readyFile+"; while [ ! -f "+releaseFile+" ]; do sleep 0.05; done")
	}

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	opID, _ := resp["operation_id"].(string)
	op := app.OperationRegistry.get(opID)
	if op == nil {
		t.Fatal("operation not found")
	}

	// Wait for the process to start.
	waitProcessReady(t, readyFile)

	// Cancel the operation.
	if err := app.OperationRegistry.terminateOne(opID, app.killContainerBestEffort); err != nil {
		t.Fatalf("terminateOne: %v", err)
	}

	// Release the process so it can exit.
	if err := os.WriteFile(releaseFile, nil, 0o644); err != nil {
		t.Fatalf("create release file: %v", err)
	}

	op.Wait()

	if cleanupPath != "" {
		if _, err := os.Stat(cleanupPath); err == nil {
			t.Error("staging directory should be cleaned up after cancellation")
		}
	}
}

// TestBuildStagedPathsContainContext verifies staged paths contain the
// expected staging directory structure.
func TestBuildStagedPathsContainContext(t *testing.T) {
	app, _, token := setupBuildTest(t)

	var capturedArgs []string
	var capturedOpDir string
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
		capturedOpDir = opDir
		return &stagedBuildContext{
			ContextPath:    ctxDir,
			DockerfilePath: filepath.Join(ctxDir, dfrel),
			cleanupPath:    opDir,
		}, nil
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		capturedArgs = args
		return exec.CommandContext(ctx, "/bin/true")
	}

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	waitBuild(t, app, w)

	// --file should be exactly the staged Dockerfile path.
	expectedDockerfile := filepath.Join(capturedOpDir, "context", "Dockerfile")
	var fileArg string
	for i, arg := range capturedArgs {
		if arg == "--file" && i+1 < len(capturedArgs) {
			fileArg = capturedArgs[i+1]
			break
		}
	}
	if fileArg == "" {
		t.Fatal("--file not found in args")
	}
	if fileArg != expectedDockerfile {
		t.Errorf("--file = %q, want %q", fileArg, expectedDockerfile)
	}

	// Last arg should be exactly the staged context path.
	expectedContext := filepath.Join(capturedOpDir, "context")
	lastArg := capturedArgs[len(capturedArgs)-1]
	if lastArg != expectedContext {
		t.Errorf("context = %q, want %q", lastArg, expectedContext)
	}
}

// TestBuildLifecycleWithStaging verifies the full build lifecycle
// (running -> succeeded) works correctly with staging.
func TestBuildLifecycleWithStaging(t *testing.T) {
	app, _, token := setupBuildTest(t)

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	opID, _ := resp["operation_id"].(string)
	op := app.OperationRegistry.get(opID)
	if op == nil {
		t.Fatal("operation not found")
	}
	op.Wait()

	if op.State != operationSucceeded {
		t.Errorf("expected 'succeeded', got %q", op.State)
	}
	if op.CompletedAt == nil {
		t.Error("expected CompletedAt to be set")
	}
	if op.Duration == nil {
		t.Error("expected Duration to be set")
	}
	if op.ResultCode == nil || *op.ResultCode != "succeeded" {
		t.Errorf("expected result_code 'succeeded', got %v", op.ResultCode)
	}
}

// TestBuildAuditWithStaging verifies audit events are emitted correctly
// with staging enabled.
func TestBuildAuditWithStaging(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app, _, _ := setupBuildTest(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	waitBuild(t, app, w)

	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	if len(records) < 2 {
		t.Fatalf("expected at least 2 audit records, got %d", len(records))
	}

	startRec := records[0]
	if startRec.Event != "build.start" {
		t.Errorf("expected 'build.start', got %q", startRec.Event)
	}
	if startRec.Image != "example:test" {
		t.Errorf("expected image 'example:test', got %q", startRec.Image)
	}
	if startRec.Context != "." {
		t.Errorf("expected context '.', got %q", startRec.Context)
	}
	if startRec.Dockerfile != "Dockerfile" {
		t.Errorf("expected dockerfile 'Dockerfile', got %q", startRec.Dockerfile)
	}

	finishRec := records[len(records)-1]
	if finishRec.Event != "build.finish" {
		t.Errorf("expected 'build.finish', got %q", finishRec.Event)
	}
	if finishRec.Result != "succeeded" {
		t.Errorf("expected result 'succeeded', got %q", finishRec.Result)
	}
}

// TestBuildStagingErrorNoOperationRegistered verifies that when staging
// fails, no operation is registered in the registry.
func TestBuildStagingErrorNoOperationRegistered(t *testing.T) {
	app, reg, token := setupBuildTest(t)
	app.StageBuildContextFn = func(ctx context.Context, ws, cpath, dfrel, rdir, opID string) (*stagedBuildContext, error) {
		return nil, os.ErrInvalid
	}

	initialCount := 0
	reg.mu.RLock()
	for range reg.ops {
		initialCount++
	}
	reg.mu.RUnlock()

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected %d, got %d", http.StatusInternalServerError, w.Code)
	}

	reg.mu.RLock()
	finalCount := len(reg.ops)
	reg.mu.RUnlock()

	if finalCount != initialCount {
		t.Errorf("no operation should be registered after staging error: had %d, now %d", initialCount, finalCount)
	}
}

// TestBuildDockerfileDotSlash verifies that "./Dockerfile" is normalized
// to "Dockerfile" and passed correctly to staging.
func TestBuildDockerfileDotSlash(t *testing.T) {
	app, _, token := setupBuildTest(t)

	var capture capturedStaging
	app.StageBuildContextFn = stagingSeamWithCapture(t, &capture)

	var capturedArgs []string
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		capturedArgs = args
		return exec.CommandContext(ctx, "/bin/true")
	}

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "./Dockerfile",
		"image":      "example:test",
	}, token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	waitBuild(t, app, w)

	// dockerfileRel should be normalized to "Dockerfile".
	if capture.dockerfileRel != "Dockerfile" {
		t.Errorf("dockerfileRel = %q, want %q", capture.dockerfileRel, "Dockerfile")
	}

	// --file should point to the staged Dockerfile with exact path.
	var fileArg string
	for i, arg := range capturedArgs {
		if arg == "--file" && i+1 < len(capturedArgs) {
			fileArg = capturedArgs[i+1]
			break
		}
	}
	if fileArg == "" {
		t.Fatal("--file not found in args")
	}
	if filepath.Base(fileArg) != "Dockerfile" {
		t.Errorf("--file base = %q, want %q", filepath.Base(fileArg), "Dockerfile")
	}
}

// TestBuildDockerfileDotDotPath verifies that a path with normalizable ".."
// inside context (e.g., "subdir/../Dockerfile") is resolved correctly.
func TestBuildDockerfileDotDotPath(t *testing.T) {
	app, _, token := setupBuildTest(t)

	subdir := filepath.Join(app.Config.AllowedRoot, "subdir")
	if err := os.MkdirAll(subdir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Create the Dockerfile at the workspace root, reference via subdir/../Dockerfile.
	dockerfilePath := filepath.Join(app.Config.AllowedRoot, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM alpine"), 0o644); err != nil {
		t.Fatal(err)
	}

	var capture capturedStaging
	app.StageBuildContextFn = stagingSeamWithCapture(t, &capture)

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "subdir/../Dockerfile",
		"image":      "example:test",
	}, token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	waitBuild(t, app, w)

	// dockerfileRel should be normalized to "Dockerfile".
	if capture.dockerfileRel != "Dockerfile" {
		t.Errorf("dockerfileRel = %q, want %q", capture.dockerfileRel, "Dockerfile")
	}
}

// TestBuildDockerfileSymlink verifies that a symlink Dockerfile pointing
// to a regular file inside context is resolved correctly.
func TestBuildDockerfileSymlink(t *testing.T) {
	app, _, token := setupBuildTest(t)

	// Remove the default Dockerfile so we can create our symlink.
	os.Remove(filepath.Join(app.Config.AllowedRoot, "Dockerfile"))

	// Create a real Dockerfile and a symlink to it.
	realDockerfile := filepath.Join(app.Config.AllowedRoot, "real.Dockerfile")
	if err := os.WriteFile(realDockerfile, []byte("FROM alpine"), 0o644); err != nil {
		t.Fatal(err)
	}
	symlinkDockerfile := filepath.Join(app.Config.AllowedRoot, "Dockerfile")
	if err := os.Symlink("real.Dockerfile", symlinkDockerfile); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	var capture capturedStaging
	app.StageBuildContextFn = stagingSeamWithCapture(t, &capture)

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	waitBuild(t, app, w)

	// dockerfileRel should resolve to the real file inside context.
	if capture.dockerfileRel != "real.Dockerfile" {
		t.Errorf("dockerfileRel = %q, want %q", capture.dockerfileRel, "real.Dockerfile")
	}
}

// TestBuildStagedPathsExactSentinel verifies Docker gets exact staged paths
// using sentinel directory names, not fuzzy string matching.
func TestBuildStagedPathsExactSentinel(t *testing.T) {
	app, _, token := setupBuildTest(t)

	var capturedArgs []string
	var capturedOpDir string
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
		capturedOpDir = opDir
		return &stagedBuildContext{
			ContextPath:    ctxDir,
			DockerfilePath: filepath.Join(ctxDir, dfrel),
			cleanupPath:    opDir,
		}, nil
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		capturedArgs = args
		return exec.CommandContext(ctx, "/bin/true")
	}

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	waitBuild(t, app, w)

	// --file should be exactly the staged Dockerfile path.
	expectedDockerfile := filepath.Join(capturedOpDir, "context", "Dockerfile")
	var fileArg string
	for i, arg := range capturedArgs {
		if arg == "--file" && i+1 < len(capturedArgs) {
			fileArg = capturedArgs[i+1]
			break
		}
	}
	if fileArg != expectedDockerfile {
		t.Errorf("--file = %q, want %q", fileArg, expectedDockerfile)
	}

	// Last arg should be exactly the staged context path.
	expectedContext := filepath.Join(capturedOpDir, "context")
	lastArg := capturedArgs[len(capturedArgs)-1]
	if lastArg != expectedContext {
		t.Errorf("context = %q, want %q", lastArg, expectedContext)
	}
}

// TestStagedCleanupReturnsError verifies that Cleanup() returns the error
// from os.RemoveAll and that repeated calls return the same error.
func TestStagedCleanupReturnsError(t *testing.T) {
	s := newTestStagedContext(t, "Dockerfile")

	// First cleanup should succeed.
	err1 := s.Cleanup()
	if err1 != nil {
		t.Errorf("first Cleanup() error = %v", err1)
	}

	// Second cleanup should return nil (already cleaned, idempotent).
	err2 := s.Cleanup()
	if err2 != nil {
		t.Errorf("second Cleanup() error = %v", err2)
	}

	// Directory should be gone.
	if _, err := os.Stat(s.ContextPath); err == nil {
		t.Error("staging directory should be removed after Cleanup")
	}
}

// TestStagedCleanupConcurrentExactlyOnce verifies that concurrent Cleanup()
// calls result in exactly one deletion and all callers get the same result.
func TestStagedCleanupConcurrentExactlyOnce(t *testing.T) {
	s := newTestStagedContext(t, "Dockerfile")

	var (
		wg       sync.WaitGroup
		errCount int32
		nilCount int32
		cleanupN int32
	)

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := s.Cleanup()
			if err != nil {
				atomic.AddInt32(&errCount, 1)
			} else {
				atomic.AddInt32(&nilCount, 1)
			}
			atomic.AddInt32(&cleanupN, 1)
		}()
	}
	wg.Wait()

	// All calls should return (some may return nil, some may not — but only
	// one actual deletion happens). The important thing is all 20 calls complete.
	if cleanupN != 20 {
		t.Errorf("cleanup calls = %d, want 20", cleanupN)
	}

	// All results should be consistent (all nil or all same error).
	// Since we're on a temp dir, all should be nil.
	if errCount != 0 {
		t.Errorf("unexpected errors: %d nil, %d err", nilCount, errCount)
	}

	// Directory should be gone.
	if _, err := os.Stat(s.ContextPath); err == nil {
		t.Error("staging directory should be removed after concurrent Cleanup")
	}
}

// TestStagedCleanupErrorLogged verifies that a cleanup error is logged
// with the operation ID in the operational log.
func TestStagedCleanupErrorLogged(t *testing.T) {
	_, opLogBuf := setupTestLogging(t)

	app, _, token := setupBuildTest(t)
	app.StageBuildContextFn = stagingSeamWithCleanupError(t)

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	waitBuild(t, app, w)

	// Operational log should contain the cleanup error with operation ID.
	opLogContent := opLogBuf.String()
	if !strings.Contains(opLogContent, "staging cleanup failed") {
		t.Errorf("operational log should contain cleanup error, got: %s", opLogContent)
	}
}

// TestBuildCleanupOnErrorPreservesSemantics verifies that cleanup errors
// do not change the HTTP response, operation state, or result code.
func TestBuildCleanupOnErrorPreservesSemantics(t *testing.T) {
	_, opLogBuf := setupTestLogging(t)

	app, _, token := setupBuildTest(t)
	app.StageBuildContextFn = stagingSeamWithCleanupError(t)

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	opID, _ := resp["operation_id"].(string)
	op := app.OperationRegistry.get(opID)
	if op == nil {
		t.Fatal("operation not found")
	}
	op.Wait()

	// Operation should still succeed despite cleanup error.
	if op.State != operationSucceeded {
		t.Errorf("state = %q, want %q", op.State, operationSucceeded)
	}
	if op.ResultCode == nil || *op.ResultCode != "succeeded" {
		t.Errorf("result_code = %v, want %q", op.ResultCode, "succeeded")
	}

	// Cleanup error should be logged.
	opLogContent := opLogBuf.String()
	if !strings.Contains(opLogContent, "staging cleanup failed") {
		t.Errorf("cleanup error should be logged, got: %s", opLogContent)
	}
}

// TestBuildCancelCleanupErrorPreservesResult verifies that when explicit
// cancel triggers cleanup with an error, the operation result is still cancelled.
func TestBuildCancelCleanupErrorPreservesResult(t *testing.T) {
	_, opLogBuf := setupTestLogging(t)

	app, _, token := setupBuildTest(t)
	app.StageBuildContextFn = stagingSeamWithCleanupError(t)

	syncDir := t.TempDir()
	readyFile := filepath.Join(syncDir, "ready")
	releaseFile := filepath.Join(syncDir, "release")

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/sh", "-c",
			"touch "+readyFile+"; while [ ! -f "+releaseFile+" ]; do sleep 0.05; done")
	}

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	opID, _ := resp["operation_id"].(string)
	op := app.OperationRegistry.get(opID)
	if op == nil {
		t.Fatal("operation not found")
	}

	waitProcessReady(t, readyFile)

	// Cancel the operation.
	if err := app.OperationRegistry.terminateOne(opID, app.killContainerBestEffort); err != nil {
		t.Fatalf("terminateOne: %v", err)
	}

	if err := os.WriteFile(releaseFile, nil, 0o644); err != nil {
		t.Fatalf("create release file: %v", err)
	}

	op.Wait()

	// Result should be cancelled despite cleanup error.
	if op.ResultCode == nil || *op.ResultCode != resultCancelled {
		t.Errorf("result_code = %v, want %q", op.ResultCode, resultCancelled)
	}

	// Cleanup error should be logged.
	opLogContent := opLogBuf.String()
	if !strings.Contains(opLogContent, "staging cleanup failed") {
		t.Errorf("cleanup error should be logged on cancel, got: %s", opLogContent)
	}
}

// TestBuildShutdownCleanupErrorPreservesResult verifies that when daemon
// shutdown triggers cleanup with an error, the operation result is not cancelled.
func TestBuildShutdownCleanupErrorPreservesResult(t *testing.T) {
	_, opLogBuf := setupTestLogging(t)

	app, _, token := setupBuildTest(t)
	app.StageBuildContextFn = stagingSeamWithCleanupError(t)

	syncDir := t.TempDir()
	readyFile := filepath.Join(syncDir, "ready")
	releaseFile := filepath.Join(syncDir, "release")

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/sh", "-c",
			"touch "+readyFile+"; while [ ! -f "+releaseFile+" ]; do sleep 0.05; done")
	}

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	opID, _ := resp["operation_id"].(string)
	op := app.OperationRegistry.get(opID)
	if op == nil {
		t.Fatal("operation not found")
	}

	waitProcessReady(t, readyFile)

	// Simulate daemon shutdown.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	app.OperationRegistry.terminateAll(ctx, app.killContainerBestEffort)

	if err := os.WriteFile(releaseFile, nil, 0o644); err != nil {
		t.Fatalf("create release file: %v", err)
	}

	op.Wait()

	// Result should NOT be cancelled (shutdown semantics).
	op.mu.Lock()
	rc := ""
	if op.ResultCode != nil {
		rc = *op.ResultCode
	}
	op.mu.Unlock()

	if rc == "cancelled" {
		t.Errorf("shutdown should not produce result_code 'cancelled', got %q", rc)
	}

	// Cleanup error should be logged.
	opLogContent := opLogBuf.String()
	if !strings.Contains(opLogContent, "staging cleanup failed") {
		t.Errorf("cleanup error should be logged on shutdown, got: %s", opLogContent)
	}
}
