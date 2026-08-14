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
	"testing"
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

	// --file should contain "context" in its path (staging structure).
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
	if !strings.Contains(fileArg, "context") {
		t.Errorf("--file path should contain 'context': %s", fileArg)
	}

	// Last arg should contain "context" in its path.
	lastArg := capturedArgs[len(capturedArgs)-1]
	if !strings.Contains(lastArg, "context") {
		t.Errorf("context path should contain 'context': %s", lastArg)
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
