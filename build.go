package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

var ErrInternal = errors.New("internal error")

type buildRequest struct {
	Context    string `json:"context"`
	Dockerfile string `json:"dockerfile"`
	Image      string `json:"image"`
}

func (a *App) handleBuild(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}

	ctx := withSessionID(r.Context(), session.ID)

	var req buildRequest

	if err := decodeJSONRequest(w, r, &req); err != nil {
		writeError(ctx, w, http.StatusBadRequest, "invalid_json", "invalid JSON request")
		return
	}

	contextPath, dockerfilePath, err := validateBuildRequest(session.Workspace, req)
	if err != nil {
		if errors.Is(err, ErrInternal) {
			opLog(ctx).Error("build validation error",
				slog.String("operation", "build_validate"),
				slog.String("error", err.Error()),
			)
			writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
			return
		}
		writeError(ctx, w, http.StatusBadRequest, "invalid_build_context", "invalid build context")
		return
	}

	cfg := a.getConfig()
	bufSize := cfg.BuildLogMaxBytes

	op := newBuildOperation(session.ID, req.Image, req.Context, req.Dockerfile, bufSize)

	if a.OperationRegistry != nil {
		if !a.OperationRegistry.tryCreate(op) {
			writeError(ctx, w, http.StatusServiceUnavailable, "shutting_down", "daemon is shutting down")
			return
		}
		a.OperationRegistry.cleanup(cfg.OperationRetentionTTL, cfg.OperationMaxCompleted)
	}

	writeAuditWithRequestID(ctx, auditRecord{
		Event:       "build.start",
		SessionID:   session.ID,
		OperationID: op.ID,
		Image:       req.Image,
		Context:     req.Context,
		Dockerfile:  req.Dockerfile,
	})

	// Build the command synchronously and start it.
	args := []string{
		"build",
		"--pull",
		"--provenance=false",
		"--sbom=false",
		"--file", dockerfilePath,
		"--tag", req.Image,
		contextPath,
	}

	cmdCtx, cancel := context.WithCancel(context.Background())

	cmd := a.newBuildCmd(cmdCtx, "docker", args...)

	// Assign LogBuffer directly to stdout/stderr for thread-safe capture.
	// boundedBuffer implements io.Writer, so this works without pipes.
	cmd.Stdout = op.LogBuffer
	cmd.Stderr = op.LogBuffer

	// Start the process under op.mu so terminateAll can synchronize:
	// either we start the process (started=true), or terminateAll marks
	// it as terminated. There is no intermediate state.
	op.mu.Lock()
	if op.terminated {
		op.mu.Unlock()
		cancel()
		msg := "build cancelled: daemon is shutting down"
		op.fail("docker_build_failed", msg, nil)
		writeJSONRaw(ctx, w, http.StatusCreated, map[string]any{
			"ok":           true,
			"operation_id": op.ID,
			"status":       op.State,
		})
		return
	}
	startTime := time.Now()
	op.StartedAt = &startTime
	op.cmd = cmd

	// cmd.Start() is called while holding op.mu so terminateAll cannot
	// race between checking started and setting terminated.
	err = cmd.Start()
	op.started = err == nil
	op.mu.Unlock()

	if err != nil {
		cancel()
		msg := fmt.Sprintf("cannot start build: %v", err)
		op.fail("docker_build_failed", msg, nil)
		writeJSONRaw(ctx, w, http.StatusCreated, map[string]any{
			"ok":           true,
			"operation_id": op.ID,
			"status":       op.State,
		})
		return
	}

	// Start goroutine for process completion.
	// cmd.Stdout/stderr write directly into op.LogBuffer (no pipes needed).
	go func() {
		defer cancel()
		a.waitBuildCompletion(op, startTime)
	}()

	writeJSONRaw(ctx, w, http.StatusCreated, map[string]any{
		"ok":           true,
		"operation_id": op.ID,
		"status":       operationRunning,
	})
}

// newBuildCmd creates a new exec.Cmd for build operations.
// It uses ExecCommandContext if set (test seam), otherwise default.
func (a *App) newBuildCmd(ctx context.Context, name string, args ...string) *exec.Cmd {
	if a.ExecCommandContext != nil {
		return a.ExecCommandContext(ctx, name, args...)
	}
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd
}

// waitBuildCompletion waits for the build process to finish and transitions
// the operation to succeeded or failed. It is the single owner of cmd.Wait().
func (a *App) waitBuildCompletion(op *buildOperation, started time.Time) {
	err := op.cmd.Wait()
	duration := time.Since(started).Round(time.Millisecond).String()

	if err != nil {
		exitCode := extractExitCode(err)
		op.fail("docker_build_failed", "docker build failed", exitCode, &duration)
		return
	}

	op.succeed(&duration)
}

func (a *App) handleOperationStatus(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}

	ctx := withSessionID(r.Context(), session.ID)
	opID := r.PathValue("id")

	if a.OperationRegistry == nil {
		writeError(ctx, w, http.StatusNotFound, "operation_not_found", "operation not found")
		return
	}

	op := a.OperationRegistry.get(opID)
	if op == nil {
		writeError(ctx, w, http.StatusNotFound, "operation_not_found", "operation not found")
		return
	}

	if op.SessionID != session.ID {
		writeError(ctx, w, http.StatusNotFound, "operation_not_found", "operation not found")
		return
	}

	cfg := a.getConfig()
	if a.OperationRegistry != nil {
		a.OperationRegistry.cleanup(cfg.OperationRetentionTTL, cfg.OperationMaxCompleted)
	}

	op.mu.Lock()
	resp := map[string]any{
		"ok":           true,
		"operation_id": op.ID,
		"status":       op.State,
		"created_at":   op.CreatedAt,
	}
	if op.StartedAt != nil {
		resp["started_at"] = *op.StartedAt
	}
	if op.CompletedAt != nil {
		resp["completed_at"] = *op.CompletedAt
	}
	if op.Duration != nil {
		resp["duration"] = *op.Duration
	}
	if op.ExitCode != nil {
		resp["exit_code"] = *op.ExitCode
	}
	if op.ResultCode != nil {
		resp["result_code"] = *op.ResultCode
	}
	op.mu.Unlock()

	writeJSONRaw(ctx, w, http.StatusOK, resp)
}

func (a *App) handleOperationLogs(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}

	ctx := withSessionID(r.Context(), session.ID)
	opID := r.PathValue("id")

	if a.OperationRegistry == nil {
		writeError(ctx, w, http.StatusNotFound, "operation_not_found", "operation not found")
		return
	}

	op := a.OperationRegistry.get(opID)
	if op == nil {
		writeError(ctx, w, http.StatusNotFound, "operation_not_found", "operation not found")
		return
	}

	if op.SessionID != session.ID {
		writeError(ctx, w, http.StatusNotFound, "operation_not_found", "operation not found")
		return
	}

	offset, err := parseOffset(r.URL.Query().Get("offset"))
	if err != nil {
		writeError(ctx, w, http.StatusBadRequest, "invalid_offset", "invalid offset parameter")
		return
	}

	data, nextOffset, truncated := op.LogBuffer.Range(offset)

	resp := map[string]any{
		"ok":           true,
		"operation_id": opID,
		"offset":       offset,
		"next_offset":  nextOffset,
		"truncated":    truncated,
		"logs":         string(data),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		opLog(ctx).Error("encode operation logs",
			slog.String("error", err.Error()),
		)
	}
}

func parseOffset(s string) (int64, error) {
	if s == "" {
		return 0, nil
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, err
	}
	if v < 0 {
		return 0, errors.New("negative offset")
	}
	return v, nil
}

func validateBuildRequest(workspace string, req buildRequest) (string, string, error) {
	if req.Context == "" || req.Dockerfile == "" || req.Image == "" {
		return "", "", errors.New("context, dockerfile and image are required")
	}

	if filepath.IsAbs(req.Dockerfile) {
		return "", "", errors.New("dockerfile must be relative to context")
	}

	var err error
	var contextPath string

	if filepath.IsAbs(req.Context) {
		contextPath, err = filepath.Abs(req.Context)
		if err != nil {
			return "", "", fmt.Errorf("cannot resolve context: %w", err)
		}
	} else {
		contextPath = filepath.Join(workspace, req.Context)
	}

	contextPath, err = filepath.EvalSymlinks(contextPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", "", fmt.Errorf("context does not exist: %s", req.Context)
		}
		return "", "", fmt.Errorf("cannot resolve context: %w", err)
	}

	if !isInside(workspace, contextPath) {
		return "", "", fmt.Errorf("context must be inside workspace: %s", req.Context)
	}

	info, err := os.Stat(contextPath)
	if err != nil {
		return "", "", fmt.Errorf("cannot access context: %w", err)
	}
	if !info.IsDir() {
		return "", "", errors.New("context is not a directory")
	}

	dockerfilePath := filepath.Join(contextPath, req.Dockerfile)
	dockerfilePath, err = filepath.EvalSymlinks(dockerfilePath)
	if err != nil {
		return "", "", fmt.Errorf("cannot resolve dockerfile: %w", err)
	}

	if !isInside(contextPath, dockerfilePath) {
		return "", "", errors.New("dockerfile escapes build context")
	}

	info, err = os.Stat(dockerfilePath)
	if err != nil {
		return "", "", fmt.Errorf("cannot access dockerfile: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", "", errors.New("dockerfile is not a regular file")
	}

	return contextPath, dockerfilePath, nil
}

func isInside(parent, child string) bool {
	relative, err := filepath.Rel(parent, child)
	if err != nil {
		return false
	}

	return relative != ".." &&
		!strings.HasPrefix(relative, ".."+string(filepath.Separator))
}
