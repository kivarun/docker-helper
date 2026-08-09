package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
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
	bufSize := cfg.OperationLogMaxBytes

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

	cmd := a.newOperationCmd(cmdCtx, "docker", args...)

	result := startOperationProcess(cmd, op)

	if result.Terminated {
		cancel()
		msg := "build cancelled: daemon is shutting down"
		if op.cancelled {
			op.fail(resultCancelled, msg, nil)
		} else {
			op.fail("docker_build_failed", msg, nil)
		}
		writeJSONRaw(ctx, w, http.StatusCreated, map[string]any{
			"ok":           true,
			"operation_id": op.ID,
			"status":       op.State,
		})
		return
	}
	if result.Err != nil {
		cancel()
		msg := fmt.Sprintf("cannot start build: %v", result.Err)
		op.fail("docker_build_failed", msg, nil)
		writeJSONRaw(ctx, w, http.StatusCreated, map[string]any{
			"ok":           true,
			"operation_id": op.ID,
			"status":       op.State,
		})
		return
	}

	// Start goroutine for process completion.
	go func() {
		defer cancel()
		a.waitBuildCompletion(op, *op.StartedAt)
	}()

	writeJSONRaw(ctx, w, http.StatusCreated, map[string]any{
		"ok":           true,
		"operation_id": op.ID,
		"status":       operationRunning,
	})
}

// waitBuildCompletion waits for the build process to finish and transitions
// the operation to succeeded or failed. It is the single owner of cmd.Wait().
func (a *App) waitBuildCompletion(op *operation, started time.Time) {
	err := op.cmd.Wait()
	duration := time.Since(started).Round(time.Millisecond).String()

	op.mu.Lock()
	wasCancelled := op.cancelled
	op.mu.Unlock()

	if err != nil {
		exitCode := extractExitCode(err)
		if wasCancelled {
			op.fail(resultCancelled, "build cancelled", exitCode, &duration)
			return
		}
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
	if opID == "" {
		// Fallback for unit tests that call the handler directly.
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) >= 3 && parts[1] == "operations" {
			opID = parts[2]
		}
	}

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
	if opID == "" {
		// Fallback for unit tests that call the handler directly.
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) >= 4 && parts[1] == "operations" && parts[3] == "logs" {
			opID = parts[2]
		}
	}

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

func (a *App) handleOperationCancel(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}

	ctx := withSessionID(r.Context(), session.ID)
	opID := r.PathValue("id")
	if opID == "" {
		// Fallback for unit tests that call the handler directly.
		// Parse /operations/{id}/cancel from the URL path.
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) >= 4 && parts[1] == "operations" && parts[3] == "cancel" {
			opID = parts[2]
		}
	}

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

	// Check if operation is already terminal.
	op.mu.Lock()
	if op.CompletedAt != nil {
		state := op.State
		rc := ""
		if op.ResultCode != nil {
			rc = *op.ResultCode
		}
		op.mu.Unlock()
		writeJSONRaw(ctx, w, http.StatusOK, map[string]any{
			"ok":           true,
			"operation_id": op.ID,
			"status":       state,
			"result_code":  rc,
		})
		return
	}
	op.mu.Unlock()

	// Initiate cancellation and wait for completion.
	if err := a.OperationRegistry.terminateOne(opID, a.killContainerBestEffort); err != nil {
		if err.Error() == "not_found" {
			writeError(ctx, w, http.StatusNotFound, "operation_not_found", "operation not found")
			return
		}
		if err.Error() == "already_terminal" {
			writeJSONRaw(ctx, w, http.StatusOK, map[string]any{
				"ok":           true,
				"operation_id": op.ID,
				"status":       op.State,
			})
			return
		}
		writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}

	// Wait for the operation to complete.
	op.Wait()

	// Return terminal state.
	op.mu.Lock()
	resp := map[string]any{
		"ok":           true,
		"operation_id": op.ID,
		"status":       op.State,
	}
	if op.ResultCode != nil {
		resp["result_code"] = *op.ResultCode
	}
	if op.ExitCode != nil {
		resp["exit_code"] = *op.ExitCode
	}
	op.mu.Unlock()

	writeJSONRaw(ctx, w, http.StatusOK, resp)
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
