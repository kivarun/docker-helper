package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

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
		writeError(ctx, w, http.StatusBadRequest, "invalid_build_context", "invalid build context")
		return
	}

	// Compute canonical relative Dockerfile path from the resolved absolute path.
	dockerfileRel, err := filepath.Rel(contextPath, dockerfilePath)
	if err != nil || !filepath.IsLocal(dockerfileRel) || dockerfileRel == "." {
		writeError(ctx, w, http.StatusBadRequest, "invalid_build_context", "invalid build context")
		return
	}

	// Validate build-arg names and collect sorted keys.
	buildArgKeys, err := validateBuildArgs(req.BuildArgs)
	if err != nil {
		writeError(ctx, w, http.StatusBadRequest, "invalid_build_args", "invalid build args")
		return
	}

	cfg := a.getConfig()
	bufSize := cfg.OperationLogMaxBytes

	// Ensure the session Docker config directory exists before registering
	// the operation so that a failure here does not leave a zombie operation.
	dockerDir, err := ensureSessionDockerDir(cfg.RuntimeDir, session.ID)
	if err != nil {
		opLog(ctx).Error("cannot create session Docker directory",
			slog.String("operation", "build"),
			slog.String("error", err.Error()),
		)
		writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}

	// Create the operation first so we have an ID for staging.
	op := newBuildOperation(session.ID, req.Image, req.Context, req.Dockerfile, bufSize, session.PrincipalName)
	op.auditBuildArgKeys = buildArgKeys

	// Stage the build context into an isolated directory.
	staged, err := a.stageBuildContext(ctx, session.Workspace, contextPath, dockerfileRel, cfg.RuntimeDir, op.ID)
	if err != nil {
		opLog(ctx).Error("build context staging failed",
			slog.String("operation", "build"),
			slog.String("error", err.Error()),
		)
		writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}

	if a.OperationRegistry != nil {
		if !a.OperationRegistry.tryCreate(op) {
			if err := staged.Cleanup(); err != nil {
				opLog(ctx).Error("staging cleanup failed after tryCreate rejection",
					slog.String("operation", op.ID),
					slog.String("error", err.Error()),
				)
			}
			writeError(ctx, w, http.StatusServiceUnavailable, "shutting_down", "daemon is shutting down")
			return
		}
		a.OperationRegistry.cleanup(cfg.OperationRetentionTTL, cfg.OperationMaxCompleted)
	}

	writeAuditWithRequestID(ctx, auditRecord{
		Event:         "build.start",
		SessionID:     session.ID,
		OperationID:   op.ID,
		Image:         req.Image,
		Context:       req.Context,
		Dockerfile:    req.Dockerfile,
		BuildArgKeys:  buildArgKeys,
		PrincipalName: session.PrincipalName,
	})

	// Build the command using staged paths — Docker never sees workspace paths.
	args := []string{
		"--config", dockerDir,
		"build",
		"--pull",
		"--provenance=false",
		"--sbom=false",
		"--file", staged.DockerfilePath,
		"--tag", req.Image,
	}

	// Append build-arg entries in sorted key order.
	for _, key := range buildArgKeys {
		args = append(args, "--build-arg", key+"="+req.BuildArgs[key])
	}
	args = append(args, staged.ContextPath)

	cmdCtx, cancel := context.WithCancel(context.Background())

	cmd := a.newOperationCmd(cmdCtx, "docker", args...)

	result := startOperationProcess(cmd, op)

	if result.Terminated {
		cancel()
		if err := staged.Cleanup(); err != nil {
			opLog(ctx).Error("staging cleanup failed after pre-start termination",
				slog.String("operation", op.ID),
				slog.String("error", err.Error()),
			)
		}
		msg := "build cancelled: daemon is shutting down"
		if op.reason == terminationCancelled {
			msg = "build cancelled"
			op.fail(resultCancelled, msg, nil)
		} else {
			op.fail("docker_build_failed", msg, nil)
		}
		writeOperationCreated(ctx, w, op.ID, op.State)
		return
	}
	if result.Err != nil {
		cancel()
		if err := staged.Cleanup(); err != nil {
			opLog(ctx).Error("staging cleanup failed after start error",
				slog.String("operation", op.ID),
				slog.String("error", err.Error()),
			)
		}
		opLog(ctx).Error("cannot start build process",
			slog.String("operation", "build"),
			slog.String("error", result.Err.Error()),
		)
		msg := fmt.Sprintf("cannot start build: %v", result.Err)
		op.fail("docker_build_failed", msg, nil)
		writeOperationCreated(ctx, w, op.ID, op.State)
		return
	}

	// Store staged context for cleanup in waitBuildCompletion.
	op.stagedCtx = staged

	// Start goroutine for process completion.
	go func() {
		defer cancel()
		a.waitBuildCompletion(op, *op.StartedAt)
	}()

	writeOperationCreated(ctx, w, op.ID, operationRunning)
}

// waitBuildCompletion waits for the build process to finish and transitions
// the operation to succeeded or failed. It is the single owner of cmd.Wait().
func (a *App) waitBuildCompletion(op *operation, started time.Time) {
	err := op.cmd.Wait()

	// Cleanup staging directory regardless of outcome.
	if op.stagedCtx != nil {
		if cerr := op.stagedCtx.Cleanup(); cerr != nil {
			l := logging.snapshotLogger()
			if l != nil {
				l.Error("staging cleanup failed",
					slog.String("operation", op.ID),
					slog.String("error", cerr.Error()),
				)
			}
		}
	}

	duration := time.Since(started).Round(time.Millisecond).String()

	op.mu.Lock()
	wasCancelled := op.reason == terminationCancelled
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

// operationForSession looks up an operation by ID and verifies it belongs
// to the given session. Returns nil if the registry is nil, the operation
// does not exist, or it belongs to a different session.
func (a *App) operationForSession(sessionID, operationID string) *operation {
	if a.OperationRegistry == nil {
		return nil
	}
	op := a.OperationRegistry.get(operationID)
	if op == nil {
		return nil
	}
	if op.SessionID != sessionID {
		return nil
	}
	return op
}

func (a *App) handleOperationStatus(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}

	ctx := withSessionID(r.Context(), session.ID)
	opID := r.PathValue("id")

	op := a.operationForSession(session.ID, opID)
	if op == nil {
		writeError(ctx, w, http.StatusNotFound, "operation_not_found", "operation not found")
		return
	}

	cfg := a.getConfig()
	if a.OperationRegistry != nil {
		a.OperationRegistry.cleanup(cfg.OperationRetentionTTL, cfg.OperationMaxCompleted)
	}

	op.mu.Lock()
	resp := operationStatusResponse{
		OK:          true,
		OperationID: op.ID,
		Status:      op.State,
		CreatedAt:   op.CreatedAt,
		StartedAt:   op.StartedAt,
		CompletedAt: op.CompletedAt,
		Duration:    op.Duration,
		ExitCode:    op.ExitCode,
		ResultCode:  op.ResultCode,
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

	op := a.operationForSession(session.ID, opID)
	if op == nil {
		writeError(ctx, w, http.StatusNotFound, "operation_not_found", "operation not found")
		return
	}

	offset, err := parseOffset(r.URL.Query().Get("offset"))
	if err != nil {
		writeError(ctx, w, http.StatusBadRequest, "invalid_offset", "invalid offset parameter")
		return
	}

	data, nextOffset, truncated := op.LogBuffer.Range(offset)

	resp := operationLogsResponse{
		OK:          true,
		OperationID: opID,
		Offset:      offset,
		NextOffset:  nextOffset,
		Truncated:   truncated,
		Logs:        string(data),
	}

	writeJSONRaw(ctx, w, http.StatusOK, resp)
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

	op := a.operationForSession(session.ID, opID)
	if op == nil {
		writeError(ctx, w, http.StatusNotFound, "operation_not_found", "operation not found")
		return
	}

	// Check if operation is already terminal.
	op.mu.Lock()
	if op.CompletedAt != nil {
		resp := operationCancelResponse{
			OK:          true,
			OperationID: op.ID,
			Status:      op.State,
			ResultCode:  op.ResultCode,
		}
		op.mu.Unlock()
		writeJSONRaw(ctx, w, http.StatusOK, resp)
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
			resp := operationCancelResponse{
				OK:          true,
				OperationID: op.ID,
				Status:      op.State,
			}
			writeJSONRaw(ctx, w, http.StatusOK, resp)
			return
		}
		writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}

	// Wait for the operation to complete.
	op.Wait()

	// Return terminal state.
	op.mu.Lock()
	resp := operationCancelResponse{
		OK:          true,
		OperationID: op.ID,
		Status:      op.State,
		ExitCode:    op.ExitCode,
		ResultCode:  op.ResultCode,
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

// validateBuildArgs validates build-arg names and returns sorted keys.
// Empty map or nil returns nil keys with no error.
func validateBuildArgs(args map[string]string) ([]string, error) {
	if len(args) == 0 {
		return nil, nil
	}
	keys := make([]string, 0, len(args))
	for k := range args {
		if !envNamePattern.MatchString(k) {
			return nil, fmt.Errorf("invalid build arg name: %q", k)
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys, nil
}
