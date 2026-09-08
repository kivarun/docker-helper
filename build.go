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
	"time"
)

func (a *App) handleBuild(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSessionCapability(w, r)
	if !ok {
		return
	}

	ctx := withSessionID(r.Context(), session.ID)

	var req buildRequest

	if err := decodeJSONRequest(w, r, &req); err != nil {
		writeDockerActionRejected(ctx, w, http.StatusBadRequest, "build", "invalid_json", "invalid JSON request", session.PrincipalName)
		return
	}

	// Acquire workspace-use lease BEFORE any filesystem access that depends
	// on workspace MAC coverage. This reserves MAC state through the
	// staging work and the Engine build.
	var leaseRelease func()
	if a.MACCoordinator != nil {
		var leaseErr error
		_, leaseRelease, leaseErr = a.MACCoordinator.AcquireWorkspaceUse(session.ID, session.Workspace)
		if leaseErr != nil {
			opLog(ctx).Error("cannot acquire workspace-use lease",
				slog.String("operation", "build"),
				slog.String("error", leaseErr.Error()),
			)
			writeDockerActionRejected(ctx, w, http.StatusInternalServerError, "build", "internal_error", "internal server error", session.PrincipalName)
			return
		}
	}

	contextPath, dockerfilePath, err := validateBuildRequest(session.Workspace, req)
	if err != nil {
		if leaseRelease != nil {
			leaseRelease()
		}
		writeDockerActionRejected(ctx, w, http.StatusBadRequest, "build", "invalid_build_context", "invalid build context", session.PrincipalName)
		return
	}

	// Compute canonical relative Dockerfile path from the resolved absolute path.
	dockerfileRel, err := filepath.Rel(contextPath, dockerfilePath)
	if err != nil || !filepath.IsLocal(dockerfileRel) || dockerfileRel == "." {
		if leaseRelease != nil {
			leaseRelease()
		}
		writeDockerActionRejected(ctx, w, http.StatusBadRequest, "build", "invalid_build_context", "invalid build context", session.PrincipalName)
		return
	}

	// Validate build-arg names and collect sorted keys.
	buildArgKeys, err := validateBuildArgs(req.BuildArgs)
	if err != nil {
		if leaseRelease != nil {
			leaseRelease()
		}
		writeDockerActionRejected(ctx, w, http.StatusBadRequest, "build", "invalid_build_args", "invalid build args", session.PrincipalName)
		return
	}

	// Synchronous Engine builds are admitted through the coordinator with
	// the build's Launcher admission state: daemon-shutdown refusal,
	// Launcher-quiesce refusal, request-context cancellation, and bounded
	// shutdown termination are its contract. A synchronous build has no
	// operation identity.
	engineCtx, syncReq, decision := a.SyncExecutionCoordinator.admitLauncherScoped(ctx, session.LauncherID, a.OperationSupervisor.launcherQuiesced)
	if decision != admissionAccepted {
		if leaseRelease != nil {
			leaseRelease()
		}
		if decision == admissionRefusedShutdown {
			writeDockerActionRejected(ctx, w, http.StatusServiceUnavailable, "build", "shutting_down", "daemon is shutting down", session.PrincipalName)
		} else {
			writeDockerActionRejected(ctx, w, http.StatusUnprocessableEntity, "build", "launcher_unavailable", "launcher is not available", session.PrincipalName)
		}
		return
	}
	defer syncReq.end()

	writeRequestContextAudit(ctx, auditRecord{
		Event:         "build.start",
		SessionID:     session.ID,
		Image:         req.Image,
		Context:       req.Context,
		Dockerfile:    req.Dockerfile,
		BuildArgKeys:  buildArgKeys,
		PrincipalName: session.PrincipalName,
		LauncherID:    session.LauncherID,
		LauncherName:  session.LauncherName,
	})

	started := time.Now()
	finishAudit := func(result string) {
		writeRequestContextAudit(ctx, auditRecord{
			Event:         "build.finish",
			SessionID:     session.ID,
			Image:         req.Image,
			Context:       req.Context,
			Dockerfile:    req.Dockerfile,
			BuildArgKeys:  buildArgKeys,
			Result:        result,
			Duration:      time.Since(started).Round(time.Millisecond).String(),
			PrincipalName: session.PrincipalName,
			LauncherID:    session.LauncherID,
			LauncherName:  session.LauncherName,
		})
	}

	cfg := a.getConfig()

	// Stage the build context into an isolated helper-owned directory. From
	// here the request owns the staging cleanup — on success, build
	// failure, cancellation, shutdown, preparation failure, and Engine
	// failure alike — and releases the workspace-use lease only when the
	// workspace-dependent cleanup completed.
	staged, err := a.stageBuildContext(ctx, session.Workspace, contextPath, dockerfileRel, cfg.RuntimeDir, generateBuildStagingID())
	if err != nil {
		if leaseRelease != nil {
			leaseRelease()
		}
		opLog(ctx).Error("build context staging failed",
			slog.String("operation", "build"),
			slog.String("error", err.Error()),
		)
		duration := time.Since(started).Round(time.Millisecond).String()
		finishAudit("docker_build_failed")
		writeJSONRaw(engineCtx, w, http.StatusInternalServerError, buildResponse{
			OK:       false,
			Code:     "docker_build_failed",
			Message:  "docker build failed",
			Duration: duration,
		})
		return
	}
	defer func() {
		cleanupErr := staged.Cleanup()
		if cleanupErr != nil {
			opLog(ctx).Error("staging cleanup failed — MAC lease intentionally retained because workspace-dependent cleanup did not complete",
				slog.String("operation", "build"),
				slog.String("error", cleanupErr.Error()),
			)
			return
		}
		if leaseRelease != nil {
			leaseRelease()
		}
	}()

	// Resolve the Session credentials the staged Dockerfile's FROM lines
	// name just in time, from the one protected credential store. Only
	// matching entries are projected into the Engine request, and the base
	// images are pulled through the Engine pull path with those
	// credentials before the build resolves them locally.
	authCredentials, err := resolveBuildAuthCredentials(cfg.RuntimeDir, session.ID, staged.DockerfilePath)
	if err != nil {
		opLog(ctx).Error("cannot read session registry credentials",
			slog.String("operation", "build"),
			slog.String("error", err.Error()),
		)
		duration := time.Since(started).Round(time.Millisecond).String()
		finishAudit("docker_build_failed")
		writeJSONRaw(engineCtx, w, http.StatusInternalServerError, buildResponse{
			OK:       false,
			Code:     "docker_build_failed",
			Message:  "docker build failed",
			Duration: duration,
		})
		return
	}

	fromImages, err := dockerfileFromImages(staged.DockerfilePath)
	if err != nil {
		opLog(ctx).Error("cannot read session registry credentials",
			slog.String("operation", "build"),
			slog.String("error", err.Error()),
		)
		duration := time.Since(started).Round(time.Millisecond).String()
		finishAudit("docker_build_failed")
		writeJSONRaw(engineCtx, w, http.StatusInternalServerError, buildResponse{
			OK:       false,
			Code:     "docker_build_failed",
			Message:  "docker build failed",
			Duration: duration,
		})
		return
	}

	// The Engine adapter consumes the prepared trusted context as a tar
	// stream; the adapter is not the workspace-policy owner.
	contextTar, err := staged.tarContext(engineCtx)
	if err != nil {
		opLog(ctx).Error("cannot prepare build context stream",
			slog.String("operation", "build"),
			slog.String("error", err.Error()),
		)
		duration := time.Since(started).Round(time.Millisecond).String()
		finishAudit("docker_build_failed")
		writeJSONRaw(engineCtx, w, http.StatusInternalServerError, buildResponse{
			OK:       false,
			Code:     "docker_build_failed",
			Message:  "docker build failed",
			Duration: duration,
		})
		return
	}
	defer contextTar.Close()

	builder, err := a.newEngineImageBuilder()
	if err != nil {
		opLog(ctx).Error("cannot construct docker engine adapter",
			slog.String("operation", "build"),
		)
		duration := time.Since(started).Round(time.Millisecond).String()
		finishAudit("docker_build_failed")
		writeJSONRaw(engineCtx, w, http.StatusInternalServerError, buildResponse{
			OK:       false,
			Code:     "docker_build_failed",
			Message:  "docker build failed",
			Duration: duration,
		})
		return
	}

	result, buildErr := builder.imageBuild(engineCtx, engineBuildSpec{
		Image:      req.Image,
		Context:    contextTar,
		Dockerfile: dockerfileRel,
		FromImages: fromImages,
		BuildArgs:  req.BuildArgs,
		Auths:      authCredentials,
	}, cfg.OperationLogMaxBytes)
	duration := time.Since(started).Round(time.Millisecond).String()

	if buildErr != nil {
		var engErr *engineError
		if !errors.As(buildErr, &engErr) {
			engErr = &engineError{kind: engineErrBackendFailure, cause: buildErr}
		}

		if engErr.kind != engineErrClientCancelled {
			// Operational logs record only the normalized category. Raw
			// Engine payloads, build-arg values, and credentials stay
			// behind the adapter boundary and never reach journald.
			opLog(ctx).Warn("build failed",
				slog.String("operation", "build"),
				slog.Int("engine_error_kind", int(engErr.kind)),
			)
		}

		auditResult := "docker_build_failed"
		if engErr.kind == engineErrClientCancelled {
			auditResult = "cancelled"
		}
		finishAudit(auditResult)
		writeBuildEngineFailure(engineCtx, w, engErr, result, duration)
		return
	}

	finishAudit("succeeded")
	writeJSONRaw(engineCtx, w, http.StatusOK, buildResponse{
		OK:        true,
		Output:    result.Output,
		Truncated: result.Truncated,
		Duration:  duration,
	})
}

// writeBuildEngineFailure maps a normalized Engine build failure to the
// accepted synchronous build failure contract. The response never carries
// credentials or raw Engine payloads; the rendered build output is preserved
// for the client as before. A cancelled build produces no trustworthy
// result, exactly as the killed docker CLI did.
func writeBuildEngineFailure(ctx context.Context, w http.ResponseWriter, engErr *engineError, result engineBuildResult, duration string) {
	switch engErr.kind {
	case engineErrBuildFailed:
		writeJSONRaw(ctx, w, http.StatusUnprocessableEntity, buildResponse{
			OK:        false,
			Code:      "build_failed",
			Message:   "image build failed",
			Output:    result.Output,
			Truncated: result.Truncated,
			Duration:  duration,
		})
	case engineErrRegistryAuthDenied:
		writeJSONRaw(ctx, w, http.StatusUnprocessableEntity, buildResponse{
			OK:        false,
			Code:      "registry_auth_denied",
			Message:   "registry authentication denied",
			Output:    result.Output,
			Truncated: result.Truncated,
			Duration:  duration,
		})
	case engineErrRegistryUnavailable:
		writeJSONRaw(ctx, w, http.StatusBadGateway, buildResponse{
			OK:        false,
			Code:      "registry_unavailable",
			Message:   "registry unreachable or backend failure",
			Output:    result.Output,
			Truncated: result.Truncated,
			Duration:  duration,
		})
	case engineErrBackendUnavailable:
		writeJSONRaw(ctx, w, http.StatusServiceUnavailable, buildResponse{
			OK:        false,
			Code:      "backend_unavailable",
			Message:   "docker engine unavailable",
			Output:    result.Output,
			Truncated: result.Truncated,
			Duration:  duration,
		})
	default:
		writeJSONRaw(ctx, w, http.StatusInternalServerError, buildResponse{
			OK:        false,
			Code:      "docker_build_failed",
			Message:   "docker build failed",
			Output:    result.Output,
			Truncated: result.Truncated,
			Duration:  duration,
		})
	}
}

// operationForSession looks up an operation by ID and verifies it belongs
// to the given session. Returns nil if the supervisor is nil, the operation
// does not exist, or it belongs to a different session.
func (a *App) operationForSession(sessionID, operationID string) *operation {
	if a.OperationSupervisor == nil {
		return nil
	}
	op := a.OperationSupervisor.lookup(operationID)
	if op == nil {
		return nil
	}
	if op.SessionID != sessionID {
		return nil
	}
	return op
}

func (a *App) handleOperationStatus(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSessionCapability(w, r)
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
	if a.OperationSupervisor != nil {
		a.OperationSupervisor.pruneCompleted(cfg.OperationRetentionTTL, cfg.OperationMaxCompleted)
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
	session, ok := a.requireSessionCapability(w, r)
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
	session, ok := a.requireSessionCapability(w, r)
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
	if err := a.OperationSupervisor.cancel(opID, a.killContainerBestEffort); err != nil {
		if errors.Is(err, ErrOperationNotFound) {
			writeError(ctx, w, http.StatusNotFound, "operation_not_found", "operation not found")
			return
		}
		if errors.Is(err, ErrOperationAlreadyTerminal) {
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

	if !pathWithin(workspace, contextPath) {
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

	if !pathWithin(contextPath, dockerfilePath) {
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
