package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// writePullEngineFailure maps a normalized Engine error to the accepted pull
// failure contract. The response never carries credentials or raw Engine
// payloads; the rendered pull progress output is preserved for the client as
// before. Backend failures, an unreachable Engine, and a cancelled request
// share the generic pull failure response: a cancelled pull produces no
// trustworthy result, exactly as the killed docker CLI did.
func writePullEngineFailure(ctx context.Context, w http.ResponseWriter, engErr *engineError, result enginePullResult, duration string) {
	switch engErr.kind {
	case engineErrImageNotFound:
		writeJSONRaw(ctx, w, http.StatusNotFound, pullResponse{
			OK:        false,
			Code:      "image_not_found",
			Message:   "image not found",
			Output:    result.Output,
			Truncated: result.Truncated,
			Duration:  duration,
		})
	case engineErrRegistryAuthDenied:
		writeJSONRaw(ctx, w, http.StatusUnauthorized, pullResponse{
			OK:        false,
			Code:      "pull_access_denied",
			Message:   "pull access denied or authentication required",
			Output:    result.Output,
			Truncated: result.Truncated,
			Duration:  duration,
		})
	case engineErrRegistryUnavailable:
		writeJSONRaw(ctx, w, http.StatusBadGateway, pullResponse{
			OK:        false,
			Code:      "registry_unavailable",
			Message:   "registry unreachable or backend failure",
			Output:    result.Output,
			Truncated: result.Truncated,
			Duration:  duration,
		})
	default:
		writeJSONRaw(ctx, w, http.StatusInternalServerError, pullResponse{
			OK:        false,
			Code:      "docker_pull_failed",
			Message:   "docker pull failed",
			Output:    result.Output,
			Truncated: result.Truncated,
			Duration:  duration,
		})
	}
}

func (a *App) handlePull(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSessionCapability(w, r)
	if !ok {
		return
	}

	ctx := withSessionID(r.Context(), session.ID)

	var req pullRequest

	if err := decodeJSONRequest(w, r, &req); err != nil {
		writeDockerActionRejected(ctx, w, http.StatusBadRequest, "pull", "invalid_json", "invalid JSON request", session.PrincipalName)
		return
	}

	if req.Image == "" {
		writeDockerActionRejected(ctx, w, http.StatusBadRequest, "pull", "invalid_image", "image is required", session.PrincipalName)
		return
	}

	if strings.HasPrefix(req.Image, "-") {
		writeDockerActionRejected(ctx, w, http.StatusBadRequest, "pull", "invalid_image", "image must not start with '-'", session.PrincipalName)
		return
	}

	// Resolve the stored Session credential for the image's registry just in
	// time, from the one protected credential store. A reference with no
	// registry or no stored credential pulls unauthenticated, exactly as a
	// pull without a prior login did; a store read failure is operational.
	credential, _, err := resolveSessionRegistryCredential(a.getConfig().RuntimeDir, session.ID, req.Image)
	if err != nil {
		opLog(ctx).Error("cannot read session registry credential",
			slog.String("operation", "pull"),
			slog.String("error", err.Error()),
		)
		writeDockerActionRejected(ctx, w, http.StatusInternalServerError, "pull", "internal_error", "internal server error", session.PrincipalName)
		return
	}

	// Synchronous Engine requests are admitted through the coordinator so
	// daemon shutdown can refuse them or cancel them deterministically.
	engineCtx, syncReq, admitted := a.SyncExecutionCoordinator.admit(ctx)
	if !admitted {
		writeDockerActionRejected(ctx, w, http.StatusServiceUnavailable, "pull", "shutting_down", "docker-helper daemon is shutting down", session.PrincipalName)
		return
	}
	defer syncReq.end()

	writeRequestContextAudit(ctx, auditRecord{
		Event:         "pull.start",
		SessionID:     session.ID,
		Image:         req.Image,
		PrincipalName: session.PrincipalName,
		LauncherID:    session.LauncherID,
		LauncherName:  session.LauncherName,
	})

	started := time.Now()

	puller, err := a.newEngineImagePuller()
	if err != nil {
		opLog(ctx).Error("cannot construct docker engine adapter",
			slog.String("operation", "pull"),
		)
		duration := time.Since(started).Round(time.Millisecond).String()
		writeRequestContextAudit(ctx, auditRecord{
			Event:         "pull.finish",
			SessionID:     session.ID,
			Image:         req.Image,
			Result:        "pull_error",
			Duration:      duration,
			PrincipalName: session.PrincipalName,
			LauncherID:    session.LauncherID,
			LauncherName:  session.LauncherName,
		})
		writeJSONRaw(engineCtx, w, http.StatusInternalServerError, pullResponse{
			OK:       false,
			Code:     "docker_pull_failed",
			Message:  "docker pull failed",
			Duration: duration,
		})
		return
	}

	result, pullErr := puller.imagePull(engineCtx, req.Image, credential, a.getConfig().OperationLogMaxBytes)
	duration := time.Since(started).Round(time.Millisecond).String()

	if pullErr != nil {
		var engErr *engineError
		if !errors.As(pullErr, &engErr) {
			engErr = &engineError{kind: engineErrBackendFailure, cause: pullErr}
		}

		if engErr.kind != engineErrClientCancelled {
			// Operational logs record only the normalized category. Raw
			// Engine payloads and credentials stay behind the adapter
			// boundary and never reach journald.
			opLog(ctx).Warn("pull failed",
				slog.String("operation", "pull"),
				slog.Int("engine_error_kind", int(engErr.kind)),
			)
		}

		writeRequestContextAudit(ctx, auditRecord{
			Event:         "pull.finish",
			SessionID:     session.ID,
			Image:         req.Image,
			Result:        "pull_error",
			Duration:      duration,
			PrincipalName: session.PrincipalName,
			LauncherID:    session.LauncherID,
			LauncherName:  session.LauncherName,
		})
		writePullEngineFailure(engineCtx, w, engErr, result, duration)
		return
	}

	writeRequestContextAudit(ctx, auditRecord{
		Event:         "pull.finish",
		SessionID:     session.ID,
		Image:         req.Image,
		Result:        "success",
		Duration:      duration,
		PrincipalName: session.PrincipalName,
		LauncherID:    session.LauncherID,
		LauncherName:  session.LauncherName,
	})
	writeJSONRaw(engineCtx, w, http.StatusOK, pullResponse{
		OK:        true,
		Message:   "image pulled successfully",
		Output:    result.Output,
		Truncated: result.Truncated,
		Duration:  duration,
	})
}
