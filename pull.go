package main

import (
	"log/slog"
	"net/http"
	"strings"
	"time"
)

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

	// Ensure the session Docker config directory exists before writing
	// pull.start so that a failure here does not leave an orphan audit event.
	cfg := a.getConfig()
	dockerDir, err := ensureSessionDockerDir(cfg.RuntimeDir, session.ID)
	if err != nil {
		opLog(ctx).Error("cannot create session Docker directory",
			slog.String("operation", "pull"),
			slog.String("error", err.Error()),
		)
		writeDockerActionRejected(ctx, w, http.StatusInternalServerError, "pull", "internal_error", "internal server error", session.PrincipalName)
		return
	}

	writeRequestContextAudit(ctx, auditRecord{
		Event:         "pull.start",
		SessionID:     session.ID,
		Image:         req.Image,
		PrincipalName: session.PrincipalName,
	})

	started := time.Now()

	args := []string{"--config", dockerDir, "pull", req.Image}

	cmd := a.newDockerCommand(ctx, "docker", args...)
	buf := newBoundedBuffer(cfg.OperationLogMaxBytes)
	cmd.Stdout = buf
	cmd.Stderr = buf

	err = cmd.Start()
	var waitErr error
	if err == nil {
		waitErr = cmd.Wait()
	}
	data, _, truncated := buf.Range(0)
	outputStr := string(data)
	duration := time.Since(started).Round(time.Millisecond).String()

	var result string
	var exitCode *int

	if err != nil {
		// cmd.Start() failed — operational error.
		result = "pull_error"

		opLog(ctx).Error("cannot start docker pull",
			slog.String("operation", "pull"),
			slog.String("error", err.Error()),
		)

		writeJSONRaw(ctx, w, http.StatusInternalServerError, pullResponse{
			OK:        false,
			Code:      "docker_pull_failed",
			Message:   "docker pull failed",
			Output:    outputStr,
			Truncated: truncated,
			Duration:  duration,
		})
	} else if waitErr != nil {
		// cmd.Wait() returned non-zero — workload result, not operational error.
		exitCode = extractExitCode(waitErr)
		result = "pull_error"

		writeJSONRaw(ctx, w, http.StatusInternalServerError, pullResponse{
			OK:        false,
			Code:      "docker_pull_failed",
			Message:   "docker pull failed",
			Output:    outputStr,
			Truncated: truncated,
			Duration:  duration,
		})
	} else {
		result = "success"

		writeJSONRaw(ctx, w, http.StatusOK, pullResponse{
			OK:        true,
			Message:   "image pulled successfully",
			Output:    outputStr,
			Truncated: truncated,
			Duration:  duration,
		})
	}

	writeRequestContextAudit(ctx, auditRecord{
		Event:         "pull.finish",
		SessionID:     session.ID,
		Image:         req.Image,
		Result:        result,
		ExitCode:      exitCode,
		Duration:      duration,
		PrincipalName: session.PrincipalName,
	})
}
