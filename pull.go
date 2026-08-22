package main

import (
	"log/slog"
	"net/http"
	"strings"
	"time"
)

func (a *App) handlePull(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}

	ctx := withSessionID(r.Context(), session.ID)

	var req pullRequest

	if err := decodeJSONRequest(w, r, &req); err != nil {
		writeError(ctx, w, http.StatusBadRequest, "invalid_json", "invalid JSON request")
		return
	}

	if req.Image == "" {
		writeError(ctx, w, http.StatusBadRequest, "invalid_image", "image is required")
		return
	}

	if strings.HasPrefix(req.Image, "-") {
		writeError(ctx, w, http.StatusBadRequest, "invalid_image", "image must not start with '-'")
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
		writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}

	writeAuditWithRequestID(ctx, auditRecord{
		Event:         "pull.start",
		SessionID:     session.ID,
		Image:         req.Image,
		PrincipalName: session.PrincipalName,
	})

	started := time.Now()

	args := []string{"--config", dockerDir, "pull", req.Image}

	cmd := a.newOperationCmd(ctx, "docker", args...)
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

	writeAuditWithRequestID(ctx, auditRecord{
		Event:         "pull.finish",
		SessionID:     session.ID,
		Image:         req.Image,
		Result:        result,
		ExitCode:      exitCode,
		Duration:      duration,
		PrincipalName: session.PrincipalName,
	})
}
