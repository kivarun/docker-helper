package main

import (
	"log/slog"
	"net/http"
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

	writeAuditWithRequestID(ctx, auditRecord{
		Event:     "pull.start",
		SessionID: session.ID,
		Image:     req.Image,
	})

	started := time.Now()

	// Ensure the session Docker config directory exists.
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

	args := []string{"--config", dockerDir, "pull", req.Image}

	pullCmd := a.ExecCommand
	if pullCmd == nil {
		pullCmd = defaultExecCommand
	}

	output, err := pullCmd("docker", args...)
	duration := time.Since(started).Round(time.Millisecond).String()

	var result string
	var exitCode *int

	if err != nil {
		exitCode = extractExitCode(err)
		result = "pull_error"

		opLog(ctx).Error("docker pull error",
			slog.String("operation", "pull"),
			slog.String("error", err.Error()),
		)

		writeJSONRaw(ctx, w, http.StatusInternalServerError, pullResponse{
			OK:       false,
			Code:     "docker_pull_failed",
			Message:  "docker pull failed",
			Output:   string(output),
			Duration: duration,
		})
	} else {
		result = "success"

		writeJSONRaw(ctx, w, http.StatusOK, pullResponse{
			OK:       true,
			Message:  "image pulled successfully",
			Output:   string(output),
			Duration: duration,
		})
	}

	writeAuditWithRequestID(ctx, auditRecord{
		Event:     "pull.finish",
		SessionID: session.ID,
		Image:     req.Image,
		Result:    result,
		ExitCode:  exitCode,
		Duration:  duration,
	})
}
