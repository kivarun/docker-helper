package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"
)

type pullRequest struct {
	Image string `json:"image"`
}

func (a *App) handlePull(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}

	ctx := withSessionID(r.Context(), session.ID)

	var req pullRequest

	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&req); err != nil {
		writeError(ctx, w, http.StatusBadRequest, "invalid_json", "invalid JSON request")
		return
	}

	if req.Image == "" {
		writeError(ctx, w, http.StatusBadRequest, "invalid_image", "image is required")
		return
	}

	if !imagePattern.MatchString(req.Image) {
		writeError(ctx, w, http.StatusBadRequest, "invalid_image", "invalid image name or tag")
		return
	}

	writeAuditWithRequestID(ctx, auditRecord{
		Event:     "pull.start",
		SessionID: session.ID,
		Image:     req.Image,
	})

	started := time.Now()

	args := []string{"pull", req.Image}

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

		writeJSON(ctx, w, http.StatusInternalServerError, response{
			OK:       false,
			Code:     "docker_pull_failed",
			Message:  "docker pull failed",
			Output:   string(output),
			Duration: duration,
		})
	} else {
		result = "success"

		writeJSON(ctx, w, http.StatusOK, response{
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
