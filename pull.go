package main

import (
	"bytes"
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
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output

	err = cmd.Start()
	if err == nil {
		err = cmd.Wait()
	}
	outputBytes := output.Bytes()
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
			Output:   string(outputBytes),
			Duration: duration,
		})
	} else {
		result = "success"

		writeJSONRaw(ctx, w, http.StatusOK, pullResponse{
			OK:       true,
			Message:  "image pulled successfully",
			Output:   string(outputBytes),
			Duration: duration,
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
