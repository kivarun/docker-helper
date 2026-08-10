package main

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/http"
	"os/exec"
	"time"
)

type registryLoginRequest struct {
	Registry string `json:"registry"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func (a *App) handleRegistryLogin(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}

	ctx := withSessionID(r.Context(), session.ID)

	var req registryLoginRequest

	if err := decodeJSONRequest(w, r, &req); err != nil {
		writeError(ctx, w, http.StatusBadRequest, "invalid_json", "invalid JSON request")
		return
	}

	if req.Registry == "" || req.Username == "" || req.Password == "" {
		writeError(ctx, w, http.StatusBadRequest, "invalid_registry_login", "invalid registry login request")
		return
	}

	// Ensure the session Docker config directory exists.
	cfg := a.getConfig()
	dockerDir, err := ensureSessionDockerDir(cfg.RuntimeDir, session.ID)
	if err != nil {
		opLog(ctx).Error("cannot create session Docker directory",
			slog.String("operation", "registry_login"),
			slog.String("error", err.Error()),
		)
		writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}

	started := time.Now()

	writeAuditWithRequestID(ctx, auditRecord{
		Event:     "registry.login.start",
		SessionID: session.ID,
		Registry:  req.Registry,
	})

	// Execute docker login with password via stdin.
	// Password must never appear in argv, environment, logs, or audit.
	cmd := exec.Command("docker",
		"--config", dockerDir,
		"login",
		"--username", req.Username,
		"--password-stdin",
		req.Registry,
	)

	var stdinBuf bytes.Buffer
	stdinBuf.WriteString(req.Password)
	cmd.Stdin = &stdinBuf

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	err = cmd.Run()
	duration := time.Since(started).Round(time.Millisecond).String()

	if err != nil {
		// Generic error — do not return Docker output.
		writeAuditWithRequestID(ctx, auditRecord{
			Event:     "registry.login.finish",
			SessionID: session.ID,
			Registry:  req.Registry,
			Result:    "login_failed",
			Duration:  duration,
		})

		opLog(ctx).Warn("registry login failed",
			slog.String("operation", "registry_login"),
			slog.String("error", err.Error()),
		)

		writeJSON(ctx, w, http.StatusBadRequest, response{
			OK:       false,
			Code:     "registry_login_failed",
			Message:  "registry login failed",
			Duration: duration,
		})
		return
	}

	writeAuditWithRequestID(ctx, auditRecord{
		Event:     "registry.login.finish",
		SessionID: session.ID,
		Registry:  req.Registry,
		Result:    "success",
		Duration:  duration,
	})

	writeJSON(ctx, w, http.StatusOK, response{
		OK:      true,
		Message: fmt.Sprintf("login succeeded for %s", req.Registry),
	})
}
