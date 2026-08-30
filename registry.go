package main

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

type registryLoginRequest struct {
	Registry string `json:"registry"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// classifyRegistryLoginFailure maps a docker login failure's stderr output to
// an HTTP status, error code, and message. Authentication/authorization
// denials are distinguished from registry/backend failures; the docker CLI
// exposes no structured error, so the classification relies on its stable
// stderr lines. Unrecognized failures keep the existing generic contract.
func classifyRegistryLoginFailure(output string) (status int, code, message string) {
	switch classifyDockerError(output) {
	case dockerErrorAuthDenied:
		return http.StatusUnauthorized, "registry_auth_denied", "authentication failed for registry"
	case dockerErrorNetwork:
		return http.StatusBadGateway, "registry_unavailable", "registry unreachable or backend failure"
	default:
		return http.StatusBadRequest, "registry_login_failed", "registry login failed"
	}
}

func (a *App) handleRegistryLogin(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSessionCapability(w, r)
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

	if strings.HasPrefix(req.Registry, "-") {
		writeError(ctx, w, http.StatusBadRequest, "invalid_registry_login", "registry must not start with '-'")
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

	writeRequestContextAudit(ctx, auditRecord{
		Event:         "registry.login.start",
		SessionID:     session.ID,
		Registry:      req.Registry,
		PrincipalName: session.PrincipalName,
	})

	// Execute docker login with password via stdin.
	// Password must never appear in argv, environment, logs, or audit.
	cmd := a.newDockerCommand(r.Context(), "docker",
		"--config", dockerDir,
		"login",
		"--username", req.Username,
		"--password-stdin",
		req.Registry,
	)

	var stdinBuf bytes.Buffer
	stdinBuf.WriteString(req.Password)
	cmd.Stdin = &stdinBuf

	// Registry login output is intentionally not retained or exposed.
	// Capture only enough stderr to classify the failure, never returning or
	// logging it: the password is supplied via stdin (never argv/env/logs) and
	// must not leak, and Docker output must not be exposed verbatim.
	var errBuf *boundedBuffer = newBoundedBuffer(4096)
	cmd.Stdout = io.Discard
	cmd.Stderr = errBuf

	err = cmd.Run()
	duration := time.Since(started).Round(time.Millisecond).String()

	if err != nil {
		// Classify the login failure (authentication vs. registry/backend)
		// using the docker CLI's stable stderr lines. Only a sanitized
		// category message is returned; the captured output is discarded.
		outData, _, _ := errBuf.Range(0)
		status, code, message := classifyRegistryLoginFailure(string(outData))

		writeRequestContextAudit(ctx, auditRecord{
			Event:         "registry.login.finish",
			SessionID:     session.ID,
			Registry:      req.Registry,
			Result:        "login_failed",
			Duration:      duration,
			PrincipalName: session.PrincipalName,
		})

		opLog(ctx).Warn("registry login failed",
			slog.String("operation", "registry_login"),
			slog.String("error", err.Error()),
		)

		writeJSON(ctx, w, status, response{
			OK:       false,
			Code:     code,
			Message:  message,
			Duration: duration,
		})
		return
	}

	writeRequestContextAudit(ctx, auditRecord{
		Event:         "registry.login.finish",
		SessionID:     session.ID,
		Registry:      req.Registry,
		Result:        "success",
		Duration:      duration,
		PrincipalName: session.PrincipalName,
	})

	writeJSON(ctx, w, http.StatusOK, response{
		OK:      true,
		Message: fmt.Sprintf("login succeeded for %s", req.Registry),
	})
}
