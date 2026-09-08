package main

import (
	"context"
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

// writeRegistryLoginFailure maps a normalized Engine error to the accepted
// registry-login failure contract. The response never carries registry
// command output, the username, the password, or any raw Engine payload.
func writeRegistryLoginFailure(ctx context.Context, w http.ResponseWriter, engErr *engineError) {
	switch engErr.kind {
	case engineErrRegistryAuthDenied:
		writeError(ctx, w, http.StatusUnprocessableEntity, "registry_auth_denied",
			"the registry rejected the supplied username and password")
	case engineErrRegistryUnavailable:
		writeError(ctx, w, http.StatusBadGateway, "registry_unavailable",
			"registry unreachable or backend failure")
	case engineErrBackendUnavailable:
		writeError(ctx, w, http.StatusServiceUnavailable, "backend_unavailable",
			"docker engine cannot be reached or observed")
	default:
		writeError(ctx, w, http.StatusBadGateway, "backend_failure",
			"unexpected docker engine failure")
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

	if _, err := ensureSessionDockerDir(a.getConfig().RuntimeDir, session.ID); err != nil {
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
		LauncherID:    session.LauncherID,
		LauncherName:  session.LauncherName,
	})

	// Validate the credentials through the Engine adapter. The password is
	// held only in the request value and the adapter call; it must never
	// appear in argv, environment, logs, audit, or errors.
	authenticator, err := a.newEngineRegistryAuthenticator()
	if err != nil {
		opLog(ctx).Error("cannot construct docker engine adapter",
			slog.String("operation", "registry_login"),
			slog.String("error", err.Error()),
		)
		writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}

	identityToken, err := authenticator.registryLogin(r.Context(), req.Registry, req.Username, req.Password)
	if err != nil {
		// Classification uses only the normalized error kind; the raw
		// backend payload stays out of the response and the captured
		// diagnostic text never carries credential material.
		engErr, ok := err.(*engineError)
		if !ok {
			opLog(ctx).Error("registry login failed with an unclassified engine error",
				slog.String("operation", "registry_login"),
				slog.String("error", err.Error()),
			)
			engErr = &engineError{kind: engineErrBackendFailure, cause: err}
		}

		writeRequestContextAudit(ctx, auditRecord{
			Event:         "registry.login.finish",
			SessionID:     session.ID,
			Registry:      req.Registry,
			Result:        "login_failed",
			Duration:      time.Since(started).Round(time.Millisecond).String(),
			PrincipalName: session.PrincipalName,
			LauncherID:    session.LauncherID,
			LauncherName:  session.LauncherName,
		})

		opLog(ctx).Warn("registry login failed",
			slog.String("operation", "registry_login"),
			slog.String("error", err.Error()),
		)

		writeRegistryLoginFailure(ctx, w, engErr)
		return
	}

	// Validation succeeded: atomically replace the Session's protected
	// credential entry for exactly this registry. Success is reported only
	// after the credential is committed.
	if err := storeSessionRegistryCredential(a.getConfig().RuntimeDir, session.ID, req.Registry, req.Username, req.Password, identityToken); err != nil {
		opLog(ctx).Error("cannot store session registry credential",
			slog.String("operation", "registry_login"),
			slog.String("error", err.Error()),
		)
		writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}

	writeRequestContextAudit(ctx, auditRecord{
		Event:         "registry.login.finish",
		SessionID:     session.ID,
		Registry:      req.Registry,
		Result:        "success",
		Duration:      time.Since(started).Round(time.Millisecond).String(),
		PrincipalName: session.PrincipalName,
		LauncherID:    session.LauncherID,
		LauncherName:  session.LauncherName,
	})

	writeJSON(ctx, w, http.StatusOK, response{
		OK: true,
	})
}
