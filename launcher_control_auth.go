package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"
)

// launcherControlAuthority is the authenticated authority for Launcher
// management: create/list/show/update/scope/delete Launchers and manage their
// optional credential. Only Admin and Principal credential are authorized; a
// Launcher credential does NOT manage Launcher metadata or credentials.
type launcherControlAuthority struct {
	isAdmin             bool
	principalCredential *PrincipalCredentialAuth
}

// authenticateLauncherControlRequest tries admin token first, then credential
// authentication. It returns the authority context on success, or writes the
// non-disclosing unauthorized response and returns nil.
func (a *App) authenticateLauncherControlRequest(w http.ResponseWriter, r *http.Request) (*launcherControlAuthority, error) {
	ctx := r.Context()

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		writeAuthFailure(ctx, r, "launcher.parse_failed")
		writeUnauthorizedLauncherControl(ctx, w)
		return nil, nil
	}

	token, ok := parseBearerToken(r)
	if !ok || token == "" {
		writeAuthFailure(ctx, r, "launcher.parse_failed")
		writeUnauthorizedLauncherControl(ctx, w)
		return nil, nil
	}

	// Check admin token.
	tokenHash := sha256.Sum256([]byte(token))
	currentHash := a.getAdminTokenHash()
	if subtle.ConstantTimeCompare(tokenHash[:], currentHash[:]) == 1 {
		return &launcherControlAuthority{isAdmin: true}, nil
	}

	// Try credential authentication.
	authResult, err := authenticateCredential(a.DB, token)
	if err == nil {
		if authResult.Launcher != nil {
			// A valid Launcher credential has no Launcher-management
			// authority. Treat as unauthorized, non-disclosing.
			writeAuthFailure(ctx, r, "launcher.unauthorized")
			writeUnauthorizedLauncherControl(ctx, w)
			return nil, nil
		}
		return &launcherControlAuthority{principalCredential: authResult.Principal}, nil
	}

	if !errors.Is(err, ErrCredentialNotFound) &&
		!errors.Is(err, ErrCredentialRevoked) &&
		!errors.Is(err, ErrPrincipalDisabled) &&
		!errors.Is(err, ErrLauncherDisabled) {
		writeAuthFailure(ctx, r, "launcher.database_error")
		opLog(ctx).Error("launcher control auth database error",
			slog.String("operation", "launcher_auth"),
			slog.String("error", err.Error()),
		)
		writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		return nil, err
	}

	writeAuthFailure(ctx, r, "launcher.unauthorized")
	writeUnauthorizedLauncherControl(ctx, w)
	return nil, nil
}
