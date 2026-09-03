package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"
)

// authResponse is the narrow wire response for GET /auth, read-only operator
// auth introspection used by the CLI to infer the authenticated Principal when
// --principal is omitted. It carries only the auth authority and, where
// applicable, the concrete owner identity derived from persistent credential
// state. No bearer data, credential IDs, roots, UID/GID, or other metadata is
// exposed.
type authResponse struct {
	Authority  string `json:"authority"`
	Principal  string `json:"principal,omitempty"`
	LauncherID string `json:"launcher_id,omitempty"`
}

// handleAuth reports the authenticated authority for the request. It accepts an
// admin token, a Principal credential, or a Launcher credential; a Session token
// does not authenticate this endpoint. Invalid/revoked/disabled credentials
// follow the existing non-disclosing authentication semantics and receive no
// identity information.
func (a *App) handleAuth(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	token, ok := parseBearerToken(r)
	if !ok || token == "" {
		writeAuthFailure(ctx, r, "auth.parse_failed")
		writeUnauthorizedAuth(ctx, w)
		return
	}

	// Admin token first, mirroring the other operator control planes.
	tokenHash := sha256.Sum256([]byte(token))
	currentHash := a.getAdminTokenHash()
	if subtle.ConstantTimeCompare(tokenHash[:], currentHash[:]) == 1 {
		writeJSONRaw(ctx, w, http.StatusOK, authResponse{Authority: "admin"})
		return
	}

	authResult, err := authenticateCredential(a.DB, token)
	if err == nil {
		if authResult.Principal != nil {
			writeJSONRaw(ctx, w, http.StatusOK, authResponse{
				Authority: "principal",
				Principal: authResult.Principal.PrincipalName,
			})
			return
		}
		if authResult.Launcher != nil {
			writeJSONRaw(ctx, w, http.StatusOK, authResponse{
				Authority:  "launcher",
				LauncherID: authResult.Launcher.LauncherID,
				Principal:  authResult.Launcher.PrincipalName,
			})
			return
		}
	}

	if !errorsIsCredentialAuthError(err) {
		writeAuthFailure(ctx, r, "auth.database_error")
		opLog(ctx).Error("auth introspection database error",
			slog.String("operation", "auth_introspect"),
			slog.String("error", err.Error()),
		)
		writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}

	writeAuthFailure(ctx, r, "auth.unauthorized")
	writeUnauthorizedAuth(ctx, w)
}

// errorsIsCredentialAuthError reports whether err is one of the expected
// non-disclosing credential authentication outcomes (unknown, revoked, or
// disabled owner) rather than a database failure. Any other error is treated
// as an internal error so it is never disclosed to the caller.
func errorsIsCredentialAuthError(err error) bool {
	return errors.Is(err, ErrCredentialNotFound) ||
		errors.Is(err, ErrCredentialRevoked) ||
		errors.Is(err, ErrPrincipalDisabled) ||
		errors.Is(err, ErrLauncherDisabled)
}
