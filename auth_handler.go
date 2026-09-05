package main

import (
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

// handleAuth reports the authenticated authority for the request. It accepts
// an admin token, a Principal credential, or a Launcher credential through the
// one canonical operator authenticator and only projects the result into the
// wire response; it performs no owner resolution of its own, and it switches
// explicitly over the three valid authority classes. A structurally invalid
// authority is an internal authentication anomaly, never an empty or default
// projection: it is audited auth.database_error and answered with HTTP 500.
// A Session token does not authenticate this endpoint. Invalid/revoked/
// disabled credentials follow the existing non-disclosing authentication
// semantics and receive no identity information.
func (a *App) handleAuth(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	token, ok := parseBearerToken(r)
	if !ok {
		writeAuthFailure(ctx, r, "auth.parse_failed")
		writeUnauthorizedAuth(ctx, w)
		return
	}

	authority, err := a.authenticateOperatorToken(token)
	if err == nil {
		switch authority.class {
		case operatorAuthorityAdmin:
			writeJSONRaw(ctx, w, http.StatusOK, authResponse{Authority: "admin"})
		case operatorAuthorityPrincipal:
			writeJSONRaw(ctx, w, http.StatusOK, authResponse{
				Authority: "principal",
				Principal: authority.principal.PrincipalName,
			})
		case operatorAuthorityLauncher:
			writeJSONRaw(ctx, w, http.StatusOK, authResponse{
				Authority:  "launcher",
				LauncherID: authority.launcher.LauncherID,
				Principal:  authority.launcher.PrincipalName,
			})
		default:
			writeInvalidOperatorAuthority(ctx, r, w, "auth", "auth_introspect", authority)
		}
		return
	}

	if classifyCredentialAuthFailure(err).isExpectedAuthFailure() {
		writeAuthFailure(ctx, r, "auth.unauthorized")
		writeUnauthorizedAuth(ctx, w)
		return
	}
	writeAuthFailure(ctx, r, "auth.database_error")
	opLog(ctx).Error("auth introspection database error",
		slog.String("operation", "auth_introspect"),
		slog.String("error", err.Error()),
	)
	writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
}
