package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"
)

// controlAuthority is the authenticated authority for Principal-owned resource
// control planes (Launcher control and Principal credential control): an admin
// token, or a Principal credential (which may only act on its own Principal).
// A Launcher credential does NOT carry control-plane authority.
type controlAuthority struct {
	isAdmin             bool
	principalCredential *PrincipalCredentialAuth
}

// authenticateControlRequest tries admin token first, then credential
// authentication. auditScope is the endpoint family's audit event prefix
// ("launcher", "credential", ...); auth failures are audited as
// <auditScope>.parse_failed / <auditScope>.unauthorized /
// <auditScope>.database_error. It returns the authority context on success, or
// writes the non-disclosing unauthorized response and returns nil.
func (a *App) authenticateControlRequest(w http.ResponseWriter, r *http.Request, auditScope string) (*controlAuthority, error) {
	ctx := r.Context()

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		writeAuthFailure(ctx, r, auditScope+".parse_failed")
		writeUnauthorizedControl(ctx, w, controlUnauthorizedMessage(auditScope))
		return nil, nil
	}

	token, ok := parseBearerToken(r)
	if !ok || token == "" {
		writeAuthFailure(ctx, r, auditScope+".parse_failed")
		writeUnauthorizedControl(ctx, w, controlUnauthorizedMessage(auditScope))
		return nil, nil
	}

	// Check admin token.
	tokenHash := sha256.Sum256([]byte(token))
	currentHash := a.getAdminTokenHash()
	if subtle.ConstantTimeCompare(tokenHash[:], currentHash[:]) == 1 {
		return &controlAuthority{isAdmin: true}, nil
	}

	// Try credential authentication.
	authResult, err := authenticateCredential(a.DB, token)
	if err == nil {
		if authResult.Launcher != nil {
			// A valid Launcher credential has no control-plane authority.
			// Treat as unauthorized, non-disclosing.
			writeAuthFailure(ctx, r, auditScope+".unauthorized")
			writeUnauthorizedControl(ctx, w, controlUnauthorizedMessage(auditScope))
			return nil, nil
		}
		return &controlAuthority{principalCredential: authResult.Principal}, nil
	}

	if !errors.Is(err, ErrCredentialNotFound) &&
		!errors.Is(err, ErrCredentialRevoked) &&
		!errors.Is(err, ErrPrincipalDisabled) &&
		!errors.Is(err, ErrLauncherDisabled) {
		writeAuthFailure(ctx, r, auditScope+".database_error")
		opLog(ctx).Error("control auth database error",
			slog.String("operation", "control_auth"),
			slog.String("error", err.Error()),
		)
		writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		return nil, err
	}

	writeAuthFailure(ctx, r, auditScope+".unauthorized")
	writeUnauthorizedControl(ctx, w, controlUnauthorizedMessage(auditScope))
	return nil, nil
}

// controlUnauthorizedMessage returns the endpoint family's non-disclosing
// unauthorized response message. Each control-plane family keeps its own
// established message contract.
func controlUnauthorizedMessage(auditScope string) string {
	if auditScope == "launcher" {
		return "Authentication required for launcher management."
	}
	if auditScope == "principal" {
		return "Authentication required for Principal management."
	}
	return "Authentication required for credential management."
}

// listQueryScope is the authorized visibility scope of a scope-first list
// Query: allPrincipals when the authenticated authority may see every
// Principal, otherwise exactly the one Principal the query is narrowed to.
type listQueryScope struct {
	allPrincipals bool
	principal     *PrincipalWithRoots
}

// resolveListScope is the single authorization owner for scope-first list
// Queries on Principal-owned resource families (launcher list, principal
// credential list): the authenticated authority establishes the maximum
// visibility — an admin token may see every Principal, a Principal credential
// only its own — and the optional Principal selector can only narrow that
// visibility, never expand it. An empty filter selects the caller's full
// visible scope. A foreign selector under a Principal credential and an
// unknown selector are both the established non-disclosing 404 (a foreign
// selector is rejected without any lookup). A Launcher credential never
// reaches this resolver: authenticateControlRequest rejects it.
func (a *App) resolveListScope(w http.ResponseWriter, r *http.Request, auth *controlAuthority, filter string) (listQueryScope, bool) {
	ctx := r.Context()
	if auth.isAdmin {
		if filter == "" {
			return listQueryScope{allPrincipals: true}, true
		}
		p, err := findPrincipalByUsername(a.DB, filter)
		if err != nil {
			if isErrPrincipalNotFound(err) {
				writeError(ctx, w, http.StatusNotFound, "principal_not_found", "principal not found")
			} else {
				opLog(ctx).Error("launcher principal lookup failed",
					slog.String("operation", "launcher_principal_lookup"),
					slog.String("error", err.Error()),
				)
				writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
			}
			return listQueryScope{}, false
		}
		return listQueryScope{principal: p}, true
	}

	// Principal credential: its own Principal is the whole visible scope.
	if filter != "" && filter != auth.principalCredential.PrincipalName {
		writeError(ctx, w, http.StatusNotFound, "principal_not_found", "principal not found")
		return listQueryScope{}, false
	}
	p, err := findPrincipalByUsername(a.DB, auth.principalCredential.PrincipalName)
	if err != nil {
		if isErrPrincipalNotFound(err) {
			writeError(ctx, w, http.StatusNotFound, "principal_not_found", "principal not found")
		} else {
			opLog(ctx).Error("launcher principal lookup failed",
				slog.String("operation", "launcher_principal_lookup"),
				slog.String("error", err.Error()),
			)
			writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		}
		return listQueryScope{}, false
	}
	return listQueryScope{principal: p}, true
}
