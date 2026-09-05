package main

import (
	"log/slog"
	"net/http"
)

// authenticatePrincipalControlRequest authenticates a Principal-owned
// resource control request: Launcher management, Principal-credential
// management, and Principal effective-roots introspection. The authority
// ceiling is an admin token or a Principal credential; a valid Launcher
// credential is authenticated but carries no control-plane authority, so it
// is rejected with the family's non-disclosing unauthorized contract —
// authentication success and authorization rejection remain distinct states
// (never a credential.not_found). Expected credential-auth failures are
// audited as <auditScope>.unauthorized and a database failure as
// <auditScope>.database_error (HTTP 500); auditScope is the endpoint family's
// audit event prefix ("launcher", "credential", ...).
func (a *App) authenticatePrincipalControlRequest(w http.ResponseWriter, r *http.Request, auditScope string) (*operatorAuthority, error) {
	ctx := r.Context()

	token, ok := parseBearerToken(r)
	if !ok {
		writeAuthFailure(ctx, r, auditScope+".parse_failed")
		writeUnauthorizedControl(ctx, w, controlUnauthorizedMessage(auditScope))
		return nil, nil
	}

	authority, err := a.authenticateOperatorToken(token)
	if err == nil {
		if authority.class == operatorAuthorityLauncher {
			writeAuthFailure(ctx, r, auditScope+".unauthorized")
			writeUnauthorizedControl(ctx, w, controlUnauthorizedMessage(auditScope))
			return nil, nil
		}
		return authority, nil
	}

	if !classifyCredentialAuthFailure(err).isExpectedAuthFailure() {
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
// reaches this resolver: authenticatePrincipalControlRequest rejects it.
func (a *App) resolveListScope(w http.ResponseWriter, r *http.Request, auth *operatorAuthority, filter string) (listQueryScope, bool) {
	ctx := r.Context()
	if auth.class == operatorAuthorityAdmin {
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
	if filter != "" && filter != auth.principal.PrincipalName {
		writeError(ctx, w, http.StatusNotFound, "principal_not_found", "principal not found")
		return listQueryScope{}, false
	}
	p, err := findPrincipalByUsername(a.DB, auth.principal.PrincipalName)
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
