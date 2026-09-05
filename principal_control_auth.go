package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
)

// authenticatePrincipalControlRequest authenticates a Principal-owned
// resource control request: Launcher management, Principal-credential
// management, and Principal effective-roots introspection. The authority
// ceiling is an explicit allow-list: an admin token or a Principal credential
// is authorized, a valid Launcher credential is authenticated but carries no
// control-plane authority and is rejected with the family's non-disclosing
// unauthorized contract — authentication success and authorization rejection
// remain distinct states (never a credential.not_found) — and a structurally
// invalid authority is an internal authentication anomaly, never an
// unauthorized credential, so it maps to the family's
// <auditScope>.database_error contract (HTTP 500). Expected credential-auth
// failures are audited as <auditScope>.unauthorized and a database failure as
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
		switch authority.class {
		case operatorAuthorityAdmin, operatorAuthorityPrincipal:
			return authority, nil
		case operatorAuthorityLauncher:
			writeAuthFailure(ctx, r, auditScope+".unauthorized")
			writeUnauthorizedControl(ctx, w, controlUnauthorizedMessage(auditScope))
			return nil, nil
		default:
			return nil, writeInvalidOperatorAuthority(ctx, r, w, auditScope, "control_auth", authority)
		}
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

// principalControlTarget is the resolved target of a Principal-control
// operation under an authenticated authority: the concrete Principal identity
// (ID) the operation may act on, plus the Principal's name at resolution time
// (selector/display provenance). A Principal credential always targets the
// exact Principal ID it authenticated as — the nested username is an
// authorization selector only — while Admin authority is name-oriented at the
// API selector boundary and resolves the current Principal by username. It
// carries identity only: Principal policy (allowed roots) is never loaded,
// because control targeting consumes no roots.
type principalControlTarget struct {
	ID   int64
	Name string
}

// errInvalidControlAuthority marks a structurally invalid operator authority
// reaching a Principal-control resolver: an internal authentication anomaly
// that fails closed — it is never treated as Admin and never resolves a
// Principal. A Launcher credential cannot reach these resolvers behind
// authenticatePrincipalControlRequest, so it shares this fail-closed class.
var errInvalidControlAuthority = errors.New("invalid operator authority")

// resolvePrincipalControlTarget resolves the Principal-control target for an
// authenticated operator authority: the single non-HTTP semantic owner for
// every Principal-owned resource control path (nested Launcher routes,
// Principal credential rotation, Principal-owned list scopes, and the
// effective-roots snapshot). It applies the established control selector rule
// and the stable-identity rule:
//
//   - Admin authority is name-oriented at the API selector boundary: the
//     current Principal named username is resolved and returned (its current
//     ID and name). Admin has global authority, so a delete/recreate under the
//     same username may legitimately target the new current Principal.
//   - A Principal credential targets exactly the Principal ID it
//     authenticated as: a foreign username fails closed as
//     ErrPrincipalNotFound without any foreign-state lookup, and the own
//     username resolves the exact authenticated PrincipalID — the row must
//     still exist and still carry the authenticated name. A stale authority
//     whose Principal was deleted therefore fails ErrPrincipalNotFound and
//     never rebinds to a recreated same-username Principal.
//   - A Launcher credential or structurally invalid authority cannot reach a
//     Principal resolution: fail closed as errInvalidControlAuthority.
func resolvePrincipalControlTarget(db *sql.DB, auth *operatorAuthority, username string) (*principalControlTarget, error) {
	if username == "" {
		return nil, fmt.Errorf("username is required: %w", ErrPrincipalNotFound)
	}
	switch {
	case auth != nil && auth.class == operatorAuthorityAdmin:
		id, err := findPrincipalIDByUsername(db, username)
		if err != nil {
			return nil, err
		}
		return &principalControlTarget{ID: int64(id), Name: username}, nil
	case auth != nil && auth.class == operatorAuthorityPrincipal:
		// The nested username is an authorization selector, not an ownership
		// lookup key: a foreign selector is the non-disclosing not-found
		// without any foreign lookup, and the own selector resolves the exact
		// authenticated Principal incarnation.
		if username != auth.principal.PrincipalName {
			return nil, fmt.Errorf("principal %q not found: %w", username, ErrPrincipalNotFound)
		}
		var name string
		err := db.QueryRow(`SELECT username FROM principals WHERE id = ?`, auth.principal.PrincipalID).Scan(&name)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, fmt.Errorf("principal %q not found: %w", auth.principal.PrincipalName, ErrPrincipalNotFound)
			}
			return nil, fmt.Errorf("cannot find principal: %w", err)
		}
		if name != auth.principal.PrincipalName {
			// The row at the exact authenticated ID no longer represents the
			// authenticated identity: fail closed, never rebind.
			return nil, fmt.Errorf("principal %q not found: %w", auth.principal.PrincipalName, ErrPrincipalNotFound)
		}
		return &principalControlTarget{ID: auth.principal.PrincipalID, Name: name}, nil
	default:
		return nil, errInvalidControlAuthority
	}
}

// writePrincipalControlLookupError maps a Principal-control target resolution
// error onto the shared lookup wire contract: a missing, foreign, or stale
// target is the non-disclosing 404, a structurally invalid authority and any
// other failure are the internal-error contract with the established
// operation log.
func writePrincipalControlLookupError(ctx context.Context, w http.ResponseWriter, err error) {
	if errors.Is(err, errInvalidControlAuthority) {
		opLog(ctx).Error("principal control target lookup failed",
			slog.String("operation", "principal_control_target_lookup"),
			slog.String("error", "invalid operator authority"),
		)
		writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	if isErrPrincipalNotFound(err) {
		writeError(ctx, w, http.StatusNotFound, "principal_not_found", "principal not found")
		return
	}
	opLog(ctx).Error("principal control target lookup failed",
		slog.String("operation", "principal_control_target_lookup"),
		slog.String("error", err.Error()),
	)
	writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
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
// Principal, otherwise the stable control target (exact Principal identity)
// the query is narrowed to.
type listQueryScope struct {
	allPrincipals bool
	principal     *principalControlTarget
}

// resolveListScope is the single authorization owner for scope-first list
// Queries on Principal-owned resource families (launcher list, principal
// credential list): the authenticated authority establishes the maximum
// visibility — an admin token may see every Principal, a Principal credential
// only its own — and the optional Principal selector can only narrow that
// visibility, never expand it. An empty filter selects the caller's full
// visible scope. A foreign selector under a Principal credential and an
// unknown selector are both the established non-disclosing 404 (a foreign
// selector is rejected without any lookup). A Principal credential's visible
// scope is resolved by its exact authenticated Principal ID through
// resolvePrincipalControlTarget — never re-resolved by username — so a stale
// authority whose Principal was deleted fails closed as principal_not_found
// instead of rebinding to a recreated same-username Principal. A Launcher
// credential never reaches this resolver: authenticatePrincipalControlRequest
// rejects it. A structurally invalid authority fails closed as an internal
// error: it is never an all-Principals scope and never resolves to a
// Principal.
func (a *App) resolveListScope(w http.ResponseWriter, r *http.Request, auth *operatorAuthority, filter string) (listQueryScope, bool) {
	ctx := r.Context()
	switch {
	case auth != nil && auth.class == operatorAuthorityAdmin:
		if filter == "" {
			return listQueryScope{allPrincipals: true}, true
		}
		target, err := resolvePrincipalControlTarget(a.DB, auth, filter)
		if err != nil {
			writePrincipalControlLookupError(ctx, w, err)
			return listQueryScope{}, false
		}
		return listQueryScope{principal: target}, true
	case auth != nil && auth.class == operatorAuthorityPrincipal:
		// Principal credential: its own Principal is the whole visible scope,
		// resolved by the exact authenticated Principal ID.
		if filter != "" && filter != auth.principal.PrincipalName {
			writeError(ctx, w, http.StatusNotFound, "principal_not_found", "principal not found")
			return listQueryScope{}, false
		}
		target, err := resolvePrincipalControlTarget(a.DB, auth, auth.principal.PrincipalName)
		if err != nil {
			writePrincipalControlLookupError(ctx, w, err)
			return listQueryScope{}, false
		}
		return listQueryScope{principal: target}, true
	default:
		// A nil, zero/invalid, or unknown-class authority is an internal
		// authentication anomaly: fail closed as an internal error — never
		// an all-Principals scope, never a resolved Principal.
		opLog(ctx).Error("list scope invalid operator authority",
			slog.String("operation", "principal_control_target_lookup"),
			slog.String("error", "invalid operator authority"),
		)
		writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		return listQueryScope{}, false
	}
}
