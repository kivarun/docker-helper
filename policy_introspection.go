package main

import (
	"errors"
	"log/slog"
	"net/http"
)

// effectiveRootsResponse is the read-only wire response for the Principal
// effective allowed-roots introspection Query.
type effectiveRootsResponse struct {
	OK           bool     `json:"ok"`
	Principal    string   `json:"principal"`
	AllowedRoots []string `json:"allowed_roots"`
}

// handlePrincipalEffectiveRoots answers GET
// /principals/{username}/effective-allowed-roots: the effective Principal
// filesystem authority, computed daemon-side by the canonical
// effective-Principal-root policy owner (computeEffectivePrincipalRoots): in
// user mode the daemon-owner Principal with zero stored roots collapses onto
// the global allowed roots, every other Principal intersects with them. The
// whole projection — target Principal identity and effective roots — is
// resolved under the lifecycle serialization boundary
// (resolvePrincipalEffectiveRootsSnapshot) through the stable Principal-control
// target owner, so the response describes one coherent policy state of one
// Principal incarnation even while a config reload or a Principal/ownership
// lifecycle mutation is concurrent; a target that disappears before the
// snapshot linearizes is the established non-disclosing 404. Authority
// semantics follow the stable target owner: an Admin authority follows the
// current same-username Principal, a Principal credential resolves its exact
// authenticated Principal ID, so a stale authority whose Principal was deleted
// (even if the same username was recreated) fails closed as 404 and never
// observes the replacement incarnation. Authentication stays outside the
// boundary. It is a policy introspection Query for shell completion and
// read-only tooling, in the same spirit as GET /auth: identity introspection
// stays separate from this policy introspection, and neither widens the
// other. Authorization follows the Principal control plane: an admin token
// may target any Principal, a Principal credential only its own (a foreign
// selector is the established non-disclosing 404), and a Launcher credential
// has no control-plane authority. Like GET /auth, successful read-only
// introspection writes no per-request audit events; authentication failures
// are audited by the shared auth helpers.
func (a *App) handlePrincipalEffectiveRoots(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	authCtx, err := a.authenticatePrincipalControlRequest(w, r, "principal")
	if err != nil || authCtx == nil {
		return
	}

	snap, err := a.resolvePrincipalEffectiveRootsSnapshot(authCtx, r.PathValue("username"))
	if err != nil {
		if isErrPrincipalNotFound(err) {
			writeError(ctx, w, http.StatusNotFound, "principal_not_found", "principal not found")
			return
		}
		if !errors.Is(err, errInvalidControlAuthority) {
			opLog(ctx).Error("principal effective roots introspection failed",
				slog.String("operation", "policy_introspect"),
				slog.String("error", err.Error()),
			)
		}
		writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	roots := snap.AllowedRoots
	if roots == nil {
		roots = []string{}
	}

	writeJSONRaw(ctx, w, http.StatusOK, effectiveRootsResponse{
		OK:           true,
		Principal:    snap.Principal,
		AllowedRoots: roots,
	})
}

// sessionCreatePolicyResponse is the read-only wire response for the
// Session-create policy introspection Query.
type sessionCreatePolicyResponse struct {
	OK           bool     `json:"ok"`
	Principal    string   `json:"principal"`
	LauncherID   string   `json:"launcher_id"`
	Launcher     string   `json:"launcher"`
	AllowedRoots []string `json:"allowed_roots"`
}

// handleSessionCreatePolicy answers GET /sessions/create-policy: what
// ownership and filesystem policy a Session created right now with this
// authority would use. It authenticates exactly like POST /sessions and
// resolves through the same single owner as real Session creation
// (resolveCreatePolicy: authority -> Launcher target -> three-level
// effective roots), under the same lifecycle serialization boundary
// (resolveCreatePolicySnapshot), so the whole projection — principal,
// Launcher, and effective roots — corresponds to one coherent policy state
// exactly like a real concurrent Session create would observe. It adds none
// of the create side effects: no workspace validation, no MAC preparation,
// no persistence. Release 2.1 session create sends no selectors, so the
// query resolves with an empty selector set; a system-mode admin without a
// resolvable Launcher therefore receives the same missing-selector contract
// the real create would return.
func (a *App) handleSessionCreatePolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	authCtx, err := a.authenticateSessionControlRequest(w, r)
	if err != nil || authCtx == nil {
		return
	}

	policy, err := a.resolveCreatePolicySnapshot(authCtx, createSelector{}, "")
	if err != nil {
		if te := classifyCreateTargetError(err); te != nil {
			writeError(ctx, w, te.status, te.code, te.msg)
			return
		}
		opLog(ctx).Error("session create-policy introspection failed",
			slog.String("operation", "policy_introspect"),
			slog.String("error", err.Error()),
		)
		writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}

	roots := policy.EffectiveAllowedRoots
	if roots == nil {
		roots = []string{}
	}

	writeJSONRaw(ctx, w, http.StatusOK, sessionCreatePolicyResponse{
		OK:           true,
		Principal:    policy.PrincipalName,
		LauncherID:   policy.LauncherID,
		Launcher:     policy.LauncherName,
		AllowedRoots: roots,
	})
}
