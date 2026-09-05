package main

import (
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
// the global allowed roots, every other Principal intersects with them. It is
// a policy introspection Query for shell completion and read-only tooling, in
// the same spirit as GET /auth: identity introspection stays separate from
// this policy introspection, and neither widens the other. Authorization
// follows the Principal control plane: an admin token may target any
// Principal, a Principal credential only its own (a foreign selector is the
// established non-disclosing 404), and a Launcher credential has no
// control-plane authority. Like GET /auth, successful read-only
// introspection writes no per-request audit events; authentication failures
// are audited by the shared auth helpers.
func (a *App) handlePrincipalEffectiveRoots(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	authCtx, err := a.authenticateControlRequest(w, r, "principal")
	if err != nil || authCtx == nil {
		return
	}

	p, ok := a.resolveControlPrincipal(w, r, authCtx, r.PathValue("username"))
	if !ok {
		return
	}

	roots, err := a.resolveEffectivePrincipalRoots(int64(p.ID))
	if err != nil {
		opLog(ctx).Error("principal effective roots introspection failed",
			slog.String("operation", "policy_introspect"),
			slog.String("error", err.Error()),
		)
		writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	if roots == nil {
		roots = []string{}
	}

	writeJSONRaw(ctx, w, http.StatusOK, effectiveRootsResponse{
		OK:           true,
		Principal:    p.Username,
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
// effective roots). It adds none of the create side effects: no workspace
// validation, no MAC preparation, no persistence. Release 2.1 session create
// sends no selectors, so the query resolves with an empty selector set; a
// system-mode admin without a resolvable Launcher therefore receives the
// same missing-selector contract the real create would return.
func (a *App) handleSessionCreatePolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	authCtx, err := a.authenticateSessionControlRequest(w, r)
	if err != nil || authCtx == nil {
		return
	}

	policy, err := a.resolveCreatePolicy(authCtx, createSelector{}, "")
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
