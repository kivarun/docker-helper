package main

import (
	"errors"
	"log/slog"
	"net/http"
)

// effectiveRootsResponse is the read-only wire response for the Principal
// effective allowed-roots introspection Query. allowed_roots is the derived
// 2.1 path-only projection; allowed_root_entries is the authoritative rich
// projection of the same effective scope — both come from one canonical
// evaluation, always serialized as JSON arrays (never null).
type effectiveRootsResponse struct {
	OK                 bool               `json:"ok"`
	Principal          string             `json:"principal"`
	AllowedRoots       []string           `json:"allowed_roots"`
	AllowedRootEntries []AllowedRootEntry `json:"allowed_root_entries"`
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
	entries := snap.AllowedRootEntries
	if entries == nil {
		entries = []AllowedRootEntry{}
	}

	writeJSONRaw(ctx, w, http.StatusOK, effectiveRootsResponse{
		OK:                 true,
		Principal:          snap.Principal,
		AllowedRoots:       roots,
		AllowedRootEntries: entries,
	})
}

// sessionCreatePolicyResponse is the read-only wire response for the
// Session-create policy introspection Query. allowed_roots is the derived
// 2.1 path-only projection of the effective session-creation scope;
// allowed_root_entries is the authoritative rich projection of the same
// scope — both are projected from the one canonical 2.2 evaluation, always
// serialized as JSON arrays (never null).
type sessionCreatePolicyResponse struct {
	OK                 bool               `json:"ok"`
	Principal          string             `json:"principal"`
	LauncherID         string             `json:"launcher_id"`
	Launcher           string             `json:"launcher"`
	AllowedRoots       []string           `json:"allowed_roots"`
	AllowedRootEntries []AllowedRootEntry `json:"allowed_root_entries"`
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
// no persistence. The query optionally carries the typed Session-create
// selectors as query parameters (principal = Principal username, launcher =
// Launcher name or dhl_ ID), exactly as the completing command line has
// them. The daemon resolves them through the same canonical owners real
// Session creation uses: a launcher selector goes through the shared
// Launcher-selector resolution owner (resolveLauncherSelector, under the
// selected Principal context for an admin and under the authenticated
// Principal's own scope for a Principal credential), a principal selector
// re-enters resolveCreatePolicy untouched. The mapped selector therefore
// resolves to exactly the target a real Session create with the same
// selectors would use, with the same non-disclosing contract for foreign,
// missing, malformed, or authority-illegal selectors (shell completion
// fails silently on any rejection). Selectorless requests keep the
// default-target policy.
func (a *App) handleSessionCreatePolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	authCtx, err := a.authenticateSessionControlRequest(w, r)
	if err != nil || authCtx == nil {
		return
	}

	q := r.URL.Query()
	sel := createSelector{principal: q.Get("principal")}
	if launcher := q.Get("launcher"); launcher != "" {
		switch {
		case authCtx.class == operatorAuthorityLauncher:
			// A Launcher credential's selector is compared against its own
			// exact ID by the create policy owner; a name or foreign ID is
			// the non-disclosing launcher-not-found.
			sel.launcherID = launcher
		case authCtx.class == operatorAuthorityPrincipal && sel.principal != "":
			// Authority-illegal combination: keep both fields so the create
			// policy owner rejects it with the structural create contract.
			sel.launcherID = launcher
		default:
			var principalCtx *int64
			if authCtx.class == operatorAuthorityPrincipal {
				// A Principal credential resolves the selector inside its own
				// scope, exactly like a real create's --launcher.
				ownID := authCtx.principal.PrincipalID
				principalCtx = &ownID
			} else if sel.principal != "" {
				target, terr := resolvePrincipalControlTarget(a.DB, authCtx, sel.principal)
				if terr != nil {
					if isErrPrincipalNotFound(terr) {
						// Real create maps a missing selected Principal to
						// the non-disclosing launcher-not-found.
						writeError(ctx, w, http.StatusNotFound, "launcher_not_found", "launcher not found")
						return
					}
					if !errors.Is(terr, errInvalidControlAuthority) {
						opLog(ctx).Error("session create-policy introspection failed",
							slog.String("operation", "policy_introspect"),
							slog.String("error", terr.Error()),
						)
					}
					writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
					return
				}
				principalCtx = &target.ID
			}
			l, lerr := resolveLauncherSelector(a.DB, principalCtx, launcher)
			if lerr != nil {
				if errors.Is(lerr, ErrLauncherNotFound) || errors.Is(lerr, ErrLauncherNameRequiresPrincipal) {
					writeError(ctx, w, http.StatusNotFound, "launcher_not_found", "launcher not found")
					return
				}
				opLog(ctx).Error("session create-policy introspection failed",
					slog.String("operation", "policy_introspect"),
					slog.String("error", lerr.Error()),
				)
				writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
				return
			}
			// The resolved Launcher supersedes the principal selector's
			// defaulting, exactly like the real create request whose
			// launcher_id the CLI resolved under that Principal.
			sel = createSelector{launcherID: l.ID}
		}
	}

	policy, err := a.resolveCreatePolicySnapshot(authCtx, sel, "")
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
	entries := policy.EffectiveAllowedRootEntries
	if entries == nil {
		entries = []AllowedRootEntry{}
	}

	writeJSONRaw(ctx, w, http.StatusOK, sessionCreatePolicyResponse{
		OK:                 true,
		Principal:          policy.PrincipalName,
		LauncherID:         policy.LauncherID,
		Launcher:           policy.LauncherName,
		AllowedRoots:       roots,
		AllowedRootEntries: entries,
	})
}
