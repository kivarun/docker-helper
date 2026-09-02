package main

import (
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
)

// sessionControlScope is the single internal boundary through which all
// Session create/list/delete handlers authorize their ownership scope. Admin ->
// all Launchers; Principal -> its Launchers; Launcher -> exactly itself.
type sessionControlScope struct {
	// admin is true for the system/user admin token authority; launcherIDs are
	// ignored when admin is set.
	admin bool
	// principalID is non-zero for Principal and Launcher credential
	// authorities.
	principalID int64
	// launcherIDs is the set of Launcher IDs the authority may manage; nil with
	// admin is all.
	launcherIDs map[string]bool
}

// resolveSessionControlScope maps an authenticated authority to the Launcher
// scope it may manage.
func (a *App) resolveSessionControlScope(auth *sessionControlAuthority) sessionControlScope {
	switch {
	case auth == nil:
		return sessionControlScope{}
	case auth.isAdmin:
		// Admin manages all Launcher-owned Sessions.
		return sessionControlScope{admin: true}
	case auth.launcherCredential != nil:
		// A Launcher credential controls exactly itself.
		return sessionControlScope{
			principalID: auth.launcherCredential.PrincipalID,
			launcherIDs: map[string]bool{auth.launcherCredential.LauncherID: true},
		}
	case auth.principalCredential != nil:
		return a.principalLauncherScope(auth.principalCredential.PrincipalID)
	default:
		return sessionControlScope{}
	}
}

// principalLauncherScope resolves the Launcher IDs owned by a Principal.
// Returns an empty (but non-nil) set when the Principal has no Launchers.
func (a *App) principalLauncherScope(principalID int64) sessionControlScope {
	rows, err := a.DB.Query(`SELECT id FROM launchers WHERE principal_id = ?`, principalID)
	if err != nil {
		// Failure to enumerate the scope degrades to no authorization rather
		// than granting a broader scope, preserving fail-closed behavior for
		// the caller's eventual 404.
		return sessionControlScope{principalID: principalID, launcherIDs: map[string]bool{}}
	}
	defer rows.Close()
	ids := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			continue
		}
		ids[id] = true
	}
	return sessionControlScope{principalID: principalID, launcherIDs: ids}
}

// createSelector carries the optional create request selectors for a Session.
type createSelector struct {
	launcherID string
	principal  string
}

// sessionOwnershipSnapshot is a consistent single-transaction projection of a
// Launcher and its owning Principal (roots and scope) used for Session-creation
// admission. It is deliberately a snapshot, not a live query: the admission
// policy must observe one consistent Principal/Launcher state, and the final
// persistence step re-validates enabled state under the same critical section.
type sessionOwnershipSnapshot struct {
	launcherID       string
	launcherName     string
	launcherEnabled  bool
	launcherScope    LauncherScopeMode
	launcherRoots    []string
	principalID      int64
	principalName    string
	principalEnabled bool
	principalRoots   []string
}

// resolveSessionOwnershipSnapshot loads a Launcher and its Principal (with
// their root sets) in one transaction. It returns ErrLauncherNotFound when the
// Launcher does not exist.
func (a *App) resolveSessionOwnershipSnapshot(launcherID string) (*sessionOwnershipSnapshot, error) {
	tx, err := a.DB.Begin()
	if err != nil {
		return nil, fmt.Errorf("cannot begin ownership snapshot: %w", err)
	}
	defer tx.Rollback()

	snap, err := loadSessionOwnershipSnapshot(tx, launcherID)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("cannot commit ownership snapshot: %w", err)
	}
	return snap, nil
}

type txQuerier interface {
	QueryRow(query string, args ...any) *sql.Row
	Query(query string, args ...any) (*sql.Rows, error)
}

func loadSessionOwnershipSnapshot(q txQuerier, launcherID string) (*sessionOwnershipSnapshot, error) {
	var snap sessionOwnershipSnapshot
	var launcherEnabled, principalEnabled int
	var scope string
	err := q.QueryRow(
		`SELECT l.id, l.name, l.enabled, l.scope_mode,
		        p.id, p.username, p.enabled
		 FROM launchers l JOIN principals p ON p.id = l.principal_id
		 WHERE l.id = ?`,
		launcherID,
	).Scan(
		&snap.launcherID, &snap.launcherName, &launcherEnabled, &scope,
		&snap.principalID, &snap.principalName, &principalEnabled,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrLauncherNotFound
		}
		return nil, fmt.Errorf("cannot find launcher: %w", err)
	}
	snap.launcherEnabled = launcherEnabled != 0
	snap.principalEnabled = principalEnabled != 0
	snap.launcherScope = LauncherScopeMode(scope)

	if snap.launcherScope == LauncherScopeRestricted {
		rows, err := q.Query(
			`SELECT root_path FROM launcher_allowed_roots WHERE launcher_id = ? ORDER BY root_path`,
			launcherID,
		)
		if err != nil {
			return nil, fmt.Errorf("cannot query launcher allowed roots: %w", err)
		}
		for rows.Next() {
			var root string
			if err := rows.Scan(&root); err != nil {
				rows.Close()
				return nil, fmt.Errorf("cannot scan launcher allowed root: %w", err)
			}
			snap.launcherRoots = append(snap.launcherRoots, root)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("iterate launcher allowed roots: %w", err)
		}
	}

	rows, err := q.Query(
		`SELECT root_path FROM principal_allowed_roots WHERE principal_id = ? ORDER BY root_path`,
		snap.principalID,
	)
	if err != nil {
		return nil, fmt.Errorf("cannot query principal allowed roots: %w", err)
	}
	for rows.Next() {
		var root string
		if err := rows.Scan(&root); err != nil {
			rows.Close()
			return nil, fmt.Errorf("cannot scan principal allowed root: %w", err)
		}
		snap.principalRoots = append(snap.principalRoots, root)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate principal allowed roots: %w", err)
	}

	return &snap, nil
}

// ErrLauncherUnavailable is returned when the resolved owning Launcher/Principal
// is disabled or otherwise not admissible for a new Session.
var ErrLauncherUnavailable = errors.New("launcher unavailable")

// computeLauncherEffectiveRoots is the single authoritative three-level
// Session-creation root policy. It consumes the global allowed roots (the
// config owner), the Principal's current roots, and the Launcher scope.
//
//   - The effective Principal ceiling is global ∩ Principal roots, except that
//     the user-mode daemon-owner Principal (identified by daemonOwnerPrincipalID
//     in user mode) with zero stored root rows collapses onto the global roots.
//     This is the ONLY Principal for which empty roots mean the global ceiling.
//   - inherit Launcher scope adds no narrowing: the effective roots equal the
//     effective Principal ceiling.
//   - restricted Launcher scope first revalidates the Launcher's stored roots
//     against the current effective Principal ceiling (rejecting stale or
//     directly-injected out-of-ceiling roots), then intersects.
func computeLauncherEffectiveRoots(globalAllowedRoots []string, snap *sessionOwnershipSnapshot, daemonOwnerPrincipalID int64, userMode bool) ([]string, error) {
	var principalCeiling []string
	if userMode && snap.principalID == daemonOwnerPrincipalID && len(snap.principalRoots) == 0 {
		// Collapsed user-mode policy: the daemon-owner Principal defers wholly
		// to the global allowed roots.
		principalCeiling = append([]string(nil), globalAllowedRoots...)
	} else {
		principalCeiling = intersectAllowedRootScopes(globalAllowedRoots, snap.principalRoots)
	}

	if snap.launcherScope == LauncherScopeRestricted {
		// Revalidate stored roots against the current ceiling; fail closed on
		// stale or injected out-of-ceiling roots.
		for _, stored := range snap.launcherRoots {
			if !isWithinAnyAllowedRoot(stored, principalCeiling) {
				return nil, ErrLauncherUnavailable
			}
		}
		return intersectAllowedRootScopes(principalCeiling, snap.launcherRoots), nil
	}
	return principalCeiling, nil
}

var (
	// ErrConflictingSelectors is returned when a Session create request supplies
	// both launcher_id and principal selectors.
	ErrConflictingSelectors = errors.New("conflicting session selectors")
	// ErrInvalidSelector is returned when an authority supplies a selector it
	// is not permitted to use (for example a Principal/Launcher supplying a
	// principal selector).
	ErrInvalidSelector = errors.New("invalid session selector")
	// ErrMissingLauncherSelector is returned when a system-mode Admin supplies
	// neither launcher_id nor principal for Session creation.
	ErrMissingLauncherSelector = errors.New("missing launcher selector")
)

// appResolvedGlobalRoots returns the canonicalized global allowed roots (the
// config owner). Each root is symlink-resolved; resolution failure of any root
// fails closed with an error.
func (a *App) appResolvedGlobalRoots() ([]string, error) {
	cfg := a.getConfig()
	out := make([]string, 0, len(cfg.AllowedRoots))
	for _, r := range cfg.AllowedRoots {
		resolved, err := filepath.EvalSymlinks(r)
		if err != nil {
			return nil, fmt.Errorf("cannot resolve allowed root %q: %w: %w", r, err, ErrSystem)
		}
		out = append(out, resolved)
	}
	return out, nil
}

// resolveCreateLauncher maps an authenticated authority and create selectors
// to the target Launcher ID, implementing the create-selector matrix. It never
// mutates state and never discloses foreign-ownership existence.
func (a *App) resolveCreateLauncher(auth *sessionControlAuthority, sel createSelector) (string, error) {
	if sel.launcherID != "" && sel.principal != "" {
		return "", ErrConflictingSelectors
	}
	switch {
	case auth.isAdmin:
		userMode := a.getConfig().Mode == ModeUser
		switch {
		case sel.launcherID != "":
			return sel.launcherID, nil
		case sel.principal != "":
			pid, err := findPrincipalIDByUsername(a.DB, sel.principal)
			if err != nil {
				return "", ErrLauncherNotFound
			}
			return findDefaultLauncher(a.DB, int64(pid))
		case userMode && a.userModeDefault != nil:
			return a.userModeDefault.launcherID, nil
		default:
			return "", ErrMissingLauncherSelector
		}
	case auth.launcherCredential != nil:
		if sel.principal != "" {
			return "", ErrInvalidSelector
		}
		if sel.launcherID != "" && sel.launcherID != auth.launcherCredential.LauncherID {
			return "", ErrLauncherNotFound
		}
		return auth.launcherCredential.LauncherID, nil
	case auth.principalCredential != nil:
		if sel.principal != "" {
			return "", ErrInvalidSelector
		}
		if sel.launcherID != "" {
			return a.resolveLauncherWithinPrincipal(sel.launcherID, auth.principalCredential.PrincipalID)
		}
		return findDefaultLauncher(a.DB, auth.principalCredential.PrincipalID)
	default:
		return "", ErrInvalidSelector
	}
}

// resolveLauncherWithinPrincipal returns the Launcher ID only if it belongs to
// the given Principal; otherwise returns ErrLauncherNotFound (non-disclosing,
// regardless of whether the Launcher exists).
func (a *App) resolveLauncherWithinPrincipal(launcherID string, principalID int64) (string, error) {
	var ownerID int64
	err := a.DB.QueryRow(`SELECT principal_id FROM launchers WHERE id = ?`, launcherID).Scan(&ownerID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrLauncherNotFound
		}
		return "", fmt.Errorf("cannot check launcher ownership: %w", err)
	}
	if ownerID != principalID {
		return "", ErrLauncherNotFound
	}
	return launcherID, nil
}

// resolveCreatePolicy resolves the complete Session-creation context (Launcher
// target, ownership names, and three-level effective root scope) for an
// authenticated authority and create request. It never mutates state.
func (a *App) resolveCreatePolicy(auth *sessionControlAuthority, sel createSelector, workspace string) (*sessionCreatePolicy, error) {
	launcherID, err := a.resolveCreateLauncher(auth, sel)
	if err != nil {
		return nil, err
	}

	snap, err := a.resolveSessionOwnershipSnapshot(launcherID)
	if err != nil {
		return nil, err
	}
	if !snap.launcherEnabled || !snap.principalEnabled {
		return nil, ErrLauncherUnavailable
	}

	globalRoots, err := a.appResolvedGlobalRoots()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSystem, err)
	}
	userMode := a.getConfig().Mode == ModeUser
	var daemonID int64
	if userMode && a.userModeDefault != nil {
		daemonID = a.userModeDefault.principalID
	}
	effective, err := computeLauncherEffectiveRoots(globalRoots, snap, daemonID, userMode)
	if err != nil {
		return nil, err
	}

	return &sessionCreatePolicy{
		Workspace:             workspace,
		EffectiveAllowedRoots: effective,
		LauncherID:            snap.launcherID,
		LauncherName:          snap.launcherName,
		PrincipalName:         snap.principalName,
	}, nil
}
