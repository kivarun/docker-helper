package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

var ErrSessionNotFound = errors.New("session not found")
var ErrInvalidWorkspace = errors.New("invalid workspace")
var ErrDatabase = errors.New("database error")
var ErrSystem = errors.New("system error")
var ErrMAC = errors.New("MAC preparation failed")

func classifyCreateSessionError(err error) string {
	switch {
	case errors.Is(err, ErrInvalidWorkspace):
		return "invalid_workspace"
	case errors.Is(err, ErrDatabase):
		return "database_error"
	case errors.Is(err, ErrSystem):
		return "system_error"
	case errors.Is(err, ErrMAC):
		return "mac_preparation_failed"
	default:
		return "unknown_error"
	}
}

// sqlScanner is satisfied by *sql.Row and *sql.Rows.
type sqlScanner interface {
	Scan(dest ...any) error
}

// Session is the final owner resolution of a Launcher-backed Session. The
// Launcher is the owner; the Principal and its name are derived projections via
// the owning Launcher. There is no ownerless Session and no separate Session
// owner authority beyond the Launcher.
type Session struct {
	ID            string
	Workspace     string
	CreatedAt     time.Time
	ExpiresAt     time.Time
	LauncherID    string
	LauncherName  string
	PrincipalName string
}

type CreatedSession struct {
	Session Session
	Token   string
}

// intersectAllowedRootScopes returns the effective allowed-root scope: the
// mathematical intersection of the global and principal allowed-root scopes.
// For each overlapping pair:
//   - equal roots contribute that root;
//   - principal inside global contributes the principal root;
//   - global inside principal contributes the global root;
//   - disjoint roots contribute nothing.
//
// Results are deduplicated and deterministic.
func intersectAllowedRootScopes(globalAllowedRoots, principalAllowedRoots []string) []string {
	seen := make(map[string]bool)
	var effectiveAllowedRoots []string
	for _, pRoot := range principalAllowedRoots {
		for _, gRoot := range globalAllowedRoots {
			if pRoot == gRoot {
				if !seen[pRoot] {
					seen[pRoot] = true
					effectiveAllowedRoots = append(effectiveAllowedRoots, pRoot)
				}
			} else if pathWithin(gRoot, pRoot) {
				// principal root inside global root -> principal root is effective
				if !seen[pRoot] {
					seen[pRoot] = true
					effectiveAllowedRoots = append(effectiveAllowedRoots, pRoot)
				}
			} else if pathWithin(pRoot, gRoot) {
				// global root inside principal root -> global root is effective
				if !seen[gRoot] {
					seen[gRoot] = true
					effectiveAllowedRoots = append(effectiveAllowedRoots, gRoot)
				}
			}
		}
	}
	return effectiveAllowedRoots
}

// scanSessionWithOwnership scans the final Launcher-owned session projection
// joined with its owning Launcher and that Launcher's Principal. Columns:
// id, workspace, created_at, expires_at, launcher_id, launcher_name,
// principal_username. This is the single Session projection helper.
func scanSessionWithOwnership(s sqlScanner) (Session, error) {
	var sess Session
	var createdAt int64
	var expiresAt int64

	if err := s.Scan(&sess.ID, &sess.Workspace, &createdAt, &expiresAt, &sess.LauncherID, &sess.LauncherName, &sess.PrincipalName); err != nil {
		return sess, err
	}

	sess.CreatedAt = time.Unix(createdAt, 0)
	sess.ExpiresAt = time.Unix(expiresAt, 0)

	return sess, nil
}

// sessionOwnershipProjection is the SQL projection columns shared by every
// Session ownership query, joined through launchers to principals. It is the
// single authoritative JOIN for Session ownership.
const sessionOwnershipProjection = `
	s.id, s.workspace, s.created_at, s.expires_at, s.launcher_id, l.name, p.username
	FROM sessions s
	JOIN launchers l ON l.id = s.launcher_id
	JOIN principals p ON p.id = l.principal_id`

// sessionCreatePolicy contains the resolved context needed to create a session.
// LauncherID is the resolved owning Launcher. EffectiveAllowedRoots is the
// already-computed effective session-creation allowed-root scope (the three-level
// evaluation result).
type sessionCreatePolicy struct {
	Workspace             string
	EffectiveAllowedRoots []string
	LauncherID            string
	LauncherName          string
	PrincipalName         string
}

func (a *App) createSessionWithPolicy(p *sessionCreatePolicy) (*CreatedSession, error) {
	a.lifecycleMu.Lock()
	defer a.lifecycleMu.Unlock()
	return a.createSessionWithPolicyLocked(p)
}

// createSessionWithPolicyLocked is the lock-already-held form of
// createSessionWithPolicy: the lifecycle serialization is already held, so
// policy resolution and persistence cannot interleave with an authority
// mutation. It performs one lifecycle critical section from workspace
// validation through MAC preparation and the conditional final persistence.
func (a *App) createSessionWithPolicyLocked(p *sessionCreatePolicy) (*CreatedSession, error) {
	if p.Workspace == "" {
		return nil, fmt.Errorf("workspace is required: %w", ErrInvalidWorkspace)
	}
	if p.LauncherID == "" {
		return nil, fmt.Errorf("launcher is required: %w", ErrInvalidWorkspace)
	}

	absWorkspace, err := filepath.Abs(p.Workspace)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve workspace path: %w: %w", err, ErrInvalidWorkspace)
	}

	absWorkspace, err = filepath.EvalSymlinks(absWorkspace)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve workspace symlinks: %w: %w", err, ErrInvalidWorkspace)
	}

	info, err := os.Stat(absWorkspace)
	if err != nil {
		return nil, fmt.Errorf("cannot access workspace: %w: %w", err, ErrInvalidWorkspace)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("workspace is not a directory: %w", ErrInvalidWorkspace)
	}

	if len(p.EffectiveAllowedRoots) == 0 {
		return nil, fmt.Errorf("no allowed roots configured: %w", ErrInvalidWorkspace)
	}

	// Check workspace is inside at least one allowed root and is a proper
	// subdirectory (not the root itself).
	inside := false
	for _, root := range p.EffectiveAllowedRoots {
		if absWorkspace == root {
			continue
		}
		if pathWithin(root, absWorkspace) {
			inside = true
			break
		}
	}
	if !inside {
		return nil, fmt.Errorf("workspace must be inside an allowed root: %w", ErrInvalidWorkspace)
	}

	// Generate session ID and token before entering lifecycle critical section.
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, fmt.Errorf("cannot generate session ID: %w: %w", err, ErrSystem)
	}
	sessionID := "dhs_" + hex.EncodeToString(idBytes)

	token, err := generateSessionToken()
	if err != nil {
		return nil, fmt.Errorf("cannot generate session token: %w: %w", err, ErrSystem)
	}
	tokenHash := sha256.Sum256([]byte(token))
	tokenHashHex := hex.EncodeToString(tokenHash[:])

	now := time.Now()
	expiresAt := now.Add(a.getConfig().SessionTTL)

	// Acquire coordinator serialization and prepare MAC.
	// CreateSessionBinding holds the lock through DB insert and rollback.
	insertSession := func() error {
		// Conditional insert: only succeeds if the owning Launcher and its
		// Principal both exist and are enabled. This prevents a stale-auth race
		// where the Launcher/Principal was disabled or deleted between
		// resolution and session creation.
		_, err := a.DB.Exec(
			`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at, launcher_id)
			 SELECT ?, ?, ?, ?, ?, ?
			 FROM launchers l JOIN principals p ON p.id = l.principal_id
			 WHERE l.id = ? AND l.enabled = 1 AND p.enabled = 1`,
			sessionID,
			tokenHashHex,
			absWorkspace,
			now.Unix(),
			expiresAt.Unix(),
			p.LauncherID,
			p.LauncherID,
		)
		if err != nil {
			return err
		}
		// Verify exactly one row was inserted. If zero, the Launcher or its
		// Principal was disabled or deleted between authentication and this
		// insert. Under lifecycle serialization this cannot interleave with a
		// policy mutation, so it surfaces only as a defense-in-depth recheck;
		// the stale-owner rejection is a deterministic typed contract
		// (422 launcher_unavailable), never an invalid_workspace relabel.
		var count int
		err = a.DB.QueryRow(
			`SELECT COUNT(*) FROM sessions WHERE id = ?`,
			sessionID,
		).Scan(&count)
		if err != nil {
			return err
		}
		if count == 0 {
			return fmt.Errorf("launcher is no longer available: %w", ErrLauncherUnavailable)
		}
		return nil
	}

	if a.MACCoordinator != nil {
		_, err := a.MACCoordinator.CreateSessionBinding(absWorkspace, sessionID, func(coverage workspaceMACCoverage) error {
			return insertSession()
		})
		if err != nil {
			// Classify: stale-owner recheck, MAC preparation, and DB insert
			// errors. The stale-owner rejection keeps its typed contract.
			switch {
			case errors.Is(err, ErrLauncherUnavailable):
				return nil, fmt.Errorf("cannot create session: %w", err)
			case errors.Is(err, ErrMACPreparation):
				return nil, fmt.Errorf("cannot create session: %w: %w", err, ErrMAC)
			default:
				return nil, fmt.Errorf("cannot create session: %w: %w", err, ErrDatabase)
			}
		}
	} else {
		if err := insertSession(); err != nil {
			if errors.Is(err, ErrLauncherUnavailable) {
				return nil, fmt.Errorf("cannot create session: %w", err)
			}
			return nil, fmt.Errorf("cannot create session: %w: %w", err, ErrDatabase)
		}
	}

	return &CreatedSession{
		Session: Session{
			ID:            sessionID,
			Workspace:     absWorkspace,
			CreatedAt:     now,
			ExpiresAt:     expiresAt,
			LauncherID:    p.LauncherID,
			LauncherName:  p.LauncherName,
			PrincipalName: p.PrincipalName,
		},
		Token: token,
	}, nil
}

// createSession is the thin default-launcher wrapper over
// createSessionWithPolicy. It leaves all policy resolution to the single
// authoritative resolveCreatePolicy path (admin authority, omitted selectors)
// so Session creation has exactly one policy owner: in user mode this resolves
// the daemon-owner 'default' Launcher under the collapsed global roots; system
// mode has no implicit default and resolves a missing-selector error. It is
// the request-time-equivalent used by tests and any non-selector caller.
// createSessionAuthorized is the single linearized Session-create owner for an
// authenticated authority: it holds the lifecycle serialization across
// current-policy resolution through final Session persistence, so a concurrent
// narrowing of any policy authority (global allowed roots, Principal allowed
// roots, Launcher scope, Launcher/Principal enabled state, Launcher
// existence/ownership) that linearizes before the create commits prevents that
// Session, and one that linearizes after leaves the created Session intact.
// It never mutates policy; it only consumes it.
func (a *App) createSessionAuthorized(auth *sessionControlAuthority, sel createSelector, workspace string) (*CreatedSession, error) {
	a.lifecycleMu.Lock()
	defer a.lifecycleMu.Unlock()

	policy, err := a.resolveCreatePolicy(auth, sel, workspace)
	if err != nil {
		return nil, err
	}
	return a.createSessionWithPolicyLocked(policy)
}

func (a *App) createSession(workspace string) (*CreatedSession, error) {
	return a.createSessionAuthorized(&sessionControlAuthority{isAdmin: true}, createSelector{}, workspace)
}

// listSessions returns all active sessions in admin scope.
func (a *App) listSessions() ([]Session, error) {
	return a.listSessionsInScope(sessionControlScope{admin: true})
}

// listSessionsInScope returns active sessions owned within the given
// ownership scope. Admin lists all Launcher-owned Sessions, a Principal scope
// lists the Sessions owned by that Principal's Launchers, and a Launcher scope
// lists that Launcher's Sessions. The scope is expressed directly in the
// ownership query (which JOINs launchers and principals), so no Launcher
// enumeration or stale snapshot is involved.
func (a *App) listSessionsInScope(scope sessionControlScope) ([]Session, error) {
	now := time.Now().Unix()

	pred, args := sessionScopePredicate(scope)

	rows, err := a.DB.Query(
		`SELECT `+sessionOwnershipProjection+`
		 WHERE s.expires_at > ?`+pred+`
		 ORDER BY s.created_at ASC`,
		append([]any{now}, args...)...,
	)
	if err != nil {
		return nil, fmt.Errorf("cannot list sessions: %w", err)
	}
	defer rows.Close()

	var sessions []Session
	for rows.Next() {
		s, err := scanSessionWithOwnership(rows)
		if err != nil {
			return nil, fmt.Errorf("cannot scan session: %w", err)
		}
		sessions = append(sessions, s)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate sessions: %w", err)
	}

	return sessions, nil
}

// deleteSessionScoped deletes a session by id within a scope, returning its
// metadata for audit. A session outside the scope is not found (non-disclosing).
// The scope is expressed directly in the ownership query; admin deletes any
// Session.
func (a *App) deleteSessionScoped(id string, scope sessionControlScope) (*Session, error) {
	pred, args := sessionScopePredicate(scope)

	selectArgs := append([]any{id}, args...)
	row := a.DB.QueryRow(
		`SELECT `+sessionOwnershipProjection+`
		 WHERE s.id = ?`+pred,
		selectArgs...,
	)

	s, err := scanSessionWithOwnership(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("session not found: %w", ErrSessionNotFound)
		}
		return nil, fmt.Errorf("cannot find session: %w: %w", err, ErrDatabase)
	}

	deletePred, deleteArgs := sessionDeletePredicate(scope)
	deleteArgs = append([]any{id}, deleteArgs...)
	result, err := a.DB.Exec(`DELETE FROM sessions WHERE id = ?`+deletePred, deleteArgs...)
	if err != nil {
		return &s, fmt.Errorf("cannot delete session: %w: %w", err, ErrDatabase)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return &s, fmt.Errorf("cannot check deletion result: %w: %w", err, ErrDatabase)
	}

	if rowsAffected == 0 {
		return nil, fmt.Errorf("session not found: %w", ErrSessionNotFound)
	}

	// Release MAC boundary for the deleted session.
	if a.MACCoordinator != nil {
		a.MACCoordinator.ReleaseSessionBinding(id)
	}

	return &s, nil
}

// sessionDeletePredicate returns the SQL predicate and args that restrict a
// standalone DELETE FROM sessions statement to the given scope. Unlike the
// ownership SELECT (which JOINs launchers/principals and can reference their
// aliases), a DELETE has no join aliases, so the scope is expressed through an
// explicit subquery. Admin deletes any Session.
func sessionDeletePredicate(scope sessionControlScope) (string, []any) {
	switch {
	case scope.admin:
		return "", nil
	case scope.launcherID != "":
		return " AND launcher_id = ?", []any{scope.launcherID}
	case scope.principalID != 0:
		return " AND launcher_id IN (SELECT id FROM launchers WHERE principal_id = ?)", []any{scope.principalID}
	default:
		return " AND 0", nil
	}
}

// sessionScopePredicate returns the SQL predicate and args that restrict a
// Session ownership query to the given scope. The predicate is appended after
// "WHERE s.expires_at > ?" (list) or "WHERE s.id = ?" (delete) and references
// the launchers/principals aliases the shared ownership projection JOINs. An
// empty/invalid scope matches nothing (fail-closed) rather than broadening.
func sessionScopePredicate(scope sessionControlScope) (string, []any) {
	switch {
	case scope.admin:
		return "", nil
	case scope.launcherID != "":
		return " AND s.launcher_id = ?", []any{scope.launcherID}
	case scope.principalID != 0:
		return " AND l.principal_id = ?", []any{scope.principalID}
	default:
		return " AND 0", nil
	}
}

// resolveSessionExecutionIdentity returns the UID:GID for Docker --user for a
// Session, resolved through the owning Launcher to its Principal. There is no
// PrincipalID == nil (daemon) special case: every Session has a Launcher
// owner.
func resolveSessionExecutionIdentity(db *sql.DB, session *Session) (uid, gid int, err error) {
	var pUID, pGID int
	row := db.QueryRow(
		`SELECT p.uid, p.gid
		 FROM launchers l JOIN principals p ON p.id = l.principal_id
		 WHERE l.id = ?`,
		session.LauncherID,
	)
	if err := row.Scan(&pUID, &pGID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, 0, fmt.Errorf("launcher %q principal not found: %w", session.LauncherID, ErrDatabase)
		}
		return 0, 0, fmt.Errorf("cannot lookup launcher principal identity: %w", err)
	}

	return pUID, pGID, nil
}

func (a *App) deleteSession(id string) (*Session, error) {
	return a.deleteSessionScoped(id, sessionControlScope{admin: true})
}

func (a *App) findSessionByToken(token string) (*Session, error) {
	tokenHash := sha256.Sum256([]byte(token))
	tokenHashHex := hex.EncodeToString(tokenHash[:])

	now := time.Now().Unix()

	row := a.DB.QueryRow(
		`SELECT `+sessionOwnershipProjection+`
		 WHERE s.token_hash = ? AND s.expires_at > ?
		 AND l.enabled = 1 AND p.enabled = 1
		 LIMIT 1`,
		tokenHashHex,
		now,
	)

	s, err := scanSessionWithOwnership(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrSessionNotFound
		}
		return nil, fmt.Errorf("cannot find session by token: %w", err)
	}

	return &s, nil
}

// sessionDockerDir returns the path to the session-scoped Docker config
// directory: $RUNTIME_DIR/sessions/<session-id>/docker/
func sessionDockerDir(runtimeDir, sessionID string) string {
	return filepath.Join(runtimeDir, "sessions", sessionID, "docker")
}

// ensureSessionDockerDir creates the session-scoped Docker config directory
// with restrictive permissions (0700) if it does not exist.
// Returns the directory path.
func ensureSessionDockerDir(runtimeDir, sessionID string) (string, error) {
	dir := sessionDockerDir(runtimeDir, sessionID)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("cannot create session Docker directory: %w", err)
	}
	return dir, nil
}

// sessionRuntimeDir returns the parent runtime directory for a session:
// $RUNTIME_DIR/sessions/<session-id>/
func sessionRuntimeDir(runtimeDir, sessionID string) string {
	return filepath.Join(runtimeDir, "sessions", sessionID)
}

// cleanupSessionRuntimeDir removes the session runtime directory best-effort.
// If the directory does not exist, it is not an error.
// Returns a non-nil error only if the directory exists but cannot be removed.
func cleanupSessionRuntimeDir(runtimeDir, sessionID string) error {
	dir := sessionRuntimeDir(runtimeDir, sessionID)
	if err := os.RemoveAll(dir); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("cannot remove session runtime directory: %w", err)
	}
	return nil
}

// cleanupSessionRuntimeDirsBestEffort removes the runtime directory of every
// invalidated session. Best-effort: a failure on one directory is logged with
// the given operation name and does not stop the remaining cleanups. Callers
// must invoke it regardless of their overall outcome whenever a durable
// session invalidation may already have committed, so a later teardown failure
// cannot lose the cleanup until daemon restart.
func cleanupSessionRuntimeDirsBestEffort(ctx context.Context, operation, runtimeDir string, sessionIDs []string) {
	for _, sessionID := range sessionIDs {
		if err := cleanupSessionRuntimeDir(runtimeDir, sessionID); err != nil {
			opLog(ctx).Warn("failed to clean up session runtime directory",
				slog.String("operation", operation),
				slog.String("session_id", sessionID),
				slog.String("error", err.Error()),
			)
		}
	}
}

// cleanupStaleSessionRuntimeDirs removes session runtime directories that no
// longer correspond to an active session. It reads all active session IDs from
// the database and removes any runtime directories whose session ID is not
// in that set. Expired sessions are excluded.
//
// This is best-effort: all stale directories are attempted, and any removal
// failures are accumulated and returned as a single error.
func cleanupStaleSessionRuntimeDirs(db *sql.DB, runtimeDir string) error {
	sessionsDir := filepath.Join(runtimeDir, "sessions")

	// List all active session IDs.
	now := time.Now().Unix()
	rows, err := db.Query(
		`SELECT id FROM sessions WHERE expires_at > ?`,
		now,
	)
	if err != nil {
		return fmt.Errorf("cannot query active sessions: %w", err)
	}

	active := make(map[string]bool)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return fmt.Errorf("cannot scan session id: %w", err)
		}
		active[id] = true
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate sessions: %w", err)
	}

	// Remove stale directories, accumulating errors.
	entries, err := os.ReadDir(sessionsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("cannot read sessions directory: %w", err)
	}

	var staleErrors []error
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if !active[entry.Name()] {
			dir := filepath.Join(sessionsDir, entry.Name())
			if removeErr := os.RemoveAll(dir); removeErr != nil {
				staleErrors = append(staleErrors, fmt.Errorf("%s: %w", entry.Name(), removeErr))
			}
		}
	}

	if len(staleErrors) > 0 {
		return fmt.Errorf("stale session cleanup failed (%d error(s)): %v", len(staleErrors), staleErrors)
	}
	return nil
}
