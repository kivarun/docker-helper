package main

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
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
		// insert. (RowsAffected is not reliable with INSERT...SELECT in SQLite,
		// so we verify by checking the session exists.)
		var count int
		err = a.DB.QueryRow(
			`SELECT COUNT(*) FROM sessions WHERE id = ?`,
			sessionID,
		).Scan(&count)
		if err != nil {
			return err
		}
		if count == 0 {
			return fmt.Errorf("launcher is no longer enabled: %w", ErrInvalidWorkspace)
		}
		return nil
	}

	if a.MACCoordinator != nil {
		_, err := a.MACCoordinator.CreateSessionBinding(absWorkspace, sessionID, func(coverage workspaceMACCoverage) error {
			return insertSession()
		})
		if err != nil {
			// Classify: MAC preparation errors vs DB insert errors.
			if errors.Is(err, ErrMACPreparation) {
				return nil, fmt.Errorf("cannot create session: %w: %w", err, ErrMAC)
			}
			return nil, fmt.Errorf("cannot create session: %w: %w", err, ErrDatabase)
		}
	} else {
		if err := insertSession(); err != nil {
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

// createSession is the thin user-mode default wrapper over
// createSessionWithPolicy. It resolves the real daemon-owner 'default' Launcher
// (provisioned at startup by ensureUserModeOwnership) and creates a Session
// under the global allowed roots (the user-mode collapsed policy). It is the
// request-time-equivalent used by tests and any non-selector user-mode caller.
// System mode has no implicit default and must use explicit selectors.
func (a *App) createSession(workspace string) (*CreatedSession, error) {
	if a.getConfig().Mode != ModeUser || a.userModeDefault == nil {
		return nil, fmt.Errorf("no default launcher available for session creation: %w", ErrInvalidWorkspace)
	}
	globalRoots, err := a.appResolvedGlobalRoots()
	if err != nil {
		return nil, fmt.Errorf("cannot resolve allowed roots: %w: %w", err, ErrSystem)
	}
	launcherID := a.userModeDefault.launcherID
	return a.createSessionWithPolicy(&sessionCreatePolicy{
		Workspace:             workspace,
		EffectiveAllowedRoots: globalRoots,
		LauncherID:            launcherID,
		LauncherName:          "default",
		PrincipalName:         a.userModeDefault.username,
	})
}

// listSessions returns all active sessions in admin scope.
func (a *App) listSessions() ([]Session, error) {
	now := time.Now().Unix()

	rows, err := a.DB.Query(
		`SELECT `+sessionOwnershipProjection+`
		 WHERE s.expires_at > ?
		 ORDER BY s.created_at ASC`,
		now,
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

// listSessionsInScope returns active sessions owned by any Launcher in the
// given authorized Launcher set. A nil/empty set (admin scope) lists all
// sessions owned by any Launcher.
func (a *App) listSessionsInScope(launcherIDs map[string]bool) ([]Session, error) {
	now := time.Now().Unix()

	pred, args, err := launcherScopePredicate(launcherIDs)
	if err != nil {
		return nil, err
	}

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
// A nil scope (admin) deletes any session.
func (a *App) deleteSessionScoped(id string, launcherIDs map[string]bool) (*Session, error) {
	pred, args, err := launcherScopePredicate(launcherIDs)
	if err != nil {
		return nil, err
	}

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

	deleteArgs := append([]any{id}, args...)
	result, err := a.DB.Exec(`DELETE FROM sessions WHERE id = ?`+pred, deleteArgs...)
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

// launcherScopePredicate returns the SQL predicate and args that restrict a
// Session query to the given Launcher set. A nil scope (admin) matches all
// Launcher-owned Sessions.
func launcherScopePredicate(launcherIDs map[string]bool) (string, []any, error) {
	if launcherIDs == nil {
		return "", nil, nil
	}
	ids := make([]string, 0, len(launcherIDs))
	args := make([]any, 0, len(launcherIDs))
	for id := range launcherIDs {
		ids = append(ids, id)
		args = append(args, id)
	}
	if len(ids) == 0 {
		return " AND 0", nil, nil
	}
	// Unqualified (not s.launcher_id): this predicate is shared by the SELECT
	// ownership queries and by the standalone DELETE, where no alias exists.
	return " AND launcher_id IN (" + placeholderList(len(ids)) + ")", args, nil
}

// placeholderList returns a SQLite placeholder list "?,?,?" of length n,
// or "NULL" (impossible match) when n is 0.
func placeholderList(n int) string {
	if n <= 0 {
		return "NULL"
	}
	out := ""
	for i := 0; i < n; i++ {
		if i > 0 {
			out += ","
		}
		out += "?"
	}
	return out
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
	return a.deleteSessionScoped(id, nil)
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
