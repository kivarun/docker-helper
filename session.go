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

type Session struct {
	ID            string
	Workspace     string
	CreatedAt     time.Time
	ExpiresAt     time.Time
	PrincipalID   *int64
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

// scanSessionWithPrincipal scans session columns joined with principal username.
// Columns: id, workspace, created_at, expires_at, principal_id, principal_username.
func scanSessionWithPrincipal(s sqlScanner) (Session, error) {
	var sess Session
	var createdAt int64
	var expiresAt int64
	var principalID sql.NullInt64
	var principalName sql.NullString

	if err := s.Scan(&sess.ID, &sess.Workspace, &createdAt, &expiresAt, &principalID, &principalName); err != nil {
		return sess, err
	}

	sess.CreatedAt = time.Unix(createdAt, 0)
	sess.ExpiresAt = time.Unix(expiresAt, 0)
	if principalID.Valid {
		sess.PrincipalID = &principalID.Int64
	}
	if principalName.Valid {
		sess.PrincipalName = principalName.String
	}

	return sess, nil
}

// sessionCreatePolicy contains the context needed to create a session.
// EffectiveAllowedRoots is the already-computed effective session-creation
// allowed-root scope (intersection of global and principal scopes, or the
// canonicalized global scope for admin creation).
type sessionCreatePolicy struct {
	Workspace             string
	EffectiveAllowedRoots []string
	PrincipalID           *int64
}

func (a *App) createSessionWithPolicy(p *sessionCreatePolicy) (*CreatedSession, error) {
	if p.Workspace == "" {
		return nil, fmt.Errorf("workspace is required: %w", ErrInvalidWorkspace)
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
		if p.PrincipalID != nil {
			// Conditional insert: only succeeds if the principal exists AND is enabled.
			// This prevents a stale-auth race where the principal was disabled between
			// authentication and session creation.
			_, err := a.DB.Exec(
				`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at, principal_id)
				 SELECT ?, ?, ?, ?, ?, ?
				 FROM principals WHERE id = ? AND enabled = 1`,
				sessionID,
				tokenHashHex,
				absWorkspace,
				now.Unix(),
				expiresAt.Unix(),
				*p.PrincipalID,
				*p.PrincipalID,
			)
			if err != nil {
				return err
			}
			// Verify exactly one row was inserted. If zero, the principal
			// was disabled or deleted between authentication and this insert.
			// (RowsAffected is not reliable with INSERT...SELECT in SQLite,
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
				return fmt.Errorf("principal is no longer enabled: %w", ErrInvalidWorkspace)
			}
			return nil
		}

		// Admin session: no principal check needed.
		_, err := a.DB.Exec(
			`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at, principal_id)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			sessionID,
			tokenHashHex,
			absWorkspace,
			now.Unix(),
			expiresAt.Unix(),
			nil,
		)
		return err
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
			ID:          sessionID,
			Workspace:   absWorkspace,
			CreatedAt:   now,
			ExpiresAt:   expiresAt,
			PrincipalID: p.PrincipalID,
		},
		Token: token,
	}, nil
}

// createSession is the admin-only session creation using global allowed roots.
func (a *App) createSession(workspace string) (*CreatedSession, error) {
	cfg := a.getConfig()
	globalAllowedRoots := make([]string, 0, len(cfg.AllowedRoots))
	for _, r := range cfg.AllowedRoots {
		resolved, err := filepath.EvalSymlinks(r)
		if err != nil {
			return nil, fmt.Errorf("cannot resolve allowed root: %w: %w", err, ErrSystem)
		}
		globalAllowedRoots = append(globalAllowedRoots, resolved)
	}
	return a.createSessionWithPolicy(&sessionCreatePolicy{
		Workspace:             workspace,
		EffectiveAllowedRoots: globalAllowedRoots,
		PrincipalID:           nil,
	})
}

func (a *App) listSessions() ([]Session, error) {
	now := time.Now().Unix()

	rows, err := a.DB.Query(
		`SELECT s.id, s.workspace, s.created_at, s.expires_at, s.principal_id, p.username
		 FROM sessions s
		 LEFT JOIN principals p ON p.id = s.principal_id
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
		s, err := scanSessionWithPrincipal(rows)
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

// listSessionsForPrincipal returns only sessions owned by the given principal.
func (a *App) listSessionsForPrincipal(principalID int64) ([]Session, error) {
	now := time.Now().Unix()

	rows, err := a.DB.Query(
		`SELECT s.id, s.workspace, s.created_at, s.expires_at, s.principal_id, p.username
		 FROM sessions s
		 LEFT JOIN principals p ON p.id = s.principal_id
		 WHERE s.expires_at > ? AND s.principal_id = ?
		 ORDER BY s.created_at ASC`,
		now, principalID,
	)
	if err != nil {
		return nil, fmt.Errorf("cannot list sessions: %w", err)
	}
	defer rows.Close()

	var sessions []Session
	for rows.Next() {
		s, err := scanSessionWithPrincipal(rows)
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

func (a *App) deleteSession(id string) (*Session, error) {
	row := a.DB.QueryRow(
		`SELECT s.id, s.workspace, s.created_at, s.expires_at, s.principal_id, p.username
		 FROM sessions s
		 LEFT JOIN principals p ON p.id = s.principal_id
		 WHERE s.id = ?`,
		id,
	)

	s, err := scanSessionWithPrincipal(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("session not found: %w", ErrSessionNotFound)
		}
		return nil, fmt.Errorf("cannot find session: %w: %w", err, ErrDatabase)
	}

	// Read-before-delete: the session must be returned to the caller so that
	// the handler can populate the audit record with the workspace even when
	// the DELETE itself fails.
	result, err := a.DB.Exec(`DELETE FROM sessions WHERE id = ?`, id)
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

// deleteSessionForPrincipal atomically deletes a session only if it belongs to the given principal.
// Returns ErrSessionNotFound if the session doesn't exist or doesn't belong to the principal.
// Returns the deleted session metadata for audit purposes.
func (a *App) deleteSessionForPrincipal(id string, principalID int64) (*Session, error) {
	tx, err := a.DB.Begin()
	if err != nil {
		return nil, fmt.Errorf("cannot begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Read session metadata first within the transaction.
	row := tx.QueryRow(
		`SELECT s.id, s.workspace, s.created_at, s.expires_at, s.principal_id, p.username
		 FROM sessions s
		 LEFT JOIN principals p ON p.id = s.principal_id
		 WHERE s.id = ? AND s.principal_id = ?`,
		id, principalID,
	)
	s, err := scanSessionWithPrincipal(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("session not found: %w", ErrSessionNotFound)
		}
		return nil, fmt.Errorf("cannot find session: %w: %w", err, ErrDatabase)
	}

	// Delete within the same transaction.
	result, err := tx.Exec(`DELETE FROM sessions WHERE id = ? AND principal_id = ?`, id, principalID)
	if err != nil {
		return nil, fmt.Errorf("cannot delete session: %w: %w", err, ErrDatabase)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("cannot check deletion result: %w: %w", err, ErrDatabase)
	}
	if affected == 0 {
		return nil, fmt.Errorf("session not found: %w", ErrSessionNotFound)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("cannot commit deletion: %w", err)
	}

	// Release MAC boundary for the deleted session.
	if a.MACCoordinator != nil {
		a.MACCoordinator.ReleaseSessionBinding(id)
	}

	return &s, nil
}

func (a *App) findSessionByToken(token string) (*Session, error) {
	tokenHash := sha256.Sum256([]byte(token))
	tokenHashHex := hex.EncodeToString(tokenHash[:])

	now := time.Now().Unix()

	row := a.DB.QueryRow(
		`SELECT s.id, s.workspace, s.created_at, s.expires_at, s.principal_id, p.username
		 FROM sessions s
		 LEFT JOIN principals p ON p.id = s.principal_id
		 WHERE s.token_hash = ? AND s.expires_at > ?
		 AND (s.principal_id IS NULL OR p.enabled = 1)
		 LIMIT 1`,
		tokenHashHex,
		now,
	)

	s, err := scanSessionWithPrincipal(row)
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

// resolveSessionExecutionIdentity returns the UID:GID for Docker --user.
// Legacy/admin sessions (principal_id == NULL) use the daemon process UID/GID.
// Principal-owned sessions use the stored principal UID/GID from the database.
func resolveSessionExecutionIdentity(db *sql.DB, session *Session) (uid, gid int, err error) {
	if session.PrincipalID == nil {
		return os.Getuid(), os.Getgid(), nil
	}

	var pUID, pGID int
	row := db.QueryRow(
		`SELECT uid, gid FROM principals WHERE id = ?`,
		*session.PrincipalID,
	)
	if err := row.Scan(&pUID, &pGID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, 0, fmt.Errorf("principal %d not found: %w", *session.PrincipalID, ErrDatabase)
		}
		return 0, 0, fmt.Errorf("cannot lookup principal identity: %w", err)
	}

	return pUID, pGID, nil
}
