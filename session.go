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

func classifyCreateSessionError(err error) string {
	switch {
	case errors.Is(err, ErrInvalidWorkspace):
		return "invalid_workspace"
	case errors.Is(err, ErrDatabase):
		return "database_error"
	case errors.Is(err, ErrSystem):
		return "system_error"
	default:
		return "unknown_error"
	}
}

// sqlScanner is satisfied by *sql.Row and *sql.Rows.
type sqlScanner interface {
	Scan(dest ...any) error
}

type Session struct {
	ID        string
	Workspace string
	CreatedAt time.Time
	ExpiresAt time.Time
}

type CreatedSession struct {
	Session Session
	Token   string
}

// scanSession scans the canonical session column order and converts
// Unix-integer timestamps to time.Time.  The caller must query exactly
// the columns: id, workspace, created_at, expires_at.
func scanSession(s sqlScanner) (Session, error) {
	var sess Session
	var createdAt int64
	var expiresAt int64

	if err := s.Scan(&sess.ID, &sess.Workspace, &createdAt, &expiresAt); err != nil {
		return sess, err
	}

	sess.CreatedAt = time.Unix(createdAt, 0)
	sess.ExpiresAt = time.Unix(expiresAt, 0)

	return sess, nil
}

func (a *App) createSession(workspace string) (*CreatedSession, error) {
	if workspace == "" {
		return nil, fmt.Errorf("workspace is required: %w", ErrInvalidWorkspace)
	}

	absWorkspace, err := filepath.Abs(workspace)
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

	cfg := a.getConfig()
	allowedRoot, err := filepath.EvalSymlinks(cfg.AllowedRoot)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve allowed root: %w: %w", err, ErrSystem)
	}

	if !isInside(allowedRoot, absWorkspace) {
		return nil, fmt.Errorf("workspace must be inside %s: %w", allowedRoot, ErrInvalidWorkspace)
	}

	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, fmt.Errorf("cannot generate session ID: %w: %w", err, ErrSystem)
	}
	sessionID := "dhs_" + hex.EncodeToString(idBytes)

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("cannot generate session token: %w: %w", err, ErrSystem)
	}
	token := "dht_" + hex.EncodeToString(tokenBytes)

	tokenHash := sha256.Sum256([]byte(token))
	tokenHashHex := hex.EncodeToString(tokenHash[:])

	now := time.Now()
	expiresAt := now.Add(cfg.SessionTTL)

	_, err = a.DB.Exec(
		`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?)`,
		sessionID,
		tokenHashHex,
		absWorkspace,
		now.Unix(),
		expiresAt.Unix(),
	)
	if err != nil {
		return nil, fmt.Errorf("cannot create session: %w: %w", err, ErrDatabase)
	}

	return &CreatedSession{
		Session: Session{
			ID:        sessionID,
			Workspace: absWorkspace,
			CreatedAt: now,
			ExpiresAt: expiresAt,
		},
		Token: token,
	}, nil
}

func (a *App) listSessions() ([]Session, error) {
	now := time.Now().Unix()

	rows, err := a.DB.Query(
		`SELECT id, workspace, created_at, expires_at
		 FROM sessions
		 WHERE expires_at > ?
		 ORDER BY created_at ASC`,
		now,
	)
	if err != nil {
		return nil, fmt.Errorf("cannot list sessions: %w", err)
	}
	defer rows.Close()

	var sessions []Session
	for rows.Next() {
		s, err := scanSession(rows)
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
		`SELECT id, workspace, created_at, expires_at
		 FROM sessions WHERE id = ?`,
		id,
	)

	s, err := scanSession(row)
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

	return &s, nil
}

func (a *App) findSessionByToken(token string) (*Session, error) {
	tokenHash := sha256.Sum256([]byte(token))
	tokenHashHex := hex.EncodeToString(tokenHash[:])

	now := time.Now().Unix()

	row := a.DB.QueryRow(
		`SELECT id, workspace, created_at, expires_at
		 FROM sessions
		 WHERE token_hash = ? AND expires_at > ?
		 LIMIT 1`,
		tokenHashHex,
		now,
	)

	s, err := scanSession(row)
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

	// Remove stale directories.
	entries, err := os.ReadDir(sessionsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("cannot read sessions directory: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if !active[entry.Name()] {
			dir := filepath.Join(sessionsDir, entry.Name())
			if removeErr := os.RemoveAll(dir); removeErr != nil {
				// Log but don't fail — stale cleanup is best-effort.
				fmt.Fprintf(os.Stderr, "warning: cannot remove stale session runtime directory %s: %v\n", dir, removeErr)
			}
		}
	}

	return nil
}
