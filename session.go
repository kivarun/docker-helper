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
	RevokedAt *time.Time
}

type CreatedSession struct {
	Session Session
	Token   string
}

// scanSession scans the canonical session column order and converts
// Unix-integer timestamps to time.Time.  The caller must query exactly
// the columns: id, workspace, created_at, expires_at, revoked_at.
func scanSession(s sqlScanner) (Session, error) {
	var sess Session
	var createdAt int64
	var expiresAt int64
	var revokedAt sql.NullInt64

	if err := s.Scan(&sess.ID, &sess.Workspace, &createdAt, &expiresAt, &revokedAt); err != nil {
		return sess, err
	}

	sess.CreatedAt = time.Unix(createdAt, 0)
	sess.ExpiresAt = time.Unix(expiresAt, 0)

	if revokedAt.Valid {
		t := time.Unix(revokedAt.Int64, 0)
		sess.RevokedAt = &t
	}

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
		`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at, revoked_at)
		 VALUES (?, ?, ?, ?, ?, NULL)`,
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
		`SELECT id, workspace, created_at, expires_at, revoked_at
		 FROM sessions
		 WHERE expires_at > ? AND revoked_at IS NULL
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
	// First get the session data before deleting
	row := a.DB.QueryRow(
		`SELECT id, workspace, created_at, expires_at, revoked_at
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

	// Now delete the session
	result, err := a.DB.Exec(`DELETE FROM sessions WHERE id = ?`, id)
	if err != nil {
		// Session was found, but delete failed - return session with error
		return &s, fmt.Errorf("cannot delete session: %w: %w", err, ErrDatabase)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		// Session was found, but RowsAffected failed - return session with error
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
		`SELECT id, workspace, created_at, expires_at, revoked_at
		 FROM sessions
		 WHERE token_hash = ? AND expires_at > ? AND revoked_at IS NULL
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
