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

func (a *App) createSession(workspace string) (*CreatedSession, error) {
	if workspace == "" {
		return nil, errors.New("workspace is required")
	}

	absWorkspace, err := filepath.Abs(workspace)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve workspace path: %w", err)
	}

	absWorkspace, err = filepath.EvalSymlinks(absWorkspace)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve workspace symlinks: %w", err)
	}

	info, err := os.Stat(absWorkspace)
	if err != nil {
		return nil, fmt.Errorf("cannot access workspace: %w", err)
	}
	if !info.IsDir() {
		return nil, errors.New("workspace is not a directory")
	}

	allowedRoot, err := filepath.EvalSymlinks(a.Config.AllowedRoot)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve allowed root: %w", err)
	}

	if !isInside(allowedRoot, absWorkspace) {
		return nil, fmt.Errorf("workspace must be inside %s", allowedRoot)
	}

	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, fmt.Errorf("cannot generate session ID: %w", err)
	}
	sessionID := "dhs_" + hex.EncodeToString(idBytes)

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("cannot generate session token: %w", err)
	}
	token := "dht_" + hex.EncodeToString(tokenBytes)

	tokenHash := sha256.Sum256([]byte(token))
	tokenHashHex := hex.EncodeToString(tokenHash[:])

	now := time.Now()
	expiresAt := now.Add(a.Config.SessionTTL)

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
		return nil, fmt.Errorf("cannot create session: %w", err)
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
		var s Session
		var createdAt int64
		var expiresAt int64
		var revokedAt sql.NullInt64

		if err := rows.Scan(&s.ID, &s.Workspace, &createdAt, &expiresAt, &revokedAt); err != nil {
			return nil, fmt.Errorf("cannot scan session: %w", err)
		}

		s.CreatedAt = time.Unix(createdAt, 0)
		s.ExpiresAt = time.Unix(expiresAt, 0)

		if revokedAt.Valid {
			t := time.Unix(revokedAt.Int64, 0)
			s.RevokedAt = &t
		}

		sessions = append(sessions, s)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate sessions: %w", err)
	}

	return sessions, nil
}

func (a *App) deleteSession(id string) (bool, error) {
	result, err := a.DB.Exec(`DELETE FROM sessions WHERE id = ?`, id)
	if err != nil {
		return false, fmt.Errorf("cannot delete session: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("cannot check deletion result: %w", err)
	}

	return rowsAffected > 0, nil
}

func (a *App) findSessionByToken(token string) (*Session, error) {
	tokenHash := sha256.Sum256([]byte(token))
	tokenHashHex := hex.EncodeToString(tokenHash[:])

	now := time.Now().Unix()

	var s Session
	var createdAt int64
	var expiresAt int64
	var revokedAt sql.NullInt64

	err := a.DB.QueryRow(
		`SELECT id, workspace, created_at, expires_at, revoked_at
		 FROM sessions
		 WHERE token_hash = ? AND expires_at > ? AND revoked_at IS NULL
		 LIMIT 1`,
		tokenHashHex,
		now,
	).Scan(&s.ID, &s.Workspace, &createdAt, &expiresAt, &revokedAt)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrSessionNotFound
		}
		return nil, fmt.Errorf("cannot find session by token: %w", err)
	}

	s.CreatedAt = time.Unix(createdAt, 0)
	s.ExpiresAt = time.Unix(expiresAt, 0)

	if revokedAt.Valid {
		t := time.Unix(revokedAt.Int64, 0)
		s.RevokedAt = &t
	}

	return &s, nil
}
