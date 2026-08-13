package main

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

var (
	ErrCredentialNotFound    = errors.New("credential not found")
	ErrCredentialExists      = errors.New("credential already exists")
	ErrInvalidCredentialName = errors.New("invalid credential name")
)

type Credential struct {
	ID        string
	Name      string
	CreatedAt time.Time
	RevokedAt *time.Time
}

// CredentialWithPrincipal is a Credential with its principal username.
type CredentialWithPrincipal struct {
	Credential
	Principal string
}

// generateCredentialToken returns a random 32-byte hex token prefixed with "dhc_".
func generateCredentialToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("cannot generate random bytes: %w", err)
	}
	return "dhc_" + hex.EncodeToString(b), nil
}

// hashCredentialToken returns the SHA-256 hex digest of the token.
func hashCredentialToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// generateCredentialID returns a random 16-byte hex ID prefixed with "dhcr_".
func generateCredentialID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("cannot generate random bytes: %w", err)
	}
	return "dhcr_" + hex.EncodeToString(b), nil
}

func createCredential(db *sql.DB, username string, name string) (*CredentialWithPrincipal, string, error) {
	if name == "" {
		return nil, "", fmt.Errorf("credential name is required: %w", ErrInvalidCredentialName)
	}

	principalID, err := findPrincipalIDByUserName(db, username)
	if err != nil {
		return nil, "", err
	}

	token, err := generateCredentialToken()
	if err != nil {
		return nil, "", err
	}
	tokenHash := hashCredentialToken(token)
	credID, err := generateCredentialID()
	if err != nil {
		return nil, "", err
	}
	now := time.Now().Unix()

	_, err = db.Exec(
		`INSERT INTO credentials (id, principal_id, name, token_hash, created_at)
		 VALUES (?, ?, ?, ?, ?)`,
		credID, principalID, name, tokenHash, now,
	)
	if err != nil {
		if isSQLiteUniqueError(err) {
			return nil, "", fmt.Errorf("credential %q already exists for principal %q: %w", name, username, ErrCredentialExists)
		}
		return nil, "", fmt.Errorf("cannot create credential: %w", err)
	}

	return &CredentialWithPrincipal{
		Credential: Credential{
			ID:        credID,
			Name:      name,
			CreatedAt: time.Unix(now, 0),
		},
		Principal: username,
	}, token, nil
}

func listCredentials(db *sql.DB, username string) ([]CredentialWithPrincipal, error) {
	principalID, err := findPrincipalIDByUserName(db, username)
	if err != nil {
		return nil, err
	}

	rows, err := db.Query(
		`SELECT c.id, c.name, c.created_at, c.revoked_at
		 FROM credentials c
		 WHERE c.principal_id = ?
		 ORDER BY c.created_at ASC`,
		principalID,
	)
	if err != nil {
		return nil, fmt.Errorf("cannot query credentials: %w", err)
	}
	defer rows.Close()

	creds := []CredentialWithPrincipal{}
	for rows.Next() {
		var c Credential
		var revokedAt sql.NullInt64
		var createdAt int64
		if err := rows.Scan(&c.ID, &c.Name, &createdAt, &revokedAt); err != nil {
			return nil, fmt.Errorf("cannot scan credential: %w", err)
		}
		c.CreatedAt = time.Unix(createdAt, 0)
		if revokedAt.Valid {
			t := time.Unix(revokedAt.Int64, 0)
			c.RevokedAt = &t
		}
		creds = append(creds, CredentialWithPrincipal{
			Credential: c,
			Principal:  username,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate credentials: %w", err)
	}

	return creds, nil
}

func findCredentialByID(db *sql.DB, id string) (*CredentialWithPrincipal, error) {
	if id == "" {
		return nil, fmt.Errorf("credential id is required: %w", ErrCredentialNotFound)
	}

	var c Credential
	var username string
	var createdAt int64
	var revokedAt sql.NullInt64
	row := db.QueryRow(
		`SELECT c.id, c.name, c.created_at, c.revoked_at, p.username
		 FROM credentials c
		 JOIN principals p ON p.id = c.principal_id
		 WHERE c.id = ?`,
		id,
	)
	err := row.Scan(&c.ID, &c.Name, &createdAt, &revokedAt, &username)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("credential %q not found: %w", id, ErrCredentialNotFound)
		}
		return nil, fmt.Errorf("cannot find credential: %w", err)
	}
	c.CreatedAt = time.Unix(createdAt, 0)
	if revokedAt.Valid {
		t := time.Unix(revokedAt.Int64, 0)
		c.RevokedAt = &t
	}

	return &CredentialWithPrincipal{
		Credential: c,
		Principal:  username,
	}, nil
}

func revokeCredential(db *sql.DB, id string) (bool, error) {
	if id == "" {
		return false, fmt.Errorf("credential id is required: %w", ErrCredentialNotFound)
	}

	// Atomic update: only set revoked_at if it's currently NULL.
	now := time.Now().Unix()
	result, err := db.Exec(
		`UPDATE credentials SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`,
		now, id,
	)
	if err != nil {
		return false, fmt.Errorf("cannot revoke credential: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("cannot check revoke result: %w", err)
	}

	if affected == 0 {
		// Check if the credential exists at all.
		var exists int
		err = db.QueryRow(`SELECT COUNT(*) FROM credentials WHERE id = ?`, id).Scan(&exists)
		if err != nil {
			return false, fmt.Errorf("cannot check credential existence: %w", err)
		}
		if exists == 0 {
			return false, fmt.Errorf("credential %q not found: %w", id, ErrCredentialNotFound)
		}
		// Credential exists but already revoked.
		return false, nil
	}

	return true, nil
}

// ErrCredentialDisabled is returned when the credential's principal is disabled.
var ErrCredentialDisabled = errors.New("credential disabled")

// ErrCredentialRevoked is returned when the credential has been revoked.
var ErrCredentialRevoked = errors.New("credential revoked")

// CredentialAuthResult contains the information needed to authorize a principal request.
type CredentialAuthResult struct {
	PrincipalID   int64
	PrincipalName string
	CredentialID  string
	AllowedRoots  []string
}

// authenticateCredential looks up a bearer token as a launcher credential.
// Returns the authenticated principal and allowed roots on success.
// Returns ErrCredentialNotFound for unknown token.
// Returns ErrCredentialRevoked for revoked credentials.
// Returns ErrCredentialDisabled for disabled principals.
func authenticateCredential(db *sql.DB, token string) (*CredentialAuthResult, error) {
	tokenHash := hashCredentialToken(token)

	var credID, principalName string
	var principalID int64
	var revokedAt sql.NullInt64
	var enabled int
	row := db.QueryRow(
		`SELECT c.id, p.id, p.username, c.revoked_at, p.enabled
		 FROM credentials c
		 JOIN principals p ON p.id = c.principal_id
		 WHERE c.token_hash = ?`,
		tokenHash,
	)
	err := row.Scan(&credID, &principalID, &principalName, &revokedAt, &enabled)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("credential not found: %w", ErrCredentialNotFound)
		}
		return nil, fmt.Errorf("cannot authenticate credential: %w", err)
	}

	if revokedAt.Valid {
		return nil, fmt.Errorf("credential revoked: %w", ErrCredentialRevoked)
	}

	if enabled == 0 {
		return nil, fmt.Errorf("principal disabled: %w", ErrCredentialDisabled)
	}

	// Fetch allowed roots for the principal.
	rows, err := db.Query(
		`SELECT root_path FROM principal_allowed_roots
		 WHERE principal_id = ?
		 ORDER BY root_path`,
		principalID,
	)
	if err != nil {
		return nil, fmt.Errorf("cannot query allowed roots: %w", err)
	}
	defer rows.Close()

	roots := []string{}
	for rows.Next() {
		var rootPath string
		if err := rows.Scan(&rootPath); err != nil {
			return nil, fmt.Errorf("cannot scan allowed root: %w", err)
		}
		roots = append(roots, rootPath)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate allowed roots: %w", err)
	}

	return &CredentialAuthResult{
		PrincipalID:   principalID,
		PrincipalName: principalName,
		CredentialID:  credID,
		AllowedRoots:  roots,
	}, nil
}
