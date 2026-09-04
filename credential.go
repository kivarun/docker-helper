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
	PrincipalName string
}

// credentialToken* define the single internal credential token format: a
// random 32-byte (256-bit) entropy value, lowercase-hex encoded and prefixed
// with "dhc_". The same bearer format is used for Principal and Launcher
// credentials; the concrete owner is determined from persistent state, never
// from a bearer prefix. The generator and the install-time validator both
// consume this definition.
const (
	credentialTokenPrefix       = "dhc_"
	credentialTokenEntropyBytes = 32
	credentialTokenHexLen       = credentialTokenEntropyBytes * 2
	credentialTokenTotalLen     = len(credentialTokenPrefix) + credentialTokenHexLen
)

// generateCredentialToken returns a random 32-byte hex token prefixed with "dhc_".
func generateCredentialToken() (string, error) {
	b := make([]byte, credentialTokenEntropyBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("cannot generate random bytes: %w", err)
	}
	return credentialTokenPrefix + hex.EncodeToString(b), nil
}

// generateCredentialTokenFn is a narrow test seam for credential token
// generation, matching the package's existing seam style (for example
// OSUserLookup). Production always calls generateCredentialToken.
var generateCredentialTokenFn = generateCredentialToken

// insertPrincipalCredentialInTx inserts a Principal credential within the given
// transaction, participating in an atomic multi-row operation. It returns the
// credential metadata and its bearer secret exactly once.
func insertPrincipalCredentialInTx(tx *sql.Tx, principalID int64, principalName, name string) (*CredentialWithPrincipal, string, error) {
	if name == "" {
		return nil, "", fmt.Errorf("credential name is required: %w", ErrInvalidCredentialName)
	}
	token, err := generateCredentialTokenFn()
	if err != nil {
		return nil, "", err
	}
	tokenHash := hashCredentialToken(token)
	credID, err := generateCredentialID()
	if err != nil {
		return nil, "", err
	}
	now := time.Now().Unix()

	_, err = tx.Exec(
		`INSERT INTO credentials (id, principal_id, launcher_id, name, token_hash, created_at)
		 VALUES (?, ?, NULL, ?, ?, ?)`,
		credID, principalID, name, tokenHash, now,
	)
	if err != nil {
		if isSQLiteUniqueError(err) {
			return nil, "", fmt.Errorf("credential %q already exists for principal %q: %w", name, principalName, ErrCredentialExists)
		}
		return nil, "", fmt.Errorf("cannot create credential: %w", err)
	}

	return &CredentialWithPrincipal{
		Credential: Credential{
			ID:        credID,
			Name:      name,
			CreatedAt: time.Unix(now, 0),
		},
		PrincipalName: principalName,
	}, token, nil
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

	principalID, err := findPrincipalIDByUsername(db, username)
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
		PrincipalName: username,
	}, token, nil
}

func listCredentials(db *sql.DB, username string) ([]CredentialWithPrincipal, error) {
	principalID, err := findPrincipalIDByUsername(db, username)
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
			Credential:    c,
			PrincipalName: username,
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
		Credential:    c,
		PrincipalName: username,
	}, nil
}

func revokeCredential(db *sql.DB, id string) (bool, error) {
	if id == "" {
		return false, fmt.Errorf("credential id is required: %w", ErrCredentialNotFound)
	}

	// Atomic update: only set revoked_at if it's currently NULL and the
	// credential is Principal-owned (principal_id IS NOT NULL). Launcher
	// credentials are excluded by that ownership predicate, so a Launcher
	// credential ID behaves as an unknown credential (ErrCredentialNotFound)
	// and remains byte-for-byte unchanged in the database.
	now := time.Now().Unix()
	result, err := db.Exec(
		`UPDATE credentials SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL AND principal_id IS NOT NULL`,
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
		// Check whether a Principal-owned credential exists at all, using the
		// same Principal-ownership predicate as the mutation.
		var exists int
		err = db.QueryRow(`SELECT COUNT(*) FROM credentials WHERE id = ? AND principal_id IS NOT NULL`, id).Scan(&exists)
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

// rotatePrincipalCredential atomically replaces the bearer secret of the
// named Principal credential: the credential ID, name, and Principal ownership
// are unchanged, the old token is immediately invalid, and the new secret is
// returned exactly once. No second credential row is created and there is no
// overlapping validity window: the row's token hash is replaced within one
// transaction. Fails with ErrCredentialNotFound when the principal has no
// credential with that name, and ErrCredentialRevoked when the named
// credential is already revoked (its token is already invalid; rotating it
// would not resurrect it).
func rotatePrincipalCredential(db *sql.DB, username, name string) (*CredentialWithPrincipal, string, error) {
	tx, err := db.Begin()
	if err != nil {
		return nil, "", fmt.Errorf("cannot begin transaction: %w", err)
	}
	defer tx.Rollback()

	var credID string
	var principalID int
	var principalName string
	var createdAt int64
	var revokedAt sql.NullInt64
	err = tx.QueryRow(
		`SELECT c.id, c.created_at, c.revoked_at, p.id, p.username
		 FROM credentials c
		 JOIN principals p ON p.id = c.principal_id
		 WHERE p.username = ? AND c.name = ?
		   AND c.principal_id IS NOT NULL AND c.launcher_id IS NULL`,
		username, name,
	).Scan(&credID, &createdAt, &revokedAt, &principalID, &principalName)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, "", fmt.Errorf("credential %q not found for principal %q: %w", name, username, ErrCredentialNotFound)
		}
		return nil, "", fmt.Errorf("cannot find credential: %w", err)
	}
	if revokedAt.Valid {
		return nil, "", fmt.Errorf("credential %q is revoked: %w", name, ErrCredentialRevoked)
	}

	token, err := generateCredentialToken()
	if err != nil {
		return nil, "", err
	}
	newHash := hashCredentialToken(token)

	// Update the SAME row: ID, name, and owner unchanged, token hash atomically
	// replaced. The ownership predicate mirrors the lookup above.
	result, err := tx.Exec(
		`UPDATE credentials SET token_hash = ?
		 WHERE id = ? AND principal_id = ? AND launcher_id IS NULL`,
		newHash, credID, principalID,
	)
	if err != nil {
		return nil, "", fmt.Errorf("cannot rotate credential: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return nil, "", fmt.Errorf("cannot check rotate result: %w", err)
	}
	if affected == 0 {
		return nil, "", fmt.Errorf("credential %q not found for principal %q: %w", name, username, ErrCredentialNotFound)
	}

	if err := tx.Commit(); err != nil {
		return nil, "", fmt.Errorf("cannot commit credential rotation: %w", err)
	}

	return &CredentialWithPrincipal{
		Credential: Credential{
			ID:        credID,
			Name:      name,
			CreatedAt: time.Unix(createdAt, 0),
		},
		PrincipalName: principalName,
	}, token, nil
}

// ErrPrincipalDisabled is returned when the credential's owning Principal is disabled.
var ErrPrincipalDisabled = errors.New("principal disabled")

// ErrCredentialRevoked is returned when the credential has been revoked.
var ErrCredentialRevoked = errors.New("credential revoked")

// ErrLauncherDisabled is returned when a Launcher credential's owning Launcher
// is disabled.
var ErrLauncherDisabled = errors.New("launcher disabled")

// PrincipalCredentialAuth contains the information needed to authorize a principal request.
type PrincipalCredentialAuth struct {
	PrincipalID           int64
	PrincipalName         string
	CredentialID          string
	PrincipalAllowedRoots []string
}

// LauncherCredentialAuth contains the information needed to authorize a
// Launcher credential. It carries only narrow provenance/authorization fields:
// the owning Launcher, the credential, and the derived owning Principal. A
// Launcher credential is NOT yet authorized for Session control in this stage.
type LauncherCredentialAuth struct {
	LauncherID    string
	CredentialID  string
	PrincipalID   int64
	PrincipalName string
	LauncherName  string
}

// credentialAuthResult is the discriminated result of a single credential
// token lookup. Exactly one of Principal or Launcher is set, determined from
// persistent state. It is authentication plumbing only, not a generic domain
// Owner hierarchy.
type credentialAuthResult struct {
	Principal *PrincipalCredentialAuth
	Launcher  *LauncherCredentialAuth
}

// authenticateCredential determines the concrete owner of a bearer token from
// persistent state in a single token lookup. Returns the discriminated result
// on success.
// Returns ErrCredentialNotFound for unknown token.
// Returns ErrCredentialRevoked for revoked credentials.
// Returns ErrPrincipalDisabled for disabled principals.
// Returns ErrLauncherDisabled for disabled Launchers.
func authenticateCredential(db *sql.DB, token string) (*credentialAuthResult, error) {
	tokenHash := hashCredentialToken(token)

	var credID string
	var principalID sql.NullInt64
	var launcherID sql.NullString
	var revokedAt sql.NullInt64
	row := db.QueryRow(
		`SELECT c.id, c.principal_id, c.launcher_id, c.revoked_at
		 FROM credentials c
		 WHERE c.token_hash = ?`,
		tokenHash,
	)
	err := row.Scan(&credID, &principalID, &launcherID, &revokedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("credential not found: %w", ErrCredentialNotFound)
		}
		return nil, fmt.Errorf("cannot authenticate credential: %w", err)
	}

	if revokedAt.Valid {
		return nil, fmt.Errorf("credential revoked: %w", ErrCredentialRevoked)
	}

	// A non-null launcher_id means the concrete owner is a Launcher.
	if launcherID.Valid {
		return authenticateLauncherCredentialOwner(db, credID, launcherID.String)
	}

	// Otherwise the concrete owner is a Principal (principal_id IS NOT NULL per
	// the concrete-owner CHECK).
	if !principalID.Valid {
		return nil, fmt.Errorf("credential not found: %w", ErrCredentialNotFound)
	}
	return authenticatePrincipalCredentialOwner(db, credID, principalID.Int64)
}

// authenticatePrincipalCredentialOwner completes authentication for a
// Principal-owned credential, preserving the existing Principal credential
// semantics including allowed roots.
func authenticatePrincipalCredentialOwner(db *sql.DB, credID string, principalID int64) (*credentialAuthResult, error) {
	var principalName string
	var enabled int
	err := db.QueryRow(
		`SELECT username, enabled FROM principals WHERE id = ?`,
		principalID,
	).Scan(&principalName, &enabled)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("principal not found: %w", ErrCredentialNotFound)
		}
		return nil, fmt.Errorf("cannot authenticate credential: %w", err)
	}
	if enabled == 0 {
		return nil, ErrPrincipalDisabled
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

	principalAllowedRoots := []string{}
	for rows.Next() {
		var rootPath string
		if err := rows.Scan(&rootPath); err != nil {
			return nil, fmt.Errorf("cannot scan allowed root: %w", err)
		}
		principalAllowedRoots = append(principalAllowedRoots, rootPath)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate allowed roots: %w", err)
	}

	return &credentialAuthResult{
		Principal: &PrincipalCredentialAuth{
			PrincipalID:           principalID,
			PrincipalName:         principalName,
			CredentialID:          credID,
			PrincipalAllowedRoots: principalAllowedRoots,
		},
	}, nil
}

// authenticateLauncherCredentialOwner completes authentication for a
// Launcher-owned credential.
func authenticateLauncherCredentialOwner(db *sql.DB, credID, launcherID string) (*credentialAuthResult, error) {
	var launcherName string
	var launcherEnabled int
	var principalID int64
	var principalName string
	var principalEnabled int
	err := db.QueryRow(
		`SELECT l.name, l.enabled, l.principal_id, p.username, p.enabled
		 FROM launchers l
		 JOIN principals p ON p.id = l.principal_id
		 WHERE l.id = ?`,
		launcherID,
	).Scan(&launcherName, &launcherEnabled, &principalID, &principalName, &principalEnabled)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// Launcher deleted/missing: cannot authenticate. Returned
			// non-disclosing, the same as an unknown token.
			return nil, fmt.Errorf("credential not found: %w", ErrCredentialNotFound)
		}
		return nil, fmt.Errorf("cannot authenticate credential: %w", err)
	}
	if launcherEnabled == 0 {
		return nil, ErrLauncherDisabled
	}
	if principalEnabled == 0 {
		return nil, ErrPrincipalDisabled
	}
	return &credentialAuthResult{
		Launcher: &LauncherCredentialAuth{
			LauncherID:    launcherID,
			CredentialID:  credID,
			PrincipalID:   principalID,
			PrincipalName: principalName,
			LauncherName:  launcherName,
		},
	}, nil
}
