package main

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ErrLauncherCredentialNotFound is returned when a Launcher has no credential.
var ErrLauncherCredentialNotFound = errors.New("launcher credential not found")

// ErrLauncherCredentialExists is returned when a Launcher already has its one
// singular credential.
var ErrLauncherCredentialExists = errors.New("launcher credential already exists")

// launcherCredential is the metadata of a Launcher's singular credential. A
// Launcher credential has no business name (the stable identity belongs to the
// Launcher); it is never exposed with its secret or token hash.
type launcherCredential struct {
	ID        string
	CreatedAt time.Time
	RevokedAt *time.Time
}

// issueLauncherCredentialInTx inserts the singular Launcher credential (owner
// launcher_id, name NULL, principal_id NULL) within the given transaction and
// returns its metadata and bearer secret exactly once.
func issueLauncherCredentialInTx(tx *sql.Tx, launcherID string) (*launcherCredential, string, error) {
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
		 VALUES (?, NULL, ?, NULL, ?, ?)`,
		credID, launcherID, tokenHash, now,
	)
	if err != nil {
		if isSQLiteUniqueError(err) {
			return nil, "", fmt.Errorf("launcher already has a credential: %w", ErrLauncherCredentialExists)
		}
		return nil, "", fmt.Errorf("cannot issue launcher credential: %w", err)
	}

	return &launcherCredential{ID: credID, CreatedAt: time.Unix(now, 0)}, token, nil
}

// issueLauncherCredential creates the singular Launcher credential for an
// existing Launcher. It fails with ErrLauncherCredentialExists if one already
// exists, and ErrLauncherNotFound if the Launcher is absent.
func issueLauncherCredential(db *sql.DB, launcherID string) (*launcherCredential, string, error) {
	tx, err := db.Begin()
	if err != nil {
		return nil, "", fmt.Errorf("cannot begin transaction: %w", err)
	}
	defer tx.Rollback()

	var exists int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM launchers WHERE id = ?`, launcherID).Scan(&exists); err != nil {
		return nil, "", fmt.Errorf("cannot check launcher: %w", err)
	}
	if exists == 0 {
		return nil, "", ErrLauncherNotFound
	}

	cred, token, err := issueLauncherCredentialInTx(tx, launcherID)
	if err != nil {
		return nil, "", err
	}

	if err := tx.Commit(); err != nil {
		return nil, "", fmt.Errorf("cannot commit launcher credential issue: %w", err)
	}
	return cred, token, nil
}

// scanLauncherCredential scans the singular Launcher credential columns
// (id, created_at, revoked_at); a missing row is ErrLauncherCredentialNotFound.
func scanLauncherCredential(s sqlScanner) (*launcherCredential, error) {
	var c launcherCredential
	var createdAt int64
	var revokedAt sql.NullInt64
	if err := s.Scan(&c.ID, &createdAt, &revokedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrLauncherCredentialNotFound
		}
		return nil, fmt.Errorf("cannot find launcher credential: %w", err)
	}
	c.CreatedAt = time.Unix(createdAt, 0)
	if revokedAt.Valid {
		t := time.Unix(revokedAt.Int64, 0)
		c.RevokedAt = &t
	}
	return &c, nil
}

// findLauncherCredential returns the metadata of a Launcher's singular
// credential, or ErrLauncherCredentialNotFound if none exists.
func findLauncherCredential(db *sql.DB, launcherID string) (*launcherCredential, error) {
	return scanLauncherCredential(db.QueryRow(
		`SELECT id, created_at, revoked_at FROM credentials WHERE launcher_id = ?`,
		launcherID,
	))
}

// prepareLauncherCredentialRotation resolves the singular Launcher credential,
// optionally requiring the exact authenticated credential ID, captures its
// current bearer hash as the CAS expectation, and generates the one-time
// replacement bearer. It performs no mutation.
func prepareLauncherCredentialRotation(
	db *sql.DB,
	launcherID string,
	expectedCredentialID string,
) (*launcherCredential, string, string, string, error) {
	var credID string
	var createdAt int64
	var revokedAt sql.NullInt64
	var currentHash string
	var err error

	if expectedCredentialID == "" {
		err = db.QueryRow(
			`SELECT id, created_at, revoked_at, token_hash
			 FROM credentials
			 WHERE launcher_id = ?`,
			launcherID,
		).Scan(&credID, &createdAt, &revokedAt, &currentHash)
	} else {
		err = db.QueryRow(
			`SELECT id, created_at, revoked_at, token_hash
			 FROM credentials
			 WHERE id = ? AND launcher_id = ?`,
			expectedCredentialID, launcherID,
		).Scan(&credID, &createdAt, &revokedAt, &currentHash)
	}
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, "", "", "", ErrLauncherCredentialNotFound
		}
		return nil, "", "", "", fmt.Errorf("cannot find launcher credential: %w", err)
	}

	token, err := generateCredentialTokenFn()
	if err != nil {
		return nil, "", "", "", err
	}
	newHash := hashCredentialToken(token)

	cred := &launcherCredential{ID: credID, CreatedAt: time.Unix(createdAt, 0)}
	if revokedAt.Valid {
		t := time.Unix(revokedAt.Int64, 0)
		cred.RevokedAt = &t
	}
	return cred, currentHash, token, newHash, nil
}

// replaceLauncherCredentialTokenHashInTx performs the exact Launcher
// credential CAS inside the caller's transaction. The stable Launcher ID,
// credential ID, active state, and prepared token hash must all still match.
func replaceLauncherCredentialTokenHashInTx(
	tx *sql.Tx,
	launcherID string,
	credentialID string,
	expectedHash string,
	newHash string,
) error {
	result, err := tx.Exec(
		`UPDATE credentials SET token_hash = ?
		 WHERE id = ? AND launcher_id = ?
		   AND revoked_at IS NULL AND token_hash = ?`,
		newHash, credentialID, launcherID, expectedHash,
	)
	if err != nil {
		return fmt.Errorf("cannot rotate launcher credential: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("cannot check launcher credential rotation result: %w", err)
	}
	if affected == 0 {
		return fmt.Errorf("launcher credential %q changed during rotation: %w", credentialID, ErrCredentialRotationConflict)
	}
	return nil
}

// commitLauncherCredentialRotationAfterDelivery applies the prepared Launcher
// credential replacement through the shared DB-backed rotation
// transaction/delivery owner.
func commitLauncherCredentialRotationAfterDelivery(
	db *sql.DB,
	launcherID string,
	credentialID string,
	expectedHash string,
	newHash string,
	deliver func() error,
) error {
	return commitCredentialRotationAfterDelivery(
		db,
		func(tx *sql.Tx) error {
			return replaceLauncherCredentialTokenHashInTx(tx, launcherID, credentialID, expectedHash, newHash)
		},
		deliver,
	)
}

// rotateLauncherCredential atomically replaces the bearer secret of the same
// logical Launcher credential for non-HTTP callers. The HTTP handlers use the
// prepare + commit-after-delivery path directly so response delivery is part of
// the rotation contract.
func rotateLauncherCredential(db *sql.DB, launcherID string) (*launcherCredential, string, error) {
	return rotateLauncherCredentialTargeted(db, launcherID, "")
}

// rotateLauncherCredentialExact preserves exact credential-ID targeting for
// non-HTTP callers while using the same canonical DB-backed rotation owner.
func rotateLauncherCredentialExact(db *sql.DB, launcherID, expectedCredentialID string) (*launcherCredential, string, error) {
	return rotateLauncherCredentialTargeted(db, launcherID, expectedCredentialID)
}

func rotateLauncherCredentialTargeted(db *sql.DB, launcherID, expectedCredentialID string) (*launcherCredential, string, error) {
	cred, expectedHash, token, newHash, err := prepareLauncherCredentialRotation(db, launcherID, expectedCredentialID)
	if err != nil {
		return nil, "", err
	}
	if err := commitLauncherCredentialRotationAfterDelivery(
		db,
		launcherID,
		cred.ID,
		expectedHash,
		newHash,
		func() error { return nil },
	); err != nil {
		return nil, "", err
	}
	return cred, token, nil
}

// deleteLauncherCredential deletes the singular Launcher credential so a new
// one may later be issued, and returns the deleted credential's metadata so
// the caller can record exactly which target credential was revoked. Fails
// with ErrLauncherCredentialNotFound if none exists. This is a physical
// delete, not a revoked_at mutation.
func deleteLauncherCredential(db *sql.DB, launcherID string) (*launcherCredential, error) {
	tx, err := db.Begin()
	if err != nil {
		return nil, fmt.Errorf("cannot begin transaction: %w", err)
	}
	defer tx.Rollback()

	cred, err := scanLauncherCredential(tx.QueryRow(
		`SELECT id, created_at, revoked_at FROM credentials WHERE launcher_id = ?`,
		launcherID,
	))
	if err != nil {
		return nil, err
	}

	result, err := tx.Exec(`DELETE FROM credentials WHERE launcher_id = ?`, launcherID)
	if err != nil {
		return nil, fmt.Errorf("cannot delete launcher credential: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("cannot check delete result: %w", err)
	}
	if affected == 0 {
		return nil, ErrLauncherCredentialNotFound
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("cannot commit launcher credential delete: %w", err)
	}
	return cred, nil
}
