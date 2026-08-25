package main

import (
	"database/sql"
	"errors"
	"fmt"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

var (
	ErrPrincipalNotFound  = errors.New("principal not found")
	ErrPrincipalExists    = errors.New("principal already exists")
	ErrOSUserNotFound     = errors.New("OS user not found")
	ErrInvalidAllowedRoot = errors.New("invalid allowed root")
)

type Principal struct {
	ID       int
	Username string
	UID      int
	GID      int
	Home     string
	Enabled  bool
}

type PrincipalWithRoots struct {
	Principal
	AllowedRoots []string
}

// OSUserLookup can be replaced in tests.
var OSUserLookup = func(username string) (uid, gid, home string, err error) {
	u, err := user.Lookup(username)
	if err != nil {
		return "", "", "", err
	}
	return u.Uid, u.Gid, u.HomeDir, nil
}

func resolveOSUser(username string) (uid int, gid int, home string, err error) {
	uStr, gStr, homeDir, err := OSUserLookup(username)
	if err != nil {
		return 0, 0, "", fmt.Errorf("OS user %q not found: %w", username, ErrOSUserNotFound)
	}
	uid64, err := strconv.ParseInt(uStr, 10, 64)
	if err != nil {
		return 0, 0, "", fmt.Errorf("invalid UID %q: %w", uStr, ErrOSUserNotFound)
	}
	gid64, err := strconv.ParseInt(gStr, 10, 64)
	if err != nil {
		return 0, 0, "", fmt.Errorf("invalid GID %q: %w", gStr, ErrOSUserNotFound)
	}
	return int(uid64), int(gid64), homeDir, nil
}

// validatePrincipalAllowedRootForAdd validates a path for adding to a
// Principal's allowed-root scope.
// Requires: absolute, no tilde, exists, is directory.
// Applies the workspace-path policy.
// Returns the canonical path.
func validatePrincipalAllowedRootForAdd(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("path is required: %w", ErrInvalidAllowedRoot)
	}
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("path must be absolute: %w", ErrInvalidAllowedRoot)
	}
	// Reject tilde prefix explicitly
	if len(path) > 1 && path[0] == '~' {
		return "", fmt.Errorf("tilde expansion not supported; use absolute path: %w", ErrInvalidAllowedRoot)
	}

	cleaned, err := canonicalizeWorkspacePathForAdd(path)
	if err != nil {
		return "", fmt.Errorf("%s: %w", err.Error(), ErrInvalidAllowedRoot)
	}
	return cleaned, nil
}

// findPrincipalByID looks up a principal by its internal ID.
func findPrincipalByID(db *sql.DB, id int) (*Principal, error) {
	var p Principal
	var enabled int
	row := db.QueryRow(
		`SELECT id, username, uid, gid, home, enabled FROM principals WHERE id = ?`,
		id,
	)
	err := row.Scan(&p.ID, &p.Username, &p.UID, &p.GID, &p.Home, &enabled)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrPrincipalNotFound
		}
		return nil, fmt.Errorf("cannot find principal: %w", err)
	}
	p.Enabled = enabled != 0
	return &p, nil
}

// findPrincipalIDByUserName resolves a username to its principal ID.
func findPrincipalIDByUserName(db *sql.DB, username string) (int, error) {
	if username == "" {
		return 0, fmt.Errorf("username is required: %w", ErrPrincipalNotFound)
	}
	var id int
	row := db.QueryRow(
		`SELECT id FROM principals WHERE username = ?`,
		username,
	)
	err := row.Scan(&id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, fmt.Errorf("principal %q not found: %w", username, ErrPrincipalNotFound)
		}
		return 0, fmt.Errorf("cannot find principal: %w", err)
	}
	return id, nil
}

// ErrPrincipalRootOutsideGlobal is returned when a principal root is outside global roots.
var ErrPrincipalRootOutsideGlobal = errors.New("principal root outside global allowed roots")

func createPrincipal(db *sql.DB, username string, globalAllowedRoots []string) (*PrincipalWithRoots, error) {
	if username == "" {
		return nil, fmt.Errorf("username is required: %w", ErrPrincipalNotFound)
	}

	uid, gid, home, err := resolveOSUser(username)
	if err != nil {
		return nil, err
	}

	if home == "" || !filepath.IsAbs(home) {
		return nil, fmt.Errorf("OS user %q has invalid home %q: must be an absolute path", username, home)
	}

	// Canonicalize the home directory and apply the workspace root policy.
	canonicalHome, err := canonicalizeWorkspacePathForAdd(home)
	if err != nil {
		return nil, fmt.Errorf("OS user %q home directory %q is not a valid workspace root: %s", username, home, err)
	}

	// Validate the home directory is under at least one global allowed root.
	if !isWithinAnyAllowedRoot(canonicalHome, globalAllowedRoots) {
		return nil, fmt.Errorf("OS user %q home directory %q is not under any global allowed root: %w", username, canonicalHome, ErrPrincipalRootOutsideGlobal)
	}

	tx, err := db.Begin()
	if err != nil {
		return nil, fmt.Errorf("cannot begin transaction: %w", err)
	}
	defer tx.Rollback()

	result, err := tx.Exec(
		`INSERT INTO principals (username, uid, gid, home, enabled)
		 VALUES (?, ?, ?, ?, 1)`,
		username, uid, gid, home,
	)
	if err != nil {
		if isSQLiteUniqueError(err) {
			return nil, fmt.Errorf("principal %q already exists: %w", username, ErrPrincipalExists)
		}
		return nil, fmt.Errorf("cannot create principal: %w", err)
	}

	principalID, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("cannot get principal ID: %w", err)
	}

	if _, err := tx.Exec(
		`INSERT INTO principal_allowed_roots (principal_id, root_path)
		 VALUES (?, ?)`,
		principalID, canonicalHome,
	); err != nil {
		return nil, fmt.Errorf("cannot add default allowed root: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("cannot commit principal creation: %w", err)
	}

	return findPrincipalByUserName(db, username)
}

func findPrincipalByUserName(db *sql.DB, username string) (*PrincipalWithRoots, error) {
	if username == "" {
		return nil, fmt.Errorf("username is required: %w", ErrPrincipalNotFound)
	}

	principalID, err := findPrincipalIDByUserName(db, username)
	if err != nil {
		return nil, err
	}

	p, err := findPrincipalByID(db, principalID)
	if err != nil {
		return nil, err
	}

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

	return &PrincipalWithRoots{
		Principal:    *p,
		AllowedRoots: roots,
	}, nil
}

// persistPrincipalEnabledChange performs a transactionally correct enabled-state
// transition for a principal. It:
//   - determines Principal existence and current enabled state within the transaction;
//   - if already in the requested state, returns Changed=false;
//   - updates enabled state;
//   - when disabling, collects and deletes the Principal's sessions;
//   - commits;
//   - returns explicit Changed and RevokedSessionIDs.
func persistPrincipalEnabledChange(db *sql.DB, username string, enabled bool) (principalEnabledChangeResult, error) {
	if username == "" {
		return principalEnabledChangeResult{}, fmt.Errorf("username is required: %w", ErrPrincipalNotFound)
	}

	tx, err := db.Begin()
	if err != nil {
		return principalEnabledChangeResult{}, fmt.Errorf("cannot begin transaction: %w", err)
	}

	principalID, err := findPrincipalIDByUserNameInTx(tx, username)
	if err != nil {
		tx.Rollback()
		return principalEnabledChangeResult{}, err
	}

	// Determine current enabled state within the transaction.
	var currentEnabled int
	err = tx.QueryRow(`SELECT enabled FROM principals WHERE id = ?`, principalID).Scan(&currentEnabled)
	if err != nil {
		tx.Rollback()
		return principalEnabledChangeResult{}, fmt.Errorf("cannot read principal enabled state: %w", err)
	}

	newEnabled := 0
	if enabled {
		newEnabled = 1
	}

	// Already in requested state.
	if currentEnabled == newEnabled {
		tx.Rollback()
		return principalEnabledChangeResult{Changed: false}, nil
	}

	_, err = tx.Exec(
		`UPDATE principals SET enabled = ? WHERE id = ?`,
		newEnabled, principalID,
	)
	if err != nil {
		tx.Rollback()
		return principalEnabledChangeResult{}, fmt.Errorf("cannot update principal enabled: %w", err)
	}

	var sessionIDs []string
	if !enabled {
		// Collect session IDs before deletion for runtime cleanup.
		rows, err := tx.Query(`SELECT id FROM sessions WHERE principal_id = ?`, principalID)
		if err != nil {
			tx.Rollback()
			return principalEnabledChangeResult{}, fmt.Errorf("cannot query principal sessions: %w", err)
		}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				tx.Rollback()
				return principalEnabledChangeResult{}, fmt.Errorf("cannot scan session id: %w", err)
			}
			sessionIDs = append(sessionIDs, id)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			tx.Rollback()
			return principalEnabledChangeResult{}, fmt.Errorf("iterate sessions: %w", err)
		}
		rows.Close()

		_, err = tx.Exec(
			`DELETE FROM sessions WHERE principal_id = ?`,
			principalID,
		)
		if err != nil {
			tx.Rollback()
			return principalEnabledChangeResult{}, fmt.Errorf("cannot delete principal sessions: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return principalEnabledChangeResult{}, fmt.Errorf("cannot commit enabled change: %w", err)
	}

	return principalEnabledChangeResult{
		Changed:           true,
		RevokedSessionIDs: sessionIDs,
	}, nil
}

// isWithinAnyAllowedRoot returns true if path is equal to or under at least one allowed root.
func isWithinAnyAllowedRoot(path string, allowedRoots []string) bool {
	for _, r := range allowedRoots {
		if path == r || pathWithin(r, path) {
			return true
		}
	}
	return false
}

// addPrincipalAllowedRoot adds an allowed root to a Principal's scope.
// The root must be contained within the global allowed-root ceiling.
func addPrincipalAllowedRoot(db *sql.DB, username string, rootPath string, globalAllowedRoots []string) (changed bool, canonicalPath string, err error) {
	if username == "" {
		return false, "", fmt.Errorf("username is required: %w", ErrPrincipalNotFound)
	}

	resolved, err := validatePrincipalAllowedRootForAdd(rootPath)
	if err != nil {
		return false, "", err
	}

	// Validate the root is under at least one global allowed root.
	if !isWithinAnyAllowedRoot(resolved, globalAllowedRoots) {
		return false, "", fmt.Errorf("path %q is not under any global allowed root: %w", resolved, ErrPrincipalRootOutsideGlobal)
	}

	principalID, err := findPrincipalIDByUserName(db, username)
	if err != nil {
		return false, "", err
	}

	result, err := db.Exec(
		`INSERT OR IGNORE INTO principal_allowed_roots (principal_id, root_path)
		 VALUES (?, ?)`,
		principalID, resolved,
	)
	if err != nil {
		return false, "", fmt.Errorf("cannot add allowed root: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return false, "", fmt.Errorf("cannot check insert result: %w", err)
	}

	return affected > 0, resolved, nil
}

// removePrincipalAllowedRoot removes an allowed root from a Principal's scope.
func removePrincipalAllowedRoot(db *sql.DB, username string, rootPath string) (changed bool, canonicalPath string, err error) {
	if username == "" {
		return false, "", fmt.Errorf("username is required: %w", ErrPrincipalNotFound)
	}
	if rootPath == "" {
		return false, "", fmt.Errorf("path is required: %w", ErrInvalidAllowedRoot)
	}
	if !filepath.IsAbs(rootPath) {
		return false, "", fmt.Errorf("path must be absolute: %w", ErrInvalidAllowedRoot)
	}

	// For REMOVE, we do NOT require the path to exist on the filesystem.
	// We match against the stored canonical path.
	resolved, err := filepath.Abs(rootPath)
	if err != nil {
		return false, "", fmt.Errorf("cannot resolve path: %w: %w", err, ErrInvalidAllowedRoot)
	}
	if canonical, err := filepath.EvalSymlinks(resolved); err == nil {
		resolved = canonical
	}

	principalID, err := findPrincipalIDByUserName(db, username)
	if err != nil {
		return false, "", err
	}

	result, err := db.Exec(
		`DELETE FROM principal_allowed_roots
		 WHERE principal_id = ? AND root_path = ?`,
		principalID, resolved,
	)
	if err != nil {
		return false, "", fmt.Errorf("cannot remove allowed root: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return false, "", fmt.Errorf("cannot check delete result: %w", err)
	}

	return affected > 0, resolved, nil
}

// isSQLiteUniqueError checks if an error is a SQLite UNIQUE constraint violation.
func isSQLiteUniqueError(err error) bool {
	return strings.Contains(err.Error(), "UNIQUE constraint failed") ||
		strings.Contains(err.Error(), "unique constraint failed")
}

// listPrincipalSummaries returns all principals ordered by username,
// with only the fields exposed by GET /principals. Allowed roots are
// intentionally not loaded; use findPrincipalByUserName for full details.
func listPrincipalSummaries(db *sql.DB) ([]principalSummary, error) {
	rows, err := db.Query(
		`SELECT username, uid, gid, home, enabled FROM principals ORDER BY username`,
	)
	if err != nil {
		return nil, fmt.Errorf("cannot list principals: %w", err)
	}
	defer rows.Close()

	summaries := make([]principalSummary, 0)
	for rows.Next() {
		var s principalSummary
		var enabled int
		if err := rows.Scan(&s.Username, &s.UID, &s.GID, &s.Home, &enabled); err != nil {
			return nil, fmt.Errorf("cannot scan principal: %w", err)
		}
		s.Enabled = enabled != 0
		summaries = append(summaries, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate principals: %w", err)
	}

	return summaries, nil
}

// deletePrincipal removes a principal and all its sessions in a single transaction.
// Credentials and allowed roots are removed via FK ON DELETE CASCADE.
// Returns the session IDs that were deleted, for runtime directory cleanup.
func deletePrincipal(db *sql.DB, username string) ([]string, error) {
	tx, err := db.Begin()
	if err != nil {
		return nil, fmt.Errorf("cannot begin transaction: %w", err)
	}

	principalID, err := findPrincipalIDByUserNameInTx(tx, username)
	if err != nil {
		tx.Rollback()
		return nil, err
	}

	// Collect session IDs before deletion for runtime cleanup.
	rows, err := tx.Query(`SELECT id FROM sessions WHERE principal_id = ?`, principalID)
	if err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("cannot query principal sessions: %w", err)
	}
	var sessionIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			tx.Rollback()
			return nil, fmt.Errorf("cannot scan session id: %w", err)
		}
		sessionIDs = append(sessionIDs, id)
	}
	if err := rows.Err(); err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("iterate sessions: %w", err)
	}
	rows.Close()

	// Delete all sessions for this principal.
	// Not relying on FK cascade — sessions.principal_id has no ON DELETE CASCADE.
	_, err = tx.Exec(`DELETE FROM sessions WHERE principal_id = ?`, principalID)
	if err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("cannot delete principal sessions: %w", err)
	}

	// Delete the principal.
	// Credentials and allowed roots are removed via FK ON DELETE CASCADE.
	_, err = tx.Exec(`DELETE FROM principals WHERE id = ?`, principalID)
	if err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("cannot delete principal: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("cannot commit deletion: %w", err)
	}

	return sessionIDs, nil
}

func findPrincipalIDByUserNameInTx(tx *sql.Tx, username string) (int, error) {
	var id int
	err := tx.QueryRow(
		`SELECT id FROM principals WHERE username = ?`,
		username,
	).Scan(&id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrPrincipalNotFound
		}
		return 0, fmt.Errorf("cannot find principal: %w", err)
	}
	return id, nil
}
