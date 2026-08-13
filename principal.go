package main

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
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

// canonicalizePath resolves a path to its canonical absolute form.
// The path must already be absolute. Symlinks are resolved via EvalSymlinks.
// The path must exist and be a directory.
func canonicalizePath(path string) (string, error) {
	cleaned, err := filepath.EvalSymlinks(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("path does not exist: %s", path)
		}
		return "", fmt.Errorf("cannot resolve path: %w", err)
	}
	info, err := os.Stat(cleaned)
	if err != nil {
		return "", fmt.Errorf("cannot stat path: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("path is not a directory: %s", cleaned)
	}
	return cleaned, nil
}

// validateAllowedRootForAdd validates a path for ADD operations.
// Requires: absolute, no tilde, exists, is directory.
// Returns the canonical path.
func validateAllowedRootForAdd(path string) (string, error) {
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
	return canonicalizePath(path)
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

func createPrincipal(db *sql.DB, username string) (*PrincipalWithRoots, error) {
	if username == "" {
		return nil, fmt.Errorf("username is required: %w", ErrPrincipalNotFound)
	}

	uid, gid, home, err := resolveOSUser(username)
	if err != nil {
		return nil, err
	}

	// Canonicalize the home directory for storage as default allowed_root.
	canonicalHome, err := canonicalizePath(home)
	if err != nil {
		return nil, fmt.Errorf("cannot canonicalize home directory %q: %w", home, err)
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

func updatePrincipalEnabled(db *sql.DB, username string, enabled bool) (bool, error) {
	principalID, err := findPrincipalIDByUserName(db, username)
	if err != nil {
		return false, err
	}

	p, err := findPrincipalByID(db, principalID)
	if err != nil {
		return false, err
	}

	if p.Enabled == enabled {
		return false, nil
	}

	newEnabled := 0
	if enabled {
		newEnabled = 1
	}

	_, err = db.Exec(
		`UPDATE principals SET enabled = ? WHERE id = ?`,
		newEnabled, principalID,
	)
	if err != nil {
		return false, fmt.Errorf("cannot update principal enabled: %w", err)
	}

	return true, nil
}

func addAllowedRoot(db *sql.DB, username string, rootPath string) (changed bool, canonicalPath string, err error) {
	if username == "" {
		return false, "", fmt.Errorf("username is required: %w", ErrPrincipalNotFound)
	}

	resolved, err := validateAllowedRootForAdd(rootPath)
	if err != nil {
		return false, "", err
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

func removeAllowedRoot(db *sql.DB, username string, rootPath string) (changed bool, canonicalPath string, err error) {
	if username == "" {
		return false, "", fmt.Errorf("username is required: %w", ErrPrincipalNotFound)
	}
	if rootPath == "" {
		return false, "", fmt.Errorf("path is required: %w", ErrInvalidAllowedRoot)
	}

	// For REMOVE, we do NOT require the path to exist on the filesystem.
	// We match against the stored canonical path.
	resolved, err := filepath.Abs(rootPath)
	if err != nil {
		return false, "", fmt.Errorf("cannot resolve path: %w", err)
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
