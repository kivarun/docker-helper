package main

import (
	"database/sql"
	"errors"
	"fmt"
	"os/user"
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

func createPrincipal(db *sql.DB, username string) (*PrincipalWithRoots, error) {
	if username == "" {
		return nil, fmt.Errorf("username is required: %w", ErrPrincipalNotFound)
	}

	uid, gid, home, err := resolveOSUser(username)
	if err != nil {
		return nil, err
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
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return nil, fmt.Errorf("principal %q already exists: %w", username, ErrPrincipalExists)
		}
		return nil, fmt.Errorf("cannot create principal: %w", err)
	}

	_, err = tx.Exec(
		`INSERT INTO principal_allowed_roots (principal_username, root_path)
		 VALUES (?, ?)`,
		username, home,
	)
	if err != nil {
		return nil, fmt.Errorf("cannot add default allowed root: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("cannot commit principal creation: %w", err)
	}

	_ = result

	return findPrincipalByUserName(db, username)
}

func findPrincipalByUserName(db *sql.DB, username string) (*PrincipalWithRoots, error) {
	if username == "" {
		return nil, fmt.Errorf("username is required: %w", ErrPrincipalNotFound)
	}

	var p Principal
	var enabled int
	row := db.QueryRow(
		`SELECT username, uid, gid, home, enabled FROM principals WHERE username = ? COLLATE NOCASE`,
		username,
	)
	err := row.Scan(&p.Username, &p.UID, &p.GID, &p.Home, &enabled)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("principal %q not found: %w", username, ErrPrincipalNotFound)
		}
		return nil, fmt.Errorf("cannot find principal: %w", err)
	}
	p.Enabled = enabled != 0

	rows, err := db.Query(
		`SELECT root_path FROM principal_allowed_roots
		 WHERE principal_username = ? COLLATE NOCASE
		 ORDER BY root_path`,
		p.Username,
	)
	if err != nil {
		return nil, fmt.Errorf("cannot query allowed roots: %w", err)
	}
	defer rows.Close()

	var roots []string
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

	if roots == nil {
		roots = []string{}
	}

	return &PrincipalWithRoots{
		Principal:    p,
		AllowedRoots: roots,
	}, nil
}

func updatePrincipalEnabled(db *sql.DB, username string, enabled bool) (bool, error) {
	if username == "" {
		return false, fmt.Errorf("username is required: %w", ErrPrincipalNotFound)
	}

	var currentEnabled int
	row := db.QueryRow(
		`SELECT enabled FROM principals WHERE username = ? COLLATE NOCASE`,
		username,
	)
	err := row.Scan(&currentEnabled)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, fmt.Errorf("principal %q not found: %w", username, ErrPrincipalNotFound)
		}
		return false, fmt.Errorf("cannot find principal: %w", err)
	}

	current := currentEnabled != 0
	if current == enabled {
		return false, nil
	}

	newEnabled := 0
	if enabled {
		newEnabled = 1
	}

	_, err = db.Exec(
		`UPDATE principals SET enabled = ? WHERE username = ? COLLATE NOCASE`,
		newEnabled, username,
	)
	if err != nil {
		return false, fmt.Errorf("cannot update principal enabled: %w", err)
	}

	return true, nil
}

func addAllowedRoot(db *sql.DB, username string, rootPath string) (bool, error) {
	if username == "" {
		return false, fmt.Errorf("username is required: %w", ErrPrincipalNotFound)
	}
	if rootPath == "" {
		return false, fmt.Errorf("path is required: %w", ErrInvalidAllowedRoot)
	}

	resolved, err := resolveAllowedRoot(rootPath)
	if err != nil {
		return false, fmt.Errorf("invalid path %q: %w", rootPath, ErrInvalidAllowedRoot)
	}

	row := db.QueryRow(
		`SELECT 1 FROM principals WHERE username = ? COLLATE NOCASE`,
		username,
	)
	if err := row.Scan(new(int)); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, fmt.Errorf("principal %q not found: %w", username, ErrPrincipalNotFound)
		}
		return false, fmt.Errorf("cannot find principal: %w", err)
	}

	result, err := db.Exec(
		`INSERT OR IGNORE INTO principal_allowed_roots (principal_username, root_path)
		 VALUES (?, ?)`,
		username, resolved,
	)
	if err != nil {
		return false, fmt.Errorf("cannot add allowed root: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("cannot check insert result: %w", err)
	}

	changed := affected > 0
	return changed, nil
}

func removeAllowedRoot(db *sql.DB, username string, rootPath string) (bool, error) {
	if username == "" {
		return false, fmt.Errorf("username is required: %w", ErrPrincipalNotFound)
	}
	if rootPath == "" {
		return false, fmt.Errorf("path is required: %w", ErrInvalidAllowedRoot)
	}

	resolved, err := resolveAllowedRoot(rootPath)
	if err != nil {
		return false, fmt.Errorf("invalid path %q: %w", rootPath, ErrInvalidAllowedRoot)
	}

	row := db.QueryRow(
		`SELECT 1 FROM principals WHERE username = ? COLLATE NOCASE`,
		username,
	)
	if err := row.Scan(new(int)); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, fmt.Errorf("principal %q not found: %w", username, ErrPrincipalNotFound)
		}
		return false, fmt.Errorf("cannot find principal: %w", err)
	}

	result, err := db.Exec(
		`DELETE FROM principal_allowed_roots
		 WHERE principal_username = ? COLLATE NOCASE AND root_path = ?`,
		username, resolved,
	)
	if err != nil {
		return false, fmt.Errorf("cannot remove allowed root: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("cannot check delete result: %w", err)
	}

	changed := affected > 0
	return changed, nil
}
