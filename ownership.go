package main

import (
	"database/sql"
	"errors"
	"fmt"
	"os/user"
	"path/filepath"
	"time"
)

// OSUserLookupByUID resolves OS account information by numeric UID. It is a
// package-global seam injectable in tests, mirroring OSUserLookup.
var OSUserLookupByUID = func(uid int) (username, gid, home string, err error) {
	u, err := user.LookupId(fmt.Sprintf("%d", uid))
	if err != nil {
		return "", "", "", err
	}
	return u.Username, u.Gid, u.HomeDir, nil
}

// findDefaultLauncher is the read-only request-time resolver for a Principal's
// 'default' Launcher. Unlike ensureDefaultLauncher it never mutates state:
// request-time default resolution must not create Launchers.
func findDefaultLauncher(q sqlExecutor, principalID int64) (string, error) {
	var id string
	err := q.QueryRow(
		`SELECT id FROM launchers WHERE principal_id = ? AND name = 'default'`,
		principalID,
	).Scan(&id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrLauncherNotFound
		}
		return "", err
	}
	return id, nil
}

// userModeDefaultLauncher carries the resolved daemon-owner Principal and its
// 'default' inherit Launcher in user mode. It is produced once at startup by
// ensureUserModeOwnership and consumed by migrateSessionOwnership and by
// request-time default Launcher resolution. It is nil in system mode.
type userModeDefaultLauncher struct {
	principalID int64
	launcherID  string
	username    string
}

// sqlExecutor abstracts the narrow database operations used to resolve/create
// default Launchers so the same helper can run against *sql.DB (startup
// provisioning) and *sql.Tx (migration). It intentionally exposes only the
// operations this ownership path needs; it is not a generic repository.
type sqlExecutor interface {
	Exec(query string, args ...any) (sql.Result, error)
	QueryRow(query string, args ...any) *sql.Row
}

// ensureDefaultLauncher returns the ID of the given Principal's 'default'
// inherit-scope Launcher, creating it idempotently if absent. Uniqueness is
// enforced by UNIQUE(principal_id, name). This is deliberately a narrow insert
// (no roots, no credential) and does not route through createLauncher, so it
// is safe to call inside a transaction for migration.
func ensureDefaultLauncher(q sqlExecutor, principalID int64) (string, error) {
	var id string
	err := q.QueryRow(
		`SELECT id FROM launchers WHERE principal_id = ? AND name = 'default'`,
		principalID,
	).Scan(&id)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	newID, err := generateLauncherID()
	if err != nil {
		return "", err
	}
	now := time.Now().Unix()
	if _, err := q.Exec(
		`INSERT OR IGNORE INTO launchers (id, principal_id, name, enabled, scope_mode, created_at)
		 VALUES (?, ?, 'default', 1, 'inherit', ?)`,
		newID, principalID, now,
	); err != nil {
		return "", err
	}
	// A concurrent identical insert (or a prior partial run) may have won;
	// re-read the canonical row.
	err = q.QueryRow(
		`SELECT id FROM launchers WHERE principal_id = ? AND name = 'default'`,
		principalID,
	).Scan(&id)
	if err != nil {
		return "", err
	}
	return id, nil
}

// insertDaemonOwnerPrincipal inserts an enabled Principal with no allowed-root
// rows and resolves its home. It is used only by user-mode bootstrapping; the
// daemon-owner Principal deliberately carries no principal_allowed_roots rows
// so its effective roots collapse onto the global allowed roots.
func insertDaemonOwnerPrincipal(db *sql.DB, username string, uid, gid int, home string) (int64, error) {
	canonicalHome, err := canonicalizeWorkspacePathForAdd(home)
	if err != nil {
		return 0, fmt.Errorf("daemon-owner home %q is not a valid workspace root: %w", home, err)
	}
	res, err := db.Exec(
		`INSERT INTO principals (username, uid, gid, home, enabled)
		 VALUES (?, ?, ?, ?, 1)`,
		username, uid, gid, canonicalHome,
	)
	if err != nil {
		if isSQLiteUniqueError(err) {
			return 0, fmt.Errorf("daemon-owner principal %q already exists: %w", username, ErrPrincipalExists)
		}
		return 0, fmt.Errorf("cannot create daemon-owner principal: %w", err)
	}
	pid, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("cannot get daemon-owner principal ID: %w", err)
	}
	return pid, nil
}

// ensureUserModeOwnership resolves the real daemon-owner OS identity from the
// effective UID and provisions (or validates) its Principal and 'default'
// Launcher. It runs only in user mode, after initializeDatabase and before
// migrateSessionOwnership, so legacy user-mode principal_id IS NULL Sessions
// can be attributed to the real daemon owner.
//
// It fails closed on any UID/GID/home conflict with an existing Principal and
// never rewrites operator-imposed Principal policy.
func ensureUserModeOwnership(db *sql.DB, mode DeploymentMode) (*userModeDefaultLauncher, error) {
	if mode != ModeUser {
		return nil, nil
	}
	uid := EffectiveUID()
	if uid == 0 {
		return nil, errors.New("user mode cannot run as root")
	}
	username, gidStr, home, err := OSUserLookupByUID(uid)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve daemon-owner OS user: %w", err)
	}
	if username == "" {
		return nil, errors.New("cannot resolve daemon-owner OS username")
	}
	if home == "" || !filepath.IsAbs(home) {
		return nil, fmt.Errorf("daemon-owner OS user %q has invalid home %q", username, home)
	}
	gid, err := parseInt(gidStr)
	if err != nil {
		return nil, fmt.Errorf("daemon-owner OS user %q has invalid GID %q", username, gidStr)
	}

	var principalID int64
	existing, err := findPrincipalByUsername(db, username)
	if errors.Is(err, ErrPrincipalNotFound) {
		principalID, err = insertDaemonOwnerPrincipal(db, username, uid, gid, home)
		if err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	} else {
		// A Principal exists under this username; verify the stored identity
		// matches the resolved daemon-owner OS identity before reuse.
		if existing.UID != uid || existing.GID != gid || existing.Home != home {
			return nil, fmt.Errorf("daemon-owner principal %q UID/GID/home conflicts with resolved OS identity", username)
		}
		principalID = int64(existing.ID)
	}

	launcherID, err := ensureDefaultLauncher(db, principalID)
	if err != nil {
		return nil, fmt.Errorf("cannot provision daemon-owner default Launcher: %w", err)
	}
	return &userModeDefaultLauncher{principalID: principalID, launcherID: launcherID, username: username}, nil
}

func parseInt(s string) (int, error) {
	if s == "" {
		return 0, errors.New("empty integer")
	}
	var n int
	_, err := fmt.Sscanf(s, "%d", &n)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// sessionMigrationResult reports the outcome of a Session ownership cutover.
type sessionMigrationResult struct {
	// attributedPrincipal counts legacy principal-owned Session rows mapped to
	// that Principal's default Launcher.
	attributedPrincipal int
	// attributedUserMode counts legacy user-mode NULL-owner Session rows mapped
	// to the daemon-owner default Launcher.
	attributedUserMode int
	// invalidated counts legacy system-mode NULL-owner Session rows that were
	// dropped because they have no Principal -> Launcher ownership chain.
	invalidated int
}

// migrateSessionOwnership rebuilds a pre-cutover sessions table to the final
// Launcher-owned schema in one atomic transaction. It is idempotent and
// restart-safe: on the final schema it is a no-op, and a crash before commit
// leaves the legacy table intact for the next startup to retry.
//
// Legacy principal-owned rows (old principal_id IS NOT NULL) map to that
// Principal's 'default' Launcher (created idempotently if absent). Legacy
// user-mode NULL-owner rows map to the already-resolved daemon-owner default
// Launcher (userModeDefault != nil in user mode). Legacy system-mode NULL-owner
// rows are invalidated (dropped) in the same transaction. A dangling non-null
// Principal reference fails the migration rather than silently dropping.
//
// This must not call createLauncher (which opens a nested transaction); it uses
// the narrow ensureDefaultLauncher insert helper.
func migrateSessionOwnership(db *sql.DB, mode DeploymentMode, userModeDefault *userModeDefaultLauncher) (*sessionMigrationResult, error) {
	class, err := classifySessionsSchema(db)
	if err != nil {
		return nil, err
	}
	if class == sessionsSchemaFinal {
		// Already at the final Launcher-owned schema; never re-add principal_id.
		return &sessionMigrationResult{}, nil
	}
	if class != sessionsSchemaLegacyPrincipal && class != sessionsSchemaLegacyBare {
		return nil, fmt.Errorf("unsupported sessions schema for ownership migration")
	}

	tx, err := db.Begin()
	if err != nil {
		return nil, fmt.Errorf("cannot begin session ownership migration: %w", err)
	}
	defer tx.Rollback()

	// Resolve default Launchers for every Principal that owns at least one
	// Session, counting attributable rows. A Session referencing a non-existent
	// Principal is a dangling reference and must fail the migration, never be
	// silently dropped.
	rows, err := tx.Query(`SELECT DISTINCT principal_id FROM sessions WHERE principal_id IS NOT NULL`)
	if err != nil {
		return nil, fmt.Errorf("cannot enumerate principal-owned sessions: %w", err)
	}
	type principalDefault struct {
		launcherID string
		count      int
	}
	defaultByPrincipal := make(map[int64]principalDefault)
	for rows.Next() {
		var pid int64
		if err := rows.Scan(&pid); err != nil {
			rows.Close()
			return nil, fmt.Errorf("cannot scan principal id: %w", err)
		}
		var exists int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM principals WHERE id = ?`, pid).Scan(&exists); err != nil {
			rows.Close()
			return nil, fmt.Errorf("cannot check session principal: %w", err)
		}
		if exists == 0 {
			rows.Close()
			return nil, fmt.Errorf("session references principal %d which no longer exists", pid)
		}
		launcherID, err := ensureDefaultLauncher(tx, pid)
		if err != nil {
			rows.Close()
			return nil, fmt.Errorf("cannot provision default Launcher for principal %d: %w", pid, err)
		}
		var count int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM sessions WHERE principal_id = ?`, pid).Scan(&count); err != nil {
			rows.Close()
			return nil, fmt.Errorf("cannot count principal-owned sessions: %w", err)
		}
		defaultByPrincipal[pid] = principalDefault{launcherID: launcherID, count: count}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate principal-owned sessions: %w", err)
	}

	// Determine whether legacy NULL-owner rows exist and must be attributed.
	var nullCount int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM sessions WHERE principal_id IS NULL`).Scan(&nullCount); err != nil {
		return nil, fmt.Errorf("cannot count legacy ownerless sessions: %w", err)
	}
	if nullCount > 0 && mode == ModeUser {
		if userModeDefault == nil {
			return nil, fmt.Errorf("user-mode legacy ownerless sessions cannot be attributed: daemon-owner ownership was not provisioned")
		}
	}

	if _, err := tx.Exec(`
		CREATE TABLE sessions_new (
			id TEXT PRIMARY KEY,
			token_hash TEXT NOT NULL UNIQUE,
			workspace TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL,
			launcher_id TEXT NOT NULL REFERENCES launchers(id)
		)`,
	); err != nil {
		return nil, fmt.Errorf("cannot create new sessions table: %w", err)
	}

	// Copy principal-owned rows, resolving each to its default Launcher. Any
	// attributable Principal that could not be mapped would be silently
	// dropped, so the per-Principal row count guard below fails closed instead.
	principalOwned := 0
	for pid, pd := range defaultByPrincipal {
		if _, err := tx.Exec(
			`INSERT INTO sessions_new (id, token_hash, workspace, created_at, expires_at, launcher_id)
			 SELECT id, token_hash, workspace, created_at, expires_at, ?
			 FROM sessions WHERE principal_id = ?`,
			pd.launcherID, pid,
		); err != nil {
			return nil, fmt.Errorf("cannot migrate principal-owned sessions: %w", err)
		}
		principalOwned += pd.count
	}

	// Verify no attributable principal-owned Session was dropped.
	var totalPrincipalOwned int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM sessions WHERE principal_id IS NOT NULL`).Scan(&totalPrincipalOwned); err != nil {
		return nil, fmt.Errorf("cannot count attributable principal-owned sessions: %w", err)
	}
	if principalOwned != totalPrincipalOwned {
		return nil, fmt.Errorf("session ownership migration would drop %d principal-owned session(s)", totalPrincipalOwned-principalOwned)
	}

	// Copy or invalidate legacy NULL-owner rows.
	attributedUser := 0
	if nullCount > 0 {
		if mode == ModeUser {
			if _, err := tx.Exec(
				`INSERT INTO sessions_new (id, token_hash, workspace, created_at, expires_at, launcher_id)
				 SELECT id, token_hash, workspace, created_at, expires_at, ?
				 FROM sessions WHERE principal_id IS NULL`,
				userModeDefault.launcherID,
			); err != nil {
				return nil, fmt.Errorf("cannot migrate user-mode legacy sessions: %w", err)
			}
			attributedUser = nullCount
		}
		// System mode: NULL-owner rows are not copied; they are invalidated.
	}

	if _, err := tx.Exec(`DROP TABLE sessions`); err != nil {
		return nil, fmt.Errorf("cannot drop old sessions table: %w", err)
	}
	if _, err := tx.Exec(`ALTER TABLE sessions_new RENAME TO sessions`); err != nil {
		return nil, fmt.Errorf("cannot rename sessions table: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("cannot commit session ownership migration: %w", err)
	}

	result := &sessionMigrationResult{
		attributedPrincipal: principalOwned,
		attributedUserMode:  attributedUser,
		invalidated:         nullCount - attributedUser,
	}
	return result, nil
}
