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
// The transparent user-mode chain is exactly: daemon-owner Principal (enabled,
// ZERO principal_allowed_roots => collapsed to the global roots) with an
// enabled, inherit-scope 'default' Launcher carrying ZERO launcher_allowed_roots
// and no provisioning-time credential. An existing Principal/Launcher that
// conflicts with this contract fails closed; operator-imposed state is never
// silently rewritten (no auto-enable, no root deletion, no restricted->inherit
// mutation).
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

	// Canonicalize the OS home once, with the same semantics used to store the
	// daemon-owner identity, so a symlinked home resolves, stores, and compares
	// identically across restarts (FIX B6).
	canonicalHome, err := canonicalizeWorkspacePathForAdd(home)
	if err != nil {
		return nil, fmt.Errorf("daemon-owner home %q is not a valid workspace root: %w", home, err)
	}

	var principalID int64
	existing, err := findPrincipalByUsername(db, username)
	if errors.Is(err, ErrPrincipalNotFound) {
		principalID, err = insertDaemonOwnerPrincipal(db, username, uid, gid, canonicalHome)
		if err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	} else {
		// A Principal exists under this username; verify it still matches the
		// transparent user-mode contract before reuse.
		if err := validateUserModePrincipalContract(existing, username, uid, gid, canonicalHome); err != nil {
			return nil, err
		}
		principalID = int64(existing.ID)
	}

	launcherID, err := ensureUserModeDefaultLauncher(db, principalID)
	if err != nil {
		return nil, fmt.Errorf("cannot provision daemon-owner default Launcher: %w", err)
	}
	return &userModeDefaultLauncher{principalID: principalID, launcherID: launcherID, username: username}, nil
}

// validateUserModePrincipalContract fails closed unless the existing Principal
// matches the transparent user-mode contract: enabled, ZERO principal_allowed_roots
// rows (so its roots collapse onto the global roots), and UID/GID/home matching
// the resolved OS daemon-owner identity.
func validateUserModePrincipalContract(p *PrincipalWithRoots, username string, uid, gid int, home string) error {
	if !p.Enabled {
		return fmt.Errorf("daemon-owner principal %q is disabled; user-mode requires it enabled", username)
	}
	if len(p.AllowedRoots) != 0 {
		return fmt.Errorf("daemon-owner principal %q has principal_allowed_roots rows; user-mode requires none", username)
	}
	if p.UID != uid || p.GID != gid || p.Home != home {
		return fmt.Errorf("daemon-owner principal %q UID/GID/home conflicts with resolved OS identity", username)
	}
	return nil
}

// ensureUserModeDefaultLauncher returns the daemon-owner Principal's 'default'
// Launcher, creating the canonical transparent Launcher if absent. If a
// 'default' Launcher already exists it is validated against the transparent
// user-mode contract and fails closed on conflict rather than being rewritten.
func ensureUserModeDefaultLauncher(db *sql.DB, principalID int64) (string, error) {
	launcherID, err := findDefaultLauncher(db, principalID)
	if err == nil {
		if verr := validateUserModeDefaultLauncherContract(db, launcherID); verr != nil {
			return "", verr
		}
		return launcherID, nil
	}
	if errors.Is(err, ErrLauncherNotFound) {
		return ensureDefaultLauncher(db, principalID)
	}
	return "", err
}

// validateUserModeDefaultLauncherContract fails closed unless the existing
// 'default' Launcher matches the transparent user-mode contract: enabled,
// scope inherit, and ZERO launcher_allowed_roots rows.
func validateUserModeDefaultLauncherContract(db *sql.DB, launcherID string) error {
	var enabled int
	var scope string
	err := db.QueryRow(`SELECT enabled, scope_mode FROM launchers WHERE id = ?`, launcherID).Scan(&enabled, &scope)
	if err != nil {
		return fmt.Errorf("cannot read daemon-owner default launcher: %w", err)
	}
	if enabled != 1 {
		return fmt.Errorf("daemon-owner default launcher %q is disabled; user-mode requires it enabled", launcherID)
	}
	if scope != string(LauncherScopeInherit) {
		return fmt.Errorf("daemon-owner default launcher %q scope %q is not inherit", launcherID, scope)
	}
	var rootCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM launcher_allowed_roots WHERE launcher_id = ?`, launcherID).Scan(&rootCount); err != nil {
		return fmt.Errorf("cannot count daemon-owner default launcher allowed roots: %w", err)
	}
	if rootCount != 0 {
		return fmt.Errorf("daemon-owner default launcher %q has launcher_allowed_roots rows; user-mode requires none", launcherID)
	}
	return nil
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
	// The bare R1 shape is owned by initializeDatabase, which adds
	// principal_id before this rebuild runs. This function therefore only ever
	// consumes the legacy principal-owned source (principal_id present,
	// launcher_id absent) or the final schema handled above; anything else is
	// unsupported and fails closed.
	if class != sessionsSchemaLegacyPrincipal {
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

	// Integrity gate before commit: the rebuilt sessions table must have no
	// foreign-key violations (e.g. a dangling launcher_id). Fail (and roll back,
	// leaving the legacy table intact) rather than commit a corrupt result. This
	// is independent of whether FK enforcement is on for this connection: the
	// check reports existing violations even when enforcement is disabled.
	if err := checkSessionsForeignKeys(tx); err != nil {
		return nil, err
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

// checkSessionsForeignKeys fails the migration if any foreign-key violation
// exists in the rebuilt database. PRAGMA foreign_key_check returns one row per
// violation regardless of whether FK enforcement is enabled on this
// connection; no rows means integrity holds.
func checkSessionsForeignKeys(tx *sql.Tx) error {
	var table, parent string
	var rowid int64
	var fkid int
	err := tx.QueryRow(`PRAGMA foreign_key_check`).Scan(&table, &rowid, &parent, &fkid)
	if err == nil {
		return fmt.Errorf("session ownership migration integrity check failed: foreign key violation in %s (rowid %d, parent %s, fkid %d)", table, rowid, parent, fkid)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	return fmt.Errorf("cannot run session ownership integrity check: %w", err)
}
