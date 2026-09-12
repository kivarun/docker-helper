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
	AllowedRoots []AllowedRootEntry
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

// findPrincipalIDByUsername resolves a username to its principal ID.
func findPrincipalIDByUsername(db *sql.DB, username string) (int, error) {
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

// ErrInvalidAllowedRootAccess is returned when a request supplies an access
// value outside the canonical vocabulary (read_write, read_only). It is the
// fail-closed refusal for every control-plane access input; there is no
// default access for an unparseable value.
var ErrInvalidAllowedRootAccess = errors.New("invalid allowed-root access")

// ErrAllowedRootNotFound is returned by the targeted set-access mutation when
// no stored root with the requested canonical identity exists for the owner.
// Unlike the idempotent remove (whose goal state is satisfied by absence), a
// targeted access change on a missing entry is refused so a mistyped path can
// never be silently reported as satisfied.
var ErrAllowedRootNotFound = errors.New("allowed root not found")

func createPrincipal(db *sql.DB, username string, globalAllowedRoots []AllowedRootEntry) (*PrincipalWithRoots, error) {
	p, _, _, err := createPrincipalWithOptionalCredential(db, username, globalAllowedRoots, false)
	return p, err
}

// createPrincipalWithOptionalCredential creates a Principal, its default
// allowed root, its canonical 'default' Launcher, and (when issueCredential is
// true) an initial Principal credential named "default" as one logical atomic
// operation in a single transaction. Returns the Principal projection and, when
// issued, the initial credential and its bearer secret exactly once. If the
// combined operation cannot complete, no half-created Principal remains.
//
// The 'default' Launcher is provisioned unconditionally (inherit scope, no
// launcher allowed roots, no credential): every Principal exists only through
// the Launcher-owned Session model, so a freshly created Principal must never
// lack its default ownership anchor.
func createPrincipalWithOptionalCredential(db *sql.DB, username string, globalAllowedRoots []AllowedRootEntry, issueCredential bool) (*PrincipalWithRoots, *PrincipalCredential, string, error) {
	if username == "" {
		return nil, nil, "", fmt.Errorf("username is required: %w", ErrPrincipalNotFound)
	}

	uid, gid, home, err := resolveOSUser(username)
	if err != nil {
		return nil, nil, "", err
	}

	if home == "" || !filepath.IsAbs(home) {
		return nil, nil, "", fmt.Errorf("OS user %q has invalid home %q: must be an absolute path", username, home)
	}

	// Canonicalize the home directory and apply the workspace root policy.
	canonicalHome, err := canonicalizeWorkspacePathForAdd(home)
	if err != nil {
		return nil, nil, "", fmt.Errorf("OS user %q home directory %q is not a valid workspace root: %s", username, home, err)
	}

	// Validate the home directory is under at least one global allowed root.
	if !isWithinAnyAllowedRoot(canonicalHome, allowedRootPaths(globalAllowedRoots)) {
		return nil, nil, "", fmt.Errorf("OS user %q home directory %q is not under any global allowed root: %w", username, canonicalHome, ErrPrincipalRootOutsideGlobal)
	}

	tx, err := db.Begin()
	if err != nil {
		return nil, nil, "", fmt.Errorf("cannot begin transaction: %w", err)
	}
	defer tx.Rollback()

	result, err := tx.Exec(
		`INSERT INTO principals (username, uid, gid, home, enabled)
		 VALUES (?, ?, ?, ?, 1)`,
		username, uid, gid, home,
	)
	if err != nil {
		if isSQLiteUniqueError(err) {
			return nil, nil, "", fmt.Errorf("principal %q already exists: %w", username, ErrPrincipalExists)
		}
		return nil, nil, "", fmt.Errorf("cannot create principal: %w", err)
	}

	principalID, err := result.LastInsertId()
	if err != nil {
		return nil, nil, "", fmt.Errorf("cannot get principal ID: %w", err)
	}

	if _, err := tx.Exec(
		`INSERT INTO principal_allowed_roots (principal_id, root_path, access)
		 VALUES (?, ?, ?)`,
		principalID, canonicalHome, string(AllowedRootAccessReadWrite),
	); err != nil {
		return nil, nil, "", fmt.Errorf("cannot add default allowed root: %w", err)
	}

	if _, err := ensureDefaultLauncher(tx, principalID); err != nil {
		return nil, nil, "", fmt.Errorf("cannot provision default Launcher: %w", err)
	}

	var cred *PrincipalCredential
	var token string
	if issueCredential {
		cred, token, err = insertPrincipalCredentialInTx(tx, principalID, username, "default")
		if err != nil {
			return nil, nil, "", err
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, nil, "", fmt.Errorf("cannot commit principal creation: %w", err)
	}

	// Construct the returned projection from known committed values. No DB read
	// is required after commit, so a successful commit cannot be followed by a
	// fallible lookup that would lose the one-time bearer secret.
	p := &PrincipalWithRoots{
		Principal: Principal{
			ID:       int(principalID),
			Username: username,
			UID:      uid,
			GID:      gid,
			Home:     home,
			Enabled:  true,
		},
		AllowedRoots: []AllowedRootEntry{allowedRootEntry(canonicalHome)},
	}
	return p, cred, token, nil
}

func findPrincipalByUsername(db *sql.DB, username string) (*PrincipalWithRoots, error) {
	if username == "" {
		return nil, fmt.Errorf("username is required: %w", ErrPrincipalNotFound)
	}

	principalID, err := findPrincipalIDByUsername(db, username)
	if err != nil {
		return nil, err
	}

	p, err := findPrincipalByID(db, principalID)
	if err != nil {
		return nil, err
	}

	rows, err := db.Query(
		`SELECT root_path, access FROM principal_allowed_roots
		 WHERE principal_id = ?
		 ORDER BY root_path`,
		principalID,
	)
	if err != nil {
		return nil, fmt.Errorf("cannot query allowed roots: %w", err)
	}
	defer rows.Close()

	roots := []AllowedRootEntry{}
	for rows.Next() {
		var rootPath string
		var access string
		if err := rows.Scan(&rootPath, &access); err != nil {
			return nil, fmt.Errorf("cannot scan allowed root: %w", err)
		}
		roots = append(roots, AllowedRootEntry{Path: rootPath, Access: AllowedRootAccess(access)})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate allowed roots: %w", err)
	}

	return &PrincipalWithRoots{
		Principal:    *p,
		AllowedRoots: roots,
	}, nil
}

// launcherAdmissionsInTx observes every child Launcher's enabled state within
// the given transaction and computes the final operation-admission state each
// child must hold after the Principal's committed enabled transition: closed
// iff the resulting Principal.enabled or the child's own Launcher.enabled does
// not hold. The enable path applies these states in memory after commit
// without another DB read.
func launcherAdmissionsInTx(tx *sql.Tx, principalID int, principalEnabled int) ([]launcherAdmission, error) {
	rows, err := tx.Query(`SELECT id, enabled FROM launchers WHERE principal_id = ?`, principalID)
	if err != nil {
		return nil, fmt.Errorf("cannot query principal launchers: %w", err)
	}
	defer rows.Close()
	var admissions []launcherAdmission
	for rows.Next() {
		var id string
		var enabled int
		if err := rows.Scan(&id, &enabled); err != nil {
			return nil, fmt.Errorf("cannot scan launcher admission state: %w", err)
		}
		admissions = append(admissions, launcherAdmission{
			LauncherID: id,
			Closed:     principalEnabled == 0 || enabled == 0,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate launchers: %w", err)
	}
	return admissions, nil
}

// persistPrincipalEnabledChange performs a transactionally correct enabled-state
// transition for a principal. It:
//   - determines Principal existence and current enabled state within the transaction;
//   - if already in the requested state, returns Changed=false with the
//     transactionally computed child-Launcher admission states;
//   - updates enabled state;
//   - when disabling, collects and deletes the Principal's sessions;
//   - commits;
//   - returns explicit Changed, RevokedSessionIDs, and the final
//     child-Launcher admission states computed within the same transaction,
//     so the enable path can apply them in memory after commit without
//     another DB read.
func persistPrincipalEnabledChange(db *sql.DB, username string, enabled bool) (principalEnabledChangeResult, error) {
	if username == "" {
		return principalEnabledChangeResult{}, fmt.Errorf("username is required: %w", ErrPrincipalNotFound)
	}

	tx, err := db.Begin()
	if err != nil {
		return principalEnabledChangeResult{}, fmt.Errorf("cannot begin transaction: %w", err)
	}

	principalID, err := findPrincipalIDByUsernameInTx(tx, username)
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

	// Already in requested state. The child Launchers' final admission states
	// are still computed transactionally so an idempotent enable applies the
	// same in-memory admission decision as a real transition.
	if currentEnabled == newEnabled {
		admissions, err := launcherAdmissionsInTx(tx, principalID, newEnabled)
		if err != nil {
			tx.Rollback()
			return principalEnabledChangeResult{}, err
		}
		tx.Rollback()
		return principalEnabledChangeResult{Changed: false, LauncherAdmissions: admissions}, nil
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
		// Collect session IDs across every Launcher attached to this Principal
		// before deletion, for runtime cleanup. Sessions are Launcher-owned, so
		// the ownership join goes through launchers.
		rows, err := tx.Query(
			`SELECT s.id FROM sessions s JOIN launchers l ON l.id = s.launcher_id WHERE l.principal_id = ?`,
			principalID,
		)
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
			`DELETE FROM sessions WHERE launcher_id IN (SELECT id FROM launchers WHERE principal_id = ?)`,
			principalID,
		)
		if err != nil {
			tx.Rollback()
			return principalEnabledChangeResult{}, fmt.Errorf("cannot delete principal sessions: %w", err)
		}
	}

	// Observe the child Launchers' enabled states within this same
	// transaction so the committed transition's final admission states can be
	// applied in memory without another DB read.
	admissions, err := launcherAdmissionsInTx(tx, principalID, newEnabled)
	if err != nil {
		tx.Rollback()
		return principalEnabledChangeResult{}, err
	}

	if err := tx.Commit(); err != nil {
		return principalEnabledChangeResult{}, fmt.Errorf("cannot commit enabled change: %w", err)
	}

	return principalEnabledChangeResult{
		Changed:            true,
		RevokedSessionIDs:  sessionIDs,
		LauncherAdmissions: admissions,
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
// The add is an idempotent create: it never changes the access of an already
// stored root (only set-access does), so the returned entry reports the
// stored access of the canonical root — the requested access when the row
// was created, the pre-existing access when it was already present.
func addPrincipalAllowedRoot(db *sql.DB, username string, rootPath string, access AllowedRootAccess, globalAllowedRoots []string) (changed bool, entry AllowedRootEntry, err error) {
	if username == "" {
		return false, AllowedRootEntry{}, fmt.Errorf("username is required: %w", ErrPrincipalNotFound)
	}
	if !access.isValid() {
		return false, AllowedRootEntry{}, fmt.Errorf("access must be read_write or read_only: %w", ErrInvalidAllowedRootAccess)
	}

	resolved, err := validatePrincipalAllowedRootForAdd(rootPath)
	if err != nil {
		return false, AllowedRootEntry{}, err
	}

	// Validate the root is under at least one global allowed root.
	if !isWithinAnyAllowedRoot(resolved, globalAllowedRoots) {
		return false, AllowedRootEntry{}, fmt.Errorf("path %q is not under any global allowed root: %w", resolved, ErrPrincipalRootOutsideGlobal)
	}

	principalID, err := findPrincipalIDByUsername(db, username)
	if err != nil {
		return false, AllowedRootEntry{}, err
	}

	// INSERT OR IGNORE keeps an already-stored root (and its access)
	// untouched: re-adding a root is never an access mutation.
	result, err := db.Exec(
		`INSERT OR IGNORE INTO principal_allowed_roots (principal_id, root_path, access)
		 VALUES (?, ?, ?)`,
		principalID, resolved, string(access),
	)
	if err != nil {
		return false, AllowedRootEntry{}, fmt.Errorf("cannot add allowed root: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return false, AllowedRootEntry{}, fmt.Errorf("cannot check insert result: %w", err)
	}

	if affected > 0 {
		return true, AllowedRootEntry{Path: resolved, Access: access}, nil
	}
	stored, err := storedPrincipalAllowedRootAccess(db, principalID, resolved)
	if err != nil {
		return false, AllowedRootEntry{}, err
	}
	return false, AllowedRootEntry{Path: resolved, Access: stored}, nil
}

// storedPrincipalAllowedRootAccess reads the stored access of one canonical
// Principal root after an idempotent no-op mutation.
func storedPrincipalAllowedRootAccess(db *sql.DB, principalID int, canonicalPath string) (AllowedRootAccess, error) {
	var stored AllowedRootAccess
	if err := db.QueryRow(
		`SELECT access FROM principal_allowed_roots WHERE principal_id = ? AND root_path = ?`,
		principalID, canonicalPath,
	).Scan(&stored); err != nil {
		return "", fmt.Errorf("cannot read stored allowed root: %w", err)
	}
	return stored, nil
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
	resolved, err := resolveAllowedRootIdentity(rootPath)
	if err != nil {
		return false, "", err
	}

	principalID, err := findPrincipalIDByUsername(db, username)
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

// setPrincipalAllowedRootAccess changes the access mode of exactly one stored
// Principal root, addressed by the same canonical stored identity as the
// remove (symlink-resolved when the path still exists, cleaned absolute
// otherwise). The targeted access change is a single conditional mutation:
// the ceiling is deliberately not re-checked here, because the effective
// policy is composed by the canonical 2.2 effective-root owner at every
// consumption boundary (widening an entry cannot exceed the composed meet).
// A missing stored root is ErrAllowedRootNotFound — unlike the idempotent
// remove, a targeted access change must not silently report a satisfied goal
// state for an entry that does not exist. An unchanged access (same value) is
// the idempotent no-op: changed=false with the stored entry.
func setPrincipalAllowedRootAccess(db *sql.DB, username string, rootPath string, access AllowedRootAccess) (changed bool, entry AllowedRootEntry, err error) {
	if username == "" {
		return false, AllowedRootEntry{}, fmt.Errorf("username is required: %w", ErrPrincipalNotFound)
	}
	if !access.isValid() {
		return false, AllowedRootEntry{}, fmt.Errorf("access must be read_write or read_only: %w", ErrInvalidAllowedRootAccess)
	}
	if rootPath == "" {
		return false, AllowedRootEntry{}, fmt.Errorf("path is required: %w", ErrInvalidAllowedRoot)
	}
	if !filepath.IsAbs(rootPath) {
		return false, AllowedRootEntry{}, fmt.Errorf("path must be absolute: %w", ErrInvalidAllowedRoot)
	}

	resolved, err := resolveAllowedRootIdentity(rootPath)
	if err != nil {
		return false, AllowedRootEntry{}, err
	}

	principalID, err := findPrincipalIDByUsername(db, username)
	if err != nil {
		return false, AllowedRootEntry{}, err
	}

	// The stored access is read once and compared before the mutation, so a
	// same-value request is the idempotent no-op (changed=false) without
	// rewriting the row, and a missing stored root is refused before any
	// mutation.
	stored, err := storedPrincipalAllowedRootAccess(db, principalID, resolved)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, AllowedRootEntry{}, allowedRootNotFoundError{path: resolved}
		}
		return false, AllowedRootEntry{}, err
	}
	if stored == access {
		return false, AllowedRootEntry{Path: resolved, Access: stored}, nil
	}

	result, err := db.Exec(
		`UPDATE principal_allowed_roots SET access = ?
		 WHERE principal_id = ? AND root_path = ?`,
		string(access), principalID, resolved,
	)
	if err != nil {
		return false, AllowedRootEntry{}, fmt.Errorf("cannot change allowed root access: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return false, AllowedRootEntry{}, fmt.Errorf("cannot check update result: %w", err)
	}
	if affected == 0 {
		return false, AllowedRootEntry{}, allowedRootNotFoundError{path: resolved}
	}
	return true, AllowedRootEntry{Path: resolved, Access: access}, nil
}

// isSQLiteUniqueError checks if an error is a SQLite UNIQUE constraint violation.
func isSQLiteUniqueError(err error) bool {
	return strings.Contains(err.Error(), "UNIQUE constraint failed") ||
		strings.Contains(err.Error(), "unique constraint failed")
}

// listPrincipalSummaries returns all principals ordered by username,
// with only the fields exposed by GET /principals. Allowed roots are
// intentionally not loaded; use findPrincipalByUsername for full details.
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

	principalID, err := findPrincipalIDByUsernameInTx(tx, username)
	if err != nil {
		tx.Rollback()
		return nil, err
	}

	// Collect session IDs across every Launcher of this Principal before
	// deletion for runtime cleanup. Sessions are Launcher-owned, so the
	// ownership join goes through launchers.
	rows, err := tx.Query(
		`SELECT s.id FROM sessions s JOIN launchers l ON l.id = s.launcher_id WHERE l.principal_id = ?`,
		principalID,
	)
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

	// Delete all sessions for this Principal's Launchers. Launchers (and their
	// credentials/roots) follow via the principal FK cascade. There is no
	// ON DELETE CASCADE from Launcher -> Session, so sessions are removed
	// explicitly first.
	_, err = tx.Exec(
		`DELETE FROM sessions WHERE launcher_id IN (SELECT id FROM launchers WHERE principal_id = ?)`,
		principalID,
	)
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

func findPrincipalIDByUsernameInTx(tx *sql.Tx, username string) (int, error) {
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
