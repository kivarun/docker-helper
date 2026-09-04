package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// LauncherScopeMode is the scope policy of a Launcher beneath its Principal.
type LauncherScopeMode string

const (
	// LauncherScopeInherit adds no narrowing: the Launcher's effective
	// Session-creation roots equal the current effective Principal roots.
	LauncherScopeInherit LauncherScopeMode = "inherit"

	// LauncherScopeRestricted intersects the current effective Principal roots
	// with the Launcher's canonical stored roots.
	LauncherScopeRestricted LauncherScopeMode = "restricted"
)

// Launcher is the stable Session owner beneath one Principal. This is the
// persistence-level domain record introduced by Stage 1.1; Launcher CRUD and
// Session ownership cutover are owned by later stages. Launcher roots do not
// own MAC state, and a Launcher is not a credential.
type Launcher struct {
	ID          string
	PrincipalID int64
	Name        string
	Enabled     bool
	ScopeMode   LauncherScopeMode
	CreatedAt   time.Time
}

// LauncherWithPrincipal is a Launcher projection carrying its owning Principal
// name and its canonical allowed roots (empty for inherit scope).
type LauncherWithPrincipal struct {
	ID            string
	PrincipalID   int64
	PrincipalName string
	Name          string
	Enabled       bool
	ScopeMode     LauncherScopeMode
	AllowedRoots  []string
	CreatedAt     time.Time
}

// launcherIDPrefix and launcherIDEntropyBytes define the single stable Launcher
// ID format: a random 16-byte (128-bit) value, lowercase-hex encoded and
// prefixed with "dhl_". The format is analogous to the existing stable
// resource-ID formats and is not generalized into a shared ID framework.
const (
	launcherIDPrefix       = "dhl_"
	launcherIDEntropyBytes = 16
)

// generateLauncherID returns a random 16-byte hex ID prefixed with "dhl_".
func generateLauncherID() (string, error) {
	b := make([]byte, launcherIDEntropyBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("cannot generate random bytes: %w", err)
	}
	return launcherIDPrefix + hex.EncodeToString(b), nil
}

var (
	// ErrLauncherNotFound is returned when a Launcher does not exist.
	ErrLauncherNotFound = errors.New("launcher not found")
	// ErrLauncherExists is returned when a Launcher name already exists within
	// the same Principal.
	ErrLauncherExists = errors.New("launcher already exists")
	// ErrInvalidLauncherName is returned when a Launcher name is empty/invalid.
	ErrInvalidLauncherName = errors.New("invalid launcher name")
	// ErrInvalidScope is returned when a Launcher scope is not inherit/restricted.
	ErrInvalidScope = errors.New("invalid launcher scope")
	// ErrInvalidAllowedRoots is returned when restricted roots are missing/invalid.
	ErrInvalidAllowedRoots = errors.New("invalid launcher allowed roots")
	// ErrLauncherRootOutsidePrincipal is returned when a Launcher restricted
	// root is not under the current effective Principal roots.
	ErrLauncherRootOutsidePrincipal = errors.New("launcher root outside effective principal roots")
)

// readLauncherAllowedRoots returns the canonical stored roots of a Launcher.
func readLauncherAllowedRoots(db *sql.DB, launcherID string) ([]string, error) {
	rows, err := db.Query(
		`SELECT root_path FROM launcher_allowed_roots WHERE launcher_id = ? ORDER BY root_path`,
		launcherID,
	)
	if err != nil {
		return nil, fmt.Errorf("cannot query launcher allowed roots: %w", err)
	}
	defer rows.Close()

	var roots []string
	for rows.Next() {
		var root string
		if err := rows.Scan(&root); err != nil {
			return nil, fmt.Errorf("cannot scan launcher allowed root: %w", err)
		}
		roots = append(roots, root)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate launcher allowed roots: %w", err)
	}
	return roots, nil
}

// scanLauncherBase scans the base launcher columns joined with its Principal
// username. Columns: id, principal_id, principal_username, name, enabled,
// scope_mode, created_at.
func scanLauncherBase(s sqlScanner) (LauncherWithPrincipal, error) {
	var l LauncherWithPrincipal
	var enabled int
	var scope string
	var createdAt int64
	if err := s.Scan(&l.ID, &l.PrincipalID, &l.PrincipalName, &l.Name, &enabled, &scope, &createdAt); err != nil {
		return l, err
	}
	l.Enabled = enabled != 0
	l.ScopeMode = LauncherScopeMode(scope)
	l.CreatedAt = time.Unix(createdAt, 0)
	return l, nil
}

// launcherSelect is the launcher projection SELECT shared by the Launcher
// lookups: base columns joined with the owning Principal username.
const launcherSelect = `SELECT l.id, l.principal_id, p.username, l.name, l.enabled, l.scope_mode, l.created_at
	FROM launchers l JOIN principals p ON p.id = l.principal_id`

// launcherFromRow scans one launcher projection row and loads its canonical
// allowed roots; a missing row is ErrLauncherNotFound.
func launcherFromRow(db *sql.DB, row sqlScanner) (*LauncherWithPrincipal, error) {
	l, err := scanLauncherBase(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrLauncherNotFound
		}
		return nil, fmt.Errorf("cannot find launcher: %w", err)
	}
	roots, err := readLauncherAllowedRoots(db, l.ID)
	if err != nil {
		return nil, err
	}
	l.AllowedRoots = roots
	return &l, nil
}

// findLauncherByID looks up a Launcher by ID, joined with its Principal name
// and its canonical allowed roots.
func findLauncherByID(db *sql.DB, id string) (*LauncherWithPrincipal, error) {
	if id == "" {
		return nil, ErrLauncherNotFound
	}
	return launcherFromRow(db, db.QueryRow(launcherSelect+` WHERE l.id = ?`, id))
}

// isLauncherIDSelector reports whether a Launcher selector is an exact
// well-formed Launcher ID: dhl_ followed by 32 lowercase hex characters.
// ID-shaped selectors resolve by ID only and never fall back to name lookup;
// the Launcher-name grammar already makes ID-shaped names impossible.
func isLauncherIDSelector(selector string) bool {
	rest, ok := strings.CutPrefix(selector, launcherIDPrefix)
	if !ok || len(rest) != launcherIDEntropyBytes*2 {
		return false
	}
	for i := 0; i < len(rest); i++ {
		c := rest[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// findLauncherByIDUnderPrincipal looks up a Launcher by ID constrained to the
// given owning Principal: a foreign ID is indistinguishable from a missing one.
func findLauncherByIDUnderPrincipal(db *sql.DB, principalID int64, id string) (*LauncherWithPrincipal, error) {
	return launcherFromRow(db, db.QueryRow(
		launcherSelect+` WHERE l.id = ? AND l.principal_id = ?`, id, principalID,
	))
}

// findLauncherByNameUnderPrincipal looks up a Launcher by
// UNIQUE(principal_id, name); names are never resolved globally.
func findLauncherByNameUnderPrincipal(db *sql.DB, principalID int64, name string) (*LauncherWithPrincipal, error) {
	return launcherFromRow(db, db.QueryRow(
		launcherSelect+` WHERE l.principal_id = ? AND l.name = ?`, principalID, name,
	))
}

// findLauncherForPrincipal resolves a Principal-scoped Launcher selector under
// the already-resolved Principal: (principal, launcher-selector) -> Launcher.
// An exact dhl_<32hex> selector looks up that ID under this Principal; a
// grammar-valid Launcher name looks up (principal_id, name). Malformed,
// foreign, and missing selectors all return ErrLauncherNotFound without any
// fallback or global scan. Principal credentials resolve their own Principal's
// Launchers; admins target the explicitly selected Principal; a foreign
// resource stays non-disclosing.
func findLauncherForPrincipal(db *sql.DB, principalID int64, selector string) (*LauncherWithPrincipal, error) {
	if isLauncherIDSelector(selector) {
		return findLauncherByIDUnderPrincipal(db, principalID, selector)
	}
	if _, err := validateLauncherName(selector); err != nil {
		return nil, ErrLauncherNotFound
	}
	return findLauncherByNameUnderPrincipal(db, principalID, selector)
}

// listLaunchersForScope returns the Launchers of one authorized list scope:
// every Launcher when principalID is nil, otherwise only that Principal's,
// each row carrying its owning Principal's username, ordered by owning
// Principal name and then Launcher name.
func listLaunchersForScope(db *sql.DB, principalID *int64) ([]LauncherWithPrincipal, error) {
	var ownerID any
	if principalID != nil {
		ownerID = *principalID
	}
	rows, err := db.Query(
		`SELECT l.id, l.principal_id, p.username, l.name, l.enabled, l.scope_mode, l.created_at
		 FROM launchers l JOIN principals p ON p.id = l.principal_id
		 WHERE (? IS NULL OR l.principal_id = ?)
		 ORDER BY p.username, l.name`,
		ownerID, ownerID,
	)
	if err != nil {
		return nil, fmt.Errorf("cannot list launchers: %w", err)
	}
	defer rows.Close()

	var out []LauncherWithPrincipal
	for rows.Next() {
		l, err := scanLauncherBase(rows)
		if err != nil {
			return nil, fmt.Errorf("cannot scan launcher: %w", err)
		}
		roots, err := readLauncherAllowedRoots(db, l.ID)
		if err != nil {
			return nil, err
		}
		l.AllowedRoots = roots
		out = append(out, l)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate launchers: %w", err)
	}
	return out, nil
}

// readPrincipalAllowedRoots returns the canonical stored roots of a Principal.
func readPrincipalAllowedRoots(db *sql.DB, principalID int64) ([]string, error) {
	rows, err := db.Query(
		`SELECT root_path FROM principal_allowed_roots WHERE principal_id = ? ORDER BY root_path`,
		principalID,
	)
	if err != nil {
		return nil, fmt.Errorf("cannot query principal allowed roots: %w", err)
	}
	defer rows.Close()

	var roots []string
	for rows.Next() {
		var root string
		if err := rows.Scan(&root); err != nil {
			return nil, fmt.Errorf("cannot scan principal allowed root: %w", err)
		}
		roots = append(roots, root)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate principal allowed roots: %w", err)
	}
	return roots, nil
}

// effectivePrincipalRoots returns the writable ceiling for a system Principal:
// the intersection of the global allowed roots and the current Principal
// allowed roots. Launcher restricted roots must be under this ceiling.
func effectivePrincipalRoots(db *sql.DB, principalID int64, globalAllowedRoots []string) ([]string, error) {
	principalRoots, err := readPrincipalAllowedRoots(db, principalID)
	if err != nil {
		return nil, err
	}
	return intersectAllowedRootScopes(globalAllowedRoots, principalRoots), nil
}

// validateLauncherAllowedRoots canonicalizes each root using the same canonical
// path semantics as Principal roots and requires each to be under the current
// effective Principal roots. Returns the deduplicated canonical set.
func validateLauncherAllowedRoots(roots []string, effectivePrincipalRoots []string) ([]string, error) {
	if len(roots) == 0 {
		return nil, fmt.Errorf("restricted scope requires at least one allowed root: %w", ErrInvalidAllowedRoots)
	}
	seen := make(map[string]bool)
	var canonical []string
	for _, r := range roots {
		resolved, err := validatePrincipalAllowedRootForAdd(r)
		if err != nil {
			return nil, err
		}
		if !isWithinAnyAllowedRoot(resolved, effectivePrincipalRoots) {
			return nil, fmt.Errorf("path %q is not under the effective principal roots: %w", resolved, ErrLauncherRootOutsidePrincipal)
		}
		if !seen[resolved] {
			seen[resolved] = true
			canonical = append(canonical, resolved)
		}
	}
	return canonical, nil
}

// defaultLauncherName is the conventional Launcher name used when a caller
// omits the name on create or the selector on individual Launcher commands.
// It is a normal Launcher name, not a subtype or a global singleton.
const defaultLauncherName = "default"

// launcherNameMaxLength is the maximum Launcher-name length.
const launcherNameMaxLength = 63

// validateLauncherName enforces the canonical Launcher-name grammar
// ^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$: 1..63 characters of lowercase ASCII
// letters, digits, and hyphens, with alphanumeric first and last characters.
// Names are identifiers: the exact supplied value is accepted or rejected,
// never trimmed or case-folded into validity.
func validateLauncherName(name string) (string, error) {
	if len(name) == 0 || len(name) > launcherNameMaxLength {
		return "", ErrInvalidLauncherName
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-':
			if i == 0 || i == len(name)-1 {
				return "", ErrInvalidLauncherName
			}
		default:
			return "", ErrInvalidLauncherName
		}
	}
	return name, nil
}

// createLauncher creates a Launcher (and its optional singular credential in
// the same transaction) beneath the given Principal. Restricted roots are
// canonicalized and validated against the current effective Principal ceiling
// before any mutation. Returns the Launcher projection and, when
// issueCredential is true, the issued credential metadata and its bearer secret
// exactly once.
func createLauncher(db *sql.DB, principalID int64, name string, scope LauncherScopeMode, allowedRoots []string, globalAllowedRoots []string, issueCredential bool) (*LauncherWithPrincipal, *launcherCredential, string, error) {
	name, err := validateLauncherName(name)
	if err != nil {
		return nil, nil, "", err
	}
	if scope != LauncherScopeInherit && scope != LauncherScopeRestricted {
		return nil, nil, "", fmt.Errorf("unknown scope %q: %w", scope, ErrInvalidScope)
	}

	// Resolve the owning Principal's name authoritatively from the database
	// rather than trusting a caller-supplied name argument, so the returned
	// projection and error messages always agree with the principals table.
	owner, err := findPrincipalByID(db, int(principalID))
	if err != nil {
		return nil, nil, "", err
	}
	principalName := owner.Username

	var canonicalRoots []string
	if scope == LauncherScopeRestricted {
		if len(allowedRoots) == 0 {
			return nil, nil, "", fmt.Errorf("restricted scope requires at least one allowed root: %w", ErrInvalidAllowedRoots)
		}
		effective, err := effectivePrincipalRoots(db, principalID, globalAllowedRoots)
		if err != nil {
			return nil, nil, "", err
		}
		canonicalRoots, err = validateLauncherAllowedRoots(allowedRoots, effective)
		if err != nil {
			return nil, nil, "", err
		}
	} else {
		if len(allowedRoots) > 0 {
			return nil, nil, "", fmt.Errorf("inherit scope cannot carry allowed roots: %w", ErrInvalidAllowedRoots)
		}
		scope = LauncherScopeInherit
	}

	id, err := generateLauncherID()
	if err != nil {
		return nil, nil, "", err
	}
	now := time.Now().Unix()

	tx, err := db.Begin()
	if err != nil {
		return nil, nil, "", fmt.Errorf("cannot begin transaction: %w", err)
	}
	defer tx.Rollback()

	_, err = tx.Exec(
		`INSERT INTO launchers (id, principal_id, name, enabled, scope_mode, created_at)
		 VALUES (?, ?, ?, 1, ?, ?)`,
		id, principalID, name, string(scope), now,
	)
	if err != nil {
		if isSQLiteUniqueError(err) {
			return nil, nil, "", fmt.Errorf("launcher %q already exists for principal %q: %w", name, principalName, ErrLauncherExists)
		}
		return nil, nil, "", fmt.Errorf("cannot create launcher: %w", err)
	}

	if scope == LauncherScopeRestricted {
		for _, root := range canonicalRoots {
			if _, err := tx.Exec(
				`INSERT INTO launcher_allowed_roots (launcher_id, root_path) VALUES (?, ?)`,
				id, root,
			); err != nil {
				return nil, nil, "", fmt.Errorf("cannot add launcher allowed root: %w", err)
			}
		}
	}

	var cred *launcherCredential
	var token string
	if issueCredential {
		cred, token, err = issueLauncherCredentialInTx(tx, id)
		if err != nil {
			return nil, nil, "", err
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, nil, "", fmt.Errorf("cannot commit launcher creation: %w", err)
	}

	// Construct the returned projection from known committed values. No DB read
	// is required after commit, so a successful commit cannot be followed by a
	// fallible lookup that would lose the one-time bearer secret.
	l := &LauncherWithPrincipal{
		ID:            id,
		PrincipalID:   principalID,
		PrincipalName: principalName,
		Name:          name,
		Enabled:       true,
		ScopeMode:     scope,
		AllowedRoots:  canonicalRoots,
		CreatedAt:     time.Unix(now, 0),
	}
	return l, cred, token, nil
}

// replaceLauncherScope atomically replaces a Launcher's scope and complete
// stored root set. For restricted scope all roots are canonicalized and
// validated against the current effective Principal ceiling before any
// mutation; a failed replacement leaves the old scope/roots unchanged.
func replaceLauncherScope(db *sql.DB, launcherID string, scope LauncherScopeMode, allowedRoots []string, globalAllowedRoots []string) (*LauncherWithPrincipal, error) {
	cur, err := findLauncherByID(db, launcherID)
	if err != nil {
		return nil, err
	}
	if scope != LauncherScopeInherit && scope != LauncherScopeRestricted {
		return nil, fmt.Errorf("unknown scope %q: %w", scope, ErrInvalidScope)
	}

	var canonicalRoots []string
	if scope == LauncherScopeRestricted {
		if len(allowedRoots) == 0 {
			return nil, fmt.Errorf("restricted scope requires at least one allowed root: %w", ErrInvalidAllowedRoots)
		}
		effective, err := effectivePrincipalRoots(db, cur.PrincipalID, globalAllowedRoots)
		if err != nil {
			return nil, err
		}
		canonicalRoots, err = validateLauncherAllowedRoots(allowedRoots, effective)
		if err != nil {
			return nil, err
		}
	} else {
		if len(allowedRoots) > 0 {
			return nil, fmt.Errorf("inherit scope cannot carry allowed roots: %w", ErrInvalidAllowedRoots)
		}
		scope = LauncherScopeInherit
	}

	tx, err := db.Begin()
	if err != nil {
		return nil, fmt.Errorf("cannot begin transaction: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`UPDATE launchers SET scope_mode = ? WHERE id = ?`, string(scope), launcherID); err != nil {
		return nil, fmt.Errorf("cannot update launcher scope: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM launcher_allowed_roots WHERE launcher_id = ?`, launcherID); err != nil {
		return nil, fmt.Errorf("cannot clear launcher allowed roots: %w", err)
	}
	for _, root := range canonicalRoots {
		if _, err := tx.Exec(
			`INSERT INTO launcher_allowed_roots (launcher_id, root_path) VALUES (?, ?)`,
			launcherID, root,
		); err != nil {
			return nil, fmt.Errorf("cannot add launcher allowed root: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("cannot commit launcher scope replacement: %w", err)
	}
	return findLauncherByID(db, launcherID)
}
