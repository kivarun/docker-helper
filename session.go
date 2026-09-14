package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

var ErrSessionNotFound = errors.New("session not found")
var ErrInvalidWorkspace = errors.New("invalid workspace")
var ErrDatabase = errors.New("database error")
var ErrSystem = errors.New("system error")
var ErrMAC = errors.New("MAC preparation failed")

// The canonical issued Session ID shape: the production prefix plus exactly
// sessionIDHexLength lowercase hex characters (16 random bytes).
const (
	sessionIDPrefix    = "dhs_"
	sessionIDHexLength = 32
)

// classifyCreateSessionError classifies a Session-create failure into its
// stable audit/HTTP result code.
func classifyCreateSessionError(err error) string {
	switch {
	case errors.Is(err, ErrInvalidWorkspace):
		return "invalid_workspace"
	case errors.Is(err, ErrInvalidSessionFilesystemPolicy):
		return "invalid_filesystem_policy"
	case errors.Is(err, ErrDatabase):
		return "database_error"
	case errors.Is(err, ErrSystem):
		return "system_error"
	case errors.Is(err, ErrMAC):
		return "mac_preparation_failed"
	default:
		return "unknown_error"
	}
}

// sqlScanner is satisfied by *sql.Row and *sql.Rows.
type sqlScanner interface {
	Scan(dest ...any) error
}

// Session is the final owner resolution of a Launcher-backed Session. The
// Launcher is the owner; the Principal and its name are derived projections via
// the owning Launcher. There is no ownerless Session and no separate Session
// owner authority beyond the Launcher.
type Session struct {
	ID            string
	Workspace     string
	CreatedAt     time.Time
	ExpiresAt     time.Time
	LauncherID    string
	LauncherName  string
	PrincipalName string
}

type CreatedSession struct {
	Session Session
	Token   string

	// FilesystemSnapshot is the immutable snapshot committed atomically with
	// the Session row: the response/test projection of the persisted Session
	// authority, not a second long-lived authoritative copy (the persisted
	// Session child state remains the one owner).
	FilesystemSnapshot *sessionFilesystemSnapshot
}

// scanSessionWithOwnership scans the final Launcher-owned session projection
// joined with its owning Launcher and that Launcher's Principal. Columns:
// id, workspace, created_at, expires_at, launcher_id, launcher_name,
// principal_username. This is the single Session projection helper.
func scanSessionWithOwnership(s sqlScanner) (Session, error) {
	var sess Session
	var createdAt int64
	var expiresAt int64

	if err := s.Scan(&sess.ID, &sess.Workspace, &createdAt, &expiresAt, &sess.LauncherID, &sess.LauncherName, &sess.PrincipalName); err != nil {
		return sess, err
	}

	sess.CreatedAt = time.Unix(createdAt, 0)
	sess.ExpiresAt = time.Unix(expiresAt, 0)

	return sess, nil
}

// sessionOwnershipProjection is the SQL projection columns shared by every
// Session ownership query, joined through launchers to principals. It is the
// single authoritative JOIN for Session ownership.
const sessionOwnershipProjection = `
	s.id, s.workspace, s.created_at, s.expires_at, s.launcher_id, l.name, p.username
	FROM sessions s
	JOIN launchers l ON l.id = s.launcher_id
	JOIN principals p ON p.id = l.principal_id`

// sessionCreatePolicy contains the resolved context needed to create a session.
// LauncherID is the resolved owning Launcher. EffectiveAllowedRoots is the
// already-computed effective session-creation allowed-root scope (the
// three-level evaluation result) in its authoritative rich form;
// EffectiveAllowedRootPaths is the same scope's derived 2.1 path-only
// projection — both are projected from one canonical evaluation, never
// computed twice. FilesystemRoots carries the caller-supplied
// issuance-time Session filesystem roots (nil when the request omitted
// filesystem_roots or carried the empty array); they are consumed by
// createSessionWithPolicyLocked inside the same lifecycle linearization
// boundary and are never applied as a post-create policy change.
// Credential carries the commit-boundary credential revalidation facts of a
// credential-authority create (nil for the admin authority, which
// authenticates by in-memory token comparison and has no credential row).
type sessionCreatePolicy struct {
	Workspace                 string
	EffectiveAllowedRoots     []AllowedRootEntry
	EffectiveAllowedRootPaths []string
	FilesystemRoots           []sessionFilesystemRootEntry
	LauncherID                string
	LauncherName              string
	PrincipalName             string
	Credential                *sessionCreateCredentialAuthority
}

// sessionCreateCredentialAuthority is the credential provenance a
// credential-authority Session create revalidates at its commit boundary:
// the exact credential row that authenticated the request and the owner
// identity that row must still prove (principalID for a Principal
// credential, launcherID for a Launcher credential) when the Session
// commits. Authentication established it once; the commit transaction
// re-proves it against the same credential store the authenticator reads.
type sessionCreateCredentialAuthority struct {
	credentialID string
	principalID  int64  // Principal credential authority
	launcherID   string // Launcher credential authority
}

// createSessionWithPolicyLocked is the internal persistence/MAC stage beneath
// createSessionAuthorized: the lifecycle serialization is already held, so
// policy resolution and persistence cannot interleave with an authority
// mutation. It performs one lifecycle critical section from workspace
// validation through MAC preparation and the conditional final persistence.
func (a *App) createSessionWithPolicyLocked(p *sessionCreatePolicy) (*CreatedSession, error) {
	if p.Workspace == "" {
		return nil, fmt.Errorf("workspace is required: %w", ErrInvalidWorkspace)
	}
	if p.LauncherID == "" {
		return nil, fmt.Errorf("launcher is required: %w", ErrInvalidWorkspace)
	}

	absWorkspace, err := filepath.Abs(p.Workspace)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve workspace path: %w: %w", err, ErrInvalidWorkspace)
	}

	if len(p.EffectiveAllowedRootPaths) == 0 {
		return nil, fmt.Errorf("no allowed roots configured: %w", ErrInvalidWorkspace)
	}

	// Authorization ceiling first (H3): the raw request spelling must be
	// lexically inside the effective allowed-root ceiling BEFORE any
	// privileged host-filesystem probing. A spelling outside the ceiling is
	// refused immediately without EvalSymlinks/stat — no existence, error
	// class, path type, or resolved alias of the requested pathname is ever
	// collected or disclosed. There is no compatibility alias for a
	// spelling outside the ceiling that would resolve into it: the
	// caller-controlled raw spelling must carry the lexical capability
	// admission itself.
	rawSpelling := filepath.Clean(absWorkspace)
	if !isWithinAnyAllowedRoot(rawSpelling, p.EffectiveAllowedRootPaths) {
		return nil, fmt.Errorf("workspace must be inside an allowed root: %w", ErrInvalidWorkspace)
	}

	// Filesystem mechanics after admission: resolution and type checks run
	// only on an admitted spelling, and the canonical containment proof
	// below remains the second, mandatory security proof — a symlink inside
	// the lexical ceiling that resolves outside is still fail-closed.
	absWorkspace, err = evalSymlinksFn(absWorkspace)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve workspace symlinks: %w: %w", err, ErrInvalidWorkspace)
	}

	info, err := osStatFn(absWorkspace)
	if err != nil {
		return nil, fmt.Errorf("cannot access workspace: %w: %w", err, ErrInvalidWorkspace)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("workspace is not a directory: %w", ErrInvalidWorkspace)
	}

	// Check workspace is inside at least one allowed root and is a proper
	// subdirectory (not the root itself).
	inside := false
	for _, root := range p.EffectiveAllowedRootPaths {
		if absWorkspace == root {
			continue
		}
		if pathWithin(root, absWorkspace) {
			inside = true
			break
		}
	}
	if !inside {
		return nil, fmt.Errorf("workspace must be inside an allowed root: %w", ErrInvalidWorkspace)
	}

	// Issuance-time Session filesystem roots (Release 2.2): when the create
	// request supplied filesystem_roots, the caller-supplied absolute host
	// paths are canonicalized (symlink resolution, existing directory or
	// regular file) and proven to be a narrowing-only composition of the
	// effective Launcher ceiling — the requested scope is the implicit
	// workspace grant at the effective ceiling mode, replaced by an explicit
	// workspace root, plus the canonicalized roots — before the existing
	// composition owner composes and normalizes them. A request that widens
	// the ceiling is refused here, before any Session state exists; an
	// omitted or empty request keeps the inherited derivation,
	// byte-for-byte compatible with the pre-filesystem-roots create path.
	// This runs inside the lifecycleMu create linearization boundary held
	// by createSessionAuthorized, so the ceiling the request is proven
	// against is exactly the ceiling the snapshot is committed from.
	var snapshotEntries []AllowedRootEntry
	if len(p.FilesystemRoots) > 0 {
		requested, err := canonicalizeSessionFilesystemRoots(p.FilesystemRoots, p.EffectiveAllowedRootPaths)
		if err != nil {
			return nil, err
		}
		// User-mode backend-safety boundary (Release 2.2): user mode has no
		// stable-object handoff for a bind source — the openat2/open_tree
		// pinning owner needs CAP_SYS_ADMIN, so the canonical resolved path
		// would still be consumed by dockerd through its pathname. Only the
		// canonical workspace root carries the established pathname-stability
		// invariant (the sandbox cannot write its parent, so it cannot
		// replace the workspace directory entry). An explicit filesystem root
		// is therefore accepted only when its canonical path equals the
		// canonical workspace — which preserves the explicit workspace
		// read_only narrowing through the same composition owner below — and
		// every additional, disjoint, or child root is refused before any
		// Session exists. This is a backend-safety boundary, not a second
		// filesystem policy engine: the immutable Session snapshot remains
		// the filesystem access-mode owner and this check never decides
		// access modes.
		if a.getConfig().Mode != ModeSystem {
			for _, root := range requested {
				if root.Path != absWorkspace {
					return nil, fmt.Errorf("user mode accepts only the canonical workspace as a session filesystem root (%q): %w", root.Path, ErrInvalidSessionFilesystemPolicy)
				}
			}
		}
		snapshotEntries, err = narrowSessionFilesystemPolicy(p.EffectiveAllowedRoots, absWorkspace, requested)
		if err != nil {
			return nil, err
		}
	} else {
		derived, err := deriveSessionFilesystemSnapshot(p.EffectiveAllowedRoots, absWorkspace)
		if err != nil {
			return nil, fmt.Errorf("cannot derive session filesystem snapshot: %w", err)
		}
		snapshotEntries = derived.Entries
	}

	// Construct the immutable Session filesystem snapshot at the
	// Session-create linearization point: lifecycleMu is already held by
	// createSessionAuthorized, so the snapshot corresponds exactly to the
	// policy state of this Session-create critical section. The effective
	// entries — composed when the request supplied filesystem_roots — are
	// the only parent-policy input; no policy is re-read after derivation.
	// A construction failure fails the Session creation before any
	// persistence.
	snapshot, err := newSessionFilesystemSnapshot(absWorkspace, snapshotEntries)
	if err != nil {
		return nil, fmt.Errorf("cannot construct session filesystem snapshot: %w", err)
	}

	// Generate Session identity and bearer after policy resolution and before
	// MAC/persistence work; lifecycleMu is already held by
	// createSessionAuthorized. The canonical issued Session ID shape is the
	// production prefix plus exactly sessionIDHexLength lowercase hex
	// characters (16 random bytes); durable ownership proofs validate
	// against this exact shape.
	idBytes := make([]byte, sessionIDHexLength/2)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, fmt.Errorf("cannot generate session ID: %w: %w", err, ErrSystem)
	}
	sessionID := sessionIDPrefix + hex.EncodeToString(idBytes)

	token, err := generateSessionToken()
	if err != nil {
		return nil, fmt.Errorf("cannot generate session token: %w: %w", err, ErrSystem)
	}
	tokenHash := sha256.Sum256([]byte(token))
	tokenHashHex := hex.EncodeToString(tokenHash[:])

	now := time.Now()
	expiresAt := now.Add(a.getConfig().SessionTTL)

	// Acquire coordinator serialization and prepare MAC.
	// CreateSessionBinding holds the lock through DB insert and rollback.
	insertSession := func() error {
		tx, err := a.DB.Begin()
		if err != nil {
			return fmt.Errorf("cannot begin session creation transaction: %w", err)
		}
		defer tx.Rollback()

		// Conditional insert: only succeeds if the owning Launcher and its
		// Principal both exist and are enabled, and — for a credential
		// authority — if the exact authorizing credential still exists,
		// still carries the authenticated owner identity, and is still
		// active. The commit-boundary credential predicate is evaluated in
		// the same statement as the insert (the create transaction's commit
		// point), so a credential revoke/delete that commits before the
		// Session commit prevents that Session; the pre-existing
		// launcher/principal predicates are unchanged and the admin
		// authority carries no credential clause (the admin token is
		// compared in memory and has no credential row).
		query := `INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at, launcher_id)
			 SELECT ?, ?, ?, ?, ?, ?
			 FROM launchers l JOIN principals p ON p.id = l.principal_id
			 WHERE l.id = ? AND l.enabled = 1 AND p.enabled = 1`
		args := []any{
			sessionID,
			tokenHashHex,
			absWorkspace,
			now.Unix(),
			expiresAt.Unix(),
			p.LauncherID,
			p.LauncherID,
		}
		if p.Credential != nil {
			switch {
			case p.Credential.launcherID != "":
				query += ` AND EXISTS (SELECT 1 FROM credentials c
					 WHERE c.id = ? AND c.launcher_id = ? AND c.revoked_at IS NULL)`
				args = append(args, p.Credential.credentialID, p.Credential.launcherID)
			default:
				query += ` AND EXISTS (SELECT 1 FROM credentials c
					 WHERE c.id = ? AND c.principal_id = ? AND c.launcher_id IS NULL AND c.revoked_at IS NULL)`
				args = append(args, p.Credential.credentialID, p.Credential.principalID)
			}
		}
		result, err := tx.Exec(query, args...)
		if err != nil {
			return err
		}
		// Verify exactly one row was inserted. If zero, the Launcher, its
		// Principal, or the authorizing credential was disabled, deleted, or
		// revoked between authentication and this insert. Under lifecycle
		// serialization the enabled-state part cannot interleave with a
		// policy mutation, so it surfaces only as a defense-in-depth
		// recheck; the credential part is the commit-boundary revocation
		// race closure. The stale-owner rejection is a deterministic typed
		// contract (422 launcher_unavailable), the credential rejection the
		// canonical non-disclosing 401 credential classes, never an
		// invalid_workspace relabel.
		inserted, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("cannot check session insert result: %w", err)
		}
		if inserted == 0 {
			return fmt.Errorf("session create stale-authority rejection: %w", classifyStaleSessionCreateAuthority(tx, p))
		}

		// The snapshot entries commit in the same transaction as the Session
		// row: there is never a committed Session bearer whose Session row
		// lacks its filesystem snapshot.
		if err := insertSessionFilesystemSnapshot(tx, sessionID, snapshot.Entries); err != nil {
			return fmt.Errorf("cannot persist session filesystem snapshot: %w", err)
		}
		return tx.Commit()
	}

	if a.MACCoordinator != nil {
		_, err := a.MACCoordinator.CreateSessionBinding(sessionID, sessionMACBoundaries(snapshot), func([]sessionMACCoverage) error {
			return insertSession()
		})
		if err != nil {
			// Classify: stale-owner recheck, commit-boundary credential
			// rejection, MAC preparation, and DB insert errors. The typed
			// stale-authority contracts keep their classes.
			switch {
			case errors.Is(err, ErrLauncherUnavailable),
				errors.Is(err, ErrCredentialRevoked),
				errors.Is(err, ErrCredentialNotFound):
				return nil, fmt.Errorf("cannot create session: %w", err)
			case errors.Is(err, ErrMACPreparation):
				return nil, fmt.Errorf("cannot create session: %w: %w", err, ErrMAC)
			default:
				return nil, fmt.Errorf("cannot create session: %w: %w", err, ErrDatabase)
			}
		}
	} else {
		if err := insertSession(); err != nil {
			switch {
			case errors.Is(err, ErrLauncherUnavailable),
				errors.Is(err, ErrCredentialRevoked),
				errors.Is(err, ErrCredentialNotFound):
				// Deterministic typed stale-authority contracts keep their
				// classes: the launcher-shaped rejection (422
				// launcher_unavailable) and the canonical credential
				// rejection (the non-disclosing 401 credential classes).
				return nil, fmt.Errorf("cannot create session: %w", err)
			}
			return nil, fmt.Errorf("cannot create session: %w: %w", err, ErrDatabase)
		}
	}

	return &CreatedSession{
		Session: Session{
			ID:            sessionID,
			Workspace:     absWorkspace,
			CreatedAt:     now,
			ExpiresAt:     expiresAt,
			LauncherID:    p.LauncherID,
			LauncherName:  p.LauncherName,
			PrincipalName: p.PrincipalName,
		},
		Token:              token,
		FilesystemSnapshot: snapshot,
	}, nil
}

// classifyStaleSessionCreateAuthority distinguishes the zero-row outcome of
// the conditional Session insert, inside the same create transaction the
// insert ran in (one snapshot: the classification observes exactly the state
// the insert predicate evaluated). The launcher/principal availability
// recheck comes first and keeps the pre-existing typed
// ErrLauncherUnavailable contract; a credential-authority create whose
// launcher is still available is then classified through the same canonical
// credential failure classes the credential authenticator produces — the
// credential row is gone (deleted, re-owned, or otherwise no longer the
// authenticated authority) or its revoked_at is set. Any other outcome is an
// insert recheck inconsistency and fails closed as a database error.
func classifyStaleSessionCreateAuthority(tx *sql.Tx, p *sessionCreatePolicy) error {
	var launcherCount int
	if err := tx.QueryRow(
		`SELECT COUNT(*) FROM launchers l JOIN principals p ON p.id = l.principal_id
		 WHERE l.id = ? AND l.enabled = 1 AND p.enabled = 1`,
		p.LauncherID,
	).Scan(&launcherCount); err != nil {
		return fmt.Errorf("cannot recheck launcher availability: %w", err)
	}
	if launcherCount == 0 {
		return ErrLauncherUnavailable
	}
	if p.Credential == nil {
		// Without a credential clause the insert predicate is the
		// availability predicate alone; an available launcher with zero
		// inserted rows is an insert recheck inconsistency.
		return fmt.Errorf("session insert recheck inconsistency: %w", ErrDatabase)
	}
	var revokedAt sql.NullInt64
	var credQuery string
	var credArgs []any
	if p.Credential.launcherID != "" {
		credQuery = `SELECT revoked_at FROM credentials WHERE id = ? AND launcher_id = ?`
		credArgs = []any{p.Credential.credentialID, p.Credential.launcherID}
	} else {
		credQuery = `SELECT revoked_at FROM credentials WHERE id = ? AND principal_id = ? AND launcher_id IS NULL`
		credArgs = []any{p.Credential.credentialID, p.Credential.principalID}
	}
	err := tx.QueryRow(credQuery, credArgs...).Scan(&revokedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("authorizing credential no longer exists for the authenticated owner: %w", ErrCredentialNotFound)
		}
		return fmt.Errorf("cannot recheck credential authority: %w", err)
	}
	if revokedAt.Valid {
		return fmt.Errorf("authorizing credential is revoked: %w", ErrCredentialRevoked)
	}
	return fmt.Errorf("session insert recheck inconsistency: %w", ErrDatabase)
}

// canonicalizeSessionFilesystemRoots converts caller-supplied absolute
// filesystem roots into canonical AllowedRootEntry values, ready for
// narrowSessionFilesystemPolicy.
//
// Each root must be an absolute host path; it is cleaned and must be
// lexically inside the effective allowed-root ceiling — the raw spelling
// carries the authorization admission itself — BEFORE any privileged
// host-filesystem probing. A spelling outside the ceiling is refused
// immediately without EvalSymlinks/stat: no existence, error class, path
// type, or resolved alias of the requested pathname is ever collected or
// disclosed, and there is no compatibility alias for a spelling outside the
// ceiling that would resolve into it. An admitted spelling is resolved
// through symlinks and must exist as a directory or a regular file — the
// resolved canonical path becomes the policy identity, so a symlink alias
// never creates a second authority identity and two spellings of one
// canonical path are a duplicate refusal. The canonical root must still be
// authorized by the effective Launcher ceiling: narrowSessionFilesystemPolicy
// proves that canonical containment against the resolved ceiling inside the
// same create linearization boundary as the second, mandatory security
// proof, so a symlink inside the lexical ceiling that resolves outside is
// still fail-closed. The orchestrator (or operator) creates the root before
// creating the Session, so an unresolvable root — whose canonical identity
// cannot be proven — is a refusal, never a guess. Every failure wraps
// ErrInvalidSessionFilesystemPolicy: one refusal family governs the whole
// Session filesystem request.
func canonicalizeSessionFilesystemRoots(roots []sessionFilesystemRootEntry, ceilingPaths []string) ([]AllowedRootEntry, error) {
	canonical := make([]AllowedRootEntry, 0, len(roots))
	for _, root := range roots {
		if root.Path == "" || !filepath.IsAbs(root.Path) {
			return nil, fmt.Errorf("filesystem root %q is not an absolute host path: %w", root.Path, ErrInvalidSessionFilesystemPolicy)
		}
		access, err := parseAllowedRootAccess(root.Access)
		if err != nil {
			return nil, fmt.Errorf("filesystem root %q: %v: %w", root.Path, err, ErrInvalidSessionFilesystemPolicy)
		}
		cleaned := filepath.Clean(root.Path)

		// Authorization ceiling first (H3): the raw cleaned spelling must be
		// lexically inside the effective allowed-root ceiling BEFORE any
		// privileged host-filesystem probing. A spelling outside the ceiling
		// is refused immediately without EvalSymlinks/stat.
		if !isWithinAnyAllowedRoot(cleaned, ceilingPaths) {
			return nil, fmt.Errorf("filesystem root %q is outside the effective launcher policy: %w", root.Path, ErrInvalidSessionFilesystemPolicy)
		}

		// Filesystem mechanics after admission: resolution and type checks
		// run only on an admitted spelling, and the canonical ceiling proof
		// in narrowSessionFilesystemPolicy remains the second, mandatory
		// security proof.
		resolved, err := evalSymlinksFn(cleaned)
		if err != nil {
			return nil, fmt.Errorf("filesystem root %q cannot be resolved: %w", root.Path, ErrInvalidSessionFilesystemPolicy)
		}
		info, err := osStatFn(resolved)
		if err != nil {
			return nil, fmt.Errorf("filesystem root %q cannot be accessed: %w", root.Path, ErrInvalidSessionFilesystemPolicy)
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return nil, fmt.Errorf("filesystem root %q is not a directory or regular file: %w", root.Path, ErrInvalidSessionFilesystemPolicy)
		}
		canonical = append(canonical, AllowedRootEntry{Path: resolved, Access: access})
	}
	if err := validateCanonicalAllowedRootEntries(canonical); err != nil {
		return nil, fmt.Errorf("session filesystem roots: %v: %w", err, ErrInvalidSessionFilesystemPolicy)
	}
	return canonical, nil
}

// createSessionAuthorized is the single linearized Session-create owner for an
// authenticated authority: it holds the lifecycle serialization across
// current-policy resolution (resolveCreatePolicy) through final Session
// persistence, so a concurrent narrowing of any policy authority (global
// allowed roots, Principal allowed roots, Launcher scope, Launcher/Principal
// enabled state, Launcher existence/ownership) that linearizes before the
// create commits prevents that Session, and one that linearizes after leaves
// the created Session intact. It never mutates policy; it only consumes it.
// filesystemRoots is the caller-supplied issuance-time Session filesystem
// request (nil when the request omitted filesystem_roots or carried the
// empty array); it is proven and composed inside this boundary.
func (a *App) createSessionAuthorized(auth *operatorAuthority, sel createSelector, workspace string, filesystemRoots []sessionFilesystemRootEntry) (*CreatedSession, error) {
	a.lifecycleMu.Lock()
	defer a.lifecycleMu.Unlock()

	policy, err := a.resolveCreatePolicy(auth, sel, workspace, filesystemRoots)
	if err != nil {
		return nil, err
	}
	return a.createSessionWithPolicyLocked(policy)
}

// listSessionsInScope returns active sessions owned within the given
// ownership scope. Admin lists all Launcher-owned Sessions, a Principal scope
// lists the Sessions owned by that Principal's Launchers, and a Launcher scope
// lists that Launcher's Sessions. The scope is expressed directly in the
// ownership query (which JOINs launchers and principals), so no Launcher
// enumeration or stale snapshot is involved.
func (a *App) listSessionsInScope(scope sessionControlScope) ([]Session, error) {
	now := time.Now().Unix()

	pred, args := sessionScopePredicate(scope)

	rows, err := a.DB.Query(
		`SELECT `+sessionOwnershipProjection+`
		 WHERE s.expires_at > ?`+pred+`
		 ORDER BY s.created_at ASC`,
		append([]any{now}, args...)...,
	)
	if err != nil {
		return nil, fmt.Errorf("cannot list sessions: %w", err)
	}
	defer rows.Close()

	var sessions []Session
	for rows.Next() {
		s, err := scanSessionWithOwnership(rows)
		if err != nil {
			return nil, fmt.Errorf("cannot scan session: %w", err)
		}
		sessions = append(sessions, s)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate sessions: %w", err)
	}

	return sessions, nil
}

// deleteSessionScoped deletes a session by id within a scope, returning its
// metadata for audit. A session outside the scope is not found (non-disclosing).
// The scope is expressed directly in the ownership query; admin deletes any
// Session.
func (a *App) deleteSessionScoped(id string, scope sessionControlScope) (*Session, error) {
	pred, args := sessionScopePredicate(scope)

	selectArgs := append([]any{id}, args...)
	row := a.DB.QueryRow(
		`SELECT `+sessionOwnershipProjection+`
		 WHERE s.id = ?`+pred,
		selectArgs...,
	)

	s, err := scanSessionWithOwnership(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("session not found: %w", ErrSessionNotFound)
		}
		return nil, fmt.Errorf("cannot find session: %w: %w", err, ErrDatabase)
	}

	deletePred, deleteArgs := sessionDeletePredicate(scope)
	deleteArgs = append([]any{id}, deleteArgs...)
	result, err := a.DB.Exec(`DELETE FROM sessions WHERE id = ?`+deletePred, deleteArgs...)
	if err != nil {
		return &s, fmt.Errorf("cannot delete session: %w: %w", err, ErrDatabase)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return &s, fmt.Errorf("cannot check deletion result: %w: %w", err, ErrDatabase)
	}

	if rowsAffected == 0 {
		return nil, fmt.Errorf("session not found: %w", ErrSessionNotFound)
	}

	// Release MAC boundary for the deleted session.
	if a.MACCoordinator != nil {
		a.MACCoordinator.ReleaseSessionBinding(id)
	}

	return &s, nil
}

// findSessionInScope returns the Session with the given ID when it belongs to
// the given ownership scope, or ErrSessionNotFound otherwise (non-disclosing:
// a missing or foreign Session is the same not-found outcome). The scope is
// expressed directly in the ownership query; admin reads any Session. This is
// the read-only form of the deleteSessionScoped lookup.
func (a *App) findSessionInScope(id string, scope sessionControlScope) (*Session, error) {
	pred, args := sessionScopePredicate(scope)

	row := a.DB.QueryRow(
		`SELECT `+sessionOwnershipProjection+`
		 WHERE s.id = ?`+pred,
		append([]any{id}, args...)...,
	)

	s, err := scanSessionWithOwnership(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("session not found: %w", ErrSessionNotFound)
		}
		return nil, fmt.Errorf("cannot find session: %w: %w", err, ErrDatabase)
	}
	return &s, nil
}

// sessionDeletePredicate returns the SQL predicate and args that restrict a
// standalone DELETE FROM sessions statement to the given scope. Unlike the
// ownership SELECT (which JOINs launchers/principals and can reference their
// aliases), a DELETE has no join aliases, so the scope is expressed through an
// explicit subquery. Admin deletes any Session.
func sessionDeletePredicate(scope sessionControlScope) (string, []any) {
	switch {
	case scope.admin:
		return "", nil
	case scope.launcherID != "":
		return " AND launcher_id = ?", []any{scope.launcherID}
	case scope.principalID != 0:
		return " AND launcher_id IN (SELECT id FROM launchers WHERE principal_id = ?)", []any{scope.principalID}
	default:
		return " AND 0", nil
	}
}

// sessionScopePredicate returns the SQL predicate and args that restrict a
// Session ownership query to the given scope. The predicate is appended after
// "WHERE s.expires_at > ?" (list) or "WHERE s.id = ?" (delete) and references
// the launchers/principals aliases the shared ownership projection JOINs. An
// empty/invalid scope matches nothing (fail-closed) rather than broadening.
func sessionScopePredicate(scope sessionControlScope) (string, []any) {
	switch {
	case scope.admin:
		return "", nil
	case scope.launcherID != "":
		return " AND s.launcher_id = ?", []any{scope.launcherID}
	case scope.principalID != 0:
		return " AND l.principal_id = ?", []any{scope.principalID}
	default:
		return " AND 0", nil
	}
}

// resolveSessionExecutionIdentity returns the UID:GID for Docker --user for a
// Session, resolved through the owning Launcher to its Principal. There is no
// PrincipalID == nil (daemon) special case: every Session has a Launcher
// owner.
func resolveSessionExecutionIdentity(db *sql.DB, session *Session) (uid, gid int, err error) {
	var pUID, pGID int
	row := db.QueryRow(
		`SELECT p.uid, p.gid
		 FROM launchers l JOIN principals p ON p.id = l.principal_id
		 WHERE l.id = ?`,
		session.LauncherID,
	)
	if err := row.Scan(&pUID, &pGID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, 0, fmt.Errorf("launcher %q principal not found: %w", session.LauncherID, ErrDatabase)
		}
		return 0, 0, fmt.Errorf("cannot lookup launcher principal identity: %w", err)
	}

	return pUID, pGID, nil
}

func (a *App) findSessionByToken(token string) (*Session, error) {
	return findSessionByTokenQuerier(a.DB, token)
}

// findSessionByTokenQuerier is the one SQL owner of Session bearer
// authentication: the token-hash lookup requires a live (unexpired) Session
// owned by an enabled Launcher with an enabled Principal. The App-level
// findSessionByToken is a thin *sql.DB wrapper over this querier, and the
// coherent filesystem authority read reuses the same query inside its read
// transaction, so the auth semantics cannot drift between callers.
func findSessionByTokenQuerier(q txQuerier, token string) (*Session, error) {
	tokenHash := sha256.Sum256([]byte(token))
	tokenHashHex := hex.EncodeToString(tokenHash[:])

	now := time.Now().Unix()

	row := q.QueryRow(
		`SELECT `+sessionOwnershipProjection+`
		 WHERE s.token_hash = ? AND s.expires_at > ?
		 AND l.enabled = 1 AND p.enabled = 1
		 LIMIT 1`,
		tokenHashHex,
		now,
	)

	s, err := scanSessionWithOwnership(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrSessionNotFound
		}
		return nil, fmt.Errorf("cannot find session by token: %w", err)
	}

	return &s, nil
}

// sessionDockerDir returns the path to the session-scoped Docker config
// directory: $RUNTIME_DIR/sessions/<session-id>/docker/
func sessionDockerDir(runtimeDir, sessionID string) string {
	return filepath.Join(runtimeDir, "sessions", sessionID, "docker")
}

// ensureSessionDockerDir creates the session-scoped Docker config directory
// with restrictive permissions (0700) if it does not exist.
// Returns the directory path.
func ensureSessionDockerDir(runtimeDir, sessionID string) (string, error) {
	dir := sessionDockerDir(runtimeDir, sessionID)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("cannot create session Docker directory: %w", err)
	}
	return dir, nil
}

// sessionRuntimeDir returns the parent runtime directory for a session:
// $RUNTIME_DIR/sessions/<session-id>/
func sessionRuntimeDir(runtimeDir, sessionID string) string {
	return filepath.Join(runtimeDir, "sessions", sessionID)
}

// cleanupSessionRuntimeDir removes the session runtime directory best-effort.
// If the directory does not exist, it is not an error.
// Returns a non-nil error only if the directory exists but cannot be removed.
func cleanupSessionRuntimeDir(runtimeDir, sessionID string) error {
	dir := sessionRuntimeDir(runtimeDir, sessionID)
	if err := os.RemoveAll(dir); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("cannot remove session runtime directory: %w", err)
	}
	return nil
}

// cleanupSessionRuntimeDirsBestEffort removes the runtime directory of every
// invalidated session. Best-effort: a failure on one directory is logged with
// the given operation name and does not stop the remaining cleanups. Callers
// must invoke it regardless of their overall outcome whenever a durable
// session invalidation may already have committed, so a later teardown failure
// cannot lose the cleanup until daemon restart.
func cleanupSessionRuntimeDirsBestEffort(ctx context.Context, operation, runtimeDir string, sessionIDs []string) {
	for _, sessionID := range sessionIDs {
		if err := cleanupSessionRuntimeDir(runtimeDir, sessionID); err != nil {
			opLog(ctx).Warn("failed to clean up session runtime directory",
				slog.String("operation", operation),
				slog.String("session_id", sessionID),
				slog.String("error", err.Error()),
			)
		}
	}
}

// cleanupStaleSessionRuntimeDirs removes session runtime directories that no
// longer correspond to an active session. It reads all active session IDs from
// the database and removes any runtime directories whose session ID is not
// in that set. Expired sessions are excluded.
//
// This is best-effort: all stale directories are attempted, and any removal
// failures are accumulated and returned as a single error.
func cleanupStaleSessionRuntimeDirs(db *sql.DB, runtimeDir string) error {
	sessionsDir := filepath.Join(runtimeDir, "sessions")

	// List all active session IDs.
	now := time.Now().Unix()
	rows, err := db.Query(
		`SELECT id FROM sessions WHERE expires_at > ?`,
		now,
	)
	if err != nil {
		return fmt.Errorf("cannot query active sessions: %w", err)
	}

	active := make(map[string]bool)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return fmt.Errorf("cannot scan session id: %w", err)
		}
		active[id] = true
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate sessions: %w", err)
	}

	// Remove stale directories, accumulating errors.
	entries, err := os.ReadDir(sessionsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("cannot read sessions directory: %w", err)
	}

	var staleErrors []error
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if !active[entry.Name()] {
			dir := filepath.Join(sessionsDir, entry.Name())
			if removeErr := os.RemoveAll(dir); removeErr != nil {
				staleErrors = append(staleErrors, fmt.Errorf("%s: %w", entry.Name(), removeErr))
			}
		}
	}

	if len(staleErrors) > 0 {
		return fmt.Errorf("stale session cleanup failed (%d error(s)): %v", len(staleErrors), staleErrors)
	}
	return nil
}
