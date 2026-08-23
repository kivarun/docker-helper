package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sync"
)

// ErrMACPreparation is returned when MAC coverage cannot be ensured or verified.
var ErrMACPreparation = errors.New("MAC preparation failed")

// macCoverage describes the actual MAC coverage boundary for a workspace.
type macCoverage struct {
	Boundary string // the actual boundary path providing coverage
	Managed  bool   // true if docker-helper owns this boundary
}

// macBackend is the backend-specific adapter for workspace MAC operations.
// The backend MUST NOT query sessions or operations.
type macBackend interface {
	// ensureCoverage ensures MAC coverage for a concrete canonical workspace.
	// Returns the actual coverage boundary (may be the workspace or an ancestor).
	// created is true if a new boundary was created.
	ensureCoverage(workspace string) (coverage macCoverage, created bool, err error)

	// verifyCoverage checks that a workspace has valid MAC coverage without
	// mutating state. Returns the actual coverage boundary.
	verifyCoverage(workspace string) (coverage macCoverage, err error)

	// removeBoundary removes a docker-helper-owned managed boundary.
	// Only called when the lifecycle has verified ownership.
	removeBoundary(boundary string) error

	// listManagedBoundaries returns all boundaries that this backend manages.
	// Used during reconciliation to import pre-existing managed boundaries
	// into ownership metadata.
	listManagedBoundaries() ([]string, error)

	// backendType returns the backend identifier ("apparmor" or "selinux").
	backendType() string
}

// workspaceMACLifecycle is the single internal owner of workspace MAC state.
// It serializes all lifecycle transitions, tracks active consumers, and
// coordinates with the backend-specific adapter.
type workspaceMACLifecycle struct {
	mu      sync.Mutex
	db      *sql.DB
	backend macBackend

	// sessionBindings maps session ID to the exact MAC coverage boundary.
	sessionBindings map[string]macCoverage

	// activeBoundaries maps boundary path to direct consumer count.
	activeBoundaries map[string]int

	// deferredBoundaries tracks helper-owned boundaries that cannot yet be
	// removed because an intersecting session/boundary is live. These are
	// retried for cleanup when any consumer disappears.
	deferredBoundaries map[string]bool

	// leases maps unique lease key to workspace.
	leases map[string]string
}

func newWorkspaceMACLifecycle(db *sql.DB, backend macBackend) *workspaceMACLifecycle {
	return &workspaceMACLifecycle{
		db:                 db,
		backend:            backend,
		sessionBindings:    make(map[string]macCoverage),
		activeBoundaries:   make(map[string]int),
		deferredBoundaries: make(map[string]bool),
		leases:             make(map[string]string),
	}
}

// CreateSessionBinding prepares MAC coverage and atomically binds it to a
// session. The insertFn callback performs the DB insert. If it fails, the
// boundary is released while still serialized.
//
// This method acquires and releases the lifecycle lock.
func (l *workspaceMACLifecycle) CreateSessionBinding(workspace string, sessionID string, insertFn func(macCoverage) error) (macCoverage, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.backend == nil {
		cov := macCoverage{Boundary: workspace}
		if err := insertFn(cov); err != nil {
			return macCoverage{}, err
		}
		l.sessionBindings[sessionID] = cov
		return cov, nil
	}

	coverage, newlyCreated, err := l.backend.ensureCoverage(workspace)
	if err != nil {
		return macCoverage{}, fmt.Errorf("%w: %w", ErrMACPreparation, err)
	}

	// Resolve ownership for existing boundaries.
	if newlyCreated {
		coverage.Managed = true
	} else {
		owned, oerr := l.isBoundaryOwnedByHelper(coverage.Boundary)
		if oerr != nil {
			return macCoverage{}, fmt.Errorf("%w: %w", ErrMACPreparation, oerr)
		}
		coverage.Managed = owned
	}

	// Record ownership for newly-created boundaries before DB insert.
	if newlyCreated {
		if err := l.recordBoundaryOwnership(coverage.Boundary); err != nil {
			l.backend.removeBoundary(coverage.Boundary) // best-effort cleanup
			return macCoverage{}, fmt.Errorf("%w: %w", ErrMACPreparation, err)
		}
	}

	// DB insert.
	if err := insertFn(coverage); err != nil {
		// Rollback: release the exact boundary while still serialized.
		if newlyCreated {
			if rbErr := l.backend.removeBoundary(coverage.Boundary); rbErr != nil {
				// Removal failed: KEEP ownership metadata for retry on next startup.
				slog.Warn("MAC boundary removal failed during rollback, ownership preserved for retry",
					slog.String("boundary", coverage.Boundary),
					slog.String("error", rbErr.Error()))
			} else {
				l.forgetBoundaryOwnership(coverage.Boundary)
			}
		}
		return macCoverage{}, err
	}

	l.sessionBindings[sessionID] = coverage
	l.activeBoundaries[coverage.Boundary]++
	return coverage, nil
}

// ReleaseSessionBoundary releases the MAC boundary for a deleted session.
// Uses the exact binding for the session ID.
//
// This method acquires and releases the lifecycle lock.
func (l *workspaceMACLifecycle) ReleaseSessionBoundary(sessionID string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	coverage, ok := l.sessionBindings[sessionID]
	if !ok {
		return
	}
	delete(l.sessionBindings, sessionID)

	if l.backend == nil {
		return
	}

	l.conditionalReleaseBoundary(coverage.Boundary, coverage.Managed)
	// Retry cleanup of previously deferred boundaries now that a consumer disappeared.
	l.retryDeferredBoundaries()
}

// AcquireUse acquires a workspace-use lease for an operation.
// Checks exact session ID and workspace. Returns a release function.
//
// This method acquires and releases the lifecycle lock.
func (l *workspaceMACLifecycle) AcquireUse(sessionID, workspace string) (leaseKey string, release func(), err error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Check exact session binding exists.
	coverage, ok := l.sessionBindings[sessionID]
	if !ok {
		return "", nil, fmt.Errorf("no MAC binding for session %s", sessionID)
	}

	// Verify session is still live in DB.
	exists, err := l.sessionExistsExact(sessionID, workspace)
	if err != nil {
		return "", nil, fmt.Errorf("cannot verify session liveness: %w", err)
	}
	if !exists {
		return "", nil, fmt.Errorf("session %s is no longer live", sessionID)
	}

	// Increment boundary count.
	l.activeBoundaries[coverage.Boundary]++

	// Create unique lease key.
	leaseKey = generateLeaseKey()
	l.leases[leaseKey] = workspace

	// Idempotent release: use sync.Once so the release function affects
	// lifecycle state exactly once.
	var releaseOnce sync.Once
	release = func() {
		releaseOnce.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			delete(l.leases, leaseKey)
			if l.backend != nil {
				l.conditionalReleaseBoundary(coverage.Boundary, coverage.Managed)
			}
			// Retry cleanup of previously deferred boundaries.
			l.retryDeferredBoundaries()
		})
	}

	return leaseKey, release, nil
}

// ReconcileLiveSessions ensures all unexpired live sessions have valid MAC state.
// It is called during startup after DB initialization.
//
// This method acquires and releases the lifecycle lock.
func (l *workspaceMACLifecycle) ReconcileLiveSessions() error {
	if l.backend == nil {
		return nil
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// Import pre-existing managed boundaries into ownership metadata.
	// This ensures that boundaries created before mac_boundaries existed
	// (e.g., AppArmor managed fragment roots) are tracked as managed.
	if err := l.importManagedBoundaries(); err != nil {
		return fmt.Errorf("cannot import managed MAC boundaries: %w", err)
	}

	sessions, err := l.listLiveSessionsWithIDs()
	if err != nil {
		return fmt.Errorf("cannot list live sessions for MAC reconciliation: %w", err)
	}

	for _, s := range sessions {
		coverage, err := l.backend.verifyCoverage(s.Workspace)
		if err != nil {
			// Attempt repair.
			coverage, newlyCreated, repairErr := l.backend.ensureCoverage(s.Workspace)
			if repairErr != nil {
				return fmt.Errorf("MAC state for workspace %s (session %s) cannot be repaired: %w (original: %v)",
					s.Workspace, s.ID, repairErr, err)
			}
			if newlyCreated {
				if rbErr := l.recordBoundaryOwnership(coverage.Boundary); rbErr != nil {
					l.backend.removeBoundary(coverage.Boundary) // best-effort
					return fmt.Errorf("cannot record ownership for repaired boundary %s: %w", coverage.Boundary, rbErr)
				}
				coverage.Managed = true
			} else {
				owned, oerr := l.isBoundaryOwnedByHelper(coverage.Boundary)
				if oerr != nil {
					return fmt.Errorf("cannot verify repaired boundary ownership: %w", oerr)
				}
				coverage.Managed = owned
			}
			l.activeBoundaries[coverage.Boundary]++
			l.sessionBindings[s.ID] = coverage
		} else {
			owned, oerr := l.isBoundaryOwnedByHelper(coverage.Boundary)
			if oerr != nil {
				return fmt.Errorf("cannot verify boundary ownership for session %s: %w", s.ID, oerr)
			}
			coverage.Managed = owned
			l.activeBoundaries[coverage.Boundary]++
			l.sessionBindings[s.ID] = coverage
		}
	}

	// Clean up stale docker-helper-owned boundaries left by earlier failures.
	if err := l.cleanupStaleBoundaries(); err != nil {
		slog.Warn("stale MAC boundary cleanup failed", slog.String("error", err.Error()))
	}

	return nil
}

// importManagedBoundaries imports pre-existing managed boundaries from the
// backend into ownership metadata. This ensures that boundaries created
// before mac_boundaries existed (e.g., AppArmor managed fragment roots)
// are tracked as managed by docker-helper.
// Must be called with l.mu held.
func (l *workspaceMACLifecycle) importManagedBoundaries() error {
	boundaries, err := l.backend.listManagedBoundaries()
	if err != nil {
		return err
	}
	for _, boundary := range boundaries {
		if err := l.recordBoundaryOwnership(boundary); err != nil {
			slog.Warn("failed to record managed boundary ownership during import",
				slog.String("boundary", boundary),
				slog.String("error", err.Error()))
		}
	}
	return nil
}

// conditionalReleaseBoundary decreases the consumer count and possibly removes
// the boundary. Accounts for live bindings and leases.
// Must be called with l.mu held.
func (l *workspaceMACLifecycle) conditionalReleaseBoundary(boundary string, managed bool) {
	if l.backend == nil {
		return
	}

	count := l.activeBoundaries[boundary]
	if count <= 1 {
		delete(l.activeBoundaries, boundary)
	} else {
		l.activeBoundaries[boundary] = count - 1
		return
	}

	// No direct consumers remain — check if any other binding or lease still needs this boundary.
	if l.isBoundaryStillNeeded(boundary) {
		// Defer cleanup: record the boundary for retry when the intersecting
		// consumer later disappears. Do NOT set a synthetic count — keep
		// activeBoundaries truthful.
		if managed {
			l.deferredBoundaries[boundary] = true
		}
		return
	}

	// Safe to remove if managed.
	if !managed {
		return
	}

	if err := l.backend.removeBoundary(boundary); err != nil {
		// Failed removal: keep ownership metadata for retry on next startup.
		slog.Warn("MAC boundary removal failed, ownership preserved for retry",
			slog.String("boundary", boundary),
			slog.String("error", err.Error()))
		return
	}

	// Successful removal: remove ownership metadata.
	l.forgetBoundaryOwnership(boundary)
	delete(l.deferredBoundaries, boundary)
}

// retryDeferredBoundaries attempts to clean up previously deferred boundaries
// now that a consumer has disappeared.
// Must be called with l.mu held.
func (l *workspaceMACLifecycle) retryDeferredBoundaries() {
	if l.backend == nil {
		return
	}

	for boundary := range l.deferredBoundaries {
		if l.activeBoundaries[boundary] > 0 {
			// Still has direct consumers, skip.
			continue
		}
		if l.isBoundaryStillNeeded(boundary) {
			// Still needed by other bindings/leases, keep deferred.
			continue
		}

		// Check if we own this boundary.
		owned, err := l.isBoundaryOwnedByHelper(boundary)
		if err != nil {
			slog.Warn("cannot verify deferred boundary ownership for retry",
				slog.String("boundary", boundary),
				slog.String("error", err.Error()))
			continue
		}
		if !owned {
			delete(l.deferredBoundaries, boundary)
			continue
		}

		if err := l.backend.removeBoundary(boundary); err != nil {
			slog.Warn("deferred MAC boundary removal failed, will retry on next startup",
				slog.String("boundary", boundary),
				slog.String("error", err.Error()))
			continue
		}

		l.forgetBoundaryOwnership(boundary)
		delete(l.deferredBoundaries, boundary)
	}
}

// isBoundaryStillNeeded checks if any active consumer (session binding or lease)
// still needs the boundary. Uses path overlap semantics.
// Must be called with l.mu held.
func (l *workspaceMACLifecycle) isBoundaryStillNeeded(boundary string) bool {
	// Check session bindings.
	for _, cov := range l.sessionBindings {
		if macBoundaryOverlap(boundary, cov.Boundary) {
			return true
		}
	}

	// Check leases.
	for _, ws := range l.leases {
		if boundaryCoversWorkspace(boundary, ws) {
			return true
		}
	}

	return false
}

// cleanupStaleBoundaries attempts to remove docker-helper-owned boundaries
// that no longer have any consumers.
// Must be called with l.mu held.
func (l *workspaceMACLifecycle) cleanupStaleBoundaries() error {
	if l.backend == nil {
		return nil
	}

	boundaries, err := l.listOwnedBoundaries()
	if err != nil {
		return err
	}

	for _, boundary := range boundaries {
		if l.activeBoundaries[boundary] > 0 {
			continue
		}
		if l.isBoundaryStillNeeded(boundary) {
			// No direct consumers but an overlapping binding/lease blocks removal.
			// Register as deferred so it is retried when the intersecting consumer disappears.
			l.deferredBoundaries[boundary] = true
			continue
		}
		if err := l.backend.removeBoundary(boundary); err != nil {
			slog.Warn("stale MAC boundary removal failed, will retry on next startup",
				slog.String("boundary", boundary),
				slog.String("error", err.Error()))
			continue
		}
		l.forgetBoundaryOwnership(boundary)
		delete(l.deferredBoundaries, boundary)
	}

	return nil
}

// sessionExistsExact checks if a specific session is still live.
func (l *workspaceMACLifecycle) sessionExistsExact(sessionID, workspace string) (bool, error) {
	var count int
	err := l.db.QueryRow(
		`SELECT COUNT(*) FROM sessions WHERE id = ? AND workspace = ? AND expires_at > unixepoch()`,
		sessionID, workspace,
	).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// liveSessionWithID represents a session row for reconciliation.
type liveSessionWithID struct {
	ID        string
	Workspace string
}

// listLiveSessionsWithIDs returns all live sessions with their IDs.
func (l *workspaceMACLifecycle) listLiveSessionsWithIDs() ([]liveSessionWithID, error) {
	rows, err := l.db.Query(
		`SELECT id, workspace FROM sessions WHERE expires_at > unixepoch()`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []liveSessionWithID
	for rows.Next() {
		var s liveSessionWithID
		if err := rows.Scan(&s.ID, &s.Workspace); err != nil {
			return nil, err
		}
		sessions = append(sessions, s)
	}
	return sessions, rows.Err()
}

// recordBoundaryOwnership stores ownership metadata for a docker-helper-owned boundary.
func (l *workspaceMACLifecycle) recordBoundaryOwnership(boundary string) error {
	_, err := l.db.Exec(
		`INSERT OR REPLACE INTO mac_boundaries (backend, boundary) VALUES (?, ?)`,
		l.backendType(), boundary,
	)
	return err
}

// isBoundaryOwnedByHelper checks if the boundary is owned by the current backend.
func (l *workspaceMACLifecycle) isBoundaryOwnedByHelper(boundary string) (bool, error) {
	var backend string
	err := l.db.QueryRow(
		`SELECT backend FROM mac_boundaries WHERE backend = ? AND boundary = ?`,
		l.backendType(), boundary,
	).Scan(&backend)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}
	return backend == l.backendType(), nil
}

// forgetBoundaryOwnership removes ownership metadata for a released boundary.
func (l *workspaceMACLifecycle) forgetBoundaryOwnership(boundary string) error {
	_, err := l.db.Exec(
		`DELETE FROM mac_boundaries WHERE boundary = ? AND backend = ?`,
		boundary, l.backendType(),
	)
	return err
}

func (l *workspaceMACLifecycle) backendType() string {
	if l.backend == nil {
		return ""
	}
	return l.backend.backendType()
}

// listOwnedBoundaries returns all boundaries owned by the current backend.
func (l *workspaceMACLifecycle) listOwnedBoundaries() ([]string, error) {
	rows, err := l.db.Query(
		`SELECT boundary FROM mac_boundaries WHERE backend = ?`,
		l.backendType(),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var boundaries []string
	for rows.Next() {
		var b string
		if err := rows.Scan(&b); err != nil {
			return nil, err
		}
		boundaries = append(boundaries, b)
	}
	return boundaries, rows.Err()
}

// generateLeaseKey creates a unique lease key.
func generateLeaseKey() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("cannot generate lease key: %v", err))
	}
	return "lease_" + hex.EncodeToString(b)
}

// pathOverlapRelation describes the canonical relationship between two paths.
type pathOverlapRelation int

const (
	pathExact      pathOverlapRelation = iota // paths are equal
	pathAncestor                              // a is an ancestor of b
	pathDescendant                            // a is a descendant of b
	pathDisjoint                              // paths do not overlap
)

// pathOverlap returns the relationship of a to b.
// Both paths must be canonical (absolute, no symlinks).
func pathOverlap(a, b string) pathOverlapRelation {
	if a == b {
		return pathExact
	}
	if isInside(a, b) {
		return pathAncestor
	}
	if isInside(b, a) {
		return pathDescendant
	}
	return pathDisjoint
}

// boundaryCoversWorkspace returns true if the boundary covers the workspace.
func boundaryCoversWorkspace(boundary, workspace string) bool {
	rel := pathOverlap(boundary, workspace)
	return rel == pathExact || rel == pathAncestor
}

// macBoundaryOverlap returns true if two boundaries overlap.
func macBoundaryOverlap(a, b string) bool {
	rel := pathOverlap(a, b)
	return rel != pathDisjoint
}

// macBackendAppArmor wraps the AppArmor manager for the lifecycle owner.
type macBackendAppArmor struct {
	addRoot    func(string) (rootResult, error)
	removeRoot func(string) (rootResult, error)
	listRoots  func() ([]string, error)
}

func (b *macBackendAppArmor) ensureCoverage(workspace string) (macCoverage, bool, error) {
	roots, err := b.listRoots()
	if err != nil {
		return macCoverage{}, false, fmt.Errorf("cannot list AppArmor managed roots: %w", err)
	}

	for _, root := range roots {
		if boundaryCoversWorkspace(root, workspace) {
			return macCoverage{Boundary: root, Managed: true}, false, nil
		}
	}

	result, err := b.addRoot(workspace)
	if err != nil {
		return macCoverage{}, false, err
	}
	return macCoverage{Boundary: workspace, Managed: true}, result.Changed, nil
}

func (b *macBackendAppArmor) verifyCoverage(workspace string) (macCoverage, error) {
	roots, err := b.listRoots()
	if err != nil {
		return macCoverage{}, err
	}
	for _, root := range roots {
		if boundaryCoversWorkspace(root, workspace) {
			return macCoverage{Boundary: root, Managed: true}, nil
		}
	}
	return macCoverage{}, fmt.Errorf("workspace %s not covered by any managed AppArmor root", workspace)
}

func (b *macBackendAppArmor) removeBoundary(boundary string) error {
	_, err := b.removeRoot(boundary)
	return err
}

func (b *macBackendAppArmor) listManagedBoundaries() ([]string, error) {
	return b.listRoots()
}

func (b *macBackendAppArmor) backendType() string {
	return "apparmor"
}

// selinuxWorkspaceOps is the subset of selinuxWorkspaceManager operations
// used by the MAC lifecycle owner. Defined as an interface so that tests
// can inject a mock without changing production behavior.
type selinuxWorkspaceOps interface {
	listCoveringBoundaries(workspace string) ([]string, error)
	verifyActualType(workspace string) error
	restoreconRecursive(workspace string) error
	ensureWorkspaceLabel(workspace string) (bool, error)
	rollbackWorkspaceLabel(boundary string) error
}

// macBackendSELinux wraps the SELinux workspace manager for the lifecycle owner.
type macBackendSELinux struct {
	mgr selinuxWorkspaceOps
}

func (b *macBackendSELinux) ensureCoverage(workspace string) (macCoverage, bool, error) {
	if isHomeRoot(workspace) {
		return macCoverage{Boundary: workspace, Managed: false}, false, nil
	}

	// Check if an existing boundary covers this workspace.
	if cov, found, err := b.findExistingCoverage(workspace); err != nil {
		return macCoverage{}, false, err
	} else if found {
		// Existing compatible coverage found: run restorecon for the concrete
		// workspace and verify the actual on-disk type.
		if err := b.mgr.restoreconRecursive(workspace); err != nil {
			return macCoverage{}, false, fmt.Errorf("restorecon failed for workspace %s under existing boundary %s: %w", workspace, cov.Boundary, err)
		}
		if err := b.mgr.verifyActualType(workspace); err != nil {
			return macCoverage{}, false, fmt.Errorf("actual SELinux type verification failed for workspace %s: %w", workspace, err)
		}
		return cov, false, nil
	}

	// Prepare the workspace as a managed boundary.
	newlyCreated, err := b.mgr.ensureWorkspaceLabel(workspace)
	if err != nil {
		return macCoverage{}, false, err
	}
	return macCoverage{Boundary: workspace, Managed: true}, newlyCreated, nil
}

func (b *macBackendSELinux) verifyCoverage(workspace string) (macCoverage, error) {
	if isHomeRoot(workspace) {
		return macCoverage{Boundary: workspace, Managed: false}, nil
	}

	// Discover the actual persistent covering boundary.
	boundaries, err := b.mgr.listCoveringBoundaries(workspace)
	if err != nil {
		return macCoverage{}, fmt.Errorf("cannot discover SELinux coverage for %s: %w", workspace, err)
	}

	for _, boundary := range boundaries {
		// Boundary exists — verify the actual on-disk type for the workspace.
		if err := b.mgr.verifyActualType(workspace); err != nil {
			return macCoverage{}, fmt.Errorf("existing SELinux boundary %s exists but actual type for %s is incorrect: %w", boundary, workspace, err)
		}
		return macCoverage{Boundary: boundary, Managed: false}, nil
	}

	// No persistent fcontext boundary found — this is not durable MAC state.
	// A correct current xattr without a persistent boundary is insufficient
	// because it will not survive a restorecon or reboot.
	return macCoverage{}, fmt.Errorf("workspace %s has no persistent SELinux fcontext boundary", workspace)
}

func (b *macBackendSELinux) findExistingCoverage(workspace string) (macCoverage, bool, error) {
	boundaries, err := b.mgr.listCoveringBoundaries(workspace)
	if err != nil {
		return macCoverage{}, false, fmt.Errorf("cannot list covering SELinux boundaries: %w", err)
	}
	for _, boundary := range boundaries {
		return macCoverage{Boundary: boundary, Managed: false}, true, nil
	}
	return macCoverage{}, false, nil
}

func (b *macBackendSELinux) removeBoundary(boundary string) error {
	if isHomeRoot(boundary) {
		return nil
	}
	return b.mgr.rollbackWorkspaceLabel(boundary)
}

func (b *macBackendSELinux) listManagedBoundaries() ([]string, error) {
	return nil, nil
}

func (b *macBackendSELinux) backendType() string {
	return "selinux"
}

// newMACBackend creates the appropriate backend adapter for the given LSM.
// Returns nil for non-system mode or when no backend is active.
func newMACBackend(mode DeploymentMode, detectLSM func() (LSMBackend, error)) (macBackend, error) {
	if mode != ModeSystem {
		return nil, nil
	}

	backend, err := detectLSM()
	if err != nil {
		return nil, err
	}

	switch backend {
	case LSMAppArmor:
		mgr := newProductionApparmorManager()
		return &macBackendAppArmor{
			addRoot: func(path string) (rootResult, error) {
				return mgr.addRoot(path)
			},
			removeRoot: func(path string) (rootResult, error) {
				return mgr.removeRoot(path)
			},
			listRoots: func() ([]string, error) {
				return mgr.listRoots()
			},
		}, nil
	case LSMSelinux:
		return &macBackendSELinux{
			mgr: newSELinuxWorkspaceManager(),
		}, nil
	default:
		return nil, nil
	}
}

// pathOverlapAncestorOrExact returns true if a is an ancestor of or equal to b.
func pathOverlapAncestorOrExact(a, b string) bool {
	return a == b || isInside(a, b)
}

// pathOverlapDescendantOrExact returns true if a is a descendant of or equal to b.
func pathOverlapDescendantOrExact(a, b string) bool {
	return a == b || isInside(b, a)
}
