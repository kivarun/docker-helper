package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sync"
)

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

	// activeBoundaries maps boundary path to consumer count.
	activeBoundaries map[string]int

	// leases maps unique lease key to workspace.
	leases map[string]string
}

func newWorkspaceMACLifecycle(db *sql.DB, backend macBackend) *workspaceMACLifecycle {
	return &workspaceMACLifecycle{
		db:               db,
		backend:          backend,
		sessionBindings:  make(map[string]macCoverage),
		activeBoundaries: make(map[string]int),
		leases:           make(map[string]string),
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
		return macCoverage{}, fmt.Errorf("MAC preparation failed for %s: %w", workspace, err)
	}

	// Resolve ownership for existing boundaries.
	if newlyCreated {
		coverage.Managed = true
	} else {
		owned, oerr := l.isBoundaryOwnedByHelper(coverage.Boundary)
		if oerr != nil {
			return macCoverage{}, fmt.Errorf("cannot verify boundary ownership: %w", oerr)
		}
		coverage.Managed = owned
	}

	// Record ownership for newly-created boundaries before DB insert.
	if newlyCreated {
		if err := l.recordBoundaryOwnership(coverage.Boundary); err != nil {
			l.backend.removeBoundary(coverage.Boundary) // best-effort cleanup
			return macCoverage{}, fmt.Errorf("cannot record MAC boundary ownership: %w", err)
		}
	}

	// DB insert.
	if err := insertFn(coverage); err != nil {
		// Rollback: release the exact boundary while still serialized.
		if newlyCreated {
			l.backend.removeBoundary(coverage.Boundary) // best-effort
			l.forgetBoundaryOwnership(coverage.Boundary)
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

	release = func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		delete(l.leases, leaseKey)
		if l.backend != nil {
			l.activeBoundaries[coverage.Boundary]--
		}
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
		l.activeBoundaries[boundary] = 1
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
			continue
		}
		if err := l.backend.removeBoundary(boundary); err != nil {
			slog.Warn("stale MAC boundary removal failed, will retry on next startup",
				slog.String("boundary", boundary),
				slog.String("error", err.Error()))
			continue
		}
		l.forgetBoundaryOwnership(boundary)
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
		`INSERT OR IGNORE INTO mac_boundaries (boundary, backend) VALUES (?, ?)`,
		boundary, l.backendType(),
	)
	return err
}

// isBoundaryOwnedByHelper checks if the boundary is owned by the current backend.
func (l *workspaceMACLifecycle) isBoundaryOwnedByHelper(boundary string) (bool, error) {
	var backend string
	err := l.db.QueryRow(
		`SELECT backend FROM mac_boundaries WHERE boundary = ?`,
		boundary,
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

func (b *macBackendAppArmor) backendType() string {
	return "apparmor"
}

// macBackendSELinux wraps the SELinux workspace manager for the lifecycle owner.
type macBackendSELinux struct {
	mgr *selinuxWorkspaceManager
}

func (b *macBackendSELinux) ensureCoverage(workspace string) (macCoverage, bool, error) {
	if isHomeRoot(workspace) {
		return macCoverage{Boundary: workspace, Managed: false}, false, nil
	}

	// Check if an existing boundary covers this workspace.
	if cov, found := b.findExistingCoverage(workspace); found {
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

	// Check if an existing boundary covers this workspace.
	if cov, found := b.findExistingCoverage(workspace); found {
		return cov, nil
	}

	// No existing boundary — verify the workspace itself.
	if err := b.mgr.verifyActualType(workspace); err == nil {
		return macCoverage{Boundary: workspace, Managed: false}, nil
	}

	return macCoverage{}, fmt.Errorf("workspace %s not covered by any SELinux boundary", workspace)
}

func (b *macBackendSELinux) findExistingCoverage(workspace string) (macCoverage, bool) {
	boundaries, err := b.mgr.listCoveringBoundaries(workspace)
	if err != nil {
		return macCoverage{}, false
	}
	for _, boundary := range boundaries {
		return macCoverage{Boundary: boundary, Managed: false}, true
	}
	return macCoverage{}, false
}

func (b *macBackendSELinux) removeBoundary(boundary string) error {
	if isHomeRoot(boundary) {
		return nil
	}
	return b.mgr.rollbackWorkspaceLabel(boundary)
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
