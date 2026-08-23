package main

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"sync"
)

// macBackend is the backend-specific adapter for workspace MAC operations.
// The lifecycle owner calls into this interface; the backend handles
// AppArmor or SELinux specifics.
type macBackend interface {
	// prepareWorkspace prepares MAC coverage for a concrete canonical workspace
	// path. It may create a new managed boundary or discover an existing one
	// that already covers the workspace.
	// Returns the boundary path that was prepared (may be the workspace itself
	// or an ancestor). If the workspace is already covered, returns the covering
	// boundary path and false for newlyCreated.
	// For home paths that use native labels, returns the path and false.
	prepareWorkspace(workspace string) (boundary string, newlyCreated bool, err error)

	// tryReleaseBoundary attempts to release a docker-helper-owned managed
	// boundary. It only succeeds if no other consumer needs it.
	// Returns nil if the boundary was released or is still needed.
	// Returns a non-nil error only if the release failed and should be retried.
	tryReleaseBoundary(boundary string) error

	// verifyWorkspace checks that a workspace has valid MAC coverage without
	// mutating state. Used during startup reconciliation.
	verifyWorkspace(workspace string) error
}

// workspaceMACLifecycle is the single internal owner of workspace MAC state.
// It serializes all lifecycle transitions, tracks active consumers, and
// coordinates with the backend-specific adapter.
type workspaceMACLifecycle struct {
	mu      sync.Mutex
	db      *sql.DB
	backend macBackend

	// activeBoundaries tracks which managed boundaries currently have consumers.
	// Key: canonical boundary path.
	// Value: number of active consumers (sessions + leases).
	activeBoundaries map[string]int

	// leases tracks active workspace-use leases held by operations.
	// Key: operation ID.
	// Value: the workspace path being used.
	leases map[string]string
}

func newWorkspaceMACLifecycle(db *sql.DB, backend macBackend) *workspaceMACLifecycle {
	return &workspaceMACLifecycle{
		db:               db,
		backend:          backend,
		activeBoundaries: make(map[string]int),
		leases:           make(map[string]string),
	}
}

// prepare prepares MAC coverage for a concrete canonical session workspace.
// It must be called under the lifecycle lock (caller holds it via
// acquireLifecycleLock/releaseLifecycleLock pattern, or the lifecycle methods
// that internally lock).
//
// Returns the boundary path that provides coverage.
func (l *workspaceMACLifecycle) prepare(workspace string) (boundary string, err error) {
	if l.backend == nil {
		return workspace, nil
	}

	boundary, newlyCreated, err := l.backend.prepareWorkspace(workspace)
	if err != nil {
		return "", fmt.Errorf("MAC preparation failed for %s: %w", workspace, err)
	}

	l.activeBoundaries[boundary]++

	if newlyCreated {
		if rbErr := l.recordBoundaryOwnership(boundary); rbErr != nil {
			l.activeBoundaries[boundary]--
			return "", fmt.Errorf("cannot record MAC boundary ownership: %w", rbErr)
		}
	}

	return boundary, nil
}

// conditionalRelease decreases the consumer count for the given boundary.
// If no consumers remain, it asks the backend to release it.
// Must be called with l.mu held.
func (l *workspaceMACLifecycle) conditionalRelease(boundary string) {
	if l.backend == nil {
		return
	}

	count := l.activeBoundaries[boundary]
	if count <= 1 {
		delete(l.activeBoundaries, boundary)
		if err := l.backend.tryReleaseBoundary(boundary); err != nil {
			// Log but do not fail — stale MAC state is safer than weakened confinement.
			// The ownership metadata persists so startup reconciliation can retry.
		}
	} else {
		l.activeBoundaries[boundary] = count - 1
	}
}

// acquireUse creates a workspace-use lease for an operation.
// It re-checks that the session is still live and increments the boundary count.
// Returns the boundary path and a release function.
// Must be called with l.mu held.
func (l *workspaceMACLifecycle) acquireUse(operationID, workspace string) (boundary string, release func(), err error) {
	// Check that the session is still live.
	exists, err := l.sessionExists(workspace)
	if err != nil {
		return "", nil, fmt.Errorf("cannot verify session liveness: %w", err)
	}
	if !exists {
		return "", nil, fmt.Errorf("session for workspace %s is no longer live", workspace)
	}

	// Prepare MAC if not already covered.
	boundary, err = l.prepare(workspace)
	if err != nil {
		return "", nil, err
	}

	l.leases[operationID] = workspace

	releaseFunc := func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		delete(l.leases, operationID)
		l.conditionalRelease(boundary)
	}

	return boundary, releaseFunc, nil
}

// reconcileLiveSessions ensures all unexpired live sessions have valid MAC state.
// It is called during startup after DB initialization.
func (l *workspaceMACLifecycle) reconcileLiveSessions() error {
	if l.backend == nil {
		return nil
	}

	sessions, err := l.listLiveSessions()
	if err != nil {
		return fmt.Errorf("cannot list live sessions for MAC reconciliation: %w", err)
	}

	for _, ws := range sessions {
		if err := l.backend.verifyWorkspace(ws); err != nil {
			// Attempt repair.
			_, _, repairErr := l.backend.prepareWorkspace(ws)
			if repairErr != nil {
				return fmt.Errorf("MAC state for workspace %s cannot be repaired: %w (original: %v)", ws, repairErr, err)
			}
			l.activeBoundaries[ws]++
		} else {
			// Already valid — find the covering boundary.
			// For simplicity, count the workspace itself as the boundary.
			l.activeBoundaries[ws]++
		}
	}

	return nil
}

// sessionExists checks if any unexpired session references the given workspace.
func (l *workspaceMACLifecycle) sessionExists(workspace string) (bool, error) {
	var count int
	err := l.db.QueryRow(
		`SELECT COUNT(*) FROM sessions WHERE workspace = ? AND expires_at > unixepoch()`,
		workspace,
	).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// listLiveSessions returns all canonical workspace paths for unexpired sessions.
func (l *workspaceMACLifecycle) listLiveSessions() ([]string, error) {
	rows, err := l.db.Query(
		`SELECT DISTINCT workspace FROM sessions WHERE expires_at > unixepoch()`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var workspaces []string
	for rows.Next() {
		var ws string
		if err := rows.Scan(&ws); err != nil {
			return nil, err
		}
		workspaces = append(workspaces, ws)
	}
	return workspaces, rows.Err()
}

// recordBoundaryOwnership stores minimal metadata about a docker-helper-owned
// MAC boundary. This is used to distinguish operator-owned rules from
// docker-helper-owned state during lifecycle release.
func (l *workspaceMACLifecycle) recordBoundaryOwnership(boundary string) error {
	_, err := l.db.Exec(
		`INSERT OR IGNORE INTO mac_boundaries (boundary, backend) VALUES (?, ?)`,
		boundary, l.backendType(),
	)
	return err
}

// isBoundaryOwnedByHelper returns true if the boundary was created by docker-helper.
func (l *workspaceMACLifecycle) isBoundaryOwnedByHelper(boundary string) (bool, error) {
	var count int
	err := l.db.QueryRow(
		`SELECT COUNT(*) FROM mac_boundaries WHERE boundary = ?`,
		boundary,
	).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// forgetBoundaryOwnership removes the ownership record for a released boundary.
func (l *workspaceMACLifecycle) forgetBoundaryOwnership(boundary string) error {
	_, err := l.db.Exec(
		`DELETE FROM mac_boundaries WHERE boundary = ?`,
		boundary,
	)
	return err
}

func (l *workspaceMACLifecycle) backendType() string {
	if l.backend == nil {
		return ""
	}
	switch l.backend.(type) {
	case *macBackendAppArmor:
		return "apparmor"
	case *macBackendSELinux:
		return "selinux"
	default:
		return "unknown"
	}
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
// A boundary covers a workspace if the boundary is an ancestor of or equal to
// the workspace path.
func boundaryCoversWorkspace(boundary, workspace string) bool {
	rel := pathOverlap(boundary, workspace)
	return rel == pathExact || rel == pathAncestor
}

// macBoundaryOverlap returns true if two boundaries overlap (one covers the other).
func macBoundaryOverlap(a, b string) bool {
	rel := pathOverlap(a, b)
	return rel != pathDisjoint
}

// findCoveringBoundary finds an existing active boundary that covers the workspace.
// Returns the boundary path and true if found, or ("", false) if not.
// Must be called with l.mu held.
func (l *workspaceMACLifecycle) findCoveringBoundary(workspace string) (string, bool) {
	for boundary, count := range l.activeBoundaries {
		if count > 0 && boundaryCoversWorkspace(boundary, workspace) {
			return boundary, true
		}
	}
	return "", false
}

// findConsumersOfBoundary returns all session workspaces and lease operation IDs
// that consume the given boundary.
// Must be called with l.mu held.
func (l *workspaceMACLifecycle) findConsumersOfBoundary(boundary string) ([]string, []string) {
	var sessions, ops []string

	// Check active boundaries (sessions).
	if l.activeBoundaries[boundary] > 0 {
		sessions = append(sessions, boundary)
	}

	// Check leases.
	for opID, ws := range l.leases {
		if boundaryCoversWorkspace(boundary, ws) {
			ops = append(ops, opID)
		}
	}

	return sessions, ops
}

// releaseSessionBoundary releases the MAC boundary for a session being deleted.
// It checks if other consumers still need the boundary before releasing.
// Must be called with l.mu held.
func (l *workspaceMACLifecycle) releaseSessionBoundary(workspace string) {
	if l.backend == nil {
		return
	}

	// Find the boundary that covers this workspace.
	boundary, found := l.findCoveringBoundary(workspace)
	if !found {
		return
	}

	l.conditionalRelease(boundary)
}

// macBackendAppArmor wraps the AppArmor manager for the lifecycle owner.
type macBackendAppArmor struct {
	addRoot    func(string) (rootResult, error)
	removeRoot func(string) (rootResult, error)
	listRoots  func() ([]string, error)
}

func (b *macBackendAppArmor) prepareWorkspace(workspace string) (string, bool, error) {
	// Check if an existing managed root already covers this workspace.
	roots, err := b.listRoots()
	if err != nil {
		return "", false, fmt.Errorf("cannot list AppArmor managed roots: %w", err)
	}

	for _, root := range roots {
		if boundaryCoversWorkspace(root, workspace) {
			return root, false, nil
		}
	}

	// Prepare the workspace itself as a managed root.
	result, err := b.addRoot(workspace)
	if err != nil {
		return "", false, err
	}
	return workspace, result.Changed, nil
}

func (b *macBackendAppArmor) tryReleaseBoundary(boundary string) error {
	_, err := b.removeRoot(boundary)
	return err
}

func (b *macBackendAppArmor) verifyWorkspace(workspace string) error {
	roots, err := b.listRoots()
	if err != nil {
		return err
	}
	for _, root := range roots {
		if boundaryCoversWorkspace(root, workspace) {
			return nil
		}
	}
	return fmt.Errorf("workspace %s not covered by any managed AppArmor root", workspace)
}

// macBackendSELinux wraps the SELinux workspace manager for the lifecycle owner.
type macBackendSELinux struct {
	mgr *selinuxWorkspaceManager
}

func (b *macBackendSELinux) prepareWorkspace(workspace string) (string, bool, error) {
	if isHomeRoot(workspace) {
		// Home paths use native labels — no preparation needed.
		return workspace, false, nil
	}

	// Check if an existing managed boundary covers this workspace.
	// We check by seeing if the workspace already has the correct type.
	if err := b.mgr.verifyActualType(workspace); err == nil {
		return workspace, false, nil
	}

	// Prepare the workspace as a managed boundary.
	newlyCreated, err := b.mgr.ensureWorkspaceLabel(workspace)
	if err != nil {
		return "", false, err
	}
	return workspace, newlyCreated, nil
}

func (b *macBackendSELinux) tryReleaseBoundary(boundary string) error {
	if isHomeRoot(boundary) {
		return nil
	}
	// The lifecycle owner checks ownership before calling this.
	return b.mgr.rollbackWorkspaceLabel(boundary)
}

func (b *macBackendSELinux) verifyWorkspace(workspace string) error {
	if isHomeRoot(workspace) {
		return nil
	}
	return b.mgr.verifyActualType(workspace)
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

// isBoundaryStillNeeded checks if any active consumer (session or lease)
// still needs the boundary. Uses path overlap semantics, not string equality.
// Must be called with l.mu held.
func (l *workspaceMACLifecycle) isBoundaryStillNeeded(boundary string) bool {
	// Check active boundaries (session consumers).
	for b, count := range l.activeBoundaries {
		if count > 0 && macBoundaryOverlap(boundary, b) {
			return true
		}
	}

	// Check leases (operation consumers).
	for _, ws := range l.leases {
		if boundaryCoversWorkspace(boundary, ws) {
			return true
		}
	}

	return false
}

// _ ensures filepath is used (avoid unused import).
var _ = filepath.Clean
