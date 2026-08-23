package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
)

// ErrMACPreparation is returned when MAC coverage cannot be ensured or verified.
var ErrMACPreparation = errors.New("MAC preparation failed")

// macCoverage describes the actual MAC coverage boundary for a workspace.
type macCoverage struct {
	Boundary string // the actual boundary path providing coverage
	Managed  bool   // true if docker-helper owns this boundary
}

// workspaceMACDriver is the backend-specific adapter for workspace MAC operations.
// The driver MUST NOT query sessions or operations.
type workspaceMACDriver interface {
	// ensureCoverage ensures MAC coverage for a concrete canonical workspace.
	// Returns the actual coverage boundary (may be the workspace or an ancestor).
	// created is true if a new boundary was created.
	ensureCoverage(workspace string) (coverage macCoverage, created bool, err error)

	// verifyCoverage checks that a workspace has valid MAC coverage without
	// mutating state. Returns the actual coverage boundary.
	verifyCoverage(workspace string) (coverage macCoverage, err error)

	// removeBoundary removes a docker-helper-owned managed boundary.
	// Only called when the coordinator has verified ownership.
	removeBoundary(boundary string) error

	// listManagedBoundaries returns all boundaries that this driver manages.
	// Used during reconciliation to import pre-existing managed boundaries
	// into ownership metadata.
	listManagedBoundaries() ([]string, error)

	// backendType returns the backend identifier ("apparmor" or "selinux").
	backendType() string
}

// sessionMACCoordinator is the single internal owner of session MAC state.
// It serializes all lifecycle transitions, tracks active consumers, and
// coordinates with the backend-specific driver.
type sessionMACCoordinator struct {
	mu     sync.Mutex
	db     *sql.DB
	driver workspaceMACDriver

	// sessionBindings maps session ID to the exact MAC coverage boundary.
	sessionBindings map[string]macCoverage

	// activeBoundaries maps boundary path to direct consumer count.
	activeBoundaries map[string]int

	// deferredBoundaries tracks driver-owned boundaries that cannot yet be
	// removed because an intersecting session/boundary is live. These are
	// retried for cleanup when any consumer disappears.
	deferredBoundaries map[string]bool

	// leases maps unique lease key to workspace.
	leases map[string]string
}

func newSessionMACCoordinator(db *sql.DB, driver workspaceMACDriver) *sessionMACCoordinator {
	return &sessionMACCoordinator{
		db:                 db,
		driver:             driver,
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
// This method acquires and releases the coordinator lock.
func (c *sessionMACCoordinator) CreateSessionBinding(workspace string, sessionID string, insertFn func(macCoverage) error) (macCoverage, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.driver == nil {
		cov := macCoverage{Boundary: workspace}
		if err := insertFn(cov); err != nil {
			return macCoverage{}, err
		}
		c.sessionBindings[sessionID] = cov
		return cov, nil
	}

	coverage, newlyCreated, err := c.driver.ensureCoverage(workspace)
	if err != nil {
		return macCoverage{}, fmt.Errorf("%w: %w", ErrMACPreparation, err)
	}

	// Resolve ownership for existing boundaries.
	if newlyCreated {
		coverage.Managed = true
	} else {
		owned, oerr := c.isBoundaryOwnedByHelper(coverage.Boundary)
		if oerr != nil {
			return macCoverage{}, fmt.Errorf("%w: %w", ErrMACPreparation, oerr)
		}
		coverage.Managed = owned
	}

	// Record ownership for newly-created boundaries before DB insert.
	if newlyCreated {
		if err := c.recordBoundaryOwnership(coverage.Boundary); err != nil {
			c.driver.removeBoundary(coverage.Boundary) // best-effort cleanup
			return macCoverage{}, fmt.Errorf("%w: %w", ErrMACPreparation, err)
		}
	}

	// DB insert.
	if err := insertFn(coverage); err != nil {
		// Rollback: release the exact boundary while still serialized.
		if newlyCreated {
			if rbErr := c.driver.removeBoundary(coverage.Boundary); rbErr != nil {
				// Removal failed: KEEP ownership metadata for retry on next startup.
				slog.Warn("MAC boundary removal failed during rollback, ownership preserved for retry",
					slog.String("boundary", coverage.Boundary),
					slog.String("error", rbErr.Error()))
			} else {
				c.forgetBoundaryOwnership(coverage.Boundary)
			}
		}
		return macCoverage{}, err
	}

	c.sessionBindings[sessionID] = coverage
	c.activeBoundaries[coverage.Boundary]++
	return coverage, nil
}

// ReleaseSessionBoundary releases the MAC boundary for a deleted session.
// Uses the exact binding for the session ID.
//
// This method acquires and releases the coordinator lock.
func (c *sessionMACCoordinator) ReleaseSessionBoundary(sessionID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	coverage, ok := c.sessionBindings[sessionID]
	if !ok {
		return
	}
	delete(c.sessionBindings, sessionID)

	if c.driver == nil {
		return
	}

	c.conditionalReleaseBoundary(coverage.Boundary, coverage.Managed)
	// Retry cleanup of previously deferred boundaries now that a consumer disappeared.
	c.retryDeferredBoundaries()
}

// AcquireUse acquires a workspace-use lease for an operation.
// Checks exact session ID and workspace. Returns a release function.
//
// This method acquires and releases the coordinator lock.
func (c *sessionMACCoordinator) AcquireUse(sessionID, workspace string) (leaseKey string, release func(), err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check exact session binding exists.
	coverage, ok := c.sessionBindings[sessionID]
	if !ok {
		return "", nil, fmt.Errorf("no MAC binding for session %s", sessionID)
	}

	// Verify session is still live in DB.
	exists, err := c.sessionExistsExact(sessionID, workspace)
	if err != nil {
		return "", nil, fmt.Errorf("cannot verify session liveness: %w", err)
	}
	if !exists {
		return "", nil, fmt.Errorf("session %s is no longer live", sessionID)
	}

	// Increment boundary count.
	c.activeBoundaries[coverage.Boundary]++

	// Create unique lease key.
	leaseKey = generateLeaseKey()
	c.leases[leaseKey] = workspace

	// Idempotent release: use sync.Once so the release function affects
	// coordinator state exactly once.
	var releaseOnce sync.Once
	release = func() {
		releaseOnce.Do(func() {
			c.mu.Lock()
			defer c.mu.Unlock()
			delete(c.leases, leaseKey)
			if c.driver != nil {
				c.conditionalReleaseBoundary(coverage.Boundary, coverage.Managed)
			}
			// Retry cleanup of previously deferred boundaries.
			c.retryDeferredBoundaries()
		})
	}

	return leaseKey, release, nil
}

// ReconcileLiveSessions ensures all unexpired live sessions have valid MAC state.
// It is called during startup after DB initialization.
//
// This method acquires and releases the coordinator lock.
func (c *sessionMACCoordinator) ReconcileLiveSessions() error {
	if c.driver == nil {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Import pre-existing managed boundaries into ownership metadata.
	// This ensures that boundaries created before mac_boundaries existed
	// (e.g., AppArmor managed fragment roots) are tracked as managed.
	if err := c.importManagedBoundaries(); err != nil {
		return fmt.Errorf("cannot import managed MAC boundaries: %w", err)
	}

	sessions, err := c.listLiveSessionsWithIDs()
	if err != nil {
		return fmt.Errorf("cannot list live sessions for MAC reconciliation: %w", err)
	}

	for _, s := range sessions {
		coverage, err := c.driver.verifyCoverage(s.Workspace)
		if err != nil {
			// Attempt repair.
			coverage, newlyCreated, repairErr := c.driver.ensureCoverage(s.Workspace)
			if repairErr != nil {
				return fmt.Errorf("MAC state for workspace %s (session %s) cannot be repaired: %w (original: %v)",
					s.Workspace, s.ID, repairErr, err)
			}
			if newlyCreated {
				if rbErr := c.recordBoundaryOwnership(coverage.Boundary); rbErr != nil {
					c.driver.removeBoundary(coverage.Boundary) // best-effort
					return fmt.Errorf("cannot record ownership for repaired boundary %s: %w", coverage.Boundary, rbErr)
				}
				coverage.Managed = true
			} else {
				owned, oerr := c.isBoundaryOwnedByHelper(coverage.Boundary)
				if oerr != nil {
					return fmt.Errorf("cannot verify repaired boundary ownership: %w", oerr)
				}
				coverage.Managed = owned
			}
			c.activeBoundaries[coverage.Boundary]++
			c.sessionBindings[s.ID] = coverage
		} else {
			owned, oerr := c.isBoundaryOwnedByHelper(coverage.Boundary)
			if oerr != nil {
				return fmt.Errorf("cannot verify boundary ownership for session %s: %w", s.ID, oerr)
			}
			coverage.Managed = owned
			c.activeBoundaries[coverage.Boundary]++
			c.sessionBindings[s.ID] = coverage
		}
	}

	// Clean up stale docker-helper-owned boundaries left by earlier failures.
	if err := c.cleanupStaleBoundaries(); err != nil {
		slog.Warn("stale MAC boundary cleanup failed", slog.String("error", err.Error()))
	}

	return nil
}

// importManagedBoundaries imports pre-existing managed boundaries from the
// driver into ownership metadata. This ensures that boundaries created
// before mac_boundaries existed (e.g., AppArmor managed fragment roots)
// are tracked as managed by docker-helper.
// Must be called with c.mu held.
func (c *sessionMACCoordinator) importManagedBoundaries() error {
	boundaries, err := c.driver.listManagedBoundaries()
	if err != nil {
		return err
	}
	for _, boundary := range boundaries {
		if err := c.recordBoundaryOwnership(boundary); err != nil {
			slog.Warn("failed to record managed boundary ownership during import",
				slog.String("boundary", boundary),
				slog.String("error", err.Error()))
		}
	}
	return nil
}

// conditionalReleaseBoundary decreases the consumer count and possibly removes
// the boundary. Accounts for live bindings and leases.
// Must be called with c.mu held.
func (c *sessionMACCoordinator) conditionalReleaseBoundary(boundary string, managed bool) {
	if c.driver == nil {
		return
	}

	count := c.activeBoundaries[boundary]
	if count <= 1 {
		delete(c.activeBoundaries, boundary)
	} else {
		c.activeBoundaries[boundary] = count - 1
		return
	}

	// No direct consumers remain — check if any other binding or lease still needs this boundary.
	if c.isBoundaryStillNeeded(boundary) {
		// Defer cleanup: record the boundary for retry when the intersecting
		// consumer later disappears. Do NOT set a synthetic count — keep
		// activeBoundaries truthful.
		if managed {
			c.deferredBoundaries[boundary] = true
		}
		return
	}

	// Safe to remove if managed.
	if !managed {
		return
	}

	if err := c.driver.removeBoundary(boundary); err != nil {
		// Failed removal: keep ownership metadata for retry on next startup.
		slog.Warn("MAC boundary removal failed, ownership preserved for retry",
			slog.String("boundary", boundary),
			slog.String("error", err.Error()))
		return
	}

	// Successful removal: remove ownership metadata.
	c.forgetBoundaryOwnership(boundary)
	delete(c.deferredBoundaries, boundary)
}

// retryDeferredBoundaries attempts to clean up previously deferred boundaries
// now that a consumer has disappeared.
// Must be called with c.mu held.
func (c *sessionMACCoordinator) retryDeferredBoundaries() {
	if c.driver == nil {
		return
	}

	for boundary := range c.deferredBoundaries {
		if c.activeBoundaries[boundary] > 0 {
			// Still has direct consumers, skip.
			continue
		}
		if c.isBoundaryStillNeeded(boundary) {
			// Still needed by other bindings/leases, keep deferred.
			continue
		}

		// Check if we own this boundary.
		owned, err := c.isBoundaryOwnedByHelper(boundary)
		if err != nil {
			slog.Warn("cannot verify deferred boundary ownership for retry",
				slog.String("boundary", boundary),
				slog.String("error", err.Error()))
			continue
		}
		if !owned {
			delete(c.deferredBoundaries, boundary)
			continue
		}

		if err := c.driver.removeBoundary(boundary); err != nil {
			slog.Warn("deferred MAC boundary removal failed, will retry on next startup",
				slog.String("boundary", boundary),
				slog.String("error", err.Error()))
			continue
		}

		c.forgetBoundaryOwnership(boundary)
		delete(c.deferredBoundaries, boundary)
	}
}

// isBoundaryStillNeeded checks if any active consumer (session binding or lease)
// still needs the boundary. Uses path overlap semantics.
// Must be called with c.mu held.
func (c *sessionMACCoordinator) isBoundaryStillNeeded(boundary string) bool {
	// Check session bindings.
	for _, cov := range c.sessionBindings {
		if macBoundaryOverlap(boundary, cov.Boundary) {
			return true
		}
	}

	// Check leases.
	for _, ws := range c.leases {
		if boundaryCoversWorkspace(boundary, ws) {
			return true
		}
	}

	return false
}

// cleanupStaleBoundaries attempts to remove docker-helper-owned boundaries
// that no longer have any consumers.
// Must be called with c.mu held.
func (c *sessionMACCoordinator) cleanupStaleBoundaries() error {
	if c.driver == nil {
		return nil
	}

	boundaries, err := c.listOwnedBoundaries()
	if err != nil {
		return err
	}

	for _, boundary := range boundaries {
		if c.activeBoundaries[boundary] > 0 {
			continue
		}
		if c.isBoundaryStillNeeded(boundary) {
			// No direct consumers but an overlapping binding/lease blocks removal.
			// Register as deferred so it is retried when the intersecting consumer disappears.
			c.deferredBoundaries[boundary] = true
			continue
		}
		if err := c.driver.removeBoundary(boundary); err != nil {
			slog.Warn("stale MAC boundary removal failed, will retry on next startup",
				slog.String("boundary", boundary),
				slog.String("error", err.Error()))
			continue
		}
		c.forgetBoundaryOwnership(boundary)
		delete(c.deferredBoundaries, boundary)
	}

	return nil
}

// sessionExistsExact checks if a specific session is still live.
func (c *sessionMACCoordinator) sessionExistsExact(sessionID, workspace string) (bool, error) {
	var count int
	err := c.db.QueryRow(
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
func (c *sessionMACCoordinator) listLiveSessionsWithIDs() ([]liveSessionWithID, error) {
	rows, err := c.db.Query(
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
func (c *sessionMACCoordinator) recordBoundaryOwnership(boundary string) error {
	_, err := c.db.Exec(
		`INSERT OR REPLACE INTO mac_boundaries (backend, boundary) VALUES (?, ?)`,
		c.backendType(), boundary,
	)
	return err
}

// isBoundaryOwnedByHelper checks if the boundary is owned by the current driver.
func (c *sessionMACCoordinator) isBoundaryOwnedByHelper(boundary string) (bool, error) {
	var backend string
	err := c.db.QueryRow(
		`SELECT backend FROM mac_boundaries WHERE backend = ? AND boundary = ?`,
		c.backendType(), boundary,
	).Scan(&backend)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}
	return backend == c.backendType(), nil
}

// forgetBoundaryOwnership removes ownership metadata for a released boundary.
func (c *sessionMACCoordinator) forgetBoundaryOwnership(boundary string) error {
	_, err := c.db.Exec(
		`DELETE FROM mac_boundaries WHERE boundary = ? AND backend = ?`,
		boundary, c.backendType(),
	)
	return err
}

func (c *sessionMACCoordinator) backendType() string {
	if c.driver == nil {
		return ""
	}
	return c.driver.backendType()
}

// listOwnedBoundaries returns all boundaries owned by the current driver.
func (c *sessionMACCoordinator) listOwnedBoundaries() ([]string, error) {
	rows, err := c.db.Query(
		`SELECT boundary FROM mac_boundaries WHERE backend = ?`,
		c.backendType(),
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

// pathWithin returns true if path is within root (equality allowed).
// Both root and path must be canonical (absolute, cleaned).
func pathWithin(root, path string) bool {
	if root == path {
		return true
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// pathStrictlyWithin returns true if path is a proper descendant of root.
// Both root and path must be canonical (absolute, cleaned).
func pathStrictlyWithin(root, path string) bool {
	if root == path {
		return false
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
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
	if pathWithin(a, b) {
		return pathAncestor
	}
	if pathWithin(b, a) {
		return pathDescendant
	}
	return pathDisjoint
}

// boundaryCoversWorkspace returns true if the boundary covers the workspace.
func boundaryCoversWorkspace(boundary, workspace string) bool {
	return pathWithin(boundary, workspace)
}

// macBoundaryOverlap returns true if two boundaries overlap.
func macBoundaryOverlap(a, b string) bool {
	rel := pathOverlap(a, b)
	return rel != pathDisjoint
}

// appArmorWorkspaceMACDriver wraps the AppArmor manager for the coordinator.
type appArmorWorkspaceMACDriver struct {
	addRoot    func(string) (rootResult, error)
	removeRoot func(string) (rootResult, error)
	listRoots  func() ([]string, error)
}

func (d *appArmorWorkspaceMACDriver) ensureCoverage(workspace string) (macCoverage, bool, error) {
	roots, err := d.listRoots()
	if err != nil {
		return macCoverage{}, false, fmt.Errorf("cannot list AppArmor managed roots: %w", err)
	}

	for _, root := range roots {
		if boundaryCoversWorkspace(root, workspace) {
			return macCoverage{Boundary: root, Managed: true}, false, nil
		}
	}

	result, err := d.addRoot(workspace)
	if err != nil {
		return macCoverage{}, false, err
	}
	return macCoverage{Boundary: workspace, Managed: true}, result.Changed, nil
}

func (d *appArmorWorkspaceMACDriver) verifyCoverage(workspace string) (macCoverage, error) {
	roots, err := d.listRoots()
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

func (d *appArmorWorkspaceMACDriver) removeBoundary(boundary string) error {
	_, err := d.removeRoot(boundary)
	return err
}

func (d *appArmorWorkspaceMACDriver) listManagedBoundaries() ([]string, error) {
	return d.listRoots()
}

func (d *appArmorWorkspaceMACDriver) backendType() string {
	return "apparmor"
}

// selinuxWorkspaceOps is the subset of selinuxWorkspaceManager operations
// used by the MAC coordinator. Defined as an interface so that tests
// can inject a mock without changing production behavior.
type selinuxWorkspaceOps interface {
	listCoveringBoundaries(workspace string) ([]string, error)
	verifyActualType(workspace string) error
	restoreconRecursive(workspace string) error
	ensureWorkspaceLabel(workspace string) (bool, error)
	rollbackWorkspaceLabel(boundary string) error
}

// selinuxWorkspaceMACDriver wraps the SELinux workspace manager for the coordinator.
type selinuxWorkspaceMACDriver struct {
	mgr selinuxWorkspaceOps
}

func (d *selinuxWorkspaceMACDriver) ensureCoverage(workspace string) (macCoverage, bool, error) {
	if isHomeRoot(workspace) {
		return macCoverage{Boundary: workspace, Managed: false}, false, nil
	}

	// Check if an existing boundary covers this workspace.
	if cov, found, err := d.findExistingCoverage(workspace); err != nil {
		return macCoverage{}, false, err
	} else if found {
		// Existing compatible coverage found: run restorecon for the concrete
		// workspace and verify the actual on-disk type.
		if err := d.mgr.restoreconRecursive(workspace); err != nil {
			return macCoverage{}, false, fmt.Errorf("restorecon failed for workspace %s under existing boundary %s: %w", workspace, cov.Boundary, err)
		}
		if err := d.mgr.verifyActualType(workspace); err != nil {
			return macCoverage{}, false, fmt.Errorf("actual SELinux type verification failed for workspace %s: %w", workspace, err)
		}
		return cov, false, nil
	}

	// Prepare the workspace as a managed boundary.
	newlyCreated, err := d.mgr.ensureWorkspaceLabel(workspace)
	if err != nil {
		return macCoverage{}, false, err
	}
	return macCoverage{Boundary: workspace, Managed: true}, newlyCreated, nil
}

func (d *selinuxWorkspaceMACDriver) verifyCoverage(workspace string) (macCoverage, error) {
	if isHomeRoot(workspace) {
		return macCoverage{Boundary: workspace, Managed: false}, nil
	}

	// Discover the actual persistent covering boundary.
	boundaries, err := d.mgr.listCoveringBoundaries(workspace)
	if err != nil {
		return macCoverage{}, fmt.Errorf("cannot discover SELinux coverage for %s: %w", workspace, err)
	}

	for _, boundary := range boundaries {
		// Boundary exists — verify the actual on-disk type for the workspace.
		if err := d.mgr.verifyActualType(workspace); err != nil {
			return macCoverage{}, fmt.Errorf("existing SELinux boundary %s exists but actual type for %s is incorrect: %w", boundary, workspace, err)
		}
		return macCoverage{Boundary: boundary, Managed: false}, nil
	}

	// No persistent fcontext boundary found — this is not durable MAC state.
	// A correct current xattr without a persistent boundary is insufficient
	// because it will not survive a restorecon or reboot.
	return macCoverage{}, fmt.Errorf("workspace %s has no persistent SELinux fcontext boundary", workspace)
}

func (d *selinuxWorkspaceMACDriver) findExistingCoverage(workspace string) (macCoverage, bool, error) {
	boundaries, err := d.mgr.listCoveringBoundaries(workspace)
	if err != nil {
		return macCoverage{}, false, fmt.Errorf("cannot list covering SELinux boundaries: %w", err)
	}
	for _, boundary := range boundaries {
		return macCoverage{Boundary: boundary, Managed: false}, true, nil
	}
	return macCoverage{}, false, nil
}

func (d *selinuxWorkspaceMACDriver) removeBoundary(boundary string) error {
	if isHomeRoot(boundary) {
		return nil
	}
	return d.mgr.rollbackWorkspaceLabel(boundary)
}

func (d *selinuxWorkspaceMACDriver) listManagedBoundaries() ([]string, error) {
	return nil, nil
}

func (d *selinuxWorkspaceMACDriver) backendType() string {
	return "selinux"
}

// newWorkspaceMACDriver creates the appropriate driver for the given LSM.
// Returns nil for non-system mode or when no driver is active.
func newWorkspaceMACDriver(mode DeploymentMode, detectLSM func() (LSMBackend, error)) (workspaceMACDriver, error) {
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
		return &appArmorWorkspaceMACDriver{
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
	case LSMSELinux:
		return &selinuxWorkspaceMACDriver{
			mgr: newSELinuxWorkspaceManager(),
		}, nil
	default:
		return nil, nil
	}
}
