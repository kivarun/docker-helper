package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"sync"
)

// ErrMACPreparation is returned when MAC coverage cannot be ensured or verified.
var ErrMACPreparation = errors.New("MAC preparation failed")

// workspaceMACCoverage describes the actual MAC coverage boundary for one
// issued filesystem tree.
type workspaceMACCoverage struct {
	Boundary    string // the actual boundary path providing coverage
	HelperOwned bool   // true if docker-helper owns this boundary (operator-compatible boundaries are not helper-owned)
}

// workspaceMACDriver is the backend-specific adapter for Session MAC
// operations. The driver MUST NOT query sessions or operations. Every
// argument is one concrete canonical filesystem tree issued in a Session's
// immutable snapshot (the workspace is one issued tree).
type workspaceMACDriver interface {
	// ensureCoverage ensures MAC coverage for a concrete canonical issued
	// tree. Returns the actual coverage boundary (may be the tree or an
	// ancestor). created is true if a new boundary was created.
	ensureCoverage(tree string) (coverage workspaceMACCoverage, created bool, err error)

	// verifyCoverage checks that a concrete canonical issued tree has valid
	// MAC coverage without mutating state. Returns the actual coverage
	// boundary.
	verifyCoverage(tree string) (coverage workspaceMACCoverage, err error)

	// removeBoundary removes a docker-helper-owned boundary.
	// Only called when the coordinator has verified ownership.
	removeBoundary(boundary string) error

	// discoverHelperOwnedBoundaries returns boundaries intrinsically attributable
	// to docker-helper. Used during startup to import pre-existing helper-owned
	// boundaries into durable ownership metadata.
	// Operator-compatible boundaries MUST NOT be returned.
	discoverHelperOwnedBoundaries() ([]string, error)

	// backend returns the LSM backend identity for this driver
	// ("apparmor" or "selinux").
	backend() LSMBackend
}

// sessionLease records the coverage set one operation lease acquired, so the
// release affects exactly those boundaries exactly once even when the
// session binding they came from is gone (a concurrent session deletion
// must never strip a live operation's MAC coverage).
type sessionLease struct {
	sessionID string
	coverage  []workspaceMACCoverage
}

// sessionMACCoordinator is the single internal owner of session MAC state.
// It serializes all lifecycle transitions, tracks active consumers, and
// coordinates with the backend-specific driver.
type sessionMACCoordinator struct {
	mu     sync.Mutex
	db     *sql.DB
	driver workspaceMACDriver

	// sessionBindings maps session ID to the session's actual MAC coverage
	// set: the deduplicated minimal set of boundaries the backend resolved
	// for the session's issued trees. Several issued trees may resolve to
	// one covering boundary; one physical boundary never becomes multiple
	// consumers of the same session.
	sessionBindings map[string][]workspaceMACCoverage

	// boundaryConsumerCounts maps boundary path to direct consumer count.
	boundaryConsumerCounts map[string]int

	// deferredBoundaries tracks helper-owned boundaries that cannot yet be
	// removed because an intersecting session/boundary is live. These are
	// retried for cleanup when any consumer disappears.
	deferredBoundaries map[string]bool

	// sessionUseLeases maps unique lease key to the acquired coverage set.
	sessionUseLeases map[string]sessionLease

	// pendingWorkloadSessions reports the session IDs with pending
	// helper-owned workload state (the workload MAC coordinator's startup
	// coverage gate source). Nil in deployments without workload MAC; the
	// gate is then vacuously satisfied.
	pendingWorkloadSessions func() map[string]bool
}

func newSessionMACCoordinator(db *sql.DB, driver workspaceMACDriver) *sessionMACCoordinator {
	if driver == nil {
		panic("sessionMACCoordinator requires a non-nil workspaceMACDriver")
	}
	return &sessionMACCoordinator{
		db:                     db,
		driver:                 driver,
		sessionBindings:        make(map[string][]workspaceMACCoverage),
		boundaryConsumerCounts: make(map[string]int),
		deferredBoundaries:     make(map[string]bool),
		sessionUseLeases:       make(map[string]sessionLease),
	}
}

// ensureBoundaryWithOwnership is the canonical per-tree MAC preparation
// primitive: ensure driver coverage for one issued tree, then resolve and
// (for a newly created boundary) record helper ownership. A newly created
// boundary whose ownership record fails is best-effort removed so no
// unowned physical state survives a failed preparation.
// Must be called with c.mu held.
func (c *sessionMACCoordinator) ensureBoundaryWithOwnership(tree string) (workspaceMACCoverage, bool, error) {
	coverage, newlyCreated, err := c.driver.ensureCoverage(tree)
	if err != nil {
		return workspaceMACCoverage{}, false, fmt.Errorf("%w: %w", ErrMACPreparation, err)
	}

	// Resolve ownership for existing boundaries.
	if newlyCreated {
		coverage.HelperOwned = true
	} else {
		owned, oerr := c.isBoundaryOwnedByHelper(coverage.Boundary)
		if oerr != nil {
			return workspaceMACCoverage{}, false, fmt.Errorf("%w: %w", ErrMACPreparation, oerr)
		}
		coverage.HelperOwned = owned
	}

	// Record ownership for newly-created boundaries before any dependent
	// state is created.
	if newlyCreated {
		if err := c.recordBoundaryOwnership(coverage.Boundary); err != nil {
			c.driver.removeBoundary(coverage.Boundary) // best-effort cleanup
			return workspaceMACCoverage{}, false, fmt.Errorf("%w: %w", ErrMACPreparation, err)
		}
	}
	return coverage, newlyCreated, nil
}

// ensureSessionCoverage prepares MAC coverage for every issued tree and
// returns the session's actual deduplicated coverage set plus the boundaries
// this call newly created (for rollback). A tree already covered by a
// resolved boundary is skipped: the backend driver may resolve several
// requested trees to one existing covering MAC boundary, and one physical
// boundary must not become multiple accidental consumers merely because
// multiple issued snapshot entries map onto it.
//
// On failure the boundaries prepared so far are rolled back through the
// canonical removal decision owner before the error is returned.
// Must be called with c.mu held.
func (c *sessionMACCoordinator) ensureSessionCoverage(trees []string) ([]workspaceMACCoverage, []string, error) {
	resolved := make(map[string]workspaceMACCoverage, len(trees))
	var prepared []string
	for _, tree := range trees {
		covered := false
		for boundary := range resolved {
			if boundaryCoversWorkspace(boundary, tree) {
				covered = true
				break
			}
		}
		if covered {
			continue
		}
		coverage, newlyCreated, err := c.ensureBoundaryWithOwnership(tree)
		if err != nil {
			c.rollbackPreparedBoundaries(prepared)
			return nil, nil, err
		}
		if newlyCreated {
			prepared = append(prepared, coverage.Boundary)
		}
		if _, ok := resolved[coverage.Boundary]; !ok {
			resolved[coverage.Boundary] = coverage
		}
	}
	return normalizeCoverageSet(resolved), prepared, nil
}

// normalizeCoverageSet reduces a resolved coverage map to the canonical
// minimal covering set: every boundary is kept in deterministic lexical
// order and a boundary covered by an already-kept boundary is dropped (its
// coverage is provided by the covering ancestor). Equal boundaries collapse
// in the map itself.
func normalizeCoverageSet(resolved map[string]workspaceMACCoverage) []workspaceMACCoverage {
	boundaries := make([]string, 0, len(resolved))
	for boundary := range resolved {
		boundaries = append(boundaries, boundary)
	}
	sort.Strings(boundaries)
	kept := make([]workspaceMACCoverage, 0, len(boundaries))
	for _, boundary := range boundaries {
		redundant := false
		for _, coverage := range kept {
			if boundaryCoversWorkspace(coverage.Boundary, boundary) {
				redundant = true
				break
			}
		}
		if !redundant {
			kept = append(kept, resolved[boundary])
		}
	}
	return kept
}

// rollbackPreparedBoundaries releases boundaries this preparation newly
// created and recorded, through the canonical removal decision owner. Under
// the coordinator lock no other session consumer could have attached to
// them yet, but pending helper-owned workload state may still rely on the
// coverage: boundaryMayBeRemoved decides, and a boundary it blocks is kept
// as deferred helper-owned state for canonical reconciliation instead of
// being removed unsafely.
// Must be called with c.mu held.
func (c *sessionMACCoordinator) rollbackPreparedBoundaries(prepared []string) {
	if len(prepared) == 0 {
		return
	}
	pendingRoots, deferAll := c.pendingWorkloadCoverage()
	for i := len(prepared) - 1; i >= 0; i-- {
		boundary := prepared[i]
		if !c.boundaryMayBeRemoved(boundary, pendingRoots, deferAll) {
			// Retain the helper-owned boundary and let the canonical
			// deferred/startup reconciliation own its cleanup.
			c.deferredBoundaries[boundary] = true
			continue
		}
		if err := c.driver.removeBoundary(boundary); err != nil {
			// Removal failed: ownership metadata stays for retry on the
			// next startup reconciliation.
			opLog(context.Background()).Warn("MAC boundary removal failed during rollback, ownership preserved for retry",
				slog.String("boundary", boundary),
				slog.String("error", err.Error()))
			continue
		}
		c.forgetBoundaryOwnership(boundary)
	}
}

// CreateSessionBinding prepares MAC coverage for every issued tree of a
// session and atomically binds the resulting coverage set to the session.
// insertFn performs the DB insert (the Session + snapshot commit); it must
// be the create transaction's commit point. If it fails, the boundaries
// this call prepared are rolled back through the canonical removal decision
// owner while still serialized. The bearer may only be returned after this
// method has committed the Session and registered every actual coverage
// boundary as a session consumer.
//
// This method acquires and releases the coordinator lock.
func (c *sessionMACCoordinator) CreateSessionBinding(sessionID string, boundaries []string, insertFn func([]workspaceMACCoverage) error) ([]workspaceMACCoverage, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	coverageSet, prepared, err := c.ensureSessionCoverage(boundaries)
	if err != nil {
		return nil, err
	}

	// DB insert (the create transaction's commit point).
	if err := insertFn(coverageSet); err != nil {
		c.rollbackPreparedBoundaries(prepared)
		return nil, err
	}

	c.sessionBindings[sessionID] = coverageSet
	for _, coverage := range coverageSet {
		c.boundaryConsumerCounts[coverage.Boundary]++
	}
	return coverageSet, nil
}

// ReleaseSessionBinding releases the session->MAC binding for a deleted
// session: the session's complete bound coverage set. The underlying
// boundaries may remain because of other consumers.
//
// This method acquires and releases the coordinator lock.
func (c *sessionMACCoordinator) ReleaseSessionBinding(sessionID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	coverageSet, ok := c.sessionBindings[sessionID]
	if !ok {
		return
	}
	delete(c.sessionBindings, sessionID)

	for _, coverage := range coverageSet {
		c.conditionalReleaseBoundary(coverage.Boundary, coverage.HelperOwned)
	}
	// Retry cleanup of previously deferred boundaries now that a consumer disappeared.
	c.retryDeferredBoundaries()
}

// AcquireSessionUse acquires a session-use lease for an operation. It proves
// exact session binding and liveness as today, then acquires consumer
// protection for the session's complete bound coverage set — every MAC
// boundary a live operation may rely on, not only the workspace. The
// release function affects the acquired boundaries exactly once.
//
// This method acquires and releases the coordinator lock.
func (c *sessionMACCoordinator) AcquireSessionUse(sessionID, workspace string) (leaseKey string, release func(), err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check exact session binding exists.
	coverageSet, ok := c.sessionBindings[sessionID]
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

	// Increment the consumer count of every bound coverage boundary.
	for _, coverage := range coverageSet {
		c.boundaryConsumerCounts[coverage.Boundary]++
	}

	// Create unique lease key.
	leaseKey = generateLeaseKey()
	c.sessionUseLeases[leaseKey] = sessionLease{sessionID: sessionID, coverage: coverageSet}

	// Idempotent release: use sync.Once so the release function affects
	// coordinator state exactly once.
	var releaseOnce sync.Once
	release = func() {
		releaseOnce.Do(func() {
			c.mu.Lock()
			defer c.mu.Unlock()
			lease, ok := c.sessionUseLeases[leaseKey]
			if !ok {
				return
			}
			delete(c.sessionUseLeases, leaseKey)
			for _, coverage := range lease.coverage {
				c.conditionalReleaseBoundary(coverage.Boundary, coverage.HelperOwned)
			}
			// Retry cleanup of previously deferred boundaries.
			c.retryDeferredBoundaries()
		})
	}

	return leaseKey, release, nil
}

// ReconcileLiveSessions ensures all unexpired live sessions have valid MAC
// state for every filesystem tree issued in their persisted immutable
// snapshot. It is called during startup after DB initialization and the
// snapshot integrity/migration pass. The persisted snapshot is loaded
// through the canonical snapshot loader — issued roots are never
// reconstructed from current parent policy — so a snapshot integrity
// failure fails startup closed through the existing integrity contract.
//
// This method acquires and releases the coordinator lock.
func (c *sessionMACCoordinator) ReconcileLiveSessions() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Import pre-existing helper-owned boundaries into ownership metadata.
	// This ensures that boundaries created before mac_boundaries existed
	// (e.g., AppArmor managed fragment boundaries) are tracked as helper-owned.
	if err := c.importHelperOwnedBoundaries(); err != nil {
		return fmt.Errorf("cannot import helper-owned MAC boundaries: %w", err)
	}

	sessions, err := c.listLiveSessionsWithIDs()
	if err != nil {
		return fmt.Errorf("cannot list live sessions for MAC reconciliation: %w", err)
	}

	for _, s := range sessions {
		snapshot, err := loadSessionFilesystemSnapshot(c.db, s.ID, s.Workspace)
		if err != nil {
			return fmt.Errorf("MAC state for session %s cannot be reconciled: persisted snapshot integrity: %w", s.ID, err)
		}
		boundaries := sessionMACBoundaries(snapshot)

		resolved := make(map[string]workspaceMACCoverage, len(boundaries))
		for _, boundary := range boundaries {
			covered := false
			for have := range resolved {
				if boundaryCoversWorkspace(have, boundary) {
					covered = true
					break
				}
			}
			if covered {
				continue
			}
			coverage, err := c.driver.verifyCoverage(boundary)
			if err != nil {
				// Attempt repair through the canonical preparation primitive.
				coverage, _, err = c.ensureBoundaryWithOwnership(boundary)
				if err != nil {
					return fmt.Errorf("MAC state for tree %s (session %s) cannot be repaired: %w (original: %v)", boundary, s.ID, err, err)
				}
			} else {
				owned, oerr := c.isBoundaryOwnedByHelper(coverage.Boundary)
				if oerr != nil {
					return fmt.Errorf("cannot verify boundary ownership for session %s: %w", s.ID, oerr)
				}
				coverage.HelperOwned = owned
			}
			if _, ok := resolved[coverage.Boundary]; !ok {
				resolved[coverage.Boundary] = coverage
			}
		}
		c.sessionBindings[s.ID] = normalizeCoverageSet(resolved)
		for _, coverage := range c.sessionBindings[s.ID] {
			c.boundaryConsumerCounts[coverage.Boundary]++
		}
	}

	// Clean up stale docker-helper-owned boundaries left by earlier failures.
	if err := c.cleanupStaleBoundaries(); err != nil {
		opLog(context.Background()).Warn("stale MAC boundary cleanup failed", slog.String("error", err.Error()))
	}

	return nil
}

// importHelperOwnedBoundaries imports pre-existing helper-owned boundaries from
// the driver into ownership metadata. This ensures that boundaries created
// before mac_boundaries existed (e.g., AppArmor managed fragment boundaries)
// are tracked as helper-owned by docker-helper.
// Must be called with c.mu held.
func (c *sessionMACCoordinator) importHelperOwnedBoundaries() error {
	boundaries, err := c.driver.discoverHelperOwnedBoundaries()
	if err != nil {
		return err
	}
	for _, boundary := range boundaries {
		if err := c.recordBoundaryOwnership(boundary); err != nil {
			opLog(context.Background()).Warn("failed to record helper-owned boundary during import",
				slog.String("boundary", boundary),
				slog.String("error", err.Error()))
		}
	}
	return nil
}

// boundaryMayBeRemoved is the canonical decision owner for "may this
// helper-owned Session MAC boundary be removed now?". Every production path
// that can remove a boundary — conditionalReleaseBoundary,
// retryDeferredBoundaries, and cleanupStaleBoundaries — decides through this
// owner, so there is exactly one definition of "still needed". In frozen
// order it considers: direct boundary consumers, overlapping Session
// bindings and workspace-use leases, and pending helper-owned workload
// coverage — including the fail-closed defer-all case when a pending
// workload session's workspace cannot be resolved (for example after the
// session row was deleted while its workload state is still pending). The
// pending coverage is resolved once per removal pass through the existing
// pendingWorkloadCoverage() owner.
// Must be called with c.mu held.
func (c *sessionMACCoordinator) boundaryMayBeRemoved(boundary string, pendingWorkspaces map[string]bool, deferAll bool) bool {
	if c.boundaryConsumerCounts[boundary] > 0 {
		return false
	}
	if c.isBoundaryStillNeeded(boundary) {
		return false
	}
	if deferAll {
		// A pending workload session or its persisted snapshot could not be
		// resolved, so any boundary might still be the one it needs: fail
		// closed.
		return false
	}
	if c.boundaryCoversPendingWorkload(boundary, pendingWorkspaces) {
		// Pending helper-owned workload state still relies on this coverage
		// (any issued tree of a pending workload's session, not only the
		// workspace); keep it until workload reconciliation proves the state
		// gone.
		return false
	}
	return true
}

// conditionalReleaseBoundary decreases the consumer count and possibly removes
// the boundary. The removal decision is the canonical boundaryMayBeRemoved
// owner: direct consumers, overlapping bindings/leases, and pending
// helper-owned workload coverage all defer the release.
// Must be called with c.mu held.
func (c *sessionMACCoordinator) conditionalReleaseBoundary(boundary string, helperOwned bool) {
	count := c.boundaryConsumerCounts[boundary]
	if count <= 1 {
		delete(c.boundaryConsumerCounts, boundary)
	} else {
		c.boundaryConsumerCounts[boundary] = count - 1
		return
	}

	// No direct consumers remain — decide through the canonical removal owner.
	pendingWorkspaces, deferAll := c.pendingWorkloadCoverage()
	if !c.boundaryMayBeRemoved(boundary, pendingWorkspaces, deferAll) {
		// Deferred cleanup: record the boundary for retry when the blocking
		// consumer or pending workload later disappears. Do NOT set a
		// synthetic count — keep boundaryConsumerCounts truthful.
		if helperOwned {
			c.deferredBoundaries[boundary] = true
		}
		return
	}

	// Safe to remove if helper-owned.
	if !helperOwned {
		return
	}

	if err := c.driver.removeBoundary(boundary); err != nil {
		// Failed removal: keep ownership metadata for retry on next startup.
		opLog(context.Background()).Warn("MAC boundary removal failed, ownership preserved for retry",
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
	pendingWorkspaces, deferAll := c.pendingWorkloadCoverage()
	for boundary := range c.deferredBoundaries {
		if !c.boundaryMayBeRemoved(boundary, pendingWorkspaces, deferAll) {
			// Still blocked by the canonical removal owner (direct consumers,
			// overlapping bindings/leases, or pending helper-owned workload
			// coverage): keep deferred.
			continue
		}

		// Check if we own this boundary.
		owned, err := c.isBoundaryOwnedByHelper(boundary)
		if err != nil {
			opLog(context.Background()).Warn("cannot verify deferred boundary ownership for retry",
				slog.String("boundary", boundary),
				slog.String("error", err.Error()))
			continue
		}
		if !owned {
			delete(c.deferredBoundaries, boundary)
			continue
		}

		if err := c.driver.removeBoundary(boundary); err != nil {
			opLog(context.Background()).Warn("deferred MAC boundary removal failed, will retry on next startup",
				slog.String("boundary", boundary),
				slog.String("error", err.Error()))
			continue
		}

		c.forgetBoundaryOwnership(boundary)
		delete(c.deferredBoundaries, boundary)
	}
}

// isBoundaryStillNeeded checks if any active consumer (session binding or
// session-use lease) still needs the boundary. Uses path overlap semantics
// over every bound coverage set: a boundary an overlapping issued tree still
// needs stays protected. It is one input of the canonical
// boundaryMayBeRemoved removal owner, not a standalone decision.
// Must be called with c.mu held.
func (c *sessionMACCoordinator) isBoundaryStillNeeded(boundary string) bool {
	// Check session bindings.
	for _, coverageSet := range c.sessionBindings {
		for _, coverage := range coverageSet {
			if macBoundaryOverlap(boundary, coverage.Boundary) {
				return true
			}
		}
	}

	// Check session-use leases.
	for _, lease := range c.sessionUseLeases {
		for _, coverage := range lease.coverage {
			if macBoundaryOverlap(boundary, coverage.Boundary) {
				return true
			}
		}
	}

	return false
}

// pendingWorkloadCoverage resolves the pending helper-owned workload
// sessions to their complete issued MAC boundary sets, derived from the
// persisted immutable snapshot through the same projection owner the create
// path uses. A pending workload may rely on any issued Session tree, not
// only the workspace, and expired Session rows intentionally remain until
// after workload reconciliation, so the rows stay resolvable here. The
// second result reports whether the pass must defer every removal (a
// pending session or its snapshot could not be resolved, so any boundary
// might be needed: fail closed).
func (c *sessionMACCoordinator) pendingWorkloadCoverage() (map[string]bool, bool) {
	pendingRoots := map[string]bool{}
	deferAll := false
	if c.pendingWorkloadSessions == nil {
		return pendingRoots, false
	}
	for sessionID := range c.pendingWorkloadSessions() {
		roots, err := c.sessionBoundCoverageRoots(sessionID)
		if err != nil {
			opLog(context.Background()).Warn("pending workload session cannot be resolved; deferring stale boundary cleanup",
				slog.String("session_id", sessionID),
				slog.String("error", err.Error()))
			deferAll = true
			continue
		}
		for _, root := range roots {
			pendingRoots[root] = true
		}
	}
	return pendingRoots, deferAll
}

// cleanupStaleBoundaries attempts to remove docker-helper-owned boundaries
// that no longer have any consumers.
// Must be called with c.mu held.
//
// Startup coverage gate: a boundary is retained (deferred) while the
// canonical boundaryMayBeRemoved owner blocks it — an overlapping
// binding/lease, pending helper-owned workload coverage, or the fail-closed
// defer-all case when a pending session cannot be resolved to a workspace.
// This keeps the host/MAC state a crashed-but-pending workload relies on
// intact until the workload reconciliation has proven or removed that state.
func (c *sessionMACCoordinator) cleanupStaleBoundaries() error {
	boundaries, err := c.listOwnedBoundaries()
	if err != nil {
		return err
	}

	// Resolve pending workload sessions to their workspaces once per pass.
	pendingWorkspaces, deferAll := c.pendingWorkloadCoverage()

	for _, boundary := range boundaries {
		if c.boundaryConsumerCounts[boundary] > 0 {
			continue
		}
		if !c.boundaryMayBeRemoved(boundary, pendingWorkspaces, deferAll) {
			// No direct consumers but the canonical removal owner blocks the
			// removal. Register as deferred so it is retried when the blocker
			// disappears.
			c.deferredBoundaries[boundary] = true
			continue
		}
		if err := c.driver.removeBoundary(boundary); err != nil {
			opLog(context.Background()).Warn("stale MAC boundary removal failed, will retry on next startup",
				slog.String("boundary", boundary),
				slog.String("error", err.Error()))
			continue
		}
		c.forgetBoundaryOwnership(boundary)
		delete(c.deferredBoundaries, boundary)
	}

	return nil
}

// boundaryCoversPendingWorkload reports whether the boundary covers any
// issued filesystem tree that still has pending helper-owned workload state.
func (c *sessionMACCoordinator) boundaryCoversPendingWorkload(boundary string, pendingWorkspaces map[string]bool) bool {
	for root := range pendingWorkspaces {
		if boundaryCoversWorkspace(boundary, root) {
			return true
		}
	}
	return false
}

// sessionBoundCoverageRoots resolves one session's complete issued MAC
// boundary set from its persisted state: the workspace row plus the
// persisted immutable snapshot loaded through the canonical snapshot loader,
// projected through the same sessionMACBoundaries owner the create path
// uses. Issued roots are never reconstructed from current parent policy.
// Expired rows still resolve: startup expires Sessions after the workload
// reconciliation, so a pending workload's coverage dependency stays
// provable for the whole startup sequence.
func (c *sessionMACCoordinator) sessionBoundCoverageRoots(sessionID string) ([]string, error) {
	var workspace string
	err := c.db.QueryRow(`SELECT workspace FROM sessions WHERE id = ?`, sessionID).Scan(&workspace)
	if err != nil {
		return nil, fmt.Errorf("session row for pending workload state cannot be resolved: %w", err)
	}
	snapshot, err := loadSessionFilesystemSnapshot(c.db, sessionID, workspace)
	if err != nil {
		return nil, fmt.Errorf("session %s persisted snapshot cannot be loaded: %w", sessionID, err)
	}
	return sessionMACBoundaries(snapshot), nil
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
		c.backend(), boundary,
	)
	return err
}

// isBoundaryOwnedByHelper checks if the boundary is owned by docker-helper
// for the current backend.
func (c *sessionMACCoordinator) isBoundaryOwnedByHelper(boundary string) (bool, error) {
	var backend LSMBackend
	err := c.db.QueryRow(
		`SELECT backend FROM mac_boundaries WHERE backend = ? AND boundary = ?`,
		c.backend(), boundary,
	).Scan(&backend)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}
	return backend == c.backend(), nil
}

// forgetBoundaryOwnership removes ownership metadata for a released boundary.
func (c *sessionMACCoordinator) forgetBoundaryOwnership(boundary string) error {
	_, err := c.db.Exec(
		`DELETE FROM mac_boundaries WHERE boundary = ? AND backend = ?`,
		boundary, c.backend(),
	)
	return err
}

func (c *sessionMACCoordinator) backend() LSMBackend {
	return c.driver.backend()
}

// listOwnedBoundaries returns all boundaries owned by docker-helper for the
// current backend.
func (c *sessionMACCoordinator) listOwnedBoundaries() ([]string, error) {
	rows, err := c.db.Query(
		`SELECT boundary FROM mac_boundaries WHERE backend = ?`,
		c.backend(),
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
	addManagedBoundary    func(string) (boundaryResult, error)
	removeManagedBoundary func(string) (boundaryResult, error)
	listManagedBoundaries func() ([]string, error)
}

func (d *appArmorWorkspaceMACDriver) ensureCoverage(workspace string) (workspaceMACCoverage, bool, error) {
	boundaries, err := d.listManagedBoundaries()
	if err != nil {
		return workspaceMACCoverage{}, false, fmt.Errorf("cannot list AppArmor managed boundaries: %w", err)
	}

	for _, boundary := range boundaries {
		if boundaryCoversWorkspace(boundary, workspace) {
			return workspaceMACCoverage{Boundary: boundary, HelperOwned: true}, false, nil
		}
	}

	result, err := d.addManagedBoundary(workspace)
	if err != nil {
		return workspaceMACCoverage{}, false, err
	}
	return workspaceMACCoverage{Boundary: workspace, HelperOwned: true}, result.Changed, nil
}

func (d *appArmorWorkspaceMACDriver) verifyCoverage(workspace string) (workspaceMACCoverage, error) {
	boundaries, err := d.listManagedBoundaries()
	if err != nil {
		return workspaceMACCoverage{}, err
	}
	for _, boundary := range boundaries {
		if boundaryCoversWorkspace(boundary, workspace) {
			return workspaceMACCoverage{Boundary: boundary, HelperOwned: true}, nil
		}
	}
	return workspaceMACCoverage{}, fmt.Errorf("workspace %s not covered by any managed AppArmor boundary", workspace)
}

func (d *appArmorWorkspaceMACDriver) removeBoundary(boundary string) error {
	_, err := d.removeManagedBoundary(boundary)
	return err
}

func (d *appArmorWorkspaceMACDriver) discoverHelperOwnedBoundaries() ([]string, error) {
	return d.listManagedBoundaries()
}

func (d *appArmorWorkspaceMACDriver) backend() LSMBackend {
	return LSMAppArmor
}

// selinuxFcontextOps is the subset of selinuxFcontextManager operations
// used by the MAC coordinator. Defined as an interface so that tests
// can inject a mock without changing production behavior.
type selinuxFcontextOps interface {
	listCoveringFcontexts(tree string) ([]string, error)
	verifyActualType(tree string) error
	restoreconTree(tree string, kind selinuxTreeKind) error
	ensureWorkspaceFcontext(tree string, kind selinuxTreeKind) (bool, error)
	removeFcontextBoundary(boundary string) error
}

// selinuxTreeKind describes the concrete filesystem kind of one issued
// Session MAC boundary. An issued tree may be a directory or a regular
// file; the backend mechanics differ (recursive vs exact fcontext rule and
// restorecon invocation).
type selinuxTreeKind int

const (
	selinuxTreeDirectory selinuxTreeKind = iota
	selinuxTreeRegularFile
)

// selinuxTreeKindFor classifies one canonical issued tree path by its
// on-disk kind. An issued tree exists at issuance (the Session-create
// boundary proved it); a missing or other-kind path fails closed because
// restorecon cannot establish a trustworthy label for it.
func selinuxTreeKindFor(path string) (selinuxTreeKind, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return 0, fmt.Errorf("cannot stat issued tree %s: %w", path, err)
	}
	if info.IsDir() {
		return selinuxTreeDirectory, nil
	}
	if info.Mode().IsRegular() {
		return selinuxTreeRegularFile, nil
	}
	return 0, fmt.Errorf("issued tree %s is neither a directory nor a regular file", path)
}

// selinuxWorkspaceMACDriver is the MAC driver backed by selinuxFcontextManager
// and SELinux fcontext mechanics. It reports discovered coverage conservatively;
// sessionMACCoordinator resolves HelperOwned using mac_boundaries metadata.
type selinuxWorkspaceMACDriver struct {
	mgr selinuxFcontextOps
	// treeKind classifies the issued tree's filesystem kind. Production
	// wires selinuxTreeKindFor; tests inject a fake.
	treeKind func(string) (selinuxTreeKind, error)
}

func (d *selinuxWorkspaceMACDriver) ensureCoverage(tree string) (workspaceMACCoverage, bool, error) {
	if isUnderHome(tree) {
		return workspaceMACCoverage{Boundary: tree, HelperOwned: false}, false, nil
	}

	kind, err := d.treeKind(tree)
	if err != nil {
		return workspaceMACCoverage{}, false, err
	}

	// Check if an existing boundary covers this tree.
	if cov, found, err := d.findExistingCoverage(tree); err != nil {
		return workspaceMACCoverage{}, false, err
	} else if found {
		// Existing compatible coverage found: relabel the concrete tree
		// (kind-aware) and verify the actual on-disk type.
		if err := d.mgr.restoreconTree(tree, kind); err != nil {
			return workspaceMACCoverage{}, false, fmt.Errorf("restorecon failed for tree %s under existing boundary %s: %w", tree, cov.Boundary, err)
		}
		if err := d.mgr.verifyActualType(tree); err != nil {
			return workspaceMACCoverage{}, false, fmt.Errorf("actual SELinux type verification failed for tree %s: %w", tree, err)
		}
		return cov, false, nil
	}

	// No existing coverage. Check whether docker-helper is allowed to create
	// a helper-owned fcontext boundary at this tree.
	if !selinuxFcontextBoundaryAllowed(tree) {
		return workspaceMACCoverage{}, false, fmt.Errorf(
			"cannot create helper-owned SELinux fcontext boundary at %s: exact /opt is not permitted as a recursive relabel boundary",
			tree,
		)
	}

	// Prepare the tree as a helper-owned boundary.
	newlyCreated, err := d.mgr.ensureWorkspaceFcontext(tree, kind)
	if err != nil {
		return workspaceMACCoverage{}, false, err
	}
	return workspaceMACCoverage{Boundary: tree, HelperOwned: true}, newlyCreated, nil
}

func (d *selinuxWorkspaceMACDriver) verifyCoverage(tree string) (workspaceMACCoverage, error) {
	if isUnderHome(tree) {
		return workspaceMACCoverage{Boundary: tree, HelperOwned: false}, nil
	}

	// Discover the actual persistent covering boundary.
	boundaries, err := d.mgr.listCoveringFcontexts(tree)
	if err != nil {
		return workspaceMACCoverage{}, fmt.Errorf("cannot discover SELinux coverage for %s: %w", tree, err)
	}

	for _, boundary := range boundaries {
		// Boundary exists — verify the actual on-disk type for the tree.
		if err := d.mgr.verifyActualType(tree); err != nil {
			return workspaceMACCoverage{}, fmt.Errorf("existing SELinux boundary %s exists but actual type for %s is incorrect: %w", boundary, tree, err)
		}
		// Driver reports discovered coverage conservatively;
		// sessionMACCoordinator resolves HelperOwned using mac_boundaries metadata.
		return workspaceMACCoverage{Boundary: boundary, HelperOwned: false}, nil
	}

	// No persistent fcontext boundary found — this is not durable MAC state.
	// A correct current xattr without a persistent boundary is insufficient
	// because it will not survive a restorecon or reboot.
	return workspaceMACCoverage{}, fmt.Errorf("tree %s has no persistent SELinux fcontext boundary", tree)
}

func (d *selinuxWorkspaceMACDriver) findExistingCoverage(tree string) (workspaceMACCoverage, bool, error) {
	boundaries, err := d.mgr.listCoveringFcontexts(tree)
	if err != nil {
		return workspaceMACCoverage{}, false, fmt.Errorf("cannot list covering SELinux boundaries: %w", err)
	}
	for _, boundary := range boundaries {
		// Driver reports discovered coverage conservatively;
		// sessionMACCoordinator resolves HelperOwned using mac_boundaries metadata.
		return workspaceMACCoverage{Boundary: boundary, HelperOwned: false}, true, nil
	}
	return workspaceMACCoverage{}, false, nil
}

func (d *selinuxWorkspaceMACDriver) removeBoundary(boundary string) error {
	if isUnderHome(boundary) {
		return nil
	}
	return d.mgr.removeFcontextBoundary(boundary)
}

// discoverHelperOwnedBoundaries returns nil because the driver does not know
// durable helper ownership; sessionMACCoordinator resolves HelperOwned using
// mac_boundaries metadata.
func (d *selinuxWorkspaceMACDriver) discoverHelperOwnedBoundaries() ([]string, error) {
	return nil, nil
}

func (d *selinuxWorkspaceMACDriver) backend() LSMBackend {
	return LSMSELinux
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
		mgr := newProductionAppArmorProfileManager()
		return &appArmorWorkspaceMACDriver{
			addManagedBoundary: func(path string) (boundaryResult, error) {
				return mgr.addManagedBoundary(path)
			},
			removeManagedBoundary: func(path string) (boundaryResult, error) {
				return mgr.removeManagedBoundary(path)
			},
			listManagedBoundaries: func() ([]string, error) {
				return mgr.listManagedBoundaries()
			},
		}, nil
	case LSMSELinux:
		return &selinuxWorkspaceMACDriver{
			mgr:      newSELinuxFcontextManager(),
			treeKind: selinuxTreeKindFor,
		}, nil
	default:
		return nil, nil
	}
}

// newMACCoordinatorForMode builds the session MAC coordinator for the given
// deployment mode, returning nil when no MAC driver is active (e.g. user
// mode). runDaemon uses this so App.MACCoordinator stays nil whenever there is
// no active MAC driver; persisted live sessions then need no in-memory MAC
// bindings to be usable.
func newMACCoordinatorForMode(db *sql.DB, mode DeploymentMode, detectLSM func() (LSMBackend, error)) (*sessionMACCoordinator, error) {
	driver, err := newWorkspaceMACDriver(mode, detectLSM)
	if err != nil {
		return nil, err
	}
	if driver == nil {
		return nil, nil
	}
	return newSessionMACCoordinator(db, driver), nil
}
