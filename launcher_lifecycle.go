package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
)

// ErrLauncherRuntimeActive is returned by checked Launcher/Principal deletion
// when attributable helper runtime is still active or unclassifiable for that
// Launcher/Principal. The stable public conflict is 409 launcher_runtime_active.
var ErrLauncherRuntimeActive = errors.New("launcher runtime active")

func isErrLauncherRuntimeActive(err error) bool { return errors.Is(err, ErrLauncherRuntimeActive) }

// helperContainer is one helper-owned container observed by the Docker
// inspector during checked deletion. State preserves the actual Docker .State
// string; classification is explicit (classifyHelperContainerState), so checked
// deletion never guesses from a boolean. Only schema-coherent,
// launcher-attributable containers are surfaced (labels are evidence, not
// authorization).
type helperContainer struct {
	ID    string
	State string
}

// helperContainerState is the checked-deletion classification of one
// helper-owned container's Docker state.
type helperContainerState int

const (
	// helperStateStale marks a container in an explicitly safe-to-remove
	// Docker state (created, exited, dead).
	helperStateStale helperContainerState = iota
	// helperStateActive marks a container in a runtime-active or transitional
	// Docker state (running, paused, restarting, removing): checked deletion
	// refuses with ErrLauncherRuntimeActive.
	helperStateActive
	// helperStateUnknown marks a Docker state outside the known set: checked
	// deletion fails closed on it instead of guessing.
	helperStateUnknown
)

// classifyHelperContainerState maps a Docker container's .State string to the
// checked-deletion class that governs it: created/exited/dead are explicitly
// safe to remove, running/paused/restarting/removing are runtime-active or
// transitional, and any unrecognized value is unknown so deletion fails
// closed rather than treating the container as stale.
func classifyHelperContainerState(state string) helperContainerState {
	switch state {
	case "created", "exited", "dead":
		return helperStateStale
	case "running", "paused", "restarting", "removing":
		return helperStateActive
	default:
		return helperStateUnknown
	}
}

// launcherEnabledChangeResult is the explicit result of a Launcher
// enabled-state transition.
type launcherEnabledChangeResult struct {
	Changed           bool
	RevokedSessionIDs []string
	// AdmissionClosed is the effective operation-admission state this Launcher
	// must hold after the committed transition, decided transactionally:
	// closed iff Principal.enabled or the resulting Launcher.enabled does not
	// hold. It is set whenever an enabled-state change was requested
	// (enabled != nil), so callers apply it in memory after commit without
	// another DB read; it is nil when only a rename was requested.
	AdmissionClosed *bool
}

// launcherAdmission is one child Launcher's final operation-admission state,
// decided transactionally during a Principal/Launcher enabled-state
// transition: closed refuses new Operations for that Launcher.
type launcherAdmission struct {
	LauncherID string
	Closed     bool
}

// persistLauncherChange performs a transactionally correct rename and/or
// enabled-state transition for a Launcher. It:
//   - determines Launcher existence within the transaction;
//   - validates and applies a requested rename (SQLite's
//     UNIQUE(principal_id, name) is the final uniqueness authority; a colliding
//     rename aborts the whole transaction, so a combined rename+disable leaves
//     no partial state);
//   - when disabling, collects and deletes only that Launcher's Sessions
//     regardless of whether the enabled state already changed (retry-safe:
//     re-invoking disable must not skip session cleanup);
//   - updates the enabled state when requested, deciding the Launcher's final
//     operation-admission state transactionally (closed iff Principal.enabled
//     or the resulting Launcher.enabled does not hold);
//   - commits;
//   - returns explicit Changed, RevokedSessionIDs, and the admission decision.
//
// Re-enabling only flips the enabled state; it never recreates Sessions. A nil
// name or enabled pointer leaves that field untouched.
func persistLauncherChange(db *sql.DB, launcherID string, name *string, enabled *bool) (launcherEnabledChangeResult, error) {
	if launcherID == "" {
		return launcherEnabledChangeResult{}, ErrLauncherNotFound
	}
	if name != nil {
		if _, err := validateLauncherName(*name); err != nil {
			return launcherEnabledChangeResult{}, err
		}
	}

	tx, err := db.Begin()
	if err != nil {
		return launcherEnabledChangeResult{}, fmt.Errorf("cannot begin transaction: %w", err)
	}

	var currentEnabled int
	var principalEnabled int
	var principalName string
	err = tx.QueryRow(
		`SELECT l.enabled, p.enabled, p.username
		   FROM launchers l JOIN principals p ON p.id = l.principal_id
		  WHERE l.id = ?`,
		launcherID,
	).Scan(&currentEnabled, &principalEnabled, &principalName)
	if err != nil {
		tx.Rollback()
		if errors.Is(err, sql.ErrNoRows) {
			return launcherEnabledChangeResult{}, ErrLauncherNotFound
		}
		return launcherEnabledChangeResult{}, fmt.Errorf("cannot read launcher enabled state: %w", err)
	}

	if name != nil {
		// SQLite's UNIQUE(principal_id, name) is the final authority on name
		// uniqueness, so we do not pre-check: a concurrent rename that races
		// this UPDATE is surfaced by the constraint and mapped to
		// ErrLauncherExists below rather than surfacing as an internal error.
		if _, err := tx.Exec(`UPDATE launchers SET name = ? WHERE id = ?`, *name, launcherID); err != nil {
			tx.Rollback()
			if isSQLiteUniqueError(err) {
				return launcherEnabledChangeResult{}, fmt.Errorf("launcher %q already exists for principal %q: %w", *name, principalName, ErrLauncherExists)
			}
			return launcherEnabledChangeResult{}, fmt.Errorf("cannot update launcher name: %w", err)
		}
	}

	var changed bool
	var sessionIDs []string
	var admissionClosed *bool
	if enabled != nil {
		newEnabled := 0
		if *enabled {
			newEnabled = 1
		}
		changed = currentEnabled != newEnabled

		// The final operation-admission state for this Launcher is decided
		// within this same transaction — closed iff Principal.enabled or the
		// resulting Launcher.enabled does not hold — so the committed enable
		// is applied in memory without another (fallible) DB read.
		closed := principalEnabled == 0 || newEnabled == 0
		admissionClosed = &closed

		if !*enabled {
			// Collect this Launcher's Session IDs before deletion for runtime
			// cleanup. Runs unconditionally on disable so a re-invoked disable
			// still cleans up any Sessions left behind by a prior partial
			// failure.
			rows, err := tx.Query(`SELECT id FROM sessions WHERE launcher_id = ?`, launcherID)
			if err != nil {
				tx.Rollback()
				return launcherEnabledChangeResult{}, fmt.Errorf("cannot query launcher sessions: %w", err)
			}
			for rows.Next() {
				var id string
				if err := rows.Scan(&id); err != nil {
					rows.Close()
					tx.Rollback()
					return launcherEnabledChangeResult{}, fmt.Errorf("cannot scan session id: %w", err)
				}
				sessionIDs = append(sessionIDs, id)
			}
			if err := rows.Err(); err != nil {
				rows.Close()
				tx.Rollback()
				return launcherEnabledChangeResult{}, fmt.Errorf("iterate sessions: %w", err)
			}
			rows.Close()

			if _, err := tx.Exec(`DELETE FROM sessions WHERE launcher_id = ?`, launcherID); err != nil {
				tx.Rollback()
				return launcherEnabledChangeResult{}, fmt.Errorf("cannot delete launcher sessions: %w", err)
			}
		}

		if changed {
			if _, err := tx.Exec(`UPDATE launchers SET enabled = ? WHERE id = ?`, newEnabled, launcherID); err != nil {
				tx.Rollback()
				return launcherEnabledChangeResult{}, fmt.Errorf("cannot update launcher enabled: %w", err)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return launcherEnabledChangeResult{}, fmt.Errorf("cannot commit launcher change: %w", err)
	}

	return launcherEnabledChangeResult{
		Changed:           changed,
		RevokedSessionIDs: sessionIDs,
		AdmissionClosed:   admissionClosed,
	}, nil
}

// applyLauncherEnabledChange is the App-level lifecycle operation for
// transitioning a Launcher's enabled state. It commits the DB change and, after
// successful commit, releases every deleted Session binding through the MAC
// coordinator. Running operations are NOT terminated.
func (a *App) applyLauncherEnabledChange(launcherID string, enabled bool) (launcherEnabledChangeResult, error) {
	result, err := persistLauncherChange(a.DB, launcherID, nil, &enabled)
	if err != nil {
		return launcherEnabledChangeResult{}, err
	}
	if len(result.RevokedSessionIDs) > 0 {
		a.releaseSessionBindings(result.RevokedSessionIDs)
	}
	return result, nil
}

// createPrincipalWithLifecycle is the lock-owning App-level Principal
// creation. It holds lifecycleMu across the current global-root resolution
// (the same symlink-resolved representation as the canonical root-policy
// surfaces — the lifecycleMu -> a.mu ordering shared with config reload), the
// Principal home/allowed-root validation against that ceiling, and the
// durable Principal/default-Launcher/credential transaction, so a Principal
// whose home is outside the ceiling committed by any reload that linearized
// before it is rejected before any durable change, and a creation that
// linearizes first completes atomically under the policy it validated
// against.
func (a *App) createPrincipalWithLifecycle(username string, issueCredential bool) (*PrincipalWithRoots, *PrincipalCredential, string, error) {
	a.lifecycleMu.Lock()
	defer a.lifecycleMu.Unlock()
	globalRoots, err := a.appResolvedGlobalRoots()
	if err != nil {
		return nil, nil, "", err
	}
	return createPrincipalWithOptionalCredential(a.DB, username, globalRoots, issueCredential)
}

// createLauncherWithLifecycle is the lock-owning App-level Launcher creation.
// It holds lifecycleMu across the canonical effective-Principal-root
// resolution (which reads the current global policy snapshot — the same
// lifecycleMu -> a.mu ordering as config reload) and the durable mutation, so
// a restricted-root validation observes the ceiling committed by any reload
// that linearized before it, and the created Launcher cannot interleave with
// another Launcher/Principal lifecycle mutation on the same ownership.
func (a *App) createLauncherWithLifecycle(principalID int64, name string, scope LauncherScopeMode, allowedRoots []string, issueCredential bool) (*LauncherWithPrincipal, *launcherCredential, string, error) {
	a.lifecycleMu.Lock()
	defer a.lifecycleMu.Unlock()
	ceiling, err := a.resolveEffectivePrincipalRoots(principalID)
	if err != nil {
		return nil, nil, "", err
	}
	return createLauncher(a.DB, principalID, name, scope, allowedRoots, ceiling, issueCredential)
}

// updateLauncherWithLifecycle is the App-level lifecycle operation for a
// Launcher PATCH (rename and/or enable/disable). Rename and enabled-state
// change commit atomically, so a failed durable change leaves no partial
// rename behind and a colliding rename aborts a requested disable as well.
//
// Disabling quiesces Operation admission before the change commits and keeps
// it closed on success (quiesce is the runtime companion of durable disabled
// state); a failed durable change restores admission from the hierarchical
// authorities. Enabling commits first and then applies the admission state
// that was decided transactionally as part of the same serialized durable
// decision — no post-commit DB read can fail after durable success — so a
// Launcher enabled while its Principal is disabled stays quiesced. After a
// successful disable commit, every deleted Session binding is released through
// the MAC coordinator; running operations are NOT terminated. The returned
// projection is composed from the pre-change row and the committed overrides,
// so success is never followed by a fallible lookup.
//
// updateLauncherWithLifecycle is a lock-owning lifecycle mutator: it holds
// lifecycleMu for the whole transition so it cannot interleave with another
// Launcher/Principal lifecycle mutation on the same ownership.
func (a *App) updateLauncherWithLifecycle(launcherID string, name *string, enabled *bool) (*LauncherWithPrincipal, []string, error) {
	a.lifecycleMu.Lock()
	defer a.lifecycleMu.Unlock()
	return a.updateLauncherWithLifecycleLocked(launcherID, name, enabled)
}

// updateLauncherWithLifecycleLocked is the lock-already-held form of
// updateLauncherWithLifecycle. It is used internally by lifecycle mutators
// that already hold lifecycleMu.
func (a *App) updateLauncherWithLifecycleLocked(launcherID string, name *string, enabled *bool) (*LauncherWithPrincipal, []string, error) {
	// The reserved user-mode daemon-owner default Launcher refuses disable and
	// rename-away-from-default here, inside the lifecycle serialization
	// boundary and before any quiesce or durable change; invariant-preserving
	// no-ops pass.
	if err := a.rejectReservedLauncherPatch(launcherID, name, enabled); err != nil {
		return nil, nil, err
	}

	cur, err := findLauncherByID(a.DB, launcherID)
	if err != nil {
		return nil, nil, err
	}

	disabling := enabled != nil && !*enabled
	if disabling {
		a.OperationSupervisor.quiesceLauncher(launcherID)
	}

	result, err := persistLauncherChange(a.DB, launcherID, name, enabled)
	if err != nil {
		if disabling {
			// The quiesce is the prologue of the durable disable: if the
			// durable change fails before committing, admission must mirror
			// exactly what Principal.enabled and Launcher.enabled now say. If
			// that authoritative re-read itself fails, admission stays
			// quiesced — never fail open. The original DB error is preserved
			// as the returned operation error.
			if syncErr := a.syncLauncherAdmission(launcherID); syncErr != nil {
				logLifecycleAdmissionSyncError(launcherID, syncErr)
			}
		}
		return nil, nil, err
	}

	if len(result.RevokedSessionIDs) > 0 {
		a.releaseSessionBindings(result.RevokedSessionIDs)
	}

	if enabled != nil && *enabled {
		// Enable commits the enabled state first. The final admission state
		// was decided transactionally as part of the same serialized durable
		// decision, so applying it here is non-fallible and requires no DB
		// read: a Launcher enabled while its Principal is disabled stays
		// quiesced.
		a.OperationSupervisor.setQuiesced(launcherID, *result.AdmissionClosed)
	}

	updated := *cur
	if name != nil {
		updated.Name = *name
	}
	if enabled != nil {
		updated.Enabled = *enabled
	}
	return &updated, result.RevokedSessionIDs, nil
}

// hasRunningForLauncher reports whether any in-memory operation of the given
// Launcher is currently running. This is the operation-supervisor provenance
// side of checked deletion.
func (s *operationSupervisor) hasRunningForLauncher(launcherID string) bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	var candidates []*operation
	for _, op := range s.ops {
		if op.LauncherID == launcherID {
			candidates = append(candidates, op)
		}
	}
	s.mu.RUnlock()
	for _, op := range candidates {
		op.mu.Lock()
		running := op.State == operationRunning
		op.mu.Unlock()
		if running {
			return true
		}
	}
	return false
}

// quiesceLauncher refuses future admit() calls for Operations owned by
// launcherID. It is the operation-admission closing point for checked deletion:
// it is set before the runtime inspection, so every Operation admitted before
// it is visible to that inspection and no Operation can be admitted after it
// while the owner removal proceeds. Atomic with admit via the supervisor mutex.
func (s *operationSupervisor) quiesceLauncher(launcherID string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.quiesced == nil {
		s.quiesced = make(map[string]bool)
	}
	s.quiesced[launcherID] = true
}

// setQuiesced sets the supervisor admission state for launcherID to the given
// value in one atomic step. closed=true refuses new Operations for it;
// closed=false reopens admission. It is the primitive used by
// syncLauncherAdmission to mirror the effective hierarchical authorities.
func (s *operationSupervisor) setQuiesced(launcherID string, closed bool) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if closed {
		if s.quiesced == nil {
			s.quiesced = make(map[string]bool)
		}
		s.quiesced[launcherID] = true
	} else {
		delete(s.quiesced, launcherID)
	}
}

// effectiveLauncherClosed reports whether runtime admission is closed for
// launcherID under the two hierarchical authorities: it is closed iff the
// Launcher does not exist or either its Principal or the Launcher itself is
// disabled (admission is open only when Principal.enabled && Launcher.enabled).
// It consults only the existing Principal.enabled and Launcher.enabled columns;
// it adds no persisted state.
func effectiveLauncherClosed(db *sql.DB, launcherID string) (bool, error) {
	var pEnabled, lEnabled int
	err := db.QueryRow(
		`SELECT p.enabled, l.enabled
		   FROM launchers l JOIN principals p ON p.id = l.principal_id
		  WHERE l.id = ?`, launcherID).Scan(&pEnabled, &lEnabled)
	if errors.Is(err, sql.ErrNoRows) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("cannot read launcher authorities: %w", err)
	}
	return pEnabled == 0 || lEnabled == 0, nil
}

// syncLauncherAdmission re-reads the effective hierarchical authorities
// (Principal.enabled && Launcher.enabled) from the database and sets the
// supervisor admission state for launcherID accordingly. It is the fail-closed
// recovery primitive for error/refusal paths: after a mutation failed before
// committing, admission must mirror exactly what the durable authorities say
// (a previously disabled Launcher stays quiesced; a committed-but-unreported
// transition is not re-opened). A failed re-read keeps the Launcher quiesced —
// never fail open — and the caller surfaces it through
// logLifecycleAdmissionSyncError. Successful enable/disable paths no longer
// use it: they apply the admission state decided transactionally as part of
// the same serialized durable decision.
func (a *App) syncLauncherAdmission(launcherID string) error {
	closed, err := effectiveLauncherClosed(a.DB, launcherID)
	if err != nil {
		return err
	}
	a.OperationSupervisor.setQuiesced(launcherID, closed)
	return nil
}

// logLifecycleAdmissionSyncError reports a failure to re-sync a Launcher's
// operation admission from its durable hierarchical authorities during an
// error-path recovery. Fail-closed behavior keeps the Launcher quiesced in this
// case; the log surfaces that the re-read (and therefore any re-open) did not
// happen, for operator visibility. It is independent of any request context,
// so it logs without request-scoped attributes.
func logLifecycleAdmissionSyncError(launcherID string, err error) {
	logger := logging.snapshotLogger()
	if logger == nil {
		return
	}
	logger.Error("sync launcher admission from authorities failed",
		slog.String("operation", "lifecycle_admission_sync"),
		slog.String("launcher_id", launcherID),
		slog.String("error", err.Error()),
	)
}

// isLauncherQuiesced reports whether operation admission is currently refused
// for launcherID.
func (s *operationSupervisor) isLauncherQuiesced(launcherID string) bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.quiesced[launcherID]
}

// inspectHelperContainersForLauncher shells out to the Docker CLI to list
// schema-coherent, launcher-attributable containers. Any unclassifiable output
// fails closed so checked deletion never deletes a Launcher it cannot attribute.
func (a *App) inspectHelperContainersForLauncher(ctx context.Context, launcherID string) ([]helperContainer, error) {
	if a.InspectHelperContainers != nil {
		return a.InspectHelperContainers(ctx, launcherID)
	}
	cmd := a.newDockerCommand(ctx, "docker", "ps", "-a",
		"--filter", "label="+runtimeLabelSchema+"="+runtimeLabelSchemaValue,
		"--filter", "label="+runtimeLabelLauncherID+"="+launcherID,
		// docker ps renders .State as a plain string ("running", "exited",
		// ...) — unlike docker inspect, where .State.Running is a boolean.
		// The raw state string is preserved verbatim and classified
		// explicitly by classifyHelperContainerState.
		"--format", "{{.ID}} {{.State}}")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("cannot inspect helper containers: %w", err)
	}
	trimmed := strings.TrimSpace(string(out))
	if trimmed == "" {
		return nil, nil
	}
	var containers []helperContainer
	for _, line := range strings.Split(trimmed, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) != 2 {
			return nil, fmt.Errorf("unexpected docker ps output: %q", line)
		}
		containers = append(containers, helperContainer{ID: parts[0], State: parts[1]})
	}
	return containers, nil
}

// removeStaleHelperContainers removes helper containers whose classification is
// explicitly safe to remove (created/exited/dead). It is part of the committed
// path of checked deletion, never the check: the check inspects runtime without
// mutating it, and stale removal runs only after the classification confirmed
// the runtime is quiescent. A removal failure is authoritative and aborts the
// delete so helper-owned runtime is never left behind silently. The function
// never removes a container that is not explicitly stale: an active or
// unclassifiable container here is a caller-contract violation and aborts the
// delete instead of mutating Docker state.
func (a *App) removeStaleHelperContainers(ctx context.Context, containers []helperContainer) error {
	for _, c := range containers {
		if classifyHelperContainerState(c.State) != helperStateStale {
			return fmt.Errorf("helper container %s is not in a removable state: %q", c.ID, c.State)
		}
		cmd := a.newDockerCommand(ctx, "docker", "rm", "-f", c.ID)
		if err := cmd.Run(); err != nil {
			opLog(ctx).Warn("stale helper container cleanup failed",
				slog.String("operation", "checked_delete"),
				slog.String("error", err.Error()),
			)
			return fmt.Errorf("cannot remove stale helper container %s: %w", c.ID, err)
		}
	}
	return nil
}

// deleteLauncherRow removes the Launcher row. Its Sessions were already removed
// by the disable step; roots and optional credential follow via FK cascade.
func deleteLauncherRow(db *sql.DB, launcherID string) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("cannot begin transaction: %w", err)
	}
	defer tx.Rollback()
	var exists int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM launchers WHERE id = ?`, launcherID).Scan(&exists); err != nil {
		return fmt.Errorf("cannot check launcher: %w", err)
	}
	if exists == 0 {
		return ErrLauncherNotFound
	}
	if _, err := tx.Exec(`DELETE FROM launchers WHERE id = ?`, launcherID); err != nil {
		return fmt.Errorf("cannot delete launcher: %w", err)
	}
	return tx.Commit()
}

// launcherRuntimeInspection is the side-effect-free result of the checked-delete
// runtime classification: whether attributable runtime is active (an in-memory
// Operation admitted before the quiesce is still running, or an attributable
// running helper container exists), plus the full attributable container list
// for the committed-path stale cleanup.
type launcherRuntimeInspection struct {
	containers []helperContainer
	active     bool
}

// inspectLauncherRuntime classifies a Launcher's runtime without mutating
// anything. An Operation admitted before the quiesce is still running refuses
// immediately on supervisor provenance (no Docker round-trip is needed); an
// attributable container in a runtime-active or transitional state refuses with
// ErrLauncherRuntimeActive, and an unrecognized container state is a
// classification error — both fail closed so a Launcher is never deleted when
// its runtime cannot be classified, and neither mutates anything.
func (a *App) inspectLauncherRuntime(ctx context.Context, launcherID string) (launcherRuntimeInspection, error) {
	if a.OperationSupervisor.hasRunningForLauncher(launcherID) {
		return launcherRuntimeInspection{active: true}, nil
	}
	containers, err := a.inspectHelperContainersForLauncher(ctx, launcherID)
	if err != nil {
		return launcherRuntimeInspection{}, err
	}
	for _, c := range containers {
		switch classifyHelperContainerState(c.State) {
		case helperStateActive:
			return launcherRuntimeInspection{containers: containers, active: true}, nil
		case helperStateUnknown:
			return launcherRuntimeInspection{}, fmt.Errorf("cannot classify helper container %s state %q", c.ID, c.State)
		}
	}
	return launcherRuntimeInspection{containers: containers}, nil
}

// restoreLauncherAdmissionAfterRefusal re-syncs a Launcher's Operation
// admission from its durable hierarchical authorities after a checked delete
// was refused while the Launcher was merely prologue-quiesced. The supervisor
// forgets the quiesce (admission re-opens) exactly where the authorities say
// the Launcher is effectively enabled, and a Launcher the operator had already
// disabled stays admission-closed. A failed re-read keeps the Launcher
// quiesced — never fail open — and is surfaced through
// logLifecycleAdmissionSyncError for operator visibility.
func (a *App) restoreLauncherAdmissionAfterRefusal(launcherID string) {
	if err := a.syncLauncherAdmission(launcherID); err != nil {
		logLifecycleAdmissionSyncError(launcherID, err)
	}
}

// disableLauncher transitions a Launcher to disabled, invalidating its Sessions
// (closing Session admission at the DB level via the enabled-conditional INSERT)
// and closing Operation admission on the supervisor. The quiesce is set BEFORE
// the DB transition so an in-flight request that already resolved its Session
// before the disable cannot admit an Operation after it. On a successful
// transition the Launcher stays quiesced: quiesce is the runtime companion of
// the durable disabled state, and only a subsequent enable reopens admission.
// If the DB transition fails before committing, admission is restored. Returns
// the invalidated Session IDs for runtime-directory cleanup.
//
// disableLauncher is a lock-owning lifecycle mutator: it holds lifecycleMu for
// the whole transition so it cannot interleave with another Launcher/Principal
// lifecycle mutation on the same ownership.
func (a *App) disableLauncher(launcherID string) ([]string, error) {
	a.lifecycleMu.Lock()
	defer a.lifecycleMu.Unlock()
	return a.disableLauncherLocked(launcherID)
}

// disableLauncherLocked is the lock-already-held form of disableLauncher. It is
// used internally by lifecycle mutators that already hold lifecycleMu.
func (a *App) disableLauncherLocked(launcherID string) ([]string, error) {
	// The reserved user-mode daemon-owner default Launcher refuses disable at
	// its durable-transition owner. For the checked-delete paths this is
	// unreachable (their reservation guard already refused before the
	// prologue quiesce); it guards the direct disable transition.
	if err := a.rejectReservedLauncherOwnerMutation(launcherID); err != nil {
		return nil, err
	}
	a.OperationSupervisor.quiesceLauncher(launcherID)
	result, err := a.applyLauncherEnabledChange(launcherID, false)
	if err != nil {
		// Restore admission from the durable hierarchical authorities instead
		// of re-opening it unconditionally. The disable may have failed before
		// committing, so admission must mirror exactly what Principal.enabled
		// and Launcher.enabled now say: admission == !(Principal.enabled &&
		// Launcher.enabled). If that authoritative re-read itself fails,
		// admission stays quiesced — never fail open. The original DB error is
		// preserved as the returned operation error.
		if syncErr := a.syncLauncherAdmission(launcherID); syncErr != nil {
			logLifecycleAdmissionSyncError(launcherID, syncErr)
		}
		return nil, err
	}
	return result.RevokedSessionIDs, nil
}

// enableLauncher re-enables a Launcher: the enabled state commits first, and
// the final admission state — decided transactionally as part of the same
// serialized durable decision — is applied in memory afterwards without
// another DB read. When the Launcher's Principal is disabled, the Launcher's
// launcher.enabled may become true but its runtime admission MUST remain
// quiesced; admission reopens only once both authorities are enabled. Sessions
// are never recreated; a fresh Session must be created against the enabled
// Launcher and enabled Principal.
//
// enableLauncher is a lock-owning lifecycle mutator: it holds lifecycleMu for
// the whole transition.
func (a *App) enableLauncher(launcherID string) error {
	a.lifecycleMu.Lock()
	defer a.lifecycleMu.Unlock()
	return a.enableLauncherLocked(launcherID)
}

// enableLauncherLocked is the lock-already-held form of enableLauncher. It is
// used internally by lifecycle mutators that already hold lifecycleMu.
func (a *App) enableLauncherLocked(launcherID string) error {
	result, err := a.applyLauncherEnabledChange(launcherID, true)
	if err != nil {
		return err
	}
	a.OperationSupervisor.setQuiesced(launcherID, *result.AdmissionClosed)
	return nil
}

// deleteLauncherChecked deletes a Launcher only after checked cleanup confirms
// no attributable runtime remains active or unclassifiable. Exact ordering:
//
//  1. Quiesce Operation admission. The quiesce is in-memory only: it is set
//     before the runtime check so every Operation admitted before it is visible
//     to that check and no Operation can be admitted after it while the owner
//     removal proceeds.
//  2. Runtime check, side-effect free: any operation admitted before the
//     quiesce that is still running, or an attributable running container,
//     refuses deletion with ErrLauncherRuntimeActive. Inspection failure
//     (runtime cannot be classified — for example Docker CLI unavailable)
//     also refuses deletion. Both refusals leave the Launcher exactly as it
//     was: row, Sessions, and enabled state untouched, and the prologue
//     quiesce undone by re-syncing admission from the authorities — the
//     Launcher stays enabled so it can be disabled explicitly first.
//  3. Authoritative stale-container removal: exited attributable containers
//     are removed before the durable disable, so a removal failure aborts the
//     delete before any durable state changes.
//  4. Durable disable: Sessions are invalidated here, and only here, after the
//     runtime was confirmed quiescent and stale containers were removed. The
//     quiesce is kept: it is the runtime companion of the durable disabled
//     state.
//  5. Launcher row removal. A row-removal failure leaves the Launcher durably
//     disabled, its Sessions invalidated, and admission closed; a retry is
//     safe because the disable is idempotent and re-runs the whole check.
//     The already-invalidated Session IDs are returned together with the
//     error so their runtime-directory cleanup still runs — invalidated
//     Sessions are never rolled back or recreated.
//
// A running Operation can never lose its persisted Launcher owner: the quiesce
// closes admission (post-quiesce admits are refused), while every Operation
// admitted before the quiesce is visible to the step-2 check, and on refusal
// the row, its Sessions, and the enabled state are preserved. It never kills a
// genuinely running Operation. The supervisor's quiesce entry outlives a
// successful delete deliberately: it refuses admission for an in-flight request
// that resolved its Session before the owner removal, and Launcher IDs are
// never reused, so it cannot leak into a re-created owner.
//
// deleteLauncherChecked is a lock-owning lifecycle mutator: it holds lifecycleMu
// across the runtime inspection so no competing enable/disable/delete of the
// same Launcher can interleave between the admission-closing prologue and the
// owner removal.
func (a *App) deleteLauncherChecked(ctx context.Context, launcherID string) ([]string, error) {
	a.lifecycleMu.Lock()
	defer a.lifecycleMu.Unlock()
	return a.deleteLauncherCheckedLocked(ctx, launcherID)
}

// deleteLauncherCheckedLocked is the lock-already-held form of
// deleteLauncherChecked. It is used internally by lifecycle mutators that
// already hold lifecycleMu.
func (a *App) deleteLauncherCheckedLocked(ctx context.Context, launcherID string) ([]string, error) {
	// The reserved user-mode daemon-owner default Launcher is never deletable:
	// refuse before the admission-closing prologue so a rejected delete leaves
	// no quiesce, runtime inspection, or durable change behind.
	if err := a.rejectReservedLauncherOwnerMutation(launcherID); err != nil {
		return nil, err
	}

	// Step 1: quiesce Operation admission. In-memory only: the quiesce is the
	// operation-admission closing point, set before the runtime check so every
	// Operation admitted before it is visible to that check and no Operation
	// can be admitted after it while the checked deletion proceeds. It is
	// undone on refusal for an effectively-enabled Launcher.
	a.OperationSupervisor.quiesceLauncher(launcherID)

	// Step 2: side-effect-free runtime classification.
	inspection, err := a.inspectLauncherRuntime(ctx, launcherID)
	if err != nil {
		a.restoreLauncherAdmissionAfterRefusal(launcherID)
		return nil, fmt.Errorf("cannot inspect launcher runtime: %w", err)
	}
	if inspection.active {
		a.restoreLauncherAdmissionAfterRefusal(launcherID)
		return nil, ErrLauncherRuntimeActive
	}

	// Step 3: authoritative stale-container removal, still before any durable
	// state change.
	if err := a.removeStaleHelperContainers(ctx, inspection.containers); err != nil {
		a.restoreLauncherAdmissionAfterRefusal(launcherID)
		return nil, err
	}

	// Step 4: durable disable. Sessions are invalidated here — and only here —
	// so a refused delete leaves the Sessions and the enabled state untouched.
	revoked, err := a.disableLauncherLocked(launcherID)
	if err != nil {
		return nil, err
	}

	// Step 5: owner removal. On failure the Launcher stays durably disabled,
	// its Sessions invalidated, and admission closed; a retry re-runs the
	// whole check against the disabled Launcher. The invalidated Session IDs
	// are returned with the error so the caller still runs their
	// runtime-directory cleanup.
	if err := deleteLauncherRow(a.DB, launcherID); err != nil {
		return revoked, err
	}
	return revoked, nil
}

// principalLaunchers returns the IDs of all Launchers beneath a Principal.
func principalLaunchers(db *sql.DB, principalID int64) ([]string, error) {
	rows, err := db.Query(`SELECT id FROM launchers WHERE principal_id = ?`, principalID)
	if err != nil {
		return nil, fmt.Errorf("cannot query principal launchers: %w", err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("cannot scan launcher id: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate launchers: %w", err)
	}
	return ids, nil
}

// deletePrincipalChecked deletes a Principal only after checked cleanup confirms
// no attributable runtime remains active or unclassifiable across any of its
// Launchers. The admission-closing prologue quiesces Operation admission for
// every Launcher beneath the Principal BEFORE the runtime check. The check is
// side-effect free: any running Operation admitted before the quiesce, or an
// attributable running container, refuses the delete with ErrLauncherRuntimeActive
// (409), leaving the Principal, its Launchers, their Sessions, and their enabled
// states untouched, with the prologue quiesce undone for effectively-enabled
// Launchers. Inspection failure (runtime cannot be classified — for example
// Docker CLI unavailable) also refuses the delete with the same side-effect-free
// guarantee. On a clean check, stale containers are removed authoritatively for
// every Launcher (still before any durable state change), every Launcher is then
// durably disabled — invalidating its Sessions — and the committed removal is
// delegated to the existing Principal delete owner.
//
// deletePrincipalChecked is a lock-owning lifecycle mutator: it holds lifecycleMu
// across the whole check so no Launcher can be created beneath this Principal,
// and no Launcher/Principal enable-disable can interleave, while the checked
// deletion proceeds.
func (a *App) deletePrincipalChecked(ctx context.Context, username string) ([]string, error) {
	a.lifecycleMu.Lock()
	defer a.lifecycleMu.Unlock()
	return a.deletePrincipalCheckedLocked(ctx, username)
}

// deletePrincipalCheckedLocked is the lock-already-held form of
// deletePrincipalChecked. It is used internally by lifecycle mutators that
// already hold lifecycleMu.
func (a *App) deletePrincipalCheckedLocked(ctx context.Context, username string) ([]string, error) {
	// The reserved user-mode daemon-owner Principal is never deletable: refuse
	// before the admission-closing prologue so a rejected delete leaves no
	// quiesce, runtime inspection, or durable change behind.
	if err := a.rejectReservedPrincipalMutation(username); err != nil {
		return nil, err
	}

	principalID, err := findPrincipalIDByUsername(a.DB, username)
	if err != nil {
		return nil, err
	}

	launchers, err := principalLaunchers(a.DB, int64(principalID))
	if err != nil {
		return nil, err
	}

	// Prologue: quiesce Operation admission for every Launcher beneath the
	// Principal before the runtime check, so no Operation can be admitted for
	// any of them while the checked deletion proceeds.
	for _, lid := range launchers {
		a.OperationSupervisor.quiesceLauncher(lid)
	}

	// Side-effect-free check phase across every Launcher.
	inspections := make(map[string]launcherRuntimeInspection, len(launchers))
	for _, lid := range launchers {
		inspection, err := a.inspectLauncherRuntime(ctx, lid)
		if err != nil {
			a.restoreLauncherAdmissionAfterPrincipalRefusal(launchers)
			return nil, fmt.Errorf("cannot inspect principal runtime: %w", err)
		}
		if inspection.active {
			a.restoreLauncherAdmissionAfterPrincipalRefusal(launchers)
			return nil, ErrLauncherRuntimeActive
		}
		inspections[lid] = inspection
	}

	// Authoritative stale-container removal for every Launcher, still before
	// any durable state changes.
	for _, lid := range launchers {
		if err := a.removeStaleHelperContainers(ctx, inspections[lid].containers); err != nil {
			a.restoreLauncherAdmissionAfterPrincipalRefusal(launchers)
			return nil, err
		}
	}

	// Durable disable across every Launcher. Sessions are invalidated here —
	// and only here — after every Launcher passed the check and stale cleanup.
	// A failure partway through leaves the already-disabled Launchers durably
	// disabled with their Sessions invalidated; the accumulated revoked IDs
	// are returned with the error so their runtime-directory cleanup still
	// runs — invalidated Sessions are never rolled back or recreated.
	var revokedAll []string
	for i, lid := range launchers {
		revoked, err := a.disableLauncherLocked(lid)
		if err != nil {
			// disableLauncher restored admission for the Launcher whose DB
			// transition failed; Launchers already durably disabled in this
			// attempt stay disabled + quiesced. The Launchers not yet reached
			// are still enabled but were prologue-quiesced: re-sync their
			// admission from the authorities so the failure does not leave
			// enabled Launchers admission-closed.
			a.restoreLauncherAdmissionAfterPrincipalRefusal(launchers[i+1:])
			return revokedAll, err
		}
		revokedAll = append(revokedAll, revoked...)
	}

	// Delegate the committed delete and MAC-binding release to the existing
	// Principal delete owner. This preserves a single production owner for the
	// DB commit. The Session IDs for runtime-dir cleanup were collected by the
	// disable step (revokedAll); the owner's own discovery returns none because
	// the disable removed the Sessions. On owner-removal failure the children
	// already durably disabled in this attempt stay disabled with their
	// Sessions invalidated, and revokedAll is returned with the error so
	// their runtime-directory cleanup still runs.
	if _, err := a.deletePrincipalWithMAC(username); err != nil {
		return revokedAll, err
	}
	return revokedAll, nil
}

// restoreLauncherAdmissionAfterPrincipalRefusal re-syncs the Operation admission
// of every given Launcher after a Principal checked delete was refused while
// they were merely prologue-quiesced. See
// restoreLauncherAdmissionAfterRefusal for the per-Launcher semantics.
func (a *App) restoreLauncherAdmissionAfterPrincipalRefusal(launchers []string) {
	for _, lid := range launchers {
		a.restoreLauncherAdmissionAfterRefusal(lid)
	}
}

// principalLaunchersByUsername returns the IDs of all Launchers beneath the
// Principal named by username.
func (a *App) principalLaunchersByUsername(username string) ([]string, error) {
	principalID, err := findPrincipalIDByUsername(a.DB, username)
	if err != nil {
		return nil, err
	}
	return principalLaunchers(a.DB, int64(principalID))
}

// disablePrincipalLaunchers is the Principal-level companion of disableLauncher.
// It quiesces Operation admission across every Launcher beneath the Principal
// BEFORE transitioning the Principal to disabled (so an in-flight request whose
// Session resolved before the disable cannot admit an Operation afterward),
// keeps them quiesced on a successful disable because quiesce is the runtime
// companion of durable disabled state, and restores them only if the DB
// transition fails before it commits.
//
// disablePrincipalLaunchers is a lock-owning lifecycle mutator: it holds
// lifecycleMu for the whole transition so it cannot interleave with a
// concurrent Launcher-enabled/Principal relation mutation on the same ownership.
func (a *App) disablePrincipalLaunchers(username string) (principalEnabledChangeResult, error) {
	a.lifecycleMu.Lock()
	defer a.lifecycleMu.Unlock()
	return a.disablePrincipalLaunchersLocked(username)
}

// disablePrincipalLaunchersLocked is the lock-already-held form of
// disablePrincipalLaunchers. It is used internally by lifecycle mutators that
// already hold lifecycleMu.
func (a *App) disablePrincipalLaunchersLocked(username string) (principalEnabledChangeResult, error) {
	// The reserved user-mode daemon-owner Principal is never disableable:
	// refuse inside the lifecycle serialization boundary and before the
	// child-Launcher quiesce prologue.
	if err := a.rejectReservedPrincipalMutation(username); err != nil {
		return principalEnabledChangeResult{}, err
	}
	launchers, err := a.principalLaunchersByUsername(username)
	if err != nil {
		return principalEnabledChangeResult{}, err
	}
	for _, lid := range launchers {
		a.OperationSupervisor.quiesceLauncher(lid)
	}
	result, err := a.applyPrincipalEnabledChange(username, false)
	if err != nil {
		// Restore each child Launcher's admission from the durable hierarchical
		// authorities instead of re-opening all of them unconditionally. The
		// Principal disable may have failed before committing, so a child is
		// admission-open only where Principal.enabled && its own Launcher.enabled
		// hold; a previously individually-disabled Launcher therefore stays
		// quiesced. If the authoritative re-read fails for a child, that child
		// stays quiesced — never fail open. The original Principal DB error is
		// preserved as the returned operation error.
		for _, lid := range launchers {
			if syncErr := a.syncLauncherAdmission(lid); syncErr != nil {
				logLifecycleAdmissionSyncError(lid, syncErr)
			}
		}
		return principalEnabledChangeResult{}, err
	}
	return result, nil
}

// enablePrincipalLaunchers is the Principal-level companion of enableLauncher.
// It persists the enabled=true transition first; every child Launcher's final
// admission state is computed transactionally as part of the same serialized
// durable decision, and applying them after the commit is non-fallible and
// requires no DB read: only Launchers whose own launcher.enabled=true are
// reopened, individually-disabled Launchers stay quiesced, and every child is
// applied in one in-memory step (no partial admission update). It never
// mutates child Launcher.enabled values. Sessions are never recreated; fresh
// Sessions must be created against the re-enabled Principal.
//
// enablePrincipalLaunchers is a lock-owning lifecycle mutator: it holds
// lifecycleMu for the whole transition.
func (a *App) enablePrincipalLaunchers(username string) (principalEnabledChangeResult, error) {
	a.lifecycleMu.Lock()
	defer a.lifecycleMu.Unlock()
	return a.enablePrincipalLaunchersLocked(username)
}

// enablePrincipalLaunchersLocked is the lock-already-held form of
// enablePrincipalLaunchers. It is used internally by lifecycle mutators that
// already hold lifecycleMu.
func (a *App) enablePrincipalLaunchersLocked(username string) (principalEnabledChangeResult, error) {
	result, err := a.applyPrincipalEnabledChange(username, true)
	if err != nil {
		return principalEnabledChangeResult{}, err
	}
	for _, la := range result.LauncherAdmissions {
		a.OperationSupervisor.setQuiesced(la.LauncherID, la.Closed)
	}
	return result, nil
}
