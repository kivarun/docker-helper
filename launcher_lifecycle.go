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
// inspector during checked deletion. Only schema-coherent, launcher-attributable
// containers are surfaced (labels are evidence, not authorization).
type helperContainer struct {
	ID      string
	Running bool
}

// launcherEnabledChangeResult is the explicit result of a Launcher
// enabled-state transition.
type launcherEnabledChangeResult struct {
	Changed           bool
	RevokedSessionIDs []string
}

// persistLauncherEnabledChange performs a transactionally correct enabled-state
// transition for a Launcher. It:
//   - determines Launcher existence within the transaction;
//   - when disabling, collects and deletes only that Launcher's Sessions
//     regardless of whether the enabled state already changed (retry-safe:
//     re-invoking disable must not skip session cleanup);
//   - updates the enabled state;
//   - commits;
//   - returns explicit Changed and RevokedSessionIDs.
//
// Re-enabling only flips the enabled state; it never recreates Sessions.
func persistLauncherEnabledChange(db *sql.DB, launcherID string, enabled bool) (launcherEnabledChangeResult, error) {
	if launcherID == "" {
		return launcherEnabledChangeResult{}, ErrLauncherNotFound
	}

	tx, err := db.Begin()
	if err != nil {
		return launcherEnabledChangeResult{}, fmt.Errorf("cannot begin transaction: %w", err)
	}

	var currentEnabled int
	err = tx.QueryRow(`SELECT enabled FROM launchers WHERE id = ?`, launcherID).Scan(&currentEnabled)
	if err != nil {
		tx.Rollback()
		if errors.Is(err, sql.ErrNoRows) {
			return launcherEnabledChangeResult{}, ErrLauncherNotFound
		}
		return launcherEnabledChangeResult{}, fmt.Errorf("cannot read launcher enabled state: %w", err)
	}

	newEnabled := 0
	if enabled {
		newEnabled = 1
	}
	changed := currentEnabled != newEnabled

	var sessionIDs []string
	if !enabled {
		// Collect this Launcher's Session IDs before deletion for runtime
		// cleanup. Runs unconditionally on disable so a re-invoked disable
		// still cleans up any Sessions left behind by a prior partial failure.
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

	if err := tx.Commit(); err != nil {
		return launcherEnabledChangeResult{}, fmt.Errorf("cannot commit enabled change: %w", err)
	}

	return launcherEnabledChangeResult{
		Changed:           changed,
		RevokedSessionIDs: sessionIDs,
	}, nil
}

// applyLauncherEnabledChange is the App-level lifecycle operation for
// transitioning a Launcher's enabled state. It commits the DB change and, after
// successful commit, releases every deleted Session binding through the MAC
// coordinator. Running operations are NOT terminated.
func (a *App) applyLauncherEnabledChange(launcherID string, enabled bool) (launcherEnabledChangeResult, error) {
	result, err := persistLauncherEnabledChange(a.DB, launcherID, enabled)
	if err != nil {
		return launcherEnabledChangeResult{}, err
	}
	if len(result.RevokedSessionIDs) > 0 {
		a.releaseSessionBindings(result.RevokedSessionIDs)
	}
	return result, nil
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

// unquiesceLauncher re-opens operation admission for launcherID. It is the
// companion of the durable enabled authorities: a Launcher's admission is open
// iff both its Principal and the Launcher itself are enabled. unquiesce is only
// called when a transition committed to an enabled-authority state; individual
// call sites derive the effective hierarchical state via
// syncLauncherAdmission rather than re-opening unconditionally.
func (s *operationSupervisor) unquiesceLauncher(launcherID string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.quiesced, launcherID)
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

// syncLauncherAdmission sets the supervisor admission state for launcherID to
// the effective hierarchical authorities (Principal.enabled && Launcher.enabled)
// after a committed transition. Used by the enable paths so a Launcher is
// reopened only when both authorities are enabled: a Launcher enabled while its
// Principal is disabled, or a sibling already individually disabled, stays
// quiesced.
func (a *App) syncLauncherAdmission(launcherID string) error {
	closed, err := effectiveLauncherClosed(a.DB, launcherID)
	if err != nil {
		return err
	}
	a.OperationSupervisor.setQuiesced(launcherID, closed)
	return nil
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
		"--format", "{{.ID}} {{.State.Running}}")
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
		containers = append(containers, helperContainer{ID: parts[0], Running: parts[1] == "true"})
	}
	return containers, nil
}

// removeStaleHelperContainers removes exited (non-running) helper containers in
// a best-effort fashion. Only schema-coherent containers already classified as
// attributable belong to this list; genuinely running containers are never
// passed here.
func (a *App) removeStaleHelperContainers(ctx context.Context, containers []helperContainer) {
	for _, c := range containers {
		if c.Running {
			continue
		}
		cmd := a.newDockerCommand(ctx, "docker", "rm", "-f", c.ID)
		if err := cmd.Run(); err != nil {
			opLog(ctx).Warn("stale helper container cleanup failed",
				slog.String("operation", "checked_delete"),
				slog.String("error", err.Error()),
			)
		}
	}
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

// runtimeActiveForLauncher reports whether checked deletion must be refused for
// launcherID: an in-memory Operation admitted before the quiesce is running, or
// an attributable running helper container exists. Fail-closes on inspection
// error so a Launcher is never deleted when its runtime cannot be classified.
func (a *App) runtimeActiveForLauncher(ctx context.Context, launcherID string) (bool, error) {
	if a.OperationSupervisor.hasRunningForLauncher(launcherID) {
		return true, nil
	}
	containers, err := a.inspectHelperContainersForLauncher(ctx, launcherID)
	if err != nil {
		return false, err
	}
	for _, c := range containers {
		if c.Running {
			return true, nil
		}
	}
	a.removeStaleHelperContainers(ctx, containers)
	return false, nil
}

// launcherPriorState captures a Launcher's enabled value before a checked-delete
// prologue disables it, so an abortive delete whose runtime cannot be classified
// can restore the authoritative state it had before it refused to proceed. It is
// internal to the checked-delete failure path and is never introduced to the
// existing disabled-state contract.
type launcherPriorState struct {
	id      string
	enabled bool
}

// launcherEnabledState reports the Launcher's current enabled value, or an error
// if it cannot be read.
func launcherEnabledState(db *sql.DB, launcherID string) (bool, error) {
	var v int
	if err := db.QueryRow(`SELECT enabled FROM launchers WHERE id = ?`, launcherID).Scan(&v); err != nil {
		return false, fmt.Errorf("cannot read launcher enabled state: %w", err)
	}
	return v != 0, nil
}

// launcherPriorStates captures the enabled state of every given Launcher before
// a checked-delete disables them.
func (a *App) launcherPriorStates(launchers []string) ([]launcherPriorState, error) {
	states := make([]launcherPriorState, 0, len(launchers))
	for _, id := range launchers {
		enabled, err := launcherEnabledState(a.DB, id)
		if err != nil {
			return nil, err
		}
		states = append(states, launcherPriorState{id: id, enabled: enabled})
	}
	return states, nil
}

// restoreLauncherStateAfterFailedDelete re-applies the captured authoritative
// enabled state of a Launcher whose checked delete was refused because its
// runtime could not be classified (and therefore the delete left no durable
// disabled authority behind), then re-syncs supervisor admission to the effective
// hierarchical authorities. A previously-enabled Launcher is re-opened; a
// previously-disabled one stays admission-closed. Sessions destroyed during the
// abortive disable prologue are not recreated; the disable was a genuine
// invalidation regardless of the delete's eventual outcome.
func (a *App) restoreLauncherStateAfterFailedDelete(ctx context.Context, prior launcherPriorState) {
	if prior.enabled {
		if _, err := a.applyLauncherEnabledChange(prior.id, true); err != nil {
			opLog(ctx).Error("restore launcher state after failed checked delete",
				slog.String("operation", "checked_delete"),
				slog.String("launcher_id", prior.id),
				slog.String("error", err.Error()),
			)
			return
		}
	}
	if err := a.syncLauncherAdmission(prior.id); err != nil {
		opLog(ctx).Error("restore launcher admission after failed checked delete",
			slog.String("operation", "checked_delete"),
			slog.String("launcher_id", prior.id),
			slog.String("error", err.Error()),
		)
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
func (a *App) disableLauncher(launcherID string) ([]string, error) {
	a.OperationSupervisor.quiesceLauncher(launcherID)
	result, err := a.applyLauncherEnabledChange(launcherID, false)
	if err != nil {
		a.OperationSupervisor.unquiesceLauncher(launcherID)
		return nil, err
	}
	return result.RevokedSessionIDs, nil
}

// enableLauncher re-enables a Launcher after the enabled state successfully
// commits, then re-syncs the supervisor admission to the effective hierarchical
// authorities. When the Launcher's Principal is disabled, the Launcher's
// launcher.enabled may become true but its runtime admission MUST remain
// quiesced; admission reopens only once both authorities are enabled. Sessions
// are never recreated; a fresh Session must be created against the enabled
// Launcher and enabled Principal.
func (a *App) enableLauncher(launcherID string) error {
	if _, err := a.applyLauncherEnabledChange(launcherID, true); err != nil {
		return err
	}
	return a.syncLauncherAdmission(launcherID)
}

// deleteLauncherChecked deletes a Launcher only after checked cleanup confirms
// no attributable runtime remains active or unclassifiable. Exact ordering:
//
//  1. Disable the Launcher, invalidate its Sessions, and quiesce Operation
//     admission (disableLauncher). Quiesce is set before the DB transition so no in-flight request whose Session resolved before the
//     disable can admit an Operation after it, and it is kept once the disable
//     commits because quiesce is the companion of durable disabled state.
//  2. Runtime check: any operation admitted before the quiesce that is still
//     running, or an attributable running container, refuses deletion with
//     ErrLauncherRuntimeActive (leaving the Launcher disabled, its Sessions
//     invalidated, admission closed, and the row preserved). Inspection failure
//     (runtime cannot be classified — for example Docker CLI unavailable)
//     also refuses deletion, but restores the Launcher to its prior enabled
//     state and re-opens admission rather than leaving it durably disabled.
//  3. If clean, remove stale/exited helper containers and delete the Launcher
//     row. Sessions were already removed by step 1.
//
// A running Operation can never lose its persisted Launcher owner: quiesce
// closes admission (post-quiesce admits return false), while every pre-quiesce
// admitted Operation is visible to the step-2 check, and on refusal the row is
// preserved. It never kills a genuinely running Operation.
func (a *App) deleteLauncherChecked(ctx context.Context, launcherID string) ([]string, error) {
	prior, err := launcherEnabledState(a.DB, launcherID)
	if err != nil {
		return nil, err
	}

	revoked, err := a.disableLauncher(launcherID)
	if err != nil {
		return nil, err
	}

	active, err := a.runtimeActiveForLauncher(ctx, launcherID)
	if err != nil {
		// Runtime cannot be classified (for example the Docker CLI is
		// unavailable): refuse the delete WITHOUT leaving the Launcher durably
		// disabled. The disable above was only the deletion prologue, so the
		// authoritative state is restored and admission re-synced to the
		// effective hierarchical authorities. This keeps checked deletion from
		// wedging a Launcher merely because its runtime cannot be inspected.
		a.restoreLauncherStateAfterFailedDelete(ctx, launcherPriorState{id: launcherID, enabled: prior})
		return nil, fmt.Errorf("cannot inspect launcher runtime: %w", err)
	}
	if active {
		// Sanctioned 409: the Launcher stays disabled + quiesced (quiesce is the
		// companion of durable disabled state); the operator re-enables or
		// retries after the runtime exits.
		return revoked, ErrLauncherRuntimeActive
	}

	if err := deleteLauncherRow(a.DB, launcherID); err != nil {
		return nil, err
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
// Launchers. The admission-closing prologue runs across every Launcher beneath
// the Principal via disableLauncher: each is disabled and its Sessions
// invalidated (closing Session admission) and quiesced on the supervisor
// (closing Operation admission). Any running Operation admitted before the
// quiesce refuses the delete with ErrLauncherRuntimeActive (409), leaving all
// of the Principal's Launchers disabled, quiesced, and their Sessions
// invalidated but preserving the rows. Inspection failure (runtime cannot be
// classified — for example Docker CLI unavailable) also refuses the delete, but
// restores every Launcher to its prior enabled state and re-opens admission so
// the Principal is not left half-torn-down. On a clean check it removes stale
// containers and delegates the committed removal to the Principal delete owner.
func (a *App) deletePrincipalChecked(ctx context.Context, username string) ([]string, error) {
	principalID, err := findPrincipalIDByUsername(a.DB, username)
	if err != nil {
		return nil, err
	}

	launchers, err := principalLaunchers(a.DB, int64(principalID))
	if err != nil {
		return nil, err
	}

	states, err := a.launcherPriorStates(launchers)
	if err != nil {
		return nil, err
	}

	var revokedAll []string
	for _, lid := range launchers {
		revoked, err := a.disableLauncher(lid)
		if err != nil {
			// disableLauncher restored admission for the Launcher whose DB
			// transition failed; Launchers already durably disabled in this
			// attempt stay disabled + quiesced.
			return nil, err
		}
		revokedAll = append(revokedAll, revoked...)
	}

	for _, lid := range launchers {
		active, err := a.runtimeActiveForLauncher(ctx, lid)
		if err != nil {
			// Runtime cannot be classified (for example the Docker CLI is
			// unavailable): refuse the Principal delete WITHOUT leaving its
			// Launchers durably disabled. Restore every Launcher to the state it
			// had before this abortive delete prologue and re-sync admission to
			// the effective hierarchical authorities.
			for _, st := range states {
				a.restoreLauncherStateAfterFailedDelete(ctx, st)
			}
			return nil, fmt.Errorf("cannot inspect principal runtime: %w", err)
		}
		if active {
			// Sanctioned 409: all Launchers stay disabled + quiesced.
			return revokedAll, ErrLauncherRuntimeActive
		}
	}

	// Delegate the committed delete and MAC-binding release to the existing
	// Principal delete owner. This preserves a single production owner for the
	// DB commit. The Session IDs for runtime-dir cleanup were already collected
	// by the disable step (revokedAll); the owner's own discovery returns none
	// because the disable removed the Sessions.
	if _, err := a.deletePrincipalWithMAC(username); err != nil {
		return nil, err
	}
	return revokedAll, nil
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
func (a *App) disablePrincipalLaunchers(username string) (principalEnabledChangeResult, error) {
	launchers, err := a.principalLaunchersByUsername(username)
	if err != nil {
		return principalEnabledChangeResult{}, err
	}
	for _, lid := range launchers {
		a.OperationSupervisor.quiesceLauncher(lid)
	}
	result, err := a.applyPrincipalEnabledChange(username, false)
	if err != nil {
		for _, lid := range launchers {
			a.OperationSupervisor.unquiesceLauncher(lid)
		}
		return principalEnabledChangeResult{}, err
	}
	return result, nil
}

// enablePrincipalLaunchers is the Principal-level companion of enableLauncher.
// It persists the enabled=true transition first and only after the successful
// commit re-syncs each child Launcher's admission to the effective hierarchical
// authorities: only Launchers whose own launcher.enabled=true are reopened;
// individually-disabled Launchers stay quiesced. It never mutates child
// Launcher.enabled values. Sessions are never recreated; fresh Sessions must be
// created against the re-enabled Principal.
func (a *App) enablePrincipalLaunchers(username string) (principalEnabledChangeResult, error) {
	launchers, err := a.principalLaunchersByUsername(username)
	if err != nil {
		return principalEnabledChangeResult{}, err
	}
	result, err := a.applyPrincipalEnabledChange(username, true)
	if err != nil {
		return principalEnabledChangeResult{}, err
	}
	for _, lid := range launchers {
		if err := a.syncLauncherAdmission(lid); err != nil {
			return result, err
		}
	}
	return result, nil
}
