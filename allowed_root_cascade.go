package main

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"path/filepath"
)

// This file is the single persistence owner of the stored allowed-root
// descendant reconciliation: when a parent ceiling is narrowed, stored child
// roots that are no longer wholly contained in the resulting parent ceiling
// are deleted in the same transaction as the parent mutation. It owns the
// reconciliation transaction boundaries only; containment and effective-scope
// semantics stay with the pure policy owner (allowed_root_policy.go) and the
// canonical path predicates (isWithinAnyAllowedRoot / pathWithin).
//
// The reconciliation covers exactly the two canonical parent mutations:
//
//   - the Principal stored-root remove (one Principal, whose stored root the
//     caller deleted in the same transaction): the Launcher-level cascade;
//   - the global-ceiling transition (reload and startup, all Principals):
//     the Principal-level prune followed by the Launcher-level cascade.
//
// Every surface calls the same primitive with the appropriate resulting
// parent policy; no surface implements its own cascade. The reconciliation
// never touches scope modes, Sessions, or Session filesystem snapshots:
// already-issued Session authority is immutable and a restricted Launcher
// whose last stored root is cascaded away stays restricted with zero roots.

// storedRootCascadeResult reports which stored allowed-root rows the
// reconciliation deleted, in canonical lexical order per Principal. The
// surfaces log it; it is not an API or audit contract.
type storedRootCascadeResult struct {
	// PrincipalRoots are the canonical Principal stored-root paths deleted
	// by the global-ceiling prune.
	PrincipalRoots []string
	// LauncherRoots are the stored restricted-Launcher roots deleted by the
	// Launcher-level cascade.
	LauncherRoots []launcherStoredRootPruned
}

// launcherStoredRootPruned is one cascaded-away stored Launcher root.
type launcherStoredRootPruned struct {
	LauncherID string
	Path       string
}

// pruneStoredAllowedRootsToCeilings deletes every stored descendant
// allowed-root row that the resulting parent ceilings no longer wholly
// contain, inside the caller's transaction.
//
// globalEntries is the resulting global allowed-root ceiling as canonical
// resolved entries (the resolved-config projection). principalID selects the
// reconciliation population: zero reconciles every Principal and additionally
// prunes stored Principal roots that no global root wholly contains (the
// global-ceiling transition — reload and startup); non-zero reconciles exactly
// that Principal without pruning any Principal root (the Principal-root remove
// surface, whose parent deletion is the caller's exact-row delete already
// committed in this transaction — other stored Principal roots are canonical
// state this surface must never touch, so an idempotent or targeted remove can
// never become an unrelated repair).
//
// For every selected Principal the resulting effective Principal ceiling is
// computed through the canonical pure policy owner
// (effectivePrincipalAllowedRoots) from the global entries and the surviving
// stored Principal roots, and every stored root of every restricted Launcher
// owned by that Principal that no effective ceiling path wholly contains is
// deleted — the same containment predicate the Session-create revalidation
// (effectiveLauncherAllowedRoots) proves against, so a canonical mutation can
// never manufacture state that owner would refuse.
//
// Containment is a path predicate only: an access-mode narrowing of a parent
// never deletes a child (the existing access meet produces the effective
// mode), and stored roots are never transformed or shortened — a root either
// remains valid as stored or is deleted.
func pruneStoredAllowedRootsToCeilings(tx *sql.Tx, globalEntries []AllowedRootEntry, principalID int64, daemonOwnerPrincipalID int64, userMode bool) (storedRootCascadeResult, error) {
	result := storedRootCascadeResult{}

	principalIDs := []int64{principalID}
	if principalID == 0 {
		rows, err := tx.Query(`SELECT id FROM principals ORDER BY id`)
		if err != nil {
			return result, fmt.Errorf("cannot enumerate principals for allowed-root reconciliation: %w", err)
		}
		principalIDs = principalIDs[:0]
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return result, fmt.Errorf("cannot scan principal for allowed-root reconciliation: %w", err)
			}
			principalIDs = append(principalIDs, id)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return result, fmt.Errorf("iterate principals for allowed-root reconciliation: %w", err)
		}
	}

	for _, pid := range principalIDs {
		if err := prunePrincipalStoredRootsToCeiling(tx, globalEntries, pid, daemonOwnerPrincipalID, userMode, principalID == 0, &result); err != nil {
			return result, err
		}
	}
	return result, nil
}

// prunePrincipalStoredRootsToCeiling reconciles one Principal's stored
// descendant roots to the resulting ceilings. globalScopePrune selects the
// Principal-root level (global-ceiling transitions only; see
// pruneStoredAllowedRootsToCeilings). appends the deleted rows to result.
func prunePrincipalStoredRootsToCeiling(tx *sql.Tx, globalEntries []AllowedRootEntry, principalID int64, daemonOwnerPrincipalID int64, userMode, globalScopePrune bool, result *storedRootCascadeResult) error {
	stored, err := readPrincipalAllowedRoots(tx, principalID)
	if err != nil {
		return err
	}

	globalPaths := allowedRootPaths(globalEntries)
	surviving := stored
	if globalScopePrune {
		surviving = make([]AllowedRootEntry, 0, len(stored))
		for _, root := range stored {
			if !isWithinAnyAllowedRoot(root.Path, globalPaths) {
				if _, err := tx.Exec(
					`DELETE FROM principal_allowed_roots WHERE principal_id = ? AND root_path = ?`,
					principalID, root.Path,
				); err != nil {
					return fmt.Errorf("cannot prune principal allowed root: %w", err)
				}
				result.PrincipalRoots = append(result.PrincipalRoots, root.Path)
				continue
			}
			surviving = append(surviving, root)
		}
	}

	ceiling := effectivePrincipalAllowedRoots(globalEntries, surviving, principalID, daemonOwnerPrincipalID, userMode)
	ceilingPaths := allowedRootPaths(ceiling)

	launchers, err := tx.Query(
		`SELECT id FROM launchers WHERE principal_id = ? AND scope_mode = ? ORDER BY id`,
		principalID, string(LauncherScopeRestricted),
	)
	if err != nil {
		return fmt.Errorf("cannot enumerate restricted launchers for allowed-root reconciliation: %w", err)
	}
	var launcherIDs []string
	for launchers.Next() {
		var id string
		if err := launchers.Scan(&id); err != nil {
			launchers.Close()
			return fmt.Errorf("cannot scan launcher for allowed-root reconciliation: %w", err)
		}
		launcherIDs = append(launcherIDs, id)
	}
	launchers.Close()
	if err := launchers.Err(); err != nil {
		return fmt.Errorf("iterate restricted launchers for allowed-root reconciliation: %w", err)
	}

	for _, launcherID := range launcherIDs {
		roots, err := readLauncherAllowedRoots(tx, launcherID)
		if err != nil {
			return err
		}
		for _, root := range roots {
			if isWithinAnyAllowedRoot(root.Path, ceilingPaths) {
				continue
			}
			if _, err := tx.Exec(
				`DELETE FROM launcher_allowed_roots WHERE launcher_id = ? AND root_path = ?`,
				launcherID, root.Path,
			); err != nil {
				return fmt.Errorf("cannot prune launcher allowed root: %w", err)
			}
			result.LauncherRoots = append(result.LauncherRoots, launcherStoredRootPruned{LauncherID: launcherID, Path: root.Path})
		}
	}
	return nil
}

// userModeDaemonOwnerPrincipalID resolves the user-mode daemon-owner
// Principal identity for the reconciliation's effective-ceiling computation:
// zero outside user mode, the startup-resolved identity inside it.
func (a *App) userModeDaemonOwnerPrincipalID() int64 {
	if a.userModeDefault != nil {
		return a.userModeDefault.principalID
	}
	return 0
}

// userModeDefaultOwnerID resolves the daemon-owner Principal identity from
// the startup ownership projection: zero when system mode resolved none.
func userModeDefaultOwnerID(owner *userModeDefaultLauncher) int64 {
	if owner != nil {
		return owner.principalID
	}
	return 0
}

// logStoredRootReconciliation records the committed reconciliation outcome on
// the operational log. It never carries bearer or secret material: the
// cascaded paths and Launcher IDs are policy identities.
func logStoredRootReconciliation(ctx context.Context, operation string, result storedRootCascadeResult) {
	if len(result.PrincipalRoots) == 0 && len(result.LauncherRoots) == 0 {
		return
	}
	opLog(ctx).Info("stored allowed-root reconciliation committed",
		slog.String("operation", operation),
		slog.Any("pruned_principal_roots", result.PrincipalRoots),
		slog.Any("pruned_launcher_roots", result.LauncherRoots),
	)
}

// reconcileStoredAllowedRootsToGlobalCeiling is the transaction owner of the
// global-ceiling reconciliation: a new global allowed-root policy becomes
// durable policy state only together with its cascaded stored descendants.
// It resolves the canonical global entries (the shared resolution owner),
// and commits the one-transaction reconciliation of every Principal's stored
// roots and restricted-Launcher roots to the resulting ceilings. A failure
// commits nothing, so the caller must not publish the new runtime policy.
//
// The global-ceiling transition surfaces (config reload and daemon startup)
// call this same owner; the lock ordering they own remains lifecycleMu ->
// a.mu (reload) or the startup path (no concurrent serving yet).
func reconcileStoredAllowedRootsToGlobalCeiling(db *sql.DB, globalEntries []AllowedRootEntry, userMode bool, daemonOwnerPrincipalID int64) (storedRootCascadeResult, error) {
	resolved, err := resolveAllowedRootEntries(globalEntries)
	if err != nil {
		return storedRootCascadeResult{}, err
	}

	tx, err := db.Begin()
	if err != nil {
		return storedRootCascadeResult{}, fmt.Errorf("cannot begin allowed-root reconciliation: %w", err)
	}
	defer tx.Rollback()

	result, err := pruneStoredAllowedRootsToCeilings(tx, resolved, 0, daemonOwnerPrincipalID, userMode)
	if err != nil {
		return storedRootCascadeResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return storedRootCascadeResult{}, fmt.Errorf("cannot commit allowed-root reconciliation: %w", err)
	}
	return result, nil
}

// removePrincipalAllowedRootCascaded is the one persistence owner of the
// Principal allowed-root remove: the exact canonical stored root is deleted
// and — when the delete actually changed state — the restricted-Launcher
// descendants of that Principal are reconciled to the resulting effective
// Principal ceiling in the same transaction. There is no observable state in
// which the parent deletion is committed while stale Launcher roots remain.
//
// The remove stays an exact-match idempotent mutation: a root that was not
// stored is the unchanged no-op (changed=false) and runs no cascade — it is
// never a general repair operation. The parent deletion never changes any
// Launcher scope mode: a restricted Launcher whose last root is cascaded away
// stays restricted with zero roots (fail-closed), never inherit.
//
// globalEntries must be the canonical resolved global ceiling resolved by the
// App lifecycle boundary under the lifecycle serialization (the same
// lifecycleMu -> a.mu ordering as config reload), so the cascade is computed
// against exactly the ceiling the mutation linearizes with.
func removePrincipalAllowedRootCascaded(db *sql.DB, username, rootPath string, globalEntries []AllowedRootEntry, userMode bool, daemonOwnerPrincipalID int64) (changed bool, canonicalPath string, pruned storedRootCascadeResult, err error) {
	if username == "" {
		return false, "", storedRootCascadeResult{}, fmt.Errorf("username is required: %w", ErrPrincipalNotFound)
	}
	if rootPath == "" {
		return false, "", storedRootCascadeResult{}, fmt.Errorf("path is required: %w", ErrInvalidAllowedRoot)
	}
	if !filepath.IsAbs(rootPath) {
		return false, "", storedRootCascadeResult{}, fmt.Errorf("path must be absolute: %w", ErrInvalidAllowedRoot)
	}

	// For REMOVE, the path does NOT have to exist on the filesystem: the
	// stored canonical identity is matched (symlink-resolved when the target
	// still exists, cleaned absolute otherwise).
	resolved, err := resolveAllowedRootIdentity(rootPath)
	if err != nil {
		return false, "", storedRootCascadeResult{}, err
	}

	principalID, err := findPrincipalIDByUsername(db, username)
	if err != nil {
		return false, "", storedRootCascadeResult{}, err
	}

	tx, err := db.Begin()
	if err != nil {
		return false, "", storedRootCascadeResult{}, fmt.Errorf("cannot begin allowed-root removal: %w", err)
	}
	defer tx.Rollback()

	result, err := tx.Exec(
		`DELETE FROM principal_allowed_roots
		 WHERE principal_id = ? AND root_path = ?`,
		principalID, resolved,
	)
	if err != nil {
		return false, "", storedRootCascadeResult{}, fmt.Errorf("cannot remove allowed root: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, "", storedRootCascadeResult{}, fmt.Errorf("cannot check delete result: %w", err)
	}

	if affected > 0 {
		pruned, err = pruneStoredAllowedRootsToCeilings(tx, globalEntries, int64(principalID), daemonOwnerPrincipalID, userMode)
		if err != nil {
			return false, "", storedRootCascadeResult{}, err
		}
	}

	if err := tx.Commit(); err != nil {
		return false, "", storedRootCascadeResult{}, fmt.Errorf("cannot commit allowed-root removal: %w", err)
	}
	return affected > 0, resolved, pruned, nil
}
