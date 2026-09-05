package main

import "errors"

// ErrUserModeOwnerReserved is the stable conflict returned when a public
// control-plane mutation targets the reserved transparent user-mode ownership
// chain — the daemon-owner Principal resolved at startup (App.userModeDefault)
// or its 'default' Launcher — in a way that would mutate it into a form
// ensureUserModeOwnership rejects at the next startup. The public API maps it
// to 409 user_mode_owner_reserved.
var ErrUserModeOwnerReserved = errors.New("user-mode daemon-owner ownership is reserved")

func isErrUserModeOwnerReserved(err error) bool {
	return errors.Is(err, ErrUserModeOwnerReserved)
}

// This file is the single owner of the reserved user-mode daemon-owner
// ownership policy. The transparent user-mode chain is exactly the daemon-owner
// Principal (enabled, ZERO principal_allowed_roots so its effective roots
// collapse onto the global roots) with its enabled, inherit-scope, zero-root
// 'default' Launcher — the same contract ensureUserModeOwnership enforces
// fail-closed at every startup. Identity is the startup-resolved
// App.userModeDefault state, never inferred from a username or Launcher name.
//
// Mutations must be refused inside the caller's lifecycleMu-serialized
// critical section (the same boundary as the mutation itself), before any
// durable change, Session invalidation, MAC release, Operation quiesce, or
// runtime cleanup, so a rejected mutation can never corrupt the chain or
// strand the running daemon.

// isUserModeDaemonOwnerPrincipal reports whether principalID is the user-mode
// daemon-owner Principal resolved at startup. Always false in system mode.
func (a *App) isUserModeDaemonOwnerPrincipal(principalID int64) bool {
	return a.userModeDefault != nil && principalID == a.userModeDefault.principalID
}

// isUserModeDefaultLauncher reports whether launcherID is the daemon-owner
// default Launcher resolved at startup. Always false in system mode.
func (a *App) isUserModeDefaultLauncher(launcherID string) bool {
	return a.userModeDefault != nil && launcherID == a.userModeDefault.launcherID
}

// rejectReservedPrincipalMutation guards a Principal mutation. The caller must
// hold lifecycleMu. The user-mode daemon-owner Principal is reserved: it may
// not be disabled, deleted, or given its own stored roots. An unknown Principal
// is not reserved; the mutation path reports its normal principal_not_found.
// A re-enable of the already-enabled daemon-owner Principal is a natural no-op
// (persistPrincipalEnabledChange reports Changed=false) and passes.
func (a *App) rejectReservedPrincipalMutation(username string) error {
	if a.userModeDefault == nil {
		return nil
	}
	principalID, err := findPrincipalIDByUsername(a.DB, username)
	if errors.Is(err, ErrPrincipalNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if a.isUserModeDaemonOwnerPrincipal(int64(principalID)) {
		return ErrUserModeOwnerReserved
	}
	return nil
}

// rejectReservedLauncherOwnerMutation guards the unconditional Launcher
// lifecycle refusals: delete and the direct disable transition. The caller
// must hold lifecycleMu. The reserved daemon-owner default Launcher is never
// deletable and never directly disableable, regardless of request parameters
// (these paths carry none).
func (a *App) rejectReservedLauncherOwnerMutation(launcherID string) error {
	if a.isUserModeDefaultLauncher(launcherID) {
		return ErrUserModeOwnerReserved
	}
	return nil
}

// rejectReservedLauncherPatch guards a Launcher PATCH (rename/enable). The
// caller must hold lifecycleMu. For the reserved daemon-owner default Launcher
// only requests that leave the invariant unchanged pass: re-enabling an
// enabled Launcher and renaming it to its current name 'default' are no-ops; a
// disable or a rename away from 'default' is refused.
func (a *App) rejectReservedLauncherPatch(launcherID string, name *string, enabled *bool) error {
	if !a.isUserModeDefaultLauncher(launcherID) {
		return nil
	}
	if name != nil && *name != defaultLauncherName {
		return ErrUserModeOwnerReserved
	}
	if enabled != nil && !*enabled {
		return ErrUserModeOwnerReserved
	}
	return nil
}

// rejectReservedLauncherScopeReplace guards a Launcher scope replacement. The
// caller must hold lifecycleMu. The reserved daemon-owner default Launcher
// must remain inherit scope with zero stored roots; any other replacement is
// refused.
func (a *App) rejectReservedLauncherScopeReplace(launcherID string, scope LauncherScopeMode, allowedRoots []string) error {
	if !a.isUserModeDefaultLauncher(launcherID) {
		return nil
	}
	if scope != LauncherScopeInherit || len(allowedRoots) > 0 {
		return ErrUserModeOwnerReserved
	}
	return nil
}

// addPrincipalAllowedRootWithLifecycle is the lock-owning App-level Principal
// allowed-root add. It holds lifecycleMu across the reservation check, the
// current-policy resolution, and the durable mutation (the same serialization
// boundary as Session creation, the other ownership lifecycle mutations, and
// the reload's config-resolution+setConfig critical section), and resolves the
// global ceiling through the same shared symlink-resolution path as the other
// root-policy surfaces, so the mutation is validated against the ceiling
// committed by any reload that linearized before it. It refuses the reserved
// daemon-owner Principal before any change.
func (a *App) addPrincipalAllowedRootWithLifecycle(username, rootPath string) (changed bool, canonicalPath string, err error) {
	a.lifecycleMu.Lock()
	defer a.lifecycleMu.Unlock()
	if err := a.rejectReservedPrincipalMutation(username); err != nil {
		return false, "", err
	}
	globalRoots, err := a.appResolvedGlobalRoots()
	if err != nil {
		return false, "", err
	}
	return addPrincipalAllowedRoot(a.DB, username, rootPath, globalRoots)
}

// removePrincipalAllowedRootWithLifecycle is the lock-owning App-level
// Principal allowed-root remove. See addPrincipalAllowedRootWithLifecycle.
func (a *App) removePrincipalAllowedRootWithLifecycle(username, rootPath string) (changed bool, canonicalPath string, err error) {
	a.lifecycleMu.Lock()
	defer a.lifecycleMu.Unlock()
	if err := a.rejectReservedPrincipalMutation(username); err != nil {
		return false, "", err
	}
	return removePrincipalAllowedRoot(a.DB, username, rootPath)
}

// replaceLauncherScopeWithLifecycle is the lock-owning App-level Launcher scope
// replacement. It holds lifecycleMu across the reservation check, the
// canonical effective-Principal-root resolution (which reads the current
// global policy snapshot — the same lifecycleMu -> a.mu ordering as config
// reload), and the durable mutation, so the replacement is validated against
// the ceiling committed by any reload that linearized before it, and it
// refuses any narrowing or rooting of the reserved daemon-owner default
// Launcher before any change.
func (a *App) replaceLauncherScopeWithLifecycle(launcherID string, scope LauncherScopeMode, allowedRoots []string) (*LauncherWithPrincipal, error) {
	a.lifecycleMu.Lock()
	defer a.lifecycleMu.Unlock()
	if err := a.rejectReservedLauncherScopeReplace(launcherID, scope, allowedRoots); err != nil {
		return nil, err
	}
	cur, err := findLauncherByID(a.DB, launcherID)
	if err != nil {
		return nil, err
	}
	ceiling, err := a.resolveEffectivePrincipalRoots(cur.PrincipalID)
	if err != nil {
		return nil, err
	}
	return replaceLauncherScope(a.DB, launcherID, scope, allowedRoots, ceiling)
}
