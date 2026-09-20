package main

// This file is the single owner of the App-level lock-owning root-policy
// lifecycle mutations. Each mutation holds lifecycleMu across the whole
// critical section (the same boundary as Session creation, the other
// ownership lifecycle mutations, and the reload's config-resolution+
// setConfig critical section), resolves the global ceiling through the same
// shared symlink-resolution path as the other root-policy surfaces, and
// returns the committed result.

func (a *App) addPrincipalAllowedRootWithLifecycle(username, rootPath string, access AllowedRootAccess) (changed bool, entry AllowedRootEntry, err error) {
	a.lifecycleMu.Lock()
	defer a.lifecycleMu.Unlock()
	globalRoots, err := a.appResolvedGlobalRoots()
	if err != nil {
		return false, AllowedRootEntry{}, err
	}
	return addPrincipalAllowedRoot(a.DB, username, rootPath, access, globalRoots)
}

// removePrincipalAllowedRootWithLifecycle is the lock-owning App-level
// Principal allowed-root remove. See addPrincipalAllowedRootWithLifecycle.
// The removal is the canonical Principal-root lifecycle transition: the
// persistence owner (removePrincipalAllowedRootCascaded) commits the exact
// stored-root deletion and — when it changed state — the restricted-Launcher
// descendant reconciliation to the resulting effective Principal ceiling in
// the same transaction, against the global ceiling resolved under this
// lifecycle serialization boundary. The reconciliation result reports what
// the transition cascaded away.
func (a *App) removePrincipalAllowedRootWithLifecycle(username, rootPath string) (changed bool, canonicalPath string, pruned storedRootCascadeResult, err error) {
	a.lifecycleMu.Lock()
	defer a.lifecycleMu.Unlock()
	globalEntries, err := a.appResolvedGlobalRootEntries()
	if err != nil {
		return false, "", storedRootCascadeResult{}, err
	}
	return removePrincipalAllowedRootCascaded(a.DB, username, rootPath, globalEntries)
}

// setPrincipalAllowedRootAccessWithLifecycle is the lock-owning App-level
// Principal allowed-root set-access, the targeted access mutation on one
// stored root. It holds the same lifecycleMu serialization boundary as the
// other root-policy mutations and refuses the reserved daemon-owner Principal
// before any change. The global ceiling is deliberately not re-resolved:
// set-access changes only the access of an already-stored, already
// ceiling-validated root, and the effective policy is composed by the
// canonical 2.2 effective-root owner at every consumption boundary.
func (a *App) setPrincipalAllowedRootAccessWithLifecycle(username, rootPath string, access AllowedRootAccess) (changed bool, entry AllowedRootEntry, err error) {
	a.lifecycleMu.Lock()
	defer a.lifecycleMu.Unlock()
	return setPrincipalAllowedRootAccess(a.DB, username, rootPath, access)
}

// replaceLauncherScopeWithLifecycle is the lock-owning App-level Launcher scope
// replacement. It holds lifecycleMu across the reservation check, the single
// authoritative pre-change projection resolution, the canonical
// effective-Principal-root resolution (which reads the current global policy
// snapshot — the same lifecycleMu -> a.mu ordering as config reload), and the
// durable mutation, so the replacement is validated against the ceiling
// committed by any reload that linearized before it, and it refuses any
// narrowing or rooting of the reserved daemon-owner default Launcher before
// any change. The resolved projection is shared with the persistence
// operation, which composes the successful result from it without any
// post-commit DB read.
func (a *App) replaceLauncherScopeWithLifecycle(launcherID string, scope LauncherScopeMode, allowedRootEntries []AllowedRootEntry) (*LauncherWithPrincipal, error) {
	a.lifecycleMu.Lock()
	defer a.lifecycleMu.Unlock()
	cur, err := findLauncherByID(a.DB, launcherID)
	if err != nil {
		return nil, err
	}
	ceiling, err := a.resolveEffectivePrincipalRoots(cur.PrincipalID)
	if err != nil {
		return nil, err
	}
	return replaceLauncherScope(a.DB, cur, scope, allowedRootEntries, ceiling)
}

// addLauncherAllowedRootWithLifecycle is the lock-owning App-level Launcher
// allowed-root add, the narrow sibling of replaceLauncherScopeWithLifecycle. It
// holds lifecycleMu across the Launcher resolution, the reservation check, the
// canonical effective-Principal-root resolution (the same lifecycleMu -> a.mu
// ordering as config reload), and the durable mutation, so the added root is
// validated against the ceiling committed by any reload that linearized before
// it, and it refuses rooting the reserved daemon-owner default Launcher before
// any change (the reserved chain stays inherit with zero stored roots). On
// success it returns the committed post-mutation Launcher projection, composed
// without any post-commit DB read (the same committed-projection contract as
// replaceLauncherScopeWithLifecycle).
func (a *App) addLauncherAllowedRootWithLifecycle(launcherID, rootPath string, access AllowedRootAccess) (committed *LauncherWithPrincipal, changed bool, entry AllowedRootEntry, err error) {
	a.lifecycleMu.Lock()
	defer a.lifecycleMu.Unlock()
	cur, err := findLauncherByID(a.DB, launcherID)
	if err != nil {
		return nil, false, AllowedRootEntry{}, err
	}
	ceiling, err := a.resolveEffectivePrincipalRoots(cur.PrincipalID)
	if err != nil {
		return nil, false, AllowedRootEntry{}, err
	}
	return addLauncherAllowedRoot(a.DB, cur, rootPath, access, ceiling)
}

// removeLauncherAllowedRootWithLifecycle is the lock-owning App-level Launcher
// allowed-root remove. See addLauncherAllowedRootWithLifecycle for the
// serialization boundary. Removal never changes the scope mode and never
// broadens authority (a restricted Launcher whose last root is removed stays
// restricted with zero roots, fail-closed), and the reserved daemon-owner
// default Launcher — which carries no stored roots — is refused like every
// other mutation of the reserved chain.
func (a *App) removeLauncherAllowedRootWithLifecycle(launcherID, rootPath string) (changed bool, canonicalPath string, err error) {
	a.lifecycleMu.Lock()
	defer a.lifecycleMu.Unlock()
	if _, err := findLauncherByID(a.DB, launcherID); err != nil {
		return false, "", err
	}
	return removeLauncherAllowedRoot(a.DB, launcherID, rootPath)
}

// setLauncherAllowedRootAccessWithLifecycle is the lock-owning App-level
// Launcher allowed-root set-access, the targeted access mutation on one stored
// root. It holds the same lifecycleMu serialization boundary as the other
// Launcher root-policy mutations, refuses the reserved daemon-owner default
// Launcher before any change, and — like the Principal set-access —
// deliberately does not re-resolve the Principal ceiling: set-access changes
// only the access of an already-stored, already ceiling-validated root, and
// the effective policy is composed by the canonical 2.2 effective-root owner
// at every consumption boundary. The scope mode is never changed.
func (a *App) setLauncherAllowedRootAccessWithLifecycle(launcherID, rootPath string, access AllowedRootAccess) (changed bool, entry AllowedRootEntry, err error) {
	a.lifecycleMu.Lock()
	defer a.lifecycleMu.Unlock()
	if _, err := findLauncherByID(a.DB, launcherID); err != nil {
		return false, AllowedRootEntry{}, err
	}
	return setLauncherAllowedRootAccess(a.DB, launcherID, rootPath, access)
}
