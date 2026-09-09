package main

import (
	"fmt"
	"path/filepath"
	"slices"
	"sort"
)

// This file is the single pure/domain owner of effective allowed-root
// semantics: most-specific match within one policy scope, composition of
// policy scopes with access-mode meet, the effective Principal ceiling
// (including the user-mode daemon-owner collapse), Launcher
// inherit/restricted semantics, deterministic canonical ordering and
// normalization, and the pure derivation of the Session filesystem snapshot
// with its source-access and writable-parent queries.
//
// It owns hierarchy semantics only. HTTP, CLI, Docker, MAC, Session
// persistence, and operation admission consume these results; they never
// recompute the hierarchy.

// meetAllowedRootAccess intersects two access modes. read_only dominates: a
// downstream scope may narrow an upstream read_write rule to read_only and
// can never widen an upstream read_only rule.
func meetAllowedRootAccess(a, b AllowedRootAccess) AllowedRootAccess {
	if a == AllowedRootAccessReadOnly || b == AllowedRootAccessReadOnly {
		return AllowedRootAccessReadOnly
	}
	return AllowedRootAccessReadWrite
}

// sortAllowedRootEntriesCanonical orders entries byte-wise by canonical path.
// An ancestor is always a strict byte prefix of its descendants, so ancestors
// precede descendants; disjoint paths keep a deterministic byte order.
func sortAllowedRootEntriesCanonical(entries []AllowedRootEntry) {
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
}

// validateCanonicalAllowedRootEntries is the pure resolver's structural input
// boundary. Inputs are canonical absolute paths produced by the existing
// canonicalization owners; the resolver performs no filesystem I/O, but any
// structurally impossible state fails closed: a relative or uncleaned path,
// an unknown access value, or a duplicate exact canonical path (one path is
// one entry; updating it changes that entry, it never leaves two rows).
func validateCanonicalAllowedRootEntries(entries []AllowedRootEntry) error {
	seen := make(map[string]AllowedRootAccess, len(entries))
	for _, e := range entries {
		if !filepath.IsAbs(e.Path) || filepath.Clean(e.Path) != e.Path {
			return fmt.Errorf("allowed-root entry %q is not a canonical absolute path", e.Path)
		}
		if !e.Access.isValid() {
			return fmt.Errorf("allowed-root entry %q has unknown access %q", e.Path, string(e.Access))
		}
		if prev, dup := seen[e.Path]; dup {
			if prev != e.Access {
				return fmt.Errorf("conflicting allowed-root entries for %q", e.Path)
			}
			return fmt.Errorf("duplicate allowed-root entry for %q", e.Path)
		}
		seen[e.Path] = e.Access
	}
	return nil
}

// lookupAllowedRootAccess resolves one source path within one policy scope:
// the most-specific (deepest) entry whose canonical path contains the source
// determines the mode. The second result is false when no entry authorizes
// the source; there is never a default access for unauthorized paths.
func lookupAllowedRootAccess(entries []AllowedRootEntry, source string) (AllowedRootAccess, bool) {
	best := -1
	for i, e := range entries {
		if !pathWithin(e.Path, source) {
			continue
		}
		if best < 0 || pathWithin(entries[best].Path, e.Path) {
			// Entries containing one source form a nested chain, so the
			// deeper entry always contains the previous best.
			best = i
		}
	}
	if best < 0 {
		return "", false
	}
	return entries[best].Access, true
}

// normalizeAllowedRootEntries removes redundant mode transitions. With
// canonical (ancestor-first) ordering, a single pass keeps every entry whose
// access differs from the deepest retained ancestor's access and drops every
// entry that does not change the lookup for any descendant path. A
// downstream read_write suppressed by an upstream read_only is therefore
// dropped, a real mode transition is retained, and disjoint roots are all
// retained. The result is canonically ordered.
func normalizeAllowedRootEntries(entries []AllowedRootEntry) []AllowedRootEntry {
	if len(entries) == 0 {
		return nil
	}
	sorted := slices.Clone(entries)
	sortAllowedRootEntriesCanonical(sorted)

	kept := make([]AllowedRootEntry, 0, len(sorted))
	// ancestors holds the retained entries still able to contain a later
	// sibling subtree, in increasing depth order.
	var ancestors []AllowedRootEntry
	for _, e := range sorted {
		for len(ancestors) > 0 && !pathWithin(ancestors[len(ancestors)-1].Path, e.Path) {
			ancestors = ancestors[:len(ancestors)-1]
		}
		if len(ancestors) > 0 && ancestors[len(ancestors)-1].Access == e.Access {
			// Same mode as the containing region: no lookup inside this
			// subtree can change whether this entry is present.
			continue
		}
		kept = append(kept, e)
		ancestors = append(ancestors, e)
	}
	return kept
}

// composeAllowedRootScopes composes one policy scope onto an upstream scope
// and returns the canonical effective entries: for every candidate path from
// either scope that both scopes authorize (each through its own
// most-specific entry), the effective access is the access-mode meet. A
// downstream scope can narrow an upstream read_write to read_only and can
// never widen an upstream read_only rule; either scope can remove path
// authority entirely. The result is normalized and canonically ordered, so
// it is independent of input order.
func composeAllowedRootScopes(ceiling, narrowing []AllowedRootEntry) []AllowedRootEntry {
	if err := validateCanonicalAllowedRootEntries(ceiling); err != nil {
		return nil
	}
	if err := validateCanonicalAllowedRootEntries(narrowing); err != nil {
		return nil
	}
	if len(ceiling) == 0 || len(narrowing) == 0 {
		return nil
	}
	candidate := make(map[string]bool, len(ceiling)+len(narrowing))
	for _, e := range ceiling {
		candidate[e.Path] = true
	}
	for _, e := range narrowing {
		candidate[e.Path] = true
	}
	var composed []AllowedRootEntry
	for path := range candidate {
		up, okUp := lookupAllowedRootAccess(ceiling, path)
		if !okUp {
			continue
		}
		down, okDown := lookupAllowedRootAccess(narrowing, path)
		if !okDown {
			continue
		}
		composed = append(composed, AllowedRootEntry{Path: path, Access: meetAllowedRootAccess(up, down)})
	}
	return normalizeAllowedRootEntries(composed)
}

// effectivePrincipalAllowedRoots is the canonical Principal-level effective
// policy, consumed by Session creation, Launcher restricted-scope create and
// replacement validation, and Principal effective-roots introspection:
//
//   - in user mode, the daemon-owner Principal (identified by
//     daemonOwnerPrincipalID, the startup-resolved App.userModeDefault
//     identity) with zero stored root entries collapses onto the global
//     allowed-root policy including its access modes: the transparent
//     ownership chain defers wholly to the global ceiling and creates no
//     second mode rule. This is the ONLY Principal for which empty roots
//     mean the global ceiling.
//   - every other Principal (and a daemon-owner Principal with unexpected
//     stored roots, a state the user-mode startup contract refuses) gets the
//     plain composition: empty or disjoint stored roots mean an empty
//     ceiling, fail-closed.
//
// It is a pure policy function: callers resolve the global entries, the
// stored Principal entries, and the daemon-owner identity, and pass them in.
func effectivePrincipalAllowedRoots(globalEntries, storedPrincipalEntries []AllowedRootEntry, principalID, daemonOwnerPrincipalID int64, userMode bool) []AllowedRootEntry {
	if userMode && principalID == daemonOwnerPrincipalID && len(storedPrincipalEntries) == 0 {
		return slices.Clone(globalEntries)
	}
	return composeAllowedRootScopes(globalEntries, storedPrincipalEntries)
}

// effectiveLauncherAllowedRoots is the canonical three-level effective policy
// for Session filesystem authority. It consumes the global allowed-root
// entries (the config owner), the Launcher's ownership snapshot with its
// Principal's and its own stored entries, and the user-mode daemon-owner
// identity. The Principal-level ceiling is
// effectivePrincipalAllowedRoots.
//
//   - an inherit-scope Launcher adds no narrowing: the effective policy equals
//     the effective Principal ceiling.
//   - a restricted Launcher first revalidates its stored entries against the
//     current effective Principal path ceiling and fails closed on stale or
//     directly-injected out-of-ceiling paths; surviving entries then compose
//     with the Principal ceiling. A restricted entry whose mode is wider than
//     the upstream mode is ordinary policy state, not corruption: the meet
//     keeps the upstream read_only.
func effectiveLauncherAllowedRoots(globalEntries []AllowedRootEntry, snap *sessionOwnershipSnapshot, daemonOwnerPrincipalID int64, userMode bool) ([]AllowedRootEntry, error) {
	principalCeiling := effectivePrincipalAllowedRoots(globalEntries, snap.principalRoots, snap.principalID, daemonOwnerPrincipalID, userMode)
	if snap.launcherScope != LauncherScopeRestricted {
		return principalCeiling, nil
	}
	principalPaths := allowedRootPaths(principalCeiling)
	for _, stored := range snap.launcherRoots {
		if !isWithinAnyAllowedRoot(stored.Path, principalPaths) {
			return nil, ErrLauncherUnavailable
		}
	}
	return composeAllowedRootScopes(principalCeiling, snap.launcherRoots), nil
}

// sessionFilesystemSnapshot is the immutable derived filesystem policy of one
// Session: the Session workspace as the explicit root entry plus every
// effective mode transition inside it. It is derived state owned by the
// Session lifecycle; it is not a fourth mutable policy scope.
type sessionFilesystemSnapshot struct {
	Workspace string
	Entries   []AllowedRootEntry
}

// newSessionFilesystemSnapshot validates one canonical snapshot value. The
// entries must be canonical, non-empty, and all inside the workspace, with
// the workspace itself as the first (root) entry. Any other state is corrupt
// and fails closed: the snapshot is the authority an issued Session bearer
// grants, so it is never guessed.
func newSessionFilesystemSnapshot(entries []AllowedRootEntry) (*sessionFilesystemSnapshot, error) {
	if err := validateCanonicalAllowedRootEntries(entries); err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("session filesystem snapshot has no entries")
	}
	root := entries[0]
	for _, e := range entries[1:] {
		if !pathWithin(root.Path, e.Path) {
			return nil, fmt.Errorf("session filesystem snapshot entry %q is outside the workspace %q", e.Path, root.Path)
		}
	}
	return &sessionFilesystemSnapshot{Workspace: root.Path, Entries: slices.Clone(entries)}, nil
}

// deriveSessionFilesystemSnapshot derives the pure Session filesystem
// snapshot from the canonical effective policy and the Session workspace:
// the workspace boundary is materialized with its effective mode (which may
// come from an ancestor entry outside the workspace), every policy entry
// strictly inside the workspace keeps its transition, and redundant
// transitions are normalized away. Entries outside the workspace never enter
// the snapshot. The derivation performs no filesystem I/O: it works on
// already-canonical paths.
//
// Existing Session-create admission rules (a workspace must be a proper
// subdirectory of an allowed root) belong to the Session lifecycle, not to
// this derivation: a workspace with no effective authority fails closed
// here with no authority derived.
func deriveSessionFilesystemSnapshot(effective []AllowedRootEntry, workspace string) (*sessionFilesystemSnapshot, error) {
	if err := validateCanonicalAllowedRootEntries(effective); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(workspace) || filepath.Clean(workspace) != workspace {
		return nil, fmt.Errorf("session workspace %q is not a canonical absolute path", workspace)
	}
	mode, ok := lookupAllowedRootAccess(effective, workspace)
	if !ok {
		return nil, fmt.Errorf("workspace %q is not inside the effective allowed-root policy", workspace)
	}
	candidates := []AllowedRootEntry{{Path: workspace, Access: mode}}
	for _, e := range effective {
		if pathStrictlyWithin(workspace, e.Path) {
			access, ok := lookupAllowedRootAccess(effective, e.Path)
			if !ok {
				return nil, fmt.Errorf("policy entry %q lost its effective authority", e.Path)
			}
			candidates = append(candidates, AllowedRootEntry{Path: e.Path, Access: access})
		}
	}
	normalized := normalizeAllowedRootEntries(candidates)
	return newSessionFilesystemSnapshot(normalized)
}

// LookupAccess resolves one source path against the snapshot: the
// source must be inside the snapshot workspace, and the most-specific
// snapshot entry determines the effective read_write/read_only mode. A
// source outside the workspace has no authority and never falls back to a
// default mode.
func (s *sessionFilesystemSnapshot) LookupAccess(source string) (AllowedRootAccess, bool) {
	if !pathWithin(s.Workspace, source) {
		return "", false
	}
	return lookupAllowedRootAccess(s.Entries, source)
}

// CanExposeWritable is the one writable-parent query: a source may be
// exposed writable only when the source itself resolves read_write and no
// effective read_only transition exists strictly below it inside the
// snapshot. A read-only source can never expose writable, and a
// read_write source spanning any protected read_only region is refused
// even when a deeper transition inside that region is read_write: the
// region between the read_only boundary and that deeper transition stays
// read-only.
func (s *sessionFilesystemSnapshot) CanExposeWritable(source string) bool {
	access, ok := s.LookupAccess(source)
	if !ok || access != AllowedRootAccessReadWrite {
		return false
	}
	for _, e := range s.Entries {
		if pathStrictlyWithin(source, e.Path) && e.Access == AllowedRootAccessReadOnly {
			return false
		}
	}
	return true
}
