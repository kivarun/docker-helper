package main

import (
	"errors"
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
// normalization, the issuance-time Session filesystem narrowing, and the
// pure derivation of the Session filesystem snapshot with its source-access
// and writable-parent queries.
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

// ErrInvalidSessionFilesystemPolicy is the typed issuance-time refusal family
// for a caller-supplied Session filesystem request that is malformed or is
// not a valid narrowing of the effective Launcher policy ceiling. The request
// may only narrow: any attempt to obtain path authority or an access mode
// wider than the ceiling is refused before the Session exists. It is distinct
// from ErrReadOnlyRoot, which is the data-plane refusal of an already-issued
// Session snapshot; at issuance time no Session exists.
var ErrInvalidSessionFilesystemPolicy = errors.New("session filesystem request is not a valid narrowing of the effective launcher policy")

// narrowSessionFilesystemPolicy is the one domain operation of the
// issuance-time Session filesystem narrowing (Release 2.2): it composes the
// effective Launcher filesystem ceiling with the canonical Session filesystem
// request and returns the canonical effective entries the Session snapshot is
// derived from.
//
// ceiling and requested are canonical absolute AllowedRootEntry values:
// requested paths have already been canonicalized by the Session lifecycle
// (workspace join, symlink resolution, containment proof) and "." has become
// the workspace path itself. The composition happens inside the existing
// create linearization boundary, so the ceiling and the committed snapshot
// always describe one coherent policy generation.
//
// Before composing, every requested entry is proven to narrow the ceiling;
// composeAllowedRootScopes alone is not a sufficient validation boundary,
// because the meet could silently turn an unlawfully requested read_write
// into read_only and an out-of-ceiling path could simply vanish from the
// result. Each requested path must be authorized by the ceiling, and a
// requested read_write under an effective read_only region is an explicit
// refusal, never a silent narrowing. The requested set must also authorize
// the workspace itself (the required "." entry), so the whole Session
// workspace stays the capability root and no unmanaged gap can be created.
// Duplicate canonical requested paths are refused by the canonical entry
// validation.
//
// After pre-validation the composition is performed by the existing
// composition/normalization owner: most-specific lookup and access-mode meet
// semantics are not duplicated here. Ceiling entries strictly inside the
// workspace survive the composition, so a narrower ceiling read_only region
// remains protected even when the request re-exposes its parent read-write.
func narrowSessionFilesystemPolicy(ceiling []AllowedRootEntry, workspace string, requested []AllowedRootEntry) ([]AllowedRootEntry, error) {
	if err := validateCanonicalAllowedRootEntries(requested); err != nil {
		return nil, fmt.Errorf("session filesystem request: %v: %w", err, ErrInvalidSessionFilesystemPolicy)
	}
	if _, ok := lookupAllowedRootAccess(requested, workspace); !ok {
		return nil, fmt.Errorf("session filesystem request must include the workspace entry %q: %w", ".", ErrInvalidSessionFilesystemPolicy)
	}
	for _, e := range requested {
		up, ok := lookupAllowedRootAccess(ceiling, e.Path)
		if !ok {
			return nil, fmt.Errorf("filesystem entry %q is outside the effective launcher policy: %w", e.Path, ErrInvalidSessionFilesystemPolicy)
		}
		if e.Access == AllowedRootAccessReadWrite && up == AllowedRootAccessReadOnly {
			return nil, fmt.Errorf("filesystem entry %q requests read_write under an effective read_only region: %w", e.Path, ErrInvalidSessionFilesystemPolicy)
		}
	}
	composed := composeAllowedRootScopes(ceiling, requested)
	if len(composed) == 0 {
		return nil, ErrInvalidSessionFilesystemPolicy
	}
	return composed, nil
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
// Structurally impossible global policy (unknown access, duplicate exact
// paths, relative or uncleaned entries) is corrupt state on every branch:
// the collapse validates its input through the same boundary as the
// composition and yields empty authority instead of guessing. The function
// keeps its error-free signature because every caller already handles the
// empty fail-closed ceiling as no-Session-authority.
//
// It is a pure policy function: callers resolve the global entries, the
// stored Principal entries, and the daemon-owner identity, and pass them in.
func effectivePrincipalAllowedRoots(globalEntries, storedPrincipalEntries []AllowedRootEntry, principalID, daemonOwnerPrincipalID int64, userMode bool) []AllowedRootEntry {
	if userMode && principalID == daemonOwnerPrincipalID && len(storedPrincipalEntries) == 0 {
		if err := validateCanonicalAllowedRootEntries(globalEntries); err != nil {
			return nil
		}
		return normalizeAllowedRootEntries(globalEntries)
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
//   - any other stored scope value is corrupt state: it is never treated as
//     inherit, and the Launcher fails closed as unavailable (the existing
//     typed Session-create contract).
func effectiveLauncherAllowedRoots(globalEntries []AllowedRootEntry, snap *sessionOwnershipSnapshot, daemonOwnerPrincipalID int64, userMode bool) ([]AllowedRootEntry, error) {
	principalCeiling := effectivePrincipalAllowedRoots(globalEntries, snap.principalRoots, snap.principalID, daemonOwnerPrincipalID, userMode)
	switch snap.launcherScope {
	case LauncherScopeInherit:
		return principalCeiling, nil
	case LauncherScopeRestricted:
		// Revalidate and compose below.
	default:
		return nil, fmt.Errorf("launcher scope mode %q is not supported: %w", string(snap.launcherScope), ErrLauncherUnavailable)
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

// newSessionFilesystemSnapshot validates one canonical snapshot value
// against the independent trusted Session workspace. The workspace must be a
// canonical absolute path, the entries must be canonical, non-empty, begin
// with the workspace itself, and stay inside it. The entries must also be
// exactly the canonical normalized representation: the boundary proves the
// stored shape instead of silently sorting, deduplicating, or reconstructing
// persisted Session authority. Any other state is corrupt and fails closed:
// the snapshot is the authority an issued Session bearer grants, so the
// boundary never guesses the workspace from persisted policy data and never
// accepts a snapshot rooted elsewhere or in a noncanonical form.
func newSessionFilesystemSnapshot(workspace string, entries []AllowedRootEntry) (*sessionFilesystemSnapshot, error) {
	if err := validateCanonicalAllowedRootEntries(entries); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(workspace) || filepath.Clean(workspace) != workspace {
		return nil, fmt.Errorf("session workspace %q is not a canonical absolute path", workspace)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("session filesystem snapshot has no entries")
	}
	if entries[0].Path != workspace {
		return nil, fmt.Errorf("session filesystem snapshot root %q is not the workspace %q", entries[0].Path, workspace)
	}
	for _, e := range entries[1:] {
		if !pathWithin(workspace, e.Path) {
			return nil, fmt.Errorf("session filesystem snapshot entry %q is outside the workspace %q", e.Path, workspace)
		}
	}
	if canonical := normalizeAllowedRootEntries(entries); !slices.Equal(entries, canonical) {
		return nil, fmt.Errorf("session filesystem snapshot entries are not the canonical normalized representation")
	}
	return &sessionFilesystemSnapshot{Workspace: workspace, Entries: slices.Clone(entries)}, nil
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
	return newSessionFilesystemSnapshot(workspace, normalized)
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

// ErrReadOnlyRoot is the typed data-plane refusal: the requested writable
// exposure of one canonical source is refused by the persisted Session
// filesystem snapshot. It is distinct from structural mount validation
// (invalid_mount) and from authentication (unauthorized): the Session is
// authenticated and the source is inside its workspace, but the issued
// snapshot does not permit writable exposure.
var ErrReadOnlyRoot = errors.New("writable exposure refused by the issued session filesystem snapshot")

// sessionFilesystemExposure is the accepted data-plane filesystem exposure
// decision for one canonical source: the persisted immutable Session
// filesystem snapshot remains the only filesystem authority, and this value
// carries the resolved policy facts (effective snapshot access, the
// caller-requested consumption mode, and the writable exposure permission)
// downstream instead of exposing raw snapshot entries. The pinned path is
// never part of this representation: pinning is a downstream materialization
// detail, not policy identity.
type sessionFilesystemExposure struct {
	// SourcePath is the canonical policy identity of the source, produced by
	// the existing canonicalization owner before this decision.
	SourcePath string
	// Target is the container target for run user mounts; empty for
	// target-less consumers such as the build host inputs.
	Target string
	// RequestedReadOnly is the caller-requested consumption mode. The Docker
	// bind-mount materialization follows exactly this mode; it is never
	// derived from Access.
	RequestedReadOnly bool
	// Access is the effective read_write/read_only mode of the canonical
	// source inside the issued snapshot.
	Access AllowedRootAccess
	// WritableAllowed records whether the snapshot owner permits writable
	// exposure of this canonical source (no read_only transition at or
	// strictly below it). False is meaningful: a read_write source can span
	// a protected read_only region and then not be writable-exposable.
	WritableAllowed bool
}

// resolveSessionFilesystemExposure is the one adapter between the persisted
// snapshot and the data-plane consumers (run mounts, build host inputs, and
// the later MAC workload projection). It resolves one canonical source
// identity against the snapshot for the requested consumption mode:
// read-only consumption is permitted for either snapshot access mode, while
// writable consumption requires the snapshot owner's writable-parent query.
// LookupAccess failing for a workspace-contained source is an internal
// state/integrity error, never a default grant and never the
// read_only_root refusal.
func resolveSessionFilesystemExposure(
	snapshot *sessionFilesystemSnapshot,
	sourcePath, target string,
	requestedReadOnly bool,
) (sessionFilesystemExposure, error) {
	access, ok := snapshot.LookupAccess(sourcePath)
	if !ok {
		return sessionFilesystemExposure{}, fmt.Errorf("canonical source %q has no issued filesystem snapshot entry in workspace %q", sourcePath, snapshot.Workspace)
	}
	exposure := sessionFilesystemExposure{
		SourcePath:        sourcePath,
		Target:            target,
		RequestedReadOnly: requestedReadOnly,
		Access:            access,
	}
	if requestedReadOnly {
		// Read-only consumption of a read_write source keeps the recorded
		// writable-parent fact so audit can still show why no writable
		// exposure of this region would be accepted.
		exposure.WritableAllowed = snapshot.CanExposeWritable(sourcePath)
		return exposure, nil
	}
	if !snapshot.CanExposeWritable(sourcePath) {
		exposure.WritableAllowed = false
		return exposure, fmt.Errorf("canonical source %q: %w", sourcePath, ErrReadOnlyRoot)
	}
	exposure.WritableAllowed = true
	return exposure, nil
}
