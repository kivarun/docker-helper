package main

// workload_apparmor.go — the AppArmor workload MAC backend (Release 2.2
// Phase 2.2.6, mechanism accepted by M0-A).
//
// The backend renders one helper-owned workload profile from the final
// container-target/access plan, loads it through apparmor_parser before the
// correlated container can start, and verifies the load through the kernel
// profile inventory. The baseline follows the Moby docker-default AppArmor
// template exactly as proven by the M0-A proof; the only projection is the
// bounded write-denial set for accepted read-only container targets.
//
// The daemon's docker-helper-system profile and its managed workspace
// boundaries are a separate concern; this backend never reads or modifies
// them.

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Production AppArmor facts. The parser path matches the shipped daemon
// profile machinery; the kernel profile inventory is the load-state proof.
const (
	appArmorWorkloadProfilePrefix = "docker-helper-workload-"
	appArmorProfilesInventoryPath = "/sys/kernel/security/apparmor/profiles"
	appArmorAbi30Path             = "/etc/apparmor.d/abi/3.0"
)

func appArmorPathLiteral(path string) string {
	out := make([]byte, 0, len(path))
	for i := 0; i < len(path); i++ {
		b := path[i]
		if (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') ||
			b == '/' || b == '.' || b == '_' || b == '-' {
			out = append(out, b)
			continue
		}
		out = append(out, '\\', 'x')
		const hexDigits = "0123456789abcdef"
		out = append(out, hexDigits[b>>4], hexDigits[b&0x0f])
	}
	return string(out)
}

// appArmorClassSafeByte reports whether b may be written verbatim inside an
// AppArmor character class. Class metacharacters (^, ], -, \, and the escape
// introducer) are excluded along with every non-ASCII byte; those are always
// hex-escaped, which the AppArmor pattern grammar accepts inside classes.
func appArmorClassSafeByte(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') ||
		b == '/' || b == '.' || b == '_'
}

// appArmorClassByte renders one byte for use inside a character class.
func appArmorClassByte(b byte) string {
	if appArmorClassSafeByte(b) {
		return string(rune(b))
	}
	const hexDigits = "0123456789abcdef"
	return string([]byte{'\\', 'x', hexDigits[b>>4], hexDigits[b&0x0f]})
}

// appArmorLiteralByte renders one byte for use as a literal pattern byte
// outside a class, mirroring appArmorPathLiteral's per-byte encoding.
func appArmorLiteralByte(b byte) string {
	if (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') ||
		b == '/' || b == '.' || b == '_' || b == '-' {
		return string(rune(b))
	}
	const hexDigits = "0123456789abcdef"
	return string([]byte{'\\', 'x', hexDigits[b>>4], hexDigits[b&0x0f]})
}

// appArmorSegmentTrieNode is one byte-level node of the exclusion trie used
// to scope a read-only subtree around the accepted read-write transitions
// beneath it.
type appArmorSegmentTrieNode struct {
	children map[byte]*appArmorSegmentTrieNode
	leaf     bool
}

func newAppArmorSegmentTrieNode() *appArmorSegmentTrieNode {
	return &appArmorSegmentTrieNode{children: map[byte]*appArmorSegmentTrieNode{}}
}

// insertSegment inserts one excluded segment into the trie.
func (n *appArmorSegmentTrieNode) insertSegment(segments []string) {
	node := n
	for _, seg := range segments {
		for i := 0; i < len(seg); i++ {
			b := seg[i]
			child, ok := node.children[b]
			if !ok {
				child = newAppArmorSegmentTrieNode()
				node.children[b] = child
			}
			node = child
		}
		node.leaf = true
	}
}

// appArmorSegmentExclusion renders an AARE fragment that matches exactly
// the single path segments (one or more bytes, never containing '/') that
// are not equal to any of the given excluded names. It is the byte-level
// complement of the excluded names over one segment: the fragment walks a
// byte trie of the excluded names and emits, at every node, the diverging
// character class and the descent alternatives; continuations past an
// excluded name must consume at least one more byte so the exact name is
// never matched. Every alternative is bounded to one segment: the diverging
// class explicitly excludes '/' and its run wildcard is the single `*`
// (which never matches '/'), so the fragment can never match across a path
// separator.
//
// The fragment is written from the already-resolved exposure plan's RW
// target paths; it is not a policy resolver.
func appArmorSegmentExclusion(names []string) string {
	root := newAppArmorSegmentTrieNode()
	for _, name := range names {
		if name == "" {
			// An empty segment name cannot occur in a plan: container
			// targets are cleaned absolute paths.
			continue
		}
		root.insertSegment([]string{name})
	}
	return appArmorExclusionFragment(root, false)
}

// appArmorExclusionFragment renders the alternation body fragment for one
// trie node. minContinuation reports whether the remaining string must
// consume at least one byte: false at the fragment root (the empty match
// is allowed while the segment is not itself an excluded name) and true
// past a leaf (the excluded name itself must not match).
//
// The alternatives per node:
//
//   - stop: the empty continuation, allowed only when no excluded name
//     ends at the consumed prefix and no minimum continuation is pending;
//   - diverge: one byte outside the node's edges and outside the path
//     separator, then an unconstrained non-separator run
//     (`[^<class>/]*`), which can never re-enter the trie nor cross a
//     separator;
//   - descent: one edge byte followed by the child fragment, where a leaf
//     child demands a non-empty continuation so the excluded name itself
//     never matches.
//
// The fragment is written from the already-resolved exposure plan's RW
// target paths; it is not a policy resolver.
func appArmorExclusionFragment(node *appArmorSegmentTrieNode, minContinuation bool) string {
	var alts []string
	if !minContinuation && !node.leaf {
		// Stopping here is allowed: the consumed prefix is not an excluded
		// name. The empty alternative anchors the rule between slashes.
		alts = append(alts, "")
	}
	// Byte-order-independent diverge alternative: exactly one byte outside
	// the node's edges and outside the path separator, followed by an
	// unconstrained run of non-separator bytes (`[^<class>/]*`). AARE
	// negated character classes match the path separator and `**` continues
	// across separators, so the unbounded `[^class]**` form could consume
	// whole following segments and mis-match accepted hole paths — denying
	// valid nested read-write subtrees. The explicit '/' class exclusion
	// keeps the leading byte separator-free and the single `*` keeps the
	// run inside one segment, so the alternative can never cross a
	// separator.
	if len(node.children) > 0 {
		edges := append(childrenBytes(node), '/')
		alts = append(alts, appArmorNegatedClass(edges)+"*")
	}
	// Edge bytes are emitted in byte order for determinism.
	for _, b := range childrenBytes(node) {
		child := node.children[b]
		if child.leaf && len(child.children) == 0 {
			// Passing the excluded name: the continuation must consume at
			// least one more byte.
			alts = append(alts, appArmorLiteralByte(b)+"?*")
			continue
		}
		alts = append(alts, appArmorLiteralByte(b)+appArmorExclusionFragment(child, child.leaf))
	}
	if len(alts) == 1 && alts[0] != "" {
		return alts[0]
	}
	return "{" + strings.Join(alts, ",") + "}"
}

func childrenBytes(node *appArmorSegmentTrieNode) []byte {
	out := make([]byte, 0, len(node.children))
	for b := range node.children {
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// appArmorNegatedClass renders a negated character class matching any byte
// except the given set. Every byte is rendered through the class-safe
// encoder; the set is deduplicated and byte-ordered for determinism.
func appArmorNegatedClass(bytes []byte) string {
	seen := map[byte]bool{}
	var rendered strings.Builder
	rendered.WriteString("[^")
	for _, b := range bytes {
		if seen[b] {
			continue
		}
		seen[b] = true
		rendered.WriteString(appArmorClassByte(b))
	}
	rendered.WriteString("]")
	return rendered.String()
}

// workloadAppArmorProfileName derives the deterministic internal workload
// profile name from the server-generated Operation ID. Session, Launcher,
// Principal, mount targets, and caller input never participate in profile
// identity. Operation IDs are `op_` + 32 hex characters, so the name stays
// inside a bounded safe character set.
func workloadAppArmorProfileName(operationID string) string {
	return appArmorWorkloadProfilePrefix + operationID
}

// appArmorWorkloadProfileFileName is the helper-owned profile source file
// name inside one operation's durable state directory. The loaded profile
// name and this source path share one correlation owner: the ownership
// record in the same directory.
const appArmorWorkloadProfileFileName = "profile"

// workloadAppArmorTargetPlan is the renderer's projection of the accepted
// exposure plan, prepared once by one owner (the AppArmor backend's
// prepare): one entry per accepted read-only container target with the
// pinned node kind, plus every accepted read-write container target path.
// The read-write paths are used only to scope the read-only denials so a
// more specific accepted RW transition stays writable. The renderer
// performs no policy resolution of its own — it never reads allowed-root
// state, snapshots, or writable-parent queries.
type workloadAppArmorTargetPlan struct {
	// RO carries one entry per accepted read-only container target.
	RO []appArmorROTarget
	// RW carries the accepted read-write container target paths.
	RW []string
}

// appArmorROTarget is one accepted read-only container target and the node
// kind of its pinned source.
type appArmorROTarget struct {
	// Target is the container-side bind target of the read-only exposure.
	Target string
	// RegularFile is true when the pinned source is a regular file: the
	// container target is then a file bind whose mediated paths never
	// carry the directory trailing slash.
	RegularFile bool
}

// workloadAppArmorTargetPlanFromExposures is the single owner of the
// exposure-plan projection for the AppArmor renderer. The node kind comes
// from the pinned kernel materialization source; a pin that cannot be
// inspected is a preparation failure (fail closed), never a guessed kind.
// The caller-requested mode — never the snapshot access alone — is the
// frozen workload exposure mode: an application-level narrowing (snapshot
// read_write requested read-only) is still read-only to the MAC layer, and
// an accepted read-write request was already proven writable by the
// application layer.
func workloadAppArmorTargetPlanFromExposures(exposures []sessionFilesystemExposure, pinnedSources []string) (workloadAppArmorTargetPlan, error) {
	if len(exposures) != len(pinnedSources) {
		return workloadAppArmorTargetPlan{}, fmt.Errorf(
			"exposure plan and pinned sources disagree: %d exposures, %d pins", len(exposures), len(pinnedSources))
	}
	plan := workloadAppArmorTargetPlan{}
	for i, exposure := range exposures {
		if !exposure.RequestedReadOnly {
			if exposure.Target != "" {
				plan.RW = append(plan.RW, exposure.Target)
			}
			continue
		}
		info, err := os.Lstat(pinnedSources[i])
		if err != nil {
			return workloadAppArmorTargetPlan{}, fmt.Errorf(
				"cannot inspect pinned source of read-only target %q: %w", exposure.Target, err)
		}
		plan.RO = append(plan.RO, appArmorROTarget{
			Target:      exposure.Target,
			RegularFile: !info.IsDir(),
		})
	}
	return plan, nil
}

// workloadAppArmorBackend is the AppArmor backend for workload MAC
// preparation. It owns profile rendering, loading, unloading, load
// verification, and helper-owned profile state for one Operation.
type workloadAppArmorBackend struct {
	parserPath string
	// runParser executes apparmor_parser with the given arguments.
	// Production shells out to the real parser; tests inject a seam.
	runParser func(parserPath string, args []string) error
	// loadedProfiles returns the names of the profiles currently loaded in
	// the kernel inventory. Production reads
	// /sys/kernel/security/apparmor/profiles; tests inject a seam.
	loadedProfiles func() ([]string, error)
	// abi30Present reports whether the AppArmor ABI 3.0 definition exists
	// on this host (determines the abi include line, as in the M0 proof).
	abi30Present func() bool
}

func newWorkloadAppArmorBackend() *workloadAppArmorBackend {
	return &workloadAppArmorBackend{
		parserPath: appArmorParserPath,
		runParser: func(parserPath string, args []string) error {
			return newProductionParserRunner()(parserPath, args)
		},
		loadedProfiles: appArmorLoadedProfileNames,
		abi30Present:   func() bool { return fileExists(appArmorAbi30Path) },
	}
}

func (b *workloadAppArmorBackend) backend() LSMBackend {
	return LSMAppArmor
}

// appArmorLoadedProfileNames reads the kernel profile inventory and returns
// the loaded profile names. It is the production load-verification owner.
func appArmorLoadedProfileNames() ([]string, error) {
	data, err := os.ReadFile(appArmorProfilesInventoryPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read AppArmor profile inventory: %w", err)
	}
	var names []string
	for _, line := range strings.Split(string(data), "\n") {
		// Inventory lines look like: "profile-name (enforce)".
		if idx := strings.IndexByte(line, ' '); idx > 0 {
			line = line[:idx]
		}
		if line != "" {
			names = append(names, line)
		}
	}
	return names, nil
}

// prepare renders, loads, and verifies the generated workload profile for
// the accepted exposure plan, and returns the prepared result whose
// SecurityOpts explicitly select that profile for the container.
func (b *workloadAppArmorBackend) prepare(p workloadPreparation) (*preparedWorkloadMAC, error) {
	if err := b.ensureParserAvailable(); err != nil {
		return nil, err
	}

	profileName := workloadAppArmorProfileName(p.OperationID)
	plan, err := workloadAppArmorTargetPlanFromExposures(p.Exposures, p.PinnedSources)
	if err != nil {
		return nil, err
	}
	profile := renderWorkloadAppArmorProfile(profileName, plan, b.abi30Present())
	profilePath := filepath.Join(p.StateDir, appArmorWorkloadProfileFileName)

	if err := atomicWriteFile(profilePath, []byte(profile), 0600); err != nil {
		return nil, fmt.Errorf("cannot write generated workload profile: %w", err)
	}
	// --skip-cache: perform no caching at all (disables cache write, implies
	// --skip-read-cache). The generated workload profile is ephemeral, and a
	// confined daemon must not depend on access to the shared parser cache
	// directory (observed on openSUSE: "Failed setting up policy cache
	// (/var/cache/apparmor): Permission denied"); the session-MAC profile
	// manager uses the same argument.
	if err := b.runParser(b.parserPath, []string{"--replace", "--skip-cache", profilePath}); err != nil {
		return nil, fmt.Errorf("cannot load generated workload profile: %w", err)
	}
	if err := b.requireProfileLoaded(profileName); err != nil {
		return nil, fmt.Errorf("generated workload profile is not loaded: %w", err)
	}

	return &preparedWorkloadMAC{
		Backend: LSMAppArmor,
		// Keep the existing SELinux-label-disable behavior of the AppArmor
		// path and explicitly select the generated workload profile; Docker
		// must never rely on an implicit default after preparation.
		SecurityOpts: []string{"label=disable", "apparmor=" + profileName},
		MountSources: p.PinnedSources,
		// The cleanup releases only the kernel MAC state and the backend
		// files that depend on it. The durable ownership record stays
		// behind as the reconciliation retry marker until the run-level
		// finalization boundary proves the dependent cleanup done.
		cleanup: func() error {
			return b.cleanupPrepared(p.StateDir, profileName)
		},
	}, nil
}

// cleanupPrepared unloads the generated profile (only if loaded), removes
// the helper-owned profile file and ownership state, and fails closed: a
// load/unload verification failure retains the owned state.
func (b *workloadAppArmorBackend) cleanupPrepared(stateDir, profileName string) error {
	profilePath := filepath.Join(stateDir, appArmorWorkloadProfileFileName)
	if err := b.unloadProfile(profilePath, profileName); err != nil {
		return err
	}
	// The profile is provably absent; the remaining files are pure state.
	if err := os.Remove(profilePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("cannot remove generated profile source: %w", err)
	}
	return nil
}

// unloadProfile removes a loaded generated profile through apparmor_parser
// and verifies the removal in the kernel inventory. An unverified removal
// is an error so the caller retains the owned state.
func (b *workloadAppArmorBackend) unloadProfile(profilePath, profileName string) error {
	loaded, err := b.isProfileLoaded(profileName)
	if err != nil {
		return err
	}
	if !loaded {
		return nil
	}
	if err := b.runParser(b.parserPath, []string{"--remove", profilePath}); err != nil {
		return fmt.Errorf("cannot unload generated workload profile: %w", err)
	}
	stillLoaded, err := b.isProfileLoaded(profileName)
	if err != nil {
		return err
	}
	if stillLoaded {
		return fmt.Errorf("generated workload profile remained loaded after removal")
	}
	return nil
}

// isProfileLoaded reports whether the profile name is currently loaded.
func (b *workloadAppArmorBackend) isProfileLoaded(profileName string) (bool, error) {
	loaded, err := b.loadedProfiles()
	if err != nil {
		return false, fmt.Errorf("cannot verify AppArmor profile inventory: %w", err)
	}
	for _, name := range loaded {
		if name == profileName {
			return true, nil
		}
	}
	return false, nil
}

// requireProfileLoaded fails closed unless the generated profile is verifiably
// loaded before any container may use it.
func (b *workloadAppArmorBackend) requireProfileLoaded(profileName string) error {
	loaded, err := b.isProfileLoaded(profileName)
	if err != nil {
		return err
	}
	if !loaded {
		return fmt.Errorf("generated workload profile was not loaded")
	}
	return nil
}

// ensureParserAvailable fails closed with an actionable operational error
// when the AppArmor parser is missing.
func (b *workloadAppArmorBackend) ensureParserAvailable() error {
	if _, err := os.Stat(b.parserPath); err != nil {
		return fmt.Errorf("apparmor_parser is not available at %s: %w", b.parserPath, err)
	}
	return nil
}

// validateOwnedState proves the durable AppArmor workload state is exact:
// the directory is a helper-owned directory whose record names the current
// backend, and the profile source file — when present — is a helper-owned
// regular file. The profile identity itself is derived from the record's
// operation ID at cleanup time, so a missing profile source is the safely
// classifiable crash window "ownership committed, crash before the profile
// source was written": an empty owned state whose cleanup is a no-op when
// the deterministic profile is absent from the kernel inventory. Anything
// else fails closed.
func (b *workloadAppArmorBackend) validateOwnedState(record workloadMACRecord) error {
	if record.Backend != string(LSMAppArmor) {
		return fmt.Errorf("record backend %q is not apparmor", record.Backend)
	}
	info, err := os.Lstat(filepath.Join(record.StateDirPath(), appArmorWorkloadProfileFileName))
	if err != nil {
		if os.IsNotExist(err) {
			// Ownership committed, crash before the profile source was
			// written: empty owned state, classified by cleanup against the
			// kernel inventory.
			return nil
		}
		return fmt.Errorf("cannot inspect generated profile source: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("generated profile source is not a helper-owned regular file")
	}
	return nil
}

// cleanupOwnedState removes the kernel profile and the helper-owned profile
// file of one owned record. Called only after container absence is proven.
//
// The profile name is derived from the record's operation ID, never read
// from durable state. A loaded deterministic profile without its profile
// source has no safe unload path and fails closed; an absent profile makes
// the remaining owned state empty and its cleanup a pure state removal.
func (b *workloadAppArmorBackend) cleanupOwnedState(record workloadMACRecord) error {
	stateDir := record.StateDirPath()
	profilePath := filepath.Join(stateDir, appArmorWorkloadProfileFileName)
	profileName := workloadAppArmorProfileName(record.OperationID)
	loaded, err := b.isProfileLoaded(profileName)
	if err != nil {
		return err
	}
	if loaded {
		info, err := os.Lstat(profilePath)
		if err != nil {
			return fmt.Errorf("loaded workload profile %s has no profile source for a safe unload: %w", profileName, err)
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("generated profile source is not a helper-owned regular file")
		}
		if err := b.unloadProfile(profilePath, profileName); err != nil {
			return err
		}
	}
	if err := os.Remove(profilePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("cannot remove generated profile source: %w", err)
	}
	return nil
}

// renderWorkloadAppArmorProfile renders the deterministic generated workload
// renderWorkloadAppArmorProfile renders the deterministic generated workload
// profile for one operation: the Moby docker-default compatibility baseline
// plus the bounded audit-deny set for the accepted read-only container
// targets, scoped around the accepted read-write transitions of the same
// plan. The output depends only on the profile name, the accepted target
// plan, and whether the host publishes AppArmor ABI 3.0 — never on
// caller-controlled identity beyond the target paths, which are
// literal-encoded.
//
// Per read-only target:
//
//   - a regular-file target denies the exact file path (file-mediated
//     paths carry no directory trailing slash, so the directory-shaped
//     "{,**}" rule alone would leave the file itself writable);
//   - a directory target without any read-write transition beneath it
//     keeps the M0-A proven recursive rule;
//   - a directory target with read-write transitions beneath it walks the
//     read-write hole paths and emits, per node, the entry rule plus
//     subtree rules whose segment exclusion keeps every accepted RW
//     transition writable.
func renderWorkloadAppArmorProfile(profileName string, plan workloadAppArmorTargetPlan, abi30 bool) string {
	var sb strings.Builder
	sb.WriteString("# Generated by docker-helper. Do not edit.\n")
	sb.WriteString("# Helper-owned workload profile; correlated with one run operation.\n")
	if abi30 {
		sb.WriteString("abi <abi/3.0>,\n")
	}
	sb.WriteString("#include <tunables/global>\n\n")
	sb.WriteString("profile \"" + profileName + "\" flags=(attach_disconnected,mediate_deleted) {\n")
	sb.WriteString("  #include <abstractions/base>\n\n")
	sb.WriteString("  network,\n")
	sb.WriteString("  deny network alg,\n")
	sb.WriteString("  deny network vsock,\n")
	sb.WriteString("  capability,\n")
	sb.WriteString("  file,\n")
	sb.WriteString("  umount,\n")
	sb.WriteString("  signal (receive) peer=unconfined,\n")
	sb.WriteString("  signal (receive) peer=runc,\n")
	sb.WriteString("  signal (receive) peer=crun,\n")
	sb.WriteString("  signal (send,receive) peer=\"" + profileName + "\",\n\n")
	sb.WriteString("  deny @{PROC}/* w,\n")
	sb.WriteString("  deny @{PROC}/{[^1-9/],[^1-9/][^0-9/],[^1-9s/][^0-9y/][^0-9s/],[^1-9/][^0-9/][^0-9/][^0-9/]*}/** w,\n")
	sb.WriteString("  deny @{PROC}/sys/[^k]** w,\n")
	sb.WriteString("  deny @{PROC}/sys/kernel/{?,??,[^s][^h][^m]**} w,\n")
	sb.WriteString("  deny @{PROC}/sysrq-trigger rwklx,\n")
	sb.WriteString("  deny @{PROC}/kcore rwklx,\n")
	sb.WriteString("  deny mount,\n")
	sb.WriteString("  deny /sys/[^f]*/** wklx,\n")
	sb.WriteString("  deny /sys/f[^s]*/** wklx,\n")
	sb.WriteString("  deny /sys/fs/[^c]*/** wklx,\n")
	sb.WriteString("  deny /sys/fs/c[^g]*/** wklx,\n")
	sb.WriteString("  deny /sys/firmware/** rwklx,\n")
	sb.WriteString("  deny /sys/devices/virtual/powercap/** rwklx,\n")
	sb.WriteString("  deny /sys/kernel/security/** rwklx,\n")
	sb.WriteString("  ptrace (trace,tracedby,read,readby) peer=\"" + profileName + "\",\n")

	// One deny-rule set per read-only target, deduplicated by rendered
	// rule text (nested read-only targets legitimately restate the same
	// rules) and emitted in deterministic generation order.
	emitted := map[string]bool{}
	for _, target := range plan.RO {
		lit := appArmorPathLiteral(target.Target)
		holeRoot := appArmorHoleTrie(target.Target, plan.RW)
		switch {
		case target.RegularFile:
			appArmorEmit(&sb, emitted, `audit deny "`+lit+`" wkl,`)
		case holeRoot == nil:
			appArmorEmit(&sb, emitted, `audit deny "`+lit+`/{,**}" wkl,`)
		default:
			appArmorEmitHoleWalk(&sb, emitted, lit, holeRoot)
		}
	}
	sb.WriteString("}\n")
	return sb.String()
}

// appArmorEmit appends one deny rule unless an identical rule was already
// rendered for another read-only target.
func appArmorEmit(sb *strings.Builder, emitted map[string]bool, rule string) {
	if emitted[rule] {
		return
	}
	emitted[rule] = true
	sb.WriteString("\n  " + rule + "\n")
}

// appArmorHoleNode is one node of the segment trie of the read-write
// transitions strictly below a read-only target root. Children are keyed
// by full path segment name; leaf marks that a maximal hole ends at this
// node.
type appArmorHoleNode struct {
	children map[string]*appArmorHoleNode
	leaf     bool
}

// appArmorHoleTrie builds the segment trie of the accepted read-write
// transitions strictly below the read-only target root. It returns nil
// when no read-write transition is strictly below the root, so the
// renderer keeps the proven unholed rule shape.
func appArmorHoleTrie(root string, rwTargets []string) *appArmorHoleNode {
	holes := make([][]string, 0, len(rwTargets))
	for _, rw := range rwTargets {
		rel, ok := appArmorRelativeSegments(root, rw)
		if ok {
			holes = append(holes, rel)
		}
	}
	if len(holes) == 0 {
		return nil
	}
	// Deterministic, prefix-independent hole set: sort and drop any hole
	// whose segment path is strictly below another hole (that subtree is
	// already writable transitively).
	sort.Slice(holes, func(i, j int) bool {
		a, b := holes[i], holes[j]
		for k := range a {
			if k >= len(b) {
				return false
			}
			if a[k] != b[k] {
				return a[k] < b[k]
			}
		}
		return len(a) < len(b)
	})
	trieRoot := &appArmorHoleNode{children: map[string]*appArmorHoleNode{}}
	for i, hole := range holes {
		if i > 0 && appArmorHoleContains(holes[i-1], hole) {
			continue
		}
		node := trieRoot
		for _, seg := range hole {
			child, ok := node.children[seg]
			if !ok {
				child = &appArmorHoleNode{children: map[string]*appArmorHoleNode{}}
				node.children[seg] = child
			}
			node = child
		}
		node.leaf = true
	}
	return trieRoot
}

// appArmorRelativeSegments reports whether target is strictly below root in
// container-path terms and returns the relative segment path.
func appArmorRelativeSegments(root, target string) ([]string, bool) {
	if !strings.HasPrefix(target, root+"/") {
		return nil, false
	}
	rel := strings.TrimPrefix(target, root+"/")
	if rel == "" {
		return nil, false
	}
	return strings.Split(rel, "/"), true
}

// appArmorHoleContains reports whether the segment path a strictly contains
// the segment path b.
func appArmorHoleContains(a, b []string) bool {
	if len(a) >= len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// appArmorEmitHoleWalk walks the read-write hole trie of one holed
// read-only target and emits the deny rules that deny the read-only region
// while keeping every hole subtree writable.
//
// Per visited node (the region root itself, then each segment-aligned
// ancestor of a continuing hole):
//
//	<base>/{,}               the node directory entry itself
//	<base>/<EXCL>            non-hole file children
//	<base>/<EXCL>/{,**}      non-hole directory children and their subtrees
//
// EXCL is the segment exclusion of the node's hole child names — the
// fragment's own brace group, always preceded by exactly one `/`. The
// fragment is never wrapped in an extra brace layer: apparmor_parser
// rejects a single-element alternation group ("Invalid number of items
// between {}"), and the fragment root is already a multi-item group.
// Nodes at or below a maximal hole end are never visited: the hole subtree
// is the accepted read-write transition and stays writable.
func appArmorEmitHoleWalk(sb *strings.Builder, emitted map[string]bool, rootLit string, trie *appArmorHoleNode) {
	var walk func(node *appArmorHoleNode, base string)
	walk = func(node *appArmorHoleNode, base string) {
		if node != trie && node.leaf {
			return
		}
		appArmorEmit(sb, emitted, `audit deny "`+base+`/{,}" wkl,`)
		if len(node.children) > 0 {
			names := make([]string, 0, len(node.children))
			for name := range node.children {
				names = append(names, name)
			}
			sort.Strings(names)
			excl := appArmorSegmentExclusion(names)
			appArmorEmit(sb, emitted, `audit deny "`+base+`/`+excl+`" wkl,`)
			appArmorEmit(sb, emitted, `audit deny "`+base+`/`+excl+`/{,**}" wkl,`)
		}
		for _, name := range sortedHoleChildNames(node) {
			walk(node.children[name], base+"/"+appArmorPathLiteral(name))
		}
	}
	walk(trie, rootLit)
}

// sortedHoleChildNames returns the child segment names of one hole trie
// node in deterministic byte order.
func sortedHoleChildNames(node *appArmorHoleNode) []string {
	names := make([]string, 0, len(node.children))
	for name := range node.children {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
