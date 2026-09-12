package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	selinuxWorkspaceType = "docker_helper_workspace_t"
	semanagePath         = "/usr/sbin/semanage"
	restoreconPath       = "/usr/sbin/restorecon"
	// selinuxFcontextLockPath is the global lock for serializing
	// SELinux workspace fcontext state transitions.
	selinuxFcontextLockPath = "/run/lock/docker-helper-selinux.lock"
)

// isUnderHome returns true if the canonical path is /home or under /home.
// The path must already be canonicalized (absolute, no symlinks).
func isUnderHome(canonical string) bool {
	if canonical == "/home" {
		return true
	}
	return strings.HasPrefix(canonical, "/home/")
}

// selinuxFcontextBoundaryAllowed returns true if the given canonical path is
// allowed as a helper-created recursive SELinux fcontext boundary. Exact /opt
// is rejected because it would make the entire standard namespace a recursive
// relabel boundary.
//
// Note: /opt is still a valid authorization ceiling. This function only
// controls whether docker-helper creates a helper-owned fcontext boundary at
// the path. The authorization-root policy and the fcontext-boundary policy are
// distinct.
func selinuxFcontextBoundaryAllowed(canonical string) bool {
	return canonical != "/opt"
}

// selinuxFcontextManager manages persistent SELinux workspace labeling for
// non-home workspaces. It uses semanage fcontext + restorecon to
// create persistent mappings that survive reboot and restorecon.
//
// Test seams: runCommand, readPathCon, selinuxActive, and acquireLock are
// injectable.
type selinuxFcontextManager struct {
	semanagePath   string
	restoreconPath string
	runCommand     func(string, ...string) ([]byte, error)
	readPathCon    func(string) (string, error)
	selinuxActive  func() (bool, bool, error) // (active, enforcing, error)
	// readMountinfo reads the current mount namespace's mount info
	// (/proc/self/mountinfo) used by the workspace relabel-boundary guard.
	readMountinfo func() ([]byte, error)
	// treeKind classifies an issued tree's filesystem kind (directory or
	// regular file). Defaults to selinuxTreeKindFor; injectable in tests.
	treeKind func(string) (selinuxTreeKind, error)
	// acquireLock acquires the global SELinux workspace management lock.
	// Returns a release function and an error. The release function must be
	// called to release the lock.
	acquireLock func() (func() error, error)
}

func newSELinuxFcontextManager() *selinuxFcontextManager {
	rc := func(cmd string, args ...string) ([]byte, error) {
		c := exec.Command(cmd, args...)
		out, err := c.CombinedOutput()
		return out, err
	}
	return &selinuxFcontextManager{
		semanagePath:   semanagePath,
		restoreconPath: restoreconPath,
		runCommand:     rc,
		readPathCon:    readPathSELinuxType,
		selinuxActive:  selinuxEnabled,
		readMountinfo:  readSelfMountinfo,
		treeKind:       selinuxTreeKindFor,
		acquireLock:    acquireSELinuxFcontextLock,
	}
}

// readSelfMountinfo reads the current process mount namespace's mount info.
func readSelfMountinfo() ([]byte, error) {
	return os.ReadFile("/proc/self/mountinfo")
}

// acquireSELinuxFcontextLock acquires the global SELinux workspace management
// lock. Returns a release function and an error.
func acquireSELinuxFcontextLock() (func() error, error) {
	if err := os.MkdirAll("/run/lock", 0755); err != nil {
		return nil, fmt.Errorf("cannot create lock directory: %w", err)
	}
	f, err := os.OpenFile(selinuxFcontextLockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("cannot open SELinux workspace lock: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, fmt.Errorf("cannot acquire SELinux workspace lock: %w", err)
	}
	return func() error {
		syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		return f.Close()
	}, nil
}

// readPathSELinuxType returns the SELinux type component of the given path's
// current label by reading the security.selinux xattr. This reads the ACTUAL
// on-disk label, not the policy-default context.
//
// Uses the two-call Lgetxattr pattern: query required size, allocate, read.
func readPathSELinuxType(path string) (string, error) {
	// Query required size.
	n, err := unix.Lgetxattr(path, "security.selinux", nil)
	if err != nil {
		if errors.Is(err, unix.ENODATA) {
			return "", fmt.Errorf("no SELinux xattr on %s", path)
		}
		return "", fmt.Errorf("cannot query SELinux xattr size for %s: %w", path, err)
	}
	if n == 0 {
		return "", fmt.Errorf("empty SELinux xattr on %s", path)
	}
	// Bounded allocation: SELinux contexts are typically < 256 bytes.
	if n > 4096 {
		return "", fmt.Errorf("SELinux xattr on %s exceeds maximum size %d", path, n)
	}
	buf := make([]byte, n)
	n, err = unix.Lgetxattr(path, "security.selinux", buf)
	if err != nil {
		return "", fmt.Errorf("cannot read SELinux xattr for %s: %w", path, err)
	}
	// Handle trailing NUL safely.
	ctx := string(buf[:n])
	if len(ctx) > 0 && ctx[len(ctx)-1] == 0 {
		ctx = ctx[:len(ctx)-1]
	}
	return parseSELinuxType(ctx)
}

// escapeFcontextPath escapes a filesystem path for use in a semanage fcontext
// regex. It escapes regex metacharacters but preserves the path structure.
// The caller appends the descendant pattern (e.g., "(/.*)?").
func escapeFcontextPath(path string) string {
	var b strings.Builder
	for _, c := range path {
		switch c {
		case '\\', '^', '$', '*', '+', '?', '(', ')', '[', ']', '{', '}', '|', '.':
			b.WriteByte('\\')
			b.WriteRune(c)
		default:
			b.WriteRune(c)
		}
	}
	return b.String()
}

// fcontextPattern returns the full regex pattern for the fcontext rule of a
// directory boundary. It correctly escapes the boundary and appends the
// descendant pattern so that /data matches /data and /data/foo but NOT
// /data/foobar as a prefix match.
func fcontextPattern(boundary string) string {
	return fcontextPatternFor(boundary, selinuxTreeDirectory)
}

// fcontextPatternFor returns the full regex pattern for the fcontext rule of
// one boundary of the given kind. A directory boundary maps the boundary and
// every descendant (/path(/.*)?); a regular-file boundary maps exactly the
// file (/path) — a descendant pattern would never match a file.
func fcontextPatternFor(boundary string, kind selinuxTreeKind) string {
	escaped := escapeFcontextPath(boundary)
	if kind == selinuxTreeRegularFile {
		return escaped
	}
	return escaped + "(/.*)?"
}

// fcontextStem extracts the literal path stem from a fcontext pattern.
// For "/data(/.*)?" it returns "/data".
// For "/data\\.test(/.*)?" it returns "/data.test".
// For an exact-path pattern (a regular-file boundary rule) it returns the
// literal path: "/data" stays "/data".
// For patterns that cannot be safely classified, it returns an empty string.
//
// Classification is canonical: the round-trip
//
//	escapeFcontextPath(unescapeFcontextPath(escaped)) == escaped
//
// is the authority for whether a stem is a safely classifiable literal path.
func fcontextStem(pattern string) string {
	// Strip the common descendant suffix.
	suffix := "(/.*)?"
	if strings.HasSuffix(pattern, suffix) {
		escaped := pattern[:len(pattern)-len(suffix)]
		literal, ok := unescapeFcontextPath(escaped)
		if !ok {
			return "" // unknown escape sequence - unclassifiable
		}
		// Round-trip check: the authority for safe classification.
		if escapeFcontextPath(literal) != escaped {
			return "" // not a literal-path regex we can classify
		}
		return literal
	}
	// Exact-path pattern (regular-file boundary rule): classify with the
	// same round-trip authority. Only an absolute literal path is a
	// classifiable exact pattern; any other unsuffixed regex is
	// unclassifiable and fails closed downstream.
	literal, ok := unescapeFcontextPath(pattern)
	if !ok {
		return "" // unknown escape sequence - unclassifiable
	}
	if !strings.HasPrefix(literal, "/") {
		return "" // not an absolute literal-path pattern
	}
	if escapeFcontextPath(literal) != pattern {
		return "" // not a literal-path pattern we can classify
	}
	return literal
}

// unescapeFcontextPath reverses escapeFcontextPath escaping.
// Returns (literal, true) when all escape sequences are ones that
// escapeFcontextPath itself can produce.
// Returns ("", false) when an unknown escape sequence is encountered
// (e.g., \d, \w, \s, \x2f, \Q, \E), indicating the pattern is
// not a simple literal path and cannot be classified safely.
func unescapeFcontextPath(s string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			next := s[i+1]
			switch next {
			case '\\', '^', '$', '*', '+', '?', '(', ')', '[', ']', '{', '}', '|', '.':
				b.WriteByte(next)
				i++
				continue
			}
			// Unknown escape sequence - not generated by escapeFcontextPath.
			return "", false
		}
		b.WriteByte(s[i])
	}
	return b.String(), true
}

// ensureWorkspaceFcontext ensures that the canonical issued tree has a
// persistent SELinux mapping to docker_helper_workspace_t. It:
//  1. Fails closed when the relabel boundary is unsafe (mount point
//     at or beneath the tree; see checkWorkspaceRelabelBoundary);
//  2. Acquires the global SELinux workspace management lock;
//  3. Checks for existing local fcontext rules;
//  4. If no matching rule exists, adds one (kind-aware: a directory
//     boundary maps the boundary and every descendant, a regular-file
//     boundary maps exactly the file);
//  5. If an existing rule maps to a different type, fails closed;
//  6. Relabels the tree (kind-aware restorecon; guarded again by the
//     mount-boundary check);
//  7. Verifies the actual on-disk type.
//
// Returns whether a new mapping was created (true) or already existed (false).
//
// This is the backend-internal atomic preparation primitive. If preparation
// fails before successful return, it may roll back its own partial changes
// (e.g., removing a newly-added fcontext rule when restorecon fails).
//
// After successful return:
//
//   - unrelated config/init/reload failures do not roll it back;
//   - normal later removal is a separate lifecycle operation owned by
//     sessionMACCoordinator (via selinuxWorkspaceMACDriver.removeBoundary).
//
// Coverage versus ownership:
//
//   - newlyCreated == true means docker-helper created the boundary;
//     the sessionMACCoordinator records ownership metadata separately.
//   - newlyCreated == false means a compatible boundary already existed;
//     it may be helper-owned (tracked in mac_boundaries) or
//     operator-compatible (never helper-owned).
//   - HelperOwned is resolved by the sessionMACCoordinator using durable
//     ownership metadata, not by this backend function.
func (m *selinuxFcontextManager) ensureWorkspaceFcontext(tree string, kind selinuxTreeKind) (newlyCreated bool, err error) {
	active, enforcing, err := m.selinuxActive()
	if err != nil {
		return false, fmt.Errorf("cannot determine SELinux status: %w", err)
	}
	if !active || !enforcing {
		return false, nil
	}

	// Fail-closed mount-boundary preflight, before any fcontext state is read
	// or mutated: reject a workspace that is itself a mount point or has a
	// mount point beneath it. The authoritative re-check also runs inside
	// restoreconRecursive immediately before the command; this early check
	// avoids creating or modifying any fcontext rule for an unsafe boundary.
	if err := m.checkWorkspaceRelabelBoundary(tree); err != nil {
		return false, err
	}

	// Acquire global SELinux workspace management lock.
	release, err := m.acquireLock()
	if err != nil {
		return false, fmt.Errorf("cannot acquire SELinux workspace lock: %w", err)
	}
	defer release() // best-effort

	boundary := tree
	pattern := fcontextPatternFor(boundary, kind)

	// Check existing local fcontext rules.
	existing, err := m.listLocalFcontextRules()
	if err != nil {
		return false, fmt.Errorf("cannot list local fcontext rules: %w", err)
	}

	// Identify our exact rule if present.
	ourRuleIdx := -1
	for i, rule := range existing {
		if rule.pattern == pattern {
			ourRuleIdx = i
			break
		}
	}

	// Validate ALL other rules for conflicts/overlap.
	if err := m.checkOverlap(boundary, pattern, existing); err != nil {
		return false, err
	}

	if ourRuleIdx >= 0 {
		existingRule := existing[ourRuleIdx]
		// Equivalence record at our exact pattern: fail closed.
		if existingRule.isEquivalence {
			return false, fmt.Errorf(
				"unclassifiable SELinux fcontext equivalence record %s may overlap with %s; remove or classify it before proceeding",
				existingRule.pattern, pattern,
			)
		}
		if existingRule.fileType == selinuxWorkspaceType {
			// Exact match already exists - idempotent path.
			// Still need to run restorecon and verify.
			if err := m.restoreconTree(tree, kind); err != nil {
				return false, fmt.Errorf("restorecon failed for existing mapping %s: %w", tree, err)
			}
			if err := m.verifyActualType(tree); err != nil {
				return false, err
			}
			return false, nil
		}
		// Conflicting local rule.
		return false, fmt.Errorf(
			"conflicting SELinux fcontext rule exists for %s: pattern %s maps to %s (expected %s); remove the conflicting rule before proceeding",
			tree, existingRule.pattern, existingRule.fileType, selinuxWorkspaceType,
		)
	}

	// No matching rule - add ours.
	if err := m.addFcontextRule(pattern, selinuxWorkspaceType); err != nil {
		return false, fmt.Errorf("cannot add fcontext rule for %s: %w", tree, err)
	}

	// Apply restorecon recursively.
	if err := m.restoreconTree(tree, kind); err != nil {
		// Internal rollback: manager cannot complete its transition.
		if rbErr := m.removeFcontextBoundary(boundary); rbErr != nil {
			return false, fmt.Errorf("restorecon failed: %v; rollback also failed: %v", err, rbErr)
		}
		return false, fmt.Errorf("restorecon failed for %s: %w", tree, err)
	}

	// Verify the actual on-disk type.
	if err := m.verifyActualType(tree); err != nil {
		// Internal rollback.
		if rbErr := m.removeFcontextBoundary(boundary); rbErr != nil {
			return false, fmt.Errorf("verification failed: %v; rollback also failed: %v", err, rbErr)
		}
		return false, err
	}

	return true, nil
}

// checkOverlap checks for overlapping operator-local rules that would conflict
// with our new mapping. It validates ALL other rules, regardless of whether
// our exact rule already exists.
//
// Contract:
//   - operator-local customization definitely inside boundary: fail closed;
//   - operator-local customization whose target is an ancestor of boundary: fail closed;
//   - unrelated sibling boundaries: allowed;
//   - if an arbitrary regex/equivalence cannot be proven disjoint safely: fail closed;
//   - rules mapping to docker_helper_workspace_t are compatible (docker-helper-owned or
//     operator-compatible) and are allowed to overlap.
func (m *selinuxFcontextManager) checkOverlap(boundary string, ourPattern string, existing []fcontextRule) error {
	boundaryStem := boundary // the literal unescaped boundary

	for _, rule := range existing {
		if rule.pattern == ourPattern {
			continue // our own exact rule, handled separately
		}

		// Equivalence records.
		if rule.isEquivalence {
			// Redirect-style equivalence: DEST = SOURCE
			if rule.equivalenceDest != "" || rule.equivalenceSource != "" {
				if err := m.checkEquivalenceOverlap(boundary, rule); err != nil {
					return err
				}
				continue
			}
			// <<None>> style equivalence at our exact pattern is handled separately.
			// For any other pattern, fail closed.
			return fmt.Errorf(
				"unclassifiable SELinux fcontext equivalence record %s may overlap with %s; remove or classify it before proceeding",
				rule.pattern, ourPattern,
			)
		}

		// Rules mapping to docker_helper_workspace_t are compatible
		// (docker-helper-owned or operator-compatible). Allow overlap.
		if rule.fileType == selinuxWorkspaceType {
			continue
		}

		// Extract literal stem from the rule pattern.
		ruleStem := fcontextStem(rule.pattern)
		if ruleStem == "" {
			// Cannot classify safely - fail closed.
			return fmt.Errorf(
				"unclassifiable SELinux fcontext pattern %s may overlap with %s; remove or classify it before proceeding",
				rule.pattern, ourPattern,
			)
		}

		// Rule stem is a descendant of the candidate boundary: our broad rule would override it.
		if pathStrictlyWithin(boundaryStem, ruleStem) {
			return fmt.Errorf(
				"operator-local fcontext rule %s (stem %s) would be overridden by %s; remove the local rule before proceeding",
				rule.pattern, ruleStem, ourPattern,
			)
		}

		// Rule stem is an ancestor of the candidate boundary: its semantics would be overridden.
		if pathStrictlyWithin(ruleStem, boundaryStem) {
			return fmt.Errorf(
				"operator-local fcontext rule %s (stem %s) is an ancestor of %s; removing it would change operator policy",
				rule.pattern, ruleStem, ourPattern,
			)
		}
	}
	return nil
}

// checkEquivalenceOverlap checks if a redirect-style equivalence record
// (DEST = SOURCE) overlaps with the selected boundary.
// Returns nil if the equivalence is completely disjoint from the boundary.
// Returns an error if DEST or SOURCE equals, contains, or is contained by the boundary.
func (m *selinuxFcontextManager) checkEquivalenceOverlap(boundary string, rule fcontextRule) error {
	dest := rule.equivalenceDest
	source := rule.equivalenceSource

	// Check if DEST overlaps with boundary.
	if dest != "" {
		if dest == boundary || pathStrictlyWithin(boundary, dest) || pathStrictlyWithin(dest, boundary) {
			return fmt.Errorf(
				"SELinux fcontext equivalence destination %s overlaps with %s; remove or classify it before proceeding",
				dest, boundary,
			)
		}
	}

	// Check if SOURCE overlaps with boundary.
	if source != "" {
		if source == boundary || pathStrictlyWithin(boundary, source) || pathStrictlyWithin(source, boundary) {
			return fmt.Errorf(
				"SELinux fcontext equivalence source %s overlaps with %s; remove or classify it before proceeding",
				source, boundary,
			)
		}
	}

	return nil
}

// verifyActualType reads the actual on-disk SELinux type for the given path and
// verifies it matches docker_helper_workspace_t.
func (m *selinuxFcontextManager) verifyActualType(path string) error {
	actualType, err := m.readPathCon(path)
	if err != nil {
		return fmt.Errorf("cannot verify SELinux type for %s: %w", path, err)
	}
	if actualType != selinuxWorkspaceType {
		return fmt.Errorf(
			"SELinux type for %s is %s, expected %s after restorecon",
			path, actualType, selinuxWorkspaceType,
		)
	}
	return nil
}

// removeFcontextBoundary removes the persistent fcontext rule(s) of one
// docker-helper-owned boundary and relabels whatever still exists at the
// boundary back to policy defaults. It is the backend-native removal
// primitive used in two contexts:
//
//  1. Internal rollback: when ensureWorkspaceFcontext fails before successful
//     return and needs to undo its own partial changes.
//
//  2. Lifecycle removal: called through sessionMACCoordinator when all
//     consumers are gone, via the call path:
//
//     sessionMACCoordinator
//     -> selinuxWorkspaceMACDriver.removeBoundary
//     -> selinuxFcontextManager.removeFcontextBoundary
//
// It is NOT called by outer init or config code on a previously successful
// mapping. Once ensureWorkspaceFcontext returns success, the mapping is
// managed durable state and removal is a separate lifecycle operation.
//
// The boundary's own rules are found by stem in the local fcontext rules and
// removed exactly as stored: a directory boundary carries the descendant
// suffix pattern, a regular-file boundary the exact-path pattern. Removing
// by stem keeps one path-kind-aware owner instead of guessing the rule
// shape. Mount-safety preflight runs BEFORE deleting the persistent rule: if
// the boundary cannot be safely restored, leave the existing rule/state
// intact and fail closed. The authoritative re-check also runs inside
// restoreconTree after rule removal (the rollback restorecon itself) — but
// by then the durable rule must already be preserved by this preflight when
// the relabel would be unsafe. A boundary whose tree no longer exists has
// nothing left to relabel; the rule removal alone is the complete rollback.
func (m *selinuxFcontextManager) removeFcontextBoundary(boundary string) error {
	// Mount-safety preflight BEFORE deleting the persistent fcontext rule.
	if err := m.checkWorkspaceRelabelBoundary(boundary); err != nil {
		return err
	}

	existing, err := m.listLocalFcontextRules()
	if err != nil {
		return fmt.Errorf("cannot list local fcontext rules: %w", err)
	}

	removed := false
	for _, rule := range existing {
		if rule.isEquivalence {
			continue
		}
		if fcontextStem(rule.pattern) != boundary {
			continue
		}
		if err := m.removeFcontextRule(rule.pattern); err != nil {
			return fmt.Errorf("cannot remove fcontext rule for %s: %w", boundary, err)
		}
		removed = true
	}
	if !removed {
		return fmt.Errorf("no persistent SELinux fcontext rule for boundary %s; helper ownership state mismatch", boundary)
	}

	// Then restore labels to policy defaults for whatever still exists at
	// the boundary.
	if kind, kindErr := m.treeKind(boundary); kindErr == nil {
		if err := m.restoreconTree(boundary, kind); err != nil {
			return fmt.Errorf("restorecon rollback for %s after rule removal: %w", boundary, err)
		}
	}

	return nil
}

// fcontextRule represents a parsed semanage fcontext rule.
type fcontextRule struct {
	pattern       string
	fileType      string
	isEquivalence bool
	// For equivalence records (DEST = SOURCE):
	equivalenceDest   string // literal prefix of DEST
	equivalenceSource string // literal prefix of SOURCE
}

// listLocalFcontextRules returns local custom fcontext rules.
// Uses -C -n to inspect only local customizations, not base policy.
//
// Fails closed on any non-empty line that cannot be classified safely.
func (m *selinuxFcontextManager) listLocalFcontextRules() ([]fcontextRule, error) {
	out, err := m.runCommand(m.semanagePath, "fcontext", "-l", "-C", "-n")
	if err != nil {
		return nil, fmt.Errorf("semanage fcontext -l -C -n: %w: %s", err, strings.TrimSpace(string(out)))
	}

	var rules []fcontextRule
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		rule, ok := parseFcontextLine(line)
		if ok {
			rules = append(rules, rule)
		} else {
			// Unparseable non-empty line: fail closed.
			return nil, fmt.Errorf(
				"unparseable local fcontext customization: %q; cannot safely determine overlap",
				line,
			)
		}
	}
	return rules, nil
}

// parseFcontextLine parses a single line from semanage fcontext output.
// Returns the rule and whether it was successfully parsed.
//
// Handles:
// - Ordinary fcontext records: PATTERN  gen_context(...) or PATTERN  user:role:type:range
// - Equivalence records (None): PATTERN  <<None>>
// - Equivalence records (redirect): DEST = SOURCE
// - Lines that cannot be classified return (fcontextRule{}, false).
func parseFcontextLine(line string) (fcontextRule, bool) {
	// Check for equivalence redirect: "DEST = SOURCE"
	if eq := parseEquivalenceRedirect(line); eq != nil {
		return *eq, true
	}

	// Find the context part by looking for the double-space separator.
	idx := strings.Index(line, "  ")
	if idx < 0 {
		return fcontextRule{}, false
	}

	pattern := strings.TrimSpace(line[:idx])
	ctxPart := strings.TrimSpace(line[idx+2:])

	if pattern == "" {
		return fcontextRule{}, false
	}

	// Equivalence record.
	if ctxPart == "<<None>>" {
		return fcontextRule{
			pattern:       pattern,
			fileType:      "",
			isEquivalence: true,
		}, true
	}

	// Extract type from context.
	var typ string
	if idx2 := strings.Index(ctxPart, "object_r:"); idx2 >= 0 {
		rest := ctxPart[idx2+len("object_r:"):]
		if colon := strings.Index(rest, ":"); colon >= 0 {
			typ = rest[:colon]
		} else {
			typ = rest
		}
	}

	if typ == "" {
		return fcontextRule{}, false
	}

	return fcontextRule{pattern: pattern, fileType: typ}, true
}

// parseEquivalenceRedirect checks if the line is an equivalence redirect
// of the form "DEST = SOURCE". Returns a parsed rule or nil if not an
// equivalence redirect.
//
// Both DEST and SOURCE must be non-empty absolute literal filesystem paths.
// Regex syntax, unknown escapes, or malformed operands cause the function
// to return nil (fail-closed).
func parseEquivalenceRedirect(line string) *fcontextRule {
	// Find " = " separator (not at the start, to avoid matching patterns
	// that contain " = ").
	idx := strings.Index(line, " = ")
	if idx <= 0 {
		return nil
	}

	dest := strings.TrimSpace(line[:idx])
	source := strings.TrimSpace(line[idx+3:])

	if dest == "" || source == "" {
		return nil
	}

	// Both operands must be non-empty absolute literal filesystem paths.
	if !isLiteralAbsPath(dest) || !isLiteralAbsPath(source) {
		return nil
	}

	return &fcontextRule{
		pattern:           line,
		isEquivalence:     true,
		equivalenceDest:   dest,
		equivalenceSource: source,
	}
}

// isLiteralAbsPath returns true if the string is a non-empty absolute
// literal filesystem path with no regex metacharacters.
func isLiteralAbsPath(s string) bool {
	if !strings.HasPrefix(s, "/") {
		return false
	}
	for _, c := range s {
		switch c {
		case '\\', '^', '$', '*', '+', '?', '(', ')', '[', ']', '{', '}', '|':
			return false
		}
	}
	return true
}

func (m *selinuxFcontextManager) addFcontextRule(pattern, fileType string) error {
	// semanage fcontext -a -t TYPE PATTERN
	out, err := m.runCommand(m.semanagePath, "fcontext", "-a", "-t", fileType, pattern)
	if err != nil {
		return fmt.Errorf("semanage fcontext -a: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (m *selinuxFcontextManager) removeFcontextRule(pattern string) error {
	// semanage fcontext -d PATTERN
	out, err := m.runCommand(m.semanagePath, "fcontext", "-d", pattern)
	if err != nil {
		return fmt.Errorf("semanage fcontext -d: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// parseMountinfoMountPoints parses /proc/self/mountinfo content and returns the
// unescaped mount point of every entry.
//
// mountinfo line format (proc(5)):
//
//	<id> <parent> <major:minor> <root> <mount point> <opts> [<optional>...] - <fstype> <source> <super opts>
//
// The kernel separates fields with single spaces but escapes any space, tab,
// newline or backslash inside path/option values as \040, \011, \012, \134.
// The first literal " - " is therefore the field-8 separator; the mount point
// is field 5, token index 4 in the pre-separator region.
//
// A non-empty line that cannot be parsed fails closed (returns an error): a
// mount topology we cannot classify must never be assumed safe.
func parseMountinfoMountPoints(data []byte) ([]string, error) {
	var mps []string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		sep := strings.Index(line, " - ")
		if sep < 0 {
			return nil, fmt.Errorf("unparseable mountinfo line %q: missing field separator", line)
		}
		fields := strings.Fields(line[:sep])
		if len(fields) < 5 {
			return nil, fmt.Errorf("unparseable mountinfo line %q: fewer than five fields before separator", line)
		}
		mps = append(mps, unescapeMountinfoPath(fields[4]))
	}
	return mps, nil
}

// unescapeMountinfoPath decodes the octal escape sequences the kernel uses in
// /proc/self/mountinfo path fields: \040 (space), \011 (tab), \012 (newline)
// and \134 (backslash). Any other backslash sequence is left untouched.
func unescapeMountinfoPath(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if v, ok := decodeMountinfoOctal(s[i+1 : i+4]); ok {
				b.WriteByte(v)
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// decodeMountinfoOctal decodes exactly three octal digits.
func decodeMountinfoOctal(s string) (byte, bool) {
	v := 0
	for i := 0; i < 3; i++ {
		c := s[i]
		if c < '0' || c > '7' {
			return 0, false
		}
		v = v*8 + int(c-'0')
	}
	return byte(v), true
}

// checkWorkspaceRelabelBoundary verifies that a helper-managed recursive
// relabel of the given workspace is safe. It fails closed (returns an error)
// when the workspace itself is a mount point or when any mount point exists
// strictly beneath the workspace: a recursive restorecon would otherwise
// descend into that mount and relabel its contents — including, for a
// same-filesystem bind mount, the external source inode — according to the
// workspace pathname (restorecon -x only skips mounts on a different st_dev).
//
// Classification (all paths canonical absolute, compared component-wise via
// pathWithin/pathStrictlyWithin, not string-prefix-wise):
//
//	mount point == workspace          -> reject (workspace itself is a mount)
//	mount point ancestor of workspace -> allowed (the workspace's own fs mount)
//	mount point strictly beneath ws   -> reject (nested mount / bind mount)
//	sibling / unrelated               -> allowed
//
// A mountinfo read or parse failure fails closed (relabel refused).
func (m *selinuxFcontextManager) checkWorkspaceRelabelBoundary(workspace string) error {
	data, err := m.readMountinfo()
	if err != nil {
		return fmt.Errorf("cannot read mount info for workspace relabel safety: %w", err)
	}
	mountPoints, err := parseMountinfoMountPoints(data)
	if err != nil {
		return fmt.Errorf("cannot parse mount info for workspace relabel safety: %w", err)
	}
	ws := filepath.Clean(workspace)
	for _, mp := range mountPoints {
		cleanMP := filepath.Clean(mp)
		if cleanMP == ws {
			return fmt.Errorf(
				"refusing recursive workspace relabel: workspace %s is itself a mount point",
				workspace,
			)
		}
		if pathWithin(cleanMP, ws) {
			// Ancestor mount (the workspace's own filesystem): allowed.
			continue
		}
		if pathStrictlyWithin(ws, cleanMP) {
			return fmt.Errorf(
				"refusing recursive workspace relabel: mount point %s exists beneath workspace %s",
				mp, workspace,
			)
		}
	}
	return nil
}

// restoreconPath relabels the given issued tree with the kind-aware
// canonical restorecon invocation shared by the initial relabel, the
// idempotent existing-boundary relabel, and the rollback/removal paths.
//
// A directory tree uses the recursive form (documented below); a
// regular-file tree uses the plain form (there is nothing to recurse into,
// and the trailing-slash recursion of a file operand is meaningless).
//
// Directory flags (confirmed against the UAT platform's restorecon(8),
// openSUSE Tumbleweed policycoreutils 3.11-2.2):
//
//	-R   change file and directory labels recursively.
//	-m   do not read /proc/mounts to obtain a list of non-seclabel mounts to
//	     be excluded from relabeling checks.
//	-x   prevent restorecon from crossing file system boundaries.
//
// -m is required in the confined context: without it selinux_restorecon(3)
// scans /proc/mounts and statvfs()es every mounted filesystem to classify
// seclabel vs non-seclabel mounts, which requires filesystem getattr on many
// filesystem types (fs_t, device_t, devpts_t, cgroup_t, ...). The docker_helper_t
// domain is intentionally not granted those mount-scan permissions. The
// trusted-CA restorecon already uses -m for the same reason.
//
// -x prevents the recursive walk from relabeling a different filesystem
// mounted beneath the tree (selinux_restorecon(3) SELINUX_RESTORECON_XDEV:
// do not descend into directories with a different device number than the
// pathname from which the descent began). Combined with -m this also covers
// the non-seclabel-mount exclusion that /proc/mounts scanning used to
// provide: a non-seclabel filesystem is necessarily a different filesystem
// (different st_dev), so -x skips it.
//
// Same-filesystem bind mounts: -x compares st_dev, so it does NOT prevent
// descent into a same-filesystem bind mount (a bind mount shares the source
// filesystem's device number) and would relabel the external source inode
// according to the tree pathname. That mount-alias case is closed here by
// checkWorkspaceRelabelBoundary, which rejects a tree that is itself a
// mount point or has any mount point strictly beneath it BEFORE restorecon
// runs. This relabel is therefore only ever invoked on a boundary with no
// mount point at or below it.
//
// Type-only: restorecon is never passed -F, so user/role/MLS/MCS range are
// not forcibly reset.
func (m *selinuxFcontextManager) restoreconTree(path string, kind selinuxTreeKind) error {
	if err := m.checkWorkspaceRelabelBoundary(path); err != nil {
		return err
	}
	if kind == selinuxTreeRegularFile {
		out, err := m.runCommand(m.restoreconPath, "-m", path)
		if err != nil {
			return fmt.Errorf("restorecon -m: %w: %s", err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	out, err := m.runCommand(m.restoreconPath, "-R", "-m", "-x", path)
	if err != nil {
		return fmt.Errorf("restorecon -R -m -x: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// listCoveringFcontexts returns all existing fcontext boundaries that cover
// the given workspace path. Returns only boundaries that map to
// docker_helper_workspace_t. The caller determines ownership via mac_boundaries.
func (m *selinuxFcontextManager) listCoveringFcontexts(workspace string) ([]string, error) {
	rules, err := m.listLocalFcontextRules()
	if err != nil {
		return nil, err
	}

	var covering []string
	for _, rule := range rules {
		if rule.fileType != selinuxWorkspaceType {
			continue
		}
		stem := fcontextStem(rule.pattern)
		if stem == "" {
			continue
		}
		if boundaryCoversWorkspace(stem, workspace) {
			covering = append(covering, stem)
		}
	}
	return covering, nil
}
