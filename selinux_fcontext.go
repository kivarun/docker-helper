package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
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
		acquireLock:    acquireSELinuxFcontextLock,
	}
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

// fcontextPattern returns the full regex pattern for the fcontext rule.
// It correctly escapes the boundary and appends the descendant pattern so that
// /data matches /data and /data/foo but NOT /data/foobar as a prefix match.
func fcontextPattern(boundary string) string {
	escaped := escapeFcontextPath(boundary)
	return escaped + "(/.*)?"
}

// fcontextStem extracts the literal path stem from a fcontext pattern.
// For "/data(/.*)?" it returns "/data".
// For "/data\\.test(/.*)?" it returns "/data.test".
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
	// Cannot classify safely.
	return ""
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

// ensureWorkspaceFcontext ensures that the canonical workspace has a persistent
// SELinux mapping to docker_helper_workspace_t. It:
//  1. Acquires the global SELinux workspace management lock;
//  2. Checks for existing local fcontext rules;
//  3. If no matching rule exists, adds one;
//  4. If an existing rule maps to a different type, fails closed;
//  5. Runs restorecon recursively;
//  6. Verifies the actual on-disk type.
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
func (m *selinuxFcontextManager) ensureWorkspaceFcontext(workspace string) (newlyCreated bool, err error) {
	active, enforcing, err := m.selinuxActive()
	if err != nil {
		return false, fmt.Errorf("cannot determine SELinux status: %w", err)
	}
	if !active || !enforcing {
		return false, nil
	}

	// Acquire global SELinux workspace management lock.
	release, err := m.acquireLock()
	if err != nil {
		return false, fmt.Errorf("cannot acquire SELinux workspace lock: %w", err)
	}
	defer release() // best-effort

	boundary := workspace
	pattern := fcontextPattern(boundary)

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
			if err := m.restoreconRecursive(workspace); err != nil {
				return false, fmt.Errorf("restorecon failed for existing mapping %s: %w", workspace, err)
			}
			if err := m.verifyActualType(workspace); err != nil {
				return false, err
			}
			return false, nil
		}
		// Conflicting local rule.
		return false, fmt.Errorf(
			"conflicting SELinux fcontext rule exists for %s: pattern %s maps to %s (expected %s); remove the conflicting rule before proceeding",
			workspace, existingRule.pattern, existingRule.fileType, selinuxWorkspaceType,
		)
	}

	// No matching rule - add ours.
	if err := m.addFcontextRule(pattern, selinuxWorkspaceType); err != nil {
		return false, fmt.Errorf("cannot add fcontext rule for %s: %w", workspace, err)
	}

	// Apply restorecon recursively.
	if err := m.restoreconRecursive(workspace); err != nil {
		// Internal rollback: manager cannot complete its transition.
		if rbErr := m.removeFcontextBoundary(boundary); rbErr != nil {
			return false, fmt.Errorf("restorecon failed: %v; rollback also failed: %v", err, rbErr)
		}
		return false, fmt.Errorf("restorecon failed for %s: %w", workspace, err)
	}

	// Verify the actual on-disk type.
	if err := m.verifyActualType(workspace); err != nil {
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

// removeWorkspaceFcontext removes an fcontext rule and runs restorecon to
// revert labels. It is the backend-native removal primitive used in two
// contexts:
//
//  1. Internal rollback: when ensureWorkspaceFcontext fails before successful
//     return and needs to undo its own partial changes.
//
//  2. Lifecycle removal: called through sessionMACCoordinator when all
//     consumers are gone, via the call path:
//
//     sessionMACCoordinator
//     -> selinuxWorkspaceMACDriver.removeBoundary
//     -> selinuxFcontextManager.removeWorkspaceFcontext
//
// It is NOT called by outer init or config code on a previously successful
// mapping. Once ensureWorkspaceFcontext returns success, the mapping is
// managed durable state and removal is a separate lifecycle operation.
func (m *selinuxFcontextManager) removeFcontextBoundary(boundary string) error {
	pattern := fcontextPattern(boundary)

	// First remove the fcontext rule.
	if err := m.removeFcontextRule(pattern); err != nil {
		return fmt.Errorf("cannot remove fcontext rule for %s: %w", boundary, err)
	}

	// Then restore labels to policy defaults.
	if err := m.restoreconRecursive(boundary); err != nil {
		return fmt.Errorf("restorecon rollback for %s after rule removal: %w", boundary, err)
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

func (m *selinuxFcontextManager) restoreconRecursive(path string) error {
	// Type-only restorecon: do not forcibly reset user, role, or MLS/MCS range.
	out, err := m.runCommand(m.restoreconPath, "-R", path)
	if err != nil {
		return fmt.Errorf("restorecon -R: %w: %s", err, strings.TrimSpace(string(out)))
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
