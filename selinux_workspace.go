package main

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	selinuxWorkspaceType = "docker_helper_workspace_t"
	semanagePath         = "/usr/sbin/semanage"
	restoreconPath       = "/usr/sbin/restorecon"
)

// isHomeRoot returns true if the canonical path is /home or under /home.
// The path must already be canonicalized (absolute, no symlinks).
func isHomeRoot(canonical string) bool {
	if canonical == "/home" {
		return true
	}
	return strings.HasPrefix(canonical, "/home/")
}

// selinuxWorkspaceManager manages persistent SELinux workspace labeling for
// non-home system allowed_roots. It uses semanage fcontext + restorecon to
// create persistent mappings that survive reboot and restorecon.
//
// Test seams: runCommand, readPathCon, and selinuxActive are injectable.
type selinuxWorkspaceManager struct {
	semanagePath   string
	restoreconPath string
	runCommand     func(string, ...string) ([]byte, error)
	readPathCon    func(string) (string, error)
	selinuxActive  func() (bool, bool, error) // (active, enforcing, error)
}

func newSELinuxWorkspaceManager() *selinuxWorkspaceManager {
	rc := func(cmd string, args ...string) ([]byte, error) {
		c := exec.Command(cmd, args...)
		out, err := c.CombinedOutput()
		return out, err
	}
	return &selinuxWorkspaceManager{
		semanagePath:   semanagePath,
		restoreconPath: restoreconPath,
		runCommand:     rc,
		readPathCon:    readPathSELinuxType,
		selinuxActive:  selinuxEnabled,
	}
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
//
// Note: regexp.QuoteMeta does not escape '.', but we need to escape it
// for fcontext patterns to avoid matching any character at that position.
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
// It correctly escapes the root and appends the descendant pattern so that
// /data matches /data and /data/foo but NOT /data/foobar as a prefix match.
func fcontextPattern(root string) string {
	escaped := escapeFcontextPath(root)
	return escaped + "(/.*)?"
}

// fcontextStem extracts the literal path stem from a fcontext pattern.
// For "/data(/.*)?" it returns "/data".
// For "/data\\.test(/.*)?" it returns "/data.test".
// For patterns that cannot be safely classified, it returns an empty string.
func fcontextStem(pattern string) string {
	// Strip the common descendant suffix.
	suffix := "(/.*)?"
	if strings.HasSuffix(pattern, suffix) {
		escaped := pattern[:len(pattern)-len(suffix)]
		// Unescape regex escapes.
		return unescapeFcontextPath(escaped)
	}
	// Cannot classify safely.
	return ""
}

// unescapeFcontextPath reverses escapeFcontextPath escaping.
func unescapeFcontextPath(s string) string {
	// escapeFcontextPath escapes: \ ^ $ * + ? ( ) [ ] { } | and .
	// We need to remove the backslash before these characters.
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
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// ensureWorkspaceLabel ensures that the canonical root has a persistent
// SELinux mapping to docker_helper_workspace_t. It:
//  1. Checks for existing local fcontext rules;
//  2. If no matching rule exists, adds one;
//  3. If an existing rule maps to a different type, fails closed;
//  4. Runs restorecon recursively;
//  5. Verifies the actual on-disk type.
//
// Returns whether a new mapping was created (true) or already existed (false).
//
// Monotonic managed-label lifecycle (R2):
// Once this function returns success, the mapping is managed durable state.
// The caller MUST NOT roll it back on subsequent failures.
// Internal rollback only occurs when the manager itself cannot complete
// before returning success.
func (m *selinuxWorkspaceManager) ensureWorkspaceLabel(root string) (newlyCreated bool, err error) {
	active, enforcing, err := m.selinuxActive()
	if err != nil {
		return false, fmt.Errorf("cannot determine SELinux status: %w", err)
	}
	if !active || !enforcing {
		return false, nil
	}

	pattern := fcontextPattern(root)

	// Check existing local fcontext rules.
	existing, err := m.listLocalFcontextRules()
	if err != nil {
		return false, fmt.Errorf("cannot list local fcontext rules: %w", err)
	}

	ourRuleIdx := -1
	for i, rule := range existing {
		if rule.pattern == pattern {
			ourRuleIdx = i
			break
		}
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
			if err := m.restoreconRecursive(root); err != nil {
				return false, fmt.Errorf("restorecon failed for existing mapping %s: %w", root, err)
			}
			if err := m.verifyActualType(root); err != nil {
				return false, err
			}
			return false, nil
		}
		// Conflicting local rule.
		return false, fmt.Errorf(
			"conflicting SELinux fcontext rule exists for %s: pattern %s maps to %s (expected %s); remove the conflicting rule before proceeding",
			root, existingRule.pattern, existingRule.fileType, selinuxWorkspaceType,
		)
	}

	// Check for overlapping operator-local rules.
	if err := m.checkOverlap(root, pattern, existing); err != nil {
		return false, err
	}

	// No matching rule - add ours.
	if err := m.addFcontextRule(pattern, selinuxWorkspaceType); err != nil {
		return false, fmt.Errorf("cannot add fcontext rule for %s: %w", root, err)
	}

	// Apply restorecon recursively.
	if err := m.restoreconRecursive(root); err != nil {
		// Internal rollback: manager cannot complete its transition.
		if rbErr := m.rollbackWorkspaceLabel(root); rbErr != nil {
			return false, fmt.Errorf("restorecon failed: %v; rollback also failed: %v", err, rbErr)
		}
		return false, fmt.Errorf("restorecon failed for %s: %w", root, err)
	}

	// Verify the actual on-disk type.
	if err := m.verifyActualType(root); err != nil {
		// Internal rollback.
		if rbErr := m.rollbackWorkspaceLabel(root); rbErr != nil {
			return false, fmt.Errorf("verification failed: %v; rollback also failed: %v", err, rbErr)
		}
		return false, err
	}

	return true, nil
}

// checkOverlap checks for overlapping operator-local rules that would conflict
// with our new mapping.
//
// Contract:
// - exact generated ROOT(/.*)? -> docker_helper_workspace_t: idempotent (handled before this call);
// - exact generated pattern -> another type: fail closed (handled before this call);
// - operator-local customization definitely inside ROOT: fail closed;
// - operator-local customization whose target is an ancestor of ROOT: fail closed;
// - unrelated sibling roots: allowed;
// - if an arbitrary regex/equivalence cannot be proven disjoint safely: fail closed.
func (m *selinuxWorkspaceManager) checkOverlap(root string, ourPattern string, existing []fcontextRule) error {
	ourStem := root // the literal unescaped root
	ourEscapedStem := escapeFcontextPath(root)

	for _, rule := range existing {
		if rule.pattern == ourPattern {
			continue // exact match handled elsewhere
		}

		// Equivalence records: fail closed.
		if rule.isEquivalence {
			return fmt.Errorf(
				"unclassifiable SELinux fcontext equivalence record %s may overlap with %s; remove or classify it before proceeding",
				rule.pattern, ourPattern,
			)
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

		// Check if the rule stem contains any regex metacharacters.
		// A literal stem should not contain these after unescaping.
		if containsRegexMeta(ruleStem) {
			return fmt.Errorf(
				"unclassifiable SELinux fcontext pattern %s (contains regex metacharacters) may overlap with %s; remove or classify it before proceeding",
				rule.pattern, ourPattern,
			)
		}

		// Rule stem is a descendant of our root: our broad rule would override it.
		// Must be a proper descendant (not just a prefix match like /data vs /data2).
		if ruleStem != ourStem && isDescendantOf(ruleStem, ourEscapedStem) {
			return fmt.Errorf(
				"operator-local fcontext rule %s (stem %s) would be overridden by %s; remove the local rule before proceeding",
				rule.pattern, ruleStem, ourPattern,
			)
		}

		// Rule stem is an ancestor of our root: its semantics would be overridden.
		if ourStem != ruleStem && isDescendantOf(ourEscapedStem, escapeFcontextPath(ruleStem)) {
			return fmt.Errorf(
				"operator-local fcontext rule %s (stem %s) is an ancestor of %s; removing it would change operator policy",
				rule.pattern, ruleStem, ourPattern,
			)
		}
	}
	return nil
}

// isDescendantOf returns true if child is a proper descendant of parent.
// parent must be the escaped form of the parent path.
// child must be the escaped form of the child path (or the literal path
// if it contains no regex metacharacters).
// This correctly handles /data vs /data2: /data2 is NOT a descendant of /data.
func isDescendantOf(child, parent string) bool {
	if !strings.HasPrefix(child, parent) {
		return false
	}
	// Must be a proper descendant: the character after the parent prefix
	// must be '/' (or the child equals the parent, but we handle equality separately).
	if len(child) == len(parent) {
		return false
	}
	return child[len(parent)] == '/'
}

// containsRegexMeta returns true if the string contains regex metacharacters
// that would indicate it is not a simple literal path.
func containsRegexMeta(s string) bool {
	for _, c := range s {
		switch c {
		case '\\', '^', '$', '*', '+', '?', '(', ')', '[', ']', '{', '}', '|':
			return true
		}
	}
	return false
}

// verifyActualType reads the actual on-disk SELinux type for the root and
// verifies it matches docker_helper_workspace_t.
func (m *selinuxWorkspaceManager) verifyActualType(root string) error {
	actualType, err := m.readPathCon(root)
	if err != nil {
		return fmt.Errorf("cannot verify SELinux type for %s: %w", root, err)
	}
	if actualType != selinuxWorkspaceType {
		return fmt.Errorf(
			"SELinux type for %s is %s, expected %s after restorecon",
			root, actualType, selinuxWorkspaceType,
		)
	}
	return nil
}

// verifyWorkspaceLabel checks that the canonical root has the expected
// SELinux type. It does NOT mutate any state. Used during daemon startup
// and reload to fail closed if a manually edited config bypasses the
// managed-label invariant.
func (m *selinuxWorkspaceManager) verifyWorkspaceLabel(root string) error {
	active, enforcing, err := m.selinuxActive()
	if err != nil {
		return fmt.Errorf("cannot determine SELinux status: %w", err)
	}
	if !active || !enforcing {
		return nil
	}

	if isHomeRoot(root) {
		return nil
	}

	actualType, err := m.readPathCon(root)
	if err != nil {
		return fmt.Errorf(
			"cannot read SELinux type for allowed_root %s: %v; "+
				"ensure the root is prepared via docker-helper init or config set",
			root, err,
		)
	}
	if actualType != selinuxWorkspaceType {
		return fmt.Errorf(
			"allowed_root %s has SELinux type %s, expected %s; "+
				"prepare the root via docker-helper init or config set allowed_root",
			root, actualType, selinuxWorkspaceType,
		)
	}
	return nil
}

// rollbackWorkspaceLabel removes a newly-created fcontext rule and runs
// restorecon to revert labels. Only called internally when the manager
// itself cannot complete its transition before returning success.
//
// Outer callers (init, config set) MUST NOT call this on a mapping that
// was previously returned as successful. Once ensureWorkspaceLabel returns
// success, the mapping is managed durable state.
func (m *selinuxWorkspaceManager) rollbackWorkspaceLabel(root string) error {
	pattern := fcontextPattern(root)

	// First remove the fcontext rule.
	if err := m.removeFcontextRule(pattern); err != nil {
		return fmt.Errorf("cannot remove fcontext rule for %s: %w", root, err)
	}

	// Then restore labels to policy defaults.
	if err := m.restoreconRecursive(root); err != nil {
		return fmt.Errorf("restorecon rollback for %s after rule removal: %w", root, err)
	}

	return nil
}

// fcontextRule represents a parsed semanage fcontext rule.
type fcontextRule struct {
	pattern       string
	fileType      string
	isEquivalence bool
}

// listLocalFcontextRules returns local custom fcontext rules.
// Uses -C -n to inspect only local customizations, not base policy.
//
// Fails closed on any non-empty line that cannot be classified safely.
func (m *selinuxWorkspaceManager) listLocalFcontextRules() ([]fcontextRule, error) {
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
// - Equivalence records: PATTERN  <<None>>
// - Lines that cannot be classified return (fcontextRule{}, false).
func parseFcontextLine(line string) (fcontextRule, bool) {
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

func (m *selinuxWorkspaceManager) addFcontextRule(pattern, fileType string) error {
	// semanage fcontext -a -t TYPE PATTERN
	out, err := m.runCommand(m.semanagePath, "fcontext", "-a", "-t", fileType, pattern)
	if err != nil {
		return fmt.Errorf("semanage fcontext -a: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (m *selinuxWorkspaceManager) removeFcontextRule(pattern string) error {
	// semanage fcontext -d PATTERN
	out, err := m.runCommand(m.semanagePath, "fcontext", "-d", pattern)
	if err != nil {
		return fmt.Errorf("semanage fcontext -d: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (m *selinuxWorkspaceManager) restoreconRecursive(root string) error {
	// Type-only restorecon: do not forcibly reset user, role, or MLS/MCS range.
	out, err := m.runCommand(m.restoreconPath, "-R", root)
	if err != nil {
		return fmt.Errorf("restorecon -R: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
