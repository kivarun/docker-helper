package main

import (
	"fmt"
	"os/exec"
	"regexp"
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
func readPathSELinuxType(path string) (string, error) {
	buf := make([]byte, 1024)
	n, err := unix.Lgetxattr(path, "security.selinux", buf)
	if err != nil {
		return "", fmt.Errorf("cannot read SELinux context for %s: %w", path, err)
	}
	return parseSELinuxType(string(buf[:n]))
}

// escapeFcontextPath escapes a filesystem path for use in a semanage fcontext
// regex. It escapes regex metacharacters but preserves the path structure.
// The caller appends the descendant pattern (e.g., "(/.*)?").
func escapeFcontextPath(path string) string {
	// semanage fcontext uses regex syntax. Escape all regex metacharacters.
	// The path is already canonicalized (absolute, clean, no symlinks).
	return regexp.QuoteMeta(path)
}

// fcontextPattern returns the full regex pattern for the fcontext rule.
// It correctly escapes the root and appends the descendant pattern so that
// /data matches /data and /data/foo but NOT /data/foobar as a prefix match.
func fcontextPattern(root string) string {
	escaped := escapeFcontextPath(root)
	return escaped + "(/.*)?"
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
// If it returns (true, nil), the caller must roll back on subsequent failure.
// If it returns (false, nil) for an existing mapping, restorecon and verification
// have already succeeded.
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
		// Existing rule found.
		if existing[ourRuleIdx].fileType == selinuxWorkspaceType {
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
			root, existing[ourRuleIdx].pattern, existing[ourRuleIdx].fileType, selinuxWorkspaceType,
		)
	}

	// Check for nested operator-local rules that our broad rule would override.
	for _, rule := range existing {
		if rule.pattern != pattern && strings.HasPrefix(rule.pattern, escapeFcontextPath(root)) {
			return false, fmt.Errorf(
				"operator-local fcontext rule %s would be overridden by %s; remove the local rule before proceeding",
				rule.pattern, pattern,
			)
		}
	}

	// No matching rule - add ours.
	if err := m.addFcontextRule(pattern, selinuxWorkspaceType); err != nil {
		return false, fmt.Errorf("cannot add fcontext rule for %s: %w", root, err)
	}

	// Apply restorecon recursively.
	if err := m.restoreconRecursive(root); err != nil {
		// Rollback: remove the rule we just added and restore labels.
		if rbErr := m.rollbackWorkspaceLabel(root); rbErr != nil {
			return false, fmt.Errorf("restorecon failed: %v; rollback also failed: %v", err, rbErr)
		}
		return false, fmt.Errorf("restorecon failed for %s: %w", root, err)
	}

	// Verify the actual on-disk type.
	if err := m.verifyActualType(root); err != nil {
		// Rollback.
		if rbErr := m.rollbackWorkspaceLabel(root); rbErr != nil {
			return false, fmt.Errorf("verification failed: %v; rollback also failed: %v", err, rbErr)
		}
		return false, err
	}

	return true, nil
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
// restorecon to revert labels. Only called when the mapping was newly created
// by this invocation.
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
	pattern  string
	fileType string
}

// listLocalFcontextRules returns local custom fcontext rules.
// Uses -C -n to inspect only local customizations, not base policy.
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
		}
	}
	return rules, nil
}

// parseFcontextLine parses a single line from semanage fcontext output.
// Returns the rule and whether it was successfully parsed.
func parseFcontextLine(line string) (fcontextRule, bool) {
	// Format: <path_regex>  gen_context(system_u:object_r:<type>:s0)
	// or:     <path_regex>  system_u:object_r:<type>:s0
	// The pattern and context are separated by multiple spaces.
	// We need to handle paths with spaces, so we can't just use strings.Fields.

	// Find the context part by looking for the gen_context or user:role:type pattern.
	// The pattern is everything before the double-space separator.
	idx := strings.Index(line, "  ")
	if idx < 0 {
		return fcontextRule{}, false
	}

	pattern := strings.TrimSpace(line[:idx])
	ctxPart := strings.TrimSpace(line[idx+2:])

	// Extract type from context
	var typ string
	if idx2 := strings.Index(ctxPart, "object_r:"); idx2 >= 0 {
		rest := ctxPart[idx2+len("object_r:"):]
		if colon := strings.Index(rest, ":"); colon >= 0 {
			typ = rest[:colon]
		} else {
			typ = rest
		}
	}

	if pattern == "" || typ == "" {
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
	out, err := m.runCommand(m.restoreconPath, "-R", "-F", root)
	if err != nil {
		return fmt.Errorf("restorecon -R -F: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
