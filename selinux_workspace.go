package main

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

const (
	selinuxWorkspaceType = "docker_helper_workspace_t"
	semanagePath         = "/usr/sbin/semanage"
	restoreconPath       = "/usr/sbin/restorecon"
	matchpathconPath     = "/usr/bin/matchpathcon"
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
// Test seams: runCommand, readPathCon, and selinuxEnabled are package-level
// vars that can be replaced in tests.
type selinuxWorkspaceManager struct {
	semanagePath     string
	restoreconPath   string
	matchpathconPath string
	runCommand       func(string, ...string) ([]byte, error)
	readPathCon      func(string) (string, error)
	selinuxActive    func() (bool, bool, error) // (active, enforcing, error)
}

func newSELinuxWorkspaceManager() *selinuxWorkspaceManager {
	return &selinuxWorkspaceManager{
		semanagePath:     semanagePath,
		restoreconPath:   restoreconPath,
		matchpathconPath: matchpathconPath,
		runCommand: func(cmd string, args ...string) ([]byte, error) {
			c := exec.Command(cmd, args...)
			out, err := c.CombinedOutput()
			return out, err
		},
		readPathCon: func(path string) (string, error) {
			return readPathSELinuxType(path)
		},
		selinuxActive: selinuxEnabled,
	}
}

// readPathSELinuxType returns the SELinux type component of the given path's
// current label. Uses stat(2) to get the raw context, then parses the type.
func readPathSELinuxType(path string) (string, error) {
	// Use matchpathcon to get the expected context, then parse the type.
	// This avoids needing root to read the actual label on arbitrary paths.
	out, err := exec.Command(matchpathconPath, path).CombinedOutput()
	if err != nil {
		// Fallback: try stat -c %C (requires root)
		out2, err2 := exec.Command("stat", "-c", "%C", path).CombinedOutput()
		if err2 != nil {
			return "", fmt.Errorf("cannot read SELinux context for %s: matchpathcon: %v; stat: %v (%s)", path, err, err2, strings.TrimSpace(string(out2)))
		}
		ctx := strings.TrimSpace(string(out2))
		return parseSELinuxType(ctx)
	}
	// matchpathcon output format: "context  (match type)"
	line := strings.TrimSpace(string(out))
	if idx := strings.Index(line, " "); idx > 0 {
		ctx := line[:idx]
		return parseSELinuxType(ctx)
	}
	return "", fmt.Errorf("unexpected matchpathcon output for %s: %s", path, line)
}

// escapeFcontextPath escapes a filesystem path for use in a semanage fcontext
// regex. It escapes regex metacharacters but preserves the path structure.
// The caller appends the descendant pattern (e.g., "(/.*)?").
func escapeFcontextPath(path string) string {
	// semanage fcontext uses regex syntax. Escape all regex metacharacters.
	// The path is already canonicalized (absolute, clean, no symlinks).
	escaped := regexp.QuoteMeta(path)
	return escaped
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
//  1. Checks for existing matching fcontext rules;
//  2. If no matching rule exists, adds one;
//  3. If an existing rule maps to a different type, fails closed;
//  4. Runs restorecon recursively;
//  5. Verifies the resulting type.
//
// Returns whether a new mapping was created (true) or already existed (false).
// If it returns (true, nil), the caller must roll back on subsequent failure.
func (m *selinuxWorkspaceManager) ensureWorkspaceLabel(root string) (newlyCreated bool, err error) {
	active, enforcing, err := m.selinuxActive()
	if err != nil {
		return false, fmt.Errorf("cannot determine SELinux status: %w", err)
	}
	if !active || !enforcing {
		// SELinux not enforcing: nothing to do.
		return false, nil
	}

	pattern := fcontextPattern(root)

	// Check existing rules.
	existing, err := m.listFcontextRules(root)
	if err != nil {
		return false, fmt.Errorf("cannot list existing fcontext rules: %w", err)
	}

	for _, rule := range existing {
		if rule.pattern == pattern {
			if rule.fileType == selinuxWorkspaceType {
				// Exact match already exists — idempotent.
				return false, nil
			}
			// Conflicting local rule.
			return false, fmt.Errorf(
				"conflicting SELinux fcontext rule exists for %s: pattern %s maps to %s (expected %s); remove the conflicting rule before proceeding",
				root, rule.pattern, rule.fileType, selinuxWorkspaceType,
			)
		}
	}

	// No matching rule — add ours.
	if err := m.addFcontextRule(pattern, selinuxWorkspaceType); err != nil {
		return false, fmt.Errorf("cannot add fcontext rule for %s: %w", root, err)
	}

	// Apply restorecon recursively.
	if err := m.restoreconRecursive(root); err != nil {
		// Rollback: remove the rule we just added.
		if rbErr := m.removeFcontextRule(pattern); rbErr != nil {
			return false, fmt.Errorf("restorecon failed: %v; rollback also failed: %v", err, rbErr)
		}
		return false, fmt.Errorf("restorecon failed for %s: %w", root, err)
	}

	// Verify the resulting type.
	actualType, err := m.readPathCon(root)
	if err != nil {
		// Rollback.
		if rbErr := m.removeFcontextRule(pattern); rbErr != nil {
			return false, fmt.Errorf("verification failed: %v; rollback also failed: %v; restorecon also failed: %v", err, rbErr, err)
		}
		return false, fmt.Errorf("cannot verify SELinux type for %s: %w", root, err)
	}
	if actualType != selinuxWorkspaceType {
		// Rollback.
		if rbErr := m.removeFcontextRule(pattern); rbErr != nil {
			return false, fmt.Errorf("type mismatch (got %s): rollback also failed: %v", actualType, rbErr)
		}
		return false, fmt.Errorf(
			"SELinux type for %s is %s, expected %s after restorecon",
			root, actualType, selinuxWorkspaceType,
		)
	}

	return true, nil
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
	if err := m.removeFcontextRule(pattern); err != nil {
		return fmt.Errorf("cannot remove fcontext rule for %s: %w", root, err)
	}
	// Restorecon to revert labels to the policy default.
	if err := m.restoreconRecursive(root); err != nil {
		return fmt.Errorf("restorecon rollback for %s: %w", root, err)
	}
	return nil
}

// fcontextRule represents a parsed semanage fcontext rule.
type fcontextRule struct {
	pattern  string
	fileType string
}

// listFcontextRules returns rules that match the given root path.
func (m *selinuxWorkspaceManager) listFcontextRules(root string) ([]fcontextRule, error) {
	out, err := m.runCommand(m.semanagePath, "fcontext", "-l")
	if err != nil {
		return nil, fmt.Errorf("semanage fcontext -l: %w: %s", err, strings.TrimSpace(string(out)))
	}

	var rules []fcontextRule
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Parse the line to find rules matching our root.
		// Format: <path_regex>  gen_context(system_u:object_r:<type>:s0)
		rule, matched := parseFcontextLine(line, root)
		if matched {
			rules = append(rules, rule)
		}
	}
	return rules, nil
}

// parseFcontextLine parses a single line from semanage fcontext -l output.
// Returns the rule and whether it matches the given root path.
func parseFcontextLine(line string, root string) (fcontextRule, bool) {
	// Format: <path_regex>  gen_context(system_u:object_r:<type>:s0)
	// or:     <path_regex>  system_u:object_r:<type>:s0
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return fcontextRule{}, false
	}

	pattern := parts[0]
	ctx := parts[len(parts)-1]

	// Extract type from context
	var typ string
	if idx := strings.Index(ctx, "object_r:"); idx >= 0 {
		rest := ctx[idx+len("object_r:"):]
		if colon := strings.Index(rest, ":"); colon >= 0 {
			typ = rest[:colon]
		} else {
			typ = rest
		}
	}

	// Check if this pattern matches our root.
	// The pattern is a regex like "/data(/.*)?" or "/data"
	// We need to check if the pattern, when applied, would match our root.
	// For exact matching, we compare the escaped prefix.
	escapedRoot := escapeFcontextPath(root)
	if strings.HasPrefix(pattern, escapedRoot) {
		return fcontextRule{pattern: pattern, fileType: typ}, true
	}
	return fcontextRule{}, false
}

func (m *selinuxWorkspaceManager) addFcontextRule(pattern, fileType string) error {
	_, err := m.runCommand(m.semanagePath, "fcontext", "-a", "-t", fileType, "-s", "targeted", pattern)
	if err != nil {
		return fmt.Errorf("semanage fcontext -a: %w", err)
	}
	return nil
}

func (m *selinuxWorkspaceManager) removeFcontextRule(pattern string) error {
	_, err := m.runCommand(m.semanagePath, "fcontext", "-d", "-s", "targeted", pattern)
	if err != nil {
		return fmt.Errorf("semanage fcontext -d: %w", err)
	}
	return nil
}

func (m *selinuxWorkspaceManager) restoreconRecursive(root string) error {
	_, err := m.runCommand(m.restoreconPath, "-R", "-F", root)
	if err != nil {
		return fmt.Errorf("restorecon -R -F: %w", err)
	}
	return nil
}
