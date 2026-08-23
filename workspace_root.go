package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// forbiddenSystemTrees are absolute paths that must never be workspace roots
// or ancestors of workspace roots. These are system directories that contain
// critical OS state, binaries, or configuration.
var forbiddenSystemTrees = []string{
	"/bin",
	"/boot",
	"/dev",
	"/etc",
	"/lib",
	"/lib32",
	"/lib64",
	"/libx32",
	"/proc",
	"/root",
	"/run",
	"/sbin",
	"/sys",
	"/usr",
	"/var",
	"/tmp",
}

// forbiddenWideNamespaces are top-level directories that are too broad to be
// workspace roots themselves, but their subdirectories are allowed.
var forbiddenWideNamespaces = []string{
	"/home",
	"/opt",
	"/srv",
	"/mnt",
	"/media",
}

// adminWideNamespaceOverrides are wide namespaces that root (uid 0) may use
// as workspace roots. Non-root users are still blocked.
var adminWideNamespaceOverrides = []string{
	"/home",
	"/opt",
}

func isAdminWideNamespaceOverride(ns string) bool {
	for _, allowed := range adminWideNamespaceOverrides {
		if ns == allowed {
			return true
		}
	}
	return false
}

// isForbiddenWorkspaceRoot returns true if the canonical path is a forbidden
// system tree or a forbidden wide namespace. It does NOT reject subdirectories
// of wide namespaces (e.g., /home/user is allowed, /home is not).
// It DOES reject system trees and everything under them (e.g., /var/lib/foo is
// rejected because /var is a system tree).
// When running as root (uid 0), /home and /opt are permitted as workspace roots.
func isForbiddenWorkspaceRoot(canonical string) error {
	if canonical == "/" {
		return fmt.Errorf("workspace root cannot be the filesystem root /")
	}

	// Check against forbidden system trees: reject the tree itself and anything
	// under it.
	for _, tree := range forbiddenSystemTrees {
		if canonical == tree {
			return fmt.Errorf("workspace root %s is a forbidden system directory", tree)
		}
		// Reject anything under a system tree.
		if strings.HasPrefix(canonical, tree+"/") {
			return fmt.Errorf("workspace root %s is under forbidden system directory %s", canonical, tree)
		}
	}

	// Check against forbidden wide namespaces: reject only the namespace itself,
	// not its subdirectories. Root (uid 0) is exempt for admin-approved namespaces.
	for _, ns := range forbiddenWideNamespaces {
		if canonical == ns {
			if EffectiveUID() == 0 && isAdminWideNamespaceOverride(ns) {
				continue
			}
			return fmt.Errorf("workspace root %s is too broad; use a subdirectory such as %s/<user-or-project>", ns, ns)
		}
	}

	return nil
}

// canonicalizeWorkspaceRootForAdd validates and canonicalizes a workspace root
// path for addition. It:
//   - expands ~ to the user's home directory
//   - resolves to an absolute path
//   - verifies the path exists and is a directory
//   - resolves all symlinks
//   - applies the workspace root security policy
//
// Returns the canonical path on success.
func canonicalizeWorkspaceRootForAdd(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("workspace root must be a non-empty path")
	}

	path = expandTilde(path)

	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("cannot resolve workspace root to absolute path: %w", err)
	}

	info, err := os.Stat(abs)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("workspace root does not exist: %s", abs)
		}
		return "", fmt.Errorf("cannot stat workspace root: %w", err)
	}

	if !info.IsDir() {
		return "", fmt.Errorf("workspace root is not a directory: %s", abs)
	}

	canonical, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("cannot resolve workspace root symlinks: %w", err)
	}

	if err := isForbiddenWorkspaceRoot(canonical); err != nil {
		return "", err
	}

	return canonical, nil
}

// selinuxManagedRootAllowed returns true if the given canonical path is
// allowed as a SELinux managed workspace root. Exact /opt is rejected
// because it would make the entire standard namespace a recursive
// managed relabel boundary.
func selinuxManagedRootAllowed(canonical string) bool {
	return canonical != "/opt"
}

// validateWorkspaceRootPolicy checks a canonical path against the workspace root
// security policy without filesystem access. This is the pure policy check that
// can be tested deterministically.
func validateWorkspaceRootPolicy(canonical string) error {
	if canonical == "" {
		return fmt.Errorf("workspace root must be a non-empty path")
	}
	if !filepath.IsAbs(canonical) {
		return fmt.Errorf("workspace root must be an absolute path: %s", canonical)
	}
	return isForbiddenWorkspaceRoot(canonical)
}
