package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

// admittedPathDiagnosis is the shared diagnosis of a failed host-path
// resolution or post-resolution stat of an ADMITTED caller spelling: the
// authorization-before-probing boundary has already admitted the spelling
// lexically, so the privileged probe ran and its failure carries a
// classifiable cause. Session-facing path boundaries (Session workspace
// admission and issuance-time filesystem-root canonicalization) classify
// these failures through this one owner so the caller-facing meaning is
// stable and non-disclosing: the probe's incidental errno and any probed or
// resolved pathname stay in the operational diagnostic, never in the public
// message. It deliberately does not cover unadmitted spellings — those are
// refused before any probe and carry no filesystem detail at all.
type admittedPathDiagnosis int

const (
	// admittedPathDoesNotExist: the requested path does not exist (ENOENT).
	// The spelling was admitted, so the caller already knows the pathname;
	// the actionable public cause is the missing path itself.
	admittedPathDoesNotExist admittedPathDiagnosis = iota
	// admittedPathDenied: the daemon may not resolve or consume the
	// pathname (EACCES). Fail-closed: containment/authority cannot be
	// proven, and on the confined backends this is how a spelling that
	// resolves across the authorized boundary presents.
	admittedPathDenied
	// admittedPathUnresolvable: any other resolution failure (ELOOP,
	// EIO, ...): a genuine canonicalization/access failure of the admitted
	// spelling, not an authority decision.
	admittedPathUnresolvable
)

// diagnoseAdmittedPath classifies one failed privileged probe
// (evalSymlinksFn/osStatFn) of an admitted caller spelling. The probe error
// may name a resolved symlink target for a denied probe, so only the
// diagnosis — never the error text — reaches a public boundary.
func diagnoseAdmittedPath(probeErr error) admittedPathDiagnosis {
	switch {
	case errors.Is(probeErr, fs.ErrNotExist):
		return admittedPathDoesNotExist
	case errors.Is(probeErr, fs.ErrPermission):
		return admittedPathDenied
	default:
		return admittedPathUnresolvable
	}
}

// validateHostPathText is the shared host capability path text-grammar check.
// A host capability path must not contain control characters that
// can desynchronize line-oriented tool output (persistent SELinux fcontext
// records, AppArmor fragments, and config serialization are line-oriented
// artifacts the path text feeds) or be unrepresentable as a host pathname.
//
// The rule is Unicode-control based: every rune with unicode.IsControl — the
// C0 controls (including LF, CR, TAB), the C1 controls, and DEL — is outside
// the Release 2.2 host-path capability text grammar. Embedded NUL is rejected
// explicitly for a clearer diagnostic: Unix path syscalls cannot represent an
// embedded NUL at all. Ordinary printable characters, including ASCII space
// inside a component, remain supported.
//
// This is the ONE owner of that invariant. Backends (SELinux fcontext,
// AppArmor fragments), handlers, and the CLI must not duplicate a
// control-character list: they consume canonical paths this grammar has
// already been applied to. escapeFcontextPath remains regex escaping, not a
// second validator.
func validateHostPathText(path string) error {
	if strings.ContainsRune(path, 0) {
		return fmt.Errorf("host path contains NUL; a host pathname cannot represent an embedded NUL")
	}
	for _, c := range path {
		if unicode.IsControl(c) {
			return fmt.Errorf("host path contains control character %q; control characters are outside the supported host-path text grammar", c)
		}
	}
	return nil
}

// forbiddenSystemTrees are absolute paths that workspace paths must never
// equal or descend from. These are system directories that contain
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
}

// forbiddenWideNamespaces are top-level namespaces that are too broad to be
// workspace paths themselves, while subdirectories are allowed.
var forbiddenWideNamespaces = []string{
	"/home",
	"/opt",
	"/srv",
	"/mnt",
	"/media",
	"/tmp",
}

// adminWideNamespaceOverrides are namespaces that root (uid 0) may use
// as workspace paths despite the normal wide-namespace restriction. Non-root users are still blocked.
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

// validateWorkspacePathSafety validates a canonical host path against the shared
// workspace-path policy. It applies the shared text grammar first (a canonical
// path containing a control character is refused, including a harmless-looking
// caller spelling that resolved into one through symlinks), then rejects the
// filesystem root, forbidden system trees, and forbidden wide namespaces (the
// namespace itself is too broad to be a workspace path, while subdirectories
// are allowed). When running as root, /home and /opt are permitted via the
// admin override.
func validateWorkspacePathSafety(canonical string) error {
	if err := validateHostPathText(canonical); err != nil {
		return err
	}
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

// canonicalizeWorkspacePathForAdd validates and canonicalizes a workspace path for addition.
// It:
//   - applies the shared host-path text grammar to the caller spelling before
//     any filesystem probing (the canonicalization owner owns caller syntax;
//     the text check is pure, so an unsupported spelling is refused without
//     stat/EvalSymlinks)
//   - expands ~ to the user's home directory
//   - resolves to an absolute path
//   - verifies the path exists and is a directory (authorization ceilings
//     are directory trees; an issued Session filesystem root may also be a
//     regular file and is validated by its own canonical tree-kind owner)
//   - resolves all symlinks
//   - applies the workspace-path policy, which re-checks the text grammar on
//     the resolved canonical path
//
// Returns the canonical path on success.
func canonicalizeWorkspacePathForAdd(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("workspace root must be a non-empty path")
	}
	if err := validateHostPathText(path); err != nil {
		return "", err
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

	if err := validateWorkspacePathSafety(canonical); err != nil {
		return "", err
	}

	return canonical, nil
}

// canonicalizeIssuedTreePathForAdd is the canonicalization owner for an
// issued Session filesystem tree handed to a MAC backend (a managed
// boundary candidate). It receives an already canonical concrete path: the
// Session lifecycle owns caller syntax (absolute path, symlink resolution,
// dir/regular-file kind), so no MAC backend reinterprets "~", relative
// syntax, or another caller grammar. The validation applies the shared
// host-path text grammar to the concrete identity, then proves it (exists,
// directory or regular file, symlink-resolved) and applies the
// workspace-path safety policy, which re-checks the text grammar on the
// resolved canonical path.
func canonicalizeIssuedTreePathForAdd(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("issued tree must be a non-empty path")
	}
	if err := validateHostPathText(path); err != nil {
		return "", err
	}

	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("issued tree %q is not an absolute host path", path)
	}

	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("issued tree does not exist: %s", path)
		}
		return "", fmt.Errorf("cannot stat issued tree: %w", err)
	}

	if !info.IsDir() && !info.Mode().IsRegular() {
		return "", fmt.Errorf("issued tree is not a directory or regular file: %s", path)
	}

	canonical, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("cannot resolve issued tree symlinks: %w", err)
	}

	if err := validateWorkspacePathSafety(canonical); err != nil {
		return "", err
	}

	return canonical, nil
}

// validateWorkspacePathPolicy checks a canonical path against the workspace-path
// policy without filesystem access. It applies the shared host-path text
// grammar first, then the absolute and safety checks. This is the pure policy
// check that can be tested deterministically.
func validateWorkspacePathPolicy(canonical string) error {
	if canonical == "" {
		return fmt.Errorf("workspace root must be a non-empty path")
	}
	if err := validateHostPathText(canonical); err != nil {
		return err
	}
	if !filepath.IsAbs(canonical) {
		return fmt.Errorf("workspace root must be an absolute path: %s", canonical)
	}
	return validateWorkspacePathSafety(canonical)
}
