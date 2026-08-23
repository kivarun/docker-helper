package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"path/filepath"
)

// workspaceRootCommand is the top-level command for workspace root management.
// This is the common user-facing workflow that handles both authorization
// and MAC preparation.
var workspaceRootCommand = &Command{
	Name:    "workspace-root",
	Summary: "Manage workspace roots",
	Subcommands: []*Command{
		workspaceRootAddCommand,
	},
}

// workspaceRootAddCommand adds a workspace root with MAC preparation.
var workspaceRootAddCommand = &Command{
	Name:       "add",
	Summary:    "Add a workspace root",
	Usage:      "docker-helper workspace-root add PATH",
	MinPosArgs: 1,
	MaxPosArgs: 1,
	Help: `Add a workspace root.

This is the normal post-init command for adding a usable workspace root.
It performs:

  1. Canonicalize and validate PATH
  2. Prepare required MAC state for the active backend
  3. Add PATH to global allowed_roots
  4. Reload the running daemon

In user mode, only the authorization step (3) is performed.

In system mode with AppArmor, the root is added to the managed AppArmor
policy before the authorization change.

In system mode with SELinux:
  - /home and its descendants use existing user_home_type labels
  - Non-home roots get persistent fcontext + restorecon preparation
  - Exact /opt is rejected (use a subdirectory or config allowed-root add)

MAC preparation happens before the config write. If preparation fails,
authorization is not widened.`,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				args := fs.Args()
				return workspaceRootAdd(args[0], stdout, stderr)
			},
		}
	},
}

// workspaceRootAdd adds a workspace root with MAC preparation.
func workspaceRootAdd(path string, stdout, stderr io.Writer) int {
	if path == "" {
		fmt.Fprintln(stderr, "error: path is required")
		return 2
	}
	if !filepath.IsAbs(path) {
		fmt.Fprintln(stderr, "error: path must be absolute")
		return 2
	}

	canonical, err := canonicalizeWorkspaceRootForAdd(path)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}

	// Prepare MAC state before authorization change.
	if err := prepareWorkspaceRootMAC(canonical, stderr); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	// Add to authorization using the shared config mutation path.
	return addAllowedRootToConfig(canonical, stdout, stderr)
}

// prepareWorkspaceRootMAC performs backend-specific MAC preparation for a
// workspace root. This is the shared helper used by workspace-root add and init.
//
// In user mode: no-op.
// In AppArmor system mode: adds root to managed AppArmor policy.
// In SELinux system mode: prepares managed label for non-home roots;
// rejects exact /opt (common workflow safety).
func prepareWorkspaceRootMAC(canonical string, stderr io.Writer) error {
	if resolveDeploymentMode() != ModeSystem {
		return nil
	}

	backend, err := detectLSM()
	if err != nil {
		return fmt.Errorf("cannot determine MAC backend: %w", err)
	}

	switch backend {
	case LSMAppArmor:
		mgr := newProductionApparmorManager()
		result, err := mgr.addRoot(canonical)
		if err != nil {
			return err
		}
		if result.Changed {
			fmt.Fprintf(stderr, "AppArmor workspace root added: %s\n", canonical)
		} else {
			fmt.Fprintf(stderr, "AppArmor workspace root already present: %s\n", canonical)
		}
		return nil

	case LSMSelinux:
		// Exact /opt is rejected for the common workflow to prevent
		// recursive relabel of the standard namespace.
		if canonical == "/opt" {
			return fmt.Errorf("exact /opt cannot be a managed workspace root in SELinux mode; use a subdirectory such as /opt/docker-helper-workspaces, or use 'docker-helper config allowed-root add /opt' to set it as an authorization ceiling without MAC preparation")
		}
		// /home and descendants use existing user_home_type labels.
		if isHomeRoot(canonical) {
			return nil
		}
		selMgr := newSELinuxWorkspaceManager()
		changed, err := selMgr.ensureWorkspaceLabel(canonical)
		if err != nil {
			return err
		}
		if changed {
			fmt.Fprintf(stderr, "SELinux workspace label prepared: %s\n", canonical)
		} else {
			fmt.Fprintf(stderr, "SELinux workspace label already present: %s\n", canonical)
		}
		return nil

	default:
		return nil
	}
}

// addAllowedRootToConfig adds a root to allowed_roots using the shared
// config transaction owner. This is the authorization-only mutation path
// shared by config allowed-root add and workspace-root add.
func addAllowedRootToConfig(canonical string, stdout, stderr io.Writer) int {
	return executeConfigTransaction(stdout, stderr, safeWriteConfig, func(raw map[string]json.RawMessage, migrated bool) (configMutationResult, error) {
		fc, err := decodeFileConfig(raw)
		if err != nil {
			return configMutationResult{}, err
		}

		// Validate existing roots with full canonicalization (strict resolver).
		existingRoots, err := resolveAllowedRoots(raw, fc)
		if err != nil {
			return configMutationResult{}, err
		}

		// Check if already present.
		present := false
		for _, r := range existingRoots {
			if r == canonical {
				present = true
				break
			}
		}

		if present {
			if !migrated {
				return configMutationResult{
					SkipWrite: true,
					Message:   fmt.Sprintf("already present %s\n", canonical),
				}, nil
			}
			// Legacy migration needed: write migrated config.
			return configMutationResult{
				Message: fmt.Sprintf("already present %s (legacy schema migrated)\n", canonical),
			}, nil
		}

		// Add new root to canonical roots list.
		rawBytes, _ := json.Marshal(append(existingRoots, canonical))
		raw["allowed_roots"] = rawBytes

		return configMutationResult{
			Message: fmt.Sprintf("added %s\n", canonical),
		}, nil
	})
}
