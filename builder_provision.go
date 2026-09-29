package main

// builder_provision.go owns the manager-side categorized provisioning of
// the per-op trees (G32 r3 §4.2). Under enforcing SELinux, each required
// top-level per-op path receives its exact FULL object context — fixed
// identity/role, the expected type for the path, and the operation's
// category from the authoritative instance record — with a mandatory
// read-back verification, before any launch step. Any failure is a failed
// START before the process spawn, converged by the existing failed-start
// owner. Non-SELinux backends keep the existing unlabeled mkdir
// semantics; there is no fallback to bare s0, no partial categorized
// tree, and no relabel of descendants (children inherit the creating
// process's or the parent's context). The launcher's process target
// context is a different composition and lives with the launcher.

import (
	"path/filepath"

	"golang.org/x/sys/unix"
)

// The per-op object types of the provisioning matrix. The spellings are
// the SELinux policy's type names (docker-helper 1.2); the category comes
// only from the record.
const (
	builderStateObjectType   = "docker_helper_builder_state_t"
	builderRuntimeObjectType = "docker_helper_builder_runtime_t"
)

// builderProvisionedPath is one required top-level provisioning entry.
type builderProvisionedPath struct {
	rel        string // label for diagnostics, relative to the op roots
	path       string
	objectType string
}

// builderProvisionedPaths is the exact provisioning matrix (G32 r3 §4.2):
// the four required top-level per-op paths and their expected types.
// State paths never carry the runtime type and vice versa; the roots and
// the shared ops containers are never relabeled.
func builderProvisionedPaths(opID, rtDir, stDir string) []builderProvisionedPath {
	return []builderProvisionedPath{
		{rel: "state", path: stDir, objectType: builderStateObjectType},
		{rel: "state/rootlesskit-state", path: filepath.Join(stDir, "rootlesskit-state"), objectType: builderStateObjectType},
		{rel: "state/root", path: filepath.Join(stDir, "root"), objectType: builderStateObjectType},
		{rel: "runtime", path: rtDir, objectType: builderRuntimeObjectType},
	}
}

// builderObjectContext builds the exact SELinux object context for one
// provisioned path: the fixed user/role, the expected type, and the
// operation's category from the authoritative record. It never accepts a
// free-form context string and never parses an existing label back into
// authority.
func builderObjectContext(objectType string, category builderCategory) string {
	return "system_u:object_r:" + objectType + ":s0:" + category.String()
}

// builderSetObjectXattr is the injectable seam around the security.selinux
// xattr write (production: unix.Setxattr on the path).
var builderSetObjectXattr = func(path, value string) error {
	return unix.Setxattr(path, "security.selinux", []byte(value), 0)
}

// builderObjectContextReadCeiling bounds the read-back: a context larger
// than this is a failure, never a silent truncation (real SELinux
// contexts are far shorter).
const builderObjectContextReadCeiling = 256

// builderGetRawObjectXattr is the injectable seam around the raw
// security.selinux xattr read-back (production: unix.Getxattr on the path,
// bounded by builderObjectContextReadCeiling — an oversized context is the
// xattr error, never a partial value).
var builderGetRawObjectXattr = func(path string) ([]byte, error) {
	buf := make([]byte, builderObjectContextReadCeiling)
	n, err := unix.Getxattr(path, "security.selinux", buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// builderGetObjectXattr reads the path's security.selinux xattr and returns
// its canonical textual context through the shared xattr decoder: the
// kernel's one-terminal-NUL convention and the no-NUL form are the same
// canonical value, and any other encoding is a read failure that fails the
// provisioning closed.
func builderGetObjectXattr(path string) (string, error) {
	raw, err := builderGetRawObjectXattr(path)
	if err != nil {
		return "", err
	}
	return decodeSELinuxXattrContext(raw)
}

// builderProvisionGate reports whether the active MAC backend requires
// categorized provisioning. Only enforcing SELinux provisions (G32 r3
// §4.2: the permissive composition keeps the existing product contract;
// AppArmor and no-backend keep the unlabeled mkdir semantics). A
// detection error fails closed: an indeterminable backend must not
// downgrade the launch to an unlabeled one.
func builderProvisionGate() (bool, error) {
	backend, err := detectLSM()
	if err != nil {
		return false, err
	}
	return backend == LSMSELinux, nil
}

// provisionCategoryContexts assigns and verifies the exact context of
// every required top-level per-op path, in the fixed matrix order:
// setxattr, then a mandatory read-back with exact byte/string equality —
// an unverified setxattr is never sufficient, and a relabel that keeps a
// random type is never acceptable (the full context is written). Any set
// error, read error, or mismatch returns false; the caller converges the
// failed START through the existing owner. The category is read from the
// authoritative record only.
func (m *builderManager) provisionCategoryContexts(inst *builderInstance, opID, rtDir, stDir string) bool {
	category := inst.category
	for _, p := range builderProvisionedPaths(opID, rtDir, stDir) {
		want := builderObjectContext(p.objectType, category)
		if err := builderSetObjectXattr(p.path, want); err != nil {
			m.managerDiagf("START %s: cannot assign context to %s: %v", opID, p.rel, err)
			return false
		}
		got, err := builderGetObjectXattr(p.path)
		if err != nil {
			m.managerDiagf("START %s: cannot verify context of %s: %v", opID, p.rel, err)
			return false
		}
		if got != want {
			m.managerDiagf("START %s: context mismatch on %s: got %q want %q", opID, p.rel, got, want)
			return false
		}
	}
	return true
}
