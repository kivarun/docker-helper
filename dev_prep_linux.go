//go:build linux

package main

// dev_prep_linux.go owns the trusted daemon-side preparation of the
// per-operation /dev tree:
//
//	/var/lib/docker-helper/dev-prep/<op>
//
// (P21-E-A2 .. A2-C5-C1). The prepared tree is the bind source that
// replaces runc's own /dev setup: a bind mount at /dev skips ALL of
// doSetupDev (pinned runc v1.4.3, libcontainer/rootfs_linux.go:88-100 —
// needsSetupDev returns false for a bind at /dev), so the tree must
// carry exactly what doSetupDev would have created:
//
//   - the six standard character devices (specconv AllowedDevices,
//     libcontainer/specconv/spec_linux.go:236-340: null 1:3, zero 1:5,
//     full 1:7, random 1:8, urandom 1:9, tty 5:0, FileMode 0o666,
//     uid/gid 0, no block devices — /dev/ptmx from a spec device list is
//     owned by setupPtmx, not createDevices);
//   - the five fixed symlinks (setupDevSymlinks rootfs_linux.go:914-935:
//     fd → /proc/self/fd, stdin/stdout/stderr → /proc/self/fd/0/1/2;
//     setupPtmx rootfs_linux.go:1139-1145: ptmx → pts/ptmx, a relative
//     target resolved against /dev) plus the CONDITIONAL core symlink →
//     /proc/kcore, created only when /proc/kcore exists on the host
//     (the same existence check runc performs at setup time);
//   - the pts/shm/mqueue mountpoint directories (the devpts/tmpfs mount
//     targets of the container mount table).
//
// The labeling sequence is the accepted C4-C1 chain: the dev-prep
// subtree root is relabeled docker_helper_devprep_t:s0 by the daemon's
// established restorecon mechanism (the trusted-CA precedent:
// execute_no_trans on setfiles_exec_t, driven by the shipped .fc row),
// the operation directory receives its per-operation category through a
// direct security.selinux xattr write (restorecon cannot set per-op
// levels) with a mandatory read-back verification BEFORE any operation
// content is created, and every child inherits
// docker_helper_devprep_t:s0:cX through creation-time defaults.
//
// The builder identity traverses the tree only through known names:
// every directory on the traverse chain (the state root, the dev-prep
// root, and the operation directory) carries the targeted search-only
// access ACL (named user entry x for the builder uid, mask --x), whose
// effective stat mode is 0710 (C4-C1 §1). The verify-and-reapply is
// mandatory: systemd's StateDirectory chmod resets the mask on every
// unit start, so an ineffective-but-present ACL is detected and restored.
//
// Hard properties of this owner:
//
//   - strictly typed inputs: the canonical operation ID grammar
//     (isOperationID) and a valid builderCategory (the single pool);
//     no caller-controlled node names, major/minor values, symlink
//     targets, or arbitrary paths exist;
//   - refuse-to-adopt: an existing operation directory is never adopted
//     or repaired — the preparation fails closed;
//   - strict creation and verification: every creation step fails on an
//     existing target, and the finished tree is verified entry by entry
//     (types, modes, device major:minor, exact symlink targets) plus an
//     exhaustive name-set check;
//   - no asynchronous work: the whole preparation is one synchronous,
//     cancellation-checking function (the C5-C1 inline-stage contract);
//   - any incomplete labeling, ACL verification, device creation, or
//     verification is an explicit failure — readiness is only the
//     successful return, and nothing is published on any partial state;
//   - synchronous own-residue cleanup: every failure after the operation
//     directory was created removes exactly that directory (the only
//     content this invocation created) before returning, and a failed
//     removal is reported alongside the primary failure — the residue
//     then stays refuse-to-adopt for any retry;
//   - canonical source root: the state root is accepted only at its
//     exact canonical spelling, the fixed daemon state root
//     (/var/lib/docker-helper, config.go's daemonStateRoot — a fixed
//     privileged path, not a configurable one); every other spelling,
//     including traversal forms, is refused before the first mutation;
//   - real creation modes: the daemon unit runs UMask=0077, so creation
//     alone cannot guarantee the fixed modes (mknod 0666 → 0600,
//     mkdir 0755 → 0700). After every device and mount-dir creation the
//     actual mode is verified and, only when it differs, corrected with
//     a narrow chmod and verified again — the process-global umask is
//     never touched (the daemon is multithreaded). The future SELinux
//     authority inventory therefore gains devprep_t:chr_file setattr and
//     keeps devprep_t:dir setattr (the C4-C1 manage set) for these
//     corrections; nothing is granted in this round.

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// builderDevPrepObjectType is the SELinux type of the prepared dev-prep
// tree (the shipped policy round defines the type; this constant carries
// the canonical spelling for the daemon-side labeling).
const builderDevPrepObjectType = "docker_helper_devprep_t"

// devPrepDevice is one fixed character device of the prepared tree.
type devPrepDevice struct {
	name  string
	major uint32
	minor uint32
}

// devPrepDevices is the fixed device contract, verified against pinned
// runc v1.4.3 (specconv AllowedDevices: all CharDevice, FileMode 0o666,
// uid/gid 0). The order is this owner's fixed creation order.
var devPrepDevices = []devPrepDevice{
	{name: "null", major: 1, minor: 3},
	{name: "zero", major: 1, minor: 5},
	{name: "full", major: 1, minor: 7},
	{name: "random", major: 1, minor: 8},
	{name: "urandom", major: 1, minor: 9},
	{name: "tty", major: 5, minor: 0},
}

// devPrepFileMode is the exact mode of every created device node
// (runc's mknodDevice applies node.FileMode | S_IFCHR).
const devPrepFileMode = 0o666

// devPrepDirMode is the mode of the created mountpoint directories.
const devPrepDirMode = 0o755

// devPrepSymlink is one fixed symlink of the prepared tree.
type devPrepSymlink struct {
	name   string
	target string
}

// devPrepSymlinks is the fixed symlink contract (setupDevSymlinks and
// setupPtmx of pinned runc v1.4.3; the ptmx target is the relative
// spelling runc itself writes).
var devPrepSymlinks = []devPrepSymlink{
	{name: "fd", target: "/proc/self/fd"},
	{name: "stdin", target: "/proc/self/fd/0"},
	{name: "stdout", target: "/proc/self/fd/1"},
	{name: "stderr", target: "/proc/self/fd/2"},
	{name: "ptmx", target: "pts/ptmx"},
}

// devPrepConditionalSymlink is the conditional core symlink: created only
// when /proc/kcore exists on the host (the exact condition of
// setupDevSymlinks; the existence check runs in the daemon's namespace,
// the same host /proc runc's setup process observes).
var devPrepConditionalSymlink = devPrepSymlink{name: "core", target: "/proc/kcore"}

// devPrepHostKcore is the host path whose existence gates the core
// symlink.
const devPrepHostKcore = "/proc/kcore"

// devPrepMountDirs are the fixed mountpoint directories of the prepared
// tree (the devpts/tmpfs targets of the container mount table).
var devPrepMountDirs = []string{"pts", "shm", "mqueue"}

// devPrepDirMode0700 is the initial mode of created ACL-managed
// directories; the access ACL set immediately after adjusts the group
// class to the mask (--x), making the effective mode 0710.
const devPrepDirMode0700 = 0o700

// devPrepACLEffectiveMode is the documented effective mode of an
// ACL-managed directory (C4-C1 §1): owner rwx, group class (the ACL
// mask) --x, other ---.
const devPrepACLEffectiveMode = 0o710

// POSIX ACL xattr constants (linux posix_acl_xattr.h) and the access-ACL
// xattr name. The encoding is the kernel's binary form: a little-endian
// version header followed by 8-byte entries.
const (
	devPrepACLXattrName = "system.posix_acl_access"

	posixACLVersion     = 0x0002
	posixACLEntrySize   = 8
	posixACLHeaderSize  = 4
	posixACLUserObjTag  = 0x01
	posixACLUserTag     = 0x02
	posixACLGroupObjTag = 0x04
	posixACLGroupTag    = 0x08
	posixACLMaskTag     = 0x10
	posixACLOtherTag    = 0x20
	posixACLUndefinedID = ^uint32(0)
)

// devPrepACLEntry is one decoded POSIX access-ACL entry.
type devPrepACLEntry struct {
	tag  uint16
	perm uint16
	id   uint32 // valid only for the named tags
}

// devPrepACLError reports an ACL that exists but does not decode, or an
// encoding that the kernel would reject; it is never a presence signal.
type devPrepACLError struct{ cause error }

func (e *devPrepACLError) Error() string { return "dev-prep access ACL: " + e.cause.Error() }
func (e *devPrepACLError) Unwrap() error { return e.cause }

// desiredDevPrepACL returns the exact access-ACL entries for one
// ACL-managed directory (C4-C1 §1): owner rwx, the named builder-uid
// entry with search-only x, group class 0, mask x, other 0. The
// resulting stat mode is 0710. The non-named tags carry the undefined id
// (the kernel's read-back form), so a decoded round trip compares equal.
func desiredDevPrepACL(builderUID uint32) []devPrepACLEntry {
	return []devPrepACLEntry{
		{tag: posixACLUserObjTag, perm: 0o7, id: posixACLUndefinedID},
		{tag: posixACLUserTag, perm: 0o1, id: builderUID},
		{tag: posixACLGroupObjTag, perm: 0o0, id: posixACLUndefinedID},
		{tag: posixACLMaskTag, perm: 0o1, id: posixACLUndefinedID},
		{tag: posixACLOtherTag, perm: 0o0, id: posixACLUndefinedID},
	}
}

// encodeDevPrepACL renders the entries in the kernel's binary xattr
// form. Entries must already be in kernel order; the encoder enforces
// the exact required sequence for the access ACL of a directory with
// named entries (user obj, named users by ascending id, group obj, mask,
// other) and rejects anything else — a malformed ACL is never written.
func encodeDevPrepACL(entries []devPrepACLEntry) ([]byte, error) {
	if len(entries) != 5 {
		return nil, &devPrepACLError{cause: fmt.Errorf("entry count %d, want exactly 5", len(entries))}
	}
	wantTags := []uint16{posixACLUserObjTag, posixACLUserTag, posixACLGroupObjTag, posixACLMaskTag, posixACLOtherTag}
	for i, want := range wantTags {
		if entries[i].tag != want {
			return nil, &devPrepACLError{cause: fmt.Errorf("entry %d tag %#x, want %#x", i, entries[i].tag, want)}
		}
	}
	buf := make([]byte, posixACLHeaderSize+posixACLEntrySize*len(entries))
	binary.LittleEndian.PutUint16(buf[0:2], posixACLVersion)
	for i, e := range entries {
		off := posixACLHeaderSize + posixACLEntrySize*i
		binary.LittleEndian.PutUint16(buf[off:off+2], e.tag)
		binary.LittleEndian.PutUint16(buf[off+2:off+4], e.perm)
		id := e.id
		if e.tag != posixACLUserTag && e.tag != posixACLGroupTag {
			id = posixACLUndefinedID
		}
		binary.LittleEndian.PutUint32(buf[off+4:off+8], id)
	}
	return buf, nil
}

// decodeDevPrepACL decodes the kernel's binary access-ACL form. An
// oversize, short, wrong-version, unknown-tag, out-of-order, or
// duplicated-entry xattr is a decode failure, never a partial result.
func decodeDevPrepACL(raw []byte) ([]devPrepACLEntry, error) {
	if len(raw) < posixACLHeaderSize || (len(raw)-posixACLHeaderSize)%posixACLEntrySize != 0 {
		return nil, &devPrepACLError{cause: fmt.Errorf("length %d is not a header plus whole entries", len(raw))}
	}
	if binary.LittleEndian.Uint16(raw[0:2]) != posixACLVersion {
		return nil, &devPrepACLError{cause: fmt.Errorf("version %#x, want %#x", binary.LittleEndian.Uint16(raw[0:2]), posixACLVersion)}
	}
	n := (len(raw) - posixACLHeaderSize) / posixACLEntrySize
	entries := make([]devPrepACLEntry, n)
	for i := range entries {
		off := posixACLHeaderSize + posixACLEntrySize*i
		entries[i] = devPrepACLEntry{
			tag:  binary.LittleEndian.Uint16(raw[off : off+2]),
			perm: binary.LittleEndian.Uint16(raw[off+2 : off+4]),
			id:   binary.LittleEndian.Uint32(raw[off+4 : off+8]),
		}
	}
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].tag != entries[j].tag {
			return entries[i].tag < entries[j].tag
		}
		return entries[i].id < entries[j].id
	})
	// Structural check: the canonical kernel order is user obj, named
	// users ascending, group obj, named groups ascending, mask, other;
	// masks appear at most once and only with named entries.
	if n == 0 {
		return nil, &devPrepACLError{cause: errors.New("empty ACL")}
	}
	prevTag := uint16(0)
	prevID := ^uint32(0)
	sawMask := false
	sawNamed := false
	sawUserObj := false
	sawGroupObj := false
	sawOther := false
	for _, e := range entries {
		switch e.tag {
		case posixACLUserObjTag, posixACLGroupObjTag, posixACLOtherTag:
			if e.id != posixACLUndefinedID {
				return nil, &devPrepACLError{cause: fmt.Errorf("tag %#x carries an id", e.tag)}
			}
			switch e.tag {
			case posixACLUserObjTag:
				if sawUserObj {
					return nil, &devPrepACLError{cause: errors.New("duplicate user-obj entry")}
				}
				sawUserObj = true
			case posixACLGroupObjTag:
				if sawGroupObj {
					return nil, &devPrepACLError{cause: errors.New("duplicate group-obj entry")}
				}
				sawGroupObj = true
			case posixACLOtherTag:
				if sawOther {
					return nil, &devPrepACLError{cause: errors.New("duplicate other entry")}
				}
				sawOther = true
			}
		case posixACLUserTag, posixACLGroupTag:
			sawNamed = true
			if e.id == posixACLUndefinedID {
				return nil, &devPrepACLError{cause: fmt.Errorf("named tag %#x without id", e.tag)}
			}
			if e.tag == prevTag && e.id <= prevID {
				return nil, &devPrepACLError{cause: errors.New("named entries not in ascending id order")}
			}
		case posixACLMaskTag:
			if sawMask {
				return nil, &devPrepACLError{cause: errors.New("duplicate mask entry")}
			}
			sawMask = true
			if !sawNamed {
				return nil, &devPrepACLError{cause: errors.New("mask entry without named entries")}
			}
		default:
			return nil, &devPrepACLError{cause: fmt.Errorf("unknown tag %#x", e.tag)}
		}
		if e.tag < prevTag {
			return nil, &devPrepACLError{cause: errors.New("entries not in canonical tag order")}
		}
		prevTag, prevID = e.tag, e.id
	}
	return entries, nil
}

// devPrepACLEqual compares two decoded ACLs exactly (order-insensitive —
// both sides are canonicalized by the decoder; the desired list is
// already in canonical order).
func devPrepACLEqual(got, want []devPrepACLEntry) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// devPrepSyscalls is the injectable filesystem seam of the preparer: one
// interface owning every privileged filesystem operation the
// preparation performs. Production uses real Linux syscalls; tests
// inject a recording/failing fake and run unprivileged.
type devPrepSyscalls interface {
	// lstat never follows a final symlink (verification and
	// refuse-to-adopt checks).
	lstat(path string) (os.FileInfo, error)
	// stat follows symlinks; used only for the /proc/kcore existence
	// check, the exact check runc performs.
	stat(path string) (os.FileInfo, error)
	mkdir(path string, perm os.FileMode) error
	mknod(path string, mode uint32, dev uint64) error
	symlink(oldname, newname string) error
	readlink(path string) (string, error)
	readDirNames(path string) ([]string, error)
	removeAll(path string) error
	// chmod is the narrow permission-correction primitive: applied only
	// to a just-created node whose actual mode differs from the fixed
	// contract (umask-truncated), never as a general-purpose mode
	// writer.
	chmod(path string, mode os.FileMode) error
	// setxattr and getxattr serve both the security.selinux label and
	// the system.posix_acl_access ACL.
	setxattr(path, name string, value []byte) error
	getxattr(path, name string) ([]byte, error)
	// restorecon relabels the dev-prep subtree root through the
	// daemon's established bounded restorecon mechanism (production
	// delegates to the trusted-CA restorecon owner; a no-op without
	// active SELinux).
	restorecon(path string) error
}

// linuxDevPrepSyscalls implements devPrepSyscalls with real Linux
// syscalls.
type linuxDevPrepSyscalls struct{}

func (linuxDevPrepSyscalls) lstat(path string) (os.FileInfo, error) { return os.Lstat(path) }
func (linuxDevPrepSyscalls) stat(path string) (os.FileInfo, error)  { return os.Stat(path) }
func (linuxDevPrepSyscalls) mkdir(path string, perm os.FileMode) error {
	return os.Mkdir(path, perm)
}
func (linuxDevPrepSyscalls) mknod(path string, mode uint32, dev uint64) error {
	return unix.Mknod(path, mode, int(dev))
}
func (linuxDevPrepSyscalls) symlink(oldname, newname string) error {
	return os.Symlink(oldname, newname)
}
func (linuxDevPrepSyscalls) readlink(path string) (string, error) { return os.Readlink(path) }
func (linuxDevPrepSyscalls) readDirNames(path string) ([]string, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names, nil
}
func (linuxDevPrepSyscalls) removeAll(path string) error { return os.RemoveAll(path) }
func (linuxDevPrepSyscalls) chmod(path string, mode os.FileMode) error {
	return unix.Chmod(path, uint32(mode))
}
func (linuxDevPrepSyscalls) setxattr(path, name string, value []byte) error {
	return unix.Setxattr(path, name, value, 0)
}
func (linuxDevPrepSyscalls) getxattr(path, name string) ([]byte, error) {
	buf := make([]byte, builderObjectContextReadCeiling)
	n, err := unix.Getxattr(path, name, buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}
func (linuxDevPrepSyscalls) restorecon(path string) error { return restoreconDevPrepTree(path) }

// devPrepRefuseError is the typed refuse-to-adopt failure: the operation
// directory already exists and is never adopted or repaired.
type devPrepRefuseError struct{ path string }

func (e *devPrepRefuseError) Error() string {
	return "dev-prep tree already exists; refusing to adopt " + e.path
}

// devPrepOpDir is the canonical prepared-tree path for one operation:
// <daemonStateRoot>/dev-prep/<op>. One owner of the path shape, shared by
// the preparer and the wrapper inspection core (which must never accept a
// caller-supplied tree path).
func devPrepOpDir(opID string) string {
	return filepath.Join(daemonStateRoot, "dev-prep", opID)
}

// devPrepDisposeOperation disposes exactly ONE operation's prepared tree:
// the canonical devPrepOpDir(opID), and nothing else. It never removes the
// shared dev-prep subtree root or the state root (the derivation is the
// one path owner above and the ID grammar bounds the final component), it
// never adopts or repairs anything (an absent tree is success), and it is
// caller-independent of any invocation path (no caller-supplied paths).
// The lstat-based removal cannot follow a final symlink, and the
// refuse-to-adopt contract is untouched. Lifetime ordering is the caller's
// contract: the build driver invokes this only after a PROVEN builder-manager
// STOP convergence, never while this operation's builder instance may
// still use the tree.
func devPrepDisposeOperation(opID string) error {
	if !isOperationID(opID) {
		return fmt.Errorf("dev-prep: operation id is not canonical")
	}
	return os.RemoveAll(devPrepOpDir(opID))
}

// prepareTrustedDev prepares the trusted /dev tree for one operation with
// the production syscall seam. The state root is bound to the daemon's
// canonical state root through the config owner; the new core is
// intentionally not invoked by any production path yet (the integration
// round wires it into the build driver's stage sequence).
func prepareTrustedDev(ctx context.Context, opID string, category builderCategory) error {
	return prepareTrustedDevWithSyscalls(linuxDevPrepSyscalls{}, ctx, getStateDirFunc(), opID, category)
}

// prepareTrustedDevWithSyscalls is the one synchronous preparation
// sequence. It never runs asynchronously, never adopts an existing
// operation tree, and removes its own residue on every partial failure.
func prepareTrustedDevWithSyscalls(seam devPrepSyscalls, ctx context.Context, stateDir, opID string, category builderCategory) (err error) {
	if !isOperationID(opID) {
		return fmt.Errorf("dev-prep: operation id is not canonical")
	}
	if !category.valid() {
		return fmt.Errorf("dev-prep: category %s is not a valid pool category", category)
	}
	// Canonical source root: only the exact canonical daemon state root
	// spelling is accepted. Privileged paths are not configurable; any
	// other absolute value — including traversal spellings that
	// filepath.Clean would canonicalize back — is refused before the
	// first mutation.
	if stateDir != daemonStateRoot {
		return fmt.Errorf("dev-prep: state dir %q is not the canonical daemon state root %q; privileged paths are not configurable", stateDir, daemonStateRoot)
	}
	devPrepRoot := filepath.Join(daemonStateRoot, "dev-prep")
	opDir := devPrepOpDir(opID)

	// Refuse-to-adopt: an existing tree is never adopted, repaired, or
	// removed by this invocation.
	if _, err := seam.lstat(opDir); err == nil {
		return &devPrepRefuseError{path: opDir}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("dev-prep: cannot inspect %s: %w", opDir, err)
	}

	// The state root must already exist (systemd owns it); this owner
	// never creates it.
	if err := devPrepRequireDir(seam, daemonStateRoot, "state root"); err != nil {
		return err
	}

	createdOpDir := false
	defer func() {
		if !createdOpDir {
			return
		}
		// Own-residue cleanup: this invocation created the operation
		// directory and everything inside it; the removal is
		// lstat-based (RemoveAll never follows a final symlink) and
		// cannot touch any other operation's tree. A failed removal is
		// reported alongside the primary failure — the residue stays
		// refuse-to-adopt for any retry, never adopted or repaired.
		if rmErr := seam.removeAll(opDir); rmErr != nil {
			err = fmt.Errorf("dev-prep: %w; additionally, own-residue cleanup of %s failed: %v", err, opDir, rmErr)
		}
	}()

	if err := ctx.Err(); err != nil {
		return err
	}
	// Ensure the dev-prep subtree root: strict creation when absent, a
	// directory check when present.
	if err := devPrepEnsureRootDir(seam, devPrepRoot); err != nil {
		return err
	}

	// SELinux labeling of the subtree root (C4-C1 step 2), before any
	// operation directory exists to inherit from.
	if gate, err := builderProvisionGate(); err != nil {
		return fmt.Errorf("dev-prep: cannot determine MAC backend: %w", err)
	} else if gate {
		if err := seam.restorecon(devPrepRoot); err != nil {
			return fmt.Errorf("dev-prep: restorecon of %s failed: %w", devPrepRoot, err)
		}
		if err := devPrepVerifyRootLabel(seam, devPrepRoot); err != nil {
			return err
		}
	}

	// The builder identity's search-only ACL on the traverse chain: the
	// state root, the dev-prep root, and the operation directory.
	builderUID, err := devPrepBuilderUID()
	if err != nil {
		return err
	}
	for _, dir := range []string{daemonStateRoot, devPrepRoot} {
		if err := devPrepEnsureACL(seam, dir, builderUID); err != nil {
			return err
		}
	}

	if err := ctx.Err(); err != nil {
		return err
	}
	// Strict creation: the refuse-to-adopt check above is re-closed
	// atomically by mkdir's EEXIST semantics.
	if err := seam.mkdir(opDir, devPrepDirMode0700); err != nil {
		return fmt.Errorf("dev-prep: cannot create %s: %w", opDir, err)
	}
	createdOpDir = true

	// The per-operation category label: direct xattr write with the exact
	// full context, mandatory read-back verification, BEFORE any
	// operation content exists (C4-C1 steps 4-5; restorecon cannot set
	// per-op levels).
	if gate, err := builderProvisionGate(); err != nil {
		return fmt.Errorf("dev-prep: cannot determine MAC backend: %w", err)
	} else if gate {
		want := builderObjectContext(builderDevPrepObjectType, category)
		if err := seam.setxattr(opDir, "security.selinux", []byte(want)); err != nil {
			return fmt.Errorf("dev-prep: cannot label %s: %w", opDir, err)
		}
		raw, err := seam.getxattr(opDir, "security.selinux")
		if err != nil {
			return fmt.Errorf("dev-prep: cannot read back the label of %s: %w", opDir, err)
		}
		got, err := decodeSELinuxXattrContext(raw)
		if err != nil {
			return fmt.Errorf("dev-prep: label read-back of %s is not a context: %w", opDir, err)
		}
		if got != want {
			return fmt.Errorf("dev-prep: label mismatch on %s: got %q want %q", opDir, got, want)
		}
	}

	// The operation directory's own ACL (mask --x → effective 0710).
	if err := devPrepEnsureACL(seam, opDir, builderUID); err != nil {
		return err
	}

	if err := ctx.Err(); err != nil {
		return err
	}
	// Operation contents, in the fixed order: mountpoint directories,
	// devices, symlinks. Every creation is strict (an existing target is
	// a failure — the tree was just created and is exclusively ours).
	// The daemon unit runs UMask=0077, so creation alone cannot
	// guarantee the fixed modes: each created node's actual mode is
	// verified and, only when the umask truncated it, corrected with a
	// narrow chmod and verified again. The process-global umask is never
	// touched (the daemon is multithreaded).
	for _, name := range devPrepMountDirs {
		path := filepath.Join(opDir, name)
		if err := seam.mkdir(path, devPrepDirMode); err != nil {
			return fmt.Errorf("dev-prep: cannot create mount dir %s: %w", name, err)
		}
		if err := devPrepEnsureMode(seam, path, name, devPrepDirMode); err != nil {
			return err
		}
	}
	for _, dev := range devPrepDevices {
		path := filepath.Join(opDir, dev.name)
		if err := seam.mknod(path, devPrepFileMode|unix.S_IFCHR, unix.Mkdev(dev.major, dev.minor)); err != nil {
			return fmt.Errorf("dev-prep: cannot create device %s: %w", dev.name, err)
		}
		if err := devPrepEnsureMode(seam, path, dev.name, devPrepFileMode); err != nil {
			return err
		}
	}
	for _, link := range devPrepSymlinks {
		if err := seam.symlink(link.target, filepath.Join(opDir, link.name)); err != nil {
			return fmt.Errorf("dev-prep: cannot create symlink %s: %w", link.name, err)
		}
	}
	if st, err := seam.stat(devPrepHostKcore); err == nil && st != nil {
		if err := seam.symlink(devPrepConditionalSymlink.target, filepath.Join(opDir, devPrepConditionalSymlink.name)); err != nil {
			return fmt.Errorf("dev-prep: cannot create symlink %s: %w", devPrepConditionalSymlink.name, err)
		}
	}

	// Strict verification of the finished tree before readiness. The
	// verification is part of the preparation: only its success
	// completes this invocation.
	if err := devPrepVerifyTree(seam, opDir, category); err != nil {
		return err
	}
	// Success: the own-residue cleanup no longer applies — the tree is
	// the prepared result, not residue.
	createdOpDir = false
	return nil
}

// devPrepRequireDir fails unless the path exists as a directory.
func devPrepRequireDir(seam devPrepSyscalls, path, what string) error {
	st, err := seam.lstat(path)
	if err != nil {
		return fmt.Errorf("dev-prep: %s %s is not accessible: %w", what, path, err)
	}
	if !st.IsDir() {
		return fmt.Errorf("dev-prep: %s %s is not a directory", what, path)
	}
	return nil
}

// devPrepEnsureRootDir creates the dev-prep subtree root strictly: absent
// → mkdir; present → it must be a directory; anything else fails.
func devPrepEnsureRootDir(seam devPrepSyscalls, devPrepRoot string) error {
	_, err := seam.lstat(devPrepRoot)
	switch {
	case err == nil:
		return devPrepRequireDir(seam, devPrepRoot, "dev-prep root")
	case errors.Is(err, os.ErrNotExist):
		if err := seam.mkdir(devPrepRoot, devPrepDirMode0700); err != nil {
			return fmt.Errorf("dev-prep: cannot create %s: %w", devPrepRoot, err)
		}
		return nil
	default:
		return fmt.Errorf("dev-prep: cannot inspect %s: %w", devPrepRoot, err)
	}
}

// devPrepVerifyRootLabel is the tripwire on the subtree-root relabel: the
// read-back context must carry the devprep type at the uncategorized
// level. The user/role spelling is policy-dependent and is not asserted.
func devPrepVerifyRootLabel(seam devPrepSyscalls, devPrepRoot string) error {
	raw, err := seam.getxattr(devPrepRoot, "security.selinux")
	if err != nil {
		return fmt.Errorf("dev-prep: cannot read the label of %s: %w", devPrepRoot, err)
	}
	got, err := decodeSELinuxXattrContext(raw)
	if err != nil {
		return fmt.Errorf("dev-prep: label read-back of %s is not a context: %w", devPrepRoot, err)
	}
	if !bytes.HasSuffix([]byte(got), []byte(":"+builderDevPrepObjectType+":s0")) {
		return fmt.Errorf("dev-prep: unexpected label on %s: got %q, want the %s:s0 type", devPrepRoot, got, builderDevPrepObjectType)
	}
	return nil
}

// devPrepBuilderUID resolves the builder identity for the ACL named-user
// entry through the established owner (the same lookup the manager
// identity guard and the manager's own uid resolution use). No hardcoded
// numeric uid exists anywhere.
func devPrepBuilderUID() (uint32, error) {
	u, err := builderLookupUser(builderManagerBuilderUser)
	if err != nil {
		return 0, fmt.Errorf("dev-prep: builder identity %q not found: %w", builderManagerBuilderUser, err)
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("dev-prep: builder identity uid %q is not numeric: %w", u.Uid, err)
	}
	return uint32(uid), nil
}

// devPrepEnsureACL applies the verify-and-reapply contract for one
// ACL-managed directory: verify the exact desired entries and the
// effective 0710 mode; reapply the ACL when either differs; verify
// again. Any mismatch after the reapply is an explicit failure — an
// ineffective ACL is never accepted as readiness (C4-C1: the reapply is
// mandatory, not belt-and-braces).
func devPrepEnsureACL(seam devPrepSyscalls, path string, builderUID uint32) error {
	want := desiredDevPrepACL(builderUID)
	ok, err := devPrepACLMatches(seam, path, want)
	if err != nil {
		return err
	}
	if ok {
		return nil
	}
	encoded, err := encodeDevPrepACL(want)
	if err != nil {
		return err
	}
	if err := seam.setxattr(path, devPrepACLXattrName, encoded); err != nil {
		return fmt.Errorf("dev-prep: cannot set the access ACL on %s: %w", path, err)
	}
	ok, err = devPrepACLMatches(seam, path, want)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("dev-prep: access ACL on %s did not verify after reapplication", path)
	}
	return nil
}

// devPrepACLMatches reports whether the path's access ACL equals want and
// its effective mode is 0710. A missing ACL (ENODATA) is a mismatch, not
// an error; an ACL that exists but does not decode is an error.
func devPrepACLMatches(seam devPrepSyscalls, path string, want []devPrepACLEntry) (bool, error) {
	raw, err := seam.getxattr(path, devPrepACLXattrName)
	switch {
	case err == nil:
	case errors.Is(err, unix.ENODATA):
		return false, nil
	default:
		return false, fmt.Errorf("dev-prep: cannot read the access ACL of %s: %w", path, err)
	}
	got, err := decodeDevPrepACL(raw)
	if err != nil {
		return false, fmt.Errorf("dev-prep: access ACL of %s: %w", path, err)
	}
	if !devPrepACLEqual(got, want) {
		return false, nil
	}
	st, err := seam.lstat(path)
	if err != nil {
		return false, fmt.Errorf("dev-prep: cannot stat %s: %w", path, err)
	}
	if st.Mode().Perm() != devPrepACLEffectiveMode {
		return false, nil
	}
	return true, nil
}

// devPrepEnsureMode is the narrowly scoped, verified permission
// correction for one just-created node: the actual mode is read (never
// assumed); only a mismatch — the UMask=0077 truncation — triggers a
// chmod to the exact contract mode, and the correction is verified with
// a second read. The umask is never changed process-wide.
func devPrepEnsureMode(seam devPrepSyscalls, path, name string, want os.FileMode) error {
	st, err := seam.lstat(path)
	if err != nil {
		return fmt.Errorf("dev-prep: cannot verify the mode of %s: %w", name, err)
	}
	if st.Mode().Perm() == want {
		return nil
	}
	if err := seam.chmod(path, want); err != nil {
		return fmt.Errorf("dev-prep: cannot correct the umask-truncated mode of %s (got %#o, want %#o): %w", name, st.Mode().Perm(), want, err)
	}
	st, err = seam.lstat(path)
	if err != nil {
		return fmt.Errorf("dev-prep: cannot verify the corrected mode of %s: %w", name, err)
	}
	if st.Mode().Perm() != want {
		return fmt.Errorf("dev-prep: mode of %s did not verify after correction: got %#o, want %#o", name, st.Mode().Perm(), want)
	}
	return nil
}

// devPrepVerifyTree strictly verifies the finished tree: the exact entry
// name set (the fixed contract is exhaustive — an unexpected entry is a
// failure), each entry's type and content contract, the effective mode
// of the operation directory, and (under SELinux) the persisted
// per-operation label. Nothing is published on any mismatch.
func devPrepVerifyTree(seam devPrepSyscalls, opDir string, category builderCategory) error {
	st, err := seam.lstat(opDir)
	if err != nil {
		return fmt.Errorf("dev-prep: cannot verify %s: %w", opDir, err)
	}
	if !st.IsDir() {
		return fmt.Errorf("dev-prep: %s is not a directory", opDir)
	}
	if st.Mode().Perm() != devPrepACLEffectiveMode {
		return fmt.Errorf("dev-prep: effective mode of %s is %#o, want %#o", opDir, st.Mode().Perm(), devPrepACLEffectiveMode)
	}

	wantNames := map[string]bool{}
	for _, d := range devPrepMountDirs {
		wantNames[d] = true
	}
	for _, d := range devPrepDevices {
		wantNames[d.name] = true
	}
	for _, l := range devPrepSymlinks {
		wantNames[l.name] = true
	}
	conditional := false
	if _, err := seam.stat(devPrepHostKcore); err == nil {
		wantNames[devPrepConditionalSymlink.name] = true
		conditional = true
	}

	names, err := seam.readDirNames(opDir)
	if err != nil {
		return fmt.Errorf("dev-prep: cannot enumerate %s: %w", opDir, err)
	}
	gotNames := map[string]bool{}
	for _, name := range names {
		gotNames[name] = true
	}
	for name := range gotNames {
		if !wantNames[name] {
			return fmt.Errorf("dev-prep: unexpected entry %q in %s", name, opDir)
		}
	}
	for name := range wantNames {
		if !gotNames[name] {
			return fmt.Errorf("dev-prep: missing entry %q in %s", name, opDir)
		}
	}

	for _, name := range devPrepMountDirs {
		st, err := seam.lstat(filepath.Join(opDir, name))
		if err != nil {
			return fmt.Errorf("dev-prep: cannot verify mount dir %s: %w", name, err)
		}
		if !st.IsDir() {
			return fmt.Errorf("dev-prep: mount dir %s is not a directory", name)
		}
		if st.Mode().Perm() != devPrepDirMode {
			return fmt.Errorf("dev-prep: mount dir %s has mode %#o, want %#o", name, st.Mode().Perm(), devPrepDirMode)
		}
	}
	for _, dev := range devPrepDevices {
		if err := devPrepVerifyDevice(seam, opDir, dev); err != nil {
			return err
		}
	}
	for _, link := range devPrepSymlinks {
		if err := devPrepVerifySymlink(seam, opDir, link); err != nil {
			return err
		}
	}
	if conditional {
		if err := devPrepVerifySymlink(seam, opDir, devPrepConditionalSymlink); err != nil {
			return err
		}
	}

	if gate, err := builderProvisionGate(); err != nil {
		return fmt.Errorf("dev-prep: cannot determine MAC backend: %w", err)
	} else if gate {
		want := builderObjectContext(builderDevPrepObjectType, category)
		raw, err := seam.getxattr(opDir, "security.selinux")
		if err != nil {
			return fmt.Errorf("dev-prep: cannot verify the label of %s: %w", opDir, err)
		}
		got, err := decodeSELinuxXattrContext(raw)
		if err != nil {
			return fmt.Errorf("dev-prep: label read-back of %s is not a context: %w", opDir, err)
		}
		if got != want {
			return fmt.Errorf("dev-prep: label mismatch on %s: got %q want %q", opDir, got, want)
		}
	}
	return nil
}

// devPrepVerifyDevice verifies one device node without following
// anything: character type, exact 0666 mode, and the exact major:minor.
func devPrepVerifyDevice(seam devPrepSyscalls, opDir string, dev devPrepDevice) error {
	st, err := seam.lstat(filepath.Join(opDir, dev.name))
	if err != nil {
		return fmt.Errorf("dev-prep: cannot verify device %s: %w", dev.name, err)
	}
	mode := st.Sys().(*syscall.Stat_t).Mode
	if mode&unix.S_IFMT != unix.S_IFCHR {
		return fmt.Errorf("dev-prep: device %s is not a character device", dev.name)
	}
	if st.Mode().Perm() != devPrepFileMode {
		return fmt.Errorf("dev-prep: device %s has mode %#o, want %#o", dev.name, st.Mode().Perm(), devPrepFileMode)
	}
	rdev := st.Sys().(*syscall.Stat_t).Rdev
	if unix.Major(rdev) != dev.major || unix.Minor(rdev) != dev.minor {
		return fmt.Errorf("dev-prep: device %s has major:minor %d:%d, want %d:%d",
			dev.name, unix.Major(rdev), unix.Minor(rdev), dev.major, dev.minor)
	}
	return nil
}

// devPrepVerifySymlink verifies one symlink without following it: the
// symlink type and the exact target spelling (os.Readlink reads the link
// itself; the target is never opened).
func devPrepVerifySymlink(seam devPrepSyscalls, opDir string, link devPrepSymlink) error {
	path := filepath.Join(opDir, link.name)
	st, err := seam.lstat(path)
	if err != nil {
		return fmt.Errorf("dev-prep: cannot verify symlink %s: %w", link.name, err)
	}
	if st.Mode()&os.ModeSymlink == 0 {
		return fmt.Errorf("dev-prep: %s is not a symlink", link.name)
	}
	got, err := seam.readlink(path)
	if err != nil {
		return fmt.Errorf("dev-prep: cannot read symlink %s: %w", link.name, err)
	}
	if got != link.target {
		return fmt.Errorf("dev-prep: symlink %s targets %q, want %q", link.name, got, link.target)
	}
	return nil
}

// restoreconDevPrepTree relabels the dev-prep subtree root to
// docker_helper_devprep_t through the daemon's established bounded
// restorecon mechanism (the trusted-CA precedent). Non-recursive (-m):
// only the root is relabeled here; the operation directory receives its
// categorized label through the direct xattr write and every child
// inherits at creation. A no-op when SELinux is not active; a detection
// error fails closed.
func restoreconDevPrepTree(dir string) error {
	active, _, err := selinuxEnabled()
	if err != nil {
		return fmt.Errorf("cannot determine SELinux state for dev-prep restorecon: %w", err)
	}
	if !active {
		return nil
	}
	// The same bounded MAC transition budget as every other daemon-owned
	// restorecon: no hung relabel can hold the preparation hostage.
	ctx, cancel := newMACTransitionContext()
	defer cancel()
	out, err := trustedCARestorecon(ctx, "-m", dir)
	if classify := macCommandError(ctx, "restorecon", err); classify != err {
		return fmt.Errorf("dev-prep restorecon failed: %w", classify)
	}
	if err != nil {
		return fmt.Errorf("dev-prep restorecon failed: %w: %s", err, bytes.TrimSpace(out))
	}
	return nil
}
