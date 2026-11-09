//go:build linux

package main

// dev_prep_linux_test.go proves the trusted /dev preparer's contract with
// an injected recording/failing filesystem seam: the exact operation
// sequence, labels, ACL semantics, device contract, failure injection at
// every mutation, refuse-to-adopt, own-residue cleanup, and same-ID
// retry. No test requires root, CAP_MKNOD, SELinux, or real xattrs.

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const devPrepTestOpID = "op_0123456789abcdef0123456789abcdef"
const devPrepTestBuilderUID = 4312

// fakeDevPrepNode is a tiny in-memory POSIX-ish model node the fake seam
// operates on. Only the shapes the preparer can create are modeled; the
// fake never follows symlinks because the preparer never creates or
// resolves through one.
type fakeDevPrepNode struct {
	kind    string // dir | chr | symlink | file
	mode    os.FileMode
	major   uint32
	minor   uint32
	target  string
	xattrs  map[string][]byte
	entries map[string]*fakeDevPrepNode
}

type fakeDevPrepFS struct {
	root  *fakeDevPrepNode
	log   []string
	fail  map[string]error // one-shot injected failures keyed by operation
	umask os.FileMode      // modeled process umask (the shipped unit: 0077)
}

func newFakeDevPrepFS() *fakeDevPrepFS {
	fs := &fakeDevPrepFS{
		root:  &fakeDevPrepNode{kind: "dir", mode: 0o755, entries: map[string]*fakeDevPrepNode{}, xattrs: map[string][]byte{}},
		fail:  map[string]error{},
		umask: 0o077,
	}
	// The state root always exists in production (systemd owns it); tests
	// that need it missing clear the model explicitly.
	fs.root.entries["var"] = &fakeDevPrepNode{kind: "dir", mode: 0o755, entries: map[string]*fakeDevPrepNode{
		"lib": {kind: "dir", mode: 0o755, entries: map[string]*fakeDevPrepNode{
			"docker-helper": {kind: "dir", mode: 0o700, entries: map[string]*fakeDevPrepNode{}, xattrs: map[string][]byte{}},
		}, xattrs: map[string][]byte{}},
	}, xattrs: map[string][]byte{}}
	return fs
}

func (f *fakeDevPrepFS) record(op string) { f.log = append(f.log, op) }

func (f *fakeDevPrepFS) arm(op string, err error) { f.fail[op] = err }

func (f *fakeDevPrepFS) take(op string) error {
	if err, ok := f.fail[op]; ok {
		delete(f.fail, op)
		return err
	}
	return nil
}

// resolve walks the path segments against the model.
func (f *fakeDevPrepFS) resolve(path string) (*fakeDevPrepNode, error) {
	clean := filepath.Clean(path)
	if clean == "/" || clean == "." {
		return f.root, nil
	}
	parts := strings.Split(strings.TrimPrefix(clean, "/"), "/")
	node := f.root
	for i, part := range parts {
		if node.kind != "dir" {
			return nil, fmt.Errorf("%s: not a directory", strings.Join(parts[:i+1], "/"))
		}
		child, ok := node.entries[part]
		if !ok {
			return nil, os.ErrNotExist
		}
		node = child
	}
	return node, nil
}

func (f *fakeDevPrepFS) parentOf(path string) (*fakeDevPrepNode, string, error) {
	clean := filepath.Clean(path)
	node, err := f.resolve(filepath.Dir(clean))
	if err != nil {
		return nil, "", err
	}
	return node, filepath.Base(clean), nil
}

func (f *fakeDevPrepFS) lstat(path string) (os.FileInfo, error) {
	f.record("lstat " + path)
	node, err := f.resolve(path)
	if err != nil {
		return nil, err
	}
	return fakeDevPrepInfo{node}, nil
}

func (f *fakeDevPrepFS) stat(path string) (os.FileInfo, error) {
	f.record("stat " + path)
	node, err := f.resolve(path)
	if err != nil {
		return nil, err
	}
	return fakeDevPrepInfo{node}, nil
}

func (f *fakeDevPrepFS) mkdir(path string, perm os.FileMode) error {
	f.record("mkdir " + path)
	if err := f.take("mkdir " + path); err != nil {
		return err
	}
	parent, base, err := f.parentOf(path)
	if err != nil {
		return err
	}
	if _, exists := parent.entries[base]; exists {
		return os.ErrExist
	}
	// The kernel applies the process umask at creation.
	parent.entries[base] = &fakeDevPrepNode{kind: "dir", mode: perm &^ f.umask, entries: map[string]*fakeDevPrepNode{}, xattrs: map[string][]byte{}}
	return nil
}

func (f *fakeDevPrepFS) chmod(path string, mode os.FileMode) error {
	f.record("chmod " + path)
	if err := f.take("chmod " + path); err != nil {
		return err
	}
	// chmod is not umask-affected.
	node, err := f.resolve(path)
	if err != nil {
		return err
	}
	node.mode = mode
	return nil
}

func (f *fakeDevPrepFS) mknod(path string, mode uint32, dev uint64) error {
	f.record("mknod " + path)
	if err := f.take("mknod " + path); err != nil {
		return err
	}
	parent, base, err := f.parentOf(path)
	if err != nil {
		return err
	}
	if _, exists := parent.entries[base]; exists {
		return os.ErrExist
	}
	parent.entries[base] = &fakeDevPrepNode{
		kind:   "chr",
		mode:   os.FileMode(mode&^unix.S_IFMT) &^ f.umask,
		major:  unix.Major(dev),
		minor:  unix.Minor(dev),
		xattrs: map[string][]byte{},
	}
	return nil
}

func (f *fakeDevPrepFS) symlink(oldname, newname string) error {
	f.record("symlink " + newname + " -> " + oldname)
	if err := f.take("symlink " + newname); err != nil {
		return err
	}
	parent, base, err := f.parentOf(newname)
	if err != nil {
		return err
	}
	if _, exists := parent.entries[base]; exists {
		return os.ErrExist
	}
	parent.entries[base] = &fakeDevPrepNode{kind: "symlink", target: oldname, xattrs: map[string][]byte{}}
	return nil
}

func (f *fakeDevPrepFS) readlink(path string) (string, error) {
	f.record("readlink " + path)
	node, err := f.resolve(path)
	if err != nil {
		return "", err
	}
	if node.kind != "symlink" {
		return "", fmt.Errorf("%s: not a symlink", path)
	}
	return node.target, nil
}

func (f *fakeDevPrepFS) readDirNames(path string) ([]string, error) {
	f.record("readdir " + path)
	node, err := f.resolve(path)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(node.entries))
	for name := range node.entries {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

func (f *fakeDevPrepFS) removeAll(path string) error {
	f.record("removeall " + path)
	if err := f.take("removeall " + path); err != nil {
		return err
	}
	parent, base, err := f.parentOf(path)
	if err != nil {
		return err
	}
	delete(parent.entries, base)
	return nil
}

func (f *fakeDevPrepFS) setxattr(path, name string, value []byte) error {
	f.record("setxattr " + name + " " + path)
	if err := f.take("setxattr " + name + " " + path); err != nil {
		return err
	}
	node, err := f.resolve(path)
	if err != nil {
		return err
	}
	node.xattrs[name] = append([]byte(nil), value...)
	if name == devPrepACLXattrName {
		// The kernel syncs the inode mode from an access ACL: owner bits
		// from user obj, group bits from the mask, other bits from other.
		entries, err := decodeDevPrepACL(value)
		if err != nil {
			return err
		}
		mode := os.FileMode(0)
		for _, e := range entries {
			switch e.tag {
			case posixACLUserObjTag:
				mode |= os.FileMode(e.perm) << 6
			case posixACLMaskTag:
				mode |= os.FileMode(e.perm) << 3
			case posixACLOtherTag:
				mode |= os.FileMode(e.perm)
			}
		}
		node.mode = mode
	}
	return nil
}

func (f *fakeDevPrepFS) getxattr(path, name string) ([]byte, error) {
	f.record("getxattr " + name + " " + path)
	if err := f.take("getxattr " + name + " " + path); err != nil {
		return nil, err
	}
	node, err := f.resolve(path)
	if err != nil {
		return nil, err
	}
	value, ok := node.xattrs[name]
	if !ok {
		return nil, unix.ENODATA
	}
	return value, nil
}

func (f *fakeDevPrepFS) restorecon(path string) error {
	f.record("restorecon " + path)
	if err := f.take("restorecon " + path); err != nil {
		return err
	}
	// Model the .fc-driven relabel of the dev-prep subtree root.
	node, err := f.resolve(path)
	if err != nil {
		return err
	}
	node.xattrs["security.selinux"] = []byte("system_u:object_r:" + builderDevPrepObjectType + ":s0")
	return nil
}

type fakeDevPrepInfo struct{ node *fakeDevPrepNode }

func (i fakeDevPrepInfo) Name() string { return "" }
func (i fakeDevPrepInfo) IsDir() bool  { return i.node.kind == "dir" }
func (i fakeDevPrepInfo) Mode() os.FileMode {
	switch i.node.kind {
	case "dir":
		return i.node.mode | os.ModeDir
	case "symlink":
		return os.ModeSymlink
	case "chr":
		return i.node.mode | os.ModeCharDevice | os.ModeDevice
	}
	return i.node.mode
}
func (i fakeDevPrepInfo) ModTime() time.Time { return time.Time{} }
func (i fakeDevPrepInfo) Sys() any {
	switch i.node.kind {
	case "chr":
		return &syscall.Stat_t{Mode: unix.S_IFCHR | uint32(i.node.mode), Rdev: unix.Mkdev(i.node.major, i.node.minor)}
	case "dir":
		return &syscall.Stat_t{Mode: unix.S_IFDIR | uint32(i.node.mode)}
	case "symlink":
		return &syscall.Stat_t{Mode: unix.S_IFLNK}
	}
	return &syscall.Stat_t{Mode: unix.S_IFREG | uint32(i.node.mode)}
}
func (i fakeDevPrepInfo) Size() int64 { return 0 }

// withDevPrepSeams swaps the seams the preparer consults (the SELinux
// gate, the builder identity lookup, and the bounded restorecon runner).
func withDevPrepSeams(t *testing.T, selinux bool, uid uint32) {
	t.Helper()
	origDetect := detectLSM
	detectLSM = func() (LSMBackend, error) {
		if selinux {
			return LSMSELinux, nil
		}
		return LSMNone, nil
	}
	t.Cleanup(func() { detectLSM = origDetect })

	origLookup := builderLookupUser
	builderLookupUser = func(string) (*user.User, error) {
		return &user.User{Username: builderManagerBuilderUser, Uid: fmt.Sprint(uid), Gid: fmt.Sprint(uid)}, nil
	}
	t.Cleanup(func() { builderLookupUser = origLookup })

	origRestorecon := trustedCARestorecon
	trustedCARestorecon = func(_ context.Context, args ...string) ([]byte, error) {
		if len(args) != 2 || args[0] != "-m" {
			return nil, fmt.Errorf("unexpected restorecon args: %v", args)
		}
		return nil, nil
	}
	t.Cleanup(func() { trustedCARestorecon = origRestorecon })
}

func devPrepPrepare(t *testing.T, fs *fakeDevPrepFS, opID string, category builderCategory) error {
	t.Helper()
	return prepareTrustedDevWithSyscalls(fs, context.Background(), "/var/lib/docker-helper", opID, category)
}

func devPrepOpDir() string {
	return filepath.Join("/var/lib/docker-helper", "dev-prep", devPrepTestOpID)
}

func devPrepNodeAt(t *testing.T, fs *fakeDevPrepFS, path string) *fakeDevPrepNode {
	t.Helper()
	node, err := fs.resolve(path)
	if err != nil {
		t.Fatalf("node %s missing: %v", path, err)
	}
	return node
}

// TestDevPrepFullSequenceSELinux proves the exact head of the operation
// sequence (refuse check, state/dev-prep dirs, restorecon), the labels,
// the ACL semantics, and the device/symlink/dir contract of a successful
// preparation under the SELinux gate.
func TestDevPrepFullSequenceSELinux(t *testing.T) {
	withDevPrepSeams(t, true, devPrepTestBuilderUID)
	fs := newFakeDevPrepFS()
	if err := devPrepPrepare(t, fs, devPrepTestOpID, builderCategory(7)); err != nil {
		t.Fatalf("prepare failed: %v", err)
	}

	opDir := devPrepOpDir()
	devPrepRoot := filepath.Dir(opDir)
	stateRoot := "/var/lib/docker-helper"

	// The exact sequence head: the refuse-to-adopt lstat comes first, the
	// state-root existence check second, the dev-prep root creation third.
	wantHead := []string{
		"lstat " + opDir,
		"lstat " + stateRoot,
		"lstat " + devPrepRoot,
		"mkdir " + devPrepRoot,
		"restorecon " + devPrepRoot,
	}
	for i, want := range wantHead {
		if fs.log[i] != want {
			t.Fatalf("sequence[%d] = %q, want %q\nfull:\n%s", i, fs.log[i], want, strings.Join(fs.log, "\n"))
		}
	}
	// The op mkdir happens strictly after the root restorecon and the
	// traverse-chain ACL work.
	mkdirIndex := -1
	restoreconIndex := -1
	for i, entry := range fs.log {
		if entry == "mkdir "+opDir {
			mkdirIndex = i
		}
		if entry == "restorecon "+devPrepRoot {
			restoreconIndex = i
		}
	}
	if mkdirIndex < 0 || restoreconIndex < 0 || mkdirIndex < restoreconIndex {
		t.Fatalf("op mkdir must follow the root restorecon:\n%s", strings.Join(fs.log, "\n"))
	}

	// The dev-prep root carries the relabeled uncategorized type.
	rootLabel := devPrepNodeAt(t, fs, devPrepRoot).xattrs["security.selinux"]
	if string(rootLabel) != "system_u:object_r:"+builderDevPrepObjectType+":s0" {
		t.Fatalf("dev-prep root label = %q", rootLabel)
	}

	// The operation directory carries the exact categorized label.
	opLabel := devPrepNodeAt(t, fs, opDir).xattrs["security.selinux"]
	if want := builderObjectContext(builderDevPrepObjectType, builderCategory(7)); string(opLabel) != want {
		t.Fatalf("op label = %q, want %q", opLabel, want)
	}

	// ACL semantics: state root, dev-prep root, and op dir each carry the
	// exact desired entries and the 0710 effective mode.
	for _, dir := range []string{stateRoot, devPrepRoot, opDir} {
		node := devPrepNodeAt(t, fs, dir)
		raw, ok := node.xattrs[devPrepACLXattrName]
		if !ok {
			t.Fatalf("%s has no access ACL", dir)
		}
		entries, err := decodeDevPrepACL(raw)
		if err != nil {
			t.Fatalf("%s ACL does not decode: %v", dir, err)
		}
		want := desiredDevPrepACL(devPrepTestBuilderUID)
		if !devPrepACLEqual(entries, want) {
			t.Fatalf("%s ACL = %+v, want %+v", dir, entries, want)
		}
		if mode := (fakeDevPrepInfo{node}).Mode().Perm(); mode != devPrepACLEffectiveMode {
			t.Fatalf("%s effective mode = %#o, want %#o", dir, mode, devPrepACLEffectiveMode)
		}
	}

	// Device contract: exactly the six fixed character devices, 0666,
	// exact major:minor.
	for _, dev := range devPrepDevices {
		node := devPrepNodeAt(t, fs, filepath.Join(opDir, dev.name))
		if node.kind != "chr" {
			t.Fatalf("%s is not a character device", dev.name)
		}
		if node.mode.Perm() != devPrepFileMode {
			t.Fatalf("%s mode = %#o, want %#o", dev.name, node.mode.Perm(), devPrepFileMode)
		}
		if node.major != dev.major || node.minor != dev.minor {
			t.Fatalf("%s major:minor = %d:%d, want %d:%d", dev.name, node.major, node.minor, dev.major, dev.minor)
		}
	}

	// Symlinks: the five fixed targets.
	for _, link := range devPrepSymlinks {
		node := devPrepNodeAt(t, fs, filepath.Join(opDir, link.name))
		if node.kind != "symlink" || node.target != link.target {
			t.Fatalf("%s = (%s, %q), want symlink to %q", link.name, node.kind, node.target, link.target)
		}
	}

	// Mount dirs.
	for _, name := range devPrepMountDirs {
		if node := devPrepNodeAt(t, fs, filepath.Join(opDir, name)); node.kind != "dir" {
			t.Fatalf("%s is not a directory", name)
		}
	}

	// The conditional core symlink is absent when /proc/kcore is absent.
	if _, err := fs.resolve(filepath.Join(opDir, "core")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("core symlink must be absent without /proc/kcore")
	}
}

// TestDevPrepConditionalCoreSymlink proves the conditional entry: with
// /proc/kcore present the core symlink exists with the exact target.
func TestDevPrepConditionalCoreSymlink(t *testing.T) {
	withDevPrepSeams(t, false, devPrepTestBuilderUID)
	fs := newFakeDevPrepFS()
	fs.root.entries["proc"] = &fakeDevPrepNode{kind: "dir", mode: 0o555, entries: map[string]*fakeDevPrepNode{
		"kcore": {kind: "file", mode: 0o444, xattrs: map[string][]byte{}},
	}, xattrs: map[string][]byte{}}
	if err := devPrepPrepare(t, fs, devPrepTestOpID, builderCategory(1)); err != nil {
		t.Fatalf("prepare failed: %v", err)
	}
	node := devPrepNodeAt(t, fs, filepath.Join(devPrepOpDir(), "core"))
	if node.kind != "symlink" || node.target != "/proc/kcore" {
		t.Fatalf("core = (%s, %q)", node.kind, node.target)
	}
}

// TestDevPrepRefusesExistingTree proves refuse-to-adopt for an existing
// operation directory of any shape, with zero mutations performed.
func TestDevPrepRefusesExistingTree(t *testing.T) {
	withDevPrepSeams(t, false, devPrepTestBuilderUID)
	for _, kind := range []string{"dir", "symlink", "chr"} {
		t.Run(kind, func(t *testing.T) {
			fs := newFakeDevPrepFS()
			node := &fakeDevPrepNode{kind: kind, xattrs: map[string][]byte{}, entries: map[string]*fakeDevPrepNode{}}
			switch kind {
			case "symlink":
				node.target = "/etc"
			case "chr":
				node.mode = 0o666
				node.major, node.minor = 1, 3
			default:
				node.mode = 0o700
			}
			fs.root.entries["var"] = &fakeDevPrepNode{kind: "dir", mode: 0o700, entries: map[string]*fakeDevPrepNode{
				"lib": {kind: "dir", mode: 0o700, entries: map[string]*fakeDevPrepNode{
					"docker-helper": {kind: "dir", mode: 0o700, entries: map[string]*fakeDevPrepNode{
						"dev-prep": {kind: "dir", mode: 0o700, entries: map[string]*fakeDevPrepNode{
							devPrepTestOpID: node,
						}, xattrs: map[string][]byte{}},
					}, xattrs: map[string][]byte{}},
				}, xattrs: map[string][]byte{}},
			}, xattrs: map[string][]byte{}}

			before := len(fs.log)
			err := devPrepPrepare(t, fs, devPrepTestOpID, builderCategory(1))
			var refuse *devPrepRefuseError
			if !errors.As(err, &refuse) {
				t.Fatalf("want refuse-to-adopt error, got %v", err)
			}
			// No mutation: the only recorded operation is the refuse-check
			// lstat itself.
			if len(fs.log) != before+1 || !strings.HasPrefix(fs.log[before], "lstat ") {
				t.Fatalf("refuse-to-adopt must not mutate:\n%s", strings.Join(fs.log[before:], "\n"))
			}
		})
	}
}

// TestDevPrepFailureInjectionCleanup proves every mutation failure after
// the operation directory exists removes exactly the own residue and
// fails explicitly, and that a same-ID retry over the cleaned path
// proceeds. Failures before the operation directory exist leave the
// shared roots in place.
func TestDevPrepFailureInjectionCleanup(t *testing.T) {
	withDevPrepSeams(t, false, devPrepTestBuilderUID)
	opDir := devPrepOpDir()
	mutations := []struct {
		name    string
		arm     string
		afterOp bool // the op dir exists when the failure hits
	}{
		{name: "dev-prep mkdir", arm: "mkdir /var/lib/docker-helper/dev-prep", afterOp: false},
		{name: "state root ACL", arm: "setxattr system.posix_acl_access /var/lib/docker-helper", afterOp: false},
		{name: "dev-prep root ACL", arm: "setxattr system.posix_acl_access /var/lib/docker-helper/dev-prep", afterOp: false},
		{name: "op mkdir", arm: "mkdir " + opDir, afterOp: false},
		{name: "op ACL", arm: "setxattr system.posix_acl_access " + opDir, afterOp: true},
		{name: "pts mkdir", arm: "mkdir " + opDir + "/pts", afterOp: true},
		{name: "shm mkdir", arm: "mkdir " + opDir + "/shm", afterOp: true},
		{name: "mqueue mkdir", arm: "mkdir " + opDir + "/mqueue", afterOp: true},
		{name: "null mknod", arm: "mknod " + opDir + "/null", afterOp: true},
		{name: "zero mknod", arm: "mknod " + opDir + "/zero", afterOp: true},
		{name: "full mknod", arm: "mknod " + opDir + "/full", afterOp: true},
		{name: "random mknod", arm: "mknod " + opDir + "/random", afterOp: true},
		{name: "urandom mknod", arm: "mknod " + opDir + "/urandom", afterOp: true},
		{name: "tty mknod", arm: "mknod " + opDir + "/tty", afterOp: true},
		{name: "fd symlink", arm: "symlink " + opDir + "/fd", afterOp: true},
		{name: "stdin symlink", arm: "symlink " + opDir + "/stdin", afterOp: true},
		{name: "stdout symlink", arm: "symlink " + opDir + "/stdout", afterOp: true},
		{name: "stderr symlink", arm: "symlink " + opDir + "/stderr", afterOp: true},
		{name: "ptmx symlink", arm: "symlink " + opDir + "/ptmx", afterOp: true},
	}
	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			fs := newFakeDevPrepFS()
			fs.arm(tc.arm, errors.New("injected failure: "+tc.name))
			err := devPrepPrepare(t, fs, devPrepTestOpID, builderCategory(1))
			if err == nil {
				t.Fatal("injected failure must fail the preparation")
			}
			if tc.afterOp {
				// The own residue must be gone, and the cleanup must be
				// the final operation.
				if _, err := fs.resolve(opDir); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("own residue not removed after %s", tc.name)
				}
				if !strings.HasSuffix(fs.log[len(fs.log)-1], "removeall "+opDir) {
					t.Fatalf("cleanup was not the final operation:\n%s", strings.Join(fs.log[len(fs.log)-3:], "\n"))
				}
				// A same-ID retry over the cleaned path succeeds.
				if err := devPrepPrepare(t, fs, devPrepTestOpID, builderCategory(1)); err != nil {
					t.Fatalf("same-ID retry after cleanup failed: %v", err)
				}
			} else {
				if _, err := fs.resolve(opDir); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("op dir exists despite a pre-op failure (%s)", tc.name)
				}
			}
		})
	}
}

// TestDevPrepFailureBeforeOpDirLeavesSharedRoots proves that failures
// before the operation directory exists never remove the shared roots.
func TestDevPrepFailureBeforeOpDirLeavesSharedRoots(t *testing.T) {
	withDevPrepSeams(t, true, devPrepTestBuilderUID)
	fs := newFakeDevPrepFS()
	fs.arm("restorecon /var/lib/docker-helper/dev-prep", errors.New("injected restorecon failure"))
	err := devPrepPrepare(t, fs, devPrepTestOpID, builderCategory(1))
	if err == nil || !strings.Contains(err.Error(), "restorecon") {
		t.Fatalf("restorecon failure must fail explicitly, got %v", err)
	}
	if _, err := fs.resolve("/var/lib/docker-helper/dev-prep"); err != nil {
		t.Fatalf("the shared dev-prep root must not be removed on failure: %v", err)
	}
}

// TestDevPrepInvalidInputs proves the typed-input refusals and that they
// never mutate.
func TestDevPrepInvalidInputs(t *testing.T) {
	withDevPrepSeams(t, false, devPrepTestBuilderUID)
	for _, tc := range []struct {
		name     string
		opID     string
		category builderCategory
	}{
		{name: "non-canonical op id", opID: "OP_UPPER", category: builderCategory(1)},
		{name: "never-issued category", opID: devPrepTestOpID, category: builderCategory(0)},
		{name: "out-of-pool category", opID: devPrepTestOpID, category: builderCategory(1024)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := newFakeDevPrepFS()
			before := len(fs.log)
			if err := devPrepPrepare(t, fs, tc.opID, tc.category); err == nil {
				t.Fatal("invalid input must be refused")
			}
			if len(fs.log) != before {
				t.Fatal("invalid inputs must not mutate")
			}
		})
	}
}

// TestDevPrepStateRootMustExist proves the preparer never creates the
// state root.
func TestDevPrepStateRootMustExist(t *testing.T) {
	withDevPrepSeams(t, false, devPrepTestBuilderUID)
	fs := newFakeDevPrepFS()
	fs.root.entries = map[string]*fakeDevPrepNode{}
	err := devPrepPrepare(t, fs, devPrepTestOpID, builderCategory(1))
	if err == nil || !strings.Contains(err.Error(), "state root") {
		t.Fatalf("a missing state root must fail explicitly, got %v", err)
	}
}

// TestDevPrepACLReapplyAfterSystemdReset proves the mandatory
// verify-and-reapply: an ACL whose mask was collapsed by a systemd chmod
// (stat 0700, entries surviving) is detected on the shared chain and
// restored to the effective 0710 by the next preparation.
func TestDevPrepACLReapplyAfterSystemdReset(t *testing.T) {
	withDevPrepSeams(t, false, devPrepTestBuilderUID)
	fs := newFakeDevPrepFS()
	if err := devPrepPrepare(t, fs, devPrepTestOpID, builderCategory(1)); err != nil {
		t.Fatalf("initial prepare failed: %v", err)
	}
	for _, dir := range []string{"/var/lib/docker-helper", "/var/lib/docker-helper/dev-prep"} {
		node := devPrepNodeAt(t, fs, dir)
		// Model the systemd reset: chmod 0700 collapses the mask to ---
		// while the entries survive.
		node.mode = 0o700
		entries, err := decodeDevPrepACL(node.xattrs[devPrepACLXattrName])
		if err != nil {
			t.Fatalf("%s: %v", dir, err)
		}
		for i := range entries {
			if entries[i].tag == posixACLMaskTag {
				entries[i].perm = 0o0
			}
		}
		reset, err := encodeDevPrepACL(entries)
		if err != nil {
			t.Fatalf("%s: encode reset ACL: %v", dir, err)
		}
		node.xattrs[devPrepACLXattrName] = reset
	}

	// A fresh preparation of a different operation re-verifies the shared
	// chain and restores both roots.
	if err := devPrepPrepare(t, fs, "op_fedcba9876543210fedcba9876543210", builderCategory(2)); err != nil {
		t.Fatalf("second prepare failed: %v", err)
	}
	for _, dir := range []string{"/var/lib/docker-helper", "/var/lib/docker-helper/dev-prep"} {
		node := devPrepNodeAt(t, fs, dir)
		got, err := decodeDevPrepACL(node.xattrs[devPrepACLXattrName])
		if err != nil {
			t.Fatalf("%s: %v", dir, err)
		}
		if !devPrepACLEqual(got, desiredDevPrepACL(devPrepTestBuilderUID)) {
			t.Fatalf("%s: ACL not restored to the desired entries", dir)
		}
		if mode := (fakeDevPrepInfo{node}).Mode().Perm(); mode != devPrepACLEffectiveMode {
			t.Fatalf("%s: effective mode %#o, want %#o", dir, mode, devPrepACLEffectiveMode)
		}
	}
}

// TestDevPrepACLEncodeDecodeRoundTrip proves the ACL binary form round
// trip and the rejection of malformed forms.
func TestDevPrepACLEncodeDecodeRoundTrip(t *testing.T) {
	want := desiredDevPrepACL(devPrepTestBuilderUID)
	raw, err := encodeDevPrepACL(want)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, err := decodeDevPrepACL(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !devPrepACLEqual(got, want) {
		t.Fatalf("round trip mismatch: got %+v want %+v", got, want)
	}
	if binary.LittleEndian.Uint16(raw[0:2]) != posixACLVersion {
		t.Fatalf("version = %#x", binary.LittleEndian.Uint16(raw[0:2]))
	}

	bad := append([]byte(nil), raw...)
	bad[0] = 0x99
	if _, err := decodeDevPrepACL(bad); err == nil {
		t.Fatal("wrong version must not decode")
	}
	if _, err := decodeDevPrepACL(raw[:len(raw)-1]); err == nil {
		t.Fatal("a truncated entry must not decode")
	}
	swapped := append([]byte(nil), raw...)
	swapped[posixACLHeaderSize] = posixACLOtherTag
	if _, err := decodeDevPrepACL(swapped); err == nil {
		t.Fatal("a duplicate singleton entry must not decode")
	}
	dup := append([]byte(nil), raw...)
	// Duplicate the named-user entry: 7 entries is a different length, so
	// instead corrupt the mask tag into a second user tag in-range order.
	dup[posixACLHeaderSize+3*posixACLEntrySize] = posixACLUserTag
	if _, err := decodeDevPrepACL(dup); err == nil {
		t.Fatal("a second named-user entry in place of the mask must not decode")
	}
}

// TestDevPrepDeviceContractMatchesPinnedRunc proves the device and
// symlink contracts against the pinned runc v1.4.3 sources:
// specconv AllowedDevices (all CharDevice, FileMode 0o666, no block
// devices, /dev/ptmx excluded from createDevices) and
// setupDevSymlinks/setupPtmx (the relative ptmx target).
func TestDevPrepDeviceContractMatchesPinnedRunc(t *testing.T) {
	type pinnedDev struct {
		path         string
		major, minor int64
	}
	pinned := []pinnedDev{
		{"/dev/null", 1, 3},
		{"/dev/random", 1, 8},
		{"/dev/full", 1, 7},
		{"/dev/tty", 5, 0},
		{"/dev/zero", 1, 5},
		{"/dev/urandom", 1, 9},
	}
	if len(devPrepDevices) != len(pinned) {
		t.Fatalf("device count = %d, want %d (the pinned AllowedDevices set)", len(devPrepDevices), len(pinned))
	}
	byPath := map[string]devPrepDevice{}
	for _, d := range devPrepDevices {
		byPath["/dev/"+d.name] = d
	}
	for _, want := range pinned {
		got, ok := byPath[want.path]
		if !ok {
			t.Fatalf("missing pinned device %s", want.path)
		}
		if int64(got.major) != want.major || int64(got.minor) != want.minor {
			t.Fatalf("%s major:minor = %d:%d, want pinned %d:%d", want.path, got.major, got.minor, want.major, want.minor)
		}
	}
	if devPrepFileMode != 0o666 {
		t.Fatalf("device FileMode = %#o, want the pinned 0o666", devPrepFileMode)
	}
	for _, link := range devPrepSymlinks {
		if link.name == "ptmx" && link.target != "pts/ptmx" {
			t.Fatalf("ptmx target = %q, want the pinned relative pts/ptmx", link.target)
		}
		if link.name == "fd" && link.target != "/proc/self/fd" {
			t.Fatalf("fd target = %q, want /proc/self/fd", link.target)
		}
	}
}

// TestDevPrepRealModesUnderUnitUmask proves the fixed modes survive the
// shipped UMask=0077: the fake applies the umask at creation, so the
// mknod'd devices start at 0600 and the mount dirs at 0700; the
// preparer's narrow verified correction must deliver 0666/0755, and with
// no umask no correction may be issued at all.
func TestDevPrepRealModesUnderUnitUmask(t *testing.T) {
	for _, tc := range []struct {
		name      string
		umask     os.FileMode
		wantChmod bool
	}{
		{name: "shipped UMask=0077", umask: 0o077, wantChmod: true},
		{name: "no umask truncation", umask: 0, wantChmod: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withDevPrepSeams(t, false, devPrepTestBuilderUID)
			fs := newFakeDevPrepFS()
			fs.umask = tc.umask
			if err := devPrepPrepare(t, fs, devPrepTestOpID, builderCategory(1)); err != nil {
				t.Fatalf("prepare failed: %v", err)
			}
			opDir := devPrepOpDir()
			for _, dev := range devPrepDevices {
				node := devPrepNodeAt(t, fs, filepath.Join(opDir, dev.name))
				if node.mode.Perm() != devPrepFileMode {
					t.Fatalf("device %s mode = %#o, want %#o", dev.name, node.mode.Perm(), devPrepFileMode)
				}
			}
			for _, name := range devPrepMountDirs {
				node := devPrepNodeAt(t, fs, filepath.Join(opDir, name))
				if node.mode.Perm() != devPrepDirMode {
					t.Fatalf("mount dir %s mode = %#o, want %#o", name, node.mode.Perm(), devPrepDirMode)
				}
			}
			chmods := 0
			for _, entry := range fs.log {
				if strings.HasPrefix(entry, "chmod "+opDir+"/") {
					chmods++
				}
			}
			if tc.wantChmod {
				// One correction per device and per mount dir — exactly
				// the nodes the umask truncated.
				if chmods != len(devPrepDevices)+len(devPrepMountDirs) {
					t.Fatalf("chmod corrections = %d, want %d", chmods, len(devPrepDevices)+len(devPrepMountDirs))
				}
			} else if chmods != 0 {
				t.Fatalf("chmod corrections = %d, want 0 when no umask truncated the modes", chmods)
			}
			// ACL-managed directories keep their effective 0710.
			for _, dir := range []string{"/var/lib/docker-helper", "/var/lib/docker-helper/dev-prep", opDir} {
				if mode := (fakeDevPrepInfo{devPrepNodeAt(t, fs, dir)}).Mode().Perm(); mode != devPrepACLEffectiveMode {
					t.Fatalf("%s effective mode = %#o, want %#o", dir, mode, devPrepACLEffectiveMode)
				}
			}
		})
	}
}

// TestDevPrepCorrectionFailureInjection proves the failure handling at
// the new permission-correction steps: an injected chmod failure is an
// explicit preparation failure and removes the own residue.
func TestDevPrepCorrectionFailureInjection(t *testing.T) {
	withDevPrepSeams(t, false, devPrepTestBuilderUID)
	opDir := devPrepOpDir()
	for _, arm := range []string{"chmod " + opDir + "/null", "chmod " + opDir + "/pts"} {
		t.Run(filepath.Base(strings.TrimPrefix(arm, "chmod "+opDir+"/")), func(t *testing.T) {
			fs := newFakeDevPrepFS()
			fs.arm(arm, errors.New("injected chmod failure"))
			err := devPrepPrepare(t, fs, devPrepTestOpID, builderCategory(1))
			if err == nil || !strings.Contains(err.Error(), "correct the umask-truncated mode") {
				t.Fatalf("chmod failure must fail explicitly, got %v", err)
			}
			if _, err := fs.resolve(opDir); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("own residue not removed after a correction failure")
			}
		})
	}
}

// TestDevPrepVerifyTreeRejectsWrongMountDirMode proves the strengthened
// strict verification: a mountpoint directory whose mode is not 0755
// fails the verification.
func TestDevPrepVerifyTreeRejectsWrongMountDirMode(t *testing.T) {
	withDevPrepSeams(t, false, devPrepTestBuilderUID)
	fs := newFakeDevPrepFS()
	if err := devPrepPrepare(t, fs, devPrepTestOpID, builderCategory(1)); err != nil {
		t.Fatalf("prepare failed: %v", err)
	}
	node := devPrepNodeAt(t, fs, filepath.Join(devPrepOpDir(), "shm"))
	node.mode = 0o700
	if err := devPrepVerifyTree(fs, devPrepOpDir(), builderCategory(1)); err == nil || !strings.Contains(err.Error(), "mount dir shm") {
		t.Fatalf("wrong mount-dir mode must fail verification, got %v", err)
	}
}

// TestDevPrepCanonicalStateRootBinding proves the canonical source-root
// contract: only the exact canonical daemon state root spelling is
// accepted; traversal and noncanonical spellings are refused before the
// first mutation, and the production binding resolves through the config
// owner's constant.
func TestDevPrepCanonicalStateRootBinding(t *testing.T) {
	withDevPrepSeams(t, false, devPrepTestBuilderUID)
	if got := getStateDirFunc(); got != daemonStateRoot {
		t.Fatalf("config state dir = %q, want the canonical %q", got, daemonStateRoot)
	}
	for _, bad := range []string{
		"",
		"var/lib/docker-helper",
		"/var/lib/docker-helper/",
		"/var/lib//docker-helper",
		"/var/lib/docker-helper/../docker-helper",
		"/var/lib/other",
		"/tmp/docker-helper",
	} {
		t.Run(bad, func(t *testing.T) {
			fs := newFakeDevPrepFS()
			before := len(fs.log)
			err := prepareTrustedDevWithSyscalls(fs, context.Background(), bad, devPrepTestOpID, builderCategory(1))
			if err == nil || !strings.Contains(err.Error(), "canonical daemon state root") {
				t.Fatalf("state dir %q must be refused, got %v", bad, err)
			}
			if len(fs.log) != before {
				t.Fatal("a noncanonical state root must be refused before any mutation")
			}
		})
	}
}

// TestDevPrepCleanupFailureReportedAndResidueRefused proves cleanup
// errors are never discarded: a failed own-residue removal is reported
// alongside the primary failure, the residue tree remains, and a same-ID
// retry into the residue is refused (no adoption).
func TestDevPrepCleanupFailureReportedAndResidueRefused(t *testing.T) {
	withDevPrepSeams(t, false, devPrepTestBuilderUID)
	opDir := devPrepOpDir()
	fs := newFakeDevPrepFS()
	fs.arm("mknod "+opDir+"/zero", errors.New("injected mknod failure"))
	fs.arm("removeall "+opDir, errors.New("injected removal failure"))

	err := devPrepPrepare(t, fs, devPrepTestOpID, builderCategory(1))
	if err == nil {
		t.Fatal("the preparation must fail")
	}
	if !strings.Contains(err.Error(), "injected mknod failure") {
		t.Fatalf("the primary failure must be preserved, got %v", err)
	}
	if !strings.Contains(err.Error(), "own-residue cleanup") {
		t.Fatalf("the cleanup failure must be reported, got %v", err)
	}
	if _, err := fs.resolve(opDir); err != nil {
		t.Fatalf("the residue tree must remain after a failed removal: %v", err)
	}

	// The same-ID retry into the residue is refused, never adopted.
	retryErr := devPrepPrepare(t, fs, devPrepTestOpID, builderCategory(1))
	var refuse *devPrepRefuseError
	if !errors.As(retryErr, &refuse) {
		t.Fatalf("the retry must refuse the residue, got %v", retryErr)
	}
}

// TestDevPrepSELinuxLabelFailureInjection proves the label write and
// read-back failures fail the preparation closed (with own-residue
// cleanup) in addition to the ordinary filesystem mutations.
func TestDevPrepSELinuxLabelFailureInjection(t *testing.T) {
	withDevPrepSeams(t, true, devPrepTestBuilderUID)
	opDir := devPrepOpDir()
	devPrepRoot := filepath.Dir(opDir)
	for _, tc := range []struct {
		name    string
		arm     string
		wantErr string
	}{
		{name: "op label write", arm: "setxattr security.selinux " + opDir, wantErr: "cannot label"},
		{name: "op label read-back", arm: "getxattr security.selinux " + opDir, wantErr: "cannot read back the label"},
		{name: "root label read-back", arm: "getxattr security.selinux " + devPrepRoot, wantErr: "cannot read the label"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := newFakeDevPrepFS()
			fs.arm(tc.arm, errors.New("injected label failure"))
			err := devPrepPrepare(t, fs, devPrepTestOpID, builderCategory(1))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("%s must fail explicitly, got %v", tc.name, err)
			}
			if _, err := fs.resolve(opDir); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("own residue not removed after %s", tc.name)
			}
		})
	}
}
