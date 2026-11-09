//go:build linux

package main

// wrapper_inspection_linux_test.go proves the enforced readiness boundary
// of the buildkit-runc wrapper with injected seams: the canonical bundle
// grammar, the kernel-trust-only own-context derivation, and the
// fail-closed fixed-entry inspection of a tree prepared by the real
// production preparer. No test requires root, SELinux, or real xattrs.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const wrapperTestBundleID = "s4pkwc8u4nxm7ihg20z5xu82j"
const wrapperTestOpID = "op_0123456789abcdef0123456789abcdef"

// fakeWrapperOwnContext is the injectable own-context reader: fixed raw
// bytes, optionally a read failure.
type fakeWrapperOwnContext struct {
	raw []byte
	err error
}

func (f fakeWrapperOwnContext) readOwnContext() ([]byte, error) { return f.raw, f.err }

// wrapperOwnContextRaw renders the raw procattr form of one own context
// with the given terminal framing ("" for none).
func wrapperOwnContextRaw(category builderCategory, terminal string) []byte {
	return []byte("system_u:system_r:" + wrapperOwnDomain + ":s0:" + category.String() + terminal)
}

// wrapperBundlePath renders the measured canonical executor bundle path.
func wrapperBundlePath(opID, bundle string) string {
	return builderStateRoot + "/ops/" + opID + "/root/runc-native/executor/" + bundle
}

// wrapperPrepareFixture builds a complete, verified prepared tree for
// opID at the given category through the real production preparer, on a
// fake filesystem whose /proc/kcore presence is controlled by the caller.
func wrapperPrepareFixture(t *testing.T, opID string, category builderCategory, kcore bool) *fakeDevPrepFS {
	t.Helper()
	withDevPrepSeams(t, true, devPrepTestBuilderUID)
	fs := newFakeDevPrepFS()
	if kcore {
		fs.root.entries["proc"] = &fakeDevPrepNode{kind: "dir", mode: 0o555, entries: map[string]*fakeDevPrepNode{
			"kcore": {kind: "file", mode: 0o444, xattrs: map[string][]byte{}},
		}, xattrs: map[string][]byte{}}
	}
	if err := prepareTrustedDevWithSyscalls(fs, context.Background(), "/var/lib/docker-helper", opID, category); err != nil {
		t.Fatalf("fixture preparation failed: %v", err)
	}
	return fs
}

// TestWrapperBundleOpIDGrammar proves the canonical executor-bundle
// derivation: only the exact canonical layout yields the operation id,
// and every relative, traversal, ambiguous, or malformed spelling is
// refused. The grammar follows the builderStateRoot owner, not a literal.
func TestWrapperBundleOpIDGrammar(t *testing.T) {
	if got := builderStateRoot; got != "/var/lib/docker-helper-builder" {
		t.Fatalf("builder state root = %q, want the canonical production constant", got)
	}
	for _, tc := range []struct {
		name       string
		path       string
		wantOpID   string
		wantRefuse bool
	}{
		{name: "canonical", path: wrapperBundlePath(wrapperTestOpID, wrapperTestBundleID), wantOpID: wrapperTestOpID},
		{name: "relative", path: "ops/" + wrapperTestOpID + "/root/runc-native/executor/" + wrapperTestBundleID, wantRefuse: true},
		{name: "empty", path: "", wantRefuse: true},
		{name: "traversal to a sibling op", path: wrapperBundlePath(wrapperTestOpID, wrapperTestBundleID[:8]+"/../"+wrapperTestBundleID), wantRefuse: true},
		{name: "doubled separator", path: builderStateRoot + "/ops//" + wrapperTestOpID + "/root/runc-native/executor/" + wrapperTestBundleID, wantRefuse: true},
		{name: "trailing slash", path: wrapperBundlePath(wrapperTestOpID, wrapperTestBundleID) + "/", wantRefuse: true},
		{name: "extra depth under the bundle", path: wrapperBundlePath(wrapperTestOpID, wrapperTestBundleID) + "/rootfs", wantRefuse: true},
		{name: "wrong middle segment", path: builderStateRoot + "/ops/" + wrapperTestOpID + "/root/runc/executor/" + wrapperTestBundleID, wantRefuse: true},
		{name: "wrong state root", path: "/var/lib/other/ops/" + wrapperTestOpID + "/root/runc-native/executor/" + wrapperTestBundleID, wantRefuse: true},
		{name: "ops placeholder not a segment", path: builderStateRoot + "/opsop/" + wrapperTestOpID + "/root/runc-native/executor/" + wrapperTestBundleID, wantRefuse: true},
		{name: "non-canonical op id", path: wrapperBundlePath("OP_0123456789ABCDEF0123456789ABCDEF", wrapperTestBundleID), wantRefuse: true},
		{name: "op id without the prefix", path: wrapperBundlePath("0123456789abcdef0123456789abcdef", wrapperTestBundleID), wantRefuse: true},
		{name: "op id shortened", path: wrapperBundlePath("op_0123456789abcdef", wrapperTestBundleID), wantRefuse: true},
		{name: "dot bundle", path: wrapperBundlePath(wrapperTestOpID, "."), wantRefuse: true},
		{name: "dot-dot bundle", path: wrapperBundlePath(wrapperTestOpID, ".."), wantRefuse: true},
		{name: "uppercase bundle", path: wrapperBundlePath(wrapperTestOpID, "S4PKWC8U4NXM7IHG20Z5XU82J"), wantRefuse: true},
		{name: "short bundle", path: wrapperBundlePath(wrapperTestOpID, "s4pkwc8u4nxm7ihg20z5xu82"), wantRefuse: true},
		{name: "long bundle", path: wrapperBundlePath(wrapperTestOpID, "s4pkwc8u4nxm7ihg20z5xu82jj"), wantRefuse: true},
		{name: "punctuated bundle", path: wrapperBundlePath(wrapperTestOpID, "s4pkwc8u4nxm7ihg20z5xu82j."), wantRefuse: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opID, err := wrapperBundleOpID(tc.path)
			if tc.wantRefuse {
				if err == nil {
					t.Fatalf("bundle path %q must be refused", tc.path)
				}
				return
			}
			if err != nil {
				t.Fatalf("canonical bundle path refused: %v", err)
			}
			if opID != tc.wantOpID {
				t.Fatalf("derived op id = %q, want %q", opID, tc.wantOpID)
			}
		})
	}

	// The grammar is bound to the builderStateRoot owner: with a
	// different (test) root, the canonical spelling under that root is
	// accepted and the production spelling is no longer canonical.
	origRoot := builderStateRoot
	builderStateRoot = "/var/lib/docker-helper-builder-next"
	t.Cleanup(func() { builderStateRoot = origRoot })
	if opID, err := wrapperBundleOpID(wrapperBundlePath(wrapperTestOpID, wrapperTestBundleID)); err != nil || opID != wrapperTestOpID {
		t.Fatalf("derivation must follow the builderStateRoot owner, got %q, %v", opID, err)
	}
	if _, err := wrapperBundleOpID(builderStateRoot[:len(builderStateRoot)-len("-next")] + "/ops/" + wrapperTestOpID + "/root/runc-native/executor/" + wrapperTestBundleID); err == nil {
		t.Fatal("the production root spelling must not stay canonical under a different owner value")
	}
}

// TestWrapperOwnContextCategory proves the kernel-trust-only own-category
// derivation: both observed live terminal framings (newline, NUL) and the
// bare form are accepted, and empty, embedded-terminal, wrong-shape,
// wrong-domain, and non-canonical-category values are refused.
func TestWrapperOwnContextCategory(t *testing.T) {
	for _, tc := range []struct {
		name      string
		raw       []byte
		want      builderCategory
		wantText  string
		wantValid bool
	}{
		{name: "newline terminal (the g26 probe encoding)", raw: wrapperOwnContextRaw(7, "\n"), want: 7, wantValid: true},
		{name: "NUL terminal (the C3 capture encoding)", raw: wrapperOwnContextRaw(7, "\x00"), want: 7, wantValid: true},
		{name: "bare context", raw: wrapperOwnContextRaw(1023, ""), want: 1023, wantValid: true},
		{name: "empty", raw: nil, wantText: "empty"},
		{name: "NUL only", raw: []byte("\x00"), wantText: "empty"},
		{name: "double newline terminal", raw: wrapperOwnContextRaw(7, "\n\n"), wantText: "embedded terminal"},
		{name: "newline then NUL terminal", raw: wrapperOwnContextRaw(7, "\n\x00"), wantText: "embedded terminal"},
		{name: "embedded NUL", raw: append(wrapperOwnContextRaw(7, "")[:len(wrapperOwnContextRaw(7, ""))-1], 0, '7'), wantText: "embedded terminal"},
		{name: "wrong shape", raw: []byte("system_u:system_r:" + wrapperOwnDomain), wantText: "user:role:type:sensitivity:category"},
		{name: "uncategorized process context", raw: []byte("system_u:system_r:" + wrapperOwnDomain + ":s0"), wantText: "user:role:type:sensitivity:category"},
		{name: "extra field", raw: []byte("system_u:system_r:" + wrapperOwnDomain + ":s0:c7:x"), wantText: "user:role:type:sensitivity:category"},
		{name: "wrong domain", raw: []byte("system_u:system_r:docker_helper_t:s0:c7"), wantText: "own process context type"},
		{name: "c0", raw: []byte("system_u:system_r:" + wrapperOwnDomain + ":s0:c0"), wantText: "canonical pool category"},
		{name: "out of pool", raw: []byte("system_u:system_r:" + wrapperOwnDomain + ":s0:c1024"), wantText: "canonical pool category"},
		{name: "leading zero", raw: []byte("system_u:system_r:" + wrapperOwnDomain + ":s0:c07"), wantText: "canonical pool category"},
		{name: "category set", raw: []byte("system_u:system_r:" + wrapperOwnDomain + ":s0:c1,c2"), wantText: "canonical pool category"},
		{name: "category range", raw: []byte("system_u:system_r:" + wrapperOwnDomain + ":s0:c1.c3"), wantText: "canonical pool category"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := wrapperOwnContextCategory(tc.raw)
			if !tc.wantValid {
				if err == nil {
					t.Fatalf("raw context %q must be refused", tc.raw)
				}
				if tc.wantText != "" && !strings.Contains(err.Error(), tc.wantText) {
					t.Fatalf("refusal %q must name %q", err, tc.wantText)
				}
				return
			}
			if err != nil {
				t.Fatalf("own context refused: %v", err)
			}
			if got != tc.want {
				t.Fatalf("derived category = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestWrapperInspectPreparedDevAccepts proves the inspection accepts a
// tree prepared by the real production preparer — with the conditional
// core symlink absent and present — using only entry-metadata reads
// (lstat/getxattr; no readdir, no mutation, no device open).
func TestWrapperInspectPreparedDevAccepts(t *testing.T) {
	for _, tc := range []struct {
		name  string
		kcore bool
	}{
		{name: "core absent (the expected steady state)", kcore: false},
		{name: "core present", kcore: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := wrapperPrepareFixture(t, wrapperTestOpID, 7, tc.kcore)
			before := len(fs.log)
			if err := wrapperInspectPreparedDev(fs, devPrepOpDir(wrapperTestOpID), 7); err != nil {
				t.Fatalf("the prepared tree must be accepted: %v", err)
			}
			for _, entry := range fs.log[before:] {
				if !strings.HasPrefix(entry, "lstat ") && !strings.HasPrefix(entry, "getxattr ") {
					t.Fatalf("the inspection performed a non-read operation: %q\nall:\n%s", entry, strings.Join(fs.log[before:], "\n"))
				}
			}
		})
	}
}

// TestWrapperInspectPreparedDevRefusals proves every fail-closed refusal
// of the fixed-entry inspection: absent and non-directory trees, a
// missing, malformed, or category-inconsistent label, every fixed-entry
// family's missing member and wrong inode type, the conditional core's
// wrong shape, and injected inspection-syscall failures.
func TestWrapperInspectPreparedDevRefusals(t *testing.T) {
	opDir := devPrepOpDir(wrapperTestOpID)
	mutations := []struct {
		name     string
		mutate   func(t *testing.T, fs *fakeDevPrepFS)
		arm      string
		wantText string
	}{
		{name: "absent tree", wantText: "is absent", mutate: func(t *testing.T, fs *fakeDevPrepFS) {
			parent, err := fs.resolve(filepath.Dir(opDir))
			if err != nil {
				t.Fatalf("fixture: %v", err)
			}
			delete(parent.entries, filepath.Base(opDir))
		}},
		{name: "tree is a symlink", wantText: "is not a directory", mutate: func(t *testing.T, fs *fakeDevPrepFS) {
			parent, err := fs.resolve(filepath.Dir(opDir))
			if err != nil {
				t.Fatalf("fixture: %v", err)
			}
			parent.entries[filepath.Base(opDir)] = &fakeDevPrepNode{kind: "symlink", target: "/etc", xattrs: map[string][]byte{}}
		}},
		{name: "label of a foreign category", wantText: "category-inconsistent", mutate: func(t *testing.T, fs *fakeDevPrepFS) {
			node, err := fs.resolve(opDir)
			if err != nil {
				t.Fatalf("fixture: %v", err)
			}
			node.xattrs["security.selinux"] = []byte(builderObjectContext(builderDevPrepObjectType, 8))
		}},
		{name: "label missing", wantText: "cannot read the label", mutate: func(t *testing.T, fs *fakeDevPrepFS) {
			node, err := fs.resolve(opDir)
			if err != nil {
				t.Fatalf("fixture: %v", err)
			}
			delete(node.xattrs, "security.selinux")
		}},
		{name: "label not a context", wantText: "is not a context", mutate: func(t *testing.T, fs *fakeDevPrepFS) {
			node, err := fs.resolve(opDir)
			if err != nil {
				t.Fatalf("fixture: %v", err)
			}
			node.xattrs["security.selinux"] = []byte("gar\x00bage\x00")
		}},
		{name: "mount dir missing", wantText: "incomplete: mount dir shm is missing", mutate: func(t *testing.T, fs *fakeDevPrepFS) {
			node, err := fs.resolve(opDir)
			if err != nil {
				t.Fatalf("fixture: %v", err)
			}
			delete(node.entries, "shm")
		}},
		{name: "device missing", wantText: "incomplete: device zero is missing", mutate: func(t *testing.T, fs *fakeDevPrepFS) {
			node, err := fs.resolve(opDir)
			if err != nil {
				t.Fatalf("fixture: %v", err)
			}
			delete(node.entries, "zero")
		}},
		{name: "symlink missing", wantText: "incomplete: symlink ptmx is missing", mutate: func(t *testing.T, fs *fakeDevPrepFS) {
			node, err := fs.resolve(opDir)
			if err != nil {
				t.Fatalf("fixture: %v", err)
			}
			delete(node.entries, "ptmx")
		}},
		{name: "mount dir wrong type", wantText: "mount dir pts does not have the required inode type", mutate: func(t *testing.T, fs *fakeDevPrepFS) {
			node, err := fs.resolve(opDir)
			if err != nil {
				t.Fatalf("fixture: %v", err)
			}
			node.entries["pts"] = &fakeDevPrepNode{kind: "file", mode: 0o755, xattrs: map[string][]byte{}}
		}},
		{name: "device wrong type", wantText: "device null does not have the required inode type", mutate: func(t *testing.T, fs *fakeDevPrepFS) {
			node, err := fs.resolve(opDir)
			if err != nil {
				t.Fatalf("fixture: %v", err)
			}
			node.entries["null"] = &fakeDevPrepNode{kind: "dir", mode: 0o755, entries: map[string]*fakeDevPrepNode{}, xattrs: map[string][]byte{}}
		}},
		{name: "symlink wrong type", wantText: "symlink fd does not have the required inode type", mutate: func(t *testing.T, fs *fakeDevPrepFS) {
			node, err := fs.resolve(opDir)
			if err != nil {
				t.Fatalf("fixture: %v", err)
			}
			node.entries["fd"] = &fakeDevPrepNode{kind: "file", mode: 0o644, xattrs: map[string][]byte{}}
		}},
		{name: "core wrong type", wantText: "core entry is not a symlink", mutate: func(t *testing.T, fs *fakeDevPrepFS) {
			fs.root.entries["proc"] = &fakeDevPrepNode{kind: "dir", mode: 0o555, entries: map[string]*fakeDevPrepNode{
				"kcore": {kind: "file", mode: 0o444, xattrs: map[string][]byte{}},
			}, xattrs: map[string][]byte{}}
			if err := prepareTrustedDevWithSyscalls(fs, context.Background(), "/var/lib/docker-helper", "op_fedcba9876543210fedcba9876543210", 9); err != nil {
				t.Fatalf("fixture: %v", err)
			}
			node, err := fs.resolve(opDir)
			if err != nil {
				t.Fatalf("fixture: %v", err)
			}
			node.entries["core"] = &fakeDevPrepNode{kind: "dir", mode: 0o755, entries: map[string]*fakeDevPrepNode{}, xattrs: map[string][]byte{}}
		}},
		{name: "entry lstat failure", arm: "lstat " + opDir + "/null", wantText: "cannot inspect null", mutate: func(t *testing.T, fs *fakeDevPrepFS) {}},
		{name: "label getxattr failure", arm: "getxattr security.selinux " + opDir, wantText: "cannot read the label", mutate: func(t *testing.T, fs *fakeDevPrepFS) {}},
		{name: "tree lstat failure", arm: "lstat " + opDir, wantText: "cannot inspect the prepared tree", mutate: func(t *testing.T, fs *fakeDevPrepFS) {}},
	}
	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			fs := wrapperPrepareFixture(t, wrapperTestOpID, 7, false)
			tc.mutate(t, fs)
			if tc.arm != "" {
				fs.arm(tc.arm, errors.New("injected inspection failure"))
			}
			err := wrapperInspectPreparedDev(fs, opDir, 7)
			var refuse *wrapperRefuseError
			if !errors.As(err, &refuse) {
				t.Fatalf("want a typed refusal, got %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantText) {
				t.Fatalf("refusal %q must name %q", err, tc.wantText)
			}
		})
	}
}

// TestWrapperInspectDevPrepEndToEnd proves the full enforced sequence of
// one wrapper invocation through the production seams: a canonical bundle
// path, a live-shaped own context, and a real prepared tree are accepted,
// and every corrupted input is a typed refusal — including a
// category-inconsistent tree whose MCS rows would also deny the consume
// (the refusal makes it loud and immediate).
func TestWrapperInspectDevPrepEndToEnd(t *testing.T) {
	fs := wrapperPrepareFixture(t, wrapperTestOpID, 7, false)
	reader := fakeWrapperOwnContext{raw: wrapperOwnContextRaw(7, "\n")}
	bundlePath := wrapperBundlePath(wrapperTestOpID, wrapperTestBundleID)

	if err := wrapperInspectDevPrepWithSeams(reader, fs, bundlePath); err != nil {
		t.Fatalf("the ready invocation must be accepted: %v", err)
	}

	for _, tc := range []struct {
		name     string
		reader   fakeWrapperOwnContext
		bundle   string
		wantText string
	}{
		{
			name:     "non-canonical bundle path",
			reader:   reader,
			bundle:   "/tmp/somewhere",
			wantText: "not a canonical executor bundle",
		},
		{
			name:     "own-context read failure",
			reader:   fakeWrapperOwnContext{err: os.ErrPermission},
			bundle:   bundlePath,
			wantText: "cannot read the own process context",
		},
		{
			name:     "own context of another domain",
			reader:   fakeWrapperOwnContext{raw: []byte("system_u:system_r:docker_helper_t:s0:c7\n")},
			bundle:   bundlePath,
			wantText: "own process context type",
		},
		{
			name:     "own context of another category",
			reader:   fakeWrapperOwnContext{raw: wrapperOwnContextRaw(9, "\x00")},
			bundle:   bundlePath,
			wantText: "category-inconsistent",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := wrapperInspectDevPrepWithSeams(tc.reader, fs, tc.bundle)
			var refuse *wrapperRefuseError
			if !errors.As(err, &refuse) {
				t.Fatalf("want a typed refusal, got %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantText) {
				t.Fatalf("refusal %q must name %q", err, tc.wantText)
			}
		})
	}
}
