package main

// builder_provision_test.go pins the Phase 3 categorized provisioning
// (G32 r3 §4.2): the exact context matrix, the mandatory set-then-read
// ordering strictly before every launch step, the exact-equality
// read-back, the fail-closed failure semantics through the existing
// failed-start owner, the record-only category source, and the
// non-SELinux no-op branch.

import (
	"errors"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"
)

// provisionLogEntry is one observed provisioning or spawn event.
type provisionLogEntry struct {
	kind  string // "set", "get", "spawn"
	path  string
	value string
}

// provisionFixture installs the logging xattr seams over the current
// command seam. setErr/getErr/getOverride key forced failures and forced
// read-back values by path; the stored set values back the read-back
// seam. The seams restore on cleanup (package-global seams: no
// t.Parallel in these tests).
type provisionFixture struct {
	mu          sync.Mutex
	log         []provisionLogEntry
	stored      map[string]string
	setErr      map[string]error
	getErr      map[string]error
	getOverride map[string]string
}

func newProvisionFixture(t *testing.T) *provisionFixture {
	t.Helper()
	f := &provisionFixture{
		stored:      map[string]string{},
		setErr:      map[string]error{},
		getErr:      map[string]error{},
		getOverride: map[string]string{},
	}
	origSet, origGet := builderSetObjectXattr, builderGetObjectXattr
	builderSetObjectXattr = func(path, value string) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.log = append(f.log, provisionLogEntry{kind: "set", path: path, value: value})
		if err := f.setErr[path]; err != nil {
			return err
		}
		f.stored[path] = value
		return nil
	}
	builderGetObjectXattr = func(path string) (string, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if err := f.getErr[path]; err != nil {
			f.log = append(f.log, provisionLogEntry{kind: "get", path: path})
			return "", err
		}
		value := f.getOverride[path]
		if value == "" {
			value = f.stored[path]
		}
		f.log = append(f.log, provisionLogEntry{kind: "get", path: path, value: value})
		return value, nil
	}
	t.Cleanup(func() { builderSetObjectXattr, builderGetObjectXattr = origSet, origGet })
	return f
}

// observeCommandCreation wraps the CURRENT command seam (install AFTER
// the fake leader) and records every production command creation as a
// spawn event.
func (f *provisionFixture) observeCommandCreation(t *testing.T) {
	t.Helper()
	orig := builderNewRootlessKitCommand
	builderNewRootlessKitCommand = func(opID, rtDir, stDir string, env []string) *exec.Cmd {
		f.mu.Lock()
		f.log = append(f.log, provisionLogEntry{kind: "spawn", path: opID})
		f.mu.Unlock()
		return orig(opID, rtDir, stDir, env)
	}
	t.Cleanup(func() { builderNewRootlessKitCommand = orig })
}

func (f *provisionFixture) entries() []provisionLogEntry {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]provisionLogEntry(nil), f.log...)
}

// seamLSMBackend forces the detected MAC backend for the test.
func seamLSMBackend(t *testing.T, backend LSMBackend) {
	t.Helper()
	orig := detectLSM
	detectLSM = func() (LSMBackend, error) { return backend, nil }
	t.Cleanup(func() { detectLSM = orig })
}

// TestBuilderObjectContextCanonical is the context-builder gate: the
// exact canonical object contexts for the pool's edges, built from the
// fixed identity/role, the expected type, and the record's category.
func TestBuilderObjectContextCanonical(t *testing.T) {
	if got := builderObjectContext(builderStateObjectType, builderCategory(1)); got != "system_u:object_r:docker_helper_builder_state_t:s0:c1" {
		t.Errorf("state c1 context = %q", got)
	}
	if got := builderObjectContext(builderRuntimeObjectType, builderCategory(1023)); got != "system_u:object_r:docker_helper_builder_runtime_t:s0:c1023" {
		t.Errorf("runtime c1023 context = %q", got)
	}
	// Type separation in the matrix: the three state paths carry the
	// state type, the runtime path carries the runtime type, and each
	// top-level path appears exactly once.
	const opID = "op_0123456789abcdef0123456789abcdef"
	paths := builderProvisionedPaths(opID, opRuntimeDir(opID), opStateDir(opID))
	if len(paths) != 4 {
		t.Fatalf("provisioning matrix has %d entries, want 4", len(paths))
	}
	seen := map[string]bool{}
	for _, p := range paths {
		if seen[p.path] {
			t.Errorf("duplicate provisioning entry: %s", p.path)
		}
		seen[p.path] = true
		want := builderRuntimeObjectType
		if p.rel != "runtime" {
			want = builderStateObjectType
		}
		if p.objectType != want {
			t.Errorf("provisioning entry %s carries type %s, want %s", p.rel, p.objectType, want)
		}
	}
}

// TestBuilderProvisioningSuccessOrderContextsBeforeSpawn proves the
// successful provisioning: all four required paths receive their exact
// expected contexts (type + the record's category), each in set-then-get
// order, and every provisioning event strictly precedes the command
// creation; the launch continues only after the last verification.
func TestBuilderProvisioningSuccessOrderContextsBeforeSpawn(t *testing.T) {
	m, _, _ := processTestManager(t)
	seamCA(t)
	seamLSMBackend(t, LSMSELinux)
	fakeLeaderSeam(t, true)
	f := newProvisionFixture(t)
	f.observeCommandCreation(t)

	opID := "op_0123456789abcdef0123456789abcdef"
	paths := builderProvisionedPaths(opID, opRuntimeDir(opID), opStateDir(opID))
	if _, ok := builderManagerCategoryOf(t, m, opID); ok {
		t.Fatal("setup self-test: the record exists before admission")
	}
	respCh := make(chan string, 1)
	go func() { respCh <- m.start(opID, nil) }()
	if !waitInstance(t, m, opID, true) {
		t.Fatal("START did not reserve")
	}
	recordCategory, _ := builderManagerCategoryOf(t, m, opID)
	if recordCategory != builderCategory(1) {
		t.Fatalf("record category = %s, want c1 (the context authority is the record)", recordCategory)
	}
	bindFakeBuildkitdSocket(t, opID)
	if resp := <-respCh; resp != builderManagerRespOK {
		t.Fatalf("START = %q, want OK", resp)
	}

	wantOrder := []struct {
		kind  string
		entry int
		typ   string
	}{
		{"set", 0, builderStateObjectType},
		{"get", 0, builderStateObjectType},
		{"set", 1, builderStateObjectType},
		{"get", 1, builderStateObjectType},
		{"set", 2, builderStateObjectType},
		{"get", 2, builderStateObjectType},
		{"set", 3, builderRuntimeObjectType},
		{"get", 3, builderRuntimeObjectType},
	}
	entries := f.entries()
	if len(entries) != len(wantOrder)+1 {
		t.Fatalf("observed %d events, want %d provisioning events + 1 spawn", len(entries), len(wantOrder))
	}
	// Every provisioning event precedes the spawn; the spawn is last.
	for i, e := range entries[:len(entries)-1] {
		if e.kind == "spawn" {
			t.Fatalf("spawn event at position %d precedes the last verification", i)
		}
	}
	if last := entries[len(entries)-1]; last.kind != "spawn" {
		t.Fatalf("last event = %q at %q, want the spawn after full verification", last.kind, last.path)
	}
	for i, w := range wantOrder {
		e := entries[i]
		if e.kind != w.kind {
			t.Fatalf("event %d kind = %q, want %q", i, e.kind, w.kind)
		}
		if e.path != paths[w.entry].path {
			t.Fatalf("event %d path = %q, want the matrix entry %d (%q)", i, e.path, w.entry, paths[w.entry].path)
		}
		if want := builderObjectContext(w.typ, recordCategory); e.value != want {
			t.Fatalf("event %d value = %q, want the record's exact context %q", i, e.value, want)
		}
	}
}

// provisionFailureCase drives one failing provisioning path to the
// fail-closed assertion set: internal refusal, no spawn, the existing
// convergence (record removed, created tree removed), and the category
// released only through that record removal.
func provisionFailureCase(t *testing.T, opID string, force func(f *provisionFixture)) {
	t.Helper()
	m, _, _ := processTestManager(t)
	seamCA(t)
	seamLSMBackend(t, LSMSELinux)
	f := newProvisionFixture(t)
	force(f)
	// The failing op must never reach command creation; later
	// admissions (the post-failure reuse proof) launch normally.
	orig := builderNewRootlessKitCommand
	builderNewRootlessKitCommand = func(seamOpID, rtDir, stDir string, env []string) *exec.Cmd {
		_ = rtDir
		_ = stDir
		_ = env
		if seamOpID == opID {
			t.Error("spawn reached despite the provisioning failure")
		}
		return exec.Command("sh", "-c", boundedSleepScript())
	}
	t.Cleanup(func() { builderNewRootlessKitCommand = orig })

	if resp := m.start(opID, nil); resp != builderManagerRespInternal {
		t.Fatalf("START = %q, want internal (provisioning failure)", resp)
	}
	if !waitInstance(t, m, opID, false) {
		t.Fatal("the failed provisioning kept the record retained")
	}
	assertDirsAbsentAt(t, opID)
	// The category released exactly at the record removal: the next
	// admission takes c1 again.
	op2 := "op_fedcba9876543210fedcba9876543210"
	if category := startWithCategory(t, m, op2); category != builderCategory(1) {
		t.Fatalf("post-failure admission bound %s, want c1", category)
	}
}

// provisionMatrixPaths computes the provisioning matrix entries against
// the test-scoped roots.
func provisionMatrixPaths(opID string) []builderProvisionedPath {
	return builderProvisionedPaths(opID, opRuntimeDir(opID), opStateDir(opID))
}

// TestBuilderProvisioningMismatchFailsClosed: a setxattr that succeeds
// but verifies wrong (read-back returns a different type) fails the START
// before the spawn.
func TestBuilderProvisioningMismatchFailsClosed(t *testing.T) {
	opID := "op_0123456789abcdef0123456789abcdef"
	provisionFailureCase(t, opID, func(f *provisionFixture) {
		f.getOverride[provisionMatrixPaths(opID)[2].path] = builderObjectContext(builderRuntimeObjectType, builderCategory(1))
	})
}

// TestBuilderProvisioningSetFailureFailsClosed: a setxattr error on the
// first path fails the START before the spawn; the convergence removes
// the reservation and the created tree; the category stays held until
// that removal.
func TestBuilderProvisioningSetFailureFailsClosed(t *testing.T) {
	opID := "op_0123456789abcdef0123456789abcdef"
	provisionFailureCase(t, opID, func(f *provisionFixture) {
		f.setErr[provisionMatrixPaths(opID)[0].path] = errors.New("EOPNOTSUPP")
	})
}

// TestBuilderProvisioningGetFailureFailsClosed: a read-back error fails
// the START before the spawn, with the same convergence.
func TestBuilderProvisioningGetFailureFailsClosed(t *testing.T) {
	opID := "op_0123456789abcdef0123456789abcdef"
	provisionFailureCase(t, opID, func(f *provisionFixture) {
		f.getErr[provisionMatrixPaths(opID)[1].path] = errors.New("ENODATA")
	})
}

// TestBuilderProvisioningPartialFailureCleansMixedTree: the first paths
// are already relabeled when a later one fails; the failed-start
// convergence removes the mixed relabeled/unrelabeled tree and the
// category does not leak or reuse prematurely.
func TestBuilderProvisioningPartialFailureCleansMixedTree(t *testing.T) {
	opID := "op_0123456789abcdef0123456789abcdef"
	provisionFailureCase(t, opID, func(f *provisionFixture) {
		f.setErr[provisionMatrixPaths(opID)[2].path] = errors.New("EPERM")
	})
	// The mixed tree was fully converged: both op trees are absent and
	// the first two successful relabels left no residue.
	for _, rel := range []string{opRuntimeDir(opID), opStateDir(opID)} {
		if _, err := os.Lstat(rel); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("relabeled residue survived: %s: %v", rel, err)
		}
	}
}

// TestBuilderProvisioningGateDetectionErrorFailsClosed: an indeterminable
// MAC backend fails the START closed — the launch must never proceed
// unlabeled when the gate cannot decide.
func TestBuilderProvisioningGateDetectionErrorFailsClosed(t *testing.T) {
	m, _, _ := processTestManager(t)
	seamCA(t)
	orig := detectLSM
	detectLSM = func() (LSMBackend, error) { return LSMNone, errors.New("indeterminable backend") }
	t.Cleanup(func() { detectLSM = orig })
	f := newProvisionFixture(t)

	opID := "op_0123456789abcdef0123456789abcdef"
	if resp := m.start(opID, nil); resp != builderManagerRespInternal {
		t.Fatalf("START = %q, want internal (detection error)", resp)
	}
	if !waitInstance(t, m, opID, false) {
		t.Fatal("the detection-error START kept the record")
	}
	assertDirsAbsentAt(t, opID)
	if n := len(f.entries()); n != 0 {
		t.Fatalf("detection-error START touched the xattr seams: %d events", n)
	}
}

// TestBuilderProvisioningSkippedOnNonSELinux proves the non-SELinux
// branch: the xattr seams are never invoked, and the existing unlabeled
// launch behavior is preserved end to end.
func TestBuilderProvisioningSkippedOnNonSELinux(t *testing.T) {
	m, _, _ := processTestManager(t)
	seamCA(t)
	seamLSMBackend(t, LSMNone)
	fakeLeaderSeam(t, true)
	f := newProvisionFixture(t)

	opID := "op_0123456789abcdef0123456789abcdef"
	respCh := make(chan string, 1)
	go func() { respCh <- m.start(opID, nil) }()
	if !waitInstance(t, m, opID, true) {
		t.Fatal("START did not reserve")
	}
	bindFakeBuildkitdSocket(t, opID)
	select {
	case resp := <-respCh:
		if resp != builderManagerRespOK {
			t.Fatalf("START = %q, want OK", resp)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("START did not converge")
	}
	if n := len(f.entries()); n != 0 {
		t.Fatalf("non-SELinux START touched the xattr seams: %d events", n)
	}
	if category, _ := builderManagerCategoryOf(t, m, opID); category != builderCategory(1) {
		t.Fatalf("record category = %s, want c1 (record mechanics unchanged on non-SELinux)", category)
	}
}
