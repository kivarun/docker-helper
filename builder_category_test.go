package main

// builder_category_test.go pins the Phase 2 category lifecycle invariants
// (G32 r3 §4.1): one canonical parser/formatter, lowest-free allocation
// under the manager lock, binding at admission, retention through the
// whole non-terminal lifecycle, and release only at the terminal record
// removal.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestBuilderCategoryParseFormat is the canonical representation gate:
// exactly c plus decimal digits, no leading zero, inside the fixed
// production pool; every alternate or decorated spelling is invalid, and
// the formatter is the single canonical spelling.
func TestBuilderCategoryParseFormat(t *testing.T) {
	valid := map[string]builderCategory{
		"c1":    builderCategory(1),
		"c2":    builderCategory(2),
		"c9":    builderCategory(9),
		"c1023": builderCategory(1023),
	}
	for text, want := range valid {
		got, ok := parseBuilderCategory(text)
		if !ok || got != want {
			t.Errorf("parseBuilderCategory(%q) = (%v, %v), want (%d, true)", text, got, ok, want)
		}
		if round, ok := parseBuilderCategory(want.String()); !ok || round != want {
			t.Errorf("format/parse round trip failed for %d: %q -> (%v, %v)", want, want.String(), round, ok)
		}
	}
	invalid := []string{
		"c0",                                  // c0 is never issued (bare s0 is the only uncategorized state)
		"c1024",                               // past the pool
		"c100000",                             // far past the pool
		"c-1",                                 // negative
		"c+1",                                 // decorated number
		"c1 ",                                 // trailing garbage
		" c1",                                 // leading garbage
		"\tc1",                                // leading whitespace
		"c1\t",                                // trailing whitespace
		"c01",                                 // leading zero: alternate spelling, not canonical
		"c1,2",                                // category set
		"c1.c3",                               // category range
		"c1,c2.c3",                            // composed set/range
		"s0",                                  // bare range spelling
		"C1",                                  // wrong case
		"c",                                   // no digits
		"",                                    // empty
		"c1a",                                 // trailing garbage
		"ca",                                  // non-digit body
		"c 1",                                 // embedded space
		"c١٢٣",                                // unicode digits
		"c1،c2",                               // unicode comma set
		"op_0123456789abcdef0123456789abcdef", // an op id is not a category
	}
	for _, text := range invalid {
		if got, ok := parseBuilderCategory(text); ok {
			t.Errorf("parseBuilderCategory(%q) = (%v, true), want invalid", text, got)
		}
	}
	if got := builderCategory(1).String(); got != "c1" {
		t.Errorf("formatter must emit the canonical spelling, got %q", got)
	}
	if got := builderCategory(1023).String(); got != "c1023" {
		t.Errorf("formatter must emit the canonical spelling, got %q", got)
	}
}

// builderManagerCategoryOf reads one instance record's category through
// the manager map (the single occupancy source).
func builderManagerCategoryOf(t *testing.T, m *builderManager, opID string) (builderCategory, bool) {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	inst, ok := m.instances[opID]
	if !ok {
		return 0, false
	}
	return inst.category, true
}

// startWithCategory runs one real START through the production admission
// path, binds the fake buildkitd socket so the readiness converges, and
// returns the bound category.
func startWithCategory(t *testing.T, m *builderManager, opID string) builderCategory {
	t.Helper()
	respCh := make(chan string, 1)
	go func() { respCh <- m.start(opID, nil) }()
	if !waitInstance(t, m, opID, true) {
		t.Fatalf("START %s did not reserve the map entry", opID)
	}
	bindFakeBuildkitdSocket(t, opID)
	if resp := <-respCh; resp != builderManagerRespOK {
		t.Fatalf("START %s = %q, want OK", opID, resp)
	}
	category, ok := builderManagerCategoryOf(t, m, opID)
	if !ok {
		t.Fatalf("START %s: bound record vanished", opID)
	}
	return category
}

// TestBuilderManagerFirstCategoryIsC1 proves the empty manager issues the
// pool's lowest category at first admission.
func TestBuilderManagerFirstCategoryIsC1(t *testing.T) {
	m, _, _ := processTestManager(t)
	seamCA(t)
	fakeLeaderSeam(t, true)

	if category := startWithCategory(t, m, "op_0123456789abcdef0123456789abcdef"); category != builderCategory(1) {
		t.Fatalf("first admission bound %s, want c1", category)
	}
}

// TestBuilderManagerLowestFreeCategoryAllocation proves the allocator's
// lowest-free selection directly: occupied entries (live and synthetic
// occupancy of the canonical map) leave the lowest hole to the next
// admission, and the pool bound holds.
func TestBuilderManagerLowestFreeCategoryAllocation(t *testing.T) {
	m := newBuilderManager(0, 0)
	m.categoryPoolMax = 5

	m.mu.Lock()
	defer m.mu.Unlock()

	// Empty map: c1.
	if c, ok := m.allocateCategoryLocked(); !ok || c != builderCategory(1) {
		t.Fatalf("empty manager allocated (%v, %v), want c1", c, ok)
	}
	// Occupy c1 and c3: the next admission must take the c2 hole.
	m.instances["op_0123456789abcdef0123456789abcdef"] = &builderInstance{operationID: "op_0123456789abcdef0123456789abcdef", category: builderCategory(1)}
	m.instances["op_fedcba9876543210fedcba9876543210"] = &builderInstance{operationID: "op_fedcba9876543210fedcba9876543210", category: builderCategory(3)}
	if c, ok := m.allocateCategoryLocked(); !ok || c != builderCategory(2) {
		t.Fatalf("hole-filling allocated (%v, %v), want c2", c, ok)
	}
	// Exhaustion at the pool bound: the bounded test pool (c1..c5) with
	// five occupied entries refuses.
	m.instances["op_11111111111111111111111111111111"] = &builderInstance{operationID: "op_11111111111111111111111111111111", category: builderCategory(2)}
	m.instances["op_22222222222222222222222222222222"] = &builderInstance{operationID: "op_22222222222222222222222222222222", category: builderCategory(4)}
	m.instances["op_33333333333333333333333333333333"] = &builderInstance{operationID: "op_33333333333333333333333333333333", category: builderCategory(5)}
	if c, ok := m.allocateCategoryLocked(); ok {
		t.Fatalf("exhausted pool allocated %v, want refusal", c)
	}
	// The production pool bound stays the canonical constant.
	if builderCategoryPoolMax != 1023 || builderCategoryPoolMin != 1 {
		t.Fatalf("production pool bounds moved: min=%v max=%v", builderCategoryPoolMin, builderCategoryPoolMax)
	}
	if pm := newBuilderManager(0, 0).categoryPoolMax; pm != builderCategoryPoolMax {
		t.Fatalf("fresh manager pool bound = %v, want the production constant", pm)
	}
}

// TestBuilderManagerConcurrentStartsNoDuplicateCategory proves concurrent
// admissions under the manager lock never collide: two simultaneous
// STARTs (the ceiling) bind two distinct categories.
func TestBuilderManagerConcurrentStartsNoDuplicateCategory(t *testing.T) {
	m, _, _ := processTestManager(t)
	seamCA(t)
	fakeLeaderSeam(t, true)

	opIDs := []string{"op_0123456789abcdef0123456789abcdef", "op_fedcba9876543210fedcba9876543210"}
	var wg sync.WaitGroup
	resps := make([]string, len(opIDs))
	for i, opID := range opIDs {
		wg.Add(1)
		go func(i int, opID string) {
			defer wg.Done()
			resps[i] = m.start(opID, nil)
		}(i, opID)
	}
	for _, opID := range opIDs {
		if !waitInstance(t, m, opID, true) {
			t.Fatalf("START %s did not reserve", opID)
		}
	}
	for _, opID := range opIDs {
		bindFakeBuildkitdSocket(t, opID)
	}
	wg.Wait()
	for i, resp := range resps {
		if resp != builderManagerRespOK {
			t.Fatalf("START %s = %q, want OK", opIDs[i], resp)
		}
	}
	first, _ := builderManagerCategoryOf(t, m, opIDs[0])
	second, _ := builderManagerCategoryOf(t, m, opIDs[1])
	if first == second {
		t.Fatalf("concurrent admissions collided on %s", first)
	}
	if first != builderCategory(1) && second != builderCategory(1) {
		t.Fatalf("c1 unused by concurrent admissions: %s and %s", first, second)
	}
}

// TestBuilderManagerRetainedInstanceKeepsCategory proves a
// retained-for-retry entry (a stop attempt whose directory cleanup did
// not converge) keeps holding its category: the next admission takes the
// next category, never the retained one.
func TestBuilderManagerRetainedInstanceKeepsCategory(t *testing.T) {
	m, _, stRoot := processTestManager(t)
	seamCA(t)
	fakeLeaderSeam(t, true)

	opID := "op_0123456789abcdef0123456789abcdef"
	if category := startWithCategory(t, m, opID); category != builderCategory(1) {
		t.Fatalf("first admission bound %s, want c1", category)
	}

	// Make the state tree's cleanup fail: the shared ops container loses
	// write permission, so removeInstanceDirs cannot complete (removing a
	// per-op entry requires write permission on its parent) and the stop
	// attempt retains the entry (truthful retry).
	opsDir := filepath.Join(stRoot, "ops")
	if err := os.Chmod(opsDir, 0500); err != nil {
		t.Fatalf("cannot lock the shared ops container: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(opsDir, 0700) })
	if resp := m.stop(opID, 0); resp == builderManagerRespOK {
		t.Fatal("STOP converged despite the unwritable state root (setup broken)")
	}
	if !waitInstance(t, m, opID, true) {
		t.Fatal("the failed-cleanup stop released the retained entry")
	}
	if category, ok := builderManagerCategoryOf(t, m, opID); !ok || category != builderCategory(1) {
		t.Fatalf("retained entry holds (%v, %v), want c1", category, ok)
	}

	// Restore and admit a second operation: it must NOT reuse c1.
	if err := os.Chmod(opsDir, 0700); err != nil {
		t.Fatalf("cannot unlock the shared ops container: %v", err)
	}
	op2 := "op_fedcba9876543210fedcba9876543210"
	if category := startWithCategory(t, m, op2); category != builderCategory(2) {
		t.Fatalf("admission beside the retained c1 bound %s, want c2", category)
	}
}

// TestBuilderManagerCategoryReleasesOnlyAtTerminalRemoval proves the
// release rule: the category returns to the pool exactly when the
// terminal convergence deletes the record — never at stopping, TERM,
// KILL, reap, or a partial cleanup.
func TestBuilderManagerCategoryReleasesOnlyAtTerminalRemoval(t *testing.T) {
	m, _, _ := processTestManager(t)
	seamCA(t)
	fakeLeaderSeam(t, true)

	opID := "op_0123456789abcdef0123456789abcdef"
	op2 := "op_fedcba9876543210fedcba9876543210"

	// First admission: c1.
	if category := startWithCategory(t, m, opID); category != builderCategory(1) {
		t.Fatalf("first admission bound %s, want c1", category)
	}
	// A second admission while the first is live: c2 (c1 held).
	if category := startWithCategory(t, m, op2); category != builderCategory(2) {
		t.Fatalf("second admission bound %s, want c2", category)
	}

	// Terminal convergence of the c1 holder: the record leaves the map,
	// and only then does c1 become the lowest free category again.
	if resp := m.stop(opID, 0); resp != builderManagerRespOK {
		t.Fatalf("STOP = %q, want OK", resp)
	}
	if _, ok := builderManagerCategoryOf(t, m, opID); ok {
		t.Fatal("terminal convergence did not remove the record")
	}
	op3 := "op_11111111111111111111111111111111"
	if category := startWithCategory(t, m, op3); category != builderCategory(1) {
		t.Fatalf("post-release admission bound %s, want c1", category)
	}
}

// TestBuilderManagerPoolExhaustionRefusesBeforeSideEffects proves the
// pool-exhaustion refusal happens at admission, before any filesystem or
// process side effect, and keeps the existing at-ceiling contract.
func TestBuilderManagerPoolExhaustionRefusesBeforeSideEffects(t *testing.T) {
	m, _, _ := processTestManager(t)
	seamCA(t)
	fakeLeaderSeam(t, true)
	m.categoryPoolMax = 1

	if category := startWithCategory(t, m, "op_0123456789abcdef0123456789abcdef"); category != builderCategory(1) {
		t.Fatalf("first admission bound %s, want c1", category)
	}

	op2 := "op_fedcba9876543210fedcba9876543210"
	if resp := m.start(op2, nil); resp != builderManagerRespAtCeiling {
		t.Fatalf("exhausted-pool START = %q, want %q", resp, builderManagerRespAtCeiling)
	}
	// The refusal is the pool-exhaustion branch, not the ceiling branch:
	// the diagnostic cause is recorded (the protocol vocabulary is
	// unchanged).
	if tail := m.diag.tailForDiagnostics(); !strings.Contains(tail, "operation category pool exhausted") {
		t.Fatalf("pool-exhaustion refusal did not record its diagnostic cause; tail: %q", tail)
	}
	// No reservation and no fence residue: the refusal is pre-side-effect.
	m.mu.Lock()
	_, reserved := m.instances[op2]
	_, fenced := m.startFences[op2]
	m.mu.Unlock()
	if reserved || fenced {
		t.Fatalf("refusal left state: reserved=%v fenced=%v", reserved, fenced)
	}
	if _, err := os.Lstat(opRuntimeDir(op2)); !os.IsNotExist(err) {
		t.Fatalf("refused START left a runtime dir: %v", err)
	}
	if _, err := os.Lstat(opStateDir(op2)); !os.IsNotExist(err) {
		t.Fatalf("refused START left a state dir: %v", err)
	}
}

// TestBuilderManagerFailedStartKeepsCategoryUntilConvergence proves a
// failed START keeps its bound category until the existing failed-start
// convergence removes the record: while the launch is parked before any
// side effect, the bound category is already occupied, and a concurrent
// admission takes the next category; after the convergence removes the
// record the category is lowest-free again.
func TestBuilderManagerFailedStartKeepsCategoryUntilConvergence(t *testing.T) {
	m, _, _ := processTestManager(t)
	seamCA(t)
	opID := "op_0123456789abcdef0123456789abcdef"
	op2 := "op_fedcba9876543210fedcba9876543210"

	// The launch of the FIRST op fails: the spawn seam resolves it to a
	// missing executable; every other op gets the normal fake leader.
	orig := builderNewRootlessKitCommand
	builderNewRootlessKitCommand = func(seamOpID string, _ builderCategory, rtDir, stDir string, _ []string, _ bool) *exec.Cmd {
		_ = rtDir
		_ = stDir
		if seamOpID == opID {
			return exec.Command("/nonexistent/rootlesskit")
		}
		return exec.Command("sh", "-c", boundedSleepScript())
	}
	t.Cleanup(func() { builderNewRootlessKitCommand = orig })

	// Park the failing launch before its filesystem work (the window
	// between reservation and convergence).
	engaged, release := launchHoldFixture(t, opID)
	respCh := make(chan string, 1)
	go func() { respCh <- m.start(opID, nil) }()
	select {
	case <-engaged:
	case <-time.After(10 * time.Second):
		t.Fatal("the failing launch never parked before its filesystem work")
	}

	// The bound category is already held by the reserved record.
	if category, ok := builderManagerCategoryOf(t, m, opID); !ok || category != builderCategory(1) {
		t.Fatalf("parked failed-start record holds (%v, %v), want c1", category, ok)
	}
	// A concurrent admission must not reuse the held c1.
	op2Cat := make(chan builderCategory, 1)
	go func() {
		op2Cat <- func() builderCategory {
			respCh2 := make(chan string, 1)
			go func() { respCh2 <- m.start(op2, nil) }()
			if !waitInstance(t, m, op2, true) {
				t.Error("concurrent admission did not reserve")
				return 0
			}
			bindFakeBuildkitdSocket(t, op2)
			if resp := <-respCh2; resp != builderManagerRespOK {
				t.Errorf("concurrent admission = %q, want OK", resp)
				return 0
			}
			category, _ := builderManagerCategoryOf(t, m, op2)
			return category
		}()
	}()
	if category := <-op2Cat; category != builderCategory(2) {
		t.Fatalf("concurrent admission beside the parked failed start bound %s, want c2", category)
	}

	// Release: the launch fails, the existing convergence removes the
	// record, and c1 becomes lowest-free again.
	release()
	if resp := <-respCh; resp != builderManagerRespInternal {
		t.Fatalf("failing START = %q, want internal", resp)
	}
	if !waitInstance(t, m, opID, false) {
		t.Fatal("the failed-start convergence did not remove the record")
	}
	op3 := "op_11111111111111111111111111111111"
	if category := startWithCategory(t, m, op3); category != builderCategory(1) {
		t.Fatalf("post-convergence admission bound %s, want c1", category)
	}
}

// TestBuilderManagerCategoryBoundToOperationRecord proves the binding
// lives in exactly one place: the record the manager map holds for the
// op id — the binding is stable across reads, survives concurrent
// readers, and no second registry exists to consult.
func TestBuilderManagerCategoryBoundToOperationRecord(t *testing.T) {
	m, _, _ := processTestManager(t)
	seamCA(t)
	fakeLeaderSeam(t, true)

	opIDs := []string{"op_0123456789abcdef0123456789abcdef", "op_fedcba9876543210fedcba9876543210"}
	for i, opID := range opIDs {
		if category := startWithCategory(t, m, opID); category != builderCategory(i+1) {
			t.Fatalf("admission %d bound %s, want c%d", i+1, category, i+1)
		}
	}
	// The binding is stable: repeated reads under the manager lock return
	// the same category for the same op id, and the record's category
	// never changes over its lifetime.
	var wg sync.WaitGroup
	for round := 0; round < 20; round++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i, opID := range opIDs {
				if category, ok := builderManagerCategoryOf(t, m, opID); !ok || category != builderCategory(i+1) {
					t.Errorf("binding drifted: %s = (%v, %v), want c%d", opID, category, ok, i+1)
				}
			}
		}()
	}
	wg.Wait()
}
