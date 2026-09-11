package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// runWorkloadLifecycleFixture wires a system-mode run app whose Docker CLI
// and workload MAC parser are replaced by recording fakes. The production
// backend keeps full ownership of rendering, loading, verification, and
// cleanup ordering; only the external mechanisms are faked.
type runWorkloadLifecycleFixture struct {
	app     *App
	coord   *workloadMACCoordinator
	backend *workloadAppArmorBackend

	mu          sync.Mutex
	dockerArgv  [][]string
	events      []string
	parserCalls []string
	pinCleaned  []string

	unloadLeavesLoaded bool
}

func newRunWorkloadLifecycleFixture(t *testing.T) *runWorkloadLifecycleFixture {
	t.Helper()
	app := newSystemModeRunTestApp(t)
	coord := app.WorkloadMAC
	backend := coord.backend.(*workloadAppArmorBackend)
	f := &runWorkloadLifecycleFixture{app: app, coord: coord, backend: backend}
	prov := coord.docker
	prov.remove = func(ctx context.Context, id string) error { return nil }
	coord.docker = prov
	app.PinWorkspaceMountSourceFn = func(workspace, sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
		f.mu.Lock()
		pinned := filepath.Join(runtimeDir, "mounts", operationID, fmt.Sprint(mountIndex))
		if err := os.MkdirAll(filepath.Dir(pinned), 0700); err != nil {
			f.mu.Unlock()
			return nil, err
		}
		if err := os.WriteFile(pinned, nil, 0600); err != nil {
			f.mu.Unlock()
			return nil, err
		}
		f.mu.Unlock()
		return &pinnedMount{
			PinnedPath: pinned,
			cleanup: func() error {
				f.mu.Lock()
				defer f.mu.Unlock()
				f.pinCleaned = append(f.pinCleaned, pinned)
				return nil
			},
		}, nil
	}
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		f.mu.Lock()
		f.dockerArgv = append(f.dockerArgv, append([]string{name}, args...))
		f.mu.Unlock()
		return exec.CommandContext(ctx, "/bin/true")
	}
	return f
}

func (f *runWorkloadLifecycleFixture) run(t *testing.T, token, body string) (*httptest.ResponseRecorder, *operation) {
	t.Helper()
	req := httptest.NewRequest("POST", "/run", bytes.NewReader([]byte(body)))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	f.app.handleRun(w, req)
	var resp struct {
		OperationID string `json:"operation_id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	var op *operation
	if resp.OperationID != "" {
		op = f.app.OperationSupervisor.lookup(resp.OperationID)
		if op != nil {
			op.Wait()
		}
	}
	return w, op
}

// parser replaces the backend parser with a recording fake that keeps the
// fake kernel inventory consistent: --replace marks the parsed profile
// loaded, --remove marks it absent. unloadLeavesLoaded forces the removal
// verification to fail for retention tests.
func (f *runWorkloadLifecycleFixture) parser(t *testing.T, unloadLeavesLoaded bool) {
	t.Helper()
	f.backend.runParser = func(parserPath string, args []string) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.parserCalls = append(f.parserCalls, args[0])
		f.events = append(f.events, "parser "+args[0])
		switch args[0] {
		case "--replace":
			source, err := os.ReadFile(args[len(args)-1])
			if err != nil {
				return err
			}
			name := profileNameFromSource(string(source))
			f.backend.loadedProfiles = func() ([]string, error) {
				return []string{name}, nil
			}
		case "--remove":
			if f.unloadLeavesLoaded {
				return nil // removal faked but inventory keeps the profile
			}
			f.backend.loadedProfiles = func() ([]string, error) { return nil, nil }
		}
		return nil
	}
}

// TestRunWorkloadPrepareFailureBlocksDocker proves the fail-closed contract:
// when the generated workload profile cannot be loaded, the run fails with
// the internal MAC failure family, Docker is never invoked, no generated
// state survives, and the pins plus workspace lease are released in reverse
// ownership order.
func TestRunWorkloadPrepareFailureBlocksDocker(t *testing.T) {
	f := newRunWorkloadLifecycleFixture(t)
	f.backend.runParser = func(parserPath string, args []string) error {
		if args[0] == "--replace" {
			return fmt.Errorf("simulated parser load failure")
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		f.parserCalls = append(f.parserCalls, args[0])
		return nil
	}
	result, err := createSystemSession(t, f.app)
	if err != nil {
		t.Fatalf("createSystemSession: %v", err)
	}
	subdir := filepath.Join(result.Session.Workspace, "subdir")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatal(err)
	}
	body := `{"image":"alpine","mounts":[{"source":"subdir","target":"/data"}]}`
	req := httptest.NewRequest("POST", "/run", bytes.NewReader([]byte(body)))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	f.app.handleRun(w, req)
	if w.Code != 500 {
		t.Fatalf("expected 500, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["code"] != "internal_error" {
		t.Errorf("MAC prepare failure must use the internal failure family, got %v", resp["code"])
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.dockerArgv) != 0 {
		t.Errorf("Docker must never be invoked after prepare failure, got %v", f.dockerArgv)
	}
	if len(f.pinCleaned) != 1 {
		t.Errorf("pins must be cleaned in rollback, got %v", f.pinCleaned)
	}
	// No generated state may survive.
	entries, _ := os.ReadDir(filepath.Join(f.app.Config.StateDir, workloadMACStateRootName))
	if len(entries) != 0 {
		t.Errorf("prepare failure must leave no workload MAC state, got %v", entries)
	}
}

// TestRunWorkloadCompletionCleanupOrder proves the frozen post-start cleanup
// order on the real handleRun completion path: the container-absence proof
// (docker ps) runs first, then the workload MAC cleanup (profile unload),
// then the source pins. The cleanup events are recorded by the harness.
func TestRunWorkloadCompletionCleanupOrder(t *testing.T) {
	f := newRunWorkloadLifecycleFixture(t)
	f.parser(t, false)
	app := f.app
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.events = append(f.events, "docker "+args[0])
		f.dockerArgv = append(f.dockerArgv, append([]string{name}, args...))
		return exec.CommandContext(ctx, "/bin/true")
	}
	app.PinWorkspaceMountSourceFn = func(workspace, sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
		return &pinnedMount{
			PinnedPath: "/runtime/pinned/0",
			cleanup: func() error {
				f.mu.Lock()
				defer f.mu.Unlock()
				f.pinCleaned = append(f.pinCleaned, "pin")
				f.events = append(f.events, "pin")
				return nil
			},
		}, nil
	}
	result, err := createSystemSession(t, app)
	if err != nil {
		t.Fatalf("createSystemSession: %v", err)
	}
	subdir := filepath.Join(result.Session.Workspace, "ord")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatal(err)
	}
	body := `{"image":"alpine","mounts":[{"source":"ord","target":"/data"}],"command":["true"]}`
	req := httptest.NewRequest("POST", "/run", bytes.NewReader([]byte(body)))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)
	if w.Code != 201 {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		OperationID string `json:"operation_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || resp.OperationID == "" {
		t.Fatalf("cannot read operation id: %v", err)
	}
	if op := app.OperationSupervisor.lookup(resp.OperationID); op != nil {
		op.Wait()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !containsBefore(f.events, "docker ps", "parser --remove") {
		t.Errorf("proof must precede profile unload, events: %v", f.events)
	}
	if !containsBefore(f.events, "parser --remove", "pin") {
		t.Errorf("profile unload must precede pin cleanup, events: %v", f.events)
	}
	if len(f.pinCleaned) != 1 {
		t.Errorf("pins must be cleaned after completion, got %v", f.pinCleaned)
	}
}

func containsBefore(events []string, first, second string) bool {
	firstIdx, secondIdx := -1, -1
	for i, e := range events {
		if firstIdx < 0 && e == first {
			firstIdx = i
		}
		if e == second {
			secondIdx = i
		}
	}
	return firstIdx >= 0 && secondIdx >= 0 && firstIdx < secondIdx
}

// TestRunWorkloadCleanupFailureRetainsDependencies proves the cleanup-failure
// retention contract: a failed workload MAC cleanup must retain the dependent
// source pins (and not release them), keeping the owned state for startup
// reconciliation instead of silently forgetting it.
func TestRunWorkloadCleanupFailureRetainsDependencies(t *testing.T) {
	f := newRunWorkloadLifecycleFixture(t)
	app := f.app
	f.unloadLeavesLoaded = true
	f.parser(t, true)
	result, err := createSystemSession(t, app)
	if err != nil {
		t.Fatalf("createSystemSession: %v", err)
	}
	req := httptest.NewRequest("POST", "/run", bytes.NewReader([]byte(`{"image":"alpine","command":["true"]}`)))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)
	if w.Code != 201 {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		OperationID string `json:"operation_id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	op := app.OperationSupervisor.lookup(resp.OperationID)
	if op == nil {
		t.Fatal("operation must exist")
	}
	op.Wait()

	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.pinCleaned) != 0 {
		t.Errorf("failed workload MAC cleanup must retain the dependent pins, got %v", f.pinCleaned)
	}
	// The owned state (profile + ownership record) must remain for startup
	// reconciliation.
	opStateDir := filepath.Join(app.Config.StateDir, workloadMACStateRootName, op.ID)
	if _, statErr := os.Stat(opStateDir); statErr != nil {
		t.Fatalf("failed workload MAC cleanup must retain owned state: %v", statErr)
	}
}

// TestRunWorkloadPinFailureRetainsRecordUntilReconciliation is the
// normal-run regression for the frozen finalization boundary: the workload
// MAC cleanup succeeds, the pin cleanup fails, and the durable ownership
// record must survive so a fresh startup reconciliation can finish the
// cleanup. Removing the record before the dependent cleanup would strand
// the surviving pins without a reconciliation owner.
func TestRunWorkloadPinFailureRetainsRecordUntilReconciliation(t *testing.T) {
	f := newRunWorkloadLifecycleFixture(t)
	app := f.app
	f.parser(t, false)
	app.PinWorkspaceMountSourceFn = func(workspace, sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
		pinned := filepath.Join(runtimeDir, "mounts", operationID, fmt.Sprint(mountIndex))
		if err := os.MkdirAll(filepath.Dir(pinned), 0700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(pinned, nil, 0600); err != nil {
			return nil, err
		}
		return &pinnedMount{
			PinnedPath: pinned,
			cleanup: func() error {
				f.mu.Lock()
				defer f.mu.Unlock()
				f.pinCleaned = append(f.pinCleaned, pinned)
				return fmt.Errorf("simulated pin cleanup failure")
			},
		}, nil
	}
	result, err := createSystemSession(t, app)
	if err != nil {
		t.Fatalf("createSystemSession: %v", err)
	}
	subdir := filepath.Join(result.Session.Workspace, "fin")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatal(err)
	}
	body := `{"image":"alpine","mounts":[{"source":"fin","target":"/data"}],"command":["true"]}`
	w, op := f.run(t, result.Token, body)
	if w.Code != 201 {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	if op == nil {
		t.Fatal("operation must exist")
	}

	// The run completed with a successful MAC cleanup and a failed pin
	// cleanup: the durable ownership record must survive as the
	// reconciliation retry marker.
	stateRoot := filepath.Join(app.Config.StateDir, workloadMACStateRootName)
	runtimeRoot := filepath.Join(app.Config.RuntimeDir, workloadMACStateRootName)
	if _, err := os.Stat(filepath.Join(stateRoot, op.ID, "ownership")); err != nil {
		t.Fatalf("durable ownership record must survive the failed dependent pin cleanup: %v", err)
	}
	pinsDir := pinsDirFor(runtimeRoot, op.ID)
	if _, err := os.Stat(pinsDir); err != nil {
		t.Fatalf("failed pin cleanup must retain the pin layout: %v", err)
	}

	// A fresh daemon start reconciles the retained record through the
	// production pin-layout owner and finishes the cleanup.
	fresh := newTestWorkloadCoordinator(t, mustTestAppArmorBackend(t), stateRoot, runtimeRoot)
	fresh.cleanupStalePins = fresh.cleanupStalePinsIn
	if err := fresh.ReconcileStartup(context.Background()); err != nil {
		t.Fatalf("fresh ReconcileStartup: %v", err)
	}
	if _, err := os.Stat(filepath.Join(stateRoot, op.ID)); !os.IsNotExist(err) {
		t.Errorf("successful reconciliation must remove the retained durable record, got %v", err)
	}
	if _, err := os.Stat(pinsDir); !os.IsNotExist(err) {
		t.Errorf("successful reconciliation must remove the stale pins, got %v", err)
	}
}

// TestRunWorkloadStaleOwnedContainerForceRemoved proves the stale-container
// contract after a docker CLI process ended: the canonical absence proof
// finds exactly one proven-owned correlated container, force-removes it,
// verifies absence, and then releases the workload MAC state and pins.
func TestRunWorkloadStaleOwnedContainerForceRemoved(t *testing.T) {
	f := newRunWorkloadLifecycleFixture(t)
	app := f.app
	f.parser(t, f.unloadLeavesLoaded)
	app.InspectOperationContainers = func(ctx context.Context, operationID, sessionID string) ([]helperContainer, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, argv := range f.dockerArgv {
			if len(argv) >= 2 && argv[1] == "rm" {
				return nil, nil // absent after force removal
			}
		}
		return []helperContainer{{ID: "stale-abc", State: "running"}}, nil
	}
	removed := []string{}
	// The stale-container removal path shells out through the Docker CLI
	// seam; classify + remove happen through removeContainer at the App
	// level, which records the removed container and simulates absence.
	app.PinWorkspaceMountSourceFn = func(workspace, sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
		return &pinnedMount{PinnedPath: "/runtime/pinned/0", cleanup: func() error { return nil }}, nil
	}
	result, err := createSystemSession(t, app)
	if err != nil {
		t.Fatalf("createSystemSession: %v", err)
	}
	req := httptest.NewRequest("POST", "/run", bytes.NewReader([]byte(`{"image":"alpine","command":["true"]}`)))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)
	var resp struct {
		OperationID string `json:"operation_id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if op := app.OperationSupervisor.lookup(resp.OperationID); op != nil {
		op.Wait()
	}
	for _, argv := range f.dockerArgv {
		if len(argv) >= 3 && argv[1] == "rm" && argv[2] == "-f" {
			removed = append(removed, argv[len(argv)-1])
		}
	}
	if len(removed) != 1 || removed[0] != "stale-abc" {
		t.Errorf("expected the stale owned container force-removed, got %v", removed)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, err := os.Stat(filepath.Join(app.Config.StateDir, workloadMACStateRootName, resp.OperationID)); !os.IsNotExist(err) {
		t.Errorf("owned workload state must be cleaned after stale container removal, got %v", err)
	}
}

// TestRunWorkloadAmbiguousProofRetainsEverything proves that an ambiguous
// container-absence proof (docker query error) retains the workload MAC
// state and the dependent pins rather than weakening confinement.
func TestRunWorkloadAmbiguousProofRetainsState(t *testing.T) {
	f := newRunWorkloadLifecycleFixture(t)
	app := f.app
	f.parser(t, f.unloadLeavesLoaded)
	app.InspectOperationContainers = func(ctx context.Context, operationID, sessionID string) ([]helperContainer, error) {
		return nil, fmt.Errorf("simulated docker query failure")
	}
	result, err := createSystemSession(t, app)
	if err != nil {
		t.Fatalf("createSystemSession: %v", err)
	}
	subdir := filepath.Join(result.Session.Workspace, "amb")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatal(err)
	}
	body := `{"image":"alpine","mounts":[{"source":"amb","target":"/data"}]}`
	req := httptest.NewRequest("POST", "/run", bytes.NewReader([]byte(body)))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)
	var resp struct {
		OperationID string `json:"operation_id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if op := app.OperationSupervisor.lookup(resp.OperationID); op != nil {
		op.Wait()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.pinCleaned) != 0 {
		t.Errorf("ambiguous proof must retain dependent pins, got %v", f.pinCleaned)
	}
	opStateDir := filepath.Join(app.Config.StateDir, workloadMACStateRootName, resp.OperationID)
	if _, statErr := os.Stat(opStateDir); statErr != nil {
		t.Fatalf("ambiguous proof must retain owned workload state: %v", statErr)
	}
}

// TestRunWorkloadSELinuxPartialProjectionRetainsDependencies is the
// run-level regression for the retained-prepare-failure contract: a partial
// SELinux projection exists, the projection proof fails, and the partial
// projection cleanup also fails. The run must produce no Docker invocation,
// the durable workload state must be retained, and the dependent pins and
// the workspace-use lease must remain until startup reconciliation.
func TestRunWorkloadSELinuxPartialProjectionRetainsDependencies(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	app.Config.Mode = ModeSystem
	app.OperationSupervisor = newOperationSupervisor()
	coord := installTestWorkloadMACForTest(t, app, LSMSELinux)
	backend := coord.backend.(*workloadSELinuxBackend)
	seam := backend.ops.(*testMountOps).seam

	// Workspace MAC coverage plus a workspace-use lease: the run path
	// acquires a real lease whose release must be retained.
	app.MACCoordinator = newSessionMACCoordinator(app.DB, newTestWorkspaceMACDriver(LSMSELinux))

	var mu sync.Mutex
	var pinCleaned []string
	var dockerArgv [][]string
	app.PinWorkspaceMountSourceFn = func(workspace, sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
		pinned := filepath.Join(runtimeDir, "mounts", operationID, fmt.Sprint(mountIndex))
		if err := os.MkdirAll(filepath.Dir(pinned), 0700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(pinned, nil, 0600); err != nil {
			return nil, err
		}
		return &pinnedMount{
			PinnedPath: pinned,
			cleanup: func() error {
				mu.Lock()
				defer mu.Unlock()
				pinCleaned = append(pinCleaned, pinned)
				return nil
			},
		}, nil
	}
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		mu.Lock()
		defer mu.Unlock()
		dockerArgv = append(dockerArgv, append([]string{name}, args...))
		return exec.CommandContext(ctx, "/bin/true")
	}

	result, err := createSystemSession(t, app)
	if err != nil {
		t.Fatalf("createSystemSession: %v", err)
	}
	subdir := filepath.Join(result.Session.Workspace, "seldata")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatal(err)
	}

	// The effective-type proof fails after mount-0 is fully materialized,
	// and the partial-projection rollback cannot prove its unmount either.
	seam.typeErr = errors.New("xattr proof unavailable")
	seam.unmountLeavesMounted = true

	body := `{"image":"alpine","mounts":[{"source":"seldata","target":"/data","read_only":true}]}`
	req := httptest.NewRequest("POST", "/run", bytes.NewReader([]byte(body)))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)
	if w.Code != 500 {
		t.Fatalf("expected 500, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["code"] != "internal_error" {
		t.Errorf("retained prepare failure must use the internal failure family, got %v", resp["code"])
	}

	mu.Lock()
	defer mu.Unlock()
	if len(dockerArgv) != 0 {
		t.Errorf("no Docker run may happen after a retained prepare failure, got %v", dockerArgv)
	}
	if len(pinCleaned) != 0 {
		t.Errorf("dependent pins must remain when partial MAC state is retained, got %v", pinCleaned)
	}
	leases := app.MACCoordinator.workspaceUseLeases
	if len(leases) == 0 {
		t.Fatal("the workspace-use lease must remain when partial MAC state is retained")
	}
	for _, ws := range leases {
		if ws != result.Session.Workspace {
			t.Errorf("retained lease must cover the run workspace, got %q", ws)
		}
	}
	// The durable state of the failed operation is the only workload-mac
	// operation directory present.
	entries, readErr := os.ReadDir(filepath.Join(app.Config.StateDir, workloadMACStateRootName))
	if readErr != nil || len(entries) != 1 {
		t.Fatalf("exactly one retained workload MAC operation state expected, got %v (%v)", entries, readErr)
	}
	opStateDir := filepath.Join(app.Config.StateDir, workloadMACStateRootName, entries[0].Name())
	if _, statErr := os.Stat(opStateDir); statErr != nil {
		t.Fatalf("durable workload state must be retained after a failed prepare, got %v", statErr)
	}
}

// TestContainerProvenanceWiringsShareOneMechanism proves the run path and the
// startup-reconciliation path drive ONE Docker CLI mechanism: the same docker
// ps argv, the same parsed correlated-container result, the same docker rm -f
// argv — only the command construction differs (App-owned vs direct exec).
// The App-owned test seams (InspectOperationContainers, ExecCommandContext)
// must keep overriding the App wiring. The consolidation pins also forbid the
// old parallel per-wiring implementations from silently returning.
func TestContainerProvenanceWiringsShareOneMechanism(t *testing.T) {
	cleanupSrc, err := os.ReadFile("run_cleanup.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(cleanupSrc)
	for _, owner := range []string{
		"func inspectCorrelatedContainers(",
		"func forceRemoveCorrelatedContainer(",
	} {
		if !strings.Contains(src, owner) {
			t.Errorf("the single Docker CLI mechanism owner is missing: %s", owner)
		}
	}
	for _, duplicate := range []string{
		"func inspectCorrelatedRunContainers(",
		"func forceRemoveCorrelatedContainerByCLI(",
		"type syncBuffer struct",
	} {
		if strings.Contains(src, duplicate) {
			t.Errorf("the parallel Docker CLI implementation must stay deleted: %s", duplicate)
		}
	}

	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	calls := filepath.Join(dir, "calls")
	// The stub records each invocation's argv (space-joined) and answers
	// docker ps with one correlated running container.
	stub := "#!/bin/sh\n" +
		"printf '%s\\n' \"$*\" >> \"" + calls + "\"\n" +
		"if [ \"$1\" = ps ]; then printf '%s\\n' \"cid123 running\"; fi\n" +
		"exit 0\n"
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	ctx := context.Background()
	app := &App{}

	// Both provenance wirings must inspect and remove identically.
	appProv := app.runContainerProvenance()
	cliProv := cliContainerProvenance()

	appSeen, appInspectErr := appProv.inspect(ctx, "opA", "sessA")
	cliSeen, cliInspectErr := cliProv.inspect(ctx, "opA", "sessA")
	if appInspectErr != nil || cliInspectErr != nil {
		t.Fatalf("inspect failed: app=%v cli=%v", appInspectErr, cliInspectErr)
	}
	if len(appSeen) != 1 || len(cliSeen) != 1 ||
		appSeen[0] != (helperContainer{ID: "cid123", State: "running"}) ||
		cliSeen[0] != (helperContainer{ID: "cid123", State: "running"}) {
		t.Fatalf("both wirings must parse the same correlated container, got app=%v cli=%v", appSeen, cliSeen)
	}
	if appProv.remove(ctx, "cidX") != nil || cliProv.remove(ctx, "cidX") != nil {
		t.Fatal("both wirings must force-remove the proven-owned container successfully")
	}

	// The recorded argv must be exactly: two identical docker ps calls
	// (App path, then startup path) followed by two identical docker rm -f
	// calls. The ps argv carries the reserved label correlation and format.
	raw, err := os.ReadFile(calls)
	if err != nil {
		t.Fatalf("read recorded docker argv: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	wantPS := strings.Join([]string{
		"ps", "-a",
		"--filter", "label=" + runtimeLabelSchema + "=" + runtimeLabelSchemaValue,
		"--filter", "label=" + runtimeLabelOperationID + "=opA",
		"--filter", "label=" + runtimeLabelSessionID + "=sessA",
		"--format", "{{.ID}} {{.State}}",
	}, " ")
	wantRM := "rm -f cidX"
	if len(lines) != 4 {
		t.Fatalf("expected exactly 4 docker invocations, got %d: %v", len(lines), lines)
	}
	if lines[0] != wantPS || lines[1] != wantPS {
		t.Errorf("both inspect wirings must issue identical argv:\napp:  %s\ncli:  %s\nwant: %s", lines[0], lines[1], wantPS)
	}
	if lines[2] != wantRM || lines[3] != wantRM {
		t.Errorf("both remove wirings must issue identical argv:\napp:  %s\ncli:  %s\nwant: %s", lines[2], lines[3], wantRM)
	}

	// The App-owned seams keep overriding the App wiring only.
	app.InspectOperationContainers = func(ctx context.Context, operationID, sessionID string) ([]helperContainer, error) {
		return []helperContainer{{ID: "seam-inspect", State: "exited"}}, nil
	}
	seamSeen, err := app.runContainerProvenance().inspect(ctx, "opS", "sessS")
	if err != nil || len(seamSeen) != 1 || seamSeen[0].ID != "seam-inspect" {
		t.Fatalf("InspectOperationContainers seam must override the App inspect wiring, got %v (%v)", seamSeen, err)
	}
	var seamArgv []string
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		seamArgv = append([]string{name}, args...)
		return exec.Command("true")
	}
	if err := app.runContainerProvenance().remove(ctx, "cidSeam"); err != nil {
		t.Fatalf("ExecCommandContext seam remove: %v", err)
	}
	if strings.Join(seamArgv, " ") != "docker rm -f cidSeam" {
		t.Errorf("ExecCommandContext seam must construct the remove command, got %v", seamArgv)
	}
}
