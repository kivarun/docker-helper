package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testWorkloadCoordinator builds a real coordinator over the given roots with
// reconcile seams that report no correlated containers and a pin cleanup seam.
func newTestWorkloadCoordinator(t *testing.T, backendImpl workloadMACBackend, stateRoot, runtimeRoot string) *workloadMACCoordinator {
	t.Helper()
	c := &workloadMACCoordinator{
		backend:     backendImpl,
		stateRoot:   stateRoot,
		runtimeRoot: runtimeRoot,
		docker: containerProvenance{
			inspect: func(ctx context.Context, operationID, sessionID string) ([]helperContainer, error) { return nil, nil },
			remove:  func(ctx context.Context, containerID string) error { return nil },
		},
		cleanupStalePins: func(operationID string) error { return nil },
	}
	return c
}

// TestCoordinatorOwnershipRecordDecoderExact proves the exact durable-record
// decoder contract: unknown fields, second JSON values, wrong enums, invalid
// session IDs, and malformed JSON are all rejected so reconciliation retains
// the state instead of normalizing it.
func TestWorkloadOwnershipRecordDecoderExact(t *testing.T) {
	valid := func() string {
		return fmt.Sprintf(`{"schema":%d,"operation_id":%q,"session_id":%q,"backend":"apparmor","created_at":"2026-01-01T00:00:00Z"}`,
			workloadMACStateSchema, testOperationID(1), testWorkloadSessionID)
	}
	cases := []struct {
		name   string
		body   string
		reject bool
	}{
		{"valid", valid(), false},
		{"unknown field rejected", strings.Replace(valid(), `"backend":"apparmor"`, `"backend":"apparmor","extra":1`, 1), true},
		{"stored profile field is forbidden", strings.Replace(valid(), `"backend":"apparmor"`, `"backend":"apparmor","profile":"docker-helper-workload-op_x"`, 1), true},
		{"two JSON values rejected", valid() + "\n{}\n", true},
		{"truncated JSON rejected", `{"schema":1,`, true},
		{"wrong schema rejected", strings.Replace(valid(), `"schema":1`, `"schema":2`, 1), true},
		{"unknown backend enum rejected", strings.Replace(valid(), `"backend":"apparmor"`, `"backend":"foreign"`, 1), true},
		{"empty session ID rejected", strings.Replace(valid(), `"session_id":"`+testWorkloadSessionID+`"`, `"session_id":""`, 1), true},
		{"wrong session ID shape rejected", strings.Replace(valid(), testWorkloadSessionID, "sess1", 1), true},
		{"unsafe operation ID rejected", strings.Replace(valid(), testOperationID(1), "../escape", 1), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "ownership"), []byte(tc.body), 0600); err != nil {
				t.Fatal(err)
			}
			_, err := readWorkloadMACRecord(dir)
			if tc.reject && err == nil {
				t.Fatalf("malformed record must be rejected, body: %s", tc.body)
			}
			if !tc.reject && err != nil {
				t.Fatalf("valid record must decode: %v", err)
			}
		})
	}
}

// TestWorkloadOwnershipRecordSecondDecodeMustBeEOF proves the exact decoder
// also rejects trailing JSON content after the single record value.
func TestWorkloadOwnershipRecordSecondDecodeMustBeEOF(t *testing.T) {
	dir := t.TempDir()
	body := fmt.Sprintf(`{"schema":%d,"operation_id":%q,"session_id":%q,"backend":"selinux","created_at":"2026-01-01T00:00:00Z"} 42`,
		workloadMACStateSchema, testOperationID(2), testWorkloadSessionID)
	if err := os.WriteFile(filepath.Join(dir, "ownership"), []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readWorkloadMACRecord(dir); err == nil {
		t.Fatal("trailing non-whitespace content after the record must be rejected")
	}
}

// TestWorkloadOwnershipRecordIdentityMustBeCanonical proves the durable
// ownership identity contract: the record's operation and session IDs must
// be exactly the canonical issued production shapes (exact prefix, exact
// lowercase hex length). Wrong length, wrong prefix, uppercase, and non-hex
// characters are foreign identity and fail closed.
func TestWorkloadOwnershipRecordIdentityMustBeCanonical(t *testing.T) {
	valid := func(opID, sessionID string) string {
		return fmt.Sprintf(`{"schema":%d,"operation_id":%q,"session_id":%q,"backend":"apparmor","created_at":"2026-01-01T00:00:00Z"}`,
			workloadMACStateSchema, opID, sessionID)
	}
	cases := []struct {
		name      string
		opID      string
		sessionID string
	}{
		{"canonical accepted", testOperationID(61), testWorkloadSessionID},
		{"operation ID too short", "op_1", testWorkloadSessionID},
		{"operation ID too long", testOperationID(61) + "a", testWorkloadSessionID},
		{"operation ID wrong prefix", strings.Replace(testOperationID(61), "op_", "run_", 1), testWorkloadSessionID},
		{"operation ID uppercase hex", strings.Replace(testOperationID(61), "3d", "3D", 1), testWorkloadSessionID},
		{"operation ID non-hex", strings.Replace(testOperationID(61), "3d", "3g", 1), testWorkloadSessionID},
		{"session ID too short", "dhs_0f", testWorkloadSessionID},
		{"session ID too long", testWorkloadSessionID + "ab", testWorkloadSessionID},
		{"session ID uppercase hex", strings.Replace(testWorkloadSessionID, "0f", "0F", 1), testWorkloadSessionID},
		{"session ID non-hex", "dhs_" + strings.Repeat("g", 32), testWorkloadSessionID},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "ownership"), []byte(valid(tc.opID, tc.sessionID)), 0600); err != nil {
				t.Fatal(err)
			}
			_, err := readWorkloadMACRecord(dir)
			if tc.name == "canonical accepted" {
				if err != nil {
					t.Fatalf("canonical record must decode: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("non-canonical durable identity must be rejected: op=%q session=%q", tc.opID, tc.sessionID)
			}
		})
	}
}

// TestWorkloadOwnershipRecordOperationIDMustMatchDirectory proves the
// reconciliation entry parser retains a record whose operation ID does not
// equal its owning directory name.
func TestWorkloadOwnershipRecordOperationIDMustMatchDirectory(t *testing.T) {
	stateRoot := t.TempDir()
	runtimeRoot := t.TempDir()
	dirName := testOperationID(11)
	dir := filepath.Join(stateRoot, dirName)
	if err := os.MkdirAll(dir, workloadMACStateDirPerm); err != nil {
		t.Fatal(err)
	}
	if err := writeWorkloadMACRecord(dir, workloadMACRecord{
		Schema: workloadMACStateSchema, OperationID: testOperationID(12),
		SessionID: testWorkloadSessionID, Backend: string(LSMAppArmor),
		CreatedAt: "2026-01-01T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	c := newTestWorkloadCoordinator(t, newWorkloadAppArmorBackend(), stateRoot, runtimeRoot)
	queries := 0
	c.docker.inspect = func(ctx context.Context, operationID, sessionID string) ([]helperContainer, error) {
		queries++
		return nil, nil
	}
	if err := c.ReconcileStartup(context.Background()); err != nil {
		t.Fatalf("ReconcileStartup: %v", err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("mismatched ownership record must be retained: %v", err)
	}
	if queries != 0 {
		t.Fatalf("unowned entry must not reach container inspection, got %d queries", queries)
	}
}

// TestCoordinatorRoundTripAppArmorReconcilesProducedState drives the real
// coordinator-produced durable format through reconciliation: a real
// Prepare commits the ownership record and loads the profile through the
// production backend, then a fresh coordinator instance must classify and
// fully clean that state through ReconcileStartup.
func TestCoordinatorRoundTripAppArmorReconcilesProducedState(t *testing.T) {
	dir := t.TempDir()
	stateRoot := filepath.Join(dir, "state")
	runtimeRoot := filepath.Join(dir, "runtime")
	opID := testOperationID(21)

	first := newTestWorkloadCoordinator(t, mustTestAppArmorBackend(t), stateRoot, runtimeRoot)
	if _, err := first.Prepare(workloadPreparation{
		OperationID:   opID,
		SessionID:     testWorkloadSessionID,
		Exposures:     []sessionFilesystemExposure{{Target: "/inputs", RequestedReadOnly: true}},
		PinnedSources: []string{"/runtime/pinned/0"},
	}); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	loaded, err := first.backend.(*workloadAppArmorBackend).loadedProfiles()
	if err != nil {
		t.Fatal(err)
	}
	if !containsString(loaded, workloadAppArmorProfileName(opID)) {
		t.Fatal("Prepare must have loaded the workload profile")
	}

	// The freshly prepared state is exactly what a crash leaves behind.
	// Reconcile it from a fresh coordinator instance whose kernel-inventory
	// seam starts empty — proving the durable format carries everything
	// reconciliation needs.
	fresh := newTestWorkloadCoordinator(t, mustTestAppArmorBackend(t), stateRoot, runtimeRoot)
	if err := fresh.ReconcileStartup(context.Background()); err != nil {
		t.Fatalf("ReconcileStartup: %v", err)
	}
	if _, err := os.Stat(filepath.Join(stateRoot, opID)); !os.IsNotExist(err) {
		t.Errorf("durable owned state must be removed after reconciliation, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(runtimeRoot, opID)); !os.IsNotExist(err) {
		t.Errorf("transient runtime state must be removed after reconciliation, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "state", opID, appArmorWorkloadProfileFileName)); err == nil {
		t.Errorf("generated profile source must be removed")
	}
}

// TestCoordinatorRoundTripSELinuxReconcilesProducedState proves the same
// round trip for the SELinux backend: a real Prepare materializes the
// projection through the production backend, and a fresh coordinator
// instance reconciles the durable ownership record into full cleanup.
func TestCoordinatorRoundTripSELinuxReconcilesProducedState(t *testing.T) {
	dir := t.TempDir()
	stateRoot := filepath.Join(dir, "state")
	runtimeRoot := filepath.Join(dir, "runtime")
	pinned := filepath.Join(dir, "pinned")
	if err := os.MkdirAll(pinned, 0700); err != nil {
		t.Fatal(err)
	}

	firstBackend, _ := newTestSELinuxBackend(t)
	first := newTestWorkloadCoordinator(t, firstBackend, stateRoot, runtimeRoot)
	prepared, err := first.Prepare(workloadPreparation{
		OperationID:   testOperationID(22),
		SessionID:     testWorkloadSessionID,
		Exposures:     []sessionFilesystemExposure{{Target: "/inputs", RequestedReadOnly: true}},
		PinnedSources: []string{pinned},
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	projection := prepared.MountSources[0]
	if !firstBackend.ops.(*testMountOps).seam.mounted[projection] {
		t.Fatal("prepared projection must be mounted")
	}

	freshBackend, freshSeam := newTestSELinuxBackend(t)
	// The fresh instance must observe the kernel state the previous
	// instance left: the projection mount still exists.
	freshSeam.mounted[projection] = true
	fresh := newTestWorkloadCoordinator(t, freshBackend, stateRoot, runtimeRoot)
	if err := fresh.ReconcileStartup(context.Background()); err != nil {
		t.Fatalf("ReconcileStartup: %v", err)
	}
	if _, err := os.Stat(filepath.Join(stateRoot, testOperationID(22))); !os.IsNotExist(err) {
		t.Errorf("durable owned state must be removed after reconciliation, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(runtimeRoot, testOperationID(22))); !os.IsNotExist(err) {
		t.Errorf("transient projection state must be removed after reconciliation, got %v", err)
	}
	if len(freshSeam.unmountCalls) != 1 {
		t.Errorf("expected exactly one projection unmount, got %v", freshSeam.unmountCalls)
	}
}

// TestCoordinatorReconcileRetainsLoadedProfileWithoutSource proves the
// fail-closed classification of the crash window "deterministic profile
// loaded, profile source for a safe unload missing": the owned state is
// retained and no unload is attempted.
func TestCoordinatorReconcileRetainsLoadedProfileWithoutSource(t *testing.T) {
	stateRoot := t.TempDir()
	runtimeRoot := t.TempDir()
	opID := testOperationID(23)

	// Produce the real durable record through a real Prepare, then rebuild
	// the crash window: record committed, profile source gone, profile
	// still loaded in the kernel inventory.
	first := newTestWorkloadCoordinator(t, mustTestAppArmorBackend(t), stateRoot, runtimeRoot)
	if _, err := first.Prepare(workloadPreparation{
		OperationID:   opID,
		SessionID:     testWorkloadSessionID,
		Exposures:     []sessionFilesystemExposure{{Target: "/inputs", RequestedReadOnly: true}},
		PinnedSources: []string{"/runtime/pinned/0"},
	}); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := os.Remove(filepath.Join(stateRoot, opID, appArmorWorkloadProfileFileName)); err != nil {
		t.Fatal(err)
	}

	// A fresh coordinator instance observes the kernel inventory the
	// previous instance left: the deterministic profile is still loaded,
	// but its safe-unload source is gone.
	b, h := newTestAppArmorWorkloadBackend(t)
	fresh := newTestWorkloadCoordinator(t, b, stateRoot, runtimeRoot)
	b.loadedProfiles = func() ([]string, error) {
		return []string{workloadAppArmorProfileName(opID)}, nil
	}
	if err := fresh.ReconcileStartup(context.Background()); err != nil {
		t.Fatalf("ReconcileStartup: %v", err)
	}
	if _, err := os.Stat(filepath.Join(stateRoot, opID)); err != nil {
		t.Fatalf("loaded profile without a safe unload source must be retained: %v", err)
	}
	if len(h.parserCalls) != 0 {
		t.Errorf("no unload may be attempted without the profile source, got %v", h.parserCalls)
	}
}

// TestCoordinatorReconcileClassifiesCrashBeforeProfileSource proves the
// other crash window "ownership committed, crash before the profile source
// was written": the empty owned state is cleaned up when the deterministic
// profile is absent from the kernel inventory, with no parser invocation.
func TestCoordinatorReconcileClassifiesCrashBeforeProfileSource(t *testing.T) {
	stateRoot := t.TempDir()
	runtimeRoot := t.TempDir()
	opID := testOperationID(24)

	first := newTestWorkloadCoordinator(t, mustTestAppArmorBackend(t), stateRoot, runtimeRoot)
	if _, err := first.Prepare(workloadPreparation{
		OperationID:   opID,
		SessionID:     testWorkloadSessionID,
		Exposures:     []sessionFilesystemExposure{{Target: "/inputs", RequestedReadOnly: true}},
		PinnedSources: []string{"/runtime/pinned/0"},
	}); err != nil {
		t.Fatalf("Prepare: %v", err)
	}

	// Rebuild the crash window from the really written ownership record:
	// only the record survives; no profile source, no loaded profile.
	record, err := os.ReadFile(filepath.Join(stateRoot, opID, "ownership"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(record), "profile") {
		t.Fatalf("ownership record must not store a second owner of the derivable profile name: %s", record)
	}
	if err := os.RemoveAll(filepath.Join(stateRoot, opID)); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(stateRoot, opID), workloadMACStateDirPerm); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateRoot, opID, "ownership"), record, 0600); err != nil {
		t.Fatal(err)
	}

	b, h := newTestAppArmorWorkloadBackend(t)
	fresh := newTestWorkloadCoordinator(t, b, stateRoot, runtimeRoot)
	if err := fresh.ReconcileStartup(context.Background()); err != nil {
		t.Fatalf("ReconcileStartup: %v", err)
	}
	if _, err := os.Stat(filepath.Join(stateRoot, opID)); !os.IsNotExist(err) {
		t.Errorf("empty owned state must be cleaned after reconciliation, got %v", err)
	}
	if len(h.parserCalls) != 0 {
		t.Errorf("empty owned state must not invoke the parser, got %v", h.parserCalls)
	}
}

// TestCoordinatorPrepareFailureClassifiesRetainedOutcome proves the typed
// Prepare failure contract: when a partial SELinux projection exists, the
// projection proof fails, and the partial MAC cleanup also fails, Prepare
// returns a *workloadMACRetainedError and retains the durable and runtime
// state. The caller must not release dependent pins or the workspace lease.
func TestCoordinatorPrepareFailureClassifiesRetainedOutcome(t *testing.T) {
	dir := t.TempDir()
	stateRoot := filepath.Join(dir, "state")
	runtimeRoot := filepath.Join(dir, "runtime")
	b, seam := newTestSELinuxBackend(t)
	pinned := filepath.Join(dir, "pinned")
	if err := os.MkdirAll(pinned, 0700); err != nil {
		t.Fatal(err)
	}
	c := newTestWorkloadCoordinator(t, b, stateRoot, runtimeRoot)
	// The effective-type proof fails after mount-0 is fully materialized,
	// and the partial-projection rollback cannot unmount either.
	seam.typeErr = errors.New("xattr proof unavailable")
	seam.unmountLeavesMounted = true
	prep := workloadPreparation{
		OperationID:   "op_ret1",
		SessionID:     testWorkloadSessionID,
		Exposures:     []sessionFilesystemExposure{{Target: "/data", RequestedReadOnly: true}},
		PinnedSources: []string{pinned},
	}
	_, err := c.Prepare(prep)
	if err == nil {
		t.Fatal("failing projection proof must fail Prepare")
	}
	var retained *workloadMACRetainedError
	if !errors.As(err, &retained) {
		t.Fatalf("partial MAC state that cannot roll back must classify as retained, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(stateRoot, "op_ret1")); statErr != nil {
		t.Errorf("durable ownership state must be retained, got %v", statErr)
	}
	if _, statErr := os.Stat(filepath.Join(runtimeRoot, "op_ret1", "mount-0")); statErr != nil {
		t.Errorf("partial projection runtime state must be retained, got %v", statErr)
	}
}

// TestCoordinatorPrepareFailureRolledBackIsNotRetained proves the contrast
// classification and the ownership-record dependency contract: when the
// partial MAC state rolls back completely, the returned error is not a
// retained error, and the durable ownership record stays as the ownership
// proof of the still-live dependent pins until the caller's rollback owner
// releases the pins and removes the record last.
func TestCoordinatorPrepareFailureFullyRolledBack(t *testing.T) {
	dir := t.TempDir()
	stateRoot := filepath.Join(dir, "state")
	runtimeRoot := filepath.Join(dir, "runtime")
	pinned := filepath.Join(dir, "pinned")
	if err := os.MkdirAll(pinned, 0700); err != nil {
		t.Fatal(err)
	}
	b, seam := newTestSELinuxBackend(t)
	c := newTestWorkloadCoordinator(t, b, stateRoot, runtimeRoot)
	// The worker fails to start: no kernel state was ever created, so the
	// rollback completes and the outcome must not be retained.
	seam.startErr = errors.New("bindfs unavailable")
	prep := workloadPreparation{
		OperationID:   "op_ret2",
		SessionID:     testWorkloadSessionID,
		Exposures:     []sessionFilesystemExposure{{Target: "/data", RequestedReadOnly: true}},
		PinnedSources: []string{pinned},
	}
	_, err := c.Prepare(prep)
	if err == nil {
		t.Fatal("failed worker start must fail Prepare")
	}
	var retained *workloadMACRetainedError
	if errors.As(err, &retained) {
		t.Fatalf("a fully rolled-back failure must not classify as retained, got %v", err)
	}
	// The ownership record is the caller's rollback dependency: it binds the
	// dependent pins until the rollback owner releases them, so a crash or
	// pin-cleanup failure after the MAC rollback leaves a complete retry
	// marker instead of anonymous pins.
	if _, statErr := os.Stat(filepath.Join(stateRoot, "op_ret2", "ownership")); statErr != nil {
		t.Fatalf("fully rolled-back preparation must keep the ownership record for the caller's rollback: %v", statErr)
	}
	// The caller's rollback owner releases the pins and removes the record
	// last; after it, no owned state survives.
	if err := c.cleanupStalePinsIn("op_ret2"); err != nil {
		t.Fatalf("caller pin release: %v", err)
	}
	if err := c.removeWorkloadMACState("op_ret2"); err != nil {
		t.Fatalf("caller ownership removal: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(stateRoot, "op_ret2")); !os.IsNotExist(statErr) {
		t.Errorf("the rollback owner must leave no durable state after the pins, got %v", statErr)
	}
}

// TestCoordinatorSELinuxRollbackRetainsLiveWorkerState is the regression for
// the prepare-rollback live-worker contract: when an owned projection worker
// exists and its exit cannot be proven, the prepare failure must be the
// typed retained outcome, the durable ownership record must survive, the
// partial projection runtime state must remain for reconciliation, and the
// coordinator must not run a second, handle-free cleanup pass.
func TestCoordinatorSELinuxRollbackRetainsLiveWorkerState(t *testing.T) {
	dir := t.TempDir()
	stateRoot := filepath.Join(dir, "state")
	runtimeRoot := filepath.Join(dir, "runtime")
	pinned := filepath.Join(dir, "pinned")
	if err := os.MkdirAll(pinned, 0700); err != nil {
		t.Fatal(err)
	}
	b, seam := newTestSELinuxBackend(t)
	c := newTestWorkloadCoordinator(t, b, stateRoot, runtimeRoot)
	// The worker starts, its projection mounts, the effective-type proof
	// then fails, and the rollback's exit wait cannot prove the worker
	// exited: the projection cannot be proven released while its live
	// worker handle still exists.
	seam.typeErr = errors.New("xattr proof unavailable")
	seam.dieAfterFirstAlive = true
	seam.waitExitErr = errors.New("worker did not exit after unmount")
	prep := workloadPreparation{
		OperationID:   "op_ret3",
		SessionID:     testWorkloadSessionID,
		Exposures:     []sessionFilesystemExposure{{Target: "/data", RequestedReadOnly: true}},
		PinnedSources: []string{pinned},
	}
	_, err := c.Prepare(prep)
	if err == nil {
		t.Fatal("a projection whose rollback cannot prove worker exit must fail Prepare")
	}
	var retained *workloadMACRetainedError
	if !errors.As(err, &retained) {
		t.Fatalf("a rollback that cannot prove the live worker exited must classify as retained, got %v", err)
	}
	// The durable ownership record stays so startup reconciliation can
	// classify and finish the cleanup without the worker handle.
	if _, statErr := os.Stat(filepath.Join(stateRoot, "op_ret3", "ownership")); statErr != nil {
		t.Errorf("the ownership record must be retained for reconciliation, got %v", statErr)
	}
	if _, statErr := os.Stat(filepath.Join(runtimeRoot, "op_ret3", "mount-0")); statErr != nil {
		t.Errorf("the partial projection runtime state must be retained, got %v", statErr)
	}
}

func mustTestAppArmorBackend(t *testing.T) *workloadAppArmorBackend {
	t.Helper()
	b, _ := newTestAppArmorWorkloadBackend(t)
	return b
}

// pinsDirFor computes the deterministic pin layout directory of one
// operation relative to the coordinator's runtime root, matching the
// mount-pin owner's production layout (<RuntimeDir>/mounts/<op-id>).
func pinsDirFor(runtimeRoot, operationID string) string {
	return filepath.Join(filepath.Dir(runtimeRoot), "mounts", operationID)
}

// TestCoordinatorReconcileRetriesAfterPinCleanupFailure proves the durable
// ownership record is the reconciliation retry marker: a first
// reconciliation whose pin cleanup fails retains the record and dependent
// pins; a second successful reconciliation finishes the cleanup.
func TestCoordinatorReconcileRetriesAfterPinCleanupFailure(t *testing.T) {
	stateRoot := t.TempDir()
	runtimeRoot := t.TempDir()
	opID := testOperationID(31)

	first := newTestWorkloadCoordinator(t, mustTestAppArmorBackend(t), stateRoot, runtimeRoot)
	if _, err := first.Prepare(workloadPreparation{
		OperationID:   opID,
		SessionID:     testWorkloadSessionID,
		Exposures:     []sessionFilesystemExposure{{Target: "/inputs", RequestedReadOnly: true}},
		PinnedSources: []string{"/runtime/pinned/0"},
	}); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	pinsDir := pinsDirFor(runtimeRoot, opID)
	if err := os.MkdirAll(pinsDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pinsDir, "0"), nil, 0600); err != nil {
		t.Fatal(err)
	}

	// First reconciliation: pin cleanup fails on the seam, state retained.
	failing := newTestWorkloadCoordinator(t, mustTestAppArmorBackend(t), stateRoot, runtimeRoot)
	failing.cleanupStalePins = func(operationID string) error {
		return errors.New("simulated pin cleanup failure")
	}
	if err := failing.ReconcileStartup(context.Background()); err != nil {
		t.Fatalf("ReconcileStartup: %v", err)
	}
	if _, err := os.Stat(filepath.Join(stateRoot, opID)); err != nil {
		t.Fatalf("failed pin cleanup must retain the ownership record: %v", err)
	}
	if _, err := os.Stat(pinsDir); err != nil {
		t.Fatalf("dependent pins must be retained when their cleanup fails: %v", err)
	}

	// Second reconciliation with a working pin cleanup owner completes.
	retrying := newTestWorkloadCoordinator(t, mustTestAppArmorBackend(t), stateRoot, runtimeRoot)
	retrying.cleanupStalePins = retrying.cleanupStalePinsIn
	if err := retrying.ReconcileStartup(context.Background()); err != nil {
		t.Fatalf("second ReconcileStartup: %v", err)
	}
	if _, err := os.Stat(filepath.Join(stateRoot, opID)); !os.IsNotExist(err) {
		t.Errorf("successful reconciliation must remove the durable record, got %v", err)
	}
	if _, err := os.Stat(pinsDir); !os.IsNotExist(err) {
		t.Errorf("stale pins must be removed by the successful reconciliation, got %v", err)
	}
}

// TestCoordinatorStalePinLayoutAdversarial proves the pin-layout ownership
// proof inside cleanupStalePinsIn: a foreign name, a symlinked destination,
// and a non-directory layout all fail the cleanup so the caller retains
// the owned state instead of unmounting or removing unproven objects.
func TestCoordinatorStalePinLayoutAdversarial(t *testing.T) {
	t.Run("foreign pin name", func(t *testing.T) {
		runtimeRoot := t.TempDir()
		opID := "op_pins1"
		pinsDir := pinsDirFor(runtimeRoot, opID)
		if err := os.MkdirAll(pinsDir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(pinsDir, "extra"), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
		c := newTestWorkloadCoordinator(t, mustTestAppArmorBackend(t), t.TempDir(), runtimeRoot)
		if err := c.cleanupStalePinsIn(opID); err == nil {
			t.Fatal("foreign pin name must fail the cleanup")
		}
		if _, err := os.Stat(pinsDir); err != nil {
			t.Errorf("pin layout must be retained on an unexpected child, got %v", err)
		}
	})
	t.Run("symlinked pin destination", func(t *testing.T) {
		runtimeRoot := t.TempDir()
		opID := "op_pins2"
		pinsDir := pinsDirFor(runtimeRoot, opID)
		if err := os.MkdirAll(pinsDir, 0700); err != nil {
			t.Fatal(err)
		}
		foreign := filepath.Join(t.TempDir(), "foreign-pin")
		if err := os.WriteFile(foreign, nil, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(foreign, filepath.Join(pinsDir, "0")); err != nil {
			t.Fatal(err)
		}
		c := newTestWorkloadCoordinator(t, mustTestAppArmorBackend(t), t.TempDir(), runtimeRoot)
		if err := c.cleanupStalePinsIn(opID); err == nil {
			t.Fatal("symlinked pin must fail the cleanup")
		}
		if _, err := os.Stat(pinsDir); err != nil {
			t.Errorf("pin layout must be retained on an unexpected shape, got %v", err)
		}
	})
	t.Run("pins directory is not a helper-owned directory", func(t *testing.T) {
		runtimeRoot := t.TempDir()
		opID := "op_pins3"
		pinsDir := pinsDirFor(runtimeRoot, opID)
		if err := os.MkdirAll(filepath.Dir(pinsDir), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(pinsDir, []byte("not a directory"), 0600); err != nil {
			t.Fatal(err)
		}
		c := newTestWorkloadCoordinator(t, mustTestAppArmorBackend(t), t.TempDir(), runtimeRoot)
		if err := c.cleanupStalePinsIn(opID); err == nil {
			t.Fatal("a non-directory pin layout must fail the cleanup")
		}
	})
}
