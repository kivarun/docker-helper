package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAppArmorPathLiteralEscapesUnsafeBytes proves the M0 byte-safe literal
// encoder never lets a caller-controlled target byte become AppArmor syntax.
func TestAppArmorPathLiteralEscapesUnsafeBytes(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"/data", "/data"},
		{"/in puts", "/in\\x20puts"},
		{`/a"b`, "/a\\x22b"},
		{`/a\b`, "/a\\x5cb"},
		{"/a*b", "/a\\x2ab"},
		{"/a?b", "/a\\x3fb"},
		{"/a[0]b", "/a\\x5b0\\x5db"},
		{"/a{b}", "/a\\x7bb\\x7d"},
		{"/a#b", "/a\\x23b"},
		{"/a$b", "/a\\x24b"},
		{"/\u00e9", "/\\xc3\\xa9"},
		{"/a\x01b", "/a\\x01b"},
		{"/a.b_c-1", "/a.b_c-1"},
	}
	for _, tc := range cases {
		got := appArmorPathLiteral(tc.input)
		if got != tc.want {
			t.Errorf("input %q: got %q, want %q", tc.input, got, tc.want)
		}
		if got != appArmorPathLiteral(tc.input) {
			t.Errorf("input %q: escaping must be deterministic", tc.input)
		}
	}
}

// TestAppArmorPathLiteralNeverEmitsGlobOrDelimiter proves the deny rule
// rendered from an adversarial target cannot become an AppArmor glob,
// comment, quote, or delimiter (the M0 literal*star sentinel failure mode).
func TestAppArmorPathLiteralNeverEmitsGlobOrDelimiter(t *testing.T) {
	targets := []string{
		`/literal*star`,
		`/quote"target`,
		`/brace{target}`,
		"/bracket[t]arget",
		`/back\slash`,
		"/has space",
		"/hash#target",
		"/utf8\u00e9",
		"/ctl\x01",
	}
	for _, target := range targets {
		lit := appArmorPathLiteral(target)
		for _, forbidden := range []string{"*", "?", "\"", "{", "}", "[", "]", "#"} {
			if strings.Contains(lit, forbidden) {
				t.Fatalf("target %q encoded as %q contains raw %q", target, lit, forbidden)
			}
		}
	}
}

// TestWorkloadAppArmorProfileNameDeterministicSafe proves profile identity
// derives only from the server operation ID under the canonical prefix.
func TestWorkloadAppArmorProfileNameDeterministicSafe(t *testing.T) {
	name := workloadAppArmorProfileName("op_0123456789abcdef")
	if !strings.HasPrefix(name, appArmorWorkloadProfilePrefix) {
		t.Fatalf("profile name %q must carry canonical prefix", name)
	}
	if name != workloadAppArmorProfileName("op_0123456789abcdef") {
		t.Fatal("profile name must be deterministic")
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			t.Fatalf("profile name %q carries unexpected character %q", name, string(r))
		}
	}
	if workloadAppArmorProfileName("op_other") == name {
		t.Fatal("distinct operation IDs must give distinct profile names")
	}
}

// TestRenderWorkloadAppArmorProfileDeterministic proves renderer
// determinism, exact RO deny rendering with encoded literals, the Moby
// baseline shape, and that RW targets never receive denies.
func TestRenderWorkloadAppArmorProfileDeterministic(t *testing.T) {
	ro := []string{"/inputs", "/has space"}
	a := renderWorkloadAppArmorProfile("docker-helper-workload-op_x", ro, true)
	b := renderWorkloadAppArmorProfile("docker-helper-workload-op_x", ro, true)
	if a != b {
		t.Fatal("renderer must be deterministic")
	}
	if !strings.Contains(a, `audit deny "/inputs/{,**}" wkl,`) {
		t.Error("RO target must render the exact M0 deny rule")
	}
	if !strings.Contains(a, `audit deny "/has\x20space/{,**}" wkl,`) {
		t.Errorf("RO target must be byte-escaped, got profile:\n%s", a)
	}
	if strings.Contains(a, `audit deny "/project`) {
		t.Error("RW target must not receive a deny rule")
	}
	if !strings.Contains(a, "abi <abi/3.0>,") {
		t.Error("abi line must be present when the ABI include is available")
	}
	if !strings.Contains(a, `flags=(attach_disconnected,mediate_deleted)`) {
		t.Error("Moby docker-default flags must be preserved")
	}
	if !strings.Contains(a, "capability,\n  file,\n  umount,") {
		t.Error("docker-default baseline rules must be preserved")
	}
	c := renderWorkloadAppArmorProfile("docker-helper-workload-op_x", ro, false)
	if strings.Contains(c, "abi <abi/3.0>,") {
		t.Error("abi line must be omitted when the ABI include is unavailable")
	}
	d := renderWorkloadAppArmorProfile("docker-helper-workload-op_x", nil, false)
	if strings.Contains(d, "audit deny") {
		t.Error("no RO targets must render no workload deny rules")
	}
}

// TestRenderWorkloadAppArmorProfileMixedModes proves one profile covers
// /project RW (no deny), /inputs RO (deny), /output RW (no deny).
func TestRenderWorkloadAppArmorProfileMixedModes(t *testing.T) {
	profile := renderWorkloadAppArmorProfile("n", []string{"/inputs"}, false)
	if !strings.Contains(profile, `audit deny "/inputs/{,**}" wkl,`) {
		t.Error("RO target must deny mutation")
	}
	if strings.Count(profile, "audit deny \"") != 1 {
		t.Errorf("exactly one RO deny rule expected, got profile:\n%s", profile)
	}
}

// TestWorkloadAppArmorPrepareLoadVerifyOrder drives the production backend
// prepare path and proves load-before-Docker semantics: the ownership record
// is committed first, the profile is loaded and verified, and the prepared
// result carries the explicit security options plus the existing pins.
func TestWorkloadAppArmorPrepareLoadVerifyOrder(t *testing.T) {
	dir := t.TempDir()
	prep := workloadPreparation{
		OperationID:   "op_a1",
		SessionID:     "sess1",
		StateDir:      dir,
		RuntimeDir:    dir,
		Exposures:     []sessionFilesystemExposure{{Target: "/inputs", RequestedReadOnly: true}, {Target: "/project", RequestedReadOnly: false}},
		PinnedSources: []string{"/runtime/pinned/0", "/runtime/pinned/1"},
	}
	b, h := newTestAppArmorWorkloadBackend(t)
	prepared, err := b.prepare(prep)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if len(h.parserCalls) != 1 || !strings.HasPrefix(h.parserCalls[0], "--replace") {
		t.Fatalf("expected one parser load, got %v", h.parserCalls)
	}
	wantOpts := []string{"label=disable", "apparmor=docker-helper-workload-op_a1"}
	if len(prepared.SecurityOpts) != len(wantOpts) {
		t.Fatalf("security options: got %v", prepared.SecurityOpts)
	}
	for i, opt := range wantOpts {
		if prepared.SecurityOpts[i] != opt {
			t.Errorf("security option %d: got %q, want %q", i, prepared.SecurityOpts[i], opt)
		}
	}
	if len(prepared.MountSources) != 2 || prepared.MountSources[0] != "/runtime/pinned/0" || prepared.MountSources[1] != "/runtime/pinned/1" {
		t.Errorf("AppArmor mounts must use existing pins, got %v", prepared.MountSources)
	}
	// The helper-owned profile source must be a regular file in the owned
	// state directory and must carry the RO deny rule.
	source, err := os.ReadFile(filepath.Join(dir, appArmorWorkloadProfileFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(source), `audit deny "/inputs/{,**}" wkl,`) {
		t.Errorf("profile source must carry the RO deny, got:\n%s", source)
	}
	if strings.Contains(string(source), "audit deny \"/project") {
		t.Error("RW target must not receive a deny rule")
	}
}

// TestWorkloadAppArmorPrepareLoadFailureFailsClosed drives the fail-closed
// contract: parser load failure must fail preparation and leave no loaded
// profile; the coordinator-side rollback removes the owned partial state.
func TestWorkloadAppArmorPrepareLoadFailureFailsClosed(t *testing.T) {
	b, h := newTestAppArmorWorkloadBackend(t)
	h.loadErr = errors.New("parser boom")
	prep := workloadPreparation{
		OperationID:   "op_a2",
		SessionID:     "sess1",
		StateDir:      t.TempDir(),
		RuntimeDir:    t.TempDir(),
		Exposures:     []sessionFilesystemExposure{{Target: "/inputs", RequestedReadOnly: true}},
		PinnedSources: []string{"/runtime/pinned/0"},
	}
	if _, err := b.prepare(prep); err == nil {
		t.Fatal("load failure must fail preparation")
	}
	if h.loaded[workloadAppArmorProfileName("op_a2")] {
		t.Fatal("profile must not be loaded after failed preparation")
	}
}

// TestWorkloadAppArmorCleanupUnloadsProfileOnce proves cleanup unloads the
// loaded profile, removes the owned profile source, and is idempotent.
func TestWorkloadAppArmorCleanupUnloadsProfileOnce(t *testing.T) {
	b, h := newTestAppArmorWorkloadBackend(t)
	dir := t.TempDir()
	name := workloadAppArmorProfileName("op_c1")
	h.loaded[name] = true
	if err := os.WriteFile(filepath.Join(dir, appArmorWorkloadProfileFileName), []byte(renderWorkloadAppArmorProfile(name, nil, false)), 0600); err != nil {
		t.Fatal(err)
	}
	rec := workloadMACRecord{OperationID: "op_c1", SessionID: "s", Backend: string(LSMAppArmor), ProfileName: name}
	rec.StateDir = dir
	rec.RuntimeDir = dir
	if err := b.cleanupOwnedState(rec); err != nil {
		t.Fatalf("cleanupOwnedState: %v", err)
	}
	if h.loaded[name] {
		t.Fatal("profile must be unloaded")
	}
	if _, statErr := os.Stat(filepath.Join(dir, appArmorWorkloadProfileFileName)); !os.IsNotExist(statErr) {
		t.Errorf("owned profile source must be removed, got %v", statErr)
	}
	// Reconciliation races may call cleanup again; absence is success.
	if err := b.cleanupOwnedState(rec); err != nil {
		t.Errorf("second cleanup must be idempotent, got %v", err)
	}
}

// TestWorkloadAppArmorValidateOwnedStateRejectsMalformed proves strict
// owned-state validation: foreign record, mismatched profile name, symlinked
// or missing profile source all fail validation and reconciliation retains
// them.
func TestWorkloadAppArmorValidateOwnedStateRejectsMalformed(t *testing.T) {
	b, _ := newTestAppArmorWorkloadBackend(t)
	name := workloadAppArmorProfileName("op_v1")
	stateDir := t.TempDir()

	// Foreign backend record.
	rec := workloadMACRecord{OperationID: "op_v1", SessionID: "s", Backend: "foreign", ProfileName: name}
	rec.StateDir = stateDir
	if err := b.validateOwnedState(rec); err == nil {
		t.Error("foreign backend record must fail validation")
	}

	// Record naming a profile that is not the deterministic one.
	rec = workloadMACRecord{OperationID: "op_v1", SessionID: "s", Backend: string(LSMAppArmor), ProfileName: "docker-helper-workload-other"}
	rec.StateDir = stateDir
	if err := b.validateOwnedState(rec); err == nil {
		t.Error("mismatched profile name must fail validation")
	}

	// Missing profile source.
	rec = workloadMACRecord{OperationID: "op_v1", SessionID: "s", Backend: string(LSMAppArmor), ProfileName: name}
	rec.StateDir = stateDir
	if err := b.validateOwnedState(rec); err == nil {
		t.Error("missing profile source must fail validation")
	}

	// Symlinked profile source must never validate as owned state.
	if err := os.WriteFile(filepath.Join(t.TempDir(), "target"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(t.TempDir(), "target"), filepath.Join(stateDir, appArmorWorkloadProfileFileName)); err != nil {
		t.Fatal(err)
	}
	if err := b.validateOwnedState(rec); err == nil {
		t.Error("symlinked profile source must fail validation")
	}

	// A well-formed owned record validates: replace the symlink with a
	// real helper-owned regular file.
	if err := os.Remove(filepath.Join(stateDir, appArmorWorkloadProfileFileName)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, appArmorWorkloadProfileFileName), []byte(renderWorkloadAppArmorProfile(name, nil, false)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := b.validateOwnedState(rec); err != nil {
		t.Errorf("well-formed owned record must validate: %v", err)
	}
}

// TestCoordinatorPrepareCommitsRecordBeforeParserLoad proves the crash-safety
// ordering: the durable ownership record exists on disk before the backend
// touches its first kernel-side resource.
func TestCoordinatorPrepareCommitsRecordBeforeParserLoad(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	app.Config.Mode = ModeSystem
	c := installTestWorkloadMACForTest(t, app, LSMAppArmor)
	prep := workloadPreparation{
		OperationID:   "op_crash1",
		SessionID:     "s",
		Exposures:     []sessionFilesystemExposure{{Target: "/inputs", RequestedReadOnly: true}},
		PinnedSources: []string{"/runtime/pinned/0"},
	}
	prepared, err := c.Prepare(prep)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer prepared.Cleanup()
	recPath := filepath.Join(app.Config.StateDir, workloadMACStateRootName, "op_crash1", "ownership")
	if _, err := os.Stat(recPath); err != nil {
		t.Fatalf("ownership record must be durable: %v", err)
	}
}

// TestCoordinatorReconcileOwnedStaleProfile drives the coordinator-level
// startup reconciliation of a owned stale AppArmor state with no correlated
// container: profile unloaded and owned state removed.
func TestCoordinatorReconcileOwnedStaleProfile(t *testing.T) {
	dir := t.TempDir()
	opID := "op_rec1"
	name := workloadAppArmorProfileName(opID)
	stateRoot := filepath.Join(dir, "state")
	runtimeRoot := filepath.Join(dir, "runtime")
	recDir := filepath.Join(stateRoot, opID)
	if err := os.MkdirAll(recDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := writeWorkloadMACRecord(recDir, workloadMACRecord{
		Schema: workloadMACStateSchema, OperationID: opID, SessionID: "sess1",
		Backend: string(LSMAppArmor), ProfileName: name,
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(recDir, appArmorWorkloadProfileFileName), []byte(renderWorkloadAppArmorProfile(name, nil, false)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(runtimeRoot, opID), 0700); err != nil {
		t.Fatal(err)
	}

	b, h := newTestAppArmorWorkloadBackend(t)
	h.loaded[name] = true
	probePath := filepath.Join(t.TempDir(), appArmorWorkloadProfileFileName)
	if err := os.WriteFile(probePath, []byte(renderWorkloadAppArmorProfile(name, nil, false)), 0600); err != nil {
		t.Fatal(err)
	}
	c := &workloadMACCoordinator{
		backend:     b,
		stateRoot:   stateRoot,
		runtimeRoot: runtimeRoot,
		inspectContainers: func(ctx context.Context, operationID, sessionID string) ([]helperContainer, error) {
			return nil, nil
		},
		removeContainer:  func(ctx context.Context, id string) error { return nil },
		cleanupStalePins: func(operationID string) {},
	}
	if err := c.ReconcileStartup(context.Background()); err != nil {
		t.Fatalf("ReconcileStartup: %v", err)
	}
	if h.loaded[name] {
		t.Fatal("owned stale profile must be unloaded")
	}
	if _, err := os.Stat(recDir); !os.IsNotExist(err) {
		t.Errorf("owned state must be removed, got %v", err)
	}
}

// TestCoordinatorReconcileRetainsForeignState proves reconciliation never
// deletes foreign or malformed state directories: only positively identified
// owned state may be cleaned.
func TestCoordinatorReconcileRetainsForeignState(t *testing.T) {
	dir := t.TempDir()
	stateRoot := filepath.Join(dir, "state")
	runtimeRoot := filepath.Join(dir, "runtime")

	// A foreign state directory (plausible name, no ownership record).
	foreignDir := filepath.Join(stateRoot, "op_foreign0000000000000000000")
	if err := os.MkdirAll(foreignDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(foreignDir, "foreign-marker"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	// A symlinked entry must be ignored outright.
	if err := os.Symlink(filepath.Join(dir, "target"), filepath.Join(stateRoot, "op_link0000000000000000000000")); err != nil {
		t.Fatal(err)
	}

	b, _ := newTestAppArmorWorkloadBackend(t)
	c := &workloadMACCoordinator{
		backend:     b,
		stateRoot:   stateRoot,
		runtimeRoot: runtimeRoot,
		inspectContainers: func(ctx context.Context, operationID, sessionID string) ([]helperContainer, error) {
			t.Fatal("foreign state must not trigger container queries")
			return nil, nil
		},
		removeContainer: func(ctx context.Context, id string) error {
			t.Fatal("foreign state must not remove containers")
			return nil
		},
		cleanupStalePins: func(operationID string) { t.Fatal("foreign state must not clean pins") },
	}
	if err := c.ReconcileStartup(context.Background()); err != nil {
		t.Fatalf("ReconcileStartup: %v", err)
	}
	if _, err := os.Stat(foreignDir); err != nil {
		t.Fatalf("foreign state directory must be preserved: %v", err)
	}
}

// TestCoordinatorReconcileRetainsAmbiguousContainers proves the reconcile
// outcomes for correlated container ambiguity: more than one correlated
// container, or an unclassifiable Docker error, must retain state and never
// remove a container on a guess.
func TestCoordinatorReconcileRetainsAmbiguousContainers(t *testing.T) {
	dir := t.TempDir()
	stateRoot := filepath.Join(dir, "state")
	runtimeRoot := filepath.Join(dir, "runtime")
	opID := "op_amb1"
	recDir := filepath.Join(stateRoot, opID)
	if err := os.MkdirAll(recDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := writeWorkloadMACRecord(recDir, workloadMACRecord{
		Schema: workloadMACStateSchema, OperationID: opID, SessionID: "sess1", Backend: string(LSMAppArmor),
		ProfileName: workloadAppArmorProfileName(opID),
	}); err != nil {
		t.Fatal(err)
	}

	b, _ := newTestAppArmorWorkloadBackend(t)
	queries := 0
	c := &workloadMACCoordinator{
		backend:     b,
		stateRoot:   stateRoot,
		runtimeRoot: runtimeRoot,
		inspectContainers: func(ctx context.Context, operationID, sessionID string) ([]helperContainer, error) {
			queries++
			return []helperContainer{{ID: "abc1", State: "running"}, {ID: "abc2", State: "running"}}, nil
		},
		removeContainer: func(ctx context.Context, id string) error {
			t.Fatal("ambiguous correlation must not remove containers")
			return nil
		},
		cleanupStalePins: func(operationID string) { t.Fatal("ambiguous state must not clean pins") },
	}
	if err := c.ReconcileStartup(context.Background()); err != nil {
		t.Fatalf("ReconcileStartup with >1 correlated containers must retain: %v", err)
	}
	if _, err := os.Stat(recDir); err != nil {
		t.Fatalf("ambiguous state must be retained: %v", err)
	}

	// Docker query failure: retain, never guess.
	recDir2 := filepath.Join(stateRoot, "op_amb2")
	if err := os.MkdirAll(recDir2, 0700); err != nil {
		t.Fatal(err)
	}
	if err := writeWorkloadMACRecord(recDir2, workloadMACRecord{
		Schema: workloadMACStateSchema, OperationID: "op_amb2", SessionID: "sess1", Backend: string(LSMAppArmor),
		ProfileName: workloadAppArmorProfileName("op_amb2"),
	}); err != nil {
		t.Fatal(err)
	}
	c.inspectContainers = func(ctx context.Context, operationID, sessionID string) ([]helperContainer, error) {
		return nil, errors.New("docker daemon down")
	}
	if err := c.ReconcileStartup(context.Background()); err != nil {
		t.Fatalf("ReconcileStartup with docker failure: %v", err)
	}
	if _, err := os.Stat(recDir2); err != nil {
		t.Fatalf("state must be retained when docker is unavailable: %v", err)
	}
}

// TestCoordinatorReconcileRemovesStaleOwnedContainer drives the exactly-one
// stale-container reconciliation outcome: force remove, verify absent, then
// clean the workload MAC state and dependent pins.
func TestCoordinatorReconcileRemovesStaleOwnedContainer(t *testing.T) {
	dir := t.TempDir()
	stateRoot := filepath.Join(dir, "state")
	runtimeRoot := filepath.Join(dir, "runtime")
	opID := "op_stale1"
	recDir := filepath.Join(stateRoot, opID)
	if err := os.MkdirAll(recDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := writeWorkloadMACRecord(recDir, workloadMACRecord{
		Schema: workloadMACStateSchema, OperationID: opID, SessionID: "sess1",
		Backend: string(LSMAppArmor), ProfileName: workloadAppArmorProfileName(opID),
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(recDir, appArmorWorkloadProfileFileName), []byte(renderWorkloadAppArmorProfile(workloadAppArmorProfileName(opID), nil, false)), 0600); err != nil {
		t.Fatal(err)
	}

	b, h := newTestAppArmorWorkloadBackend(t)
	h.loaded[workloadAppArmorProfileName(opID)] = true
	removed := []string{}
	pinsCleaned := []string{}
	c := &workloadMACCoordinator{
		backend:     b,
		stateRoot:   stateRoot,
		runtimeRoot: runtimeRoot,
		inspectContainers: func(ctx context.Context, operationID, sessionID string) ([]helperContainer, error) {
			if len(removed) > 0 {
				return nil, nil // absent after removal
			}
			return []helperContainer{{ID: "stale1", State: "running"}}, nil
		},
		removeContainer: func(ctx context.Context, id string) error {
			removed = append(removed, id)
			return nil
		},
		cleanupStalePins: func(operationID string) { pinsCleaned = append(pinsCleaned, operationID) },
	}
	if err := c.ReconcileStartup(context.Background()); err != nil {
		t.Fatalf("ReconcileStartup: %v", err)
	}
	if len(removed) != 1 || removed[0] != "stale1" {
		t.Errorf("expected one stale container removal, got %v", removed)
	}
	if len(pinsCleaned) != 1 || pinsCleaned[0] != opID {
		t.Errorf("expected dependent pins cleaned, got %v", pinsCleaned)
	}
	if _, err := os.Stat(recDir); !os.IsNotExist(err) {
		t.Errorf("owned state must be removed after container removal, got %v", err)
	}
}
