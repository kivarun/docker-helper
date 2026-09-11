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
	ro := workloadAppArmorTargetPlan{
		RO: []appArmorROTarget{{Target: "/inputs"}, {Target: "/has space"}},
	}
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
	d := renderWorkloadAppArmorProfile("docker-helper-workload-op_x", workloadAppArmorTargetPlan{}, false)
	if strings.Contains(d, "audit deny") {
		t.Error("no RO targets must render no workload deny rules")
	}
}

// TestRenderWorkloadAppArmorProfileMixedModes proves one profile covers
// /project RW (no deny), /inputs RO (deny), /output RW (no deny).
func TestRenderWorkloadAppArmorProfileMixedModes(t *testing.T) {
	profile := renderWorkloadAppArmorProfile("n", workloadAppArmorTargetPlan{
		RO: []appArmorROTarget{{Target: "/inputs"}},
		RW: []string{"/project", "/output"},
	}, false)
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
	pins := testPinnedSources(t, dir, 2)
	prep := workloadPreparation{
		OperationID:   "op_a1",
		SessionID:     "sess1",
		StateDir:      dir,
		RuntimeDir:    dir,
		Exposures:     []sessionFilesystemExposure{{Target: "/inputs", RequestedReadOnly: true}, {Target: "/project", RequestedReadOnly: false}},
		PinnedSources: pins,
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
	if len(prepared.MountSources) != 2 || prepared.MountSources[0] != pins[0] || prepared.MountSources[1] != pins[1] {
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
	dir := t.TempDir()
	prep := workloadPreparation{
		OperationID:   "op_a2",
		SessionID:     "sess1",
		StateDir:      dir,
		RuntimeDir:    dir,
		Exposures:     []sessionFilesystemExposure{{Target: "/inputs", RequestedReadOnly: true}},
		PinnedSources: testPinnedSources(t, dir, 1),
	}
	if _, err := b.prepare(prep); err == nil {
		t.Fatal("load failure must fail preparation")
	}
	if h.loaded[workloadAppArmorProfileName("op_a2")] {
		t.Fatal("profile must not be loaded after failed preparation")
	}
}

// TestWorkloadAppArmorCleanupUnloadsProfileOnce proves cleanup unloads the
// loaded profile (identity derived from the record's operation ID), removes
// the owned profile source, and is idempotent.
func TestWorkloadAppArmorCleanupUnloadsProfileOnce(t *testing.T) {
	b, h := newTestAppArmorWorkloadBackend(t)
	dir := t.TempDir()
	name := workloadAppArmorProfileName("op_c1")
	h.loaded[name] = true
	if err := os.WriteFile(filepath.Join(dir, appArmorWorkloadProfileFileName), []byte(renderWorkloadAppArmorProfile(name, workloadAppArmorTargetPlan{}, false)), 0600); err != nil {
		t.Fatal(err)
	}
	rec := workloadMACRecord{OperationID: "op_c1", SessionID: "s", Backend: string(LSMAppArmor)}
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
// owned-state validation: foreign records and symlinked profile sources
// fail validation, while a missing profile source is the safely
// classifiable crash window (empty owned state) and a well-formed source
// validates.
func TestWorkloadAppArmorValidateOwnedStateRejectsMalformed(t *testing.T) {
	b, _ := newTestAppArmorWorkloadBackend(t)
	name := workloadAppArmorProfileName("op_v1")
	stateDir := t.TempDir()

	// Foreign backend record.
	rec := workloadMACRecord{OperationID: "op_v1", SessionID: "s", Backend: "foreign"}
	rec.StateDir = stateDir
	if err := b.validateOwnedState(rec); err == nil {
		t.Error("foreign backend record must fail validation")
	}

	// Ownership committed, crash before the profile source was written:
	// empty owned state validates and its cleanup classifies against the
	// kernel inventory.
	rec = workloadMACRecord{OperationID: "op_v1", SessionID: "s", Backend: string(LSMAppArmor)}
	rec.StateDir = stateDir
	if err := b.validateOwnedState(rec); err != nil {
		t.Errorf("missing profile source must classify as empty owned state: %v", err)
	}

	// Symlinked profile source must never validate as owned state.
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(stateDir, appArmorWorkloadProfileFileName)); err != nil {
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
	if err := os.WriteFile(filepath.Join(stateDir, appArmorWorkloadProfileFileName), []byte(renderWorkloadAppArmorProfile(name, workloadAppArmorTargetPlan{}, false)), 0600); err != nil {
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
		PinnedSources: testPinnedSources(t, app.Config.RuntimeDir, 1),
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
	opID := testOperationID(41)
	name := workloadAppArmorProfileName(opID)
	stateRoot := filepath.Join(dir, "state")
	runtimeRoot := filepath.Join(dir, "runtime")
	recDir := filepath.Join(stateRoot, opID)
	if err := os.MkdirAll(recDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := writeWorkloadMACRecord(recDir, workloadMACRecord{
		Schema: workloadMACStateSchema, OperationID: opID, SessionID: testWorkloadSessionID,
		Backend: string(LSMAppArmor),
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(recDir, appArmorWorkloadProfileFileName), []byte(renderWorkloadAppArmorProfile(name, workloadAppArmorTargetPlan{}, false)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(runtimeRoot, opID), 0700); err != nil {
		t.Fatal(err)
	}

	b, h := newTestAppArmorWorkloadBackend(t)
	h.loaded[name] = true
	probePath := filepath.Join(t.TempDir(), appArmorWorkloadProfileFileName)
	if err := os.WriteFile(probePath, []byte(renderWorkloadAppArmorProfile(name, workloadAppArmorTargetPlan{}, false)), 0600); err != nil {
		t.Fatal(err)
	}
	c := &workloadMACCoordinator{
		backend:     b,
		stateRoot:   stateRoot,
		runtimeRoot: runtimeRoot,
		docker: containerProvenance{
			inspect: func(ctx context.Context, operationID, sessionID string) ([]helperContainer, error) {
				return nil, nil
			},
			remove: func(ctx context.Context, id string) error { return nil },
		},
		cleanupStalePins: func(operationID string) error { return nil },
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
		docker: containerProvenance{
			inspect: func(ctx context.Context, operationID, sessionID string) ([]helperContainer, error) {
				t.Fatal("foreign state must not trigger container queries")
				return nil, nil
			},
			remove: func(ctx context.Context, id string) error {
				t.Fatal("foreign state must not remove containers")
				return nil
			},
		},
		cleanupStalePins: func(operationID string) error { t.Fatal("foreign state must not clean pins"); return nil },
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
	opID := testOperationID(43)
	recDir := filepath.Join(stateRoot, opID)
	if err := os.MkdirAll(recDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := writeWorkloadMACRecord(recDir, workloadMACRecord{
		Schema: workloadMACStateSchema, OperationID: opID, SessionID: testWorkloadSessionID, Backend: string(LSMAppArmor),
	}); err != nil {
		t.Fatal(err)
	}

	b, _ := newTestAppArmorWorkloadBackend(t)
	queries := 0
	c := &workloadMACCoordinator{
		backend:     b,
		stateRoot:   stateRoot,
		runtimeRoot: runtimeRoot,
		docker: containerProvenance{
			inspect: func(ctx context.Context, operationID, sessionID string) ([]helperContainer, error) {
				queries++
				return []helperContainer{{ID: "abc1", State: "running"}, {ID: "abc2", State: "running"}}, nil
			},
			remove: func(ctx context.Context, id string) error {
				t.Fatal("ambiguous correlation must not remove containers")
				return nil
			},
		},
		cleanupStalePins: func(operationID string) error { t.Fatal("ambiguous state must not clean pins"); return nil },
	}
	if err := c.ReconcileStartup(context.Background()); err != nil {
		t.Fatalf("ReconcileStartup with >1 correlated containers must retain: %v", err)
	}
	if _, err := os.Stat(recDir); err != nil {
		t.Fatalf("ambiguous state must be retained: %v", err)
	}

	// Docker query failure: retain, never guess.
	recDir2 := filepath.Join(stateRoot, testOperationID(44))
	if err := os.MkdirAll(recDir2, 0700); err != nil {
		t.Fatal(err)
	}
	if err := writeWorkloadMACRecord(recDir2, workloadMACRecord{
		Schema: workloadMACStateSchema, OperationID: testOperationID(44), SessionID: testWorkloadSessionID, Backend: string(LSMAppArmor),
	}); err != nil {
		t.Fatal(err)
	}
	c.docker.inspect = func(ctx context.Context, operationID, sessionID string) ([]helperContainer, error) {
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
	opID := testOperationID(42)
	recDir := filepath.Join(stateRoot, opID)
	if err := os.MkdirAll(recDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := writeWorkloadMACRecord(recDir, workloadMACRecord{
		Schema: workloadMACStateSchema, OperationID: opID, SessionID: testWorkloadSessionID,
		Backend: string(LSMAppArmor),
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(recDir, appArmorWorkloadProfileFileName), []byte(renderWorkloadAppArmorProfile(workloadAppArmorProfileName(opID), workloadAppArmorTargetPlan{}, false)), 0600); err != nil {
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
		docker: containerProvenance{
			inspect: func(ctx context.Context, operationID, sessionID string) ([]helperContainer, error) {
				if len(removed) > 0 {
					return nil, nil // absent after removal
				}
				return []helperContainer{{ID: "stale1", State: "running"}}, nil
			},
			remove: func(ctx context.Context, id string) error {
				removed = append(removed, id)
				return nil
			},
		},
		cleanupStalePins: func(operationID string) error {
			pinsCleaned = append(pinsCleaned, operationID)
			return nil
		},
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

// matchAAREFragment evaluates the subset of the AppArmor alternation
// language produced by the workload renderer against one path segment:
// literals (with \xNN escapes), '?' (one byte), '*' (any run of bytes),
// '[^...]' (one byte outside the class), '{a,b}' (alternation), and '**'
// (any run of bytes; path segments carry no separators). The kernel
// semantics of these fragments are proven by the required live proofs;
// this matcher only pins the rendered logic between releases.
func matchAAREFragment(pattern, segment string) bool {
	return matchAARESub(pattern, 0, segment, 0)
}

func matchAARESub(pattern string, pi int, segment string, si int) bool {
	for pi < len(pattern) {
		switch pattern[pi] {
		case '{':
			depth, j := 1, pi+1
			for ; j < len(pattern) && depth > 0; j++ {
				switch pattern[j] {
				case '{':
					depth++
				case '}':
					depth--
				}
			}
			if depth != 0 {
				return false
			}
			body := pattern[pi+1 : j-1]
			for _, alt := range splitAAREAlternation(body) {
				if matchAARESub(alt+pattern[j:], 0, segment, si) {
					return true
				}
			}
			return false
		case '\\':
			if pi+3 >= len(pattern)+1 || pi+4 > len(pattern) || pattern[pi+1] != 'x' {
				return false
			}
			hi := hexByteVal(pattern[pi+2])
			lo := hexByteVal(pattern[pi+3])
			if hi < 0 || lo < 0 || si >= len(segment) || segment[si] != byte(hi<<4|lo) {
				return false
			}
			pi += 4
			si++
		case '?':
			if si >= len(segment) {
				return false
			}
			pi++
			si++
		case '*':
			if pi+1 < len(pattern) && pattern[pi+1] == '*' {
				return true
			}
			for k := si; k <= len(segment); k++ {
				if matchAARESub(pattern, pi+1, segment, k) {
					return true
				}
			}
			return false
		case '[':
			end := strings.IndexByte(pattern[pi:], ']')
			if end < 0 {
				return false
			}
			end += pi
			body, negated := pattern[pi+1:end], false
			if strings.HasPrefix(body, "^") {
				negated, body = true, body[1:]
			}
			allowed := decodeAAREClass(body)
			if si >= len(segment) {
				return false
			}
			_, in := allowed[segment[si]]
			if in == negated {
				return false
			}
			pi = end + 1
			si++
		default:
			if si >= len(segment) || pattern[pi] != segment[si] {
				return false
			}
			pi++
			si++
		}
	}
	return si == len(segment)
}

func splitAAREAlternation(body string) []string {
	var alts []string
	depth, start := 0, 0
	for i := 0; i < len(body); i++ {
		switch body[i] {
		case '{':
			depth++
		case '}':
			depth--
		case ',':
			if depth == 0 {
				alts = append(alts, body[start:i])
				start = i + 1
			}
		}
	}
	return append(alts, body[start:])
}

func decodeAAREClass(body string) map[byte]bool {
	set := map[byte]bool{}
	for i := 0; i < len(body); {
		if body[i] == '\\' && i+3 < len(body) && body[i+1] == 'x' {
			hi := hexByteVal(body[i+2])
			lo := hexByteVal(body[i+3])
			if hi >= 0 && lo >= 0 {
				set[byte(hi<<4|lo)] = true
				i += 4
				continue
			}
		}
		set[body[i]] = true
		i++
	}
	return set
}

func hexByteVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	default:
		return -1
	}
}

// appArmorExclusionFromRule extracts the {EXCL} fragment of one subtree
// rule rendered by the workload renderer: the balanced-brace group that
// opens right after the base's `/{`.
func appArmorExclusionFromRule(rule string) string {
	open := strings.Index(rule, `/{`) + 2
	if open-1 >= len(rule) || open > len(rule) {
		return ""
	}
	depth := 1
	for i := open; i < len(rule); i++ {
		switch rule[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return rule[open:i]
			}
		}
	}
	return ""
}

// appArmorHoleExclusion extracts the widest exclusion fragment rendered
// for the base path of one read-only target: the longest `{EXCL}` group
// among that base's rules.
func appArmorHoleExclusion(profile, base string) string {
	excl := ""
	for _, line := range strings.Split(profile, "\n") {
		if !strings.Contains(line, `audit deny "`+base+`/{`) {
			continue
		}
		if inner := appArmorExclusionFromRule(line); len(inner) > len(excl) {
			excl = inner
		}
	}
	return excl
}

// TestAppArmorSegmentExclusionSemantics proves the segment exclusion
// fragment matches exactly the segments that are not one of the excluded
// names, including byte-level boundaries of multi-byte names.
func TestAppArmorSegmentExclusionSemantics(t *testing.T) {
	cases := []struct {
		names   []string
		match   []string
		noMatch []string
		name    string
	}{
		{[]string{"output"}, []string{"input", "o", "ou", "outputs"}, []string{"output"}, "single name"},
		{[]string{"output", "aux"}, []string{"input", "out", "au", "axx"}, []string{"output", "aux"}, "siblings"},
		{[]string{"a", "ab"}, []string{"abc", "ax", "b"}, []string{"a", "ab"}, "prefix pair"},
		{[]string{"b", "bd"}, []string{"bda", "bx", "d", "dz", "e"}, []string{"b", "bd"}, "first-byte divergence"},
		{[]string{"ab", "bax"}, []string{"ax", "ba", "bb", "aba"}, []string{"ab", "bax"}, "multi-byte leaf boundaries"},
		{[]string{"ou", "x"}, []string{"out", "o", "ouu", "xy"}, []string{"ou", "x"}, "partial-prefix and full leaf"},
	}
	for _, tc := range cases {
		frag := appArmorSegmentExclusion(tc.names)
		if strings.Contains(frag, ",,") {
			t.Errorf("%s: fragment %q contains an empty alternation entry", tc.name, frag)
		}
		for _, s := range tc.match {
			if !matchAAREFragment(frag, s) {
				t.Errorf("%s: fragment %q must match %q", tc.name, frag, s)
			}
		}
		for _, s := range tc.noMatch {
			if matchAAREFragment(frag, s) {
				t.Errorf("%s: fragment %q must not match %q", tc.name, frag, s)
			}
		}
	}
}

// TestRenderWorkloadAppArmorProfileRegularFileDeniesFileShape proves F2:
// a read-only target whose pinned source is a regular file renders the
// exact-file deny rule and no directory-shaped rule.
func TestRenderWorkloadAppArmorProfileRegularFileDeniesFileShape(t *testing.T) {
	profile := renderWorkloadAppArmorProfile("n", workloadAppArmorTargetPlan{
		RO: []appArmorROTarget{{Target: "/config.txt", RegularFile: true}},
	}, false)
	if !strings.Contains(profile, `audit deny "/config.txt" wkl,`) {
		t.Errorf("regular-file target must deny the exact path, got:\n%s", profile)
	}
	if strings.Contains(profile, `"/config.txt/{`) {
		t.Errorf("regular-file target must not carry a directory-shaped rule:\n%s", profile)
	}
}

// TestRenderWorkloadAppArmorProfileNestedRWStaysWritable proves F3 case A:
// RO /work plus RW /work/output renders hole rules whose exclusion keeps
// /work/output writable while every other name under /work is denied.
func TestRenderWorkloadAppArmorProfileNestedRWStaysWritable(t *testing.T) {
	profile := renderWorkloadAppArmorProfile("n", workloadAppArmorTargetPlan{
		RO: []appArmorROTarget{{Target: "/work"}},
		RW: []string{"/work/output"},
	}, false)
	if strings.Contains(profile, `"/work/{,**}"`) {
		t.Errorf("holed RO target must not render the unholed recursive rule:\n%s", profile)
	}
	excl := appArmorHoleExclusion(profile, "/work")
	if excl == "" {
		t.Fatalf("holed RO target must render exclusion rules:\n%s", profile)
	}
	if matchAAREFragment(excl, "output") {
		t.Errorf("accepted RW target %q must stay writable (exclusion %q)", "/work/output", excl)
	}
	for _, s := range []string{"inputs", "outputx", "out", "o", ""} {
		if s != "" && !matchAAREFragment(excl, s) {
			t.Errorf("exclusion %q must match non-hole segment %q", excl, s)
		}
	}
	if strings.Count(profile, `audit deny "`) != 3 {
		t.Errorf("single-hole target renders exactly entry, file, and subtree rules:\n%s", profile)
	}
}

// TestRenderWorkloadAppArmorProfileNestedRWWithInnerRO proves F3 case B:
// RO /work, RW /work/output, RO /work/output/protected keeps the RW
// transition writable and independently denies the nested RO island.
func TestRenderWorkloadAppArmorProfileNestedRWWithInnerRO(t *testing.T) {
	profile := renderWorkloadAppArmorProfile("n", workloadAppArmorTargetPlan{
		RO: []appArmorROTarget{{Target: "/work"}, {Target: "/work/output/protected"}},
		RW: []string{"/work/output"},
	}, false)
	if !strings.Contains(profile, `audit deny "/work/output/protected/{,**}" wkl,`) {
		t.Errorf("nested RO island must keep the recursive deny rule:\n%s", profile)
	}
	excl := appArmorHoleExclusion(profile, "/work")
	if matchAAREFragment(excl, "output") {
		t.Errorf("RW transition must stay writable, exclusion %q", excl)
	}
	if strings.Count(profile, `audit deny "`) != 4 {
		t.Errorf("island rules must not duplicate hole rules:\n%s", profile)
	}
}

// TestRenderWorkloadAppArmorProfileExoticHoleBytes proves the hole-path
// renderer keeps bytes outside the AppArmor class set literal-safe: the
// exclusion class escapes them as hex and never emits raw continuation
// bytes into the rendered rule.
func TestRenderWorkloadAppArmorProfileExoticHoleBytes(t *testing.T) {
	hole := "/work/aéb→c"
	profile := renderWorkloadAppArmorProfile("n", workloadAppArmorTargetPlan{
		RO: []appArmorROTarget{{Target: "/work"}},
		RW: []string{hole},
	}, false)
	excl := appArmorHoleExclusion(profile, "/work")
	if matchAAREFragment(excl, "aéb→c") {
		t.Errorf("hole segment must stay writable, exclusion %q", excl)
	}
	for _, s := range []string{"aéb→d", "aéb", "aé", "a", "other"} {
		if !matchAAREFragment(excl, s) {
			t.Errorf("exclusion %q must match non-hole segment %q", excl, s)
		}
	}
	for _, b := range []byte(excl) {
		if b >= 0x80 {
			t.Errorf("exclusion %q must escape non-class-safe bytes as \\xNN", excl)
		}
	}
}

// TestRenderWorkloadAppArmorProfileHoleDeterminism proves the hole-path
// rendering is deterministic across repeated generation.
func TestRenderWorkloadAppArmorProfileHoleDeterminism(t *testing.T) {
	plan := workloadAppArmorTargetPlan{
		RO: []appArmorROTarget{{Target: "/work"}},
		RW: []string{"/work/output", "/work/aux/data"},
	}
	if renderWorkloadAppArmorProfile("n", plan, false) != renderWorkloadAppArmorProfile("n", plan, false) {
		t.Error("rendering must be deterministic")
	}
	profile := renderWorkloadAppArmorProfile("n", plan, false)
	if !strings.Contains(profile, `audit deny "/work/aux/{,}" wkl,`) {
		t.Errorf("intermediate hole nodes must render their own entry rule:\n%s", profile)
	}
}

// TestWorkloadAppArmorTargetPlanFromExposures proves the plan builder
// classifies pinned node kinds fail-closed and collects RW targets.
func TestWorkloadAppArmorTargetPlanFromExposures(t *testing.T) {
	dir := t.TempDir()
	filePin := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(filePin, []byte("cfg"), 0600); err != nil {
		t.Fatal(err)
	}
	dirPin := filepath.Join(dir, "tree")
	if err := os.Mkdir(dirPin, 0700); err != nil {
		t.Fatal(err)
	}
	plan, err := workloadAppArmorTargetPlanFromExposures(
		[]sessionFilesystemExposure{
			{Target: "/work", RequestedReadOnly: true},
			{Target: "/cfg", RequestedReadOnly: true},
			{Target: "/out", RequestedReadOnly: false},
		},
		[]string{dirPin, filePin, "/irrelevant"},
	)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if len(plan.RO) != 2 || plan.RO[0].Target != "/work" || plan.RO[0].RegularFile {
		t.Errorf("directory pin must classify as directory: %+v", plan.RO)
	}
	if len(plan.RO) != 2 || plan.RO[1].Target != "/cfg" || !plan.RO[1].RegularFile {
		t.Errorf("file pin must classify as regular file: %+v", plan.RO)
	}
	if len(plan.RW) != 1 || plan.RW[0] != "/out" {
		t.Errorf("RW targets must be collected: %+v", plan.RW)
	}
	if _, err := workloadAppArmorTargetPlanFromExposures(
		[]sessionFilesystemExposure{{Target: "/x", RequestedReadOnly: true}},
		[]string{filepath.Join(dir, "missing")},
	); err == nil {
		t.Error("uninspectable pin must fail the plan (fail closed)")
	}
}
