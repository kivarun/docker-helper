package main

// builder_launcher_test.go pins the Phase 4A categorized launcher chain
// (G32 r3 §5): the fixed target context, the single canonical argv
// grammar, the validate -> procattr -> exec ordering with no
// intermediate spawn owner, the fail-closed failure semantics, the
// manager's single composition decision, and the internal command's
// invisibility on every presentation surface.

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

// launcherEvent is one observed launcher action.
type launcherEvent struct {
	kind string // "procattr", "exec"
	path string // the procattr pathname or the exec target
	ctx  string // the procattr value
	argv []string
	env  []string
}

// launcherSeams installs the procattr/exec observation seams; failures
// are forced per test through the returned struct. Package-global seams:
// no t.Parallel around them.
type launcherSeams struct {
	mu          sync.Mutex
	events      []launcherEvent
	procattrErr error
	execErr     error
}

func installLauncherSeams(t *testing.T) *launcherSeams {
	t.Helper()
	s := &launcherSeams{}
	origProcattr, origExec := builderWriteProcattrExec, builderExecve
	builderWriteProcattrExec = func(context string) error {
		s.mu.Lock()
		s.events = append(s.events, launcherEvent{kind: "procattr", path: "/proc/self/attr/exec", ctx: context})
		s.mu.Unlock()
		if s.procattrErr != nil {
			return s.procattrErr
		}
		return nil
	}
	builderExecve = func(path string, argv []string, env []string) error {
		s.mu.Lock()
		s.events = append(s.events, launcherEvent{kind: "exec", path: path, argv: append([]string(nil), argv...), env: append([]string(nil), env...)})
		s.mu.Unlock()
		if s.execErr != nil {
			return s.execErr
		}
		return nil
	}
	t.Cleanup(func() { builderWriteProcattrExec, builderExecve = origProcattr, origExec })
	return s
}

func (s *launcherSeams) snapshot() []launcherEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]launcherEvent(nil), s.events...)
}

// TestBuilderProcessTargetContextCanonical is the fixed target-context
// gate: the only variable part is the canonical category.
func TestBuilderProcessTargetContextCanonical(t *testing.T) {
	if got := builderProcessTargetContext(builderCategory(1)); got != "system_u:system_r:docker_helper_rootlesskit_t:s0:c1" {
		t.Errorf("target context c1 = %q", got)
	}
	if got := builderProcessTargetContext(builderCategory(1023)); got != "system_u:system_r:docker_helper_rootlesskit_t:s0:c1023" {
		t.Errorf("target context c1023 = %q", got)
	}
}

// TestBuilderLauncherInvalidCategoryRefuses proves the category grammar
// gate runs before any side effect: every malformed token refuses with
// the launcher's refusal code and touches neither the procattr nor the
// exec seam.
func TestBuilderLauncherInvalidCategoryRefuses(t *testing.T) {
	_, _, _ = processTestManager(t) // the argv grammar needs the root seams
	s := installLauncherSeams(t)

	opID := "op_0123456789abcdef0123456789abcdef"
	argv := builderRootlessKitArgv(opID, opRuntimeDir(opID), opStateDir(opID))
	for _, token := range []string{"c0", "c1024", "c1,2", "c1.c3", "s0", "C1", "c", "", "c-1", "c01", " c1", "c1 "} {
		var stderr bytes.Buffer
		if code := runBuilderLaunchExec(append([]string{token}, argv...), &stderr); code != 2 {
			t.Errorf("launch-exec %q: exit %d, want refusal 2 (stderr: %q)", token, code, stderr.String())
		}
	}
	if n := len(s.snapshot()); n != 0 {
		t.Fatalf("invalid category touched the launch seams: %d events", n)
	}
}

// TestBuilderLauncherRejectsInvalidArgv proves the argv grammar gate: the
// received rootlesskit argv must rebuild EXACTLY from the canonical owner
// for the op id derived from the --state-dir argument.
func TestBuilderLauncherRejectsInvalidArgv(t *testing.T) {
	_, _, _ = processTestManager(t)
	s := installLauncherSeams(t)

	opID := "op_0123456789abcdef0123456789abcdef"
	other := "op_fedcba9876543210fedcba9876543210"
	canonical := builderRootlessKitArgv(opID, opRuntimeDir(opID), opStateDir(opID))

	otherCanonical := builderRootlessKitArgv(other, opRuntimeDir(other), opStateDir(other))
	wrongRoot := slices.Clone(canonical)
	for i, a := range wrongRoot {
		if strings.HasPrefix(a, "--root=") {
			wrongRoot[i] = otherCanonical[6]
		}
	}
	noStateDir := slices.DeleteFunc(slices.Clone(canonical), func(a string) bool {
		return strings.HasPrefix(a, "--state-dir=")
	})
	wrongPath := slices.Clone(canonical)
	for i, a := range wrongPath {
		if strings.HasPrefix(a, "--state-dir=") {
			wrongPath[i] = "--state-dir=/tmp/somewhere/rootlesskit-state"
		}
	}
	wrongOpID := builderRootlessKitArgv("garbage", opRuntimeDir(opID), opStateDir(opID))
	changedFlag := slices.Clone(canonical)
	for i, a := range changedFlag {
		if a == "--net=slirp4netns" {
			changedFlag[i] = "--net=bridge"
		}
	}
	duplicated := append(slices.Clone(canonical), "--state-dir="+filepath.Join(opStateDir(opID), "rootlesskit-state"))

	for _, tc := range []struct {
		name string
		argv []string
	}{
		{"empty argv", nil},
		{"no state-dir argument", noStateDir},
		{"non-canonical state path", wrongPath},
		{"non-canonical op id", wrongOpID},
		{"cross-op path correlation", wrongRoot},
		{"altered flag value", changedFlag},
		{"extra flag", append(slices.Clone(canonical), "--extra=1")},
		{"duplicate state-dir", duplicated},
	} {
		var stderr bytes.Buffer
		if code := runBuilderLaunchExec(append([]string{"c1"}, tc.argv...), &stderr); code != 2 {
			t.Errorf("%s: exit %d, want refusal 2 (stderr: %q)", tc.name, code, stderr.String())
		}
	}
	if n := len(s.snapshot()); n != 0 {
		t.Fatalf("invalid argv touched the launch seams: %d events", n)
	}
}

// TestBuilderLauncherSetExecThenExecFixedTarget proves the launcher's
// successful chain: the canonical argv is accepted, the procattr write
// happens with the exact fixed target context, and the exec REPLACES the
// launcher with the fixed rootlesskit entry file — validate, then write,
// then exec, with no intermediate spawn owner.
func TestBuilderLauncherSetExecThenExecFixedTarget(t *testing.T) {
	_, _, _ = processTestManager(t)
	s := installLauncherSeams(t)

	opID := "op_0123456789abcdef0123456789abcdef"
	argv := builderRootlessKitArgv(opID, opRuntimeDir(opID), opStateDir(opID))

	var stderr bytes.Buffer
	if code := runBuilderLaunchExec(append([]string{"c1"}, argv...), &stderr); code != 0 {
		t.Fatalf("launch-exec exit %d (stderr: %q), want the successful exec replacement", code, stderr.String())
	}
	events := s.snapshot()
	if len(events) != 2 {
		t.Fatalf("observed %d events, want exactly procattr then exec", len(events))
	}
	procattr, execEvent := events[0], events[1]
	if procattr.kind != "procattr" || procattr.ctx != "system_u:system_r:docker_helper_rootlesskit_t:s0:c1" {
		t.Fatalf("procattr event = %+v, want the fixed c1 target context", procattr)
	}
	if execEvent.kind != "exec" {
		t.Fatalf("second event kind = %q, want exec", execEvent.kind)
	}
	if execEvent.path != builderManagerRootlessKit {
		t.Fatalf("exec target = %q, want the fixed %s (no PATH lookup)", execEvent.path, builderManagerRootlessKit)
	}
	if want := append([]string{builderManagerRootlessKit}, argv...); !slices.Equal(execEvent.argv, want) {
		t.Fatalf("exec argv = %v, want %v", execEvent.argv, want)
	}
	if !slices.Equal(execEvent.env, os.Environ()) {
		t.Fatalf("exec env must be the inherited environment verbatim")
	}
}

// TestBuilderLauncherProcattrFailureNoExec proves the procattr failure is
// fatal before any exec: the launcher exits non-zero and never execs.
func TestBuilderLauncherProcattrFailureNoExec(t *testing.T) {
	_, _, _ = processTestManager(t)
	s := installLauncherSeams(t)
	s.procattrErr = errors.New("procattr write denied")

	opID := "op_0123456789abcdef0123456789abcdef"
	argv := builderRootlessKitArgv(opID, opRuntimeDir(opID), opStateDir(opID))

	var stderr bytes.Buffer
	if code := runBuilderLaunchExec(append([]string{"c1"}, argv...), &stderr); code != 1 {
		t.Fatalf("launch-exec exit %d (stderr: %q), want 1", code, stderr.String())
	}
	if n := len(s.snapshot()); n != 1 {
		t.Fatalf("observed %d events, want exactly one procattr and no exec", n)
	}
}

// TestBuilderLauncherExecFailureNoFallback proves an exec failure exits
// non-zero with no fallback: exactly one fixed-target exec attempt, and
// never a second (legacy or retry) exec path.
func TestBuilderLauncherExecFailureNoFallback(t *testing.T) {
	_, _, _ = processTestManager(t)
	s := installLauncherSeams(t)
	s.execErr = errors.New("ENOEXEC")

	opID := "op_0123456789abcdef0123456789abcdef"
	argv := builderRootlessKitArgv(opID, opRuntimeDir(opID), opStateDir(opID))

	var stderr bytes.Buffer
	if code := runBuilderLaunchExec(append([]string{"c1"}, argv...), &stderr); code != 1 {
		t.Fatalf("launch-exec exit %d (stderr: %q), want 1", code, stderr.String())
	}
	events := s.snapshot()
	if len(events) != 2 || events[1].path != builderManagerRootlessKit {
		t.Fatalf("observed %+v, want procattr then exactly one fixed-target exec", events)
	}
}

// TestBuilderManagerSELinuxLaunchCommandShape proves the manager's
// enforcing-SELinux command: the fixed packaged binary, the internal
// launcher grammar, the record's category token, and the canonical argv.
func TestBuilderManagerSELinuxLaunchCommandShape(t *testing.T) {
	_, _, _ = processTestManager(t)

	opID := "op_0123456789abcdef0123456789abcdef"
	canonical := builderRootlessKitArgv(opID, opRuntimeDir(opID), opStateDir(opID))
	cmd := builderNewRootlessKitCommand(opID, builderCategory(1), opRuntimeDir(opID), opStateDir(opID), []string{"HOME=/x", "USER=u"}, true)

	if cmd.Path != builderManagerSelfBinary {
		t.Fatalf("SELinux launch command path = %q, want the fixed packaged binary %s", cmd.Path, builderManagerSelfBinary)
	}
	wantArgs := append([]string{builderManagerSelfBinary, "builder", "launch-exec", "c1"}, canonical...)
	if !slices.Equal(cmd.Args, wantArgs) {
		t.Fatalf("SELinux launch command args = %v, want %v", cmd.Args, wantArgs)
	}
	if !slices.Equal(cmd.Env, []string{"HOME=/x", "USER=u"}) {
		t.Fatalf("the manager keeps building the child environment: %v", cmd.Env)
	}
}

// TestBuilderManagerNonSELinuxLaunchCommandShape proves the non-SELinux
// command: the direct rootlesskit exec, unchanged, with the canonical
// argv; the launcher path is not used.
func TestBuilderManagerNonSELinuxLaunchCommandShape(t *testing.T) {
	_, _, _ = processTestManager(t)

	opID := "op_0123456789abcdef0123456789abcdef"
	canonical := builderRootlessKitArgv(opID, opRuntimeDir(opID), opStateDir(opID))
	cmd := builderNewRootlessKitCommand(opID, builderCategory(1), opRuntimeDir(opID), opStateDir(opID), []string{"HOME=/x"}, false)

	if cmd.Path != builderManagerRootlessKit {
		t.Fatalf("non-SELinux launch command path = %q, want the direct %s", cmd.Path, builderManagerRootlessKit)
	}
	if want := append([]string{builderManagerRootlessKit}, canonical...); !slices.Equal(cmd.Args, want) {
		t.Fatalf("non-SELinux launch command args = %v, want %v", cmd.Args, want)
	}
}

// TestBuilderManagerSingleCompositionDecision proves one START has one
// composition decision: the backend is detected exactly once per START,
// the same decision drives the provisioning AND the command choice, and
// the launcher-shaped command carries the record's category.
func TestBuilderManagerSingleCompositionDecision(t *testing.T) {
	_, _, _ = processTestManager(t)
	m, _, _ := processTestManager(t)
	seamCA(t)
	seamLSMBackend(t, LSMSELinux)
	fakeLeaderSeam(t, true)
	f := newProvisionFixture(t)

	// Count the backend detections and capture the decision the command
	// owner received.
	detectionCalls := 0
	var capturedProvision bool
	origDetect := detectLSM
	detectLSM = func() (LSMBackend, error) {
		detectionCalls++
		return origDetect()
	}
	t.Cleanup(func() { detectLSM = origDetect })
	origCmd := builderNewRootlessKitCommand
	var cmdMu sync.Mutex
	builderNewRootlessKitCommand = func(opID string, category builderCategory, rtDir, stDir string, env []string, provision bool) *exec.Cmd {
		cmdMu.Lock()
		capturedProvision = provision
		cmdMu.Unlock()
		return origCmd(opID, category, rtDir, stDir, env, provision)
	}
	t.Cleanup(func() { builderNewRootlessKitCommand = origCmd })

	opID := "op_0123456789abcdef0123456789abcdef"
	respCh := make(chan string, 1)
	go func() { respCh <- m.start(opID, nil) }()
	if !waitInstance(t, m, opID, true) {
		t.Fatal("START did not reserve")
	}
	bindFakeBuildkitdSocket(t, opID)
	if resp := <-respCh; resp != builderManagerRespOK {
		t.Fatalf("START = %q, want OK", resp)
	}
	cmdMu.Lock()
	decided := capturedProvision
	cmdMu.Unlock()
	if !decided {
		t.Fatal("the command owner did not receive the SELinux composition decision")
	}
	if detectionCalls != 1 {
		t.Fatalf("detectLSM called %d times per START, want exactly one decision", detectionCalls)
	}
	setEvents := 0
	for _, e := range f.entries() {
		if e.kind == "set" {
			setEvents++
		}
	}
	if setEvents != 4 {
		t.Fatalf("the same decision must drive provisioning: %d set events, want 4", setEvents)
	}
	if category, _ := builderManagerCategoryOf(t, m, opID); category != builderCategory(1) {
		t.Fatalf("record category = %s, want c1", category)
	}
}

// TestBuilderLauncherFailureRunsFailedStartLifecycle proves the launcher
// failure semantics end to end: a launch child that exits non-zero (the
// launcher's own failure shape) converges through the existing failed
// START owner — record removed, tree removed, category reusable only
// after that removal — with no fallback to a direct launch.
func TestBuilderLauncherFailureRunsFailedStartLifecycle(t *testing.T) {
	m, _, _ := processTestManager(t)
	seamCA(t)
	seamLSMBackend(t, LSMSELinux)
	f := newProvisionFixture(t)

	opID := "op_0123456789abcdef0123456789abcdef"

	// The FIRST op's launch child exits immediately with a non-zero
	// status (the launcher's own failure shape: validation/procattr/exec
	// failure); the post-failure reuse proof launches normally.
	orig := builderNewRootlessKitCommand
	builderNewRootlessKitCommand = func(seamOpID string, _ builderCategory, rtDir, stDir string, _ []string, _ bool) *exec.Cmd {
		_ = rtDir
		_ = stDir
		if seamOpID == opID {
			return exec.Command("sh", "-c", "exit 3")
		}
		return exec.Command("sh", "-c", boundedSleepScript())
	}
	t.Cleanup(func() { builderNewRootlessKitCommand = orig })

	if resp := m.start(opID, nil); resp != builderManagerRespInternal {
		t.Fatalf("START with a failing launch child = %q, want internal", resp)
	}
	if !waitInstance(t, m, opID, false) {
		t.Fatal("the failed launch kept the record retained")
	}
	assertDirsAbsentAt(t, opID)
	// The provisioning ran strictly before the child failure: the failed
	// START's own provisioning assigned all four contexts (the count is
	// snapshotted before the post-failure reuse start adds its own).
	setEvents := 0
	for _, e := range f.entries() {
		if e.kind == "set" {
			setEvents++
		}
	}
	if setEvents != 4 {
		t.Fatalf("the provisioning before the child failure: %d set events, want 4", setEvents)
	}
	op2 := "op_fedcba9876543210fedcba9876543210"
	if category := startWithCategory(t, m, op2); category != builderCategory(1) {
		t.Fatalf("post-failure admission bound %s, want c1", category)
	}
}

// TestBuilderLaunchExecHiddenFromPresentation proves the internal command
// appears on NO presentation surface: root help, builder help, the help
// command, the missing-subcommand listing, the completion script, and the
// man-page source.
func TestBuilderLaunchExecHiddenFromPresentation(t *testing.T) {
	surfaces := []struct {
		name string
		run  func(t *testing.T) string
	}{
		{"root help (no args)", func(t *testing.T) string {
			var out, errOut bytes.Buffer
			runCommandWithWriters(nil, &out, &errOut)
			return out.String() + errOut.String()
		}},
		{"root help command", func(t *testing.T) string {
			var out, errOut bytes.Buffer
			runCommandWithWriters([]string{"help"}, &out, &errOut)
			return out.String() + errOut.String()
		}},
		{"builder --help", func(t *testing.T) string {
			var out, errOut bytes.Buffer
			runCommandWithWriters([]string{"builder", "--help"}, &out, &errOut)
			return out.String() + errOut.String()
		}},
		{"help builder", func(t *testing.T) string {
			var out, errOut bytes.Buffer
			runCommandWithWriters([]string{"help", "builder"}, &out, &errOut)
			return out.String() + errOut.String()
		}},
		{"builder missing subcommand", func(t *testing.T) string {
			var out, errOut bytes.Buffer
			runCommandWithWriters([]string{"builder"}, &out, &errOut)
			return out.String() + errOut.String()
		}},
		{"completion script", func(t *testing.T) string {
			return completionScript(t)
		}},
		{"man page", func(t *testing.T) string {
			data, err := os.ReadFile("docs/man/docker-helper.1")
			if err != nil {
				t.Fatalf("cannot read manpage: %v", err)
			}
			return string(data)
		}},
	}
	for _, surface := range surfaces {
		if text := surface.run(t); strings.Contains(text, "launch-exec") {
			t.Errorf("presentation surface %q leaks the internal command name", surface.name)
		}
	}
}

// TestBuilderLaunchExecDispatchableInternal proves the hidden command is
// still resolved and dispatched by the production dispatcher: the exact
// internal invocation reaches the launcher's validation and its malformed
// grammar refuses (the dispatcher path; the valid chain is covered by the
// seam-level tests).
func TestBuilderLaunchExecDispatchableInternal(t *testing.T) {
	var out, errOut bytes.Buffer
	code := runCommandWithWriters([]string{"builder", "launch-exec", "c0", "--net=slirp4netns"}, &out, &errOut)
	if code != 2 {
		t.Fatalf("internal invocation exit = %d, want the validation refusal 2", code)
	}
	if !strings.Contains(errOut.String(), "invalid operation category") {
		t.Fatalf("refusal stderr = %q, want the launcher's category refusal", errOut.String())
	}
	// The malformed internal grammar refuses too.
	errOut.Reset()
	code = runCommandWithWriters([]string{"builder", "launch-exec"}, &out, &errOut)
	if code != 2 {
		t.Fatalf("launch-exec without arguments: exit %d, want refusal 2", code)
	}
}
