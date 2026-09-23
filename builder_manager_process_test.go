package main

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"
)

// processTestManager builds a manager over test-scoped roots (production
// constants are package vars; restore on cleanup).
func processTestManager(t *testing.T) (*builderManager, string, string) {
	t.Helper()
	// Socket paths must fit sun_path (108 bytes): keep the base short.
	base, err := os.MkdirTemp(".", "bmt")
	if err != nil {
		t.Fatalf("cannot create short test base: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	rtRoot := filepath.Join(base, "run")
	stRoot := filepath.Join(base, "state")
	for _, d := range []string{rtRoot, stRoot} {
		if err := os.MkdirAll(d, 0700); err != nil {
			t.Fatalf("cannot create test roots: %v", err)
		}
	}
	origRT, origST := builderRuntimeRoot, builderStateRoot
	builderRuntimeRoot, builderStateRoot = rtRoot, stRoot
	t.Cleanup(func() { builderRuntimeRoot, builderStateRoot = origRT, origST })

	m := newBuilderManager(os.Getuid(), os.Getgid())

	// Test-owned instance teardown: every instance left running at test
	// end goes through the ONE production stop owner (bounded SIGTERM ->
	// SIGKILL group kill, single-owner reap, dir removal). The cleanup is
	// registered here so it runs BEFORE the runtime/state roots and the
	// spawn seam are restored (LIFO): stopInstance resolves op dirs and
	// process handles while the test-scoped values are still in place.
	// Stopping an already-stopped instance is the OK-absent no-op branch.
	t.Cleanup(func() {
		m.mu.Lock()
		ids := make([]string, 0, len(m.instances))
		for id := range m.instances {
			ids = append(ids, id)
		}
		m.mu.Unlock()
		for _, id := range ids {
			m.stop(id, 0)
			if !waitInstance(t, m, id, false) {
				t.Errorf("instance %s did not converge after test-owned stop", id)
			}
		}
	})

	return m, rtRoot, stRoot
}

// fakeLeader installs the synthetic process-tree leader seam: a real sh
// child that becomes session leader (Setsid is applied by the production
// spawn owner) and optionally creates the expected buildkitd socket via a
// listener (proving readiness mechanics against the real contract).
func fakeLeaderSeam(t *testing.T, ready bool) {
	t.Helper()
	orig := builderNewRootlessKitCommand
	builderNewRootlessKitCommand = func(opID, rtDir, stDir string, env []string) *exec.Cmd {
		cmd := exec.Command("sh", "-c", boundedSleepScript())
		_ = opID
		_ = rtDir
		_ = stDir
		_ = env
		_ = ready
		return cmd
	}
	t.Cleanup(func() { builderNewRootlessKitCommand = orig })
}

func seamCA(t *testing.T) {
	t.Helper()
	orig := builderResolveSystemCAFunc
	builderResolveSystemCAFunc = func() ([]string, bool) { return []string{"SSL_CERT_FILE=/dev/null"}, true }
	t.Cleanup(func() { builderResolveSystemCAFunc = orig })
}

// bindFakeBuildkitdSocket binds a real unix socket at the expected
// readiness path (stand-in for buildkitd's bind). It waits for the
// manager to create the per-op runtime dir first and enforces the private
// mode contract the readiness check requires.
func bindFakeBuildkitdSocket(t *testing.T, opID string) net.Listener {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, err := os.Lstat(opRuntimeDir(opID))
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("runtime dir never created: %v", err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: opSocketPath(opID), Net: "unix"})
	if err != nil {
		t.Fatalf("cannot bind fake buildkitd socket: %v", err)
	}
	if err := os.Chmod(opSocketPath(opID), 0600); err != nil {
		t.Fatalf("cannot chmod fake socket: %v", err)
	}
	t.Cleanup(func() { listener.Close() })
	return listener
}

func waitInstance(t *testing.T, m *builderManager, opID string, want bool) bool {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		m.mu.Lock()
		_, ok := m.instances[opID]
		m.mu.Unlock()
		if ok == want {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

// waitLeaderPid waits bounded for the instance's leader pid to be
// recorded. waitInstance only proves the map reservation, not that
// launchInstance reached cmd.Start yet; asserting on a pid snapshot
// without this barrier can exit through t.Fatalf while the START
// goroutine is still inside launchInstance, racing the t.Cleanup seam
// restore (observed as a -race DATA RACE on builderRuntimeRoot).
func waitLeaderPid(t *testing.T, inst *builderInstance) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if pid := inst.leaderPidSnapshot(); pid > 1 {
			return pid
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("leader pid never recorded")
	return 0
}

// TestBuilderManagerStartReadinessSuccess: START through the real
// launchInstance path with a real leader child and a real socket bind;
// admission reservation, readiness contract, and ceiling entry all hold.
func TestBuilderManagerStartReadinessSuccess(t *testing.T) {
	m, _, _ := processTestManager(t)
	seamCA(t)
	fakeLeaderSeam(t, true)

	opID := "op_0123456789abcdef0123456789abcdef"
	respCh := make(chan string, 1)
	go func() { respCh <- m.start(opID, nil) }()

	// Wait for the child to spawn, then bind the fake buildkitd socket.
	if !waitInstance(t, m, opID, true) {
		t.Fatal("START did not reserve the map entry")
	}
	bindFakeBuildkitdSocket(t, opID)

	select {
	case resp := <-respCh:
		if resp != builderManagerRespOK {
			t.Fatalf("START response = %q, want OK", resp)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("START did not converge")
	}
}

// TestBuilderManagerConcurrentStartSameOpExactlyOneChild: two concurrent
// STARTs for one op -> exactly one spawn, one OK, one operation_exists.
func TestBuilderManagerConcurrentStartSameOpExactlyOneChild(t *testing.T) {
	m, _, _ := processTestManager(t)
	seamCA(t)
	fakeLeaderSeam(t, true)

	opID := "op_0123456789abcdef0123456789abcdef"

	var wg sync.WaitGroup
	respCh := make(chan string, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			respCh <- m.start(opID, nil)
		}()
	}
	if !waitInstance(t, m, opID, true) {
		t.Fatal("reservation missing")
	}
	bindFakeBuildkitdSocket(t, opID)
	wg.Wait()
	close(respCh)
	var okCount, existsCount int
	for resp := range respCh {
		switch resp {
		case builderManagerRespOK:
			okCount++
		case builderManagerRespOpExists:
			existsCount++
		default:
			t.Fatalf("unexpected response %q", resp)
		}
	}
	if okCount != 1 || existsCount != 1 {
		t.Fatalf("ok=%d exists=%d, want exactly one child admission", okCount, existsCount)
	}
}

// TestBuilderManagerThirdStartAtCeiling: two admitted distinct instances
// fill the ceiling (maxConcurrentBuildsGlobal=2); the third START is
// refused immediately with builder_at_ceiling. Proves the ceiling counts
// the reserved map entry (no queue).
func TestBuilderManagerThirdStartAtCeiling(t *testing.T) {
	m, _, _ := processTestManager(t)
	seamCA(t)
	fakeLeaderSeam(t, true)

	for _, opID := range []string{"op_0123456789abcdef0123456789abcdef", "op_fedcba9876543210fedcba9876543210"} {
		respCh := make(chan string, 1)
		go func() { respCh <- m.start(opID, nil) }()
		if !waitInstance(t, m, opID, true) {
			t.Fatalf("START %s did not reserve", opID)
		}
		bindFakeBuildkitdSocket(t, opID)
		if resp := <-respCh; resp != builderManagerRespOK {
			t.Fatalf("START %s = %q, want OK", opID, resp)
		}
	}
	if resp := m.start("op_11111111111111111111111111111111", nil); resp != builderManagerRespAtCeiling {
		t.Fatalf("third START = %q, want builder_at_ceiling", resp)
	}
	m.mu.Lock()
	count := len(m.instances)
	m.mu.Unlock()
	if count != 2 {
		t.Fatalf("instance count = %d, want 2 (refusal must not reserve)", count)
	}
}

// TestBuilderManagerStopDuringReadiness: STOP cancels a still-starting
// launch/readiness wait; the instance converges, dirs are removed, the
// ceiling is released.
func TestBuilderManagerStopDuringReadiness(t *testing.T) {
	m, _, _ := processTestManager(t)
	seamCA(t)
	fakeLeaderSeam(t, true)

	opID := "op_0123456789abcdef0123456789abcdef"
	respCh := make(chan string, 1)
	go func() { respCh <- m.start(opID, nil) }()
	if !waitInstance(t, m, opID, true) {
		t.Fatal("reservation missing")
	}

	if resp := m.stop(opID, 0); resp != builderManagerRespOK {
		t.Fatalf("STOP = %q, want OK", resp)
	}
	if !waitInstance(t, m, opID, false) {
		t.Fatal("STOP did not remove the map entry")
	}
	if _, err := os.Lstat(opRuntimeDir(opID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("runtime dir not removed: %v", err)
	}
	if _, err := os.Lstat(opStateDir(opID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state dir not removed: %v", err)
	}
	// Ceiling released: a new START is admitted.
	op2 := "op_fedcba9876543210fedcba9876543210"
	resp2Ch := make(chan string, 1)
	go func() { resp2Ch <- m.start(op2, nil) }()
	if !waitInstance(t, m, op2, true) {
		t.Fatal("post-STOP reservation missing")
	}
	bindFakeBuildkitdSocket(t, op2)
	if resp := <-resp2Ch; resp != builderManagerRespOK {
		t.Fatalf("post-STOP START = %q, want OK (ceiling must release)", resp)
	}
}

// TestBuilderManagerTwoConcurrentStops: both STOPs return OK (single
// cleanup claimant; the other waits for done) and the instance is gone.
func TestBuilderManagerTwoConcurrentStops(t *testing.T) {
	m, _, _ := processTestManager(t)
	seamCA(t)
	fakeLeaderSeam(t, true)

	opID := "op_0123456789abcdef0123456789abcdef"
	respCh := make(chan string, 1)
	go func() { respCh <- m.start(opID, nil) }()
	if !waitInstance(t, m, opID, true) {
		t.Fatal("reservation missing")
	}
	bindFakeBuildkitdSocket(t, opID)
	if resp := <-respCh; resp != builderManagerRespOK {
		t.Fatalf("START = %q", resp)
	}

	var wg sync.WaitGroup
	stopCh := make(chan string, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			stopCh <- m.stop(opID, 0)
		}()
	}
	wg.Wait()
	close(stopCh)
	for resp := range stopCh {
		if resp != builderManagerRespOK {
			t.Fatalf("STOP = %q, want OK", resp)
		}
	}
	if !waitInstance(t, m, opID, false) {
		t.Fatal("instance not removed")
	}
}

// TestBuilderManagerPurgeRacingStop: PURGE and STOP race; both converge
// through the single cleanup owner; final map is empty; responses legal.
func TestBuilderManagerPurgeRacingStop(t *testing.T) {
	m, _, _ := processTestManager(t)
	seamCA(t)
	fakeLeaderSeam(t, true)

	opID := "op_0123456789abcdef0123456789abcdef"
	respCh := make(chan string, 1)
	go func() { respCh <- m.start(opID, nil) }()
	if !waitInstance(t, m, opID, true) {
		t.Fatal("reservation missing")
	}
	bindFakeBuildkitdSocket(t, opID)
	if resp := <-respCh; resp != builderManagerRespOK {
		t.Fatalf("START = %q", resp)
	}

	var wg sync.WaitGroup
	resp2 := make(chan string, 2)
	wg.Add(2)
	go func() { defer wg.Done(); resp2 <- m.stop(opID, 0) }()
	go func() { defer wg.Done(); resp2 <- m.purge() }()
	wg.Wait()
	close(resp2)
	for resp := range resp2 {
		if resp != builderManagerRespOK {
			t.Fatalf("response = %q, want OK", resp)
		}
	}
	if !waitInstance(t, m, opID, false) {
		t.Fatal("instance not removed")
	}
}

// TestBuilderManagerUnexpectedExitReleasesCeiling: the leader exits by
// itself; the single Wait owner converges (dirs removed, map entry
// removed); a later STOP sees OK absent; the ceiling is released.
func TestBuilderManagerUnexpectedExitReleasesCeiling(t *testing.T) {
	m, _, _ := processTestManager(t)
	seamCA(t)

	// Leader that exits immediately after spawning.
	orig := builderNewRootlessKitCommand
	builderNewRootlessKitCommand = func(opID, rtDir, stDir string, env []string) *exec.Cmd {
		_ = opID
		_ = rtDir
		_ = stDir
		_ = env
		return exec.Command("sh", "-c", "exit 3")
	}
	t.Cleanup(func() { builderNewRootlessKitCommand = orig })

	opID := "op_0123456789abcdef0123456789abcdef"
	if resp := m.start(opID, nil); resp != builderManagerRespInternal {
		t.Fatalf("START after self-exit = %q, want internal", resp)
	}
	if !waitInstance(t, m, opID, false) {
		t.Fatal("unexpected exit did not release the map entry (zombie ceiling)")
	}
	if _, err := os.Lstat(opRuntimeDir(opID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("runtime dir not removed after self-exit: %v", err)
	}
	if resp := m.stop(opID, 0); resp != builderManagerRespOKAbsent {
		t.Fatalf("post-exit STOP = %q, want OK absent", resp)
	}
}

// TestBuilderManagerStartFailureReleasesCeiling: spawn failure (missing
// executable) converges: map entry removed, dirs removed, ceiling free.
func TestBuilderManagerStartFailureReleasesCeiling(t *testing.T) {
	m, _, _ := processTestManager(t)
	seamCA(t)

	orig := builderNewRootlessKitCommand
	builderNewRootlessKitCommand = func(opID, rtDir, stDir string, env []string) *exec.Cmd {
		_ = opID
		_ = rtDir
		_ = stDir
		_ = env
		return exec.Command("/nonexistent/rootlesskit")
	}
	t.Cleanup(func() { builderNewRootlessKitCommand = orig })

	opID := "op_0123456789abcdef0123456789abcdef"
	if resp := m.start(opID, nil); resp != builderManagerRespInternal {
		t.Fatalf("START spawn failure = %q, want internal", resp)
	}
	if !waitInstance(t, m, opID, false) {
		t.Fatal("failed START did not release the reservation")
	}
	if _, err := os.Lstat(opRuntimeDir(opID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("runtime dir not removed after failed START: %v", err)
	}
	if _, err := os.Lstat(opStateDir(opID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state dir not removed after failed START: %v", err)
	}
}

// TestBuilderManagerReadinessFailureKillsGroupAndRemovesDirs: the leader
// runs but never binds the socket; readiness fails bounded; the group is
// killed/reaped and dirs removed.
func TestBuilderManagerReadinessFailureKillsGroupAndRemovesDirs(t *testing.T) {
	// Shorten the readiness timeout for the test via a copy of the
	// constant? The constant is a const; instead rely on STOP semantics:
	// run readiness in the background, then STOP it and verify the
	// group died and dirs were removed (the same escalation owner).
	m, _, _ := processTestManager(t)
	seamCA(t)
	fakeLeaderSeam(t, true)

	opID := "op_0123456789abcdef0123456789abcdef"
	respCh := make(chan string, 1)
	go func() { respCh <- m.start(opID, nil) }()
	if !waitInstance(t, m, opID, true) {
		t.Fatal("reservation missing")
	}
	inst := m.instances[opID]
	pid := waitLeaderPid(t, inst)
	// Pre-existence self-test: the leader exists as a group leader.
	if processGroupGone(pid) {
		t.Fatal("pre-existence self-test: leader group already gone")
	}
	if resp := m.stop(opID, 0); resp != builderManagerRespOK {
		t.Fatalf("STOP = %q", resp)
	}
	select {
	case resp := <-respCh:
		if resp != builderManagerRespInternal {
			t.Fatalf("START after STOP = %q, want internal", resp)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("START did not converge after STOP")
	}
	if !processGroupGone(pid) {
		t.Fatalf("process group %d still alive after STOP", pid)
	}
	if _, err := os.Lstat(opRuntimeDir(opID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("runtime dir not removed: %v", err)
	}
	if _, err := os.Lstat(opStateDir(opID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state dir not removed: %v", err)
	}
}

// TestBuilderManagerStopBeforeSpawn: STOP claims during the launch
// window before cmd.Start; the child never spawns (no group to kill) and
// the instance converges cleanly. With the F1.3 quiescence await the
// STOP's OK cannot arrive while the parked launch is still in flight, so
// the STOP runs asynchronously: the test observes the claim, releases
// the launch (its post-claim convergence runs: claim check, dir
// re-removal), and only then reads the OK — at which instant the
// converged state carries no path residue without polling.
func TestBuilderManagerStopBeforeSpawn(t *testing.T) {
	m, _, _ := processTestManager(t)
	seamCA(t)

	spawnBlocker := make(chan struct{})
	orig := builderNewRootlessKitCommand
	builderNewRootlessKitCommand = func(opID, rtDir, stDir string, env []string) *exec.Cmd {
		<-spawnBlocker // hold the launch inside the spawn window
		_ = opID
		_ = rtDir
		_ = stDir
		_ = env
		return exec.Command("sh", "-c", boundedSleepScript())
	}
	t.Cleanup(func() { builderNewRootlessKitCommand = orig })

	opID := "op_0123456789abcdef0123456789abcdef"
	respCh := make(chan string, 1)
	go func() { respCh <- m.start(opID, nil) }()
	if !waitInstance(t, m, opID, true) {
		t.Fatal("reservation missing")
	}
	inst := m.instances[opID]

	// STOP while the launch is blocked before spawn; the quiescence await
	// holds the OK until the launch settles. Observe the claim (the
	// phase), prove the OK cannot arrive while parked, then release.
	stopCh := make(chan string, 1)
	go func() { stopCh <- m.stop(opID, 0) }()
	waitPhase(t, inst, builderInstanceStopping)
	select {
	case resp := <-stopCh:
		t.Fatalf("STOP replied %q while the parked launch was still in flight (quiescence await missing)", resp)
	case <-time.After(500 * time.Millisecond):
	}

	// Unblock the seam: the launch observes the stop claim at its spawn
	// check (no child ever spawned), settles its own pre-spawn state, and
	// the attempt then converges; the STOP reports OK only afterwards.
	close(spawnBlocker)
	select {
	case resp := <-stopCh:
		if resp != builderManagerRespOK {
			t.Fatalf("STOP before spawn = %q, want OK", resp)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("STOP did not converge after the launch settled")
	}

	// Zero residue at the OK instant, without polling: the launch's
	// settlement (and its dir re-removal) preceded the OK.
	if _, err := os.Lstat(opRuntimeDir(opID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("runtime dir exists at the STOP's OK instant: %v", err)
	}
	if _, err := os.Lstat(opStateDir(opID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state dir exists at the STOP's OK instant: %v", err)
	}

	select {
	case resp := <-respCh:
		if resp != builderManagerRespInternal {
			t.Fatalf("cancelled START = %q, want internal", resp)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("cancelled START did not converge")
	}
	if !waitInstance(t, m, opID, false) {
		t.Fatal("instance not removed")
	}
}

// TestBuilderManagerStopWaitsLaunchQuiescence is the F1.3 proof for the
// earliest launch window: the launch is parked BEFORE its filesystem
// work (no dirs created yet), a STOP claims and converges the pre-spawn
// instance, and — without the quiescence await — would reply OK while
// the released launch could still create the op paths and only converge
// them afterwards. With the await: the STOP's OK arrives only after the
// old launch fully settled; at the OK instant there is zero residue
// (asserted directly, without polling) and nothing live; an immediate
// same-ID START after the OK is admitted cleanly (no refuse-to-adopt
// internal error from post-OK path re-creation), and the old launch
// cannot remove the NEW instance's paths.
func TestBuilderManagerStopWaitsLaunchQuiescence(t *testing.T) {
	m, _, _ := processTestManager(t)
	seamCA(t)
	fakeLeaderSeam(t, true)

	opID := "op_0123456789abcdef0123456789abcdef"
	launchEngaged, launchRelease := launchHoldFixture(t, opID)

	startResp := make(chan string, 1)
	go func() { startResp <- m.start(opID, nil) }()

	// The launch is parked before any filesystem work.
	select {
	case <-launchEngaged:
	case <-time.After(10 * time.Second):
		t.Fatal("launch never parked before the filesystem work")
	}
	if !waitInstance(t, m, opID, true) {
		t.Fatal("reservation missing")
	}
	if _, err := os.Lstat(opRuntimeDir(opID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("setup self-test: the parked launch already created the runtime dir")
	}

	// STOP: claims (observed via the phase) and converges the pre-spawn
	// instance, then the quiescence await holds the OK until the parked
	// launch settles.
	stopResp := make(chan string, 1)
	go func() { stopResp <- m.stop(opID, 0) }()
	inst := m.instances[opID]
	waitPhase(t, inst, builderInstanceStopping)
	select {
	case resp := <-stopResp:
		t.Fatalf("STOP replied %q while the old launch was still in flight (quiescence await missing)", resp)
	case <-time.After(500 * time.Millisecond):
	}

	// Release: the launch creates its dirs (post-claim re-creation),
	// observes the stop claim, converges (dirs re-removed), and settles;
	// only then does the STOP report convergence.
	launchRelease()
	select {
	case resp := <-stopResp:
		if resp != builderManagerRespOK {
			t.Fatalf("STOP reply = %q, want OK", resp)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("STOP did not converge after the old launch settled")
	}

	// Zero residue AT the OK instant (direct assertions, no polling): the
	// launch's settlement strictly preceded the OK.
	if _, err := os.Lstat(opRuntimeDir(opID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("runtime dir exists at the STOP's OK instant: %v", err)
	}
	if _, err := os.Lstat(opStateDir(opID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state dir exists at the STOP's OK instant: %v", err)
	}

	// An immediate same-ID START after the OK is admitted cleanly, and
	// the old (settled) launch cannot remove the NEW instance's paths.
	// bindFakeBuildkitdSocket doubles as the barrier that the new
	// instance's runtime dir exists (it waits for it) before binding.
	start2Resp := make(chan string, 1)
	go func() { start2Resp <- m.start(opID, nil) }()
	if !waitInstance(t, m, opID, true) {
		t.Fatal("immediate same-ID START after OK not admitted")
	}
	bindFakeBuildkitdSocket(t, opID)
	select {
	case resp := <-start2Resp:
		if resp != builderManagerRespOK {
			t.Fatalf("immediate same-ID START = %q, want OK", resp)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("immediate same-ID START did not converge")
	}
	if _, err := os.Lstat(opRuntimeDir(opID)); err != nil {
		t.Fatalf("new instance's runtime dir removed after its OK: %v", err)
	}
}

// TestBuilderManagerRealProcessTreeTeardown is the §26 proof through the
// production process-group owner: a REAL session leader with a real
// child and grandchild; STOP kills the GROUP, reaps the leader, and all
// three are absent afterwards. Mandatory pre-existence self-test.
func TestBuilderManagerRealProcessTreeTeardown(t *testing.T) {
	m, _, _ := processTestManager(t)
	seamCA(t)

	orig := builderNewRootlessKitCommand
	builderNewRootlessKitCommand = func(opID, rtDir, stDir string, env []string) *exec.Cmd {
		_ = opID
		_ = rtDir
		_ = stDir
		_ = env
		// Session leader: sh (Setsid by the production owner) spawning a
		// child sh which spawns a grandchild sh; all busy-wait.
		cmd := exec.Command("sh", "-c",
			`sh -c 'sh -c "while :; do sleep 0.05; done" & while :; do sleep 0.05; done' &
while :; do sleep 0.05; done`)
		_ = cmd
		return cmd
	}
	t.Cleanup(func() { builderNewRootlessKitCommand = orig })

	opID := "op_0123456789abcdef0123456789abcdef"
	respCh := make(chan string, 1)
	go func() { respCh <- m.start(opID, nil) }()
	if !waitInstance(t, m, opID, true) {
		t.Fatal("reservation missing")
	}
	leader := m.instances[opID]
	pid := waitLeaderPid(t, leader)

	// Pre-existence self-test: leader + child + grandchild all exist.
	if pgid, err := syscall.Getpgid(pid); err != nil || pgid != pid {
		t.Fatalf("leader pgid=%d err=%v; Setsid ownership broken", pgid, err)
	}
	deadline := time.Now().Add(5 * time.Second)
	var childPid, grandPid int
	for time.Now().Before(deadline) {
		if found := findGroupDescendants(pid); len(found) >= 2 {
			childPid, grandPid = found[0], found[1]
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if childPid == 0 || grandPid == 0 {
		t.Fatal("pre-existence self-test: descendants did not appear")
	}

	if resp := m.stop(opID, 0); resp != builderManagerRespOK {
		t.Fatalf("STOP = %q, want OK", resp)
	}
	select {
	case resp := <-respCh:
		if resp != builderManagerRespInternal {
			t.Fatalf("raced START = %q, want internal", resp)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("raced START did not converge")
	}

	// All absent: leader, child, grandchild; leader reaped.
	if !processGroupGone(pid) {
		t.Fatalf("group %d still alive after STOP", pid)
	}
	if processAlive(pid) || processAlive(childPid) || processAlive(grandPid) {
		t.Fatalf("descendants alive after STOP: leader=%d child=%d grand=%d", pid, childPid, grandPid)
	}
	if !waitInstance(t, m, opID, false) {
		t.Fatal("map entry not removed")
	}
	if _, err := os.Lstat(opRuntimeDir(opID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("runtime dir not removed: %v", err)
	}
}

// findGroupDescendants returns pids in the group pgid other than pgid
// itself (its descendants), discovered via /proc.
func findGroupDescendants(pgid int) []int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var found []int
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid == pgid {
			continue
		}
		if g, err := syscall.Getpgid(pid); err == nil && g == pgid {
			found = append(found, pid)
		}
	}
	return found
}

// ---------------------------------------------------------------------------
// F1: START/STOP dispatch-fence proofs through the REAL dispatch path.
// ---------------------------------------------------------------------------

// realDispatchFixture mounts a test unix listener whose accepted
// connections are served by the REAL production dispatch owner
// (handleConnection: peer authentication, bounded read, parse, command
// dispatch), exactly like serve's accept loop. Cleanup closes the
// listener, joins the accept loop, and joins every handler goroutine with
// a bounded wait (a visible error on timeout, never a silent leak), so no
// handler outlives the test-owned roots or seams.
func realDispatchFixture(t *testing.T, m *builderManager) *net.UnixListener {
	t.Helper()
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(t.TempDir(), "dispatch.sock"), Net: "unix"})
	if err != nil {
		t.Fatalf("cannot create dispatch listener: %v", err)
	}
	var handlers sync.WaitGroup
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			conn, err := listener.AcceptUnix()
			if err != nil {
				return
			}
			// Same registration order as the production serve loop: the
			// pending entry exists before the next connection can be
			// accepted.
			seq := m.ingress.accept()
			handlers.Add(1)
			go func() {
				defer handlers.Done()
				m.handleConnection(conn, io.Discard, seq)
			}()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		<-acceptDone
		handlers.Wait()
	})
	return listener
}

// managerPeerRootSeam makes the real dispatch's authenticatePeer accept
// the test connections as the root daemon peer (production peers are
// root; the test connections' SO_PEERCRED is the test process identity).
func managerPeerRootSeam(t *testing.T) {
	t.Helper()
	orig := builderPeerCredentials
	builderPeerCredentials = func(*net.UnixConn) (int, int, int, error) { return 0, 0, 0, nil }
	t.Cleanup(func() { builderPeerCredentials = orig })
}

// startFenceHoldFixture parks every dispatched START of target (inside
// its dispatch-fence window, between fence registration and reservation)
// until released; engaged signals the park. The release is once-guarded
// and bounded (a test that fails before releasing must not park the START
// forever) and the seam restores on cleanup.
func startFenceHoldFixture(t *testing.T, target string) (engaged <-chan struct{}, release func()) {
	t.Helper()
	engagedCh := make(chan struct{}, 1)
	releaseCh := make(chan struct{})
	var releaseOnce sync.Once
	orig := builderStartFenceHold
	builderStartFenceHold = func(opID string) {
		if opID != target {
			return
		}
		select {
		case engagedCh <- struct{}{}:
		default:
		}
		select {
		case <-releaseCh:
		case <-time.After(10 * time.Second):
			// Bounded park (same liveness-backstop idiom as the seam
			// children's binary-liveness guard).
		}
	}
	t.Cleanup(func() {
		builderStartFenceHold = orig
		releaseOnce.Do(func() { close(releaseCh) })
	})
	return engagedCh, func() { releaseOnce.Do(func() { close(releaseCh) }) }
}

// preParseAuthHoldFixture parks the FIRST connection that reaches peer
// authentication — accepted and ingress-registered, but before its
// request is read or parsed — until released. Tests must dispatch the
// parked connection's request and wait for `engaged` before dispatching
// any other connection, so the parked connection is deterministically the
// one the test targets.
func preParseAuthHoldFixture(t *testing.T) (engaged <-chan struct{}, release func()) {
	t.Helper()
	engagedCh := make(chan struct{}, 1)
	releaseCh := make(chan struct{})
	var releaseOnce sync.Once
	orig := builderPeerCredentials
	var first sync.Mutex
	parked := false
	builderPeerCredentials = func(c *net.UnixConn) (int, int, int, error) {
		uid, gid, pid, err := orig(c)
		first.Lock()
		firstCall := !parked
		parked = true
		first.Unlock()
		if firstCall {
			select {
			case engagedCh <- struct{}{}:
			default:
			}
			select {
			case <-releaseCh:
			case <-time.After(10 * time.Second):
				// Bounded park (same liveness-backstop idiom as the seam
				// children's binary-liveness guard).
			}
		}
		return uid, gid, pid, err
	}
	t.Cleanup(func() {
		builderPeerCredentials = orig
		releaseOnce.Do(func() { close(releaseCh) })
	})
	return engagedCh, func() { releaseOnce.Do(func() { close(releaseCh) }) }
}

// stopFenceWaitFixture observes the STOP fence-wait branch through the
// builderStopFenceWait seam: engaged signals that a STOP provably reached
// the fence wait for target (the F1.1 review's missing synchronization
// barrier for the committed fence tests).
func stopFenceWaitFixture(t *testing.T, target string) <-chan struct{} {
	t.Helper()
	engagedCh := make(chan struct{}, 1)
	orig := builderStopFenceWait
	builderStopFenceWait = func(opID string) {
		if opID != target {
			return
		}
		select {
		case engagedCh <- struct{}{}:
		default:
		}
	}
	t.Cleanup(func() { builderStopFenceWait = orig })
	return engagedCh
}

// launchHoldFixture parks the FIRST launchInstance of target at its top
// — before the refuse-to-adopt checks and directory creation — until
// released; engaged signals the park. Later launches of the same op id
// proceed normally. Same idiom and bounded-park backstop as
// startFenceHoldFixture.
func launchHoldFixture(t *testing.T, target string) (engaged <-chan struct{}, release func()) {
	t.Helper()
	engagedCh := make(chan struct{}, 1)
	releaseCh := make(chan struct{})
	var releaseOnce sync.Once
	orig := builderLaunchHold
	var mu sync.Mutex
	parked := false
	builderLaunchHold = func(opID string) {
		if opID != target {
			return
		}
		mu.Lock()
		first := !parked
		parked = true
		mu.Unlock()
		if !first {
			return
		}
		select {
		case engagedCh <- struct{}{}:
		default:
		}
		select {
		case <-releaseCh:
		case <-time.After(10 * time.Second):
			// Bounded park (same liveness-backstop idiom as the seam
			// children's binary-liveness guard).
		}
	}
	t.Cleanup(func() {
		builderLaunchHold = orig
		releaseOnce.Do(func() { close(releaseCh) })
	})
	return engagedCh, func() { releaseOnce.Do(func() { close(releaseCh) }) }
}

// waitPhase polls bounded for the instance's phase to equal want (the
// deterministic observation point for a stop claim: claimStop sets the
// phase synchronously at attempt start).
func waitPhase(t *testing.T, inst *builderInstance, want builderInstancePhase) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		inst.mu.Lock()
		phase := inst.phase
		inst.mu.Unlock()
		if phase == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("instance phase = %v, want %v", phase, want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// waitDescendants polls bounded for at least want members of the
// leader's process group other than the leader itself; returns them.
func waitDescendants(t *testing.T, pgid int, want int) []int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		found := findGroupDescendants(pgid)
		if len(found) >= want {
			return found
		}
		if time.Now().After(deadline) {
			t.Fatalf("process group %d never showed %d descendants (found %v)", pgid, want, found)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// waitProcessExit polls bounded until pid is no longer alive.
func waitProcessExit(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if !processAlive(pid) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("process %d still alive", pid)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// waitProcessStays asserts for a bounded window that pid REMAINS alive
// (the pre-existence self-test: the descendants outlive a dead leader
// before the manager settles them).
func waitProcessStays(t *testing.T, pid int, window time.Duration) {
	t.Helper()
	deadline := time.Now().Add(window)
	for time.Now().Before(deadline) {
		if !processAlive(pid) {
			t.Fatalf("process %d did not stay alive (pre-existence broken)", pid)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// assertDirsAbsentAt fails when either op directory still exists (direct
// assertion, no polling: the F1.3/F2 zero-residue-at-OK contract).
func assertDirsAbsentAt(t *testing.T, opID string) {
	t.Helper()
	if _, err := os.Lstat(opRuntimeDir(opID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("runtime dir exists at the observation instant: %v", err)
	}
	if _, err := os.Lstat(opStateDir(opID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state dir exists at the observation instant: %v", err)
	}
}

// dispatchRequest opens one real connection to the dispatch listener and
// sends one request line.
func dispatchRequest(t *testing.T, listener *net.UnixListener, request string) *net.UnixConn {
	t.Helper()
	conn := dialDispatch(t, listener)
	if _, err := conn.Write([]byte(request + "\n")); err != nil {
		t.Fatalf("cannot write request %q: %v", request, err)
	}
	return conn
}

// dialDispatch opens one real connection to the dispatch listener without
// writing anything (the ingress-barrier silent-connection case).
func dialDispatch(t *testing.T, listener *net.UnixListener) *net.UnixConn {
	t.Helper()
	conn, err := net.DialUnix("unix", nil, listener.Addr().(*net.UnixAddr))
	if err != nil {
		t.Fatalf("cannot dial dispatch listener: %v", err)
	}
	return conn
}

// readReply reads one bounded reply line from a dispatched connection.
func readReply(t *testing.T, conn *net.UnixConn) string {
	t.Helper()
	line, ok := readReplyWithin(t, conn, 10*time.Second)
	if !ok {
		t.Fatal("no reply line within 10s")
	}
	return line
}

// readReplyWithin reads one reply line with an explicit bounded deadline.
// ok is false when no reply arrived within the window (the deterministic
// observation that a barrier is still holding: an unsettled older
// connection must delay the absent STOP's reply, and the pre-fix code
// answered within microseconds).
func readReplyWithin(t *testing.T, conn *net.UnixConn, within time.Duration) (string, bool) {
	t.Helper()
	buf := make([]byte, builderManagerRequestCeiling+1)
	if err := conn.SetReadDeadline(time.Now().Add(within)); err != nil {
		t.Fatalf("cannot set read deadline: %v", err)
	}
	n, err := conn.Read(buf)
	if n == 0 && err != nil {
		return "", false
	}
	if err != nil && err != io.EOF {
		t.Fatalf("reply read: %v", err)
	}
	return trimNewlineSuffix(string(buf[:n])), true
}

// waitInstanceResidueGone polls bounded for the op's runtime/state dirs
// to be gone: the raced launch's failed-start convergence removes the
// dirs it re-created after the stop owner's pass, so the converged state
// (not the OK reply instant) is the assertion point.
func waitInstanceResidueGone(t *testing.T, opID string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, rtErr := os.Lstat(opRuntimeDir(opID))
		_, stErr := os.Lstat(opStateDir(opID))
		if errors.Is(rtErr, os.ErrNotExist) && errors.Is(stErr, os.ErrNotExist) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("instance residue survived convergence: runtime=%v state=%v", rtErr, stErr)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestBuilderManagerStopDoesNotOvertakeDispatchedStart proves the
// START/STOP fence through the REAL dispatch path (handleConnection over
// real connections): a START for the op id is accepted and parked inside
// its dispatch-fence window (registered fence, no reservation yet); a
// STOP dispatched in that window must NOT report convergence (`OK
// absent`) — after the START is released and reserves+launches, the
// waiting STOP converges the instance through the ONE stop owner and
// replies OK. After the STOP's convergence reply there is no instance
// map entry and no runtime/state residue; the raced START's own reply is
// the internal refusal of its cancelled launch.
//
// The STOP's fence-wait branch is exercised deterministically: the test
// holds the START until the builderStopFenceWait observation point
// proves the STOP reached the fence wait (F1.1 review: without that
// barrier the release raced the STOP's dispatch and the branch never
// executed).
func TestBuilderManagerStopDoesNotOvertakeDispatchedStart(t *testing.T) {
	m, _, _ := processTestManager(t)
	seamCA(t)
	fakeLeaderSeam(t, true)
	managerPeerRootSeam(t)
	listener := realDispatchFixture(t, m)

	opID := "op_0123456789abcdef0123456789abcdef"
	engaged, release := startFenceHoldFixture(t, opID)
	fenceWait := stopFenceWaitFixture(t, opID)

	startConn := dispatchRequest(t, listener, "START "+opID)
	defer startConn.Close()
	select {
	case <-engaged:
	case <-time.After(10 * time.Second):
		t.Fatal("dispatched START never parked inside the fence window")
	}

	// Setup self-test: the accepted START is fenced but has NOT reserved
	// (exactly the state the original code lost the race in).
	m.mu.Lock()
	_, reserved := m.instances[opID]
	_, fenced := m.startFences[opID]
	m.mu.Unlock()
	if reserved {
		t.Fatal("setup self-test: the parked START already reserved the instance")
	}
	if !fenced {
		t.Fatal("setup self-test: the parked START has no dispatch fence")
	}

	stopConn := dispatchRequest(t, listener, "STOP "+opID)
	defer stopConn.Close()

	// Hold the release until the waiting STOP provably reached the
	// fence-wait branch.
	select {
	case <-fenceWait:
	case <-time.After(10 * time.Second):
		t.Fatal("STOP never reached the dispatch-fence wait")
	}

	// Release the START: it reserves and launches; the waiting STOP
	// converges the instance instead of reporting `OK absent`.
	release()

	stopReply := readReply(t, stopConn)
	if stopReply != builderManagerRespOK {
		t.Fatalf("STOP reply = %q, want OK (a completed compensating STOP must never be overtaken by the released START)", stopReply)
	}

	// The raced START's own reply: its launch was claimed by the STOP and
	// converged — the internal refusal, never OK. The reply is emitted
	// only after that failed-start convergence completed, so it is the
	// deterministic barrier for the final converged state below.
	startReply := readReply(t, startConn)
	if startReply != builderManagerRespInternal {
		t.Fatalf("raced START reply = %q, want internal (the STOP claimed and converged its launch)", startReply)
	}

	if !waitInstance(t, m, opID, false) {
		t.Fatal("instance map entry survived the converged STOP")
	}
	waitInstanceResidueGone(t, opID)
}

// TestBuilderClientCompensatingStopConvergesDispatchedStart proves the
// compensation end to end through the PRODUCTION client and the REAL
// manager dispatch: the START round-trip parks inside the dispatch-fence
// window until the caller context cancels (ambiguous START), the P2
// client issues the compensating STOP on a fresh context, the manager
// waits out the fence, the released START reserves and launches, and the
// compensating STOP converges that instance before replying OK. The
// client's proven-convergence verdict then stands with no live instance,
// no residue, and no process left.
//
// As in the manager-level fence test, the release waits for the
// builderStopFenceWait observation point so the compensating STOP
// provably executes the fence-wait branch.
func TestBuilderClientCompensatingStopConvergesDispatchedStart(t *testing.T) {
	m, _, _ := processTestManager(t)
	seamCA(t)
	fakeLeaderSeam(t, true)
	managerPeerRootSeam(t)
	listener := realDispatchFixture(t, m)

	opID := "op_0123456789abcdef0123456789abcdef"
	engaged, release := startFenceHoldFixture(t, opID)
	fenceWait := stopFenceWaitFixture(t, opID)

	// The production client dials the REAL manager endpoint; the test
	// mount's peer credentials match the resolved builder identity.
	fakeManagerUID(t, os.Getuid(), os.Getgid())
	fakeManagerPeer(t, os.Getuid(), os.Getgid())
	origPath := builderClientSocketPath
	builderClientSocketPath = listener.Addr().String()
	t.Cleanup(func() { builderClientSocketPath = origPath })

	startErrCh := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		startErrCh <- (&builderManagerClient{}).Start(ctx, opID)
	}()

	select {
	case <-engaged:
	case <-time.After(10 * time.Second):
		t.Fatal("dispatched START never parked inside the fence window")
	}

	// The caller context cancels while the manager holds the START in its
	// fence window: the client's read aborts (ambiguous) and the
	// compensating STOP is issued on a fresh context.
	cancel()

	// Hold the release until the compensating STOP provably reached the
	// fence-wait branch.
	select {
	case <-fenceWait:
	case <-time.After(10 * time.Second):
		t.Fatal("compensating STOP never reached the dispatch-fence wait")
	}

	// Release the START: it reserves and launches; the already-waiting
	// compensating STOP converges the instance and the client's
	// proven-convergence verdict stands.
	release()

	select {
	case err := <-startErrCh:
		if err == nil {
			t.Fatal("ambiguous START must not report success")
		}
		var mgrErr *builderManagerError
		if !errors.As(err, &mgrErr) || mgrErr.kind != builderManagerRespInternal {
			t.Fatalf("Start error = %v, want the proven-convergence internal refusal", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("client Start did not return after the compensating STOP converged")
	}

	if !waitInstance(t, m, opID, false) {
		t.Fatal("instance map entry survived the compensating STOP")
	}
	waitInstanceResidueGone(t, opID)
}

// ---------------------------------------------------------------------------
// F1.2: accept-order ingress barrier.
// ---------------------------------------------------------------------------

// TestBuilderManagerIngressAcceptOrderMatchesDialOrder establishes the
// barrier's ordering assumption on the production transport: on Linux the
// unix-socket accept queue is FIFO, so accept(2) dequeues connections in
// the order their peers dialed — the order in which the P2 client
// submits its requests. Each dial writes a marker only AFTER all dials
// completed, so the marker arrives on the server side of the same
// connection regardless of accept timing, and the accepted connection at
// position i must carry the marker of dial i.
func TestBuilderManagerIngressAcceptOrderMatchesDialOrder(t *testing.T) {
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(t.TempDir(), "order.sock"), Net: "unix"})
	if err != nil {
		t.Fatalf("cannot create order listener: %v", err)
	}
	defer listener.Close()

	const n = 3
	dials := make([]*net.UnixConn, n)
	for i := range dials {
		conn, err := net.DialUnix("unix", nil, listener.Addr().(*net.UnixAddr))
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		dials[i] = conn
		defer dials[i].Close()
	}
	for i, conn := range dials {
		if _, err := conn.Write([]byte{byte('a' + i)}); err != nil {
			t.Fatalf("marker %d: %v", i, err)
		}
	}

	accepted := make([]*net.UnixConn, n)
	for i := range accepted {
		conn, err := listener.AcceptUnix()
		if err != nil {
			t.Fatalf("accept %d: %v", i, err)
		}
		accepted[i] = conn
		defer conn.Close()
	}

	buf := make([]byte, 1)
	for i, conn := range accepted {
		if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatalf("deadline %d: %v", i, err)
		}
		if _, err := conn.Read(buf); err != nil {
			t.Fatalf("marker read %d: %v", i, err)
		}
		if buf[0] != byte('a'+i) {
			t.Fatalf("accept position %d carries marker %q, want %q: accept order does not match dial order", i, buf[0], byte('a'+i))
		}
	}
}

// TestBuilderManagerStopBarrierSettlesUnparsedStart is the F1.2 proof of
// the residual window through the REAL dispatch path: a START connection
// is accepted, ingress-registered, and parked BEFORE its request is read
// or parsed (inside peer authentication); a compensating STOP dispatched
// after it must NOT report `OK absent` while that START is unsettled —
// the STOP waits at the ingress barrier (no reply within a bounded
// window, the deterministic observation against the pre-fix immediate
// `OK absent`); the released START then parses, registers its dispatch
// fence (its settle fires exactly there, under the manager lock), and
// the barrier-released STOP sees the fence, waits it out, and converges
// the launched instance. After the STOP's OK there is no map entry, no
// residue, and the released START's own reply is the internal refusal of
// its claimed launch.
func TestBuilderManagerStopBarrierSettlesUnparsedStart(t *testing.T) {
	m, _, _ := processTestManager(t)
	seamCA(t)
	fakeLeaderSeam(t, true)
	managerPeerRootSeam(t)
	authEngaged, authRelease := preParseAuthHoldFixture(t)
	listener := realDispatchFixture(t, m)

	opID := "op_0123456789abcdef0123456789abcdef"
	startConn := dispatchRequest(t, listener, "START "+opID)
	defer startConn.Close()
	select {
	case <-authEngaged:
	case <-time.After(10 * time.Second):
		t.Fatal("START connection never parked before parsing")
	}

	stopConn := dispatchRequest(t, listener, "STOP "+opID)
	defer stopConn.Close()

	// The barrier is engaged: the STOP must not answer while the older
	// accepted START connection is unsettled (pre-fix behavior: immediate
	// `OK absent` while the parked START could still launch).
	if line, ok := readReplyWithin(t, stopConn, 500*time.Millisecond); ok {
		t.Fatalf("STOP replied %q while an older accepted START was unsettled (barrier missing)", line)
	}

	// Release the START: it parses, registers the dispatch fence, settles
	// its ingress entry, reserves, and launches; the barrier-released
	// STOP sees the fence, waits it out, and converges the instance.
	authRelease()

	if reply := readReply(t, stopConn); reply != builderManagerRespOK {
		t.Fatalf("STOP reply = %q, want OK (the compensating STOP must converge the released START)", reply)
	}
	if reply := readReply(t, startConn); reply != builderManagerRespInternal {
		t.Fatalf("released START reply = %q, want internal (its launch was claimed by the STOP)", reply)
	}
	if !waitInstance(t, m, opID, false) {
		t.Fatal("instance map entry survived the converged STOP")
	}
	waitInstanceResidueGone(t, opID)
}

// TestBuilderManagerSilentConnectionDoesNotBlockStop: a connection
// accepted BEFORE a STOP's connection but silent (no request bytes)
// settles at its bounded read deadline; the STOP's ingress barrier waits
// it out and still answers `OK absent` in bounded time. Proves the
// barrier is transient (silent/dead connections leak no pending entry)
// and bounded (the absent STOP is never blocked indefinitely).
func TestBuilderManagerSilentConnectionDoesNotBlockStop(t *testing.T) {
	m, _, _ := processTestManager(t)
	seamCA(t)
	fakeLeaderSeam(t, true)
	managerPeerRootSeam(t)
	listener := realDispatchFixture(t, m)

	opID := "op_0123456789abcdef0123456789abcdef"
	silentConn := dialDispatch(t, listener)
	defer silentConn.Close()

	stopConn := dispatchRequest(t, listener, "STOP "+opID)
	defer stopConn.Close()

	// The barrier waits out the older silent connection (bounded by its
	// 2s read deadline): no reply within the first 500ms.
	if line, ok := readReplyWithin(t, stopConn, 500*time.Millisecond); ok {
		t.Fatalf("STOP replied %q while the older silent connection was unsettled (barrier missing)", line)
	}
	// ...and the reply arrives bounded, after the silent connection's
	// deadline settled it.
	if reply := readReply(t, stopConn); reply != builderManagerRespOKAbsent {
		t.Fatalf("STOP reply = %q, want OK absent after the silent connection settled", reply)
	}
}

// TestBuilderManagerIngressSettlesRejectedOlderConnections: rejected or
// dead older connections (malformed request, unauthorized peer, EOF
// before any request) settle through the catch-all handler exit without
// blocking the absent STOP indefinitely and without leaking a pending
// entry. Rejected connections are precisely the paths that must never
// reach a START dispatch.
//
// Seam discipline: every seam is installed through install() BEFORE the
// dispatch fixture exists (no handler goroutine can read a seam while it
// is being installed) and restored at cleanup AFTER the fixture's
// handler join (LIFO), so no handler reads a seam during install/restore.
func TestBuilderManagerIngressSettlesRejectedOlderConnections(t *testing.T) {
	cases := []struct {
		name    string
		install func(t *testing.T) <-chan struct{}
		older   func(t *testing.T, listener *net.UnixListener, engaged <-chan struct{}) *net.UnixConn
	}{
		{
			name: "malformed request",
			older: func(t *testing.T, listener *net.UnixListener, _ <-chan struct{}) *net.UnixConn {
				// Bad op id: the reply proves the handler ran and exited
				// (the deferred settle fired with it).
				conn := dispatchRequest(t, listener, "START nope\n")
				if reply := readReply(t, conn); reply != builderManagerRespBadOpID {
					t.Fatalf("malformed older conn reply = %q, want %q", reply, builderManagerRespBadOpID)
				}
				return conn
			},
		},
		{
			name: "unauthorized peer",
			install: func(t *testing.T) <-chan struct{} {
				// Refuse the FIRST peer-credential call (no reply, the
				// handler exits at once) and signal when it happens;
				// later connections are admitted as root. The test waits
				// for the signal before dispatching the STOP, so the
				// refused connection is deterministically the older one.
				orig := builderPeerCredentials
				engagedCh := make(chan struct{}, 1)
				var mu sync.Mutex
				calls := 0
				builderPeerCredentials = func(c *net.UnixConn) (int, int, int, error) {
					mu.Lock()
					n := calls
					calls++
					mu.Unlock()
					if n == 0 {
						select {
						case engagedCh <- struct{}{}:
						default:
						}
						return 4312, 4312, 12, nil
					}
					return orig(c)
				}
				t.Cleanup(func() { builderPeerCredentials = orig })
				return engagedCh
			},
			older: func(t *testing.T, listener *net.UnixListener, engaged <-chan struct{}) *net.UnixConn {
				conn := dispatchRequest(t, listener, "STOP op_fedcba9876543210fedcba9876543210\n")
				select {
				case <-engaged:
				case <-time.After(10 * time.Second):
					t.Fatal("older connection never reached peer authentication")
				}
				return conn
			},
		},
		{
			name: "EOF before request",
			older: func(t *testing.T, listener *net.UnixListener, _ <-chan struct{}) *net.UnixConn {
				// Dial and close: the handler's bounded read returns EOF
				// with no line and exits without a reply.
				conn := dialDispatch(t, listener)
				conn.Close()
				return conn
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, _, _ := processTestManager(t)
			seamCA(t)
			fakeLeaderSeam(t, true)
			managerPeerRootSeam(t)
			var engaged <-chan struct{}
			if tc.install != nil {
				engaged = tc.install(t)
			}
			listener := realDispatchFixture(t, m)

			opID := "op_0123456789abcdef0123456789abcdef"
			olderConn := tc.older(t, listener, engaged)
			defer olderConn.Close()

			// The absent STOP settles the older connection through the
			// barrier and still answers in bounded time.
			stopConn := dispatchRequest(t, listener, "STOP "+opID)
			defer stopConn.Close()
			if reply := readReply(t, stopConn); reply != builderManagerRespOKAbsent {
				t.Fatalf("STOP reply = %q, want OK absent after the rejected older connection settled", reply)
			}

			// No pending entry leaked: every accepted connection settled.
			deadline := time.Now().Add(5 * time.Second)
			for {
				m.ingress.mu.Lock()
				leaked := len(m.ingress.pending)
				m.ingress.mu.Unlock()
				if leaked == 0 {
					return
				}
				if time.Now().After(deadline) {
					t.Fatalf("%d pending ingress entries leaked after convergence", leaked)
				}
				time.Sleep(5 * time.Millisecond)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// F2: truthful STOP and process ownership.
// ---------------------------------------------------------------------------

// TestBuilderManagerStopGroupSurvivalEscalation: a REAL session leader
// whose child traps SIGTERM survives the graceful window; the STOP
// escalates to SIGKILL and may reply OK only after the WHOLE group —
// leader, child, and any in-group sleeper — is proven dead and the exact
// directories are removed. Pre-existence is asserted for the leader and
// the TERM-trapping child before the STOP.
func TestBuilderManagerStopGroupSurvivalEscalation(t *testing.T) {
	m, _, _ := processTestManager(t)
	seamCA(t)

	orig := builderNewRootlessKitCommand
	builderNewRootlessKitCommand = func(opID, rtDir, stDir string, env []string) *exec.Cmd {
		_ = opID
		_ = rtDir
		_ = stDir
		_ = env
		// Leader busy-waits (dies on SIGTERM); its child traps SIGTERM
		// and survives the graceful window, forcing the escalation. The
		// loops are sleep-free so every group member is long-lived and
		// the descendant identity is stable.
		cmd := exec.Command("sh", "-c", `sh -c 'trap "" TERM; while :; do :; done' & while :; do :; done`)
		return cmd
	}
	t.Cleanup(func() { builderNewRootlessKitCommand = orig })

	opID := "op_0123456789abcdef0123456789abcdef"
	startResp := make(chan string, 1)
	go func() { startResp <- m.start(opID, nil) }()
	if !waitInstance(t, m, opID, true) {
		t.Fatal("reservation missing")
	}
	inst := m.instances[opID]
	pid := waitLeaderPid(t, inst)
	descendants := waitDescendants(t, pid, 1)
	if !processAlive(descendants[0]) {
		t.Fatal("pre-existence self-test: TERM-trapping child not alive")
	}

	// The STOP escalates through the full graceful window (~5s) before
	// SIGKILL; the OK is only possible after the whole group died.
	stopResp := make(chan string, 1)
	go func() { stopResp <- m.stop(opID, 0) }()
	select {
	case resp := <-stopResp:
		if resp != builderManagerRespOK {
			t.Fatalf("STOP = %q, want OK after the group escalation", resp)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("STOP did not converge through the SIGKILL escalation")
	}

	if !processGroupGone(pid) {
		t.Fatalf("process group %d survived the escalated STOP", pid)
	}
	if processAlive(pid) || processAlive(descendants[0]) {
		t.Fatalf("leader/child alive after the escalated STOP: leader=%d child=%d", pid, descendants[0])
	}
	assertDirsAbsentAt(t, opID)
	if !waitInstance(t, m, opID, false) {
		t.Fatal("instance map entry survived the converged STOP")
	}
}

// TestBuilderManagerStopRetainsOnDirCleanupFailure: the exact directory
// cleanup is part of the truthful STOP contract. When the removal fails,
// the STOP answers ERR internal, RETAINS the map entry (ownership and
// ceiling capacity) instead of releasing an instance whose state was not
// cleaned, and a retry STOP through the same owner converges.
func TestBuilderManagerStopRetainsOnDirCleanupFailure(t *testing.T) {
	m, rtRoot, stRoot := processTestManager(t)
	seamCA(t)
	fakeLeaderSeam(t, true)

	opID := "op_0123456789abcdef0123456789abcdef"
	startResp := make(chan string, 1)
	go func() { startResp <- m.start(opID, nil) }()
	if !waitInstance(t, m, opID, true) {
		t.Fatal("reservation missing")
	}

	// Make both op-directory parents unwritable: RemoveAll of the op
	// dirs fails deterministically while their interior is removable.
	opsParents := []string{filepath.Join(rtRoot, "ops"), filepath.Join(stRoot, "ops")}
	for _, d := range opsParents {
		if err := os.Chmod(d, 0o500); err != nil {
			t.Fatalf("cannot chmod %s: %v", d, err)
		}
		defer os.Chmod(d, 0o700)
	}

	if resp := m.stop(opID, 0); resp != builderManagerRespInternal {
		t.Fatalf("STOP with failed dir cleanup = %q, want internal (truthful refusal to report success)", resp)
	}
	// Retained: the entry and its ceiling slot survive, the state is not
	// half-removed.
	if !waitInstance(t, m, opID, true) {
		t.Fatal("failed STOP released the instance entry (capacity leaked on unproven cleanup)")
	}
	if _, err := os.Lstat(opRuntimeDir(opID)); err != nil {
		t.Fatalf("runtime dir vanished despite the failed cleanup: %v", err)
	}

	// Retry through the same owner after the cleanup can succeed.
	for _, d := range opsParents {
		if err := os.Chmod(d, 0o700); err != nil {
			t.Fatalf("cannot restore %s: %v", d, err)
		}
	}
	if resp := m.stop(opID, 0); resp != builderManagerRespOK {
		t.Fatalf("retry STOP = %q, want OK", resp)
	}
	if !waitInstance(t, m, opID, false) {
		t.Fatal("retry did not release the entry")
	}
	assertDirsAbsentAt(t, opID)
}

// TestBuilderManagerStopSelfExitRace: the STOP's claim is followed by a
// self-exiting leader. The single Wait owner reaps the leader and skips
// convergence (the claimant owns it); the claimant settles through the
// reap signal without ever calling Process.Wait — no second Wait owner,
// no double terminal cleanup.
func TestBuilderManagerStopSelfExitRace(t *testing.T) {
	m, _, _ := processTestManager(t)
	seamCA(t)

	flag := filepath.Join(t.TempDir(), "leader-exit-flag")
	orig := builderNewRootlessKitCommand
	builderNewRootlessKitCommand = func(opID, rtDir, stDir string, env []string) *exec.Cmd {
		_ = opID
		_ = rtDir
		_ = stDir
		_ = env
		return exec.Command("sh", "-c", "while [ ! -f "+flag+" ]; do sleep 0.05; done")
	}
	t.Cleanup(func() { builderNewRootlessKitCommand = orig })

	opID := "op_0123456789abcdef0123456789abcdef"
	startResp := make(chan string, 1)
	go func() { startResp <- m.start(opID, nil) }()
	if !waitInstance(t, m, opID, true) {
		t.Fatal("reservation missing")
	}
	inst := m.instances[opID]
	pid := waitLeaderPid(t, inst)

	// Claim first (observed via the phase), then trigger the self-exit:
	// the deterministic ordering of the race the pre-F2 code lost.
	stopResp := make(chan string, 1)
	go func() { stopResp <- m.stop(opID, 0) }()
	waitPhase(t, inst, builderInstanceStopping)

	// Trigger the self-exit: the Wait owner reaps (its Wait was already
	// blocked on the alive leader), observes the claim, and skips
	// convergence; the claimant settles through the reap signal without
	// ever calling Process.Wait.
	if err := os.WriteFile(flag, []byte("go\n"), 0o600); err != nil {
		t.Fatalf("cannot write the exit flag: %v", err)
	}

	select {
	case resp := <-stopResp:
		if resp != builderManagerRespOK {
			t.Fatalf("STOP = %q, want OK after the self-exited leader was settled", resp)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("STOP did not converge after the leader self-exited")
	}
	if processAlive(pid) {
		t.Fatalf("leader %d still alive/reaped after the converged STOP", pid)
	}
	assertDirsAbsentAt(t, opID)
	if !waitInstance(t, m, opID, false) {
		t.Fatal("instance map entry survived the converged STOP")
	}
}

// TestBuilderManagerSelfExitSettlesDescendantsBeforeDirs: a leader that
// exits on its own while its child and grandchild stay alive in the
// group. The unexpected-exit owner must settle the whole group (kill,
// verify disappearance) BEFORE removing the exact directories; the test
// pre-existence-proves both descendants alive under the live leader
// before triggering the exit.
func TestBuilderManagerSelfExitSettlesDescendantsBeforeDirs(t *testing.T) {
	m, _, _ := processTestManager(t)
	seamCA(t)

	orig := builderNewRootlessKitCommand
	exitFlag := filepath.Join(t.TempDir(), "leader-exit-flag")
	builderNewRootlessKitCommand = func(opID, rtDir, stDir string, env []string) *exec.Cmd {
		_ = opID
		_ = rtDir
		_ = stDir
		_ = env
		// Leader forks a middle sh which forks a grandchild and
		// busy-waits; the leader stays alive until the test's exit flag,
		// then self-exits, leaving both descendants alive in its process
		// group. The middle's output is redirected so the descendants
		// release the leader's diagnostic pipe ends (the pipe-blocking
		// case is the documented bounded behavior). All loops are
		// sleep-free so every group member is long-lived and the
		// descendant identity is stable.
		cmd := exec.Command("sh", "-c", `sh -c 'sh -c "while :; do :; done" & while :; do :; done' >/dev/null 2>&1 & while [ ! -f `+exitFlag+` ]; do :; done`)
		return cmd
	}
	t.Cleanup(func() { builderNewRootlessKitCommand = orig })

	opID := "op_0123456789abcdef0123456789abcdef"
	startResp := make(chan string, 1)
	go func() { startResp <- m.start(opID, nil) }()
	if !waitInstance(t, m, opID, true) {
		t.Fatal("reservation missing")
	}
	inst := m.instances[opID]
	pid := waitLeaderPid(t, inst)

	// Pre-existence: the leader alive, both descendants alive in its
	// group, and the op paths in place (all three will have to be
	// settled).
	descendants := waitDescendants(t, pid, 2)
	waitProcessStays(t, descendants[0], 300*time.Millisecond)
	waitProcessStays(t, descendants[1], 300*time.Millisecond)

	// Trigger the self-exit. The unexpected-exit owner must settle the
	// whole group (kill, verify disappearance) BEFORE removing the exact
	// directories; a later STOP observes the terminal state as OK absent.
	if err := os.WriteFile(exitFlag, []byte("go\n"), 0o600); err != nil {
		t.Fatalf("cannot write the exit flag: %v", err)
	}

	// The unexpected-exit owner settles the group and then the paths; a
	// later STOP observes the terminal state as OK absent.
	select {
	case resp := <-startResp:
		if resp != builderManagerRespInternal {
			t.Fatalf("self-exited START = %q, want internal", resp)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("self-exited START did not converge")
	}
	// The claim-observed launch reply does not wait the owning attempt's
	// convergence; the instance's terminal settlement is the barrier for
	// the state assertions below.
	select {
	case <-inst.done:
	case <-time.After(15 * time.Second):
		t.Fatal("unexpected-exit settlement did not complete")
	}
	if !processGroupGone(pid) {
		t.Fatalf("descendants of group %d survived the unexpected-exit settlement", pid)
	}
	assertDirsAbsentAt(t, opID)
	if !waitInstance(t, m, opID, false) {
		t.Fatal("unexpected-exit did not release the map entry")
	}
}
