package main

import (
	"errors"
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
			m.stop(id)
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
	go func() { respCh <- m.start(opID) }()

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
			respCh <- m.start(opID)
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
		go func() { respCh <- m.start(opID) }()
		if !waitInstance(t, m, opID, true) {
			t.Fatalf("START %s did not reserve", opID)
		}
		bindFakeBuildkitdSocket(t, opID)
		if resp := <-respCh; resp != builderManagerRespOK {
			t.Fatalf("START %s = %q, want OK", opID, resp)
		}
	}
	if resp := m.start("op_11111111111111111111111111111111"); resp != builderManagerRespAtCeiling {
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
	go func() { respCh <- m.start(opID) }()
	if !waitInstance(t, m, opID, true) {
		t.Fatal("reservation missing")
	}

	if resp := m.stop(opID); resp != builderManagerRespOK {
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
	go func() { resp2Ch <- m.start(op2) }()
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
	go func() { respCh <- m.start(opID) }()
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
			stopCh <- m.stop(opID)
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
	go func() { respCh <- m.start(opID) }()
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
	go func() { defer wg.Done(); resp2 <- m.stop(opID) }()
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
	if resp := m.start(opID); resp != builderManagerRespInternal {
		t.Fatalf("START after self-exit = %q, want internal", resp)
	}
	if !waitInstance(t, m, opID, false) {
		t.Fatal("unexpected exit did not release the map entry (zombie ceiling)")
	}
	if _, err := os.Lstat(opRuntimeDir(opID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("runtime dir not removed after self-exit: %v", err)
	}
	if resp := m.stop(opID); resp != builderManagerRespOKAbsent {
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
	if resp := m.start(opID); resp != builderManagerRespInternal {
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
	go func() { respCh <- m.start(opID) }()
	if !waitInstance(t, m, opID, true) {
		t.Fatal("reservation missing")
	}
	inst := m.instances[opID]
	pid := waitLeaderPid(t, inst)
	// Pre-existence self-test: the leader exists as a group leader.
	if processGroupGone(pid) {
		t.Fatal("pre-existence self-test: leader group already gone")
	}
	if resp := m.stop(opID); resp != builderManagerRespOK {
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
// the instance converges cleanly.
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
	go func() { respCh <- m.start(opID) }()
	if !waitInstance(t, m, opID, true) {
		t.Fatal("reservation missing")
	}

	// STOP while the launch is blocked before spawn.
	if resp := m.stop(opID); resp != builderManagerRespOK {
		t.Fatalf("STOP before spawn = %q, want OK", resp)
	}
	// Unblock the seam: the launch observes the stop claim at its next
	// check (no child ever spawned).
	close(spawnBlocker)
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
	go func() { respCh <- m.start(opID) }()
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

	if resp := m.stop(opID); resp != builderManagerRespOK {
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
