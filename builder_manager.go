package main

// builder_manager.go implements the builder-manager backend role of the
// docker-helper binary: the unprivileged per-build-operation BuildKit
// instance lifecycle owner proven by the M1 architectural probe.
//
// It is backend mechanics ONLY. It owns no Session authorization, no
// filesystem policy, no staging, no image names, no build args, no
// registry credentials, no Docker import, and no Operation result
// semantics. Its request vocabulary is exactly START/STOP/PURGE with the
// canonical Operation ID grammar.

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Fixed production paths (canonical constants; no config, no PATH lookup).
const (
	builderManagerSocketPath   = "/run/docker-helper-builder/manager.sock"
	builderManagerRuntimeRoot  = "/run/docker-helper-builder"
	builderManagerStateRoot    = "/var/lib/docker-helper-builder"
	builderManagerRootlessKit  = "/usr/bin/rootlesskit"
	builderManagerBuildkitd    = "/usr/libexec/docker-helper/buildkit/buildkitd"
	builderManagerBuilderUser  = "docker-helper-builder"
	builderManagerBuilderGroup = "docker-helper-builder"

	// RootlessKit may find its distro helpers (newuidmap, newgidmap,
	// slirp4netns) through exactly this manager-owned PATH, and the
	// bundled buildkitd resolves its OCI worker helper buildkit-runc
	// through the same child PATH (upstream exec.LookPath over
	// defaultCommandCandidates ["buildkit-runc", "runc"]); the product
	// payload directory is therefore part of the fixed child PATH.
	builderManagerChildPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:" +
		"/usr/libexec/docker-helper/buildkit"

	// builderInstanceDiagMaxBytes is the fixed internal diagnostic ceiling
	// for one instance's RootlessKit/buildkitd combined stdout/stderr
	// (bounded tail; not config/API).
	builderInstanceDiagMaxBytes int64 = 64 * 1024

	// builderInstanceReadinessTimeout bounds the START readiness wait.
	builderInstanceReadinessTimeout = 60 * time.Second

	// builderStopGracefulTimeout bounds the SIGTERM->SIGKILL escalation.
	builderStopGracefulTimeout = 5 * time.Second

	// builderStopFinalizeTimeout bounds the post-escalation group-death
	// and reap wait inside one stop attempt (covers the zombie window
	// between SIGKILL delivery and the group's full disappearance).
	builderStopFinalizeTimeout = 2 * time.Second

	// builderInstanceWaitDelay bounds how long the single Wait owner's
	// cmd.Wait may stay blocked on the leader's diagnostic pipes after
	// the leader itself has exited (group members inheriting stdout/
	// stderr keep the pipe ends open). F4: once the bound elapses the
	// Wait owner returns and the existing convergence settles the
	// remaining group members. Fixed protocol constant, not operator
	// policy.
	builderInstanceWaitDelay = 2 * time.Second
)

// errBuilderStopNotConverged is the truthful-STOP failure: a stop attempt
// ended without the process group proven dead, the leader reaped, and the
// exact directories removed. The instance entry and its ceiling slot stay
// retained for retry; STOP/PURGE reply ERR internal and a later STOP
// retries through the same owner.
var errBuilderStopNotConverged = errors.New("builder stop did not converge")

// identity guard seams (unit-test injectable; production defaults below).
var (
	builderLookupUser = user.Lookup
	builderOSGeteuid  = func() int { return os.Geteuid() }
	builderOSGetegid  = func() int { return os.Getegid() }
	// builderPeerCredentials returns the SO_PEERCRED credentials of a
	// unix connection (uid, gid, pid). Injectable for tests.
	builderPeerCredentials = peerCredentialsUnix

	// builderStartFenceHold is a test-only seam invoked after a START
	// registered its dispatch fence and before the reservation critical
	// section (production: nil). It parks the accepted START inside
	// exactly the dispatch-fence window a concurrent STOP waits out.
	builderStartFenceHold func(opID string)

	// builderStopFenceWait is a test-only seam invoked by a STOP right
	// before it waits on a START dispatch fence (production: nil). It is
	// the explicit observation point for the fence-wait branch: tests hold
	// their parked START until the waiting STOP provably reached the
	// fence wait, so committed tests actually execute that branch instead
	// of racing past it.
	builderStopFenceWait func(opID string)

	// builderLaunchHold is a test-only seam invoked at the top of
	// launchInstance, before the refuse-to-adopt checks and directory
	// creation (production: nil). It parks the launch in the pre-
	// filesystem window so tests can hold a STOP's quiescence await
	// against launch work that runs after the STOP's claim.
	builderLaunchHold func(opID string)
)

// builderNewRootlessKitCommand constructs the RootlessKit leader command
// for one operation. Injectable for tests: tests mount a synthetic
// session-leader process tree through the production spawn owner; the
// production seam builds the manager-owned immutable argv.
var builderNewRootlessKitCommand = func(opID string, rtDir, stDir string, env []string) *exec.Cmd {
	args := []string{
		"--net=slirp4netns",
		"--copy-up=/etc",
		"--disable-host-loopback",
		"--state-dir=" + filepath.Join(stDir, "rootlesskit-state"),
		builderManagerBuildkitd,
		"--rootless",
		"--root=" + filepath.Join(stDir, "root"),
		"--addr=unix://" + opSocketPath(opID),
	}
	cmd := exec.Command(builderManagerRootlessKit, args...)
	cmd.Env = env
	return cmd
}

// builderVerifyIdentity is the fail-closed execution-identity guard for
// `builder serve`: the process must run as the exact dedicated
// docker-helper-builder identity (no hardcoded numeric UID/GID), and
// root invocation or invocation as any other user is refused before any
// side effect.
func builderVerifyIdentity() (uid int, gid int, err error) {
	u, lookupErr := builderLookupUser(builderManagerBuilderUser)
	if lookupErr != nil {
		return 0, 0, fmt.Errorf("builder identity %q not found: %w", builderManagerBuilderUser, lookupErr)
	}
	if u.Username != builderManagerBuilderUser {
		return 0, 0, fmt.Errorf("builder identity lookup returned %q", u.Username)
	}
	uid, err = strconv.Atoi(u.Uid)
	if err != nil {
		return 0, 0, fmt.Errorf("builder identity UID %q is not numeric", u.Uid)
	}
	gid, err = strconv.Atoi(u.Gid)
	if err != nil {
		return 0, 0, fmt.Errorf("builder identity GID %q is not numeric", u.Gid)
	}
	if builderOSGeteuid() == 0 {
		return 0, 0, errors.New("builder serve must not run as root")
	}
	if builderOSGeteuid() != uid {
		return 0, 0, fmt.Errorf("builder serve must run as the %q user (euid %d != builder uid %d)", builderManagerBuilderUser, builderOSGeteuid(), uid)
	}
	if builderOSGetegid() != gid {
		return 0, 0, fmt.Errorf("builder serve must run with the %q group (egid %d != builder gid %d)", builderManagerBuilderGroup, builderOSGetegid(), gid)
	}
	return uid, gid, nil
}

// peerCredentialsUnix reads SO_PEERCRED for a *net.UnixConn.
func peerCredentialsUnix(conn *net.UnixConn) (uid, gid, pid int, err error) {
	rawConn, rawErr := conn.SyscallConn()
	if rawErr != nil {
		return 0, 0, 0, rawErr
	}
	var ucred *unix.Ucred
	var sockErr error
	ctrlErr := rawConn.Control(func(fd uintptr) {
		u, e := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if e != nil {
			sockErr = e
			return
		}
		ucred = u
	})
	if ctrlErr != nil {
		return 0, 0, 0, ctrlErr
	}
	if sockErr != nil {
		return 0, 0, 0, sockErr
	}
	if ucred == nil {
		return 0, 0, 0, errors.New("SO_PEERCRED returned no credentials")
	}
	return int(ucred.Uid), int(ucred.Gid), int(ucred.Pid), nil
}

// builderInstancePhase is backend implementation state for one per-op
// instance lifecycle (not a product/domain state; never exposed through
// any public surface).
type builderInstancePhase int

const (
	builderInstanceStarting builderInstancePhase = iota
	builderInstanceRunning
	builderInstanceStopping
	builderInstanceDone
)

// builderInstance is one manager-owned ephemeral BuildKit instance.
type builderInstance struct {
	operationID string

	mu          sync.Mutex
	phase       builderInstancePhase
	leader      *exec.Cmd // the setsid RootlessKit session/process-group leader
	pid         int       // leader pid; 0 when not yet launched/reaped
	diag        *boundedBuffer
	stopClaimed bool
	done        chan struct{} // closed exactly once when terminal cleanup finished

	// launchDone is the launch settlement signal: closed exactly once
	// when launchInstance returns, on any path. A STOP that converged
	// this instance awaits it before replying OK, so no post-claim launch
	// work (directory creation, spawn, failed-start convergence) can run
	// after the STOP reported convergence (F1.3 quiescence).
	launchDone chan struct{}

	// reaped is the reap signal: closed exactly once by the instance's
	// single child Wait owner right after leader.Wait() returned, on any
	// path (self-exit or stop-killed). Stop attempts never call
	// Process.Wait themselves; they await this signal, so there is
	// exactly ONE Wait owner per leader (F2).
	reaped chan struct{}
}

// builderManager owns the per-operation ephemeral BuildKit instance
// lifecycle. The instance map counts an instance against the ceiling from
// reservation until terminal cleanup removes it (starting/running/
// stopping all count). startFences holds the dispatch fence of every
// accepted-but-not-yet-settled START (at most one per op id, lifetime =
// the dispatch-to-reservation window): a STOP for that id waits the fence
// out instead of reporting convergence while the START may still reserve
// and launch. No tombstones: a settled fence is removed. ingress is the
// accept-order barrier: every accepted connection is registered pending
// before the next connection can be accepted, and an absent STOP settles
// every older pending connection before reporting `OK absent`, so no
// accepted-but-unparsed START can reserve and launch afterwards.
type builderManager struct {
	mu          sync.Mutex
	instances   map[string]*builderInstance
	startFences map[string]chan struct{}
	ingress     builderIngress
	uid, gid    int
	diag        *boundedBuffer // manager-level operational diagnostics

	// stderr mirrors the operational diagnostics to the service's
	// journal (systemd StandardError=journal). nil in tests that build
	// the manager directly; the buffer remains the programmatic owner.
	stderr io.Writer
}

func newBuilderManager(uid, gid int) *builderManager {
	return &builderManager{
		instances:   map[string]*builderInstance{},
		startFences: map[string]chan struct{}{},
		ingress:     builderIngress{pending: map[int]chan struct{}{}},
		uid:         uid,
		gid:         gid,
		diag:        newBoundedBuffer(builderInstanceDiagMaxBytes),
	}
}

// builderIngress is the manager's accept-order barrier. On Linux the
// unix-socket accept queue is FIFO: accept(2) returns queued connections
// in connect order, and the accept loop registers each connection here
// synchronously before accepting the next one, so a connection's
// sequence number orders it against every other connection by submit
// time. A pending connection settles exactly once — at handler exit for
// unauthorized, malformed, dead, or read-deadline connections, at
// dispatch for STOP/PURGE, and for START only when its refusal or
// startFences registration is visible under the manager lock — and no
// entry survives its handler's lifetime (each older connection settles
// within its bounded read window at the latest). An absent STOP waits
// for every connection accepted before its own, then re-checks the map
// and fences under the manager lock.
type builderIngress struct {
	mu      sync.Mutex
	seq     int
	pending map[int]chan struct{}
}

// accept registers an accepted connection as pending and returns its
// sequence number. Called synchronously in the accept loop before the
// next Accept.
func (b *builderIngress) accept() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.seq++
	b.pending[b.seq] = make(chan struct{})
	return b.seq
}

// settle marks the connection's request admission as visible, removing
// its pending entry. Idempotent: an already-settled or unregistered
// sequence number (direct handleConnection callers, seq 0) is a no-op.
func (b *builderIngress) settle(seq int) {
	b.mu.Lock()
	if ch, ok := b.pending[seq]; ok {
		delete(b.pending, seq)
		close(ch)
	}
	b.mu.Unlock()
}

// waitOlder blocks until every pending connection with a sequence number
// lower than before has settled. All such connections were accepted
// before the caller's connection, so the set is complete at collection:
// sequence numbers are assigned in accept order and no lower number can
// be registered afterwards.
func (b *builderIngress) waitOlder(before int) {
	b.mu.Lock()
	older := make([]chan struct{}, 0, len(b.pending))
	for s, ch := range b.pending {
		if s < before {
			older = append(older, ch)
		}
	}
	b.mu.Unlock()
	for _, ch := range older {
		<-ch
	}
}

// ceiling is the existing canonical product constant — no duplicate
// literal.
func (m *builderManager) ceiling() int {
	return maxConcurrentBuildsGlobal
}

// opRuntimeDir/opStateDir derive the deterministic per-op paths both
// sides compute independently (the protocol never carries paths). The
// roots are seams for tests (production: fixed canonical constants).
var (
	builderRuntimeRoot = builderManagerRuntimeRoot
	builderStateRoot   = builderManagerStateRoot
)

func opRuntimeDir(opID string) string {
	return filepath.Join(builderRuntimeRoot, "ops", opID)
}

func opStateDir(opID string) string {
	return filepath.Join(builderStateRoot, "ops", opID)
}

func opSocketPath(opID string) string {
	return filepath.Join(opRuntimeDir(opID), "buildkitd.sock")
}

// start is the START protocol operation. The dispatch fence is the
// START/STOP ordering guarantee (§3 of the plan): an accepted START
// registers its fence BEFORE the reservation, and the fence settles
// exactly when the reservation is installed or the START is refused — so
// a concurrent STOP for the same id can never report convergence (`OK
// absent`) while an accepted START of that id may still create a live
// instance.
//
// settled, when non-nil, is the connection's ingress-barrier settle
// callback (F1.2): it fires exactly when this START's admission decision
// — a refusal, or the dispatch-fence registration — is visible under the
// manager lock, never after the launch, so an absent STOP waiting out
// older connections does not wait out a BuildKit readiness cycle.
func (m *builderManager) start(opID string, settled func()) string {
	// Fence registration: under the manager lock — refuse an existing
	// instance or an in-flight START of the same id (the fixed
	// one-instance-per-operation grammar), then register the dispatch
	// fence. The ceiling stays with the reservation below: a fenced START
	// consumes no capacity until it reserves.
	m.mu.Lock()
	if _, exists := m.instances[opID]; exists {
		m.mu.Unlock()
		if settled != nil {
			settled()
		}
		return builderManagerRespOpExists
	}
	if _, inflight := m.startFences[opID]; inflight {
		m.mu.Unlock()
		if settled != nil {
			settled()
		}
		return builderManagerRespOpExists
	}
	fence := make(chan struct{})
	m.startFences[opID] = fence
	if settled != nil {
		settled()
	}
	m.mu.Unlock()

	if builderStartFenceHold != nil {
		builderStartFenceHold(opID)
	}

	// Reservation: validate the ceiling and reserve the map entry in the
	// same critical section, then settle the fence — a waiting STOP
	// re-checks the map after this and converges the reserved instance
	// through the ONE stop owner.
	m.mu.Lock()
	delete(m.startFences, opID)
	if len(m.instances) >= m.ceiling() {
		close(fence)
		m.mu.Unlock()
		return builderManagerRespAtCeiling
	}
	inst := &builderInstance{
		operationID: opID,
		phase:       builderInstanceStarting,
		diag:        newBoundedBuffer(builderInstanceDiagMaxBytes),
		done:        make(chan struct{}),
		launchDone:  make(chan struct{}),
		reaped:      make(chan struct{}),
	}
	m.instances[opID] = inst
	close(fence)
	m.mu.Unlock()

	// Launch outside the manager lock: a START readiness wait must not
	// block other STARTs, STOPs, or PURGE.
	if !m.launchInstance(inst) {
		return builderManagerRespInternal
	}
	return builderManagerRespOK
}

// launchInstance performs the filesystem preparation, process-group spawn,
// and bounded readiness wait. On ANY failure it converges to a clean
// state (process group killed/reaped, dirs removed, map entry removed)
// and returns false.
//
// The launch settles (closes inst.launchDone) exactly when this function
// returns, on any path. A STOP that claimed this instance awaits that
// settlement before reporting convergence: every post-claim launch step
// — directory creation, the spawn-phase claim check, the failed-start
// convergence with its idempotent dir re-removal — runs strictly before
// the STOP's OK, so the OK instant carries zero live processes and zero
// path residue, and an immediate same-ID START after the OK is admitted
// against clean paths.
func (m *builderManager) launchInstance(inst *builderInstance) bool {
	defer close(inst.launchDone)

	opID := inst.operationID
	rtDir := opRuntimeDir(opID)
	stDir := opStateDir(opID)

	if builderLaunchHold != nil {
		builderLaunchHold(opID)
	}

	// Refuse to adopt: if the paths already exist, a previous instance for
	// this op id was not reaped — fail closed.
	if _, err := os.Lstat(rtDir); err == nil {
		m.managerDiagf("START %s: runtime dir already exists; refusing to adopt", opID)
		m.removeReservation(inst)
		return false
	}
	if _, err := os.Lstat(stDir); err == nil {
		m.managerDiagf("START %s: state dir already exists; refusing to adopt", opID)
		m.removeReservation(inst)
		return false
	}
	for _, dir := range []string{rtDir, filepath.Join(stDir, "rootlesskit-state"), filepath.Join(stDir, "root")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			m.managerDiagf("START %s: cannot create instance dirs: %v", opID, err)
			m.removeReservation(inst)
			return false
		}
	}

	// CA bundle (backend mechanics; fail closed when required and absent).
	caEnv, caOK := builderResolveSystemCAFunc()
	if !caOK {
		m.managerDiagf("START %s: no readable supported system CA bundle", opID)
		m.convergeFailedStart(inst)
		return false
	}

	// Explicit child environment; no os.Environ() inheritance.
	// USER names the builder identity for buildkitd's rootless-mode
	// detection (isRootlessConfig: RunningInUserNS && $USER != "" &&
	// $USER != "root"); without it buildkitd v0.33 falls back to the
	// root defaults and its OTEL trace controller mkdirs /run/buildkit,
	// which an in-namespace root cannot create (M0/M1 carried USER and
	// are the proven composition).
	env := []string{
		"HOME=" + builderManagerStateRoot,
		"USER=" + builderManagerBuilderUser,
		"XDG_RUNTIME_DIR=" + rtDir,
		"PATH=" + builderManagerChildPath,
	}
	env = append(env, caEnv...)

	cmd := builderNewRootlessKitCommand(opID, rtDir, stDir, env)
	cmd.Stdin = nil
	cmd.Stdout = inst.diag
	cmd.Stderr = inst.diag
	// Go equivalent of setsid: the child becomes session and process-group
	// leader; instance.pid identifies THAT leader.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	// F4: bound the Wait owner's exposure to inherited pipes. When the
	// leader exits while group members still hold the ends of its
	// diagnostic pipes, cmd.Wait would otherwise block until those ends
	// are closed — and the convergence that would close them runs after
	// the Wait, so nothing would settle the group on its own. WaitDelay
	// makes the single Wait owner return once the leader has exited; the
	// existing convergence then settles the remaining group members
	// through the bounded escalation. There is still exactly one Wait
	// owner and one cleanup owner.
	cmd.WaitDelay = builderInstanceWaitDelay

	inst.mu.Lock()
	if inst.phase != builderInstanceStarting {
		inst.mu.Unlock()
		// A stop attempt owns the terminal convergence. Nothing was
		// spawned, so no stop right is needed for a kill; the launch
		// settles its own pre-spawn filesystem state (the dirs it
		// created) without blocking on the attempt. A removal failure
		// keeps the entry retained (truthful retry) instead of releasing
		// a reservation over surviving paths.
		if err := m.removeInstanceDirs(opID); err == nil {
			m.removeReservation(inst)
		}
		return false
	}
	spawnErr := cmd.Start()
	if spawnErr == nil {
		inst.leader = cmd
		inst.pid = cmd.Process.Pid
	}
	inst.mu.Unlock()

	if spawnErr != nil {
		m.managerDiagf("START %s: rootlesskit spawn failed: %v", opID, spawnErr)
		m.convergeFailedStart(inst)
		return false
	}

	// One child Wait owner per instance, started immediately after the
	// spawn and BEFORE the pid persist: it is the ONLY goroutine that
	// Waits the leader (F2 single-Wait-owner rule) and closes the reap
	// signal every stop attempt waits out. Starting it here closes the
	// claim window in which a stop attempt would otherwise await a Wait
	// owner that does not exist yet. When the leader later exits without
	// a STOP, this owner performs the terminal cleanup (unexpected-exit
	// contract, §18 of the plan).
	go m.awaitInstanceExit(inst)

	// Persist the leader PID for crash-cleanup identity proofing.
	if err := os.WriteFile(filepath.Join(rtDir, "instance.pid"), []byte(strconv.Itoa(inst.pid)+"\n"), 0600); err != nil {
		m.managerDiagf("START %s: cannot persist instance pid: %v", opID, err)
		if inst.stopRightTaken() {
			// A stop attempt owns convergence; this launch just settles.
			return false
		}
		m.convergeFailedStart(inst)
		return false
	}

	// Bounded readiness: leader alive + expected socket entry with the
	// expected owner/mode contract.
	if !m.awaitReadiness(inst) {
		inst.mu.Lock()
		claimed := inst.phase != builderInstanceStarting
		inst.mu.Unlock()
		if claimed {
			// The stop attempt (STOP/PURGE/self-exit owner) observed the
			// claim and owns convergence; this launch just settles.
			m.managerDiagf("START %s: launch cancelled by a stop claim", opID)
			return false
		}
		m.managerDiagf("START %s: readiness failed", opID)
		m.convergeFailedStart(inst)
		return false
	}

	// SUCCESS: phase -> running (unless a stop attempt claimed).
	inst.mu.Lock()
	if inst.phase == builderInstanceStarting {
		inst.phase = builderInstanceRunning
	}
	stopping := inst.phase == builderInstanceStopping
	inst.mu.Unlock()
	if stopping {
		// A stop attempt owns convergence; this launch settles (the
		// instance was never reported running) without touching it.
		return false
	}
	return true
}

func (m *builderManager) managerDiagf(format string, args ...any) {
	line := fmt.Sprintf(format, args...) + "\n"
	m.diag.Write([]byte(line))
	if m.stderr != nil {
		_, _ = m.stderr.Write([]byte(line))
	}
}

// removeReservation removes the map reservation for a failed START that
// never reached a state another owner may still be converging on.
func (m *builderManager) removeReservation(inst *builderInstance) {
	m.mu.Lock()
	if cur, ok := m.instances[inst.operationID]; ok && cur == inst {
		delete(m.instances, inst.operationID)
	}
	m.mu.Unlock()
}

// convergeFailedStart is the START failure convergence for the launch's
// own failure paths (CA resolve, spawn, pid persist, readiness deadline):
// claim the stop right and run one stop attempt through the shared owner.
// When a stop attempt is already in flight it owns convergence; this
// launch must not block on it (the attempt awaits this launch's
// settlement), so it just returns — the launch's reply is the internal
// refusal either way, and no dir of a possibly-live instance is touched.
func (m *builderManager) convergeFailedStart(inst *builderInstance) {
	if inst.claimStop() {
		_ = m.runStopAttempt(inst, false)
	}
}

// claimStop claims the single stop right for an instance: the gate for
// every convergence (STOP, PURGE, START failure paths, unexpected
// self-exit). Returns false while another attempt is in flight or the
// instance is already terminal. The claim is released at the end of every
// attempt (success or failure), so a failed attempt leaves the retained
// entry re-claimable for the next caller's retry.
func (inst *builderInstance) claimStop() bool {
	inst.mu.Lock()
	defer inst.mu.Unlock()
	if inst.stopClaimed || inst.phase == builderInstanceDone {
		return false
	}
	inst.stopClaimed = true
	inst.phase = builderInstanceStopping
	return true
}

// releaseStopClaim ends this attempt: the stop right returns for a retry
// (terminal state aside). The instance entry, its ceiling slot, and its
// possibly-live process group stay owned.
func (inst *builderInstance) releaseStopClaim() {
	inst.mu.Lock()
	inst.stopClaimed = false
	inst.mu.Unlock()
}

// stopRightTaken reports whether the instance's phase already moved off
// `starting` (a stop attempt claimed it, or it is terminal). A launch
// observing this must settle without touching the instance the attempt
// converges.
func (inst *builderInstance) stopRightTaken() bool {
	inst.mu.Lock()
	defer inst.mu.Unlock()
	return inst.phase != builderInstanceStarting
}

// awaitAttemptEnd blocks until the current stop attempt ended (its claim
// released) or the instance reached the terminal phase. Attempt durations
// are bounded by the stop constants, so the wait is bounded.
func (inst *builderInstance) awaitAttemptEnd() {
	for {
		inst.mu.Lock()
		claimed := inst.stopClaimed
		terminal := inst.phase == builderInstanceDone
		inst.mu.Unlock()
		if !claimed || terminal {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// leaderPidSnapshot returns the current leader pid (0 when none).
func (inst *builderInstance) leaderPidSnapshot() int {
	inst.mu.Lock()
	defer inst.mu.Unlock()
	return inst.pid
}

// signalProcessGroup sends sig to the leader's process group. The leader
// was spawned with Setsid, so its pid IS its pgid.
func (inst *builderInstance) signalProcessGroup(sig syscall.Signal) bool {
	pid := inst.leaderPidSnapshot()
	if pid <= 1 {
		return false
	}
	// Signal the NEGATIVE pid: the whole process group.
	if err := syscall.Kill(-pid, sig); err != nil && err != syscall.ESRCH {
		return false
	}
	return true
}

// stopInstance is THE cleanup owner for one instance. It is
// concurrency-safe against racing STOPs, PURGE, START failure paths, and
// self-exit. Convergence is gated by the stop-right claim: the claimant
// runs one bounded kill/reap/cleanup attempt; the others wait that
// attempt out and then claim for themselves (a failed attempt leaves the
// entry retained, so the next caller IS the retry). It returns nil only
// when the instance is terminal: process group proven gone, leader
// reaped by the single Wait owner, exact directories removed, done
// closed, entry released. A non-convergence returns
// errBuilderStopNotConverged with the entry RETAINED (ownership and
// ceiling capacity kept; no unproven-live process released) for the
// caller to surface as ERR internal and retry.
func (m *builderManager) stopInstance(inst *builderInstance) error {
	for {
		if inst.claimStop() {
			return m.runStopAttempt(inst, true)
		}
		inst.mu.Lock()
		terminal := inst.phase == builderInstanceDone
		inst.mu.Unlock()
		if terminal {
			<-inst.done
			return nil
		}
		// Another attempt is in flight (bounded): wait it out, then
		// claim the retry.
		inst.awaitAttemptEnd()
	}
}

// terminateGroupBounded escalates one process group to death: SIGTERM,
// the bounded graceful window, SIGKILL, and a bounded finalize wait. It
// returns nil only when the group is PROVEN gone (kill(-pgid, 0) ESRCH).
// Callers own the reap (an instance's stop attempt gets it from the
// single Wait owner) or have none to do (disk-only residue groups). The
// signal callback's return is advisory (signal delivery failures are
// diagnosable, not fatal); the group-gone probe is the truth source.
func terminateGroupBounded(pgid int, signal func(syscall.Signal) bool) error {
	if pgid <= 1 {
		return nil
	}
	signal(syscall.SIGTERM)
	deadline := time.Now().Add(builderStopGracefulTimeout)
	for !processGroupGone(pgid) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !processGroupGone(pgid) {
		signal(syscall.SIGKILL)
		finalize := time.Now().Add(builderStopFinalizeTimeout)
		for !processGroupGone(pgid) && time.Now().Before(finalize) {
			time.Sleep(10 * time.Millisecond)
		}
	}
	if !processGroupGone(pgid) {
		return fmt.Errorf("%w: process group %d did not fully die", errBuilderStopNotConverged, pgid)
	}
	return nil
}

// runStopAttempt is one bounded stop attempt, run by the claimant. The
// reap is NEVER performed here: the instance's single child Wait owner
// (awaitInstanceExit) owns the Wait and closes the reap signal, which
// this attempt awaits — STOP must not race cmd.Wait vs Process.Wait.
//
// awaitLaunch: when the caller is not the launch goroutine itself, the
// attempt first awaits the launch settlement (launchDone) so the exact
// directory cleanup below sees a quiesced filesystem for this op id —
// the launch's mkdir and its claim-observed re-removal both run strictly
// before the cleanup, and no re-creation can race the removal. The
// launch's own attempt passes false (its filesystem work is its own).
func (m *builderManager) runStopAttempt(inst *builderInstance, awaitLaunch bool) error {
	defer inst.releaseStopClaim()

	inst.mu.Lock()
	leader := inst.leader
	pid := inst.pid
	inst.mu.Unlock()

	if leader != nil {
		if leader.Process != nil {
			// Settle the whole group (the setsid leader's pid IS its
			// pgid); the claim already marked the phase so
			// launchInstance's spawn/readiness checks observe it.
			if err := terminateGroupBounded(pid, inst.signalProcessGroup); err != nil {
				m.managerDiagf("STOP %s: %v; retaining entry for retry", inst.operationID, err)
				return err
			}
		}
		// The leader is dead: its reap is owned by the single Wait owner.
		select {
		case <-inst.reaped:
		case <-time.After(builderStopFinalizeTimeout):
			m.managerDiagf("STOP %s: leader reap not observed by the Wait owner; retaining entry for retry", inst.operationID)
			return fmt.Errorf("%w: leader reap not observed", errBuilderStopNotConverged)
		}
	}

	// Terminal convergence: launch settlement, exact dir removal
	// (verified), entry release, terminal phase, done closed once — by
	// the claimant only.
	if awaitLaunch {
		<-inst.launchDone
	}
	if err := m.removeInstanceDirs(inst.operationID); err != nil {
		m.managerDiagf("STOP %s: directory cleanup failed; retaining entry for retry: %v", inst.operationID, err)
		return fmt.Errorf("%w: %v", errBuilderStopNotConverged, err)
	}
	m.removeReservation(inst)
	inst.mu.Lock()
	inst.phase = builderInstanceDone
	inst.leader = nil
	inst.pid = 0
	inst.mu.Unlock()
	close(inst.done)
	return nil
}

// processGroupGone reports whether the process group with pgid pid has no
// remaining members. A group ceases to exist when kill(-pgid, 0) returns
// ESRCH. pid<=1 is treated as gone (never a signal target).
func processGroupGone(pgid int) bool {
	if pgid <= 1 {
		return true
	}
	return syscall.Kill(-pgid, 0) == syscall.ESRCH
}

// awaitInstanceExit is the instance's single child Wait owner: the ONLY
// goroutine that Waits the leader. When the leader exits without a STOP,
// this owner claims the stop right (the single cleanup gate — the claim
// closes the window in which a racing STOP could converge the same
// instance twice) and settles the remaining group members BEFORE any
// directory removal, so no descendant keeps living under removed paths.
// When a STOP already owns convergence, the reap (above) is this owner's
// whole contribution.
func (m *builderManager) awaitInstanceExit(inst *builderInstance) {
	inst.mu.Lock()
	leader := inst.leader
	inst.mu.Unlock()
	if leader == nil {
		return
	}
	waitErr := leader.Wait()
	close(inst.reaped)

	inst.mu.Lock()
	stopping := inst.phase == builderInstanceStopping || inst.stopClaimed
	inst.mu.Unlock()
	if stopping {
		// STOP owns convergence; do not close done or remove dirs here.
		return
	}

	// Unexpected exit: bounded diagnostic tail, then terminal convergence
	// through the shared stop owner — claiming the stop right first.
	if tail := inst.diag.tailForDiagnostics(); tail != "" {
		m.managerDiagf("instance %s exited unexpectedly (wait=%v); child output tail:\n%s", inst.operationID, waitErr, tail)
	} else {
		m.managerDiagf("instance %s exited unexpectedly (wait=%v)", inst.operationID, waitErr)
	}
	if !inst.claimStop() {
		// A racing owner claimed between the check and here; it converges.
		return
	}
	m.runStopAttempt(inst, true)
}

// awaitReadiness implements the bounded readiness contract: leader alive,
// expected socket entry exists, is a Unix socket, is owned by the builder
// UID, and satisfies the expected private mode contract.
func (m *builderManager) awaitReadiness(inst *builderInstance) bool {
	deadline := time.Now().Add(builderInstanceReadinessTimeout)
	socketPath := opSocketPath(inst.operationID)
	for time.Now().Before(deadline) {
		inst.mu.Lock()
		phase := inst.phase
		leaderAlive := inst.leader != nil
		inst.mu.Unlock()
		if phase != builderInstanceStarting {
			return false
		}
		if leaderAlive {
			var st unix.Stat_t
			if err := unix.Stat(socketPath, &st); err == nil {
				if st.Mode&unix.S_IFSOCK != 0 && st.Uid == uint32(m.uid) {
					perm := st.Mode & 0o777
					// Private contract (the buildkitd socket shape:
					// containerd sys.GetLocalListener chmods 0660;
					// M0 evidence srw-rw----): owner-only or
					// owner+group; never world-accessible.
					if perm&0o007 == 0 && (perm&0o070 == 0o060 || perm&0o070 == 0) {
						return true
					}
				}
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// removeInstanceDirs removes the exact op runtime and state directories
// and verifies their disappearance. Paths derive from the canonical op id
// (validated by isOperationID), never from raw input; remove the exact
// tree, never an arbitrary path. An error means the cleanup did not
// complete; callers converge truthfully (retain for retry) instead of
// reporting success over remaining state.
func (m *builderManager) removeInstanceDirs(opID string) error {
	if !isOperationID(opID) {
		m.managerDiagf("refusing to remove instance dirs for noncanonical op id")
		return fmt.Errorf("refusing to remove instance dirs for noncanonical op id")
	}
	_ = os.RemoveAll(opRuntimeDir(opID))
	_ = os.RemoveAll(opStateDir(opID))
	if _, err := os.Lstat(opRuntimeDir(opID)); !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("runtime dir still present after removal: %v", err)
	}
	if _, err := os.Lstat(opStateDir(opID)); !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("state dir still present after removal: %v", err)
	}
	return nil
}

// tailForDiagnostics returns a bounded sanitized tail of the instance
// diagnostic buffer (newest bytes, capped), for manager operational stderr
// on relevant failure only.
func (b *boundedBuffer) tailForDiagnostics() string {
	b.mu.RLock()
	total := b.totalLen
	b.mu.RUnlock()
	const maxTail int64 = 8 * 1024
	start := total - maxTail
	if start < 0 {
		start = 0
	}
	data, _, _ := b.Range(start, maxTail)
	return strings.TrimSpace(string(data))
}

// builderSystemCABundleCandidates is the frozen deterministic resolver
// order (backend mechanics; the M0/M1-proven SSL_CERT_FILE fix).
var builderSystemCABundleCandidates = []string{
	"/etc/ssl/ca-bundle.pem",
	"/var/lib/ca-certificates/ca-bundle.pem",
	"/etc/pki/tls/certs/ca-bundle.crt",
	"/etc/ssl/certs/ca-certificates.crt",
}

// builderResolveSystemCAFunc is the injectable resolver seam (production:
// builderResolveSystemCA).
var builderResolveSystemCAFunc = builderResolveSystemCA

// builderResolveSystemCA selects the first supported real/readable system
// CA bundle and returns SSL_CERT_FILE env for the buildkitd child. It
// never chmods host material and never adds user config. ok=false means
// START fails closed.
func builderResolveSystemCA() ([]string, bool) {
	for _, path := range builderSystemCABundleCandidates {
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			continue
		}
		// Must be readable by the current process; never modify it.
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		_ = f.Close()
		return []string{"SSL_CERT_FILE=" + path}, true
	}
	return nil, false
}

// verifyRealDirectory verifies that path is a real (non-symlink)
// directory owned by the builder identity.
func (m *builderManager) verifyRealDirectory(path string) error {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("%s is not a real directory", path)
	}
	if st.Uid != uint32(m.uid) || st.Gid != uint32(m.gid) {
		return fmt.Errorf("%s is not owned by the builder identity", path)
	}
	return nil
}

// builderStalePidIdentity is the minimum stale-process identity proof
// before a persisted pid may be signaled: pid>1, process exists, process
// UID == builder UID, PGID == PID (session/group leader), and
// /proc/<pid>/cmdline identifies the exact expected manager-owned
// rootlesskit invocation for this op. Never trust the integer alone.
func builderStalePidIdentity(pid int, opID string, uid int) bool {
	if pid <= 1 {
		return false
	}
	// Process exists?
	if err := syscall.Kill(pid, 0); err != nil {
		return false
	}
	// Owner check. A failed stat cannot prove ownership; an incomplete
	// identity proof must never authorize a signal (F5).
	stat, err := os.Stat(filepath.Join("/proc", strconv.Itoa(pid)))
	if err != nil {
		return false
	}
	if uint32(stat.Sys().(*syscall.Stat_t).Uid) != uint32(uid) {
		return false
	}
	// Group-leader check: pgid == pid.
	pgid, err := syscall.Getpgid(pid)
	if err != nil || pgid != pid {
		return false
	}
	// Cmdline identity check.
	raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	if err != nil {
		return false
	}
	parts := strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00")
	if len(parts) == 0 || parts[0] != builderManagerRootlessKit {
		return false
	}
	wantState := "--state-dir=" + filepath.Join(opStateDir(opID), "rootlesskit-state")
	for _, part := range parts {
		if part == wantState {
			return true
		}
	}
	return false
}

// builderManagerUnitCgroupName is the canonical systemd unit cgroup name of
// the builder service: the P4 identity-boundary token. The manager
// recognizes the boundary by its own unified (cgroup v2) cgroup path ending
// in exactly this name; the unit's control-group kill discipline (systemd
// default) is the outer safety net that settles every builder-owned process
// — anchored or not — when a prior service generation stops.
const builderManagerUnitCgroupName = "docker-helper-builder.service"

// builderProcCgroupPathFunc is the per-process unified-cgroup-path reader
// seam (production: builderProcCgroupPath). Injectable for tests.
var builderProcCgroupPathFunc = builderProcCgroupPath

// builderUnitCgroupPathFunc is the unit-cgroup boundary seam (production:
// builderReadUnitCgroupPath). Injectable for tests.
var builderUnitCgroupPathFunc = builderReadUnitCgroupPath

// builderReadUnitCgroupPath returns the manager's own unified cgroup path
// when the running process provably sits inside the docker-helper-builder
// service cgroup (cgroup v2), and false otherwise — manual runs, cgroup v1,
// or any other unit name keep the boundary-independent fail-closed purge
// semantics. The cgroup path is kernel-owned truth for a live process: the
// unprivileged manager cannot shape it, and a unit name only appears here
// when systemd placed the process there.
func builderReadUnitCgroupPath() (string, bool) {
	path, err := builderProcCgroupPathFunc(os.Getpid())
	if err != nil {
		return "", false
	}
	if filepath.Base(path) != builderManagerUnitCgroupName {
		return "", false
	}
	return path, true
}

// builderProcCgroupPath reads the unified (cgroup v2) cgroup path of one
// process from /proc/<pid>/cgroup (the single "0::<path>" line). A missing
// entry (os.ErrNotExist) means the process died between the /proc listing
// and this read — a verified disappearance (F5.1). Any other error,
// including the absence of a v2 line, is an inconclusive inspection and
// taints the calling enumeration.
func builderProcCgroupPath(pid int) (string, error) {
	raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		// Unified line grammar: "<0>:<no controllers>:<path>".
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 || parts[0] != "0" || parts[1] != "" {
			continue
		}
		if parts[2] == "" {
			return "", errors.New("empty unified cgroup path")
		}
		return parts[2], nil
	}
	return "", errors.New("no unified cgroup v2 entry")
}

// procCgroupWithin reports whether a unified cgroup path is the unit cgroup
// itself or lies inside its subtree: systemd's control-group kill
// discipline covers the whole subtree.
func procCgroupWithin(path, unitCgroup string) bool {
	return path == unitCgroup || strings.HasPrefix(path, unitCgroup+"/")
}

// builderScanUnitOwnedGroups enumerates the live processes of the builder
// uid inside the manager's unit cgroup subtree, excluding the manager
// process itself. Under the P4 service-unit boundary, membership inside
// this cgroup IS the ownership proof for builder-owned residue: systemd is
// the only boundary that can place builder-uid processes there, and it
// fully stopped the prior service generation (control-group kill) before
// this manager generation started. The command line is NOT consulted — an
// unanchored member (slirp4netns) is as owned as an anchored leader, which
// is exactly what the cmdline-anchor enumeration cannot see.
//
// ok=false is an inconclusive enumeration and the caller must fail closed
// (F5.1 rules: a verified disappearance never taints; a non-ENOENT read
// error does).
func builderScanUnitOwnedGroups(unitCgroup string, uid int) ([]int, bool) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, false
	}
	pgids := make(map[int]bool)
	self := os.Getpid()
	for _, entry := range entries {
		name := entry.Name()
		pid, err := strconv.Atoi(name)
		if err != nil || pid <= 1 {
			continue
		}
		procDir := filepath.Join("/proc", name)
		stat, err := os.Stat(procDir)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue // died mid-scan: verified disappearance
			}
			return nil, false // inconclusive inspection
		}
		if uint32(stat.Sys().(*syscall.Stat_t).Uid) != uint32(uid) {
			continue // different owner: provably not ours
		}
		if pid == self {
			continue // the manager itself
		}
		path, err := builderProcCgroupPathFunc(pid)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue // died mid-scan: verified disappearance
			}
			return nil, false // inconclusive inspection
		}
		if !procCgroupWithin(path, unitCgroup) {
			continue // outside the unit boundary: not owned by this unit
		}
		pgid, err := syscall.Getpgid(pid)
		if err != nil {
			if errors.Is(err, syscall.ESRCH) {
				continue // died between the classification and now
			}
			return nil, false // inconclusive inspection
		}
		pgids[pgid] = true
	}
	out := make([]int, 0, len(pgids))
	for pgid := range pgids {
		out = append(out, pgid)
	}
	sort.Ints(out)
	return out, true
}

// startupPurge performs startup PURGE semantics: terminate every
// manager-owned op process group found live in the instance map, remove
// op-private runtime/state, and scan crash residue left on disk. No
// adoption into live entries; no reconciliation. For stale disk-only
// state: validate the op directory name with isOperationID, validate the
// persisted process identity before signaling, remove dead/verified-owned
// residue, and FAIL CLOSED rather than kill a process whose identity
// cannot be proven.
//
// The P4 systemd unit boundary changes the residue model when the manager
// provably runs inside the docker-helper-builder service cgroup: cgroup
// membership (plus the builder uid) is then the ownership proof for
// builder-owned residue — stronger than and independent of the per-op
// cmdline anchors — and the boundary guarantees the prior service
// generation was fully stopped (its whole cgroup settled) before this
// generation started. The purge first settles every live builder-owned
// process group found inside the unit cgroup subtree (including unanchored
// members the anchor scan cannot see); the absence of a live owned process
// afterwards is PROVEN, not inferred, and resolves the previously
// fail-closed ambiguous states below (F5.1): pid-file-less residue,
// unreadable same-uid identities outside the boundary, and reused pids.
func (m *builderManager) startupPurge() error {
	unitCgroup, inUnit := builderUnitCgroupPathFunc()
	if inUnit {
		m.managerDiagf("startup purge: P4 unit cgroup boundary active (%s)", unitCgroup)
	}

	// Live instances (should be none at startup, but converge if so) —
	// synchronously through the single stop owner: claiming the stop
	// right and THEN handing the attempt to a fresh stopInstance would
	// double-claim (the new call sees the claim taken and waits for done
	// that only a claimant closes), so the attempt runs on this goroutine.
	m.mu.Lock()
	snapshot := make([]*builderInstance, 0, len(m.instances))
	for _, inst := range m.instances {
		snapshot = append(snapshot, inst)
	}
	m.mu.Unlock()
	for _, inst := range snapshot {
		if err := m.stopInstance(inst); err != nil {
			return err
		}
	}

	// The unit boundary: settle every live builder-owned process group
	// inside the unit cgroup subtree. These can only be residue of an
	// already-stopped prior service generation (systemd starts a new
	// generation only into an empty control group); the settlement is
	// justified by cgroup membership, without any cmdline attribution,
	// and is what later authorizes the pid-file-less residue removal
	// below.
	if inUnit {
		pgids, ok := builderScanUnitOwnedGroups(unitCgroup, m.uid)
		if !ok {
			m.managerDiagf("startup purge: unit-cgroup enumeration failed; refusing startup")
			return fmt.Errorf("startup purge: unit-cgroup enumeration failed; refusing startup")
		}
		for _, pgid := range pgids {
			if err := m.killOwnedResidueGroup("unit residue group", pgid); err != nil {
				return err
			}
		}
	}

	// Crash residue on disk: one recovery decision per canonical op id
	// across both fixed roots (F5.1). The runtime dir holds the
	// authoritative pid file; the state dir never does, so a per-dir
	// zero-match rule would permanently wedge state residue.
	rtOps, err := m.canonicalOpsEntries(builderRuntimeRoot)
	if err != nil {
		return err
	}
	stOps, err := m.canonicalOpsEntries(builderStateRoot)
	if err != nil {
		return err
	}
	seen := make(map[string]bool, len(rtOps)+len(stOps))
	opIDs := make([]string, 0, len(rtOps)+len(stOps))
	for _, opID := range append(append([]string{}, rtOps...), stOps...) {
		if !seen[opID] {
			seen[opID] = true
			opIDs = append(opIDs, opID)
		}
	}
	sort.Strings(opIDs)
	for _, opID := range opIDs {
		if err := m.purgeOpResidue(opID, unitCgroup); err != nil {
			return err
		}
	}
	return nil
}

// canonicalOpsEntries returns the canonical operation ids found under
// <root>/ops, sorted. Noncanonical entries are product-foreign state:
// bounded diagnostic, never removed.
func (m *builderManager) canonicalOpsEntries(root string) ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(root, "ops"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var ops []string
	for _, entry := range entries {
		name := entry.Name()
		if !isOperationID(name) {
			m.managerDiagf("startup purge: skipping noncanonical ops entry %q", name)
			continue
		}
		ops = append(ops, name)
	}
	sort.Strings(ops)
	return ops, nil
}

// purgeOpResidue converges the crash residue of ONE canonical op id
// across its runtime and state directories through the startup contract
// (F3+F5+F5.1). The persisted pid (exactly "<pid>\n", runtime dir) is
// classified through the liveness tri-state: undecidable liveness fails
// closed; a live pid that cannot be proven owned as the exact rootlesskit
// leader (unknown, mismatched, reused) fails closed WITHOUT any signal or
// removal — except under the P4 unit boundary, where a live recorded pid
// inside the unit cgroup subtree is owned residue by membership (settled
// through the existing bounded escalation owner) and a live recorded pid
// outside the boundary is a reused pid whose recorded instance is provably
// gone (no signal; the directories are removable residue); a positively
// identified live leader is settled through the existing bounded escalation
// owner before the enumeration. The /proc enumeration then positively
// identifies remaining owned groups behind this op — anchored groups
// always, and under the unit boundary additionally in-unit groups by
// membership — one group is settled through the same termination owner and
// its verified group death is the removal proof; ambiguity (more than one
// group) fails closed. After the anchored convergence, a recorded pid's
// group must be verifiably gone (kill(-pid,0) == ESRCH): live unproven
// members (e.g. an unanchored descendant of a dead recorded leader) fail
// closed with the directories retained — except under the unit boundary,
// where such members were already settled by the boundary scan above and a
// still-live recorded group can only hold foreign members (reused pid), so
// the recorded instance is provably gone and the directories are removed
// without any signal. With NO authoritative pid file, zero anchored matches
// do not prove an unknown group gone and fail closed in the legacy mode;
// under the unit boundary the boundary scan proved the absence of every
// live owned process, so the directories are residue of a prior, fully
// settled service generation (the pre-pid-write crash window or the
// systemd-wiped runtime tree) and are removed. Incomplete enumeration and
// removal failures fail closed.
func (m *builderManager) purgeOpResidue(opID string, unitCgroup string) error {
	rtDir := opRuntimeDir(opID)
	pid := readInstancePid(rtDir)
	if pid > 0 {
		switch builderLivenessOf(pid) {
		case builderProcessUnknown:
			// Undecidable liveness: never treated as death (F5).
			m.managerDiagf("startup purge: liveness of persisted pid %d for op %s is undecidable; refusing startup", pid, opID)
			return fmt.Errorf("startup purge: liveness of persisted pid %d for op %s is undecidable; refusing startup", pid, opID)
		case builderProcessAlive:
			if !builderStalePidIdentity(pid, opID, m.uid) {
				if unitCgroup == "" {
					// Live but unproven (foreign or reused pid): fail
					// closed. No signal, no removal.
					m.managerDiagf("startup purge: live process %d for op %s could not be proven owned; refusing startup", pid, opID)
					return fmt.Errorf("startup purge: live process %d for op %s could not be proven owned; refusing startup", pid, opID)
				}
				// P4 unit boundary: classify the live recorded pid by
				// cgroup membership. Inside the unit subtree it is owned
				// residue by membership (the cgroup is the ownership
				// proof, stronger than the cmdline identity): settle it
				// through the same bounded escalation owner. Outside the
				// boundary it is a reused pid: the recorded instance is
				// provably gone and the recorded group holds no owned
				// members (the boundary scan settled those); no signal.
				if path, err := builderProcCgroupPathFunc(pid); err == nil && procCgroupWithin(path, unitCgroup) {
					if err := m.killOwnedResidueGroup("op "+opID+" (unit-owned)", pid); err != nil {
						return err
					}
					break
				}
				m.managerDiagf("startup purge: persisted pid %d for op %s was reused by a process outside the unit boundary; recorded instance is gone", pid, opID)
				break
			}
			// Exactly owned live leader: settle it through the existing
			// termination owner before the enumeration.
			if err := m.killOwnedResidueGroup("op "+opID, pid); err != nil {
				return err
			}
		case builderProcessDead:
			// The leader is gone, but live owned group members may
			// remain behind the op; the enumeration below decides.
		}
	}
	// Enumerate live owned groups behind this op (the /proc
	// fallback for absent/truncated pid files, the crash window, and
	// dead leaders with surviving members). Incomplete enumeration does
	// not prove absence (F5.1).
	pgids, ok := builderScanOwnedStateDirGroups(opID, m.uid, unitCgroup)
	if !ok {
		m.managerDiagf("startup purge: /proc enumeration failed for op %s; refusing startup", opID)
		return fmt.Errorf("startup purge: /proc enumeration failed for op %s; refusing startup", opID)
	}
	switch len(pgids) {
	case 0:
		if pid == 0 {
			if unitCgroup == "" {
				// No authoritative pid file and no anchored live process
				// (F5.1): zero matches do not prove an unknown group gone —
				// an unanchored member of an unrecorded group is
				// undetectable here. Retain the directories and fail closed.
				m.managerDiagf("startup purge: no pid file and no anchored process behind op %s; zero matches do not prove an unknown group gone; refusing startup", opID)
				return fmt.Errorf("startup purge: no pid file and no anchored process behind op %s; refusing startup", opID)
			}
			// P4 unit boundary: the boundary scan above proved that no
			// live builder-owned process exists at all (inside the
			// boundary nothing can be owned, and outside it only exact
			// per-op anchors are owned). The directories are residue of a
			// prior, fully settled service generation and are removable.
			m.managerDiagf("startup purge: no pid file behind op %s; the unit boundary proves the prior service generation settled; removing residue", opID)
		}
		// pid > 0: the recorded group's own liveness check below decides.
	case 1:
		// Positively identified by the exact per-op anchor and uid (or,
		// under the unit boundary, additionally by in-unit membership):
		// settle through the existing bounded escalation owner; the
		// verified group death (which takes unanchored members of the
		// same group with it) is the removal proof.
		if err := m.killOwnedResidueGroup("op "+opID, pgids[0]); err != nil {
			return err
		}
	default:
		// Ambiguous: more than one owned group behind one op.
		m.managerDiagf("startup purge: %d owned groups behind op %s; refusing startup", len(pgids), opID)
		return fmt.Errorf("startup purge: %d owned groups behind op %s; refusing startup", len(pgids), opID)
	}
	if pid > 0 && !processGroupGone(pid) {
		if unitCgroup == "" {
			// The recorded group still has live members that the anchor
			// enumeration could not prove owned (e.g. an unanchored
			// descendant of the dead recorded leader): no speculative
			// signal, no removal (F5.1).
			m.managerDiagf("startup purge: recorded group %d for op %s still has live unproven members; refusing startup", pid, opID)
			return fmt.Errorf("startup purge: recorded group %d for op %s still has live unproven members; refusing startup", pid, opID)
		}
		// P4 unit boundary: any owned member of the recorded group was
		// inside the unit cgroup subtree and was already settled by the
		// boundary scan; a still-live group can only hold foreign members
		// (reused pid outside the boundary). The recorded instance is
		// provably gone: no signal, the directories are removable.
		m.managerDiagf("startup purge: recorded group %d for op %s holds no owned members under the unit boundary; removing residue", pid, opID)
	}
	for _, dir := range []string{rtDir, opStateDir(opID)} {
		if err := os.RemoveAll(dir); err != nil {
			return fmt.Errorf("startup purge: cannot remove residue %s: %v", dir, err)
		}
		if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("startup purge: residue %s still present after removal: %v", dir, err)
		}
	}
	return nil
}

// killOwnedResidueGroup terminates a verified-owned live residue group
// through the shared bounded escalation (SIGTERM -> SIGKILL, verified
// group death). The exact ownership was proven BEFORE any signal: either
// the full builderStalePidIdentity leader proof (pid file path), the
// builderScanOwnedStateDirGroups anchor enumeration (crash-window path),
// or the P4 unit-cgroup membership proof. label names the residue in
// diagnostics. Fail closed when the group survives.
func (m *builderManager) killOwnedResidueGroup(label string, pid int) error {
	signal := func(sig syscall.Signal) bool {
		if err := syscall.Kill(-pid, sig); err != nil && err != syscall.ESRCH {
			return false
		}
		return true
	}
	if err := terminateGroupBounded(pid, signal); err != nil {
		m.managerDiagf("startup purge: %v; refusing startup", err)
		return fmt.Errorf("startup purge: owned group %d (%s) did not die", pid, label)
	}
	return nil
}

// builderScanOwnedStateDirGroups enumerates /proc for live processes of
// the manager's uid whose command line carries an exact per-op anchor
// argument for this operation's own state paths: --state-dir=
// <stDir>/rootlesskit-state for the rootlesskit leader and --root=
// <stDir>/root for the buildkitd child. It returns the distinct process
// group ids behind those processes.
//
// With a non-empty unitCgroup (the P4 systemd unit boundary), the
// classification extends: a same-uid process inside the unit cgroup
// subtree is owned by cgroup MEMBERSHIP regardless of its command line
// (the boundary scan settles it before the per-op decisions; its
// cmdline is not consulted), while a same-uid process outside the
// boundary is foreign by membership and never taints the enumeration —
// the per-op anchor proof still applies to it best-effort, with an
// unreadable or empty (zombie) cmdline skipped instead of tainted: a
// process outside the unit boundary cannot be owned residue of this
// service generation.
//
// Error classification (F5.1): a verified disappearance never taints the
// enumeration — an entry that vanished between listing and inspection
// (ENOENT on stat/cmdline/cgroup, ESRCH on Getpgid) is a process that died
// mid-scan and cannot be a live owned group member. An INCONCLUSIVE
// inspection does taint it: a failed /proc ReadDir, a non-ENOENT stat or
// cmdline read error, or a same-uid entry whose cmdline read succeeds
// but is empty (the identity itself is unreadable, e.g. a zombie) yield
// ok=false and the caller must fail closed — with the unit-cgroup
// exception above. Silent skips never become proof of absence.
//
// Unanchored group members (processes without a per-op anchor argument)
// are NOT enumerable by the anchor scan; under the unit boundary the
// builderScanUnitOwnedGroups membership scan is the authoritative
// enumeration for them. No parallel supervisor exists here.
func builderScanOwnedStateDirGroups(opID string, uid int, unitCgroup string) ([]int, bool) {
	stDir := opStateDir(opID)
	anchors := map[string]bool{
		"--state-dir=" + filepath.Join(stDir, "rootlesskit-state"): true,
		"--root=" + filepath.Join(stDir, "root"):                   true,
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, false
	}
	pgids := make(map[int]bool)
	self := os.Getpid()
	for _, entry := range entries {
		name := entry.Name()
		pid, err := strconv.Atoi(name)
		if err != nil || pid <= 1 {
			continue
		}
		if pid == self {
			continue // the manager itself (in-unit by definition)
		}
		procDir := filepath.Join("/proc", name)
		stat, err := os.Stat(procDir)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue // died mid-scan: verified disappearance
			}
			return nil, false // inconclusive inspection
		}
		if uint32(stat.Sys().(*syscall.Stat_t).Uid) != uint32(uid) {
			continue // different owner: provably not ours
		}
		if unitCgroup != "" {
			path, err := builderProcCgroupPathFunc(pid)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					continue // died mid-scan: verified disappearance
				}
				return nil, false // inconclusive inspection
			}
			if procCgroupWithin(path, unitCgroup) {
				// Inside the unit boundary: owned by membership. The
				// cmdline is not consulted (an unreadable identity here
				// is still owned residue; the settle's verified group
				// death is the proof).
				pgid, err := syscall.Getpgid(pid)
				if err != nil {
					if errors.Is(err, syscall.ESRCH) {
						continue // died between the classification and now
					}
					return nil, false // inconclusive inspection
				}
				pgids[pgid] = true
				continue
			}
		}
		raw, err := os.ReadFile(filepath.Join(procDir, "cmdline"))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue // died mid-scan: verified disappearance
			}
			if unitCgroup != "" {
				// Outside the unit boundary: foreign by membership; the
				// anchor proof is best-effort and a non-ENOENT read
				// error does not taint this classification.
				continue
			}
			return nil, false // inconclusive inspection (unreadable identity)
		}
		if len(raw) == 0 {
			// Same-uid entry with an unreadable identity (empty cmdline,
			// e.g. a zombie): inconclusive, not absence — outside the
			// unit boundary it is foreign by membership and skipped.
			if unitCgroup != "" {
				continue
			}
			return nil, false
		}
		matched := false
		for _, part := range strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00") {
			if anchors[part] {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		pgid, err := syscall.Getpgid(pid)
		if err != nil {
			if errors.Is(err, syscall.ESRCH) {
				continue // died between the cmdline read and now
			}
			return nil, false // inconclusive inspection
		}
		pgids[pgid] = true
	}
	out := make([]int, 0, len(pgids))
	for pgid := range pgids {
		out = append(out, pgid)
	}
	sort.Ints(out)
	return out, true
}

// readInstancePid reads and parses instance.pid. The manager always
// writes the decimal pid followed by exactly one newline; a file without
// the trailing newline is a crash-mid-write truncation and cannot become
// a valid pid, because a decimal prefix may name a different live
// process (F5). Returns 0 when absent, unreadable, truncated, or
// invalid.
func readInstancePid(opDir string) int {
	raw, err := os.ReadFile(filepath.Join(opDir, "instance.pid"))
	if err != nil || len(raw) == 0 || raw[len(raw)-1] != '\n' {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimRight(string(raw), "\n"))
	if err != nil || pid <= 0 {
		return 0
	}
	return pid
}

// builderProcessLiveness is the kill(pid, 0) tri-state the startup purge
// must distinguish (F5): ESRCH proves the process is gone; nil and EPERM
// both mean a live process (EPERM merely denies the signal to a foreign
// process); any other errno is undecidable and must fail closed rather
// than be treated as death.
type builderProcessLiveness int

const (
	builderProcessDead builderProcessLiveness = iota
	builderProcessAlive
	builderProcessUnknown
)

// builderLivenessOf classifies a pid without signaling it.
func builderLivenessOf(pid int) builderProcessLiveness {
	if pid <= 1 {
		return builderProcessDead
	}
	err := syscall.Kill(pid, 0)
	switch {
	case err == nil || errors.Is(err, syscall.EPERM):
		return builderProcessAlive
	case errors.Is(err, syscall.ESRCH):
		return builderProcessDead
	default:
		return builderProcessUnknown
	}
}

// processAlive reports whether pid names a process that exists; an
// undecidable liveness is never reported as death.
func processAlive(pid int) bool {
	return builderLivenessOf(pid) == builderProcessAlive
}

// removeStaleManagerSocket removes a stale manager socket ONLY after
// proving it is the expected builder-owned socket entry (real socket,
// builder-owned). Never removes an arbitrary path.
func (m *builderManager) removeStaleManagerSocket() error {
	return m.removeStaleManagerSocketAt(builderClientSocketPath)
}

// removeStaleManagerSocketAt is the path-parameterized stale-socket
// remover (test seam; production always passes the canonical constant).
func (m *builderManager) removeStaleManagerSocketAt(socketPath string) error {
	var st unix.Stat_t
	if err := unix.Lstat(socketPath, &st); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return fmt.Errorf("%s exists and is not a socket; refusing", socketPath)
	}
	if st.Uid != uint32(m.uid) || st.Gid != uint32(m.gid) {
		return fmt.Errorf("%s is not owned by the builder identity; refusing", socketPath)
	}
	return os.Remove(socketPath)
}

// prepareManagerSocket creates the manager-owned 0600 unix stream socket
// after verifying both roots.
func (m *builderManager) prepareManagerSocket() (*net.UnixListener, error) {
	return m.prepareManagerSocketAt(builderClientSocketPath)
}

// prepareManagerSocketAt is the path-parameterized socket owner (the test
// seam mounts a non-production path; production always passes the
// canonical constant).
func (m *builderManager) prepareManagerSocketAt(socketPath string) (*net.UnixListener, error) {
	if err := m.verifyRealDirectory(builderManagerRuntimeRoot); err != nil {
		return nil, fmt.Errorf("runtime root: %w", err)
	}
	if err := m.verifyRealDirectory(builderManagerStateRoot); err != nil {
		return nil, fmt.Errorf("state root: %w", err)
	}
	if err := m.removeStaleManagerSocketAt(socketPath); err != nil {
		return nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(socketPath, 0600); err != nil {
		_ = listener.Close()
		return nil, err
	}
	return listener, nil
}

// authenticatePeer enforces the server-side SO_PEERCRED contract: only
// uid 0 (the root docker-helper daemon) may dispatch commands. Anything
// else: refuse, no command execution.
func authenticatePeer(conn *net.UnixConn) error {
	uid, _, _, err := builderPeerCredentials(conn)
	if err != nil {
		return err
	}
	if uid != 0 {
		return errBuilderManagerUnauthorized
	}
	return nil
}

// serve is the builder serve long-running loop: startup purge, socket
// setup, concurrent per-connection handling with one request per
// connection and one bounded response line.
func (m *builderManager) serve(stderr io.Writer) error {
	if err := m.startupPurge(); err != nil {
		fmt.Fprintf(stderr, "builder serve: startup purge failed: %v\n", err)
		return err
	}
	listener, err := m.prepareManagerSocket()
	if err != nil {
		fmt.Fprintf(stderr, "builder serve: %v\n", err)
		return err
	}
	defer func() {
		_ = listener.Close()
		_ = os.Remove(builderClientSocketPath)
	}()

	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			// Transient accept errors keep serving; permanent ones return.
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			fmt.Fprintf(stderr, "builder serve: accept: %v\n", err)
			continue
		}
		seq := m.ingress.accept()
		go m.handleConnection(conn, stderr, seq)
	}
}

// handleConnection reads exactly one bounded request line, authenticates
// the peer BEFORE dispatch, executes, and writes exactly one response
// line from the fixed vocabulary.
//
// seq is the connection's ingress-barrier sequence number (0 for direct
// callers outside the accept loop: never registered, settle is a no-op).
// The deferred settle is the catch-all for connections that never reach
// a command dispatch (unauthorized peer, malformed or oversized request,
// EOF, read deadline); STOP and PURGE settle at dispatch; a START settles
// through its admission callback inside start, at the refusal or the
// dispatch-fence registration — never after the launch.
func (m *builderManager) handleConnection(conn *net.UnixConn, stderr io.Writer, seq int) {
	defer conn.Close()
	defer m.ingress.settle(seq)

	if err := authenticatePeer(conn); err != nil {
		if !errors.Is(err, errBuilderManagerUnauthorized) {
			fmt.Fprintf(stderr, "builder serve: peer credential check failed: %v\n", err)
		}
		return
	}

	// Bounded read: exactly one request line within the fixed ceiling.
	// Read up to ceiling+1 bytes; EOF before the newline is a complete
	// request only when a line was actually received. Never an unbounded
	// ReadString.
	buf := make([]byte, builderManagerRequestCeiling+1)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		return // broken request: no response, no execution
	}
	if err == nil && n > builderManagerRequestCeiling {
		// Oversized request: no response, no execution.
		return
	}
	line := buf[:n]
	if idx := bytes.IndexByte(line, '\n'); idx >= 0 {
		line = line[:idx]
	} else if err == nil {
		// No newline yet: keep reading bounded until EOF or newline.
		for {
			more, readErr := conn.Read(buf[n:])
			if more > 0 {
				n += more
				if bytes.IndexByte(buf[:n], '\n') >= 0 || n > builderManagerRequestCeiling {
					break
				}
			}
			if readErr != nil {
				if readErr == io.EOF {
					break
				}
				return
			}
		}
		if idx := bytes.IndexByte(buf[:n], '\n'); idx >= 0 {
			line = buf[:idx]
		} else {
			// No newline within the ceiling: oversized/malformed.
			return
		}
	} else {
		// EOF with no complete line: malformed.
		return
	}

	req, errResp := parseBuilderManagerRequest(line)
	if errResp != "" {
		fmt.Fprintf(conn, "%s\n", errResp)
		return
	}

	var response string
	switch req.Command {
	case builderManagerCmdStart:
		response = m.start(req.OperationID, func() { m.ingress.settle(seq) })
	case builderManagerCmdStop:
		m.ingress.settle(seq)
		response = m.stop(req.OperationID, seq)
	case builderManagerCmdPurge:
		m.ingress.settle(seq)
		response = m.purge()
	default:
		response = builderManagerRespUnknownCmd
	}
	fmt.Fprintf(conn, "%s\n", response)
}

// stop is the STOP protocol operation. Idempotent: unknown/absent ->
// OK absent; an existing instance converges through stopInstance (the
// single cleanup owner) and then returns OK. The `OK absent` answer
// carries the START/STOP ordering guarantee: a STOP never reports
// convergence while an accepted START of the same id is still unsettled —
// it waits for the dispatch fence and then converges whatever that START
// created (or reports absent when the START was refused).
//
// seq is the STOP connection's ingress-barrier sequence number. The
// absent answer is additionally ordered against ACCEPTED-BUT-UNPARSED
// STARTs (F1.2): before reporting `OK absent` the STOP settles every
// connection accepted before its own — a START's settle is its refusal
// or fence registration under the manager lock — and then re-checks the
// map and fences, so no older accepted START can reserve and launch
// after the STOP reported convergence. The wait is transient: older
// connections settle within their bounded read window at the latest, a
// START settles at admission (never after its launch), and the barrier
// holds only the absent answer — instance convergence and other commands
// proceed concurrently. seq 0 (direct callers outside the accept loop)
// has nothing older and skips the barrier.
//
// The convergence answer (OK) carries the launch-quiescence contract
// (F1.3): it is emitted only after the converged instance's launch
// goroutine settled, so zero live processes and zero path residue exist
// at the OK instant and an immediate same-ID START afterwards is
// admitted against clean paths.
func (m *builderManager) stop(opID string, seq int) string {
	barrierSettled := false
	for {
		m.mu.Lock()
		inst, ok := m.instances[opID]
		var fence chan struct{}
		if !ok {
			fence = m.startFences[opID]
		}
		m.mu.Unlock()
		if ok {
			// stopInstance is safe for racing callers: exactly one claimant
			// performs the kill/reap/cleanup attempt; the others wait it
			// out and claim the retry. A non-convergence is truthful:
			// ERR internal with the entry retained (ownership and ceiling
			// capacity kept; no unproven-live process released).
			if err := m.stopInstance(inst); err != nil {
				return builderManagerRespInternal
			}
			// Launch quiescence: the OK is emitted only after the
			// instance's launch goroutine fully settled, so no post-claim
			// launch work (directory re-creation, spawn, failed-start
			// convergence) runs after this STOP reported convergence.
			<-inst.launchDone
			return builderManagerRespOK
		}
		if fence != nil {
			if builderStopFenceWait != nil {
				builderStopFenceWait(opID)
			}
			<-fence
			// The START settled: re-check — it may have reserved the
			// instance this STOP must converge.
			continue
		}
		if barrierSettled {
			return builderManagerRespOKAbsent
		}
		// No entry, no fence: an older accepted connection may still be
		// carrying the START this STOP must not overtake. Settle the
		// barrier, then re-check under the manager lock.
		m.ingress.waitOlder(seq)
		barrierSettled = true
	}
}

// purge is the runtime PURGE protocol operation: snapshot/claim all
// manager-owned instances, stop them with the same STOP owner, remove
// op-private state, return OK only after convergence — including each
// instance's launch settlement (the same quiescence contract as STOP).
func (m *builderManager) purge() string {
	m.mu.Lock()
	snapshot := make([]*builderInstance, 0, len(m.instances))
	for _, inst := range m.instances {
		snapshot = append(snapshot, inst)
	}
	m.mu.Unlock()
	converged := true
	for _, inst := range snapshot {
		if err := m.stopInstance(inst); err != nil {
			converged = false
			continue
		}
		<-inst.launchDone
	}
	if !converged {
		// Truthful PURGE: retained entries (and their capacity) stay for
		// a retry PURGE through the same stop owner.
		return builderManagerRespInternal
	}
	return builderManagerRespOK
}

// runBuilderServe implements the `docker-helper builder serve` command:
// the long-running builder backend service. It is an operator/service
// command, not an agent command, and owns NO runtime/state/socket/path
// overrides: the fixed production paths are canonical constants.
//
// Startup is fail closed: service-role umask 0077, execution-identity
// verification (exact dedicated docker-helper-builder identity, no root,
// no other user), then the manager serve loop.
func runBuilderServe(stdout, stderr io.Writer) error {
	// Service-role umask before creating manager-owned runtime objects.
	syscall.Umask(0o077)

	if _, _, err := builderVerifyIdentity(); err != nil {
		fmt.Fprintf(stderr, "builder serve: %v\n", err)
		return err
	}

	m := newBuilderManager(-1, -1)
	// Mirror the operational diagnostics to the service stderr (the unit
	// journal); the bounded buffer stays the programmatic owner.
	m.stderr = stderr
	// Resolve the concrete builder identity for ownership checks.
	u, err := builderLookupUser(builderManagerBuilderUser)
	if err != nil {
		fmt.Fprintf(stderr, "builder serve: %v\n", err)
		return err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		fmt.Fprintf(stderr, "builder serve: %v\n", err)
		return err
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		fmt.Fprintf(stderr, "builder serve: %v\n", err)
		return err
	}
	m.uid = uid
	m.gid = gid

	return m.serve(stderr)
}
