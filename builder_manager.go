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
	// slirp4netns) through exactly this manager-owned PATH.
	builderManagerChildPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"

	// builderInstanceDiagMaxBytes is the fixed internal diagnostic ceiling
	// for one instance's RootlessKit/buildkitd combined stdout/stderr
	// (bounded tail; not config/API).
	builderInstanceDiagMaxBytes int64 = 64 * 1024

	// builderInstanceReadinessTimeout bounds the START readiness wait.
	builderInstanceReadinessTimeout = 60 * time.Second

	// builderStopGracefulTimeout bounds the SIGTERM->SIGKILL escalation.
	builderStopGracefulTimeout = 5 * time.Second
)

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
}

// builderManager owns the per-operation ephemeral BuildKit instance
// lifecycle. The instance map counts an instance against the ceiling from
// reservation until terminal cleanup removes it (starting/running/
// stopping all count). startFences holds the dispatch fence of every
// accepted-but-not-yet-settled START (at most one per op id, lifetime =
// the dispatch-to-reservation window): a STOP for that id waits the fence
// out instead of reporting convergence while the START may still reserve
// and launch. No tombstones: a settled fence is removed.
type builderManager struct {
	mu          sync.Mutex
	instances   map[string]*builderInstance
	startFences map[string]chan struct{}
	uid, gid    int
	diag        *boundedBuffer // manager-level operational diagnostics
}

func newBuilderManager(uid, gid int) *builderManager {
	return &builderManager{
		instances:   map[string]*builderInstance{},
		startFences: map[string]chan struct{}{},
		uid:         uid,
		gid:         gid,
		diag:        newBoundedBuffer(builderInstanceDiagMaxBytes),
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
func (m *builderManager) start(opID string) string {
	// Fence registration: under the manager lock — refuse an existing
	// instance or an in-flight START of the same id (the fixed
	// one-instance-per-operation grammar), then register the dispatch
	// fence. The ceiling stays with the reservation below: a fenced START
	// consumes no capacity until it reserves.
	m.mu.Lock()
	if _, exists := m.instances[opID]; exists {
		m.mu.Unlock()
		return builderManagerRespOpExists
	}
	if _, inflight := m.startFences[opID]; inflight {
		m.mu.Unlock()
		return builderManagerRespOpExists
	}
	fence := make(chan struct{})
	m.startFences[opID] = fence
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
func (m *builderManager) launchInstance(inst *builderInstance) bool {
	opID := inst.operationID
	rtDir := opRuntimeDir(opID)
	stDir := opStateDir(opID)

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
	env := []string{
		"HOME=" + builderManagerStateRoot,
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

	inst.mu.Lock()
	if inst.phase != builderInstanceStarting {
		// A concurrent STOP claimed/cancelled this launch.
		inst.mu.Unlock()
		m.convergeFailedStart(inst)
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

	// Persist the leader PID for crash-cleanup identity proofing.
	if err := os.WriteFile(filepath.Join(rtDir, "instance.pid"), []byte(strconv.Itoa(inst.pid)+"\n"), 0600); err != nil {
		m.managerDiagf("START %s: cannot persist instance pid: %v", opID, err)
		m.stopInstance(inst)
		return false
	}

	// One child Wait owner per instance: when the leader exits without a
	// STOP, the instance goes terminal and cleans up (unexpected-exit
	// contract, §18 of the plan).
	go m.awaitInstanceExit(inst)

	// Bounded readiness: leader alive + expected socket entry with the
	// expected owner/mode contract.
	if !m.awaitReadiness(inst) {
		m.managerDiagf("START %s: readiness failed", opID)
		m.stopInstance(inst)
		return false
	}

	// SUCCESS: phase -> running (unless a concurrent STOP already claimed).
	inst.mu.Lock()
	if inst.phase == builderInstanceStarting {
		inst.phase = builderInstanceRunning
	}
	stillStarting := inst.phase == builderInstanceRunning
	stopping := inst.phase == builderInstanceStopping
	inst.mu.Unlock()
	if stopping {
		// A STOP raced during the readiness wait: converge now.
		m.stopInstance(inst)
		return false
	}
	_ = stillStarting
	return true
}

func (m *builderManager) managerDiagf(format string, args ...any) {
	m.diag.Write([]byte(fmt.Sprintf(format, args...) + "\n"))
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

// convergeFailedStart is the START failure convergence: terminate any
// spawned process group, reap it, remove op runtime/state, remove the map
// reservation. No half-admitted instance. The dir removal runs AFTER the
// stop owner settled because a stop claim that raced the launch may have
// removed the (then still absent) dirs before launchInstance created
// them; the failed launch must not leave its own re-creation behind
// (RemoveAll is idempotent).
func (m *builderManager) convergeFailedStart(inst *builderInstance) {
	m.stopInstance(inst)
	m.removeInstanceDirs(inst.operationID)
}

// claimStop claims the single stop right for an instance. Returns true
// exactly once per instance lifecycle.
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
// self-exit: exactly one claimant performs the kill/reap/cleanup and the
// done channel closes exactly once.
func (m *builderManager) stopInstance(inst *builderInstance) {
	if !inst.claimStop() {
		// Another owner (STOP/PURGE/await-exit) already owns convergence;
		// wait for it to finish so callers observe a settled state.
		<-inst.done
		return
	}

	deadline := time.Now().Add(builderStopGracefulTimeout)
	// Cancel a still-starting launch/readiness wait: mark stopping so
	// launchInstance's spawn/readiness checks observe the claim.
	inst.mu.Lock()
	leader := inst.leader
	pid := inst.pid
	inst.mu.Unlock()

	if leader != nil && leader.Process != nil {
		inst.signalProcessGroup(syscall.SIGTERM)
	}
	// Wait bounded for group death, escalating to SIGKILL.
	for time.Now().Before(deadline) {
		if leader == nil || processGroupGone(pid) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if leader != nil && !processGroupGone(pid) {
		inst.signalProcessGroup(syscall.SIGKILL)
	}
	// Reap the leader exactly once (the single Wait owner; a self-exit
	// winner skips this because awaitInstanceExit already Waited).
	if leader != nil {
		_, _ = leader.Process.Wait()
	}

	// Prove descendants are gone before removing directories.
	if pid > 1 && !processGroupGone(pid) {
		m.managerDiagf("STOP %s: process group %d did not fully die; not removing dirs", inst.operationID, pid)
	} else {
		m.removeInstanceDirs(inst.operationID)
	}

	inst.mu.Lock()
	inst.phase = builderInstanceDone
	inst.leader = nil
	inst.pid = 0
	inst.mu.Unlock()
	m.removeReservation(inst)
	close(inst.done)
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

// awaitInstanceExit is the instance's single child Wait owner for
// self-exit. If the leader exits without a STOP, this owner performs the
// terminal cleanup (runtime/state removal, map entry removal) so no
// zombie instance consumes the ceiling.
func (m *builderManager) awaitInstanceExit(inst *builderInstance) {
	inst.mu.Lock()
	leader := inst.leader
	inst.mu.Unlock()
	if leader == nil {
		return
	}
	waitErr := leader.Wait()

	inst.mu.Lock()
	stopping := inst.phase == builderInstanceStopping || inst.stopClaimed
	inst.mu.Unlock()
	if stopping {
		// STOP owns convergence; do not close done or remove dirs here.
		return
	}

	// Unexpected exit: bounded diagnostic tail, then terminal cleanup.
	if tail := inst.diag.tailForDiagnostics(); tail != "" {
		m.managerDiagf("instance %s exited unexpectedly (wait=%v); child output tail:\n%s", inst.operationID, waitErr, tail)
	} else {
		m.managerDiagf("instance %s exited unexpectedly (wait=%v)", inst.operationID, waitErr)
	}
	m.removeInstanceDirs(inst.operationID)
	inst.mu.Lock()
	inst.phase = builderInstanceDone
	inst.leader = nil
	inst.pid = 0
	inst.mu.Unlock()
	m.removeReservation(inst)
	close(inst.done)
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
					// Private contract: owner-only or owner+group; never
					// world-accessible.
					if perm&0o077 == 0 {
						return true
					}
				}
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// removeInstanceDirs removes the exact op runtime and state directories.
// Paths derive from the canonical op id (validated by isOperationID), never
// from raw input; remove the exact tree, never an arbitrary path.
func (m *builderManager) removeInstanceDirs(opID string) {
	if !isOperationID(opID) {
		m.managerDiagf("refusing to remove instance dirs for noncanonical op id")
		return
	}
	_ = os.RemoveAll(opRuntimeDir(opID))
	_ = os.RemoveAll(opStateDir(opID))
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
	// Owner check.
	if stat, err := os.Stat(filepath.Join("/proc", strconv.Itoa(pid))); err == nil {
		if uint32(stat.Sys().(*syscall.Stat_t).Uid) != uint32(uid) {
			return false
		}
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

// startupPurge performs startup PURGE semantics: terminate every
// manager-owned op process group found live in the instance map, remove
// op-private runtime/state, and scan crash residue left on disk. No
// adoption into live entries; no reconciliation. For stale disk-only
// state: validate the op directory name with isOperationID, validate the
// persisted process identity before signaling, remove dead/verified-owned
// residue, and FAIL CLOSED rather than kill a process whose identity
// cannot be proven.
func (m *builderManager) startupPurge() error {
	// Live instances (should be none at startup, but converge if so).
	m.mu.Lock()
	snapshot := make([]*builderInstance, 0, len(m.instances))
	for _, inst := range m.instances {
		snapshot = append(snapshot, inst)
	}
	m.mu.Unlock()
	for _, inst := range snapshot {
		if inst.claimStop() {
			go m.stopInstance(inst)
			<-inst.done
		} else {
			<-inst.done
		}
	}

	// Crash residue on disk.
	if err := m.purgeDiskResidue(builderRuntimeRoot); err != nil {
		return err
	}
	if err := m.purgeDiskResidue(builderStateRoot); err != nil {
		return err
	}
	return nil
}

// purgeDiskResidue scans <root>/ops/<op_id> residue under both fixed roots.
// Only canonical op ids are considered (never an arbitrary path obtained
// from input).
func (m *builderManager) purgeDiskResidue(root string) error {
	opsDir := filepath.Join(root, "ops")
	entries, err := os.ReadDir(opsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		if !isOperationID(name) {
			// Not product-owned state; do not remove an arbitrary
			// path. Bounded diagnostic and continue.
			m.managerDiagf("startup purge: skipping noncanonical ops entry %q", name)
			continue
		}
		opDir := filepath.Join(opsDir, name)
		// A live verified-owned process must NOT be killed by disk purge;
		// fail closed with a bounded diagnostic.
		if pid := readInstancePid(opDir); pid > 0 {
			if !builderStalePidIdentity(pid, name, m.uid) {
				if processAlive(pid) {
					return fmt.Errorf("startup purge: unproven live process %d for op %s; refusing", pid, name)
				}
			}
			// Dead or proven-owned-dead: residue removal below.
			if processAlive(pid) && builderStalePidIdentity(pid, name, m.uid) {
				return fmt.Errorf("startup purge: verified-owned live process %d for op %s; refusing startup", pid, name)
			}
		}
		_ = os.RemoveAll(opDir)
	}
	return nil
}

// readInstancePid reads and parses instance.pid (0 when absent/invalid).
func readInstancePid(opDir string) int {
	raw, err := os.ReadFile(filepath.Join(opDir, "instance.pid"))
	if err != nil {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		return 0
	}
	return pid
}

// processAlive reports whether pid names a live process.
func processAlive(pid int) bool {
	if pid <= 1 {
		return false
	}
	return syscall.Kill(pid, 0) == nil
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
		go m.handleConnection(conn, stderr)
	}
}

// handleConnection reads exactly one bounded request line, authenticates
// the peer BEFORE dispatch, executes, and writes exactly one response
// line from the fixed vocabulary.
func (m *builderManager) handleConnection(conn *net.UnixConn, stderr io.Writer) {
	defer conn.Close()

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
		response = m.start(req.OperationID)
	case builderManagerCmdStop:
		response = m.stop(req.OperationID)
	case builderManagerCmdPurge:
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
func (m *builderManager) stop(opID string) string {
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
			// performs the kill/reap/cleanup; the others wait for done.
			m.stopInstance(inst)
			return builderManagerRespOK
		}
		if fence == nil {
			return builderManagerRespOKAbsent
		}
		<-fence
		// The START settled: re-check — it may have reserved the instance
		// this STOP must converge.
	}
}

// purge is the runtime PURGE protocol operation: snapshot/claim all
// manager-owned instances, stop them with the same STOP owner, remove
// op-private state, return OK only after convergence.
func (m *builderManager) purge() string {
	m.mu.Lock()
	snapshot := make([]*builderInstance, 0, len(m.instances))
	for _, inst := range m.instances {
		snapshot = append(snapshot, inst)
	}
	m.mu.Unlock()
	for _, inst := range snapshot {
		m.stopInstance(inst)
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
