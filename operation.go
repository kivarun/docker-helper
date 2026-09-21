package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os/exec"
	"sort"
	"sync"
	"syscall"
	"time"
)

type operationState string

const (
	operationRunning   operationState = "running"
	operationSucceeded operationState = "succeeded"
	operationFailed    operationState = "failed"
)

const resultCancelled = "cancelled"

// operationKindRun and operationKindBuild are the canonical Operation kind
// terms. They identify the operation kind in the public Operation model, in
// audit events, and in admission decisions.
const (
	operationKindRun   = "run"
	operationKindBuild = "build"
)

// Release-2.2 fixed security ceilings. These are hard,
// non-configurable daemon resource ceilings measured at closure. They are
// not Principal/Launcher quotas and have no config, CLI,
// or API surface.
//
// Concurrent execution capacity counts preparation and running execution of
// every admitted Operation AND every synchronous Session-token Docker
// execution (pull, registry-login), all through the one shared accounting
// core below. Operation-backed capacity is released exactly once when the
// Operation reaches a terminal state (retained metadata/logs never keep
// capacity); synchronous capacity is released exactly once when the request
// handler returns.
//
//   - 4 concurrent executions per Session: two times the maximum
//     per-Session concurrency exercised by the existing UAT (2), sized for
//     realistic agent parallelism.
//   - 8 concurrent executions globally: keeps at least half of the global
//     capacity available to other Sessions when one Session is saturated.
//   - 2 concurrent builds globally: worst-case hostile staging occupancy is
//     2 × 128 MiB (the per-build staging ceiling) = 256 MiB, which is 42%
//     of the /run tmpfs of the smallest supported host (3 GiB RAM, ~614 MB
//     /run); three or more concurrent maximal builds would exceed half of
//     that tmpfs.
const (
	maxConcurrentOperationsPerSession = 4
	maxConcurrentOperationsGlobal     = 8
	maxConcurrentBuildsGlobal         = 2
)

// defaultTerminationTimeout is the graceful termination budget applied
// when the caller does not supply a context deadline. Used by both
// explicit cancel (cancel) and daemon shutdown (terminateForShutdown).
const defaultTerminationTimeout = 5 * time.Second

// defaultForceCleanupTimeout is the shared force-cleanup budget for
// daemon-side container cleanup and CLI process kill after the graceful
// phase expires. Both owner and followers share this budget.
const defaultForceCleanupTimeout = 3 * time.Second

type terminationReason uint8

const (
	terminationNone terminationReason = iota
	terminationShutdown
	terminationCancelled
)

// ErrOperationNotFound is returned by operationSupervisor.cancel when no
// operation with the given ID is registered.
var ErrOperationNotFound = errors.New("operation not found")

// ErrOperationAlreadyTerminal is returned by operationSupervisor.cancel when
// the operation has already reached a terminal state.
var ErrOperationAlreadyTerminal = errors.New("operation already terminal")

type operation struct {
	mu          sync.Mutex
	ID          string         `json:"operation_id"`
	SessionID   string         `json:"session_id"`
	LauncherID  string         `json:"launcher_id,omitempty"`
	Kind        string         `json:"kind"`
	State       operationState `json:"status"`
	CreatedAt   time.Time      `json:"created_at"`
	StartedAt   *time.Time     `json:"started_at,omitempty"`
	CompletedAt *time.Time     `json:"completed_at,omitempty"`
	Duration    *string        `json:"duration,omitempty"`
	ExitCode    *int           `json:"exit_code,omitempty"`
	ResultCode  *string        `json:"result_code,omitempty"`
	Image       string         `json:"image,omitempty"`
	Context     string         `json:"context,omitempty"`
	Dockerfile  string         `json:"dockerfile,omitempty"`
	LogBuffer   *boundedBuffer `json:"-"`
	// currentCmd is the Operation's current child-process slot: the one
	// child process the Operation owns right now, or nil when no child is
	// active (not yet started, already waited, or between sequential
	// stages). A sequential stage installs the slot under op.mu via
	// startOperationStage and the stage's single Wait owner clears it via
	// waitCurrentStage. No exited *exec.Cmd is ever retained in the slot.
	currentCmd *exec.Cmd
	done       chan struct{}
	doneOnce   sync.Once // ensures op.done is closed exactly once
	// terminationRequested is the permanent termination latch. Set once by
	// terminateForShutdown/cancel under op.mu; it never becomes false
	// again. Meaning: this Operation has been claimed for termination and
	// NO new child process stage may start — regardless of whether a child
	// has not started yet, is currently running, has just exited, or the
	// Operation is between stages.
	terminationRequested bool
	reason               terminationReason
	forceOwned           bool          // true when force cleanup has been claimed for this operation
	forceDone            chan struct{} // closed when shared force-cleanup phase completes
	forceDeadline        time.Time     // absolute deadline shared by owner and all followers
	// cidfile is the path to the Docker --cidfile for run operations.
	// The helper determines this path before cmd.Start(); Docker CLI
	// publishes the container ID into the file after the daemon creates
	// the container. During force shutdown, the container ID is read
	// from this file to perform daemon-side cleanup before killing the
	// docker run CLI process. The file is removed after the operation
	// completes regardless of outcome.
	cidfile string
	// pinnedMounts are the inode-pinned mount destinations for system-mode
	// run operations. They are cleaned up after cmd.Wait completes.
	pinnedMounts []*pinnedMount
	// workloadMAC is the prepared workload MAC state of a system-mode run
	// operation. It is bounded runtime cleanup state only: it
	// carries the Docker materialization facts of the already-accepted
	// exposure plan, never policy authority.
	workloadMAC *preparedWorkloadMAC
	// stagedCtx is the staged build context for build operations.
	// It is cleaned up after the operation completes or fails.
	stagedCtx *stagedBuildContext
	// macLeaseRelease releases the session-use lease held by this operation.
	// nil when no lease was acquired (no MAC backend).
	macLeaseRelease func()
	// capacityRelease releases the fixed Release-2.2 capacity slot of this
	// operation. It is set at final admission (transferred from the
	// pre-preparation reservation) and invoked exactly once when the
	// operation reaches a terminal state; pre-admission failure paths release
	// through the same reservation before the slot ever transfers.
	capacityRelease func()
	// audit metadata for finish event, set by operation-specific factory.
	auditCommandArgCount    *int
	auditMounts             []auditMount
	auditEnvKeys            []string
	auditBuildArgKeys       []string
	auditShmSize            string
	auditTrustedCAInjected  bool
	auditHelperSocket       bool
	auditWorkloadMACBackend string
	auditPrincipalName      string
	auditLauncherName       string
}

func newBuildOperation(sessionID, image, ctxPath, dockerfile string, bufSize int64, principalName, launcherID, launcherName string) *operation {
	opID := generateOperationID()
	now := time.Now()
	return &operation{
		ID:                 opID,
		SessionID:          sessionID,
		Kind:               operationKindBuild,
		State:              operationRunning,
		CreatedAt:          now,
		Image:              image,
		Context:            ctxPath,
		Dockerfile:         dockerfile,
		LogBuffer:          newBoundedBuffer(bufSize),
		done:               make(chan struct{}),
		LauncherID:         launcherID,
		auditPrincipalName: principalName,
		auditLauncherName:  launcherName,
	}
}

func newRunOperation(sessionID, image string, bufSize int64, principalName, launcherID, launcherName string) *operation {
	opID := generateOperationID()
	now := time.Now()
	return &operation{
		ID:                 opID,
		SessionID:          sessionID,
		Kind:               operationKindRun,
		State:              operationRunning,
		CreatedAt:          now,
		Image:              image,
		LogBuffer:          newBoundedBuffer(bufSize),
		done:               make(chan struct{}),
		LauncherID:         launcherID,
		auditPrincipalName: principalName,
		auditLauncherName:  launcherName,
	}
}

// The canonical issued operation ID shape: the production prefix plus
// exactly operationIDHexLength lowercase hex characters (16 random bytes).
// Durable ownership proofs validate against this exact shape.
const (
	operationIDPrefix    = "op_"
	operationIDHexLength = 32
)

func generateOperationID() string {
	b := make([]byte, operationIDHexLength/2)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("cannot generate operation ID: %v", err))
	}
	return operationIDPrefix + hex.EncodeToString(b)
}

// isOperationIDSafe checks that the operation ID cannot be used for path traversal.
func isOperationIDSafe(id string) bool {
	if id == "" {
		return false
	}
	if len(id) > 0 && (id[0] == '.' || id[0] == '/') {
		return false
	}
	for _, r := range id {
		if r == '/' || r == '\\' {
			return false
		}
	}
	return true
}

type operationSupervisor struct {
	mu       sync.RWMutex
	ops      map[string]*operation
	shutting bool
	// quiesced holds Launcher IDs for which new operation admission is
	// currently refused. Checked Launcher/Principal deletion sets it as the
	// operation-admission closing point: once set, no new Operation may be
	// admitted for that Launcher, while Operations admitted before it remain
	// visible to checked cleanup. Quiesce is Operation lifecycle policy: it
	// is consulted by reserve/admitReserved, never by the shared capacity
	// accounting, and never by the synchronous execution surfaces.
	quiesced map[string]bool
	// Release-2.2 fixed capacity accounting. The ceilings are the
	// documented security constants; only the counts live here. A capacity
	// slot is reserved before any expensive preparation (Operations) or
	// before any Docker process starts (synchronous surfaces), transfers to
	// the admitted Operation at final admission, and is released exactly
	// once when the Operation reaches a terminal state or when the
	// synchronous request handler returns — never when retained
	// metadata/logs are pruned.
	maxPerSession    int
	maxGlobal        int
	maxGlobalBuilds  int
	sessionRunning   map[string]int
	globalRunning    int
	globalBuildCount int
}

func newOperationSupervisor() *operationSupervisor {
	return &operationSupervisor{
		ops:             make(map[string]*operation),
		maxPerSession:   maxConcurrentOperationsPerSession,
		maxGlobal:       maxConcurrentOperationsGlobal,
		maxGlobalBuilds: maxConcurrentBuildsGlobal,
		sessionRunning:  make(map[string]int),
	}
}

// admissionDecision is the narrow result of operation admission. It lets HTTP
// distinguish the refusal causes: daemon shutdown (a global condition),
// per-Launcher quiesce (the runtime companion of a disabled Launcher or an
// in-progress checked deletion), and exhausted fixed Release-2.2 capacity
// (a bounded resource refusal that names no capacity topology). A quiesced
// Launcher must never be reported as "daemon is shutting down", and neither
// must capacity exhaustion.
type admissionDecision uint8

const (
	// admissionAccepted admits the operation and registers it.
	admissionAccepted admissionDecision = iota
	// admissionRefusedShutdown refuses admission because the daemon is
	// shutting down.
	admissionRefusedShutdown
	// admissionRefusedQuiesced refuses admission because Operation admission
	// is closed for the operation's Launcher.
	admissionRefusedQuiesced
	// admissionRefusedCapacity refuses admission because the fixed
	// Release-2.2 concurrent Operation capacity is exhausted (Session scope
	// or global scope; the refusal is identical for both).
	admissionRefusedCapacity
)

// capacityReservation is the narrow internal capacity lease of the fixed
// Release-2.2 admission ceilings. It is acquired before any expensive
// preparation (Operations) or before any Docker process starts (synchronous
// surfaces), consumed by admitReserved into the registered Operation's
// capacity, and released exactly once on every other path. It is not an
// Operation, is never registered or exposed, and never waits: at a security
// ceiling the request is refused immediately and the caller decides whether
// to retry.
type capacityReservation struct {
	release func()
}

// Release returns the reserved capacity exactly once. It is safe to call
// repeatedly and after the reservation was converted into an admitted
// Operation (post-conversion calls are no-ops). The nil reservation is a
// no-op, so callers that skip reservation (tests without a supervisor) can
// release unconditionally.
func (r *capacityReservation) Release() {
	if r == nil {
		return
	}
	if r.release != nil {
		r.release()
		r.release = nil
	}
}

// reserveCapacityLocked is the pure capacity-accounting core of the fixed
// Release-2.2 ceilings, called under the supervisor lock. It checks the
// Session ceiling, the global ceiling and the build sub-ceiling, then
// reserves one capacity slot for the Session. The build flag is the one
// dimension the accounting distinguishes: only a build consumes the narrow
// global build sub-ceiling; every other caller is accounted against the
// Session and global ceilings alone. It returns nil when a ceiling is
// exhausted; the caller owns the refusal in its own critical section.
func (s *operationSupervisor) reserveCapacityLocked(sessionID string, build bool) *capacityReservation {
	if s.globalRunning >= s.maxGlobal {
		return nil
	}
	if s.sessionRunning[sessionID] >= s.maxPerSession {
		return nil
	}
	if build && s.globalBuildCount >= s.maxGlobalBuilds {
		return nil
	}

	s.globalRunning++
	s.sessionRunning[sessionID]++
	if build {
		s.globalBuildCount++
	}

	released := false
	release := func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if released {
			return
		}
		released = true
		if s.globalRunning > 0 {
			s.globalRunning--
		}
		if s.sessionRunning[sessionID] > 0 {
			s.sessionRunning[sessionID]--
		}
		if s.sessionRunning[sessionID] == 0 {
			delete(s.sessionRunning, sessionID)
		}
		if build && s.globalBuildCount > 0 {
			s.globalBuildCount--
		}
	}
	return &capacityReservation{release: release}
}

// reserveCapacity atomically reserves one capacity slot on behalf of the
// Session under the fixed Release-2.2 ceilings. It is the shared
// resource-accounting owner of every Session-token Docker execution surface:
// Operation-backed run/build reach it through reserve (which adds the
// Operation lifecycle gates), and the synchronous pull/registry-login
// surfaces call it directly before their Docker process is started — they
// consume the SAME Session/global counters and participate in the SAME
// common ceilings, but never register an Operation. Capacity is pure
// resource accounting: no lifecycle gate (daemon shutdown, Launcher quiesce)
// is consulted here; that policy stays with its Operation-admission owners.
// The reservation is released exactly once when the synchronous handler
// returns — completion, Docker failure, and every pre-exec failure path.
func (s *operationSupervisor) reserveCapacity(sessionID string, build bool) (*capacityReservation, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	res := s.reserveCapacityLocked(sessionID, build)
	return res, res != nil
}

// reserve atomically checks the Operation lifecycle gates (daemon shutdown,
// Launcher quiesce) and the fixed Release-2.2 capacity ceilings (Session
// scope, global scope, and the build sub-ceiling), then reserves one
// capacity slot for the given operation kind on behalf of the Session. The
// check-and-reserve is a single critical section under the supervisor lock,
// so concurrent reserves can never oversubscribe.
//
// The reservation must be released exactly once if the operation does not
// reach admitReserved; the callers' failure paths own that release. Capacity
// is never re-checked or re-reserved at final admission.
func (s *operationSupervisor) reserve(sessionID, launcherID, kind string) (*capacityReservation, admissionDecision) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.shutting {
		return nil, admissionRefusedShutdown
	}
	if s.quiesced[launcherID] {
		return nil, admissionRefusedQuiesced
	}
	res := s.reserveCapacityLocked(sessionID, kind == operationKindBuild)
	if res == nil {
		return nil, admissionRefusedCapacity
	}
	return res, admissionAccepted
}

// admitReserved re-checks the lifecycle closure at final admission and
// registers the prepared Operation. A reservation obtained before a quiesce
// or shutdown is NOT an admitted Operation: shutdown or quiesce reached in
// between still refuses, and the caller cleans preparation and releases the
// reservation through its failure path.
//
// The reserved capacity is never re-checked or re-reserved here: it transfers
// to the registered Operation and is released exactly once when the Operation
// reaches a terminal state.
func (s *operationSupervisor) admitReserved(op *operation, reservation *capacityReservation) admissionDecision {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.shutting {
		return admissionRefusedShutdown
	}
	if s.quiesced[op.LauncherID] {
		return admissionRefusedQuiesced
	}
	s.ops[op.ID] = op
	if reservation != nil && reservation.release != nil {
		op.capacityRelease = reservation.release
		reservation.release = nil
	}
	return admissionAccepted
}

func (s *operationSupervisor) lookup(id string) *operation {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ops[id]
}

func (s *operationSupervisor) pruneCompleted(retentionTTL time.Duration, maxCompleted int) {
	// Step 1: Copy operation pointers under short RLock.
	s.mu.RLock()
	ops := make([]*operation, 0, len(s.ops))
	for _, op := range s.ops {
		ops = append(ops, op)
	}
	s.mu.RUnlock()

	// Step 2: Snapshot each operation's state under op.mu once.
	type completedOp struct {
		op          *operation
		completedAt time.Time
	}
	var completed []completedOp
	now := time.Now()
	for _, op := range ops {
		op.mu.Lock()
		if op.State != operationRunning && op.CompletedAt != nil {
			completed = append(completed, completedOp{op: op, completedAt: *op.CompletedAt})
		}
		op.mu.Unlock()
	}

	// Step 3: Determine which operations to remove (outside all locks).
	type removeOp struct {
		id string
		op *operation
	}
	var toRemove []removeOp

	// Separate TTL-expired from non-expired.
	var nonExpired []completedOp
	for _, c := range completed {
		if now.Sub(c.completedAt) > retentionTTL {
			toRemove = append(toRemove, removeOp{id: c.op.ID, op: c.op})
		} else {
			nonExpired = append(nonExpired, c)
		}
	}

	// Apply cap to non-expired: keep maxCompleted newest, remove oldest.
	if len(nonExpired) > maxCompleted {
		sort.Slice(nonExpired, func(i, j int) bool {
			return nonExpired[i].completedAt.Before(nonExpired[j].completedAt)
		})
		for _, c := range nonExpired[:len(nonExpired)-maxCompleted] {
			toRemove = append(toRemove, removeOp{id: c.op.ID, op: c.op})
		}
	}

	// Step 4: Remove under single Lock with TOCTOU check.
	if len(toRemove) > 0 {
		s.mu.Lock()
		for _, rem := range toRemove {
			if s.ops[rem.id] == rem.op {
				delete(s.ops, rem.id)
			}
		}
		s.mu.Unlock()
	}
}

func (s *operationSupervisor) beginShutdown() {
	s.mu.Lock()
	s.shutting = true
	s.mu.Unlock()
}

// terminateForShutdown sends SIGTERM to all running operations, waits for them
// to complete until the shared deadline, then force-kills any that remain.
// The killContainer callback (may be nil) is called for run operations
// that have a cidfile, to perform daemon-side container cleanup before
// force-killing the CLI process.
//
// For daemon shutdown, the caller's context deadline is the authoritative
// absolute deadline. All operations share this deadline. Force cleanup
// runs concurrently for all remaining operations.
func (s *operationSupervisor) terminateForShutdown(ctx context.Context, killContainer func(context.Context, string)) {
	s.terminateOperations(ctx, nil, killContainer, terminationShutdown, true)
}

// cancel cancels a single operation by ID.
// Returns nil if the operation was found and cancellation initiated.
// Returns ErrOperationNotFound if the operation does not exist.
// Returns ErrOperationAlreadyTerminal if the operation is already completed.
func (s *operationSupervisor) cancel(id string, killContainer func(context.Context, string)) error {
	s.mu.RLock()
	op, ok := s.ops[id]
	s.mu.RUnlock()
	if !ok {
		return ErrOperationNotFound
	}

	op.mu.Lock()
	if op.CompletedAt != nil {
		op.mu.Unlock()
		return ErrOperationAlreadyTerminal
	}
	op.mu.Unlock()

	s.terminateOperations(context.Background(), op, killContainer, terminationCancelled, false)
	return nil
}

// terminateOperations is the shared termination primitive used by both
// terminateForShutdown (shutdown) and cancel (explicit cancel).
// If targetOp is nil, all operations are terminated (shutdown).
// If targetOp is non-nil, only that operation is terminated (cancel).
// reason distinguishes shutdown from explicit cancel for result semantics.
// isShutdown controls the deadline model:
//
//	shutdown: caller's ctx deadline is the absolute daemon shutdown deadline.
//	  graceful SIGTERM starts immediately. Force cleanup runs concurrently
//	  for all remaining operations under the same deadline.
//	cancel: per-operation bounded cleanup with a fresh force-cleanup budget.
func (s *operationSupervisor) terminateOperations(ctx context.Context, targetOp *operation, killContainer func(context.Context, string), reason terminationReason, isShutdown bool) {
	// Normalize context: if the caller did not supply a deadline, create
	// a bounded termination context so that all wait paths are guaranteed
	// to be bounded. This prevents unbounded waits when cancel
	// passes context.Background().
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultTerminationTimeout)
		defer cancel()
	}

	s.mu.RLock()
	var ops []*operation
	if targetOp != nil {
		ops = []*operation{targetOp}
	} else {
		for _, op := range s.ops {
			ops = append(ops, op)
		}
	}
	s.mu.RUnlock()

	// Determine force deadline and graceful wait end.
	// For shutdown: the root deadline is authoritative.
	// Reserve defaultForceCleanupTimeout at the tail for force cleanup.
	var forceDeadline time.Time
	var forceStart time.Time
	if isShutdown {
		dl, _ := ctx.Deadline()
		forceDeadline = dl
		forceStart = dl.Add(-defaultForceCleanupTimeout)
		// If remaining budget is shorter than force cleanup reserve,
		// begin force cleanup immediately.
		if time.Now().After(forceStart) {
			forceStart = time.Time{} // zero means "skip graceful"
		}
	}

	// Phase 0+1: For each operation, atomically decide its fate under op.mu.
	// Latch the permanent termination request (no later stage may ever
	// start), and if a child process is active right now, signal it.
	// Termination admission and child signaling happen in the same critical
	// section, so there is no intermediate state: either the child receives
	// the signal, or the Operation is latched before any later stage could
	// have been admitted.
	var terminated []*operation
	for _, op := range ops {
		op.mu.Lock()
		if op.reason == terminationNone {
			op.reason = reason
		}
		op.terminationRequested = true
		if op.currentCmd != nil && op.currentCmd.Process != nil {
			op.currentCmd.Process.Signal(syscall.SIGTERM)
		} else {
			// No active child: the operation is either pre-start (its
			// handler owns the terminal transition on the refused start)
			// or between sequential stages (its stage driver completes
			// it). Both observe the latch and never admit another child.
			terminated = append(terminated, op)
		}
		op.mu.Unlock()
	}

	terminatedSet := make(map[*operation]struct{}, len(terminated))
	for _, op := range terminated {
		terminatedSet[op] = struct{}{}
	}

	// Phase 2: Wait for each operation to complete gracefully.
	// For shutdown, wait only until forceStart (may be zero = skip graceful).
	// For cancel, wait until ctx deadline.
	var completed []*operation

	if isShutdown {
		if !forceStart.IsZero() {
			// Graceful phase: use a single timer for all operations.
			graceTimer := time.NewTimer(time.Until(forceStart))
			defer graceTimer.Stop()
			for _, op := range ops {
				if _, ok := terminatedSet[op]; ok {
					continue
				}
				select {
				case <-op.done:
					completed = append(completed, op)
				case <-graceTimer.C:
					// forceStart reached; proceed to force cleanup below.
					goto forceCleanup
				}
			}
		}
		// forceStart is zero or timer expired: skip to force cleanup.
	} else {
		// Cancel: wait until each op completes or ctx deadline.
		for _, op := range ops {
			if _, ok := terminatedSet[op]; ok {
				continue
			}
			select {
			case <-op.done:
				completed = append(completed, op)
			case <-ctx.Done():
				// Deadline exceeded: legacy sequential force cleanup.
				s.forceCleanupSequential(op, killContainer)
			}
		}
	}

forceCleanup:

	// Phase 3: Force cleanup for remaining operations.
	// For shutdown: concurrent force cleanup under the shared deadline.
	// For cancel: already handled sequentially above.
	if isShutdown {
		completedSet := make(map[*operation]struct{}, len(completed))
		for _, c := range completed {
			completedSet[c] = struct{}{}
		}

		var wg sync.WaitGroup
		for _, op := range ops {
			if _, ok := terminatedSet[op]; ok {
				continue
			}
			if _, ok := completedSet[op]; ok {
				continue
			}
			wg.Add(1)
			go func(op *operation) {
				defer wg.Done()
				forceCleanupOperation(op, killContainer, forceDeadline)
			}(op)
		}
		wg.Wait()
	}
}

// forceCleanupSequential performs sequential force cleanup for a single
// operation using a per-operation force-cleanup deadline. Used by cancel mode.
func (s *operationSupervisor) forceCleanupSequential(op *operation, killContainer func(context.Context, string)) {
	op.mu.Lock()
	if op.forceOwned {
		forceDone := op.forceDone
		forceDeadline := op.forceDeadline
		op.mu.Unlock()
		remaining := time.Until(forceDeadline)
		if remaining > 0 {
			timer := time.NewTimer(remaining)
			select {
			case <-forceDone:
				timer.Stop()
			case <-timer.C:
			}
		}
		return
	}
	if op.CompletedAt != nil {
		op.mu.Unlock()
		return
	}
	op.forceOwned = true
	op.forceDone = make(chan struct{})
	op.forceDeadline = time.Now().Add(defaultForceCleanupTimeout)
	forceDeadline := op.forceDeadline
	forceDone := op.forceDone
	op.mu.Unlock()

	forceCtx, forceCancel := context.WithDeadline(context.Background(), forceDeadline)
	if op.cidfile != "" {
		containerID := waitForContainerID(forceCtx, op)
		if containerID != "" && killContainer != nil {
			killContainer(forceCtx, containerID)
		}
	}
	op.mu.Lock()
	if op.currentCmd != nil && op.currentCmd.Process != nil {
		op.currentCmd.Process.Kill()
	}
	op.mu.Unlock()
	forceCancel()
	close(forceDone)
}

// forceCleanupOperation performs the force-cleanup phase for a single
// operation under a shared absolute deadline. Used by shutdown mode.
// Only one goroutine performs the actual cleanup (single-owner guard).
// Followers wait until the shared deadline.
func forceCleanupOperation(op *operation, killContainer func(context.Context, string), forceDeadline time.Time) {
	op.mu.Lock()
	if op.forceOwned {
		// Another termination path already claimed force cleanup.
		// Wait for the shared force phase to complete, bounded
		// by the remaining time until the shared deadline.
		forceDone := op.forceDone
		op.mu.Unlock()
		remaining := time.Until(forceDeadline)
		if remaining > 0 {
			timer := time.NewTimer(remaining)
			select {
			case <-forceDone:
				timer.Stop()
			case <-timer.C:
			}
		}
		return
	}
	if op.CompletedAt != nil {
		op.mu.Unlock()
		return
	}
	op.forceOwned = true
	op.forceDone = make(chan struct{})
	op.forceDeadline = forceDeadline
	op.mu.Unlock()
	forceCtx, forceCancel := context.WithDeadline(context.Background(), forceDeadline)
	if op.cidfile != "" {
		containerID := waitForContainerID(forceCtx, op)
		if containerID != "" && killContainer != nil {
			killContainer(forceCtx, containerID)
		}
	}
	op.mu.Lock()
	if op.currentCmd != nil && op.currentCmd.Process != nil {
		op.currentCmd.Process.Kill()
	}
	op.mu.Unlock()
	forceCancel()
	close(op.forceDone)
}

// boundedBuffer is a thread-safe rolling byte buffer that preserves the newest
// bytes when the configured maximum size is exceeded.
type boundedBuffer struct {
	mu       sync.RWMutex
	buf      []byte
	maxSize  int64
	offset   int64 // start of retained range
	totalLen int64 // total bytes ever written
}

func newBoundedBuffer(maxSize int64) *boundedBuffer {
	return &boundedBuffer{
		maxSize: maxSize,
	}
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	n := len(p)
	b.totalLen += int64(n)
	b.buf = append(b.buf, p...)

	// Trim oldest data if retained range exceeds maxSize.
	retainedLen := int64(len(b.buf))
	if retainedLen > b.maxSize {
		trim := retainedLen - b.maxSize
		b.offset += trim
		b.buf = b.buf[trim:]
	}

	return n, nil
}

func (b *boundedBuffer) ReadFrom(r io.Reader) (int64, error) {
	buf := make([]byte, 32*1024)
	var total int64
	for {
		n, err := r.Read(buf)
		if n > 0 {
			b.Write(buf[:n])
			total += int64(n)
		}
		if err != nil {
			if err == io.EOF {
				return total, nil
			}
			return total, err
		}
	}
}

// Release-2.2 fixed security ceiling for the operation-log response:
// one HTTP logs response carries at most this many RAW retained log bytes.
// The value is independent of the configurable operation_log_max_bytes
// retention: measured worst-case JSON encoding expands adversarial bytes 6×
// (control characters and invalid UTF-8 escape to six-character sequences), so
// a chunked response stays under ~1.6 MiB encoded regardless of retention.
const logResponseChunkBytes = 262144

// rangeUnbounded is the Range maxBytes value for callers whose contract is the
// complete retained range (the synchronous pull response and registry-login
// classification capture).
const rangeUnbounded = math.MaxInt64

// Range returns the retained log bytes from the requested offset, bounded to
// maxBytes raw bytes. It is the fixed Release-2.2 response-chunk
// mechanism of the logs surface: one HTTP logs response carries at most
// logResponseChunkBytes raw bytes regardless of the configured retention, so
// a request can never materialize the whole retained buffer.
//
// next_offset identifies the byte immediately AFTER the bytes actually
// returned — never the total length when bytes in between were not returned.
// truncated retains its established meaning: the requested offset predates
// the retained data. In that case the read starts at the oldest retained
// byte, returns at most one chunk, and the caller continues from
// next_offset; no retained bytes are silently skipped.
//
// Callers whose contract is the complete retained range (the synchronous pull
// response and the registry-login classification capture) pass
// rangeUnbounded. A maxBytes of zero or less returns no bytes with no
// progress; the bounded drain helpers terminate on exactly that observation.
func (b *boundedBuffer) Range(offset int64, maxBytes int64) (data []byte, nextOffset int64, truncated bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if offset >= b.totalLen {
		return nil, b.totalLen, false
	}

	// retained range is [b.offset, b.totalLen).
	// data in b.buf corresponds to that range.
	start := offset
	if start < b.offset {
		// offset is older than retained data.
		start = b.offset
		truncated = true
	}

	idx := int(start - b.offset)
	if idx > len(b.buf) {
		idx = len(b.buf)
	}
	available := int64(len(b.buf) - idx)
	n := available
	if maxBytes < available {
		n = maxBytes
	}
	if n < 0 {
		n = 0
	}
	data = make([]byte, n)
	copy(data, b.buf[idx:int(idx)+int(n)])
	return data, start + n, truncated
}

// releaseCapacity releases the operation's fixed Release-2.2 capacity slot
// exactly once. The reservation release closure is itself once-guarded, so
// every terminal and failure path can invoke this unconditionally.
func (op *operation) releaseCapacity() {
	if op.capacityRelease != nil {
		op.capacityRelease()
		op.capacityRelease = nil
	}
}

func (op *operation) succeed(duration *string) bool {
	op.mu.Lock()
	if op.CompletedAt != nil {
		op.mu.Unlock()
		return false
	}
	now := time.Now()
	op.State = operationSucceeded
	op.CompletedAt = &now
	op.Duration = duration
	if op.ResultCode == nil {
		rc := "succeeded"
		op.ResultCode = &rc
	}
	// Capacity ends at the terminal state, not when retained metadata/logs
	// are later pruned. Release inside the winning transition so a lost race
	// (another path already completed the operation) releases nothing.
	op.releaseCapacity()
	op.mu.Unlock()

	op.writeFinishAudit(nil, duration)
	op.doneOnce.Do(func() { close(op.done) })
	return true
}

func (op *operation) fail(resultCode, message string, exitCode *int, duration ...*string) bool {
	op.mu.Lock()
	if op.CompletedAt != nil {
		op.mu.Unlock()
		return false
	}
	now := time.Now()
	op.State = operationFailed
	op.CompletedAt = &now
	op.ExitCode = exitCode
	if op.ResultCode == nil {
		op.ResultCode = &resultCode
	}
	if len(duration) > 0 && duration[0] != nil {
		op.Duration = duration[0]
	}
	// Capacity ends at the terminal state (see succeed).
	op.releaseCapacity()
	op.mu.Unlock()

	var dur *string
	if len(duration) > 0 {
		dur = duration[0]
	}
	op.writeFinishAudit(exitCode, dur)
	op.doneOnce.Do(func() { close(op.done) })
	return true
}

// writeFinishAudit writes the <kind>.finish audit record for the operation.
func (op *operation) writeFinishAudit(exitCode *int, duration *string) {
	dur := ""
	if duration != nil {
		dur = *duration
	}
	writeRequestContextAudit(context.Background(), auditRecord{
		Event:              op.Kind + ".finish",
		SessionID:          op.SessionID,
		OperationID:        op.ID,
		Image:              op.Image,
		Context:            op.Context,
		Dockerfile:         op.Dockerfile,
		CommandArgCount:    op.auditCommandArgCount,
		Mounts:             op.auditMounts,
		EnvKeys:            op.auditEnvKeys,
		BuildArgKeys:       op.auditBuildArgKeys,
		ShmSize:            op.auditShmSize,
		TrustedCAInjected:  op.auditTrustedCAInjected,
		HelperSocket:       op.auditHelperSocket,
		WorkloadMACBackend: op.auditWorkloadMACBackend,
		PrincipalName:      op.auditPrincipalName,
		LauncherID:         op.LauncherID,
		LauncherName:       op.auditLauncherName,
		Result:             *op.ResultCode,
		ExitCode:           exitCode,
		Duration:           dur,
	})
}

func (op *operation) Wait() {
	<-op.done
}

// operationStartResult is returned by startOperationStage.
type operationStartResult struct {
	Terminated bool  // true if the operation's termination latch was already set
	Err        error // error from cmd.Start(), nil if successful
}

// startOperationStage is the shared owner of admitting and starting an
// Operation's next child process (build/run; sequential stages install the
// current-child slot one at a time). It assigns stdout/stderr to
// op.LogBuffer, refuses admission once the termination latch is set, and
// performs the synchronized start under op.mu so the start-vs-terminate
// race linearizes in one critical section (either the child starts, or the
// termination latch is set first and the child never starts).
//
// The caller must:
// - handle pre-start termination (Terminated == true) with operation-specific cleanup
// - handle start failure (Err != nil) with operation-specific result codes
// - be the single Wait owner for the started child via waitCurrentStage
func startOperationStage(cmd *exec.Cmd, op *operation) operationStartResult {
	op.mu.Lock()
	if op.terminationRequested {
		op.mu.Unlock()
		return operationStartResult{Terminated: true}
	}
	if op.currentCmd != nil {
		// Sequential-stage discipline violation: a stage must Wait and
		// clear the slot (waitCurrentStage) before the next admission.
		op.mu.Unlock()
		return operationStartResult{Err: errors.New("operation already owns an active child process")}
	}
	// Assign LogBuffer directly to stdout/stderr for thread-safe capture.
	cmd.Stdout = op.LogBuffer
	cmd.Stderr = op.LogBuffer
	op.currentCmd = cmd

	// cmd.Start() is called while holding op.mu so terminateOperations cannot
	// race between latching termination and the child start: either the child
	// starts and termination signals it, or the latch wins and no child
	// starts.
	err := cmd.Start()
	if err != nil {
		op.currentCmd = nil
	} else if op.StartedAt == nil {
		// StartedAt is Operation metadata, set exactly once on the first
		// successful child start; it is not reset per stage.
		startTime := time.Now()
		op.StartedAt = &startTime
	}
	op.mu.Unlock()

	if err != nil {
		return operationStartResult{Err: err}
	}

	return operationStartResult{}
}

// waitCurrentStage is the single Wait owner for the Operation's current
// child process: it waits for the child installed by startOperationStage,
// then clears the current-child slot under op.mu so a later stage can be
// admitted. The permanent termination latch guarantees that a termination
// arriving before, during, or after the Wait refuses any later stage.
func (op *operation) waitCurrentStage() error {
	op.mu.Lock()
	cmd := op.currentCmd
	op.mu.Unlock()
	if cmd == nil {
		return errors.New("operation has no active child process to wait for")
	}
	err := cmd.Wait()
	op.mu.Lock()
	if op.currentCmd == cmd {
		op.currentCmd = nil
	}
	op.mu.Unlock()
	return err
}
