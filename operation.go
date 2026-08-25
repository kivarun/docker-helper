package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
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

type operation struct {
	mu            sync.Mutex
	ID            string         `json:"operation_id"`
	SessionID     string         `json:"session_id"`
	Kind          string         `json:"kind"`
	State         operationState `json:"status"`
	CreatedAt     time.Time      `json:"created_at"`
	StartedAt     *time.Time     `json:"started_at,omitempty"`
	CompletedAt   *time.Time     `json:"completed_at,omitempty"`
	Duration      *string        `json:"duration,omitempty"`
	ExitCode      *int           `json:"exit_code,omitempty"`
	ResultCode    *string        `json:"result_code,omitempty"`
	Image         string         `json:"image,omitempty"`
	Context       string         `json:"context,omitempty"`
	Dockerfile    string         `json:"dockerfile,omitempty"`
	LogBuffer     *boundedBuffer `json:"-"`
	cmd           *exec.Cmd
	done          chan struct{}
	doneOnce      sync.Once // ensures op.done is closed exactly once
	terminated    bool      // set by terminateForShutdown/cancel when process not yet started
	reason        terminationReason
	started       bool          // set to true only after cmd.Start() succeeds
	forceOwned    bool          // true when force cleanup has been claimed for this operation
	forceDone     chan struct{} // closed when shared force-cleanup phase completes
	forceDeadline time.Time     // absolute deadline shared by owner and all followers
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
	// stagedCtx is the staged build context for build operations.
	// It is cleaned up after the operation completes or fails.
	stagedCtx *stagedBuildContext
	// macLeaseRelease releases the workspace-use lease held by this operation.
	// nil when no lease was acquired (user mode or no MAC backend).
	macLeaseRelease func()
	// audit metadata for finish event, set by operation-specific factory.
	auditCommandArgCount   *int
	auditMounts            []auditMount
	auditEnvKeys           []string
	auditBuildArgKeys      []string
	auditShmSize           string
	auditTrustedCAInjected bool
	auditPrincipalName     string
}

func newBuildOperation(sessionID, image, ctxPath, dockerfile string, bufSize int64, principalName string) *operation {
	opID := generateOperationID()
	now := time.Now()
	return &operation{
		ID:                 opID,
		SessionID:          sessionID,
		Kind:               "build",
		State:              operationRunning,
		CreatedAt:          now,
		Image:              image,
		Context:            ctxPath,
		Dockerfile:         dockerfile,
		LogBuffer:          newBoundedBuffer(bufSize),
		done:               make(chan struct{}),
		auditPrincipalName: principalName,
	}
}

func newRunOperation(sessionID, image string, bufSize int64, principalName string) *operation {
	opID := generateOperationID()
	now := time.Now()
	return &operation{
		ID:                 opID,
		SessionID:          sessionID,
		Kind:               "run",
		State:              operationRunning,
		CreatedAt:          now,
		Image:              image,
		LogBuffer:          newBoundedBuffer(bufSize),
		done:               make(chan struct{}),
		auditPrincipalName: principalName,
	}
}

func generateOperationID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("cannot generate operation ID: %v", err))
	}
	return "op_" + hex.EncodeToString(b)
}

type operationSupervisor struct {
	mu       sync.RWMutex
	ops      map[string]*operation
	shutting bool
}

func newOperationSupervisor() *operationSupervisor {
	return &operationSupervisor{
		ops: make(map[string]*operation),
	}
}

// admit atomically checks the shutdown gate and registers the operation.
// Returns true if the operation was admitted, false if the supervisor is shutting down.
// The caller must not start the operation process if admit returns false.
func (s *operationSupervisor) admit(op *operation) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.shutting {
		return false
	}
	s.ops[op.ID] = op
	return true
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
// Returns "not_found" if the operation does not exist.
// Returns "already_terminal" if the operation is already completed.
func (s *operationSupervisor) cancel(id string, killContainer func(context.Context, string)) error {
	s.mu.RLock()
	op, ok := s.ops[id]
	s.mu.RUnlock()
	if !ok {
		return fmt.Errorf("not_found")
	}

	op.mu.Lock()
	if op.CompletedAt != nil {
		op.mu.Unlock()
		return fmt.Errorf("already_terminal")
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
	// If not started: mark terminated (blocks cmd.Start from proceeding).
	// If started: send graceful SIGTERM.
	// This single lock acquisition eliminates the race between checking
	// started and setting terminated.
	var terminated []*operation
	for _, op := range ops {
		op.mu.Lock()
		if op.reason == terminationNone {
			op.reason = reason
		}
		if !op.started {
			op.terminated = true
			terminated = append(terminated, op)
		} else if op.cmd != nil && op.cmd.Process != nil {
			op.cmd.Process.Signal(syscall.SIGTERM)
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
	if op.cmd != nil && op.cmd.Process != nil {
		op.cmd.Process.Kill()
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
	if op.cmd != nil && op.cmd.Process != nil {
		op.cmd.Process.Kill()
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

func (b *boundedBuffer) Range(offset int64) (data []byte, nextOffset int64, truncated bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	nextOffset = b.totalLen

	if offset >= b.totalLen {
		return nil, nextOffset, false
	}

	// retained range is [b.offset, b.totalLen).
	// data in b.buf corresponds to that range.
	if offset < b.offset {
		// offset is older than retained data.
		data = make([]byte, len(b.buf))
		copy(data, b.buf)
		return data, nextOffset, true
	}

	// offset is inside retained range.
	idx := int(offset - b.offset)
	if idx > len(b.buf) {
		idx = len(b.buf)
	}
	data = make([]byte, len(b.buf)-idx)
	copy(data, b.buf[idx:])
	return data, nextOffset, false
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
	writeAuditWithRequestID(context.Background(), auditRecord{
		Event:             op.Kind + ".finish",
		SessionID:         op.SessionID,
		OperationID:       op.ID,
		Image:             op.Image,
		Context:           op.Context,
		Dockerfile:        op.Dockerfile,
		CommandArgCount:   op.auditCommandArgCount,
		Mounts:            op.auditMounts,
		EnvKeys:           op.auditEnvKeys,
		BuildArgKeys:      op.auditBuildArgKeys,
		ShmSize:           op.auditShmSize,
		TrustedCAInjected: op.auditTrustedCAInjected,
		PrincipalName:     op.auditPrincipalName,
		Result:            *op.ResultCode,
		ExitCode:          exitCode,
		Duration:          dur,
	})
}

func (op *operation) Wait() {
	<-op.done
}

// operationStartResult is returned by startOperationProcess.
type operationStartResult struct {
	Terminated bool  // true if operation was already terminated before start
	Err        error // error from cmd.Start(), nil if successful
}

// startOperationProcess is a shared helper for starting operation processes
// (build/run). It assigns stdout/stderr to op.LogBuffer, performs synchronized
// start under op.mu, and returns the result.
//
// The caller must:
// - handle pre-start termination (Terminated == true) with operation-specific cleanup
// - handle start failure (Err != nil) with operation-specific result codes
// - start the completion goroutine with operation-specific completion handler
func startOperationProcess(cmd *exec.Cmd, op *operation) operationStartResult {
	// Assign LogBuffer directly to stdout/stderr for thread-safe capture.
	cmd.Stdout = op.LogBuffer
	cmd.Stderr = op.LogBuffer

	// Start the process under op.mu so terminateForShutdown can synchronize:
	// either we start the process (started=true), or terminateForShutdown marks
	// it as terminated. There is no intermediate state.
	op.mu.Lock()
	if op.terminated {
		op.mu.Unlock()
		return operationStartResult{Terminated: true}
	}
	startTime := time.Now()
	op.StartedAt = &startTime
	op.cmd = cmd

	// cmd.Start() is called while holding op.mu so terminateForShutdown cannot
	// race between checking started and setting terminated.
	err := cmd.Start()
	op.started = err == nil
	op.mu.Unlock()

	if err != nil {
		return operationStartResult{Err: err}
	}

	return operationStartResult{}
}
