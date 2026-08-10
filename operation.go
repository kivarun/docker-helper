package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os/exec"
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
// explicit cancel (terminateOne) and daemon shutdown (terminateAll).
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
	terminated    bool      // set by terminateAll/terminateOne when process not yet started
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
	// audit metadata for finish event, set by operation-specific factory.
	auditCommandArgCount *int
	auditMounts          []auditMount
	auditEnvKeys         []string
}

func newBuildOperation(sessionID, image, ctxPath, dockerfile string, bufSize int64) *operation {
	opID := generateOperationID()
	now := time.Now()
	return &operation{
		ID:         opID,
		SessionID:  sessionID,
		Kind:       "build",
		State:      operationRunning,
		CreatedAt:  now,
		Image:      image,
		Context:    ctxPath,
		Dockerfile: dockerfile,
		LogBuffer:  newBoundedBuffer(bufSize),
		done:       make(chan struct{}),
	}
}

func newRunOperation(sessionID, image string, bufSize int64) *operation {
	opID := generateOperationID()
	now := time.Now()
	return &operation{
		ID:        opID,
		SessionID: sessionID,
		Kind:      "run",
		State:     operationRunning,
		CreatedAt: now,
		Image:     image,
		LogBuffer: newBoundedBuffer(bufSize),
		done:      make(chan struct{}),
	}
}

func generateOperationID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("cannot generate operation ID: %v", err))
	}
	return "op_" + hex.EncodeToString(b)
}

type operationRegistry struct {
	mu       sync.RWMutex
	ops      map[string]*operation
	shutting bool
}

func newOperationRegistry() *operationRegistry {
	return &operationRegistry{
		ops: make(map[string]*operation),
	}
}

// tryCreate atomically checks the shutting-down gate and registers the operation.
// Returns true if the operation was registered, false if the registry is shutting down.
// The caller must not start the operation process if tryCreate returns false.
func (r *operationRegistry) tryCreate(op *operation) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.shutting {
		return false
	}
	r.ops[op.ID] = op
	return true
}

func (r *operationRegistry) get(id string) *operation {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.ops[id]
}

func (r *operationRegistry) remove(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.ops, id)
}

func (r *operationRegistry) cleanup(retentionTTL time.Duration, maxCompleted int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	var completed []*operation
	for _, op := range r.ops {
		op.mu.Lock()
		state := op.State
		completedAt := op.CompletedAt
		op.mu.Unlock()
		if state != operationRunning && completedAt != nil {
			completed = append(completed, op)
		}
	}

	for _, op := range completed {
		if now.Sub(*op.CompletedAt) > retentionTTL {
			delete(r.ops, op.ID)
		}
	}

	if len(completed) > maxCompleted {
		sorted := make([]*operation, 0, len(completed))
		for _, op := range completed {
			op.mu.Lock()
			completedAt := op.CompletedAt
			op.mu.Unlock()
			if completedAt != nil {
				sorted = append(sorted, op)
			}
		}
		for i := 0; i < len(sorted)-1; i++ {
			for j := i + 1; j < len(sorted); j++ {
				sorted[i].mu.Lock()
				sorted[j].mu.Lock()
				if sorted[j].CompletedAt.Before(*sorted[i].CompletedAt) {
					sorted[i], sorted[j] = sorted[j], sorted[i]
				}
				sorted[i].mu.Unlock()
				sorted[j].mu.Unlock()
			}
		}
		for _, op := range sorted[:len(sorted)-maxCompleted] {
			delete(r.ops, op.ID)
		}
	}
}

func (r *operationRegistry) isShuttingDown() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.shutting
}

func (r *operationRegistry) setShuttingDown() {
	r.mu.Lock()
	r.shutting = true
	r.mu.Unlock()
}

// terminateAll sends SIGTERM to all running operations, waits for them
// to complete until the shared deadline, then force-kills any that remain.
// The killContainer callback (may be nil) is called for run operations
// that have a cidfile, to perform daemon-side container cleanup before
// force-killing the CLI process.
func (r *operationRegistry) terminateAll(ctx context.Context, killContainer func(context.Context, string)) {
	r.terminateAllOps(ctx, nil, killContainer, terminationShutdown)
}

// terminateOne cancels a single operation by ID.
// Returns nil if the operation was found and cancellation initiated.
// Returns "not_found" if the operation does not exist.
// Returns "already_terminal" if the operation is already completed.
func (r *operationRegistry) terminateOne(id string, killContainer func(context.Context, string)) error {
	r.mu.RLock()
	op, ok := r.ops[id]
	r.mu.RUnlock()
	if !ok {
		return fmt.Errorf("not_found")
	}

	op.mu.Lock()
	if op.CompletedAt != nil {
		op.mu.Unlock()
		return fmt.Errorf("already_terminal")
	}
	op.mu.Unlock()

	r.terminateAllOps(context.Background(), op, killContainer, terminationCancelled)
	return nil
}

// terminateAllOps is the shared termination primitive used by both
// terminateAll (shutdown) and terminateOne (explicit cancel).
// If targetOp is nil, all operations are terminated (shutdown).
// If targetOp is non-nil, only that operation is terminated (cancel).
// reason distinguishes shutdown from explicit cancel for result semantics.
func (r *operationRegistry) terminateAllOps(ctx context.Context, targetOp *operation, killContainer func(context.Context, string), reason terminationReason) {
	// Normalize context: if the caller did not supply a deadline, create
	// a bounded termination context so that all wait paths are guaranteed
	// to be bounded. This prevents unbounded waits when terminateOne
	// passes context.Background().
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultTerminationTimeout)
		defer cancel()
	}

	r.mu.RLock()
	var ops []*operation
	if targetOp != nil {
		ops = []*operation{targetOp}
	} else {
		for _, op := range r.ops {
			ops = append(ops, op)
		}
	}
	r.mu.RUnlock()

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

	// Phase 2: Wait for each operation to complete. If the termination
	// context expires, claim force-cleanup ownership (single-owner) and
	// perform bounded daemon-side cleanup.
	for _, op := range ops {
		if _, ok := terminatedSet[op]; ok {
			continue
		}
		select {
		case <-op.done:
		case <-ctx.Done():
			// Deadline exceeded: claim force-cleanup ownership under op.mu.
			// Only the first caller to claim performs the actual cleanup.
			// All callers share a single absolute force-cleanup deadline
			// via op.forceDeadline.
			op.mu.Lock()
			if op.forceOwned {
				// Another termination path already claimed force cleanup.
				// Wait for the shared force phase to complete, bounded
				// by the remaining time until the shared deadline.
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
				continue
			}
			if op.CompletedAt != nil {
				// Operation completed naturally just before force claim.
				// No cleanup needed.
				op.mu.Unlock()
				continue
			}
			op.forceOwned = true
			op.forceDone = make(chan struct{})
			op.forceDeadline = time.Now().Add(defaultForceCleanupTimeout)
			forceDeadline := op.forceDeadline
			forceDone := op.forceDone
			op.mu.Unlock()

			// Force cleanup phase (single owner):
			// bounded daemon-side cleanup before force-killing the docker run CLI.
			// Uses the shared force deadline so followers can bound their wait
			// to the same absolute deadline rather than independent timers.
			forceCtx, forceCancel := context.WithDeadline(
				context.Background(), forceDeadline,
			)
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
	}
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

	dur := ""
	if duration != nil {
		dur = *duration
	}
	writeAuditWithRequestID(context.Background(), auditRecord{
		Event:           op.Kind + ".finish",
		SessionID:       op.SessionID,
		OperationID:     op.ID,
		Image:           op.Image,
		Context:         op.Context,
		Dockerfile:      op.Dockerfile,
		CommandArgCount: op.auditCommandArgCount,
		Mounts:          op.auditMounts,
		EnvKeys:         op.auditEnvKeys,
		Result:          *op.ResultCode,
		Duration:        dur,
	})
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

	dur := ""
	if len(duration) > 0 && duration[0] != nil {
		dur = *duration[0]
	}
	writeAuditWithRequestID(context.Background(), auditRecord{
		Event:           op.Kind + ".finish",
		SessionID:       op.SessionID,
		OperationID:     op.ID,
		Image:           op.Image,
		Context:         op.Context,
		Dockerfile:      op.Dockerfile,
		CommandArgCount: op.auditCommandArgCount,
		Mounts:          op.auditMounts,
		EnvKeys:         op.auditEnvKeys,
		Result:          *op.ResultCode,
		ExitCode:        exitCode,
		Duration:        dur,
	})
	op.doneOnce.Do(func() { close(op.done) })
	return true
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

	// Start the process under op.mu so terminateAll can synchronize:
	// either we start the process (started=true), or terminateAll marks
	// it as terminated. There is no intermediate state.
	op.mu.Lock()
	if op.terminated {
		op.mu.Unlock()
		return operationStartResult{Terminated: true}
	}
	startTime := time.Now()
	op.StartedAt = &startTime
	op.cmd = cmd

	// cmd.Start() is called while holding op.mu so terminateAll cannot
	// race between checking started and setting terminated.
	err := cmd.Start()
	op.started = err == nil
	op.mu.Unlock()

	if err != nil {
		return operationStartResult{Err: err}
	}

	return operationStartResult{}
}
