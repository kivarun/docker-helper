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

type operation struct {
	mu          sync.Mutex
	ID          string         `json:"operation_id"`
	SessionID   string         `json:"session_id"`
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
	cmd         *exec.Cmd
	done        chan struct{}
	doneOnce    sync.Once // ensures op.done is closed exactly once
	terminated  bool      // set by terminateAll when process not yet started
	started     bool      // set to true only after cmd.Start() succeeds
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
	r.mu.RLock()
	var ops []*operation
	for _, op := range r.ops {
		ops = append(ops, op)
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
		if !op.started {
			op.terminated = true
			terminated = append(terminated, op)
		} else if op.cmd != nil && op.cmd.Process != nil {
			op.cmd.Process.Signal(syscall.SIGTERM)
		}
		op.mu.Unlock()
	}

	// Phase 2: Wait for non-terminated operations to complete until the
	// shared deadline. Terminated operations will be cleaned up by the
	// handler detecting op.terminated before cmd.Start.
	deadline, hasDeadline := ctx.Deadline()
	if !hasDeadline {
		deadline = time.Now().Add(5 * time.Second)
	}

	terminatedSet := make(map[*operation]struct{}, len(terminated))
	for _, op := range terminated {
		terminatedSet[op] = struct{}{}
	}

	for _, op := range ops {
		if _, ok := terminatedSet[op]; ok {
			continue
		}
		select {
		case <-op.done:
		case <-time.After(time.Until(deadline)):
			// Deadline exceeded: perform bounded daemon-side cleanup
			// before force-killing the docker run CLI.
			//
			// The cidfile may not yet be populated because Docker daemon
			// publishes the container ID asynchronously after cmd.Start().
			// We use a single bounded cleanup context that covers both
			// waiting for the cidfile and the docker kill itself.
			if op.cidfile != "" {
				// Single bounded context for the entire cleanup phase:
				// up to 3 seconds total for cidfile polling + docker kill.
				cleanupCtx, cleanupCancel := context.WithTimeout(
					context.Background(), 3*time.Second,
				)
				containerID := waitForContainerID(cleanupCtx, op)
				if containerID != "" && killContainer != nil {
					killContainer(cleanupCtx, containerID)
				}
				cleanupCancel()
			}
			op.mu.Lock()
			if op.cmd != nil && op.cmd.Process != nil {
				op.cmd.Process.Kill()
			}
			op.mu.Unlock()
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

func (op *operation) succeed(duration *string) {
	op.mu.Lock()
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
}

func (op *operation) fail(resultCode, message string, exitCode *int, duration ...*string) {
	op.mu.Lock()
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
}

func (op *operation) Wait() {
	<-op.done
}
