package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"
)

type operationState string

const (
	operationRunning   operationState = "running"
	operationSucceeded operationState = "succeeded"
	operationFailed    operationState = "failed"
)

type buildOperation struct {
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
	cancel      context.CancelFunc
	done        chan struct{}
}

func newBuildOperation(sessionID, image, ctxPath, dockerfile string, bufSize int64) *buildOperation {
	opID := generateOperationID()
	now := time.Now()
	return &buildOperation{
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

func generateOperationID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("cannot generate operation ID: %v", err))
	}
	return "op_" + hex.EncodeToString(b)
}

type operationRegistry struct {
	mu       sync.RWMutex
	ops      map[string]*buildOperation
	shutting atomic.Bool
}

func newOperationRegistry() *operationRegistry {
	return &operationRegistry{
		ops: make(map[string]*buildOperation),
	}
}

func (r *operationRegistry) create(op *buildOperation) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ops[op.ID] = op
}

func (r *operationRegistry) get(id string) *buildOperation {
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
	var completed []*buildOperation
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
		sorted := make([]*buildOperation, 0, len(completed))
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
	return r.shutting.Load()
}

func (r *operationRegistry) setShuttingDown() {
	r.shutting.Store(true)
}

func (r *operationRegistry) terminateAll(ctx context.Context) {
	r.mu.RLock()
	var ops []*buildOperation
	for _, op := range r.ops {
		ops = append(ops, op)
	}
	r.mu.RUnlock()

	// Phase 1: Send graceful SIGTERM to all running operations.
	// Do NOT call cancel() here - that would immediately kill the process.
	for _, op := range ops {
		op.mu.Lock()
		if op.cmd != nil && op.cmd.Process != nil {
			op.cmd.Process.Signal(os.Interrupt)
		}
		op.mu.Unlock()
	}

	// Phase 2: Wait for operations to complete with context deadline.
	// The completion goroutine owns cmd.Wait() and will close op.done.
	deadline, hasDeadline := ctx.Deadline()
	if !hasDeadline {
		deadline = time.Now().Add(5 * time.Second)
	}

	for _, op := range ops {
		select {
		case <-op.done:
			// Operation completed normally (or was killed by completion goroutine).
		case <-time.After(time.Until(deadline)):
			// Timeout: force kill the process.
			// The completion goroutine will still call cmd.Wait() and close op.done.
			op.mu.Lock()
			if op.cmd != nil && op.cmd.Process != nil {
				op.cmd.Process.Kill()
			}
			op.mu.Unlock()
			// Wait for the completion goroutine to reap the killed process.
			select {
			case <-op.done:
			case <-time.After(2 * time.Second):
			}
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

func (op *buildOperation) succeed(duration *string) {
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
		Event:       "build.finish",
		SessionID:   op.SessionID,
		OperationID: op.ID,
		Image:       op.Image,
		Context:     op.Context,
		Dockerfile:  op.Dockerfile,
		Result:      "success",
		Duration:    dur,
	})
	close(op.done)
}

func (op *buildOperation) fail(resultCode, message string, exitCode *int, duration ...*string) {
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
		Event:       "build.finish",
		SessionID:   op.SessionID,
		OperationID: op.ID,
		Image:       op.Image,
		Context:     op.Context,
		Dockerfile:  op.Dockerfile,
		Result:      "failure",
		ExitCode:    exitCode,
		Duration:    dur,
	})
	close(op.done)
}

func (op *buildOperation) Wait() {
	<-op.done
}
