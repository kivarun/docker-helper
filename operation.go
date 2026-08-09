package main

import (
	"bytes"
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
	var cmds []*buildOperation
	for _, op := range r.ops {
		op.mu.Lock()
		if op.State == operationRunning && op.cmd != nil {
			cmds = append(cmds, op)
		}
		op.mu.Unlock()
	}
	r.mu.RUnlock()

	for _, op := range cmds {
		if op.cancel != nil {
			op.cancel()
		}
		if op.cmd != nil && op.cmd.Process != nil {
			op.cmd.Process.Signal(os.Interrupt)
		}
	}

	for _, op := range cmds {
		if op.cmd != nil {
			op.cmd.Wait()
		}
	}

	deadline, _ := ctx.Deadline()
	timeout := time.Until(deadline)
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	for _, op := range cmds {
		select {
		case <-time.After(timeout):
			if op.cmd != nil && op.cmd.Process != nil {
				op.cmd.Process.Kill()
			}
		default:
		}
	}
}

// boundedBuffer is a thread-safe rolling byte buffer that preserves the newest
// bytes when the configured maximum size is exceeded.
type boundedBuffer struct {
	mu       sync.RWMutex
	buf      bytes.Buffer
	maxSize  int64
	offset   int64
	totalLen int64
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

	if b.buf.Len()+n > int(b.maxSize) {
		keep := int(b.maxSize) - b.buf.Len() + n
		if keep < 0 {
			keep = 0
		}
		truncated := b.buf.Len() - keep
		if truncated > 0 {
			b.offset += int64(truncated)
			data := b.buf.Bytes()
			b.buf.Reset()
			b.buf.Write(data[truncated:])
		}
	}

	b.buf.Write(p)
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

	data = b.buf.Bytes()

	if offset < b.offset {
		trim := int(b.offset - offset)
		if trim > len(data) {
			trim = len(data)
		}
		data = data[trim:]
		truncated = true
	}

	nextOffset = b.totalLen
	return data, nextOffset, truncated
}

func (b *boundedBuffer) currentOffset() int64 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.offset
}

func (b *boundedBuffer) totalWritten() int64 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.totalLen
}

func (op *buildOperation) succeed(duration *string) {
	op.mu.Lock()
	defer op.mu.Unlock()

	now := time.Now()
	op.State = operationSucceeded
	op.CompletedAt = &now
	op.Duration = duration

	if op.ResultCode != nil {
		close(op.done)
		return
	}
	rc := "succeeded"
	op.ResultCode = &rc

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

func (op *buildOperation) fail(resultCode, message string, exitCode *int) {
	op.mu.Lock()
	defer op.mu.Unlock()

	now := time.Now()
	op.State = operationFailed
	op.CompletedAt = &now
	op.ExitCode = exitCode
	op.ResultCode = &resultCode

	writeAuditWithRequestID(context.Background(), auditRecord{
		Event:       "build.finish",
		SessionID:   op.SessionID,
		OperationID: op.ID,
		Image:       op.Image,
		Context:     op.Context,
		Dockerfile:  op.Dockerfile,
		Result:      "failure",
		ExitCode:    exitCode,
	})
	close(op.done)
}

func (op *buildOperation) Wait() {
	<-op.done
}
