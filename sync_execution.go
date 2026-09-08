package main

import (
	"context"
	"sync"
)

// syncExecutionCoordinator owns admission, cancellation, and bounded shutdown
// termination for synchronous Engine-backed requests (currently the pull
// path). It is the synchronous companion of the operationSupervisor: unlike
// build/run operations, a synchronous request has no stored operation record
// to terminate, so the coordinator tracks the derived request contexts that
// are live right now.
//
// Admission and the shutdown gate are one atomic step: admit either derives
// and registers a request context while shutdown is closed, or refuses when
// shutdown has begun. Daemon shutdown first closes admission, then cancels
// every live request and waits for their handlers to release them under the
// shared shutdown deadline.
type syncExecutionCoordinator struct {
	mu       sync.Mutex
	shutting bool
	live     map[*syncExecutionRequest]struct{}
}

func newSyncExecutionCoordinator() *syncExecutionCoordinator {
	return &syncExecutionCoordinator{
		live: make(map[*syncExecutionRequest]struct{}),
	}
}

// syncExecutionRequest is one admitted synchronous request. end must be
// called exactly once by the owning handler, through defer, to release the
// request whether it succeeded or failed.
type syncExecutionRequest struct {
	coord  *syncExecutionCoordinator
	cancel context.CancelFunc
	done   chan struct{}
}

// admit derives a request context from parent and registers it atomically
// with the shutdown gate. ok is false when shutdown has begun; the caller
// must then refuse the request and must not use the returned values.
func (c *syncExecutionCoordinator) admit(parent context.Context) (ctx context.Context, req *syncExecutionRequest, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.shutting {
		return nil, nil, false
	}
	ctx, cancel := context.WithCancel(parent)
	req = &syncExecutionRequest{
		coord:  c,
		cancel: cancel,
		done:   make(chan struct{}),
	}
	c.live[req] = struct{}{}
	return ctx, req, true
}

// end deregisters the request and cancels its context. After end, shutdown
// termination no longer waits for this request.
func (req *syncExecutionRequest) end() {
	req.coord.mu.Lock()
	delete(req.coord.live, req)
	req.coord.mu.Unlock()
	req.cancel()
	close(req.done)
}

// beginShutdown closes admission. Live requests are not cancelled here;
// termination happens in terminateForShutdown so handlers admitted before
// the gate closed are cancelled exactly once, under the shutdown deadline.
func (c *syncExecutionCoordinator) beginShutdown() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.shutting = true
}

// terminateForShutdown cancels every live request and waits for their
// handlers to release them. The caller's context deadline is the
// authoritative absolute shutdown deadline; requests whose handlers have not
// released by then are abandoned (their contexts are already cancelled).
func (c *syncExecutionCoordinator) terminateForShutdown(ctx context.Context) {
	c.mu.Lock()
	live := make([]*syncExecutionRequest, 0, len(c.live))
	for req := range c.live {
		live = append(live, req)
	}
	c.mu.Unlock()

	for _, req := range live {
		req.cancel()
	}
	for _, req := range live {
		select {
		case <-req.done:
		case <-ctx.Done():
			return
		}
	}
}
