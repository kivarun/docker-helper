package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"sync"
	"testing"
)

// runSeamOptions configures the fake Engine container runner for run tests.
type runSeamOptions struct {
	// Output is the bounded combined output the fake runner returns.
	Output string
	// Truncated is reported by the fake runner.
	Truncated bool
	// ExitCode is the terminal container exit code the fake runner returns.
	ExitCode int
	// Err is the normalized Engine failure the fake runner returns.
	Err error
	// Block holds containerRun open until it is closed or the request
	// context is cancelled.
	Block chan struct{}
	// ConstructErr makes adapter construction itself fail.
	ConstructErr error
}

// capturedRun records what the fake runner received.
type capturedRun struct {
	mu    sync.Mutex
	specs []engineRunSpec
	ctxs  []context.Context
}

// reached reports whether the fake runner was invoked.
func (c *capturedRun) reached() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.specs) > 0
}

// callCount reports how many times the fake runner was invoked.
func (c *capturedRun) callCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.specs)
}

// lastSpec returns the most recent run spec the fake runner received.
func (c *capturedRun) lastSpec() engineRunSpec {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.specs[len(c.specs)-1]
}

// fakeEngineRunner is the Engine container-runner test seam.
type fakeEngineRunner struct {
	captured *capturedRun
	opts     runSeamOptions
}

func (f fakeEngineRunner) containerRun(ctx context.Context, spec engineRunSpec, outputLimit int64) (engineRunResult, error) {
	f.captured.mu.Lock()
	f.captured.specs = append(f.captured.specs, spec)
	f.captured.ctxs = append(f.captured.ctxs, ctx)
	f.captured.mu.Unlock()
	if f.opts.Block != nil {
		select {
		case <-f.opts.Block:
		case <-ctx.Done():
			return engineRunResult{Output: f.opts.Output, Truncated: f.opts.Truncated},
				&engineError{kind: engineErrClientCancelled, cause: ctx.Err()}
		}
	}
	return engineRunResult{Output: f.opts.Output, Truncated: f.opts.Truncated, ExitCode: f.opts.ExitCode}, f.opts.Err
}

// setupRunSeam installs a fake Engine container runner on the App and
// returns the capture handle.
func setupRunSeam(t *testing.T, app *App, opts runSeamOptions) *capturedRun {
	t.Helper()
	captured := &capturedRun{}
	app.NewEngineRunFn = func() (engineContainerRunner, error) {
		if opts.ConstructErr != nil {
			return nil, opts.ConstructErr
		}
		return fakeEngineRunner{captured: captured, opts: opts}, nil
	}
	return captured
}

// postRun posts a run request through the production handler and returns the
// recorder. The synchronous handler returns the final result in the response
// body; there is no operation to wait for.
func postRun(t *testing.T, app *App, token string, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	req := newRunRequest(body, token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)
	return w
}

// decodeRunResponse decodes the synchronous run response envelope. The
// recorder body is left intact so later helpers can re-read it.
func decodeRunResponse(t *testing.T, w *httptest.ResponseRecorder) runResponse {
	t.Helper()
	raw, err := io.ReadAll(w.Body)
	if err != nil {
		t.Fatalf("read run response: %v", err)
	}
	w.Body.Reset()
	w.Body.Write(raw)
	var resp runResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("decode run response: %v", err)
	}
	return resp
}

// assertNoRunOperation proves the synchronous run left no operation in the
// supervisor: no registered operation at all, and the response carries no
// operation identity.
func assertNoRunOperation(t *testing.T, app *App, body []byte) {
	t.Helper()
	var envelope map[string]any
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("re-decode run response: %v", err)
	}
	if _, has := envelope["operation_id"]; has {
		t.Error("synchronous run response must not carry operation_id")
	}
	if app.OperationSupervisor != nil {
		app.OperationSupervisor.mu.RLock()
		opCount := len(app.OperationSupervisor.ops)
		app.OperationSupervisor.mu.RUnlock()
		if opCount != 0 {
			t.Errorf("run must not register an operation, supervisor has %d", opCount)
		}
	}
}
