package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/moby/moby/api/pkg/stdcopy"
)

// fakeRunContainerID is the fixed container ID the fake run Engine issues.
// It doubles as the raw-backend-identifier canary for leak assertions.
const fakeRunContainerID = "dhfake0123456789abcdef0123456789ab"

// fakeRunEngineRemoveMsg is the raw Engine failure message the fake remove
// endpoint reports. It doubles as the raw-backend-payload canary for leak
// assertions.
const fakeRunEngineRemoveMsg = "raw engine removal probe k8q2w"

// fakeRunEngineOutput is the combined workload output the fake attach
// stream delivers to the bounded run buffer.
const fakeRunEngineOutput = "fake-engine run output n4m7z"

// fakeRunEngineOptions configures the fake run Engine for one row.
type fakeRunEngineOptions struct {
	// ExitCode is the container exit status the /wait endpoint reports.
	ExitCode int
	// RemoveFails makes the forced removal answer an internal Engine
	// failure carrying the raw payload canary.
	RemoveFails bool
	// RemoveTimeout makes the forced removal hang until the adapter's
	// removal context ends.
	RemoveTimeout bool
	// HoldWorkload keeps the workload running after start: the wait stream
	// never reports an exit, so only request cancellation ends the run.
	HoldWorkload bool
}

// fakeRunEngine is the fake Engine serving the container lifecycle endpoints
// the synchronous run adapter consumes: create, attach (stdcopy-framed
// combined stream), wait, start, and the forced DELETE removal. It exists so
// the production adapter and the production /run handler can be driven
// together while the removal outcome is injected at the exact Engine
// operation under test.
type fakeRunEngine struct {
	srv  *httptest.Server
	opts fakeRunEngineOptions

	mu         sync.Mutex
	createBody string
	removeHits int
	startHits  int

	startedOnce sync.Once
	exitOnce    sync.Once
	started     chan struct{}
	exit        chan struct{}
}

// newFakeRunEngine starts the fake run Engine and registers its shutdown.
func newFakeRunEngine(t *testing.T, opts fakeRunEngineOptions) *fakeRunEngine {
	t.Helper()
	fe := &fakeRunEngine{
		opts:    opts,
		started: make(chan struct{}),
		exit:    make(chan struct{}),
	}
	fe.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fe.serve(t, w, r)
	}))
	t.Cleanup(fe.srv.Close)
	return fe
}

// serve routes one fake Engine request.
func (fe *fakeRunEngine) serve(t *testing.T, w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/_ping":
		w.Header().Set("Api-Version", "1.51")
		w.Header().Set("Ostype", "linux")
		w.WriteHeader(http.StatusOK)
	case strings.HasSuffix(r.URL.Path, "/containers/create"):
		blob, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read create body: %v", err)
		}
		fe.mu.Lock()
		fe.createBody = string(blob)
		fe.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"Id":"` + fakeRunContainerID + `","Warnings":[]}`))
	case strings.HasSuffix(r.URL.Path, "/attach"):
		fakeRunEngineAttach(w)
	case strings.HasSuffix(r.URL.Path, "/wait"):
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// The wait response header goes out immediately, the way the
		// Engine acknowledges a next-exit wait; the exit status arrives
		// only when the workload exits.
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
			return
		case <-fe.exit:
		}
		_, _ = w.Write([]byte(fmt.Sprintf(`{"StatusCode":%d}`, fe.opts.ExitCode)))
	case strings.HasSuffix(r.URL.Path, "/start"):
		w.WriteHeader(http.StatusNoContent)
		fe.mu.Lock()
		fe.startHits++
		fe.mu.Unlock()
		fe.startedOnce.Do(func() { close(fe.started) })
		if !fe.opts.HoldWorkload {
			fe.exitOnce.Do(func() { close(fe.exit) })
		}
	case r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/containers/"):
		fe.mu.Lock()
		fe.removeHits++
		fe.mu.Unlock()
		if fe.opts.RemoveTimeout {
			// Hang until the adapter's bounded removal context ends.
			<-r.Context().Done()
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if fe.opts.RemoveFails {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"message":"` + fakeRunEngineRemoveMsg + `"}`))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}

// createBodyJSON returns the create request the adapter sent, decoded.
func (fe *fakeRunEngine) createLabels(t *testing.T) map[string]string {
	t.Helper()
	fe.mu.Lock()
	body := fe.createBody
	fe.mu.Unlock()
	var payload struct {
		Labels map[string]string `json:"Labels"`
	}
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("decode create body: %v (%q)", err, body)
	}
	return payload.Labels
}

// removeCalls reports how many forced-removal DELETE requests reached the
// fake Engine.
func (fe *fakeRunEngine) removeCalls() int {
	fe.mu.Lock()
	defer fe.mu.Unlock()
	return fe.removeHits
}

// startCalls reports how many start requests reached the fake Engine.
func (fe *fakeRunEngine) startCalls() int {
	fe.mu.Lock()
	defer fe.mu.Unlock()
	return fe.startHits
}

// startedUp signals the run path when the workload container started. The
// cancelled row cancels the request only after this signal, so the
// cancellation lands on a started workload.
func (fe *fakeRunEngine) waitStarted(t *testing.T) {
	t.Helper()
	select {
	case <-fe.started:
	case <-time.After(10 * time.Second):
		t.Fatal("the run never started its workload container")
	}
}

// fakeRunEngineAttach hijacks the attach connection the way the Engine does
// and delivers the fake combined workload output as one stdcopy-framed
// stdout frame. The connection is held open until the client closes it.
func fakeRunEngineAttach(w http.ResponseWriter) {
	conn, buf, err := w.(http.Hijacker).Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	if _, err := buf.WriteString("HTTP/1.1 101 Switching Protocols\r\nContent-Type: application/vnd.docker.raw-stream\r\n\r\n"); err != nil {
		return
	}
	_ = buf.Flush()
	header := []byte{byte(stdcopy.Stdout), 0, 0, 0, 0, 0, 0, byte(len(fakeRunEngineOutput))}
	if _, err := conn.Write(append(header, fakeRunEngineOutput...)); err != nil {
		return
	}
	blob := make([]byte, 4096)
	for {
		if _, err := conn.Read(blob); err != nil {
			return
		}
	}
}

// runCleanupFailureFixture is the shared driver for the remove-failure rows:
// the production handler runs against the production adapter with the fake
// Engine behind it. It returns the app, the fake Engine handle, the Session
// bearer token, and the Session ID for audit assertions.
func runCleanupFailureFixture(t *testing.T, opts fakeRunEngineOptions) (*App, *fakeRunEngine, string, string) {
	t.Helper()
	app := newTestAppWithAdminToken(t)
	app.OperationSupervisor = newOperationSupervisor()
	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}
	fe := newFakeRunEngine(t, opts)
	app.NewEngineRunFn = func() (engineContainerRunner, error) {
		return newEngineClientAgainstFake(t, fe.srv.URL), nil
	}
	return app, fe, result.Token, result.Session.ID
}

// assertRunCleanupFailure asserts the full synchronous run contract for a
// removal that failed: the run never reports a successful postcondition or a
// terminal workload result, the public error is the normalized backend
// failure with the bounded output preserved, the raw backend identifiers and
// payloads stay out of the response, audit, and operational log, and the
// finish audit reports the run failure.
func assertRunCleanupFailure(t *testing.T, auditBuf, opBuf *bytes.Buffer, app *App, w *httptest.ResponseRecorder, sessionID string) {
	t.Helper()
	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected status %d, got %d: %s", http.StatusBadGateway, w.Code, w.Body.String())
	}
	resp := decodeRunResponse(t, w)
	if resp.OK || resp.Code != "backend_failure" {
		t.Errorf("response = %+v, want backend_failure", resp)
	}
	if resp.ExitCode != nil {
		t.Errorf("a failed removal must not report a terminal workload exit code: %+v", resp)
	}
	if resp.Output != fakeRunEngineOutput {
		t.Errorf("bounded output before the failure = %q, want %q", resp.Output, fakeRunEngineOutput)
	}
	if resp.Truncated {
		t.Error("short output must not be truncated")
	}
	if resp.Duration == "" {
		t.Error("duration must be set")
	}

	assertRunFinishResult(t, auditBuf, sessionID, "docker_run_failed")

	for _, sink := range []struct{ name, blob string }{
		{"response body", w.Body.String()},
		{"audit log", auditBuf.String()},
		{"operational log", opBuf.String()},
	} {
		if strings.Contains(sink.blob, fakeRunContainerID) {
			t.Errorf("%s leaked the backend container identifier", sink.name)
		}
		if strings.Contains(sink.blob, fakeRunEngineRemoveMsg) {
			t.Errorf("%s leaked the raw Engine failure payload", sink.name)
		}
	}

	assertNoRunOperation(t, app, w.Body.Bytes())
}

// TestRunEngineRemoveFailureFailsTheRun proves the forced removal is part of
// the synchronous run postcondition: when the Engine refuses the removal,
// neither a successful workload nor a terminal non-zero workload exit may be
// reported — the run returns the normalized cleanup failure with the bounded
// output preserved, the audit reports the failure, and the surviving
// container keeps its helper-owned correlation labels.
func TestRunEngineRemoveFailureFailsTheRun(t *testing.T) {
	cases := []struct {
		name     string
		exitCode int
	}{
		{name: "successful workload", exitCode: 0},
		{name: "non-zero workload", exitCode: 7},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			auditBuf, opBuf := setupTestLogging(t)
			app, fe, token, sessionID := runCleanupFailureFixture(t, fakeRunEngineOptions{
				ExitCode:    tc.exitCode,
				RemoveFails: true,
			})

			w := postRun(t, app, token, map[string]any{"image": "alpine:3.24"})
			assertRunCleanupFailure(t, auditBuf, opBuf, app, w, sessionID)

			if fe.removeCalls() != 1 {
				t.Errorf("forced removal attempts = %d, want 1", fe.removeCalls())
			}
			labels := fe.createLabels(t)
			if labels[runtimeLabelSessionID] == "" {
				t.Errorf("create configuration missed the helper-owned session label: %v", labels)
			}
		})
	}
}

// TestRunEngineRemoveSuccessKeepsWorkloadResult is the control row for the
// fake run Engine: with a successful forced removal the synchronous run
// keeps the workload result, proving the remove-failure rows discriminate
// the injected cleanup failure rather than the fake plumbing.
func TestRunEngineRemoveSuccessKeepsWorkloadResult(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app, fe, token, sessionID := runCleanupFailureFixture(t, fakeRunEngineOptions{ExitCode: 0})

	w := postRun(t, app, token, map[string]any{"image": "alpine:3.24"})
	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
	}
	resp := decodeRunResponse(t, w)
	if !resp.OK || resp.ExitCode == nil || *resp.ExitCode != 0 || resp.Code != "" {
		t.Errorf("control row response = %+v", resp)
	}
	if resp.Output != fakeRunEngineOutput {
		t.Errorf("output = %q, want %q", resp.Output, fakeRunEngineOutput)
	}
	assertRunFinishResult(t, auditBuf, sessionID, "succeeded")
	if fe.removeCalls() != 1 {
		t.Errorf("forced removal attempts = %d, want 1", fe.removeCalls())
	}
}

// TestRunEngineRemoveFailureAfterCancelledWorkload proves a cancelled
// workload with a failed forced removal reports the cleanup failure, not a
// clean cancellation outcome: the container survives with its correlation
// labels, so the run must answer the normalized backend failure.
func TestRunEngineRemoveFailureAfterCancelledWorkload(t *testing.T) {
	auditBuf, opBuf := setupTestLogging(t)
	app, fe, token, sessionID := runCleanupFailureFixture(t, fakeRunEngineOptions{
		RemoveFails:  true,
		HoldWorkload: true,
	})

	reqCtx, cancel := context.WithCancel(context.Background())
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- postRunCtx(t, app, token, map[string]any{"image": "alpine:3.24"}, reqCtx)
	}()

	// The workload must be running before the cancellation, so the row
	// proves a cancelled workload whose cleanup then failed.
	fe.waitStarted(t)
	cancel()

	var w *httptest.ResponseRecorder
	select {
	case w = <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("the cancelled run did not return")
	}

	assertRunCleanupFailure(t, auditBuf, opBuf, app, w, sessionID)
	if fe.removeCalls() != 1 {
		t.Errorf("forced removal attempts = %d, want 1", fe.removeCalls())
	}
}

// TestRunEngineRemoveTimeoutIsBoundedBackendFailure proves the removal
// budget is honored and its expiry is a bounded backend failure, never a
// client cancellation and never a successful run: the removal consumes its
// full budget and the run returns the normalized failure.
func TestRunEngineRemoveTimeoutIsBoundedBackendFailure(t *testing.T) {
	auditBuf, opBuf := setupTestLogging(t)
	app, fe, token, sessionID := runCleanupFailureFixture(t, fakeRunEngineOptions{
		ExitCode:      0,
		RemoveTimeout: true,
	})

	started := time.Now()
	w := postRun(t, app, token, map[string]any{"image": "alpine:3.24"})
	elapsed := time.Since(started)

	if elapsed < engineRunRemoveTimeout {
		t.Errorf("the run returned after %v, before the %v removal budget expired", elapsed, engineRunRemoveTimeout)
	}

	assertRunCleanupFailure(t, auditBuf, opBuf, app, w, sessionID)
	if fe.removeCalls() != 1 {
		t.Errorf("forced removal attempts = %d, want 1", fe.removeCalls())
	}
}
