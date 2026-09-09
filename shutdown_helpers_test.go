package main

import (
	"context"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// setupBuildTest creates an app, supervisor, session and Dockerfile for build tests.
// setupRunSupervisorTest creates an app with a supervisor, a session, and a
// workspace, for tests that exercise legacy run operations through the
// supervisor. The caller installs its own ExecCommandContext seam before
// starting operations.
func setupRunSupervisorTest(t *testing.T) (*App, *operationSupervisor, *CreatedSession, string) {
	t.Helper()
	app := newTestAppWithAdminToken(t)
	supervisor := newOperationSupervisor()
	app.OperationSupervisor = supervisor

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	return app, supervisor, result, result.Token
}

// startRunTestOperation constructs and starts a legacy run operation through
// the production supervisor primitives. The synchronous run no longer
// registers operations; the legacy operation lifecycle stays contract-tested
// through its production primitives until the operation framework removal
// (D0.4). The caller may have installed an ExecCommandContext seam; the
// command below is created through that seam.
func startRunTestOperation(t *testing.T, app *App, session *CreatedSession) *operation {
	t.Helper()
	op := newRunOperation(session.Session.ID, "example:test", 4*1024*1024, "", "", "")
	if app.OperationSupervisor.admit(op) != admissionAccepted {
		t.Fatal("admit failed")
	}
	cmd := app.newDockerCommand(context.Background(), "sleep", "60")
	res := startOperationProcess(cmd, op)
	if res.Terminated || res.Err != nil {
		t.Fatalf("start operation: terminated=%v err=%v", res.Terminated, res.Err)
	}
	go func() {
		cmd.Wait()
		exitCode := 137
		op.fail("docker_run_failed", "docker run failed", &exitCode, nil)
	}()
	return op
}

// startRunOperationConcurrent starts a legacy run operation in a goroutine
// through the production supervisor primitives and returns the operation
// channel for synchronization.
func startRunOperationConcurrent(t *testing.T, app *App, session *CreatedSession) (*httptest.ResponseRecorder, chan *operation, func() *operation) {
	t.Helper()
	w := httptest.NewRecorder()

	opCh := make(chan *operation, 1)
	go func() {
		op := newRunOperation(session.Session.ID, "example:test", 4*1024*1024, "", "", "")
		if app.OperationSupervisor.admit(op) != admissionAccepted {
			opCh <- nil
			return
		}
		cmd := app.newDockerCommand(context.Background(), "sleep", "60")
		res := startOperationProcess(cmd, op)
		if res.Terminated || res.Err != nil {
			opCh <- op
			return
		}
		go func() {
			cmd.Wait()
			exitCode := 137
			op.fail("docker_run_failed", "docker run failed", &exitCode, nil)
		}()
		opCh <- op
	}()

	return w, opCh, func() *operation {
		select {
		case op := <-opCh:
			return op
		case <-time.After(5 * time.Second):
			t.Fatal("run operation did not start")
			return nil
		}
	}
}

// waitProcessReady waits for a readiness file to appear, polling with short intervals.
// Returns immediately if the file already exists.
func waitProcessReady(t *testing.T, readyFile string) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(readyFile); err == nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, err := os.Stat(readyFile); err != nil {
		t.Fatal("process did not become ready in time")
	}
}

// makeSleepCmd returns an ExecCommandContext that creates a sleep process.
func makeSleepCmd() func(context.Context, string, ...string) *exec.Cmd {
	return func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/sleep", "60")
	}
}

// makeIgnoringSignalCmd returns an ExecCommandContext that creates a process
// ignoring SIGTERM. It uses a pre-built helper binary that ignores SIGTERM,
// signals readiness via a file, then blocks.
func makeIgnoringSignalCmd(t *testing.T, readyFile string) func(context.Context, string, ...string) *exec.Cmd {
	// Build the helper binary once per test.
	helperBin := filepath.Join(t.TempDir(), "helper")
	if err := exec.Command("go", "build", "-o", helperBin, "testhelper_ignore_sigterm.go").Run(); err != nil {
		t.Fatalf("failed to build helper binary: %v", err)
	}

	return func(ctx context.Context, name string, args ...string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, helperBin)
		cmd.Env = append(os.Environ(), "READY_FILE="+readyFile)
		return cmd
	}
}
