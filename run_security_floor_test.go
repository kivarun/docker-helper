package main

// The workload privilege floor is the server-owned Docker execution floor
// every docker-helper run workload carries: Linux no-new-privileges is
// enforced and container capabilities are dropped (ALL) before any
// caller-owned or backend-owned option is appended. The caller has no
// request field that can disable or weaken the floor, and the workload MAC
// --security-opt options stay additional independent confinement layers.
//
// These tests protect the floor invariant at the run argv owner for both
// modes; the hostile live escalation proof runs in the backend-specific
// workload UAT owners (uat-workload-apparmor.sh, uat-workload-selinux.sh).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

// assertRunWorkloadPrivilegeFloor proves the floor invariants on one
// captured docker run argv:
//   - exactly one --cap-drop ALL pair and one
//     --security-opt no-new-privileges:true pair are present;
//   - the caller has no privilege-widening surface in argv at all
//     (--privileged, --cap-add, and --user override are absent as callers
//     cannot compose them);
//   - the floor flags precede every MAC --security-opt option, so a
//     backend option list can never replace the floor.
func assertRunWorkloadPrivilegeFloor(t *testing.T, args []string, wantMACOpts []string) {
	t.Helper()

	var capDropIndexes []int
	var nnpIndexes []int
	for i := 0; i+1 < len(args); i++ {
		switch args[i] {
		case "--cap-drop":
			capDropIndexes = append(capDropIndexes, i)
		case "--security-opt":
			if args[i+1] == "no-new-privileges:true" {
				nnpIndexes = append(nnpIndexes, i)
			}
		}
	}
	if len(capDropIndexes) != 1 || len(nnpIndexes) != 1 {
		t.Fatalf("privilege floor not emitted exactly once: --cap-drop pairs at %v, no-new-privileges pairs at %v in %v", capDropIndexes, nnpIndexes, args)
	}
	if args[capDropIndexes[0]+1] != "ALL" {
		t.Fatalf("--cap-drop value = %q, want ALL (capabilities dropped by default)", args[capDropIndexes[0]+1])
	}

	for _, forbidden := range []string{"--privileged", "--cap-add"} {
		for _, arg := range args {
			if arg == forbidden || strings.HasPrefix(arg, forbidden+"=") {
				t.Fatalf("privilege-widening flag %q reached Docker argv: %v", forbidden, args)
			}
		}
	}

	if len(wantMACOpts) > 0 {
		floorIndex := capDropIndexes[0]
		for _, macOpt := range wantMACOpts {
			macIndex := -1
			for i := 0; i+1 < len(args); i++ {
				if args[i] == "--security-opt" && args[i+1] == macOpt {
					macIndex = i
					break
				}
			}
			if macIndex < 0 {
				t.Fatalf("MAC security option %q absent from argv %v", macOpt, args)
			}
			if macIndex < floorIndex {
				t.Fatalf("MAC security option %q precedes the privilege floor: %v", macOpt, args)
			}
		}
	}
}

// securityOptValue returns the value of the first --security-opt pair with
// the given prefix, or "" when absent.
func securityOptValue(args []string, prefix string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "--security-opt" && strings.HasPrefix(args[i+1], prefix) {
			return args[i+1]
		}
	}
	return ""
}

// runWithCapturedDockerArgs performs one run request through the production
// handler with the default image request and returns the captured docker
// argv and the HTTP status code.
func runWithCapturedDockerArgs(t *testing.T, app *App, token string, request map[string]any) ([]string, int) {
	t.Helper()

	waitAllOperationsTerminal(t, app)

	var mu sync.Mutex
	var capturedArgs []string
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		if len(args) > 0 && args[0] == "--config" && args[2] == "run" {
			mu.Lock()
			capturedArgs = args
			mu.Unlock()
		}
		return exec.CommandContext(ctx, "/bin/true")
	}

	body, _ := json.Marshal(request)
	req := httptest.NewRequest(http.MethodPost, "/run", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	app.handleRun(w, req)

	mu.Lock()
	defer mu.Unlock()
	return capturedArgs, w.Code
}

// waitAllOperationsTerminal waits (bounded) until every operation the
// supervisor currently holds has reached a terminal state, so a repeated
// ExecCommandContext seam assignment cannot race a prior operation's
// cleanup goroutine.
func waitAllOperationsTerminal(t *testing.T, app *App) {
	t.Helper()
	if app.OperationSupervisor == nil {
		return
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		app.OperationSupervisor.mu.RLock()
		var pending []*operation
		for _, op := range app.OperationSupervisor.ops {
			op.mu.Lock()
			terminal := op.CompletedAt != nil
			op.mu.Unlock()
			if !terminal {
				pending = append(pending, op)
			}
		}
		app.OperationSupervisor.mu.RUnlock()
		if len(pending) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("operations did not reach a terminal state in time")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestRunWorkloadPrivilegeFloor proves the captured docker run argv carries
// the server-owned privilege floor and the fixed label=disable policy stays
// present.
func TestRunWorkloadPrivilegeFloor(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0].Path))
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}

	args, code := runWithCapturedDockerArgs(t, app, result.Token, map[string]any{"image": "alpine:latest"})
	if code != http.StatusCreated {
		t.Fatalf("run status = %d, want 201", code)
	}

	assertRunWorkloadPrivilegeFloor(t, args, []string{"label=disable"})
}

// TestRunWorkloadPrivilegeFloorSystemModeAppArmor proves the system-mode
// AppArmor floor composition: the privilege floor is emitted by the same
// run argv owner and the backend security options select the generated
// workload profile as before.
func TestRunWorkloadPrivilegeFloorSystemModeAppArmor(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	installTestWorkloadMACForTest(t, app, LSMAppArmor)

	result, err := createSystemSession(t, app)
	if err != nil {
		t.Fatalf("createSystemSession() error: %v", err)
	}

	args, code := runWithCapturedDockerArgs(t, app, result.Token, map[string]any{"image": "alpine:latest"})
	if code != http.StatusCreated {
		t.Fatalf("run status = %d, want 201", code)
	}

	apparmorOpt := securityOptValue(args, "apparmor=")
	if apparmorOpt == "" {
		t.Fatalf("generated workload profile not selected in argv %v", args)
	}
	assertRunWorkloadPrivilegeFloor(t, args, []string{"label=disable", apparmorOpt})
}

// TestRunWorkloadPrivilegeFloorSystemModeSELinux proves the system-mode
// SELinux floor composition: the privilege floor is emitted by the same run
// argv owner and the SELinux type selection stays present.
func TestRunWorkloadPrivilegeFloorSystemModeSELinux(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	installTestWorkloadMACForTest(t, app, LSMSELinux)

	result, err := createSystemSession(t, app)
	if err != nil {
		t.Fatalf("createSystemSession() error: %v", err)
	}

	args, code := runWithCapturedDockerArgs(t, app, result.Token, map[string]any{"image": "alpine:latest"})
	if code != http.StatusCreated {
		t.Fatalf("run status = %d, want 201", code)
	}

	assertRunWorkloadPrivilegeFloor(t, args, []string{"label=type:docker_helper_container_t"})
}

// TestRunWorkloadPrivilegeFloorRequestInvariant proves the floor cannot be
// disabled or weakened by the caller: a request carrying mounts and
// environment receives the identical floor (the run request contract has no
// privilege field), and an unknown privilege-shaped field is rejected by
// strict request decoding instead of silently widening the floor.
func TestRunWorkloadPrivilegeFloorRequestInvariant(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0].Path))
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}

	fullRequest := map[string]any{
		"image":   "alpine:latest",
		"command": []string{"sh"},
	}
	args, code := runWithCapturedDockerArgs(t, app, result.Token, fullRequest)
	if code != http.StatusCreated {
		t.Fatalf("run status = %d, want 201", code)
	}
	assertRunWorkloadPrivilegeFloor(t, args, []string{"label=disable"})

	// A privilege-widening request field does not exist in the run contract;
	// a caller sending one must not reach Docker with widened privileges.
	privilegedRequest := map[string]any{
		"image":      "alpine:latest",
		"privileged": true,
	}
	_, code = runWithCapturedDockerArgs(t, app, result.Token, privilegedRequest)
	if code == http.StatusCreated {
		t.Fatalf("a privileged run request was accepted (status 201); the run contract must not carry privilege widening")
	}
}
