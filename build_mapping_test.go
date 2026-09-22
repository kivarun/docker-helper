package main

// build_mapping_test.go freezes the exact server-owned buildctl argv
// mapping (Release-2.4 §8/§10) end to end through the production build
// handler and driver: fixed address (the opSocketPath-derived BuildKit
// endpoint), fixed frontend/progress, staged --local paths only, the
// --opt filename derivation, sorted build args, and the one internal-tag
// docker exporter. Nothing caller-controlled may appear: no requested
// image, no original workspace paths, no unauthorized options, no
// credentials, no socket/frontend/network/entitlements/cache/exporter
// override.

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// assertBuildctlExactArgv proves the complete exact buildctl argv for one
// completed backend build: fixed flags in the frozen order, staged paths,
// and every absence contract. It is the shared proof body for the root,
// nested, and custom-filename mappings. dockerfileRel is the request's
// Dockerfile spelling; the expected --local dockerfile dir is derived
// mechanically from the staged context exactly as the production mapping
// does (staged context root for a root/custom Dockerfile, the staged
// parent directory for a nested one).
func assertBuildctlExactArgv(t *testing.T, app *App, token string, body map[string]any, calls *recordedCalls, dockerfileRel string) []string {
	t.Helper()

	req := newBuildRequest(body, token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d: %s", http.StatusCreated, w.Code, w.Body.String())
	}
	waitBuild(t, app, w)

	args := buildctlCall(t, calls)

	// Staged paths supplied by the staging owner.
	stagedContext := calls.contextPathOf(calls.buildctlIndex())
	if stagedContext == "" {
		t.Fatalf("staged context path missing from argv: %v", args)
	}

	// The requested image spelling never appears anywhere in argv.
	image := body["image"].(string)
	if joined := strings.Join(args, "\x00"); strings.Contains(joined, image) {
		t.Errorf("requested image %q must not appear in buildctl argv: %v", image, args)
	}

	// The op ID is derived from the staged context path: the staging
	// layout is <staging-root>/<op_id>/context.
	opID := filepath.Base(filepath.Dir(stagedContext))

	// Exactly one --addr and it is the deterministic op-owned socket.
	var addrs []string
	for i, arg := range args {
		if arg == "--addr" {
			if i+1 >= len(args) {
				t.Fatal("--addr without a value")
			}
			addrs = append(addrs, args[i+1])
		}
	}
	if len(addrs) != 1 {
		t.Fatalf("exactly one --addr expected, got %v in %v", addrs, args)
	}
	wantAddr := "unix://" + opSocketPath(opID)
	if addrs[0] != wantAddr {
		t.Errorf("--addr = %q, want %q", addrs[0], wantAddr)
	}

	// The frozen fixed prefix (§8): --addr, build, progress, frontend,
	// staged context, staged dockerfile dir, filename.
	dockerfileDir := stagedContext
	if rel := filepath.Dir(dockerfileRel); rel != "." {
		dockerfileDir = filepath.Join(stagedContext, rel)
	}
	wantPrefix := []string{
		"--addr", wantAddr,
		"build",
		"--progress=plain",
		"--frontend=dockerfile.v0",
		"--local", "context=" + stagedContext,
		"--local", "dockerfile=" + dockerfileDir,
	}
	for i, want := range wantPrefix {
		if args[i] != want {
			t.Errorf("argv[%d] = %q, want %q (full argv %v)", i, args[i], want, args)
		}
	}

	// --opt filename names exactly the staged Dockerfile basename.
	wantFilename := filepath.Base(body["dockerfile"].(string))
	if got := optValue(t, args, "filename"); got != wantFilename {
		t.Errorf("--opt filename = %q, want %q", got, wantFilename)
	}

	// --output: the one internal-tag docker exporter into the staged
	// export tar inside the operation staging tree.
	var outputs []string
	for i, arg := range args {
		if arg == "--output" {
			if i+1 >= len(args) {
				t.Fatal("--output without a value")
			}
			outputs = append(outputs, args[i+1])
		}
	}
	if len(outputs) != 1 {
		t.Fatalf("exactly one --output expected, got %v in %v", outputs, args)
	}
	wantOutput := "type=docker,name=" + buildInternalTag(opID) + ",dest=" + filepath.Join(filepath.Dir(stagedContext), buildExportTarName)
	if outputs[0] != wantOutput {
		t.Errorf("--output = %q, want %q", outputs[0], wantOutput)
	}

	// No caller-controlled backend options: every --opt element must be a
	// filename or build-arg (the only authorized opt kinds), and the
	// forbidden option flags must be absent entirely.
	forbiddenFlags := map[string]bool{
		"--allow": true, "--network": true, "--exporter": true,
		"--oci": true, "--tar": true, "--push": true, "--unlock": true,
		"--no-cache": true, "--cache-from": true, "--cache-to": true,
		"--frontend-opts": true, "--local-dir": true, "--oci-cdi": true,
	}
	for i, arg := range args {
		if forbiddenFlags[arg] {
			t.Errorf("forbidden buildctl option %q present in argv: %v", arg, args)
		}
		if arg == "--opt" && i+1 < len(args) {
			v := args[i+1]
			if !strings.HasPrefix(v, "filename=") && !strings.HasPrefix(v, "build-arg:") {
				t.Errorf("unauthorized --opt element %q in argv: %v", v, args)
			}
		}
	}
	for _, banned := range []string{"network.host", "security.insecure"} {
		if strings.Contains(strings.Join(args, "\x00"), banned) {
			t.Errorf("forbidden opt vocabulary %q present in argv: %v", banned, args)
		}
	}

	// The original workspace path must never leak into argv.
	if joined := strings.Join(args, "\x00"); strings.Contains(joined, app.Config.AllowedRoots[0].Path) {
		t.Errorf("original workspace path leaked into buildctl argv: %v", args)
	}

	// Credentials: the buildctl child env carries only DOCKER_CONFIG and it
	// names the session Docker config directory (never a credential value).
	envIdx := calls.buildctlIndex()
	env := calls.env(envIdx)
	if len(env) != 1 || !strings.HasPrefix(env[0], "DOCKER_CONFIG=") {
		t.Errorf("buildctl env = %d entries (%q first), want exactly DOCKER_CONFIG", len(env), firstEnvEntry(env))
	}

	return args
}

// firstEnvEntry returns a bounded preview of the first env entry for
// diagnostics (never a full env dump; credentials must not appear in test
// failure output).
func firstEnvEntry(env []string) string {
	if len(env) == 0 {
		return ""
	}
	if len(env[0]) > 40 {
		return env[0][:40] + "..."
	}
	return env[0]
}

// TestBuildMappingRootDockerfile proves the exact buildctl argv for the
// root Dockerfile mapping (dockerfile=Dockerfile): --local dockerfile is
// the staged context root and --opt filename is the plain basename.
func TestBuildMappingRootDockerfile(t *testing.T) {
	app, _, result, _, calls := setupBuildBackendTest(t)

	assertBuildctlExactArgv(t, app, result.Token, map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, calls, "Dockerfile")
}

// TestBuildMappingNestedDockerfile proves the exact buildctl argv for a
// nested Dockerfile (dockerfile=sub/dir/Dockerfile): --local dockerfile is
// the staged SUBDIRECTORY (buildctl's filename is relative to its
// dockerfile local dir) and --opt filename stays the plain basename.
func TestBuildMappingNestedDockerfile(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0].Path))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	// The staging owner copies the Dockerfile at exactly the validated
	// relative path inside the staged context, so the workspace must
	// contain the nested Dockerfile before the build.
	nested := filepath.Join(result.Session.Workspace, "sub", "dir")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "Dockerfile"), []byte("FROM alpine"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(result.Session.Workspace, "data.txt"), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}

	manager, calls := attachBackendFixture(t, app)
	_ = manager

	args := assertBuildctlExactArgv(t, app, result.Token, map[string]any{
		"context":    ".",
		"dockerfile": "sub/dir/Dockerfile",
		"image":      "example:test",
	}, calls, "sub/dir/Dockerfile")

	if got := optValue(t, args, "filename"); got != "Dockerfile" {
		t.Errorf("--opt filename = %q, want Dockerfile", got)
	}
}

// TestBuildMappingCustomFilename proves the custom Dockerfile filename
// mapping (dockerfile=build.prod): --opt filename carries the exact custom
// basename and the dockerfile dir is the staged context root.
func TestBuildMappingCustomFilename(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0].Path))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	// The staging owner copies the Dockerfile at exactly the validated
	// relative path inside the staged context, so the workspace must
	// contain the custom-named Dockerfile before the build.
	if err := os.WriteFile(filepath.Join(result.Session.Workspace, "build.prod"), []byte("FROM alpine"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(result.Session.Workspace, "data.txt"), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}

	manager, calls := attachBackendFixture(t, app)
	_ = manager

	assertBuildctlExactArgv(t, app, result.Token, map[string]any{
		"context":    ".",
		"dockerfile": "build.prod",
		"image":      "example:test",
	}, calls, "build.prod")
}

// TestBuildMappingSortedBuildArgsInArgv proves the build-arg values are
// mapped in sorted-key order with exact KEY=VALUE spelling, including a
// value containing '='.
func TestBuildMappingSortedBuildArgsInArgv(t *testing.T) {
	app, _, result, _, calls := setupBuildBackendTest(t)

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
		"build_args": map[string]any{
			"ZEBRA": "z=v",
			"ALPHA": "a",
			"MIKE":  "m",
		},
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}
	waitBuild(t, app, w)

	args := buildctlCall(t, calls)
	var got []string
	for i, arg := range args {
		if arg == "--opt" && i+1 < len(args) {
			if v, ok := strings.CutPrefix(args[i+1], "build-arg:"); ok {
				got = append(got, v)
			}
		}
	}
	want := []string{"ALPHA=a", "MIKE=m", "ZEBRA=z=v"}
	if len(got) != len(want) {
		t.Fatalf("build args = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("build args[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestBuildMappingAbsenceNoUnauthorizedOptions proves the requested image,
// original workspace paths, unauthorized backend options, and any
// credential material never appear in the recorded buildctl invocation.
func TestBuildMappingAbsenceNoUnauthorizedOptions(t *testing.T) {
	app, _, result, _, calls := setupBuildBackendTest(t)

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "registry.example.com/team/app:tag",
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}
	waitBuild(t, app, w)

	args := buildctlCall(t, calls)
	joined := strings.Join(args, "\x00")

	// No requested image (spelling or well-known name components) in argv.
	if strings.Contains(joined, "registry.example.com/team/app:tag") {
		t.Errorf("requested image in buildctl argv: %v", args)
	}
	// No unauthorized options at all.
	for _, f := range []string{"--allow", "--network", "--exporter", "--push", "--unlock", "--no-cache", "--cache-from", "--cache-to"} {
		for _, arg := range args {
			if arg == f {
				t.Errorf("unauthorized option %q in buildctl argv: %v", f, args)
			}
		}
	}
	// No original workspace path.
	if strings.Contains(joined, app.Config.AllowedRoots[0].Path) {
		t.Errorf("workspace path in buildctl argv: %v", args)
	}
	// Credential owner env only: exactly DOCKER_CONFIG pointing at the
	// session Docker config dir; no auth-bearing env, no token values.
	env := calls.env(calls.buildctlIndex())
	if len(env) != 1 || !strings.HasPrefix(env[0], "DOCKER_CONFIG=") {
		t.Errorf("buildctl env = %d entries (%q first), want exactly DOCKER_CONFIG", len(env), firstEnvEntry(env))
	} else {
		sessionDockerDir := sessionDockerDir(app.Config.RuntimeDir, result.Session.ID)
		if env[0] != "DOCKER_CONFIG="+sessionDockerDir {
			t.Errorf("DOCKER_CONFIG = %q, want the session Docker config dir %q", env[0], sessionDockerDir)
		}
	}
}

// TestBuildMappingAbsenceSocketOwnership proves --addr uses exactly the
// shared opSocketPath owner (the P2 canonical endpoint derivation), never
// a caller-supplied socket, and that no other path vocabulary shares the
// argv.
func TestBuildMappingAbsenceSocketOwnership(t *testing.T) {
	app, _, result, _, calls := setupBuildBackendTest(t)

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}
	waitBuild(t, app, w)

	args := buildctlCall(t, calls)
	var addrArgs []string
	for i, arg := range args {
		if arg == "--addr" && i+1 < len(args) {
			addrArgs = append(addrArgs, args[i+1])
		}
	}
	if len(addrArgs) != 1 {
		t.Fatalf("exactly one --addr expected, got %v", addrArgs)
	}
	if !strings.HasPrefix(addrArgs[0], "unix://") {
		t.Fatalf("--addr must be a unix endpoint, got %q", addrArgs[0])
	}
	socketPath := strings.TrimPrefix(addrArgs[0], "unix://")
	opID := filepath.Base(filepath.Dir(strings.TrimPrefix(calls.contextPathOf(calls.buildctlIndex()), app.Config.RuntimeDir)))
	if socketPath != opSocketPath(opID) {
		t.Errorf("--addr socket = %q, want opSocketPath owner %q", socketPath, opSocketPath(opID))
	}
	if !strings.HasSuffix(socketPath, "/buildkitd.sock") {
		t.Errorf("unexpected socket spelling: %q", socketPath)
	}
}

// TestBuildMappingOmittedBuildArgsProvesAbsence proves no --opt
// build-arg: element appears when build_args is omitted.
func TestBuildMappingOmittedBuildArgsProvesAbsence(t *testing.T) {
	app, _, result, _, calls := setupBuildBackendTest(t)

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}
	waitBuild(t, app, w)

	for _, arg := range buildctlCall(t, calls) {
		if strings.Contains(arg, "build-arg:") {
			t.Errorf("unexpected build-arg element %q with build_args omitted: %v", arg, buildctlCall(t, calls))
		}
	}
}

// TestBuildMappingNestedStagedLayoutCrossCheck proves the nested-Dockerfile
// argv against the REAL production staging layout (no staging seam): the
// staged Dockerfile lives exactly at ContextPath/<rel>, so the derived
// --local dockerfile dir is the staged parent directory.
func TestBuildMappingNestedStagedLayoutCrossCheck(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0].Path))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	nested := filepath.Join(result.Session.Workspace, "sub", "dir")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "Dockerfile"), []byte("FROM alpine"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(result.Session.Workspace, "data.txt"), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}

	manager, calls := attachBackendFixture(t, app)
	_ = manager

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "sub/dir/Dockerfile",
		"image":      "example:test",
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}
	waitBuild(t, app, w)

	args := buildctlCall(t, calls)
	stagedContext := calls.contextPathOf(calls.buildctlIndex())
	wantLocal := "dockerfile=" + filepath.Join(stagedContext, "sub/dir")
	found := false
	for i, arg := range args {
		if arg == "--local" && i+1 < len(args) && args[i+1] == wantLocal {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("--local dockerfile = %q missing in %v", wantLocal, args)
	}
	if got := optValue(t, args, "filename"); got != "Dockerfile" {
		t.Errorf("--opt filename = %q, want Dockerfile", got)
	}

	// The staged copy is inside the operation-scoped runtime staging tree,
	// never the workspace.
	if !strings.HasPrefix(stagedContext, app.Config.RuntimeDir) {
		t.Errorf("staged context %q outside runtime staging tree %q", stagedContext, app.Config.RuntimeDir)
	}
	if strings.Contains(stagedContext, result.Session.Workspace) {
		t.Errorf("staged context must not be the workspace: %q", stagedContext)
	}
}
