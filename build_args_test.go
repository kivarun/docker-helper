package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildArgsProducesExpectedArgv(t *testing.T) {
	app := newTestAppWithAdminTokenAndStaging(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	dockerfilePath := filepath.Join(result.Session.Workspace, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM alpine"), 0644); err != nil {
		t.Fatalf("cannot create Dockerfile: %v", err)
	}

	var capturedArgs []string
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		capturedArgs = args
		return exec.CommandContext(ctx, "true")
	}

	body := map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
		"build_args": map[string]any{
			"FOO":     "bar",
			"VERSION": "1.2.3",
		},
	}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/build", strings.NewReader(string(data)))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	// Verify --build-arg entries are present.
	foundFoo := false
	foundVersion := false
	for i, arg := range capturedArgs {
		if arg == "--build-arg" {
			next := capturedArgs[i+1]
			if next == "FOO=bar" {
				foundFoo = true
			}
			if next == "VERSION=1.2.3" {
				foundVersion = true
			}
		}
	}
	if !foundFoo {
		t.Error("expected --build-arg FOO=bar in command args")
	}
	if !foundVersion {
		t.Error("expected --build-arg VERSION=1.2.3 in command args")
	}
}

func TestBuildArgsDeterministicOrder(t *testing.T) {
	app := newTestAppWithAdminTokenAndStaging(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	dockerfilePath := filepath.Join(result.Session.Workspace, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM alpine"), 0644); err != nil {
		t.Fatalf("cannot create Dockerfile: %v", err)
	}

	var capturedArgs []string
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		capturedArgs = args
		return exec.CommandContext(ctx, "true")
	}

	body := map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
		"build_args": map[string]any{
			"ZEBRA": "z",
			"ALPHA": "a",
			"MIKE":  "m",
		},
	}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/build", strings.NewReader(string(data)))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	// Extract build-arg values in order.
	var argOrder []string
	for i, arg := range capturedArgs {
		if arg == "--build-arg" {
			parts := strings.SplitN(capturedArgs[i+1], "=", 2)
			if len(parts) == 2 {
				argOrder = append(argOrder, parts[0])
			}
		}
	}

	expected := []string{"ALPHA", "MIKE", "ZEBRA"}
	if len(argOrder) != len(expected) {
		t.Fatalf("got %d build args, want %d", len(argOrder), len(expected))
	}
	for i, want := range expected {
		if argOrder[i] != want {
			t.Errorf("arg[%d] = %q, want %q", i, argOrder[i], want)
		}
	}
}

func TestBuildArgsEmptyValue(t *testing.T) {
	app := newTestAppWithAdminTokenAndStaging(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	dockerfilePath := filepath.Join(result.Session.Workspace, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM alpine"), 0644); err != nil {
		t.Fatalf("cannot create Dockerfile: %v", err)
	}

	var capturedArgs []string
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		capturedArgs = args
		return exec.CommandContext(ctx, "true")
	}

	body := map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
		"build_args": map[string]any{
			"EMPTY": "",
		},
	}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/build", strings.NewReader(string(data)))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	found := false
	for i, arg := range capturedArgs {
		if arg == "--build-arg" && capturedArgs[i+1] == "EMPTY=" {
			found = true
		}
	}
	if !found {
		t.Error("expected --build-arg EMPTY= in command args")
	}
}

func TestBuildArgsInvalidKeyRejected(t *testing.T) {
	app := newTestAppWithAdminTokenAndStaging(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	dockerfilePath := filepath.Join(result.Session.Workspace, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM alpine"), 0644); err != nil {
		t.Fatalf("cannot create Dockerfile: %v", err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		t.Fatal("ExecCommandContext should not be called for invalid build args")
		return exec.CommandContext(ctx, "true")
	}

	body := map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
		"build_args": map[string]any{
			"123INVALID": "value",
		},
	}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/build", strings.NewReader(string(data)))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d", http.StatusBadRequest, w.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["code"] != "invalid_build_args" {
		t.Errorf("expected code 'invalid_build_args', got %v", resp["code"])
	}
}

func TestBuildArgsOmittedPreservesBehavior(t *testing.T) {
	app := newTestAppWithAdminTokenAndStaging(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	dockerfilePath := filepath.Join(result.Session.Workspace, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM alpine"), 0644); err != nil {
		t.Fatalf("cannot create Dockerfile: %v", err)
	}

	var capturedArgs []string
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		capturedArgs = args
		return exec.CommandContext(ctx, "true")
	}

	body := map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/build", strings.NewReader(string(data)))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	// No --build-arg should be present.
	for _, arg := range capturedArgs {
		if arg == "--build-arg" {
			t.Error("unexpected --build-arg when build_args is omitted")
		}
	}
}

func TestBuildArgsAuditContainsKeysNotValues(t *testing.T) {
	auditBuf := new(bytes.Buffer)
	initLoggers(new(bytes.Buffer), auditBuf, slog.LevelInfo, true)
	defer logging.reset()

	app := newTestAppWithAdminTokenAndStaging(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	dockerfilePath := filepath.Join(result.Session.Workspace, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM alpine"), 0644); err != nil {
		t.Fatalf("cannot create Dockerfile: %v", err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "true")
	}

	body := map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
		"build_args": map[string]any{
			"SECRET_KEY": "supersecret123",
			"VERSION":    "1.0.0",
		},
	}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/build", strings.NewReader(string(data)))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	// Wait for the build to complete.
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	opID, _ := resp["operation_id"].(string)
	op := app.OperationSupervisor.lookup(opID)
	if op == nil {
		t.Fatal("operation not found")
	}
	op.Wait()

	// Parse audit records.
	records := parseAuditRecords(auditBuf)
	sessionRecords := filterBySession(records, result.Session.ID)

	// Find build.start and build.finish records.
	var startFound, finishFound bool
	for _, r := range sessionRecords {
		switch r.Event {
		case "build.start":
			startFound = true
			if len(r.BuildArgKeys) != 2 {
				t.Fatalf("build.start: expected 2 build_arg_keys, got %d", len(r.BuildArgKeys))
			}
			keySet := make(map[string]bool)
			for _, k := range r.BuildArgKeys {
				keySet[k] = true
			}
			if !keySet["SECRET_KEY"] || !keySet["VERSION"] {
				t.Errorf("build.start build_arg_keys missing expected keys: %v", r.BuildArgKeys)
			}
		case "build.finish":
			finishFound = true
			if len(r.BuildArgKeys) != 2 {
				t.Fatalf("build.finish: expected 2 build_arg_keys, got %d", len(r.BuildArgKeys))
			}
		}
	}

	if !startFound {
		t.Error("build.start audit record not found")
	}
	if !finishFound {
		t.Error("build.finish audit record not found")
	}

	// Verify values are NOT in audit output.
	auditOutput := auditBuf.String()
	if strings.Contains(auditOutput, "supersecret123") {
		t.Error("build-arg value leaked into audit")
	}
	if strings.Contains(auditOutput, "1.0.0") {
		t.Error("build-arg value leaked into audit")
	}
}

func TestValidateBuildArgs(t *testing.T) {
	tests := []struct {
		name    string
		args    map[string]string
		want    []string
		wantErr bool
	}{
		{
			name:    "nil map",
			args:    nil,
			want:    nil,
			wantErr: false,
		},
		{
			name:    "empty map",
			args:    map[string]string{},
			want:    nil,
			wantErr: false,
		},
		{
			name:    "single valid",
			args:    map[string]string{"FOO": "bar"},
			want:    []string{"FOO"},
			wantErr: false,
		},
		{
			name:    "multiple sorted",
			args:    map[string]string{"Z": "1", "A": "2"},
			want:    []string{"A", "Z"},
			wantErr: false,
		},
		{
			name:    "underscore prefix",
			args:    map[string]string{"_FOO": "bar"},
			want:    []string{"_FOO"},
			wantErr: false,
		},
		{
			name:    "digit in middle",
			args:    map[string]string{"FOO123": "bar"},
			want:    []string{"FOO123"},
			wantErr: false,
		},
		{
			name:    "invalid digit start",
			args:    map[string]string{"1FOO": "bar"},
			wantErr: true,
		},
		{
			name:    "invalid hyphen",
			args:    map[string]string{"FOO-BAR": "baz"},
			wantErr: true,
		},
		{
			name:    "invalid space",
			args:    map[string]string{"FOO BAR": "baz"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keys, err := validateBuildArgs(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateBuildArgs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if len(keys) != len(tt.want) {
				t.Errorf("got %d keys, want %d", len(keys), len(tt.want))
				return
			}
			for i, want := range tt.want {
				if keys[i] != want {
					t.Errorf("keys[%d] = %q, want %q", i, keys[i], want)
				}
			}
		})
	}
}
