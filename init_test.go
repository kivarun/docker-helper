package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitExplicitAllowedRoot(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	t.Setenv("DOCKER_HELPER_CONFIG", configPath)
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(dir, "runtime"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))

	allowedRoot := filepath.Join(testAllowedRootDir(t), "workspaces")
	if err := os.MkdirAll(allowedRoot, 0755); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"init", "--allowed-root", allowedRoot}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("init exited %d, stderr: %s", code, stderr.String())
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}

	var fc fileConfig
	if err := json.Unmarshal(data, &fc); err != nil {
		t.Fatalf("parse config: %v", err)
	}
	if fc.AllowedRoot != allowedRoot {
		t.Errorf("allowed_root = %q, want %q", fc.AllowedRoot, allowedRoot)
	}
}

func TestInitNonInteractiveNoFlag(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	t.Setenv("DOCKER_HELPER_CONFIG", configPath)
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(dir, "runtime"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"init"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit code 2, got %d", code)
	}
	if !strings.Contains(stderr.String(), "--allowed-root is required in non-interactive mode") {
		t.Errorf("expected non-interactive error, got: %s", stderr.String())
	}
}

func TestInitInvalidAllowedRootNonExistent(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	t.Setenv("DOCKER_HELPER_CONFIG", configPath)
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(dir, "runtime"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"init", "--allowed-root", filepath.Join(dir, "no-such-dir")}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit code 2, got %d", code)
	}
	if !strings.Contains(stderr.String(), "does not exist") {
		t.Errorf("expected 'does not exist' error, got: %s", stderr.String())
	}
}

func TestInitInvalidAllowedRootNotDirectory(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	t.Setenv("DOCKER_HELPER_CONFIG", configPath)
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(dir, "runtime"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))

	file := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"init", "--allowed-root", file}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit code 2, got %d", code)
	}
	if !strings.Contains(stderr.String(), "not a directory") {
		t.Errorf("expected 'not a directory' error, got: %s", stderr.String())
	}
}

func TestInitHelpContainsAllowedRoot(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"init", "--help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("init --help exited %d", code)
	}
	if !strings.Contains(stdout.String(), "--allowed-root") {
		t.Error("init --help should contain --allowed-root flag")
	}
}

func TestInitHelpDescribesInteractiveBehavior(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"init", "--help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("init --help exited %d", code)
	}
	out := stdout.String()
	for _, want := range []string{
		"prompted",
		"current working directory",
		"default",
		"non-interactive",
	} {
		if !strings.Contains(strings.ToLower(out), strings.ToLower(want)) {
			t.Errorf("init --help should mention %q, got:\n%s", want, out)
		}
	}
}

func TestResolveAllowedRootEmptyRejected(t *testing.T) {
	_, err := resolveAllowedRoot("")
	if err == nil {
		t.Fatal("expected error for empty path")
	}
}

func TestResolveAllowedRootRelativePath(t *testing.T) {
	dir := testAllowedRootDir(t)
	subdir := filepath.Join(dir, "sub")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatal(err)
	}

	cwd, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(cwd)

	resolved, err := resolveAllowedRoot("sub")
	if err != nil {
		t.Fatalf("resolveAllowedRoot(\"sub\") = error: %v", err)
	}
	if resolved != subdir {
		t.Errorf("resolveAllowedRoot(\"sub\") = %q, want %q", resolved, subdir)
	}
}

func TestResolveAllowedRootNonExistent(t *testing.T) {
	_, err := resolveAllowedRoot("/no/such/path/that/exists/nowhere")
	if err == nil {
		t.Error("expected error for non-existent path")
	}
}

func TestResolveAllowedRootNotDirectory(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := resolveAllowedRoot(file)
	if err == nil {
		t.Error("expected error for non-directory path")
	}
}

func TestResolveAllowedRootTildeExpansion(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("cannot determine home directory")
	}

	resolved, err := resolveAllowedRoot("~")
	if err != nil {
		t.Fatalf("resolveAllowedRoot(\"~\") = error: %v", err)
	}
	if resolved != home {
		t.Errorf("resolveAllowedRoot(\"~\") = %q, want %q", resolved, home)
	}
}

func TestResolveAllowedRootTildeSubdirExpansion(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("cannot determine home directory")
	}

	resolved, err := resolveAllowedRoot("~/..")
	expected, _ := filepath.EvalSymlinks(filepath.Join(home, ".."))
	// The parent of home may be a forbidden wide namespace (e.g., /home).
	// In that case, the policy check should reject it.
	if err != nil {
		if !strings.Contains(err.Error(), "forbidden") && !strings.Contains(err.Error(), "too broad") {
			t.Fatalf("resolveAllowedRoot(\"~/..\") = unexpected error: %v", err)
		}
		return
	}
	if resolved != expected {
		t.Errorf("resolveAllowedRoot(\"~/..\") = %q, want %q", resolved, expected)
	}
}

func TestExpandTildeNoExpansion(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"/absolute/path", "/absolute/path"},
		{"relative/path", "relative/path"},
		{"~nottilde", "~nottilde"},
	}
	for _, tt := range tests {
		got := expandTilde(tt.input)
		if got != tt.want {
			t.Errorf("expandTilde(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestPromptAllowedRootEmptyInput(t *testing.T) {
	input := strings.NewReader("\n")
	var buf bytes.Buffer
	result, err := promptAllowedRoot("/default", input, &buf)
	if err != nil {
		t.Fatalf("promptAllowedRoot error: %v", err)
	}
	if result != "/default" {
		t.Errorf("promptAllowedRoot = %q, want %q", result, "/default")
	}
}

func TestPromptAllowedRootCustomInput(t *testing.T) {
	input := strings.NewReader("/custom/path\n")
	var buf bytes.Buffer
	result, err := promptAllowedRoot("/default", input, &buf)
	if err != nil {
		t.Fatalf("promptAllowedRoot error: %v", err)
	}
	if result != "/custom/path" {
		t.Errorf("promptAllowedRoot = %q, want %q", result, "/custom/path")
	}
}

func TestPromptOutputGoesToStderr(t *testing.T) {
	input := strings.NewReader("\n")
	var buf bytes.Buffer
	_, err := promptAllowedRoot("/default", input, &buf)
	if err != nil {
		t.Fatalf("promptAllowedRoot error: %v", err)
	}
	if !strings.Contains(buf.String(), "Enter allowed root directory") {
		t.Error("prompt should write to stderr")
	}
	if !strings.Contains(buf.String(), "/default") {
		t.Error("prompt should show default value")
	}
}

func TestResolveAllowedRootForInitWithFlag(t *testing.T) {
	allowedRoot := filepath.Join(testAllowedRootDir(t), "workspaces")
	if err := os.MkdirAll(allowedRoot, 0755); err != nil {
		t.Fatal(err)
	}

	resolved, err := resolveAllowedRootForInit(allowedRoot, nil, nil, false)
	if err != nil {
		t.Fatalf("resolveAllowedRootForInit = error: %v", err)
	}
	if resolved != allowedRoot {
		t.Errorf("resolveAllowedRootForInit = %q, want %q", resolved, allowedRoot)
	}
}

func TestResolveAllowedRootForInitNoFlagNonTerminal(t *testing.T) {
	_, err := resolveAllowedRootForInit("", nil, nil, false)
	if err == nil {
		t.Error("expected error for non-interactive mode without flag")
	}
	if !strings.Contains(err.Error(), "non-interactive") {
		t.Errorf("expected non-interactive error, got: %v", err)
	}
}

func TestResolveAllowedRootForInitNoFlagTerminal(t *testing.T) {
	dir := testAllowedRootDir(t)
	cwd, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(cwd)

	input := strings.NewReader("\n")
	var buf bytes.Buffer
	resolved, err := resolveAllowedRootForInit("", input, &buf, true)
	if err != nil {
		t.Fatalf("resolveAllowedRootForInit = error: %v", err)
	}
	if resolved != dir {
		t.Errorf("resolveAllowedRootForInit = %q, want %q (CWD default)", resolved, dir)
	}
}

func TestResolveAllowedRootForInitTerminalCustomInput(t *testing.T) {
	allowedRoot := filepath.Join(testAllowedRootDir(t), "custom-workspaces")
	if err := os.MkdirAll(allowedRoot, 0755); err != nil {
		t.Fatal(err)
	}

	input := strings.NewReader(allowedRoot + "\n")
	var buf bytes.Buffer
	resolved, err := resolveAllowedRootForInit("", input, &buf, true)
	if err != nil {
		t.Fatalf("resolveAllowedRootForInit = error: %v", err)
	}
	if resolved != allowedRoot {
		t.Errorf("resolveAllowedRootForInit = %q, want %q", resolved, allowedRoot)
	}
}
