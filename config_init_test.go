package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// --- Init core tests ---

func TestInitCoreCreatesConfig(t *testing.T) {
	dir := t.TempDir()

	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return filepath.Join(dir, "config.json") }
	defer func() { getConfigPathFunc = origGetConfig }()
	origState := getStateDirFunc
	getStateDirFunc = func() string { return filepath.Join(dir, "state") }
	defer func() { getStateDirFunc = origState }()

	// Use a real directory for the allowed root
	rootDir := testAllowedRootDir(t)

	var stdout, stderr bytes.Buffer
	result, err := initCore(rootDir, &stdout, &stderr)
	if err != nil {
		t.Fatalf("initCore failed: %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.allowedRoot != rootDir {
		t.Errorf("expected allowedRoot %s, got %s", rootDir, result.allowedRoot)
	}
	if result.token == "" {
		t.Error("expected non-empty token")
	}

	// Verify config file exists
	configPath := filepath.Join(dir, "config.json")
	if _, err := os.Stat(configPath); err != nil {
		t.Errorf("config file not created: %v", err)
	}

	// Verify token file exists
	tokenPath := filepath.Join(dir, "admin.token")
	if _, err := os.Stat(tokenPath); err != nil {
		t.Errorf("token file not created: %v", err)
	}
}

func TestInitCoreExistingTokenFails(t *testing.T) {
	dir := t.TempDir()

	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return filepath.Join(dir, "config.json") }
	defer func() { getConfigPathFunc = origGetConfig }()
	origState := getStateDirFunc
	getStateDirFunc = func() string { return filepath.Join(dir, "state") }
	defer func() { getStateDirFunc = origState }()

	// Create existing token
	tokenPath := filepath.Join(dir, "admin.token")
	if err := os.MkdirAll(filepath.Dir(tokenPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenPath, []byte("existing\n"), 0600); err != nil {
		t.Fatal(err)
	}

	rootDir := testAllowedRootDir(t)
	var stdout, stderr bytes.Buffer
	_, err := initCore(rootDir, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for existing token")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("expected 'already exists' error, got: %v", err)
	}
}

// --- System mode integration tests ---

// TestInitSystemCoreInvocation verifies that initSystem calls the core
// callback. System init no longer prepares MAC state for the bootstrap
// allowed root; MAC preparation occurs at session creation time.
func TestInitSystemCoreInvocation(t *testing.T) {
	dir := t.TempDir()

	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return filepath.Join(dir, "config.json") }
	defer func() { getConfigPathFunc = origGetConfig }()
	origState := getStateDirFunc
	getStateDirFunc = func() string { return filepath.Join(dir, "state") }
	defer func() { getStateDirFunc = origState }()

	rootDir := testAllowedRootDir(t)

	var stdout, stderr bytes.Buffer
	err := initSystem(rootDir, &stdout, &stderr, nil,
		func(ar string, so, se io.Writer) error {
			_, err := initCore(ar, so, se)
			return err
		})
	if err != nil {
		t.Fatalf("initSystem failed: %v", err)
	}
}

// TestInitSystemCoreFailurePropagates verifies that when the core callback
// fails, initSystem propagates the error.
func TestInitSystemCoreFailurePropagates(t *testing.T) {
	dir := t.TempDir()

	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return filepath.Join(dir, "config.json") }
	defer func() { getConfigPathFunc = origGetConfig }()

	rootDir := testAllowedRootDir(t)

	var stdout, stderr bytes.Buffer
	err := initSystem(rootDir, &stdout, &stderr, nil,
		func(ar string, so, se io.Writer) error {
			return errors.New("core init failed")
		})
	if err == nil {
		t.Fatal("expected error for core failure")
	}
	if !strings.Contains(err.Error(), "core init failed") {
		t.Errorf("expected core failure in error, got: %v", err)
	}
}

// TestInitSystemExistingConfigMismatch verifies that initSystem rejects a
// new root not present in an existing config.
func TestInitSystemExistingConfigMismatch(t *testing.T) {
	dir := t.TempDir()

	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return filepath.Join(dir, "config.json") }
	defer func() { getConfigPathFunc = origGetConfig }()

	// Create two real directories for the mismatch
	baseDir := testAllowedRootDir(t)
	oldRoot := filepath.Join(baseDir, "old")
	newRoot := filepath.Join(baseDir, "new")
	for _, d := range []string{oldRoot, newRoot} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}

	// Create existing config with old root
	configPath := filepath.Join(dir, "config.json")
	if err := os.MkdirAll(filepath.Dir(configPath), 0700); err != nil {
		t.Fatal(err)
	}
	configData := fmt.Sprintf(`{"allowed_root": %q, "session_ttl": "12h"}`, oldRoot)
	if err := os.WriteFile(configPath, []byte(configData), 0600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	err := initSystem(newRoot, &stdout, &stderr, nil,
		func(ar string, so, se io.Writer) error {
			t.Error("core should not be called on config mismatch")
			return nil
		})
	if err == nil {
		t.Fatal("expected error for config mismatch")
	}

	// Verify exact error message with canonical paths
	expectedMsg := fmt.Sprintf("existing configuration allowed_roots [%s] do not include %s", oldRoot, newRoot)
	if err.Error() != expectedMsg {
		t.Errorf("exact mismatch error expected\ngot:  %s\nwant: %s", err.Error(), expectedMsg)
	}
}

// TestInitSystemExistingConfigMatch verifies that initSystem proceeds when
// the new root matches an existing config root.
func TestInitSystemExistingConfigMatch(t *testing.T) {
	dir := t.TempDir()

	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return filepath.Join(dir, "config.json") }
	defer func() { getConfigPathFunc = origGetConfig }()
	origState := getStateDirFunc
	getStateDirFunc = func() string { return filepath.Join(dir, "state") }
	defer func() { getStateDirFunc = origState }()

	// Create real directory for the matching root
	rootDir := testAllowedRootDir(t)

	// Create existing config with matching allowed_root
	configPath := filepath.Join(dir, "config.json")
	if err := os.MkdirAll(filepath.Dir(configPath), 0700); err != nil {
		t.Fatal(err)
	}
	configData := fmt.Sprintf(`{"allowed_root": %q, "session_ttl": "12h"}`, rootDir)
	if err := os.WriteFile(configPath, []byte(configData), 0600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	err := initSystem(rootDir, &stdout, &stderr, nil,
		func(ar string, so, se io.Writer) error {
			_, err := initCore(ar, so, se)
			return err
		})
	if err != nil {
		t.Fatalf("initSystem failed: %v", err)
	}
}

// TestInitSystemMultiRootConfigAccepted verifies that initSystem accepts a
// root that is one of multiple existing config roots (not first-root-only).
func TestInitSystemMultiRootConfigAccepted(t *testing.T) {
	dir := t.TempDir()

	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return filepath.Join(dir, "config.json") }
	defer func() { getConfigPathFunc = origGetConfig }()

	// Create two real directories for the multi-root config.
	rootA := testAllowedRootDir(t)
	rootB := testAllowedRootDir(t)

	// Create existing config with two roots.
	configPath := filepath.Join(dir, "config.json")
	if err := os.MkdirAll(filepath.Dir(configPath), 0700); err != nil {
		t.Fatal(err)
	}
	configData := fmt.Sprintf(`{"allowed_roots": [%q, %q], "session_ttl": "12h"}`, rootA, rootB)
	if err := os.WriteFile(configPath, []byte(configData), 0600); err != nil {
		t.Fatal(err)
	}

	// Track what core receives.
	var coreReceived string

	var stdout, stderr bytes.Buffer
	err := initSystem(rootB, &stdout, &stderr, nil,
		func(ar string, so, se io.Writer) error {
			coreReceived = ar
			return nil
		})
	if err != nil {
		t.Fatalf("initSystem with rootB failed: %v", err)
	}
	if coreReceived != rootB {
		t.Errorf("core received %q, want rootB %q", coreReceived, rootB)
	}
}

// TestInitSystemExistingTokenFails verifies that initSystem rejects when an
// admin token already exists.
func TestInitSystemExistingTokenFails(t *testing.T) {
	dir := t.TempDir()

	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return filepath.Join(dir, "config.json") }
	defer func() { getConfigPathFunc = origGetConfig }()

	rootDir := testAllowedRootDir(t)

	// Create existing token
	tokenPath := filepath.Join(dir, "admin.token")
	if err := os.WriteFile(tokenPath, []byte("existing\n"), 0600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	err := initSystem(rootDir, &stdout, &stderr, nil,
		func(ar string, so, se io.Writer) error {
			t.Error("core should not be called when token exists")
			return nil
		})
	if err == nil {
		t.Fatal("expected error for existing token")
	}
}

// --- Input error exit code tests ---

func TestInitCLIInputErrorExitCode(t *testing.T) {
	dir := t.TempDir()

	// Create two real directories for the mismatch
	oldRoot := t.TempDir()
	newRoot := t.TempDir()

	// Create existing config with mismatch at a controlled path
	configPath := filepath.Join(dir, "config.json")
	configData := fmt.Sprintf(`{"allowed_root": %q, "session_ttl": "12h"}`, oldRoot)
	if err := os.WriteFile(configPath, []byte(configData), 0600); err != nil {
		t.Fatal(err)
	}

	// Mock system mode and config path.
	origUID := EffectiveUID
	origGetConfig := getConfigPathFunc
	// System init probes the MAC backend before the input validation; the
	// seam keeps this test on the intended mismatch path on every host, so
	// the asserted exit code cannot come from (or depend on) the host's own
	// MAC detection.
	origLSM := detectLSM
	detectLSM = func() (LSMBackend, error) { return LSMAppArmor, nil }
	EffectiveUID = func() int { return 0 }
	getConfigPathFunc = func() string { return configPath }
	defer func() {
		EffectiveUID = origUID
		getConfigPathFunc = origGetConfig
		detectLSM = origLSM
	}()

	// The requested root is canonicalized before the mismatch is reported.
	effective, err := resolveAllowedRoot(newRoot)
	if err != nil {
		t.Fatal(err)
	}
	wantMismatch := fmt.Sprintf("existing configuration allowed_roots [%s] do not include %s", oldRoot, effective)

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"init", "--allowed-root", newRoot}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit code 2 for input error, got %d (stderr: %s)", code, stderr.String())
	}
	// The stderr must carry the concrete existing-roots/requested-root
	// mismatch diagnostics, so the test cannot become false-green through an
	// unrelated input error on the same exit code.
	if !strings.Contains(stderr.String(), wantMismatch) {
		t.Errorf("stderr must report the allowed-roots mismatch %q, got: %s", wantMismatch, stderr.String())
	}
}

// --- Config path validation tests ---

// TestInitSystemConfigPathIsDirectory verifies that initSystem fails when
// the config path is a directory.
func TestInitSystemConfigPathIsDirectory(t *testing.T) {
	dir := t.TempDir()

	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return filepath.Join(dir, "config.json") }
	defer func() { getConfigPathFunc = origGetConfig }()

	rootDir := testAllowedRootDir(t)

	// Create config.json as a directory
	configPath := filepath.Join(dir, "config.json")
	if err := os.MkdirAll(configPath, 0755); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	err := initSystem(rootDir, &stdout, &stderr,
		nil,
		func(ar string, so, se io.Writer) error {
			t.Error("core should not be called")
			return nil
		})
	if err == nil {
		t.Fatal("expected error for config path as directory")
	}

	if !strings.Contains(err.Error(), "directory") {
		t.Errorf("expected directory error, got: %v", err)
	}
}

// TestInitSystemExistingConfigReadError verifies that initSystem fails when
// the existing config file cannot be read.
func TestInitSystemExistingConfigReadError(t *testing.T) {
	dir := t.TempDir()

	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return filepath.Join(dir, "config.json") }
	defer func() { getConfigPathFunc = origGetConfig }()

	rootDir := testAllowedRootDir(t)

	// Create config file without read permissions
	configPath := filepath.Join(dir, "config.json")
	if err := os.MkdirAll(filepath.Dir(configPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte(`{"allowed_roots": ["`+rootDir+`"], "session_ttl": "12h"}`), 0000); err != nil {
		t.Fatal(err)
	}
	defer func() { os.Chmod(configPath, 0600) }() // Cleanup

	var stdout, stderr bytes.Buffer
	err := initSystem(rootDir, &stdout, &stderr,
		nil,
		func(ar string, so, se io.Writer) error {
			t.Error("core should not be called")
			return nil
		})
	if err == nil {
		t.Fatal("expected error for config read error")
	}

	if !strings.Contains(err.Error(), "read") {
		t.Errorf("expected read error, got: %v", err)
	}
}

// TestInitSystemExistingConfigInvalid verifies that initSystem fails when
// the existing config is invalid JSON or missing required fields.
func TestInitSystemExistingConfigInvalid(t *testing.T) {
	dir := t.TempDir()

	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return filepath.Join(dir, "config.json") }
	defer func() { getConfigPathFunc = origGetConfig }()

	rootDir := testAllowedRootDir(t)

	// Create invalid config
	configPath := filepath.Join(dir, "config.json")
	if err := os.MkdirAll(filepath.Dir(configPath), 0700); err != nil {
		t.Fatal(err)
	}
	// Missing required field
	configData := `{"session_ttl": "12h"}`
	if err := os.WriteFile(configPath, []byte(configData), 0600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	err := initSystem(rootDir, &stdout, &stderr,
		nil,
		func(ar string, so, se io.Writer) error {
			t.Error("core should not be called")
			return nil
		})
	if err == nil {
		t.Fatal("expected error for invalid config")
	}

	if !strings.Contains(err.Error(), "invalid") {
		t.Errorf("expected invalid config error, got: %v", err)
	}
}

// --- Validate raw config error ---

func TestValidateRawConfigRejectsMissingAllowedRoot(t *testing.T) {
	raw := map[string]json.RawMessage{
		"session_ttl": json.RawMessage(`"12h"`),
	}
	err := validateRawConfig(raw)
	if err == nil {
		t.Fatal("expected error for missing allowed_root")
	}
	if !strings.Contains(err.Error(), "allowed_root") {
		t.Errorf("expected allowed_root error, got: %v", err)
	}
}

func TestValidateRawConfigRejectsRelativeAllowedRoot(t *testing.T) {
	raw := map[string]json.RawMessage{
		"allowed_root": json.RawMessage(`"relative"`),
		"session_ttl":  json.RawMessage(`"12h"`),
	}
	err := validateRawConfig(raw)
	if err == nil {
		t.Fatal("expected error for relative allowed_root")
	}
}

// --- SELinux deployment relabel (system init) tests ---
//
// These cover the clean-install SELinux lifecycle invariant: system-mode init
// under enforcing SELinux applies the installed fcontext rules to the
// helper-owned config/state directories (recursive restorecon) immediately
// after creating them and before writing the admin token, so the first daemon
// start succeeds. AppArmor system mode and user mode never invoke the SELinux
// relabel, and a relabel failure is fatal (no misleading partial init).

// setupInitSystemMode points config + state dirs at temp dirs and forces
// system mode (EffectiveUID 0) so initCore can run without root and without
// touching /etc/docker-helper or /var/lib/docker-helper.
func setupInitSystemMode(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return filepath.Join(dir, "config.json") }
	t.Cleanup(func() { getConfigPathFunc = origGetConfig })

	origGetState := getStateDirFunc
	getStateDirFunc = func() string { return filepath.Join(dir, "state") }
	t.Cleanup(func() { getStateDirFunc = origGetState })

	origUID := EffectiveUID
	EffectiveUID = func() int { return 0 }
	t.Cleanup(func() { EffectiveUID = origUID })

	return dir
}

// TestInitSystemSELinuxRelabelsDeploymentPaths verifies that system init under
// enforcing SELinux applies the deployment relabel to exactly the helper-owned
// config/state trees and the exact Docker CLI executable, before the admin
// token is created, and never touches the runtime tree or a Session/workspace
// path.
func TestInitSystemSELinuxRelabelsDeploymentPaths(t *testing.T) {
	dir := setupInitSystemMode(t)

	origLSM := detectLSM
	detectLSM = func() (LSMBackend, error) { return LSMSELinux, nil }
	defer func() { detectLSM = origLSM }()

	origDockerCLI := dockerCLIExecutable
	dockerCLIExecutable = func() (string, error) { return "/usr/bin/docker", nil }
	defer func() { dockerCLIExecutable = origDockerCLI }()

	origRC := deploymentRestorecon
	var calls [][]string
	var tokenAtCall []string
	deploymentRestorecon = func(args ...string) ([]byte, error) {
		calls = append(calls, args)
		if _, err := os.Stat(filepath.Join(dir, "admin.token")); os.IsNotExist(err) {
			tokenAtCall = append(tokenAtCall, "absent")
		} else {
			tokenAtCall = append(tokenAtCall, "present")
		}
		return nil, nil
	}
	defer func() { deploymentRestorecon = origRC }()

	rootDir := testAllowedRootDir(t)
	var stdout, stderr bytes.Buffer
	if _, err := initCore(rootDir, &stdout, &stderr); err != nil {
		t.Fatalf("initCore failed: %v", err)
	}

	// The tree relabels and the Docker CLI relabel run BEFORE the admin
	// token is created; the exact admin-token relabel runs AFTER the token
	// is written (SC1/H6 post-create relabel) so the fresh token carries the
	// dedicated token replacement type.
	want := [][]string{
		{"-R", "-m", "/etc/docker-helper", "/var/lib/docker-helper"},
		{"-m", "/usr/bin/docker"},
		{"-m", filepath.Join(dir, "admin.token")},
	}
	if !reflect.DeepEqual(calls, want) {
		t.Errorf("deployment restorecon calls = %v, want %v", calls, want)
	}
	if len(tokenAtCall) != 3 {
		t.Fatalf("expected 3 restorecon calls, got %d", len(tokenAtCall))
	}
	if tokenAtCall[0] != "absent" || tokenAtCall[1] != "absent" {
		t.Errorf("deployment tree relabel must run before the admin token is created, got %v", tokenAtCall)
	}
	if tokenAtCall[2] != "present" {
		t.Errorf("the admin-token relabel must run after the token is written, got %q", tokenAtCall[2])
	}
	for _, call := range calls {
		for _, a := range call {
			if strings.Contains(a, "/run/docker-helper") {
				t.Errorf("deployment relabel must never target /run/docker-helper, got %q", a)
			}
			if a == rootDir || strings.HasPrefix(a, rootDir+string(filepath.Separator)) {
				t.Errorf("system init must not prepare Session/workspace MAC state (relabeled workspace %q)", a)
			}
		}
	}
}

// TestInitSystemSELinuxDockerCLIRelabelIsExactPath verifies that the Docker CLI
// relabel is an exact-path restorecon: a single file path with no -R (never a
// recursive /usr/bin relabel) and no directory argument.
func TestInitSystemSELinuxDockerCLIRelabelIsExactPath(t *testing.T) {
	_ = setupInitSystemMode(t)

	origLSM := detectLSM
	detectLSM = func() (LSMBackend, error) { return LSMSELinux, nil }
	defer func() { detectLSM = origLSM }()

	origDockerCLI := dockerCLIExecutable
	dockerCLIExecutable = func() (string, error) { return "/usr/local/bin/docker", nil }
	defer func() { dockerCLIExecutable = origDockerCLI }()

	var dockerCalls [][]string
	origRC := deploymentRestorecon
	deploymentRestorecon = func(args ...string) ([]byte, error) {
		if len(args) == 2 && args[1] == "/usr/local/bin/docker" {
			dockerCalls = append(dockerCalls, args)
		}
		return nil, nil
	}
	defer func() { deploymentRestorecon = origRC }()

	rootDir := testAllowedRootDir(t)
	var stdout, stderr bytes.Buffer
	if _, err := initCore(rootDir, &stdout, &stderr); err != nil {
		t.Fatalf("initCore failed: %v", err)
	}

	if len(dockerCalls) != 1 {
		t.Fatalf("docker CLI must be relabeled exactly once, got %v", dockerCalls)
	}
	args := dockerCalls[0]
	if strings.Join(args, " ") != "-m /usr/local/bin/docker" {
		t.Errorf("docker CLI restorecon must be exact-path (-m <file>), got %v", args)
	}
	for _, a := range args {
		if a == "-R" {
			t.Error("docker CLI relabel must never be recursive (-R)")
		}
		if strings.HasPrefix(a, "/usr/bin/") || a == "/usr/bin" {
			t.Error("docker CLI relabel must never target /usr/bin broadly")
		}
	}
}

// TestDockerCLIExecutableDeterministicOrder verifies the SELinux deploy Docker
// CLI resolver returns the first executable "docker" in dockerCLISearchPath
// order, deterministically.
func TestDockerCLIExecutableDeterministicOrder(t *testing.T) {
	dirs := []string{t.TempDir(), t.TempDir(), t.TempDir()}
	if err := os.WriteFile(filepath.Join(dirs[0], "docker"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dirs[1], "docker"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	origSearch := dockerCLISearchPath
	dockerCLISearchPath = dirs
	defer func() { dockerCLISearchPath = origSearch }()

	got, err := dockerCLIExecutable()
	if err != nil {
		t.Fatalf("dockerCLIExecutable: %v", err)
	}
	want := filepath.Join(dirs[0], "docker")
	if got != want {
		t.Errorf("dockerCLIExecutable = %q, want first search-path match %q", got, want)
	}
}

// TestDockerCLIExecutableSkipsNonExecutable verifies the resolver skips
// non-executable and non-regular candidates and falls through to the next
// search-path directory.
func TestDockerCLIExecutableSkipsNonExecutable(t *testing.T) {
	dirs := []string{t.TempDir(), t.TempDir()}
	if err := os.WriteFile(filepath.Join(dirs[0], "docker"), []byte("not executable"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dirs[1], "docker"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	origSearch := dockerCLISearchPath
	dockerCLISearchPath = dirs
	defer func() { dockerCLISearchPath = origSearch }()

	got, err := dockerCLIExecutable()
	if err != nil {
		t.Fatalf("dockerCLIExecutable: %v", err)
	}
	want := filepath.Join(dirs[1], "docker")
	if got != want {
		t.Errorf("dockerCLIExecutable = %q, want executable fallback %q", got, want)
	}
}

// TestDockerCLIExecutableNotFound verifies the resolver errors consistently when
// no executable candidate exists anywhere in the search path.
func TestDockerCLIExecutableNotFound(t *testing.T) {
	origSearch := dockerCLISearchPath
	dockerCLISearchPath = []string{t.TempDir()}
	defer func() { dockerCLISearchPath = origSearch }()

	if _, err := dockerCLIExecutable(); err == nil {
		t.Error("dockerCLIExecutable must error when no executable docker is found")
	}
}

// TestInitSystemSELinuxDockerCLIRelabelFailureFatal verifies that a Docker CLI
// relabel failure under enforcing SELinux system mode makes init fail and
// leaves no partial initialization (no admin token).
func TestInitSystemSELinuxDockerCLIRelabelFailureFatal(t *testing.T) {
	dir := setupInitSystemMode(t)

	origLSM := detectLSM
	detectLSM = func() (LSMBackend, error) { return LSMSELinux, nil }
	defer func() { detectLSM = origLSM }()

	origDockerCLI := dockerCLIExecutable
	dockerCLIExecutable = func() (string, error) { return "/usr/bin/docker", nil }
	defer func() { dockerCLIExecutable = origDockerCLI }()

	origRC := deploymentRestorecon
	call := 0
	deploymentRestorecon = func(args ...string) ([]byte, error) {
		call++
		if call == 2 {
			return []byte("restorecon: permission denied"), errors.New("restorecon exit status 1")
		}
		return nil, nil
	}
	defer func() { deploymentRestorecon = origRC }()

	rootDir := testAllowedRootDir(t)
	var stdout, stderr bytes.Buffer
	_, err := initCore(rootDir, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected init to fail when the Docker CLI relabel fails")
	}
	if !strings.Contains(err.Error(), "docker CLI relabel failed") {
		t.Errorf("expected docker CLI relabel error, got: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "admin.token")); !os.IsNotExist(statErr) {
		t.Error("admin.token must not be created when the Docker CLI relabel fails (no partial init)")
	}
}

// TestInitSystemSELinuxDockerCLINotFoundFatal verifies that init fails
// explicitly when the Docker CLI executable cannot be located under enforcing
// SELinux system mode (the relabel is required and cannot be skipped).
func TestInitSystemSELinuxDockerCLINotFoundFatal(t *testing.T) {
	dir := setupInitSystemMode(t)

	origLSM := detectLSM
	detectLSM = func() (LSMBackend, error) { return LSMSELinux, nil }
	defer func() { detectLSM = origLSM }()

	origDockerCLI := dockerCLIExecutable
	dockerCLIExecutable = func() (string, error) { return "", errors.New("no docker CLI") }
	defer func() { dockerCLIExecutable = origDockerCLI }()

	origRC := deploymentRestorecon
	deploymentRestorecon = func(args ...string) ([]byte, error) { return nil, nil }
	defer func() { deploymentRestorecon = origRC }()

	rootDir := testAllowedRootDir(t)
	var stdout, stderr bytes.Buffer
	_, err := initCore(rootDir, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected init to fail when the Docker CLI cannot be located")
	}
	if !strings.Contains(err.Error(), "cannot locate docker CLI") {
		t.Errorf("expected docker CLI location error, got: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "admin.token")); !os.IsNotExist(statErr) {
		t.Error("admin.token must not be created when the Docker CLI cannot be located (no partial init)")
	}
}

// TestInitSystemSELinuxTokenRelabelFailureRemovesFreshToken verifies the
// fresh-init recovery contract for the exact post-create admin-token relabel:
// a relabel failure after the fresh token write is fatal AND the just-created
// token file is removed, so the failed token is never printed as a success
// result and a retry init with the same requested root is not poisoned by the
// "admin.token already exists" preflight (no partial initialization left
// behind). The existing config.json written before the failure remains valid.
func TestInitSystemSELinuxTokenRelabelFailureRemovesFreshToken(t *testing.T) {
	dir := setupInitSystemMode(t)

	origLSM := detectLSM
	detectLSM = func() (LSMBackend, error) { return LSMSELinux, nil }
	defer func() { detectLSM = origLSM }()

	origDockerCLI := dockerCLIExecutable
	dockerCLIExecutable = func() (string, error) { return "/usr/bin/docker", nil }
	defer func() { dockerCLIExecutable = origDockerCLI }()

	tokenPath := filepath.Join(dir, "admin.token")
	origRC := deploymentRestorecon
	call := 0
	deploymentRestorecon = func(args ...string) ([]byte, error) {
		call++
		// Calls 1 (config/state trees) and 2 (docker CLI) precede the token
		// write; call 3 is the exact admin-token relabel after the write.
		if call == 3 {
			return []byte("restorecon: permission denied"), errors.New("restorecon exit status 1")
		}
		return nil, nil
	}
	defer func() { deploymentRestorecon = origRC }()

	rootDir := testAllowedRootDir(t)
	var stdout, stderr bytes.Buffer
	_, err := initCore(rootDir, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected init to fail when the exact admin-token relabel fails")
	}
	if !strings.Contains(err.Error(), "admin token relabel failed") {
		t.Errorf("expected admin token relabel error, got: %v", err)
	}
	if call != 3 {
		t.Fatalf("init must reach the exact admin-token relabel, restorecon calls = %d", call)
	}
	if _, statErr := os.Stat(tokenPath); !os.IsNotExist(statErr) {
		t.Fatal("failed fresh-init token relabel must not leave admin.token behind (poisoned partial init)")
	}
	if strings.Contains(stdout.String(), "initialized successfully") || strings.Contains(stdout.String(), "Admin token:") {
		t.Error("failed init must not print the token as a successful init result")
	}

	// The config written before the failure may remain valid.
	data, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatalf("config.json must remain after the failed token relabel: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("existing config.json must remain valid JSON: %v", err)
	}
	if err := validateRawConfig(raw); err != nil {
		t.Fatalf("existing config.json must remain semantically valid: %v", err)
	}

	// A retry init with the same requested root must succeed.
	var retryStdout, retryStderr bytes.Buffer
	if err := initSystem(rootDir, &retryStdout, &retryStderr, nil,
		func(ar string, so, se io.Writer) error {
			_, err := initCore(ar, so, se)
			return err
		}); err != nil {
		t.Fatalf("retry init after a failed fresh-init token relabel must succeed: %v", err)
	}
	if call != 6 {
		t.Fatalf("retry init must run the full relabel lifecycle again, restorecon calls = %d", call)
	}
	if _, statErr := os.Stat(tokenPath); statErr != nil {
		t.Fatalf("retry init must leave a working admin.token: %v", statErr)
	}
}

// TestInitSystemSELinuxTokenRelabelFailureCleanupFailureReportsBoth verifies
// that when the post-relabel cleanup of the just-created token file itself
// fails, the returned error reports the original relabel failure AND the
// cleanup failure instead of hiding either.
func TestInitSystemSELinuxTokenRelabelFailureCleanupFailureReportsBoth(t *testing.T) {
	dir := setupInitSystemMode(t)

	origLSM := detectLSM
	detectLSM = func() (LSMBackend, error) { return LSMSELinux, nil }
	defer func() { detectLSM = origLSM }()

	origDockerCLI := dockerCLIExecutable
	dockerCLIExecutable = func() (string, error) { return "/usr/bin/docker", nil }
	defer func() { dockerCLIExecutable = origDockerCLI }()

	// Narrow fault injection: at the exact admin-token relabel (call 3) the
	// restorecon fails AND the config directory loses its write permission,
	// so the post-failure removal of the just-created token file fails.
	origRC := deploymentRestorecon
	call := 0
	deploymentRestorecon = func(args ...string) ([]byte, error) {
		call++
		if call == 3 {
			if err := os.Chmod(dir, 0500); err != nil {
				t.Fatalf("cannot stage the unremovable token state: %v", err)
			}
			return []byte("restorecon: permission denied"), errors.New("restorecon exit status 1")
		}
		return nil, nil
	}
	defer func() {
		deploymentRestorecon = origRC
		os.Chmod(dir, 0700)
	}()

	rootDir := testAllowedRootDir(t)
	var stdout, stderr bytes.Buffer
	_, err := initCore(rootDir, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected init to fail when the admin-token relabel and its cleanup fail")
	}
	if !strings.Contains(err.Error(), "admin token relabel failed") {
		t.Errorf("error must report the original relabel failure, got: %v", err)
	}
	if !strings.Contains(err.Error(), "removing the just-created admin token failed") {
		t.Errorf("error must report the cleanup failure, got: %v", err)
	}
}

// TestInitSystemAppArmorNoSELinuxRelabel verifies that AppArmor system init
// does not invoke any SELinux relabel.
func TestInitSystemAppArmorNoSELinuxRelabel(t *testing.T) {
	setupInitSystemMode(t)

	origLSM := detectLSM
	detectLSM = func() (LSMBackend, error) { return LSMAppArmor, nil }
	defer func() { detectLSM = origLSM }()

	called := false
	origRC := deploymentRestorecon
	deploymentRestorecon = func(args ...string) ([]byte, error) { called = true; return nil, nil }
	defer func() { deploymentRestorecon = origRC }()

	rootDir := testAllowedRootDir(t)
	var stdout, stderr bytes.Buffer
	if _, err := initCore(rootDir, &stdout, &stderr); err != nil {
		t.Fatalf("initCore failed: %v", err)
	}
	if called {
		t.Error("AppArmor system init must not invoke the SELinux deployment relabel")
	}
}

// TestInitSystemSELinuxRelabelFailureFatal verifies that a deployment relabel
// failure under enforcing SELinux system mode makes init fail and leaves no
// partial initialization (no admin token).
func TestInitSystemSELinuxRelabelFailureFatal(t *testing.T) {
	dir := setupInitSystemMode(t)

	origLSM := detectLSM
	detectLSM = func() (LSMBackend, error) { return LSMSELinux, nil }
	defer func() { detectLSM = origLSM }()

	origRC := deploymentRestorecon
	deploymentRestorecon = func(args ...string) ([]byte, error) {
		return []byte("restorecon: permission denied"), errors.New("restorecon exit status 1")
	}
	defer func() { deploymentRestorecon = origRC }()

	rootDir := testAllowedRootDir(t)
	var stdout, stderr bytes.Buffer
	_, err := initCore(rootDir, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected init to fail when the deployment relabel fails")
	}
	if !strings.Contains(err.Error(), "relabel") {
		t.Errorf("expected deployment relabel error, got: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "admin.token")); !os.IsNotExist(statErr) {
		t.Error("admin.token must not be created when the relabel fails (no partial init)")
	}
}
