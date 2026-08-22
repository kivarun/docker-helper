package main

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateCAConfigPropagatesHashError(t *testing.T) {
	// Regression: validateCAConfig must propagate the error from
	// computeOpenSSLHash, not discard it.
	//
	// We inject a hasher that returns a sentinel error to prove the error
	// path is exercised and the error context is preserved.

	_, caPath := setupCAConfigPreflightTest(t)

	// Create a hasher that returns a sentinel error.
	sentinelErr := errors.New("simulated hash failure")
	failingHasher := func(*x509.Certificate) (string, error) {
		return "", sentinelErr
	}

	raw := map[string]json.RawMessage{
		"trusted_ca_injection": json.RawMessage(`"auto"`),
		"trusted_ca_path":      json.RawMessage(fmt.Sprintf(`"%s"`, caPath)),
	}

	err := validateCAConfigWithHasher(raw, failingHasher)
	if err == nil {
		t.Fatal("expected error from failing hasher, got nil")
	}

	// Verify the error contains useful context.
	if !strings.Contains(err.Error(), "subject hash computation failed") {
		t.Errorf("expected 'subject hash computation failed' in error, got: %v", err)
	}

	// Verify the underlying error is preserved.
	if !errors.Is(err, sentinelErr) {
		t.Errorf("expected error to wrap sentinel, got: %v", err)
	}
}

func TestCAPreflightAutoMissingCA(t *testing.T) {
	configPath, caPath := setupCAConfigPreflightTest(t)

	// Remove the CA file so it's missing.
	if err := os.Remove(caPath); err != nil {
		t.Fatalf("cannot remove CA: %v", err)
	}

	// Set trusted_ca_path to the missing file first.
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "trusted_ca_path", caPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("set path: expected 0, got %d", code)
	}

	// Save original config bytes before the failing command.
	originalBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("cannot read config: %v", err)
	}

	// Now try to enable auto with the missing CA.
	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "set", "trusted_ca_injection", "auto"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1, got %d, stdout: %q, stderr: %q", code, stdout.String(), stderr.String())
	}
	if stdout.String() != "" {
		t.Errorf("expected empty stdout, got: %q", stdout.String())
	}
	if stderr.String() == "" {
		t.Error("expected non-empty stderr")
	}

	// Config file should be byte-for-byte unchanged.
	newBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("cannot read config: %v", err)
	}
	if !bytes.Equal(originalBytes, newBytes) {
		t.Error("config.json should be byte-for-byte unchanged")
	}
}

func TestCAPreflightAutoMalformedCA(t *testing.T) {
	configPath, _ := setupCAConfigPreflightTest(t)

	// Create a malformed CA file.
	badCAPath := filepath.Join(filepath.Dir(configPath), "bad-ca.crt")
	if err := os.WriteFile(badCAPath, []byte("not valid PEM data"), 0644); err != nil {
		t.Fatalf("cannot write bad CA: %v", err)
	}

	// First set the path.
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "trusted_ca_path", badCAPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("set path: expected 0, got %d", code)
	}

	// Save original config bytes.
	originalBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("cannot read config: %v", err)
	}

	// Now try to enable auto with the malformed CA.
	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "set", "trusted_ca_injection", "auto"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1, got %d, stderr: %q", code, stderr.String())
	}
	if stdout.String() != "" {
		t.Errorf("expected empty stdout, got: %q", stdout.String())
	}
	if stderr.String() == "" {
		t.Error("expected non-empty stderr")
	}

	// Config should be byte-for-byte unchanged.
	newBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("cannot read config: %v", err)
	}
	if !bytes.Equal(originalBytes, newBytes) {
		t.Error("config.json should be byte-for-byte unchanged")
	}
}

func TestCAPreflightAutoLeafCA(t *testing.T) {
	configPath, _ := setupCAConfigPreflightTest(t)

	// Create a leaf certificate.
	leafPath := filepath.Join(filepath.Dir(configPath), "leaf.crt")
	leafPEM := generateTestLeafPEM(t)
	if err := os.WriteFile(leafPath, leafPEM, 0644); err != nil {
		t.Fatalf("cannot write leaf: %v", err)
	}

	// Set the path first.
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "trusted_ca_path", leafPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("set path: expected 0, got %d", code)
	}

	// Save original config bytes.
	originalBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("cannot read config: %v", err)
	}

	// Try to enable auto with the leaf CA.
	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "set", "trusted_ca_injection", "auto"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1, got %d, stderr: %q", code, stderr.String())
	}
	if stdout.String() != "" {
		t.Errorf("expected empty stdout, got: %q", stdout.String())
	}
	if stderr.String() == "" {
		t.Error("expected non-empty stderr")
	}

	// Config should be byte-for-byte unchanged.
	newBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("cannot read config: %v", err)
	}
	if !bytes.Equal(originalBytes, newBytes) {
		t.Error("config.json should be byte-for-byte unchanged")
	}
}

func TestCAPreflightReplacePathInvalidWhileAuto(t *testing.T) {
	configPath, caPath := setupCAConfigPreflightTest(t)

	// First set path and enable auto (should succeed with valid CA).
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "trusted_ca_path", caPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("set path: expected 0, got %d stdout: %q stderr: %q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "set", "trusted_ca_injection", "auto"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("set auto: expected 0, got %d stdout: %q stderr: %q", code, stdout.String(), stderr.String())
	}

	// Save original config bytes after setup.
	originalBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("cannot read config: %v", err)
	}

	// Now try to replace path with a non-existent file.
	badPath := filepath.Join(filepath.Dir(configPath), "nonexistent.crt")
	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "set", "trusted_ca_path", badPath}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1, got %d, stderr: %q", code, stderr.String())
	}
	if stdout.String() != "" {
		t.Errorf("expected empty stdout, got: %q", stdout.String())
	}
	if stderr.String() == "" {
		t.Error("expected non-empty stderr")
	}

	// Config should be byte-for-byte unchanged.
	newBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("cannot read config: %v", err)
	}
	if !bytes.Equal(originalBytes, newBytes) {
		t.Error("config.json should be byte-for-byte unchanged")
	}
}

func TestCAPreflightValidCASucceeds(t *testing.T) {
	configPath, caPath := setupCAConfigPreflightTest(t)

	// Set path and enable auto (should succeed).
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "trusted_ca_path", caPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("set path: expected 0, got %d, stderr: %q", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "set", "trusted_ca_injection", "auto"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("set auto: expected 0, got %d, stderr: %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "updated") {
		t.Errorf("expected 'updated' in stdout, got: %q", stdout.String())
	}

	// Verify config was written.
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("cannot read config: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("cannot parse config: %v", err)
	}
	if raw["trusted_ca_injection"] != "auto" {
		t.Errorf("expected auto, got %v", raw["trusted_ca_injection"])
	}
}

func TestCAPreflightDisabledNoValidation(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	tokenPath := filepath.Join(dir, "admin.token")
	nonexistentRuntime := filepath.Join(dir, "nonexistent_runtime")
	nonexistentState := filepath.Join(dir, "nonexistent_state")

	// Write admin token.
	if err := os.WriteFile(tokenPath, []byte("test-admin-token\n"), 0600); err != nil {
		t.Fatalf("cannot write token: %v", err)
	}

	// Write initial config with disabled injection.
	allowedRoot := testAllowedRootDir(t)
	writeCAConfig(t, configPath, map[string]any{
		"allowed_root":         allowedRoot,
		"session_ttl":          "12h",
		"trusted_ca_injection": "disabled",
	})

	// Set environment: nonexistent runtime/state.
	t.Setenv("DOCKER_HELPER_CONFIG", configPath)
	t.Setenv("XDG_RUNTIME_DIR", nonexistentRuntime)
	t.Setenv("XDG_STATE_HOME", nonexistentState)

	// Prevent reaching a real system daemon.
	origSocket := systemSocketExists
	systemSocketExists = func() bool { return false }
	t.Cleanup(func() { systemSocketExists = origSocket })

	// Point to a non-existent CA path while injection is disabled.
	badPath := filepath.Join(dir, "nonexistent.crt")

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "trusted_ca_path", badPath}, &stdout, &stderr)
	if code != 0 {
		t.Errorf("expected exit code 0 for disabled mode, got %d, stderr: %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "updated") {
		t.Errorf("expected 'updated' in stdout, got: %q", stdout.String())
	}

	// Verify runtime directory was NOT created.
	if _, err := os.Stat(nonexistentRuntime); !os.IsNotExist(err) {
		t.Errorf("runtime dir %s should not have been created", nonexistentRuntime)
	}

	// Verify state directory was NOT created.
	if _, err := os.Stat(nonexistentState); !os.IsNotExist(err) {
		t.Errorf("state dir %s should not have been created", nonexistentState)
	}
}

func TestCAPreflightUnchangedWithBrokenCA(t *testing.T) {
	configPath, caPath := setupCAConfigPreflightTest(t)

	// Set up valid config first.
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "trusted_ca_path", caPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("set path: expected 0, got %d stdout: %q stderr: %q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "set", "trusted_ca_injection", "auto"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("set auto: expected 0, got %d stdout: %q stderr: %q", code, stdout.String(), stderr.String())
	}

	// Save original config bytes.
	originalBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("cannot read config: %v", err)
	}

	// Now break the CA file.
	if err := os.Remove(caPath); err != nil {
		t.Fatalf("cannot remove CA: %v", err)
	}

	// Try to set the same values (unchanged path).
	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "set", "trusted_ca_injection", "auto"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1 for unchanged with broken CA, got %d, stdout: %q, stderr: %q", code, stdout.String(), stderr.String())
	}
	if stdout.String() != "" {
		t.Errorf("expected empty stdout, got: %q", stdout.String())
	}
	if stderr.String() == "" {
		t.Error("expected non-empty stderr")
	}

	// Config should be byte-for-byte unchanged.
	newBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("cannot read config: %v", err)
	}
	if !bytes.Equal(originalBytes, newBytes) {
		t.Error("config.json should be byte-for-byte unchanged")
	}
}

func TestCAPreflightSetUnchanged(t *testing.T) {
	configPath, caPath, _ := setupCAConfigTest(t)

	writeCAConfig(t, configPath, map[string]any{
		"allowed_roots":        []string{testAllowedRootDir(t)},
		"session_ttl":          "12h",
		"trusted_ca_path":      caPath,
		"trusted_ca_injection": "auto",
	})

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "trusted_ca_injection", "auto"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "unchanged") {
		t.Errorf("expected 'unchanged' in output, got: %s", stdout.String())
	}
}

func TestCAPreflightUnsetAbsentWithBrokenCA(t *testing.T) {
	configPath, caPath, _ := setupCAConfigTest(t)

	writeCAConfig(t, configPath, map[string]any{
		"allowed_root":         testAllowedRootDir(t),
		"session_ttl":          "12h",
		"trusted_ca_path":      caPath,
		"trusted_ca_injection": "auto",
	})

	beforeData, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}

	// Break the CA file so preflight validation fails.
	if err := os.Remove(caPath); err != nil {
		t.Fatal(err)
	}

	// Unset a field that is already absent to hit the "already absent" branch.
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "unset", "log_level"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1, got %d, stdout: %q, stderr: %q", code, stdout.String(), stderr.String())
	}
	if stdout.String() != "" {
		t.Errorf("expected empty stdout, got %q", stdout.String())
	}
	if stderr.String() == "" {
		t.Error("expected non-empty stderr")
	}

	afterData, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(beforeData, afterData) {
		t.Error("config.json should not be modified when preflight fails")
	}
}

// --- System-mode CA source-path policy tests ---

func TestIsPathContainedUnder(t *testing.T) {
	root := t.TempDir()
	insideFile := filepath.Join(root, "subdir", "file.crt")
	if err := os.MkdirAll(filepath.Dir(insideFile), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(insideFile, []byte("cert"), 0644); err != nil {
		t.Fatal(err)
	}

	outsideFile := filepath.Join(t.TempDir(), "outside.crt")
	if err := os.WriteFile(outsideFile, []byte("cert"), 0644); err != nil {
		t.Fatal(err)
	}

	// Similarly-prefixed path outside the root.
	similarRoot := root + "-other"
	if err := os.MkdirAll(similarRoot, 0755); err != nil {
		t.Fatal(err)
	}
	similarFile := filepath.Join(similarRoot, "file.crt")
	if err := os.WriteFile(similarFile, []byte("cert"), 0644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		path    string
		want    bool
		wantErr bool
	}{
		{
			name: "file inside root passes",
			path: insideFile,
			want: true,
		},
		{
			name: "outside file fails",
			path: outsideFile,
			want: false,
		},
		{
			name: "similarly-prefixed path fails",
			path: similarFile,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := isPathContainedUnder(tt.path, root)
			if (err != nil) != tt.wantErr {
				t.Errorf("isPathContainedUnder(%q, %q) error = %v, wantErr %v", tt.path, root, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("isPathContainedUnder(%q, %q) = %v, want %v", tt.path, root, got, tt.want)
			}
		})
	}
}

func TestIsPathContainedUnderSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outsideDir := t.TempDir()
	outsideFile := filepath.Join(outsideDir, "outside.crt")
	if err := os.WriteFile(outsideFile, []byte("cert"), 0644); err != nil {
		t.Fatal(err)
	}

	// Symlink inside root pointing to outside file.
	insideLink := filepath.Join(root, "link.crt")
	if err := os.Symlink(outsideFile, insideLink); err != nil {
		t.Fatal(err)
	}

	// Symlink inside root pointing to file still inside root.
	insideFile := filepath.Join(root, "real.crt")
	if err := os.WriteFile(insideFile, []byte("cert"), 0644); err != nil {
		t.Fatal(err)
	}
	insideLinkValid := filepath.Join(root, "link-valid.crt")
	if err := os.Symlink(insideFile, insideLinkValid); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		path string
		want bool
	}{
		{
			name: "symlink inside -> outside fails",
			path: insideLink,
			want: false,
		},
		{
			name: "symlink inside -> inside passes",
			path: insideLinkValid,
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := isPathContainedUnder(tt.path, root)
			if err != nil {
				t.Fatalf("isPathContainedUnder(%q, %q) error = %v", tt.path, root, err)
			}
			if got != tt.want {
				t.Errorf("isPathContainedUnder(%q, %q) = %v, want %v", tt.path, root, got, tt.want)
			}
		})
	}
}

func TestValidateSystemCASourcePath(t *testing.T) {
	root := t.TempDir()
	insideFile := filepath.Join(root, "subdir", "file.crt")
	if err := os.MkdirAll(filepath.Dir(insideFile), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(insideFile, []byte("cert"), 0644); err != nil {
		t.Fatal(err)
	}

	outsideFile := filepath.Join(t.TempDir(), "outside.crt")
	if err := os.WriteFile(outsideFile, []byte("cert"), 0644); err != nil {
		t.Fatal(err)
	}

	// Symlink inside root pointing to outside file.
	outsideDir := t.TempDir()
	outsideTarget := filepath.Join(outsideDir, "target.crt")
	if err := os.WriteFile(outsideTarget, []byte("cert"), 0644); err != nil {
		t.Fatal(err)
	}
	escapeLink := filepath.Join(root, "escape.crt")
	if err := os.Symlink(outsideTarget, escapeLink); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{
			name: "file inside root passes",
			path: insideFile,
		},
		{
			name:    "outside file fails",
			path:    outsideFile,
			wantErr: true,
		},
		{
			name:    "symlink escape fails",
			path:    escapeLink,
			wantErr: true,
		},
		{
			name:    "nonexistent file fails",
			path:    filepath.Join(root, "nope.crt"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSystemCASourcePathWithRoot(tt.path, root)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateSystemCASourcePathWithRoot(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
			}
		})
	}
}

// validateSystemCASourcePathWithRoot is like validateSystemCASourcePath but
// accepts a custom root for testing. Production always uses systemCASourceRoot.
func validateSystemCASourcePathWithRoot(caPath, root string) error {
	contained, err := isPathContainedUnder(caPath, root)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("trusted_ca_path does not exist: %s", caPath)
		}
		return fmt.Errorf("cannot resolve trusted_ca_path: %w", err)
	}
	if !contained {
		return fmt.Errorf("system mode trusted_ca_path must be under %s: %s", root, caPath)
	}

	info, err := os.Stat(caPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("trusted_ca_path does not exist: %s", caPath)
		}
		return fmt.Errorf("cannot access trusted_ca_path: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("trusted_ca_path must be a regular file: %s", caPath)
	}

	return nil
}

func TestSystemModeCAOutsideSourceFails(t *testing.T) {
	// System mode + auto + outside source must fail before config write.
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	tokenPath := filepath.Join(dir, "admin.token")
	caPath := filepath.Join(dir, "test-ca.crt")
	generateTestCAPEM(t, caPath)

	if err := os.WriteFile(tokenPath, []byte("test-admin-token\n"), 0600); err != nil {
		t.Fatal(err)
	}

	allowedRoot := testAllowedRootDir(t)
	// Pre-set the CA path so we only need one command to test the validation.
	writeCAConfig(t, configPath, map[string]any{
		"allowed_root":         allowedRoot,
		"session_ttl":          "12h",
		"trusted_ca_path":      caPath,
		"trusted_ca_injection": "disabled",
	})

	t.Setenv("DOCKER_HELPER_CONFIG", configPath)
	shortRuntime := filepath.Join(os.TempDir(), fmt.Sprintf("dh-ca-sys-%d", os.Getpid()))
	t.Setenv("XDG_RUNTIME_DIR", shortRuntime)
	t.Cleanup(func() { os.RemoveAll(shortRuntime) })

	// Mock system mode.
	origUID := EffectiveUID
	EffectiveUID = func() int { return 0 }
	defer func() { EffectiveUID = origUID }()

	// Mock config path so operator client token resolution uses the test dir.
	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return configPath }
	defer func() { getConfigPathFunc = origGetConfig }()

	// Prevent reaching a real system daemon.
	origSocket := systemSocketExists
	systemSocketExists = func() bool { return false }
	defer func() { systemSocketExists = origSocket }()

	// Save original config bytes.
	originalBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}

	// Try to enable auto with a CA outside /etc/docker-helper.
	// This should fail during validation, before any config write or reload.
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "trusted_ca_injection", "auto"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1, got %d, stderr: %q", code, stderr.String())
	}

	// Config must be byte-for-byte unchanged.
	newBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(originalBytes, newBytes) {
		t.Error("config.json should be byte-for-byte unchanged when system CA source policy fails")
	}
}

func TestUserModeCAArbitraryPath(t *testing.T) {
	// User mode must accept arbitrary absolute CA paths.
	_, caPath := setupCAConfigPreflightTest(t)

	// Ensure user mode.
	origUID := EffectiveUID
	EffectiveUID = func() int { return 1000 }
	defer func() { EffectiveUID = origUID }()

	// Set path and enable auto (should succeed with valid CA in user mode).
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "trusted_ca_path", caPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("set path: expected 0, got %d, stderr: %q", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "set", "trusted_ca_injection", "auto"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("set auto: expected 0, got %d, stderr: %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "updated") {
		t.Errorf("expected 'updated' in stdout, got: %q", stdout.String())
	}
}

// TestSystemCADocumentation verifies that the Release 2 system-mode CA source
// documentation explicitly identifies /etc/docker-helper as the CA source namespace.
func TestSystemCADocumentation(t *testing.T) {
	readmeData, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	readme := string(readmeData)

	// Locate the trusted CA injection section.
	caSectionIdx := strings.Index(readme, "### Trusted CA injection")
	if caSectionIdx < 0 {
		t.Fatal("README.md must contain '### Trusted CA injection' section")
	}
	// Find the next top-level section (## heading at line start) to bound the section.
	caSection := readme[caSectionIdx:]
	// Look for "\n## " to avoid matching #### subsections.
	nextSectionIdx := strings.Index(caSection[1:], "\n## ")
	if nextSectionIdx >= 0 {
		caSection = caSection[:nextSectionIdx+1]
	}

	// The system-mode subsection must mention /etc/docker-helper.
	systemIdx := strings.Index(caSection, "#### System mode")
	if systemIdx < 0 {
		t.Fatal("README.md CA section must contain '#### System mode' subsection")
	}
	systemSubsection := caSection[systemIdx:]
	if !strings.Contains(systemSubsection, "/etc/docker-helper") {
		t.Error("README.md system-mode CA section must document /etc/docker-helper as the CA source namespace")
	}
}

// --- Runtime enforcement tests (loadConfig path) ---

func TestIsPathContainedUnderRejectsRoot(t *testing.T) {
	// path == root must return false (not a proper descendant).
	root := t.TempDir()
	got, err := isPathContainedUnder(root, root)
	if err != nil {
		t.Fatalf("isPathContainedUnder(%q, %q) error = %v", root, root, err)
	}
	if got {
		t.Errorf("isPathContainedUnder(%q, %q) = true, want false (path == root is not contained)", root, root)
	}
}

func TestValidateSystemCASourcePathUnder(t *testing.T) {
	// Test the canonical containment semantics using a temp root.
	root := t.TempDir()
	insideFile := filepath.Join(root, "subdir", "file.crt")
	if err := os.MkdirAll(filepath.Dir(insideFile), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(insideFile, []byte("cert"), 0644); err != nil {
		t.Fatal(err)
	}

	// Symlink inside root pointing to file still inside root.
	insideTarget := filepath.Join(root, "real.crt")
	if err := os.WriteFile(insideTarget, []byte("cert"), 0644); err != nil {
		t.Fatal(err)
	}
	insideLink := filepath.Join(root, "link-inside.crt")
	if err := os.Symlink(insideTarget, insideLink); err != nil {
		t.Fatal(err)
	}

	// Symlink inside root pointing to outside file.
	outsideDir := t.TempDir()
	outsideFile := filepath.Join(outsideDir, "outside.crt")
	if err := os.WriteFile(outsideFile, []byte("cert"), 0644); err != nil {
		t.Fatal(err)
	}
	outsideLink := filepath.Join(root, "link-outside.crt")
	if err := os.Symlink(outsideFile, outsideLink); err != nil {
		t.Fatal(err)
	}

	// Similarly-prefixed path outside the root.
	similarRoot := root + "-other"
	if err := os.MkdirAll(similarRoot, 0755); err != nil {
		t.Fatal(err)
	}
	similarFile := filepath.Join(similarRoot, "file.crt")
	if err := os.WriteFile(similarFile, []byte("cert"), 0644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{
			name: "file inside root passes",
			path: insideFile,
		},
		{
			name: "symlink inside -> inside passes",
			path: insideLink,
		},
		{
			name:    "symlink inside -> outside fails",
			path:    outsideLink,
			wantErr: true,
		},
		{
			name:    "similarly-prefixed sibling fails",
			path:    similarFile,
			wantErr: true,
		},
		{
			name:    "path == root fails",
			path:    root,
			wantErr: true,
		},
		{
			name:    "nonexistent file fails",
			path:    filepath.Join(root, "nope.crt"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSystemCASourcePathUnder(tt.path, root)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateSystemCASourcePathUnder(%q, %q) error = %v, wantErr %v", tt.path, root, err, tt.wantErr)
			}
		})
	}
}

func TestLoadConfigSystemModeRejectsOutsideCA(t *testing.T) {
	// loadConfig in system mode must reject trusted_ca_path outside
	// /etc/docker-helper, even when config was written manually.
	// The system CA source check runs before runtime dir creation,
	// so we do not need to mock getRuntimeDir.
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	caPath := filepath.Join(dir, "test-ca.crt")
	generateTestCAPEM(t, caPath)

	// Manually write config bypassing config CLI.
	cfg := map[string]any{
		"allowed_root":         testAllowedRootDir(t),
		"session_ttl":          "12h",
		"trusted_ca_path":      caPath,
		"trusted_ca_injection": "auto",
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}

	// Mock system mode.
	origUID := EffectiveUID
	EffectiveUID = func() int { return 0 }
	defer func() { EffectiveUID = origUID }()

	// Mock config path.
	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return configPath }
	defer func() { getConfigPathFunc = origGetConfig }()

	_, err := loadConfig()
	if err == nil {
		t.Fatal("loadConfig should reject CA outside /etc/docker-helper in system mode")
	}
	if !strings.Contains(err.Error(), systemCASourceRoot) {
		t.Errorf("expected error mentioning %s, got: %v", systemCASourceRoot, err)
	}
}

func TestLoadConfigUserModeAcceptsArbitraryCA(t *testing.T) {
	// loadConfig in user mode must accept arbitrary absolute CA paths.
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	caPath := filepath.Join(dir, "test-ca.crt")
	generateTestCAPEM(t, caPath)

	// Manually write config.
	cfg := map[string]any{
		"allowed_root":         testAllowedRootDir(t),
		"session_ttl":          "12h",
		"trusted_ca_path":      caPath,
		"trusted_ca_injection": "auto",
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}

	// Mock user mode.
	origUID := EffectiveUID
	EffectiveUID = func() int { return 1000 }
	defer func() { EffectiveUID = origUID }()

	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return configPath }
	defer func() { getConfigPathFunc = origGetConfig }()

	// Use XDG environment variables for user mode paths.
	runtimeDir := filepath.Join(dir, "runtime")
	stateDir := filepath.Join(dir, "state")
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)
	t.Setenv("XDG_STATE_HOME", stateDir)

	loaded, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig should accept arbitrary CA path in user mode: %v", err)
	}
	if loaded.TrustedCAPath != caPath {
		t.Errorf("TrustedCAPath = %q, want %q", loaded.TrustedCAPath, caPath)
	}
	if loaded.TrustedCAPreparedDir == "" {
		t.Error("TrustedCAPreparedDir should be set")
	}
}
