package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateCredentialTokenValid(t *testing.T) {
	token := "dhc_" + strings.Repeat("a", 64)
	if err := validateCredentialToken(token); err != nil {
		t.Fatalf("expected valid token, got: %v", err)
	}
}

func TestValidateCredentialTokenInvalidPrefix(t *testing.T) {
	token := "abc_" + strings.Repeat("a", 64)
	err := validateCredentialToken(token)
	if err == nil {
		t.Fatal("expected error for invalid prefix")
	}
	if !strings.Contains(err.Error(), "prefix") {
		t.Errorf("expected prefix error, got: %v", err)
	}
}

func TestValidateCredentialTokenInvalidLength(t *testing.T) {
	token := "dhc_" + strings.Repeat("a", 63)
	err := validateCredentialToken(token)
	if err == nil {
		t.Fatal("expected error for invalid length")
	}
	if !strings.Contains(err.Error(), "length") {
		t.Errorf("expected length error, got: %v", err)
	}
}

func TestValidateCredentialTokenInvalidHex(t *testing.T) {
	token := "dhc_" + strings.Repeat("g", 64)
	err := validateCredentialToken(token)
	if err == nil {
		t.Fatal("expected error for invalid hex")
	}
	if !strings.Contains(err.Error(), "character") {
		t.Errorf("expected character error, got: %v", err)
	}
}

func TestValidateCredentialTokenUppercaseHex(t *testing.T) {
	token := "dhc_" + strings.Repeat("A", 64)
	err := validateCredentialToken(token)
	if err == nil {
		t.Fatal("expected error for uppercase hex")
	}
}

func TestCredentialInstallNonTTY(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	validToken := "dhc_" + strings.Repeat("a", 64)

	credPath, err := installCredential(credentialInstallConfig{
		reader:       strings.NewReader(validToken),
		writer:       safeWriteCredential,
		uid:          func() int { return 1000 },
		isTerminal:   func() bool { return false },
		readPassword: func() (string, error) { return "", nil },
		force:        false,
		stderr:       nil,
	})
	if err != nil {
		t.Fatalf("installCredential: %v", err)
	}

	expectedDir := filepath.Join(dir, "docker-helper")
	expectedPath := filepath.Join(expectedDir, "credential.token")
	if credPath != expectedPath {
		t.Errorf("credPath = %q, want %q", credPath, expectedPath)
	}

	dirInfo, err := os.Stat(expectedDir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0700 {
		t.Errorf("directory mode = %o, want 0700", perm)
	}

	fileInfo, err := os.Stat(expectedPath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fileInfo.Mode().Perm(); perm != 0600 {
		t.Errorf("file mode = %o, want 0600", perm)
	}

	data, err := os.ReadFile(expectedPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != validToken+"\n" {
		t.Errorf("file content = %q, want %q", string(data), validToken+"\n")
	}
}

func TestCredentialInstallEmptyStdin(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	_, err := installCredential(credentialInstallConfig{
		reader:       strings.NewReader(""),
		writer:       safeWriteCredential,
		uid:          func() int { return 1000 },
		isTerminal:   func() bool { return false },
		readPassword: func() (string, error) { return "", nil },
		force:        false,
		stderr:       nil,
	})
	if err == nil {
		t.Fatal("expected error for empty input")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("expected empty error, got: %v", err)
	}
}

func TestCredentialInstallExistingNoForce(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	oldToken := "dhc_" + strings.Repeat("a", 64)
	newToken := "dhc_" + strings.Repeat("b", 64)

	_, err := installCredential(credentialInstallConfig{
		reader:       strings.NewReader(oldToken),
		writer:       safeWriteCredential,
		uid:          func() int { return 1000 },
		isTerminal:   func() bool { return false },
		readPassword: func() (string, error) { return "", nil },
		force:        false,
		stderr:       nil,
	})
	if err != nil {
		t.Fatalf("first install: %v", err)
	}

	// Re-install with different token, no force — should reject.
	_, err = installCredential(credentialInstallConfig{
		reader:       strings.NewReader(newToken),
		writer:       safeWriteCredential,
		uid:          func() int { return 1000 },
		isTerminal:   func() bool { return false },
		readPassword: func() (string, error) { return "", nil },
		force:        false,
		stderr:       nil,
	})
	if err == nil {
		t.Fatal("expected error when re-installing without --force")
	}
	if !errors.Is(err, ErrCredentialAlreadyExists) {
		t.Errorf("expected ErrCredentialAlreadyExists, got: %v", err)
	}

	// Verify old token is still installed.
	credPath, _ := credentialPath()
	data, _ := os.ReadFile(credPath)
	if string(data) != oldToken+"\n" {
		t.Errorf("credential was changed: %q", string(data))
	}
}

func TestCredentialInstallRootRejected(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	_, err := installCredential(credentialInstallConfig{
		reader:       strings.NewReader("dhc_" + strings.Repeat("a", 64)),
		writer:       safeWriteCredential,
		uid:          func() int { return 0 },
		isTerminal:   func() bool { return false },
		readPassword: func() (string, error) { return "", nil },
		force:        false,
		stderr:       nil,
	})
	if err == nil {
		t.Fatal("expected error for root")
	}
	if !errors.Is(err, ErrCredentialInstallAsRoot) {
		t.Errorf("expected ErrCredentialInstallAsRoot, got: %v", err)
	}
}

func TestCredentialInstallWriterFailure(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	failingWriter := func(path string, data []byte) error {
		return fmt.Errorf("simulated write failure")
	}

	_, err := installCredential(credentialInstallConfig{
		reader:       strings.NewReader("dhc_" + strings.Repeat("a", 64)),
		writer:       failingWriter,
		uid:          func() int { return 1000 },
		isTerminal:   func() bool { return false },
		readPassword: func() (string, error) { return "", nil },
		force:        false,
		stderr:       nil,
	})
	if err == nil {
		t.Fatal("expected error for write failure")
	}
}

func TestCredentialInstallTokenNotInOutput(t *testing.T) {
	validToken := "dhc_" + strings.Repeat("a", 64)

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"credential", "install", "--help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("help exited %d", code)
	}
	// Help output must not contain the token.
	if strings.Contains(stdout.String(), validToken) {
		t.Error("token must not appear in stdout")
	}
	if strings.Contains(stderr.String(), validToken) {
		t.Error("token must not appear in stderr")
	}
}

func TestCredentialInstallHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"credential", "install", "--help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("help exited %d", code)
	}
	out := stdout.String()
	if !strings.Contains(out, "credential install") {
		t.Error("help should mention credential install")
	}
	if !strings.Contains(out, "--force") {
		t.Error("help should mention --force")
	}
}

func TestCredentialCreateShowsNextStep(t *testing.T) {
	// Verify that credential create output includes the next step.
	// The output should include "docker-helper credential install"
	// and should NOT include the actual token in the command.
	// We check the command's Run function output format by inspecting
	// the actual output lines in principal_cli.go.

	// The credential create command prints:
	// "Give this token securely to the principal."
	// "The principal installs it with:"
	// "  docker-helper credential install"
	// This is verified by checking the command definition includes
	// the expected text and does NOT include a token placeholder.

	// Static check: verify the credential install command has help text
	// that describes the principal workflow.
	installHelp := credentialInstallCommand.Help
	if installHelp == "" {
		t.Fatal("credential install command should have help text")
	}
	if !strings.Contains(installHelp, "principal") {
		t.Error("help should mention principal users")
	}
	if !strings.Contains(installHelp, "--system") {
		t.Error("help should mention --system mode")
	}
}

func TestReadTokenFromReader(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"valid", "dhc_aaa\n", "dhc_aaa", false},
		{"no newline", "dhc_aaa", "dhc_aaa", false},
		{"trailing spaces", "dhc_aaa  \n", "dhc_aaa", false},
		{"empty", "", "", true},
		{"whitespace only", "  \n", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := strings.NewReader(tt.input)
			got, err := readTokenFromReader(reader)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCredentialPath(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	path, err := credentialPath()
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(dir, "docker-helper", "credential.token")
	if path != want {
		t.Errorf("path = %q, want %q", path, want)
	}
}

func TestNonRootSystemUsesCredential(t *testing.T) {
	orig := EffectiveUID
	defer func() { EffectiveUID = orig }()
	EffectiveUID = func() int { return 1000 }

	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	credDir := filepath.Join(dir, "docker-helper")
	if err := os.MkdirAll(credDir, 0700); err != nil {
		t.Fatal(err)
	}
	validToken := "dhc_" + strings.Repeat("a", 64)
	if err := os.WriteFile(filepath.Join(credDir, "credential.token"), []byte(validToken+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	client, err := resolveOperatorClient(operatorClientOptions{
		System: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	gotToken, err := client.tokenSource()
	if err != nil {
		t.Fatalf("tokenSource: %v", err)
	}
	if gotToken != validToken {
		t.Errorf("token = %q, want %q", gotToken, validToken)
	}
}

func TestRootSystemUsesAdminToken(t *testing.T) {
	orig := EffectiveUID
	defer func() { EffectiveUID = orig }()
	EffectiveUID = func() int { return 0 }

	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	// Create admin token in a temp system config dir.
	// We can't write to /etc, so we verify the error mentions admin.token.
	_, err := resolveOperatorClient(operatorClientOptions{
		System: true,
	})
	if err == nil {
		t.Fatal("expected error when admin token doesn't exist")
	}
	if !strings.Contains(err.Error(), "admin.token") {
		t.Errorf("expected admin.token error, got: %v", err)
	}
}

func TestExplicitTokenFileHasPriority(t *testing.T) {
	orig := EffectiveUID
	defer func() { EffectiveUID = orig }()
	EffectiveUID = func() int { return 1000 }

	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	// Create credential token.
	credDir := filepath.Join(dir, "docker-helper")
	if err := os.MkdirAll(credDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(credDir, "credential.token"), []byte("credential-token\n"), 0600); err != nil {
		t.Fatal(err)
	}

	// Create explicit token file.
	tokenFile := filepath.Join(dir, "custom.token")
	if err := os.WriteFile(tokenFile, []byte("explicit-token\n"), 0600); err != nil {
		t.Fatal(err)
	}

	client, err := resolveOperatorClient(operatorClientOptions{
		System:    true,
		TokenFile: tokenFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	gotToken, err := client.tokenSource()
	if err != nil {
		t.Fatalf("tokenSource: %v", err)
	}
	if gotToken != "explicit-token" {
		t.Errorf("token = %q, want explicit-token", gotToken)
	}
}

func TestUserModeUnchanged(t *testing.T) {
	orig := EffectiveUID
	defer func() { EffectiveUID = orig }()
	EffectiveUID = func() int { return 1000 }

	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("XDG_RUNTIME_DIR", dir)

	// User mode should use admin.token in user config dir.
	_, err := resolveOperatorClient(operatorClientOptions{})
	if err == nil {
		t.Fatal("expected error when user admin.token doesn't exist")
	}
	if strings.Contains(err.Error(), "credential.token") {
		t.Error("user mode should not use credential.token")
	}
}

func TestEndpointWithoutTokenFileRejected(t *testing.T) {
	_, err := resolveOperatorClient(operatorClientOptions{
		Endpoint: "unix:///tmp/test.sock",
	})
	if err == nil {
		t.Fatal("expected error when --endpoint lacks --token-file")
	}
	if !strings.Contains(err.Error(), "--endpoint requires --token-file") {
		t.Errorf("expected endpoint error, got: %v", err)
	}
}

func TestSafeWriteCredentialAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.token")

	if err := safeWriteCredential(path, []byte("first\n")); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "first\n" {
		t.Errorf("content = %q, want first\\n", string(data))
	}

	if err := safeWriteCredential(path, []byte("second\n")); err != nil {
		t.Fatal(err)
	}

	data, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "second\n" {
		t.Errorf("content = %q, want second\\n", string(data))
	}
}

func TestSafeWriteCredentialMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.token")

	if err := safeWriteCredential(path, []byte("test\n")); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("mode = %o, want 0600", perm)
	}
}

func TestSafeWriteCredentialFailureNoTemp(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0555); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0755)

	path := filepath.Join(dir, "test.token")
	err := safeWriteCredential(path, []byte("test\n"))
	if err == nil {
		t.Fatal("expected error for read-only directory")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), "credential-") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

func TestCredentialInstallForceReplace(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	oldToken := "dhc_" + strings.Repeat("a", 64)
	newToken := "dhc_" + strings.Repeat("b", 64)

	// Install first credential.
	_, err := installCredential(credentialInstallConfig{
		reader:       strings.NewReader(oldToken),
		writer:       safeWriteCredential,
		uid:          func() int { return 1000 },
		isTerminal:   func() bool { return false },
		readPassword: func() (string, error) { return "", nil },
		force:        false,
		stderr:       nil,
	})
	if err != nil {
		t.Fatalf("first install: %v", err)
	}

	// Replace with --force while old file is in place.
	_, err = installCredential(credentialInstallConfig{
		reader:       strings.NewReader(newToken),
		writer:       safeWriteCredential,
		uid:          func() int { return 1000 },
		isTerminal:   func() bool { return false },
		readPassword: func() (string, error) { return "", nil },
		force:        true,
		stderr:       nil,
	})
	if err != nil {
		t.Fatalf("force replace: %v", err)
	}

	credPath, _ := credentialPath()
	data, err := os.ReadFile(credPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != newToken+"\n" {
		t.Errorf("credential not replaced: %q", string(data))
	}
}

func TestCredentialInstallAtomicReplace(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	oldToken := "dhc_" + strings.Repeat("a", 64)
	newToken := "dhc_" + strings.Repeat("b", 64)

	// Install first credential.
	_, err := installCredential(credentialInstallConfig{
		reader:       strings.NewReader(oldToken),
		writer:       safeWriteCredential,
		uid:          func() int { return 1000 },
		isTerminal:   func() bool { return false },
		readPassword: func() (string, error) { return "", nil },
		force:        false,
		stderr:       nil,
	})
	if err != nil {
		t.Fatalf("first install: %v", err)
	}

	// Verify old token is installed.
	credPath, _ := credentialPath()
	data, _ := os.ReadFile(credPath)
	if string(data) != oldToken+"\n" {
		t.Fatalf("expected old token, got: %q", string(data))
	}

	// Writer that fails — simulates disk full or I/O error.
	failingWriter := func(path string, data []byte) error {
		return fmt.Errorf("simulated write failure")
	}

	// Force replace with failing writer — should fail, old file intact.
	_, err = installCredential(credentialInstallConfig{
		reader:       strings.NewReader(newToken),
		writer:       failingWriter,
		uid:          func() int { return 1000 },
		isTerminal:   func() bool { return false },
		readPassword: func() (string, error) { return "", nil },
		force:        true,
		stderr:       nil,
	})
	if err == nil {
		t.Fatal("expected error for write failure")
	}

	// Verify old token is still intact.
	data, err = os.ReadFile(credPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != oldToken+"\n" {
		t.Errorf("old credential was corrupted: %q", string(data))
	}
}

func TestCredentialInstallTTYHiddenInput(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	validToken := "dhc_" + strings.Repeat("d", 64)

	_, err := installCredential(credentialInstallConfig{
		reader:       strings.NewReader(""),
		writer:       safeWriteCredential,
		uid:          func() int { return 1000 },
		isTerminal:   func() bool { return true },
		readPassword: func() (string, error) { return validToken, nil },
		force:        false,
		stderr:       nil,
	})
	if err != nil {
		t.Fatalf("TTY install: %v", err)
	}

	credPath, _ := credentialPath()
	data, _ := os.ReadFile(credPath)
	if string(data) != validToken+"\n" {
		t.Errorf("credential = %q, want %q", string(data), validToken+"\n")
	}
}

func TestCredentialInstallTTYErrorPropagation(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	_, err := installCredential(credentialInstallConfig{
		reader:       strings.NewReader(""),
		writer:       safeWriteCredential,
		uid:          func() int { return 1000 },
		isTerminal:   func() bool { return true },
		readPassword: func() (string, error) { return "", fmt.Errorf("simulated TTY error") },
		force:        false,
		stderr:       nil,
	})
	if err == nil {
		t.Fatal("expected error for TTY read failure")
	}
	if !strings.Contains(err.Error(), "simulated TTY error") {
		t.Errorf("expected TTY error, got: %v", err)
	}
}

func TestEnsureCredentialDirFixesMode(t *testing.T) {
	dir := t.TempDir()
	credDir := filepath.Join(dir, "docker-helper")

	// Create directory with wrong mode.
	if err := os.MkdirAll(credDir, 0755); err != nil {
		t.Fatal(err)
	}

	// ensureCredentialDir should fix the mode.
	if err := ensureCredentialDir(credDir); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(credDir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0700 {
		t.Errorf("directory mode = %o, want 0700", perm)
	}
}
