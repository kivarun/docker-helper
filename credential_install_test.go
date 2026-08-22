package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
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
	})
	if err == nil {
		t.Fatal("expected error for write failure")
	}
}
func TestCredentialInstallTokenNotInOutput(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	orig := EffectiveUID
	defer func() { EffectiveUID = orig }()
	EffectiveUID = func() int { return 1000 }
	validToken := "dhc_" + strings.Repeat("a", 64)
	r, w, _ := os.Pipe()
	go func() {
		fmt.Fprintln(w, validToken)
		w.Close()
	}()
	oldStdin := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = oldStdin }()
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"credential", "install"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %s)", code, stderr.String())
	}
	// Verify credential was created with the correct token.
	credPath := filepath.Join(dir, "docker-helper", "credential.token")
	data, err := os.ReadFile(credPath)
	if err != nil {
		t.Fatalf("credential file not created: %v", err)
	}
	if string(data) != validToken+"\n" {
		t.Errorf("credential = %q, want %q", string(data), validToken+"\n")
	}
	// Token must never appear in stdout or stderr.
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
	// Set up a test server that serves POST /principals/{username}/credentials.
	mux := http.NewServeMux()
	mux.HandleFunc("POST /principals/alice/credentials", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(createCredentialResponse{
			OK: true,
			Credential: credentialJSON{
				ID:        "dhcr_test123",
				Principal: "alice",
				Name:      "laptop",
				CreatedAt: "2024-01-01T00:00:00Z",
			},
			Token: "dhc_" + strings.Repeat("a", 64),
		})
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	// Create a token file for authentication.
	tokenDir := t.TempDir()
	tokenPath := filepath.Join(tokenDir, "token")
	if err := os.WriteFile(tokenPath, []byte("test-token"), 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{
		"credential", "create",
		"--endpoint", server.URL,
		"--token-file", tokenPath,
		"--name", "laptop",
		"alice",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %s)", code, stderr.String())
	}
	out := stdout.String()
	// Verify the output includes the next step.
	if !strings.Contains(out, "docker-helper credential install") {
		t.Error("output must include 'docker-helper credential install' as next step")
	}
	// Verify the output includes the warning.
	if !strings.Contains(out, "Save the token now") {
		t.Error("output must include 'Save the token now' warning")
	}
	// Verify the token appears in output (it's shown once).
	if !strings.Contains(out, "dhc_"+strings.Repeat("a", 64)) {
		t.Error("output must include the token")
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
func TestDefaultEndpointSystemSocketUsesCredentialToken(t *testing.T) {
	origUID := EffectiveUID
	origSocket := systemSocketExists
	defer func() { EffectiveUID = origUID; systemSocketExists = origSocket }()
	EffectiveUID = func() int { return 1000 }
	systemSocketExists = func() bool { return true }

	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("XDG_RUNTIME_DIR", dir)
	credDir := filepath.Join(dir, "docker-helper")
	if err := os.MkdirAll(credDir, 0700); err != nil {
		t.Fatal(err)
	}
	validToken := "dhc_" + strings.Repeat("b", 64)
	if err := os.WriteFile(filepath.Join(credDir, "credential.token"), []byte(validToken+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	client, err := resolveOperatorClient(operatorClientOptions{})
	if err != nil {
		t.Fatalf("resolveOperatorClient: %v", err)
	}
	gotToken, err := client.tokenSource()
	if err != nil {
		t.Fatalf("tokenSource: %v", err)
	}
	if gotToken != validToken {
		t.Errorf("token = %q, want %q", gotToken, validToken)
	}
}
func TestDefaultEndpointUserSocketUsesAdminToken(t *testing.T) {
	origUID := EffectiveUID
	origSocket := systemSocketExists
	defer func() { EffectiveUID = origUID; systemSocketExists = origSocket }()
	EffectiveUID = func() int { return 1000 }
	systemSocketExists = func() bool { return false }

	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("XDG_RUNTIME_DIR", dir)
	dhDir := filepath.Join(dir, "docker-helper")
	if err := os.MkdirAll(dhDir, 0755); err != nil {
		t.Fatal(err)
	}
	adminToken := "admin-token-usermode"
	if err := os.WriteFile(filepath.Join(dhDir, "admin.token"), []byte(adminToken+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	client, err := resolveOperatorClient(operatorClientOptions{})
	if err != nil {
		t.Fatalf("resolveOperatorClient: %v", err)
	}
	gotToken, err := client.tokenSource()
	if err != nil {
		t.Fatalf("tokenSource: %v", err)
	}
	if gotToken != adminToken {
		t.Errorf("token = %q, want %q", gotToken, adminToken)
	}
}
func TestDefaultEndpointUserSocketIgnoresCredentialToken(t *testing.T) {
	origUID := EffectiveUID
	origSocket := systemSocketExists
	defer func() { EffectiveUID = origUID; systemSocketExists = origSocket }()
	EffectiveUID = func() int { return 1000 }
	systemSocketExists = func() bool { return false }

	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("XDG_RUNTIME_DIR", dir)
	dhDir := filepath.Join(dir, "docker-helper")
	if err := os.MkdirAll(dhDir, 0700); err != nil {
		t.Fatal(err)
	}
	// Both tokens exist — user socket must use admin.token, not credential.token.
	if err := os.WriteFile(filepath.Join(dhDir, "credential.token"), []byte("dhc_"+strings.Repeat("c", 64)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	adminToken := "admin-token-wins"
	if err := os.WriteFile(filepath.Join(dhDir, "admin.token"), []byte(adminToken+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	client, err := resolveOperatorClient(operatorClientOptions{})
	if err != nil {
		t.Fatalf("resolveOperatorClient: %v", err)
	}
	gotToken, err := client.tokenSource()
	if err != nil {
		t.Fatalf("tokenSource: %v", err)
	}
	if gotToken != adminToken {
		t.Errorf("token = %q, want admin.token %q (credential.token must not be used for user socket)", gotToken, adminToken)
	}
}
func TestDefaultEndpointNoTokensFails(t *testing.T) {
	origUID := EffectiveUID
	origSocket := systemSocketExists
	defer func() { EffectiveUID = origUID; systemSocketExists = origSocket }()
	EffectiveUID = func() int { return 1000 }
	systemSocketExists = func() bool { return false }

	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("XDG_RUNTIME_DIR", dir)
	_, err := resolveOperatorClient(operatorClientOptions{})
	if err == nil {
		t.Fatal("expected error when no token files exist")
	}
}
func TestDefaultEndpointNonRootFallsBackToSystem(t *testing.T) {
	origUID := EffectiveUID
	origSocket := systemSocketExists
	defer func() { EffectiveUID = origUID; systemSocketExists = origSocket }()
	EffectiveUID = func() int { return 1000 }
	systemSocketExists = func() bool { return true }

	dir := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", dir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "xdg_config"))
	credToken := "user-cred-token"
	credPath := filepath.Join(dir, "xdg_config", "docker-helper", "credential.token")
	os.MkdirAll(filepath.Dir(credPath), 0755)
	if err := os.WriteFile(credPath, []byte(credToken+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	client, err := resolveOperatorClient(operatorClientOptions{})
	if err != nil {
		t.Fatalf("resolveOperatorClient: %v", err)
	}
	gotToken, err := client.tokenSource()
	if err != nil {
		t.Fatalf("tokenSource: %v", err)
	}
	if gotToken != credToken {
		t.Errorf("token = %q, want %q", gotToken, credToken)
	}
}
func TestEndpointWithoutTokenFileRejected(t *testing.T) {
	_, err := resolveOperatorClient(operatorClientOptions{
		Endpoint: "http://127.0.0.1:8080",
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

func TestCheckCredentialStateAbsent(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	token := "dhc_" + strings.Repeat("a", 64)
	state, err := checkCredentialState(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state != credentialAbsent {
		t.Errorf("state = %v, want credentialAbsent", state)
	}
}

func TestCheckCredentialStateMatch(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	token := "dhc_" + strings.Repeat("a", 64)
	credDir := filepath.Join(dir, "docker-helper")
	if err := os.MkdirAll(credDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(credDir, "credential.token"), []byte(token+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	state, err := checkCredentialState(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state != credentialMatch {
		t.Errorf("state = %v, want credentialMatch", state)
	}
}

func TestCheckCredentialStateConflict(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	existingToken := "dhc_" + strings.Repeat("a", 64)
	newToken := "dhc_" + strings.Repeat("b", 64)
	credDir := filepath.Join(dir, "docker-helper")
	if err := os.MkdirAll(credDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(credDir, "credential.token"), []byte(existingToken+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	state, err := checkCredentialState(newToken)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state != credentialConflict {
		t.Errorf("state = %v, want credentialConflict", state)
	}
}

func TestCheckCredentialStateReadErrorFailsClosed(t *testing.T) {
	// A credential file that exists but cannot be read must NOT be treated
	// as absent. The caller must fail closed.
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	token := "dhc_" + strings.Repeat("a", 64)
	credDir := filepath.Join(dir, "docker-helper")
	if err := os.MkdirAll(credDir, 0700); err != nil {
		t.Fatal(err)
	}
	credFile := filepath.Join(credDir, "credential.token")
	if err := os.WriteFile(credFile, []byte("some-content\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// Make the file unreadable.
	if err := os.Chmod(credFile, 0000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(credFile, 0600) })

	state, err := checkCredentialState(token)
	if err == nil {
		t.Fatalf("expected error for unreadable credential file, got state %v", state)
	}
	if state != 0 {
		t.Errorf("state = %v, want 0 on error", state)
	}
}

func TestInitUserWithSystemDaemonFirstUse(t *testing.T) {
	// Regression: first-use with system daemon must actually install the credential.
	origUID := EffectiveUID
	defer func() { EffectiveUID = origUID }()
	EffectiveUID = func() int { return 1000 }

	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	validToken := "dhc_" + strings.Repeat("a", 64)

	var stdout, stderr bytes.Buffer
	err := installCredentialForInit(validToken, &stdout, &stderr)
	if err != nil {
		t.Fatalf("installCredentialForInit: %v", err)
	}

	// Credential file must exist.
	credPath := filepath.Join(dir, "docker-helper", "credential.token")
	data, err := os.ReadFile(credPath)
	if err != nil {
		t.Fatalf("credential file not created: %v", err)
	}
	if string(data) != validToken+"\n" {
		t.Errorf("credential = %q, want %q", string(data), validToken+"\n")
	}

	// File mode must be 0600.
	info, err := os.Stat(credPath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("file mode = %o, want 0600", perm)
	}

	// Directory mode must be 0700.
	dirInfo, err := os.Stat(filepath.Join(dir, "docker-helper"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0700 {
		t.Errorf("directory mode = %o, want 0700", perm)
	}

	// Output must indicate success, NOT "Credential already installed."
	out := stdout.String()
	if strings.Contains(out, "Credential already installed") {
		t.Error("first-use must NOT say 'Credential already installed'")
	}
	if !strings.Contains(out, "Credential installed successfully") {
		t.Errorf("expected success message, got: %s", out)
	}
}

func TestInitUserWithSystemDaemonSameTokenIdempotent(t *testing.T) {
	origUID := EffectiveUID
	defer func() { EffectiveUID = origUID }()
	EffectiveUID = func() int { return 1000 }

	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	token := "dhc_" + strings.Repeat("a", 64)

	// Pre-install the credential.
	credDir := filepath.Join(dir, "docker-helper")
	if err := os.MkdirAll(credDir, 0700); err != nil {
		t.Fatal(err)
	}
	credPath := filepath.Join(credDir, "credential.token")
	if err := os.WriteFile(credPath, []byte(token+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	err := installCredentialForInit(token, &stdout, &stderr)
	if err != nil {
		t.Fatalf("installCredentialForInit: %v", err)
	}

	out := stdout.String()
	if !strings.Contains(out, "Credential already installed") {
		t.Errorf("expected idempotent message, got: %s", out)
	}

	// File mode preserved.
	info, err := os.Stat(credPath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("file mode = %o, want 0600", perm)
	}
}

func TestInitUserWithSystemDaemonDifferentTokenConflict(t *testing.T) {
	origUID := EffectiveUID
	defer func() { EffectiveUID = origUID }()
	EffectiveUID = func() int { return 1000 }

	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	existingToken := "dhc_" + strings.Repeat("a", 64)
	newToken := "dhc_" + strings.Repeat("b", 64)

	// Pre-install the existing credential.
	credDir := filepath.Join(dir, "docker-helper")
	if err := os.MkdirAll(credDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(credDir, "credential.token"), []byte(existingToken+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	err := installCredentialForInit(newToken, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for different token conflict")
	}

	// Must reference credential install --force.
	if !strings.Contains(err.Error(), "credential install --force") {
		t.Errorf("error should reference 'credential install --force', got: %v", err)
	}

	// Existing credential must NOT have been overwritten.
	data, err := os.ReadFile(filepath.Join(credDir, "credential.token"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != existingToken+"\n" {
		t.Errorf("credential was overwritten: %q", string(data))
	}
}

func TestInitCLIFirstUseWithSystemDaemon(t *testing.T) {
	// End-to-end CLI regression: docker-helper init as non-root with system daemon.
	origSocket := systemSocketExists
	defer func() { systemSocketExists = origSocket }()
	systemSocketExists = func() bool { return true }

	origUID := EffectiveUID
	defer func() { EffectiveUID = origUID }()
	EffectiveUID = func() int { return 1000 }

	configDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configDir)

	// --allowed-root is required by the CLI parser even though
	// initUserWithSystemDaemon does not use it.
	allowedRoot := testAllowedRootDir(t)

	validToken := "dhc_" + strings.Repeat("c", 64)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		fmt.Fprintln(w, validToken)
		w.Close()
	}()

	oldStdin := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = oldStdin }()

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"init", "--allowed-root", allowedRoot}, &stdout, &stderr)

	r.Close()

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %s)", code, stderr.String())
	}

	// Credential file must exist.
	credPath := filepath.Join(configDir, "docker-helper", "credential.token")
	data, err := os.ReadFile(credPath)
	if err != nil {
		t.Fatalf("credential file not created: %v", err)
	}
	if string(data) != validToken+"\n" {
		t.Errorf("credential = %q, want %q", string(data), validToken+"\n")
	}

	// File mode must be 0600.
	info, err := os.Stat(credPath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("file mode = %o, want 0600", perm)
	}

	// Directory mode must be 0700.
	dirInfo, err := os.Stat(filepath.Join(configDir, "docker-helper"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0700 {
		t.Errorf("directory mode = %o, want 0700", perm)
	}

	// Output must indicate success.
	out := stdout.String()
	if strings.Contains(out, "Credential already installed") {
		t.Error("first-use must NOT say 'Credential already installed'")
	}
	if !strings.Contains(out, "Credential installed successfully") {
		t.Errorf("expected success message, got: %s", out)
	}
}
