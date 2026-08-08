package main

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func startTestServer(t *testing.T, socketPath string, handler http.HandlerFunc) net.Listener {
	t.Helper()
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() {
		listener.Close()
		os.Remove(socketPath)
	})

	server := &http.Server{Handler: handler}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })

	return listener
}

func TestListSessionsSuccess(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "test.sock")
	tokenPath := filepath.Join(dir, "admin.token")

	const token = "test-token"
	if err := os.WriteFile(tokenPath, []byte(token), 0600); err != nil {
		t.Fatalf("write token: %v", err)
	}

	startTestServer(t, socketPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(listSessionsResponse{
			OK: true,
			Sessions: []sessionJSON{
				{ID: "dhs_001", Workspace: "/home/user/proj", CreatedAt: "2024-01-01T00:00:00Z", ExpiresAt: "2024-01-02T00:00:00Z"},
			},
		})
	})

	client := newUnixAPIClient(socketPath, func() (string, error) {
		return readAdminTokenPlain(tokenPath)
	})

	result, err := client.listSessions()
	if err != nil {
		t.Fatalf("listSessions: %v", err)
	}

	if !result.OK {
		t.Fatal("expected ok=true")
	}
	if len(result.Sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(result.Sessions))
	}
	if result.Sessions[0].ID != "dhs_001" {
		t.Errorf("expected id dhs_001, got %s", result.Sessions[0].ID)
	}
}

func TestListSessionsAuthHeader(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "test.sock")
	tokenPath := filepath.Join(dir, "admin.token")

	// Write token with trailing newline, as runInit does.
	if err := os.WriteFile(tokenPath, []byte("my-secret-token\n"), 0600); err != nil {
		t.Fatalf("write token: %v", err)
	}

	var capturedAuth string
	startTestServer(t, socketPath, func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(listSessionsResponse{OK: true, Sessions: []sessionJSON{}})
	})

	client := newUnixAPIClient(socketPath, func() (string, error) {
		return readAdminTokenPlain(tokenPath)
	})

	if _, err := client.listSessions(); err != nil {
		t.Fatalf("listSessions: %v", err)
	}

	if capturedAuth != "Bearer my-secret-token" {
		t.Errorf("expected 'Bearer my-secret-token', got %q", capturedAuth)
	}
}

func TestListSessionsAuthError(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "test.sock")
	tokenPath := filepath.Join(dir, "admin.token")

	if err := os.WriteFile(tokenPath, []byte("wrong-token"), 0600); err != nil {
		t.Fatalf("write token: %v", err)
	}

	startTestServer(t, socketPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", "Bearer")
		w.WriteHeader(http.StatusUnauthorized)
	})

	client := newUnixAPIClient(socketPath, func() (string, error) {
		return readAdminTokenPlain(tokenPath)
	})

	_, err := client.listSessions()
	if err == nil {
		t.Fatal("expected error for unauthorized response")
	}
	if !strings.Contains(err.Error(), "API error") {
		t.Errorf("expected API error, got: %v", err)
	}
}

func TestListSessionsConnectionError(t *testing.T) {
	client := newUnixAPIClient("/nonexistent/path.sock", func() (string, error) {
		return "token", nil
	})

	_, err := client.listSessions()
	if err == nil {
		t.Fatal("expected connection error for nonexistent socket")
	}
}

func TestReadAdminTokenPlainWhitespaceOnly(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "admin.token")

	if err := os.WriteFile(tokenPath, []byte("   \n\t  \n"), 0600); err != nil {
		t.Fatalf("write token: %v", err)
	}

	_, err := readAdminTokenPlain(tokenPath)
	if err == nil {
		t.Fatal("expected error for whitespace-only token file")
	}
	if !strings.Contains(err.Error(), "admin token file is empty") {
		t.Errorf("expected 'admin token file is empty', got: %v", err)
	}
}

func TestPrintSessionsTableNoToken(t *testing.T) {
	sessions := []sessionJSON{
		{ID: "dhs_abc123", Workspace: "/home/user/project", CreatedAt: "2024-01-01T10:00:00Z", ExpiresAt: "2024-01-02T10:00:00Z"},
	}

	var buf strings.Builder
	printSessionsTable(&buf, sessions)

	output := buf.String()

	// Token must not appear in output.
	if strings.Contains(output, "dht_") {
		t.Error("session token must not appear in table output")
	}

	// Session ID must appear.
	if !strings.Contains(output, "dhs_abc123") {
		t.Errorf("expected session ID in output: %s", output)
	}

	// Workspace must appear.
	if !strings.Contains(output, "/home/user/project") {
		t.Errorf("expected workspace in output: %s", output)
	}
}

func TestSessionListJSONOutput(t *testing.T) {
	dir := t.TempDir()
	runtimeDir := filepath.Join(dir, "runtime")
	xdgConfigHome := dir // XDG_CONFIG_HOME → dir, so config dir = dir/docker-helper
	tokenPath := filepath.Join(xdgConfigHome, "docker-helper", "admin.token")
	configPath := filepath.Join(xdgConfigHome, "docker-helper", "config.json")
	// Socket path derived by loadConfig: XDG_RUNTIME_DIR/docker-helper/docker-helper.sock
	socketPath := filepath.Join(runtimeDir, "docker-helper", "docker-helper.sock")

	if err := os.MkdirAll(filepath.Dir(socketPath), 0700); err != nil {
		t.Fatalf("mkdir runtime: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(tokenPath), 0700); err != nil {
		t.Fatalf("mkdir config: %v", err)
	}

	if err := os.WriteFile(tokenPath, []byte("test-token"), 0600); err != nil {
		t.Fatalf("write token: %v", err)
	}

	configData := []byte(`{"allowed_root":"` + dir + `","session_ttl":"12h"}`)
	if err := os.WriteFile(configPath, configData, 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	expectedSessions := []sessionJSON{
		{ID: "dhs_001", Workspace: "/home/user/proj", CreatedAt: "2024-01-01T00:00:00Z", ExpiresAt: "2024-01-02T00:00:00Z"},
	}

	startTestServer(t, socketPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(listSessionsResponse{
			OK:       true,
			Sessions: expectedSessions,
		})
	})

	// Set environment variables so loadConfig resolves to our test paths.
	t.Setenv("DOCKER_HELPER_CONFIG", configPath)
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)
	t.Setenv("XDG_CONFIG_HOME", xdgConfigHome)

	var stdout, stderr bytes.Buffer
	code := runSessionCommandWithWriters([]string{"list", "--json"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %s)", code, stderr.String())
	}

	if stderr.Len() > 0 {
		t.Errorf("expected empty stderr, got: %s", stderr.String())
	}

	var decoded listSessionsResponse
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("stdout is not valid JSON: %v (output: %s)", err, stdout.String())
	}

	if !decoded.OK {
		t.Fatal("expected ok=true")
	}
	if len(decoded.Sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(decoded.Sessions))
	}
	if decoded.Sessions[0].ID != "dhs_001" {
		t.Errorf("expected id dhs_001, got %s", decoded.Sessions[0].ID)
	}

	// Token must not appear in output.
	if strings.Contains(stdout.String(), "dht_") {
		t.Error("session token must not appear in JSON output")
	}
}

func TestParseSessionListFlagsJSON(t *testing.T) {
	jsonOut, err := parseSessionListFlags([]string{"--json"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !jsonOut {
		t.Error("expected jsonOutput=true")
	}
}

func TestParseSessionListFlagsUnknown(t *testing.T) {
	_, err := parseSessionListFlags([]string{"--unknown"})
	if err == nil {
		t.Fatal("expected error for unknown flag")
	}
}

func TestParseSessionListFlagsEmpty(t *testing.T) {
	jsonOut, err := parseSessionListFlags([]string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if jsonOut {
		t.Error("expected jsonOutput=false")
	}
}

func TestRunSessionCommandNoSubcommand(t *testing.T) {
	code := runSessionCommand([]string{})
	if code != 2 {
		t.Errorf("expected exit code 2, got %d", code)
	}
}

func TestRunSessionCommandUnknownSubcommand(t *testing.T) {
	code := runSessionCommand([]string{"unknown"})
	if code != 2 {
		t.Errorf("expected exit code 2, got %d", code)
	}
}

func TestRunCommandUnknown(t *testing.T) {
	code := runCommand([]string{"bogus"})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestRunCommandSessionHelp(t *testing.T) {
	code := runCommand([]string{"session", "list", "--help"})
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
}
