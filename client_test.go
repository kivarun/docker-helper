package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
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

func setupCLITestEnv(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	runtimeDir := filepath.Join(dir, "runtime")
	xdgConfigHome := dir
	tokenPath := filepath.Join(xdgConfigHome, "docker-helper", "admin.token")
	configPath := filepath.Join(xdgConfigHome, "docker-helper", "config.json")
	socketPath := filepath.Join(runtimeDir, "docker-helper", "docker-helper.sock")

	if err := os.MkdirAll(filepath.Dir(socketPath), 0700); err != nil {
		t.Fatalf("mkdir runtime: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(tokenPath), 0700); err != nil {
		t.Fatalf("mkdir config: %v", err)
	}

	if err := os.WriteFile(tokenPath, []byte("test-token\n"), 0600); err != nil {
		t.Fatalf("write token: %v", err)
	}

	allowedRoot := testAllowedRootDir(t)
	configData := []byte(`{"allowed_root":"` + allowedRoot + `","session_ttl":"12h"}`)
	if err := os.WriteFile(configPath, configData, 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	t.Setenv("DOCKER_HELPER_CONFIG", configPath)
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)
	t.Setenv("XDG_CONFIG_HOME", xdgConfigHome)

	return socketPath
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
		return readTokenFile(tokenPath)
	}, nil)

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
		return readTokenFile(tokenPath)
	}, nil)

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
		return readTokenFile(tokenPath)
	}, nil)

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
	}, nil)

	_, err := client.listSessions()
	if err == nil {
		t.Fatal("expected connection error for nonexistent socket")
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

func TestPrintSessionsTablePrincipal(t *testing.T) {
	principal := "alice"
	sessions := []sessionJSON{
		{ID: "dhs_001", PrincipalName: &principal, Workspace: "/srv/ws-a", CreatedAt: "2024-01-01T00:00:00Z", ExpiresAt: "2024-01-02T00:00:00Z"},
		{ID: "dhs_002", PrincipalName: nil, Workspace: "/srv/ws-b", CreatedAt: "2024-01-01T00:00:00Z", ExpiresAt: "2024-01-02T00:00:00Z"},
	}

	var buf strings.Builder
	printSessionsTable(&buf, sessions)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected exactly 3 lines, got %d: %s", len(lines), buf.String())
	}

	header := strings.Fields(lines[0])
	if len(header) != 5 {
		t.Fatalf("expected 5 header columns, got %d: %v", len(header), header)
	}
	if !slices.Equal(header, []string{"ID", "PRINCIPAL", "WORKSPACE", "CREATED", "EXPIRES"}) {
		t.Errorf("header = %v, want [ID PRINCIPAL WORKSPACE CREATED EXPIRES]", header)
	}

	first := strings.Fields(lines[1])
	if len(first) != 5 {
		t.Fatalf("expected 5 fields in first data row, got %d: %v", len(first), first)
	}
	if first[0] != "dhs_001" {
		t.Errorf("fields[0] = %q, want %q", first[0], "dhs_001")
	}
	if first[1] != "alice" {
		t.Errorf("fields[1] = %q, want %q", first[1], "alice")
	}

	second := strings.Fields(lines[2])
	if len(second) != 5 {
		t.Fatalf("expected 5 fields in second data row, got %d: %v", len(second), second)
	}
	if second[0] != "dhs_002" {
		t.Errorf("fields[0] = %q, want %q", second[0], "dhs_002")
	}
	if second[1] != "-" {
		t.Errorf("fields[1] = %q, want %q", second[1], "-")
	}
}

func TestSessionListJSONOutput(t *testing.T) {
	socketPath := setupCLITestEnv(t)

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

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"session", "list", "--json"}, &stdout, &stderr)

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

func TestSessionListJSONFlag(t *testing.T) {
	socketPath := setupCLITestEnv(t)

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

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"session", "list", "--json"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %s)", code, stderr.String())
	}

	var decoded listSessionsResponse
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("stdout is not valid JSON: %v (output: %s)", err, stdout.String())
	}

	if !decoded.OK {
		t.Fatal("expected ok=true")
	}
}

func TestSessionListUnknownFlag(t *testing.T) {
	var stderr bytes.Buffer
	code := runCommandWithWriters([]string{"session", "list", "--unknown"}, &bytes.Buffer{}, &stderr)
	if code != 2 {
		t.Errorf("expected exit code 2, got %d", code)
	}
}

func TestSessionListNoFlags(t *testing.T) {
	socketPath := setupCLITestEnv(t)

	startTestServer(t, socketPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(listSessionsResponse{
			OK:       true,
			Sessions: []sessionJSON{},
		})
	})

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"session", "list"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %s)", code, stderr.String())
	}
}

// ---------- principal list CLI ----------

// startPrincipalListTestServer starts an HTTP test server answering
// GET /principals with the given principals. It requires the request to
// carry the token from tokenPath as a Bearer token.
func startPrincipalListTestServer(t *testing.T, principals []principalSummary) (endpoint string, tokenPath string) {
	t.Helper()

	const token = "test-token"

	mux := http.NewServeMux()
	mux.HandleFunc("GET /principals", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]any{"ok": false, "code": "unauthorized"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(listPrincipalsResponse{OK: true, Principals: principals})
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	tokenPath = filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte(token), 0600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	return server.URL, tokenPath
}

func TestPrincipalListHumanOutput(t *testing.T) {
	endpoint, tokenPath := startPrincipalListTestServer(t, []principalSummary{
		{Username: "alice", UID: 1001, GID: 1001, Home: "/home/alice", Enabled: true},
		{Username: "bob", UID: 1002, GID: 1002, Home: "/home/bob", Enabled: false},
	})

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"principal", "list", "--endpoint", endpoint, "--token-file", tokenPath}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %s)", code, stderr.String())
	}
	if stderr.Len() > 0 {
		t.Errorf("expected empty stderr, got: %s", stderr.String())
	}

	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d: %s", len(lines), stdout.String())
	}
	header := strings.Fields(lines[0])
	if !slices.Equal(header, []string{"USER", "UID", "GID", "HOME", "ENABLED"}) {
		t.Errorf("header = %v, want [USER UID GID HOME ENABLED]", header)
	}
	first := strings.Fields(lines[1])
	if !slices.Equal(first, []string{"alice", "1001", "1001", "/home/alice", "yes"}) {
		t.Errorf("first row = %v, want [alice 1001 1001 /home/alice yes]", first)
	}
	second := strings.Fields(lines[2])
	if !slices.Equal(second, []string{"bob", "1002", "1002", "/home/bob", "no"}) {
		t.Errorf("second row = %v, want [bob 1002 1002 /home/bob no] (disabled principal must be listed)", second)
	}
}

func TestPrincipalListJSONOutput(t *testing.T) {
	endpoint, tokenPath := startPrincipalListTestServer(t, []principalSummary{
		{Username: "alice", UID: 1001, GID: 1001, Home: "/home/alice", Enabled: true},
		{Username: "bob", UID: 1002, GID: 1002, Home: "/home/bob", Enabled: false},
	})

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"principal", "list", "--endpoint", endpoint, "--token-file", tokenPath, "--json"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %s)", code, stderr.String())
	}
	if stderr.Len() > 0 {
		t.Errorf("expected empty stderr, got: %s", stderr.String())
	}

	var decoded listPrincipalsResponse
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("stdout is not valid JSON: %v (output: %s)", err, stdout.String())
	}
	if !decoded.OK {
		t.Fatal("expected ok=true")
	}
	if len(decoded.Principals) != 2 {
		t.Fatalf("expected 2 principals, got %d", len(decoded.Principals))
	}
	want := []principalSummary{
		{Username: "alice", UID: 1001, GID: 1001, Home: "/home/alice", Enabled: true},
		{Username: "bob", UID: 1002, GID: 1002, Home: "/home/bob", Enabled: false},
	}
	if !slices.Equal(decoded.Principals, want) {
		t.Errorf("principals = %+v, want %+v (order and enabled must be preserved)", decoded.Principals, want)
	}
}

func TestPrincipalListEmptyHuman(t *testing.T) {
	endpoint, tokenPath := startPrincipalListTestServer(t, []principalSummary{})

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"principal", "list", "--endpoint", endpoint, "--token-file", tokenPath}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %s)", code, stderr.String())
	}
	if stderr.Len() > 0 {
		t.Errorf("expected empty stderr, got: %s", stderr.String())
	}

	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected header row only, got %d lines: %q", len(lines), stdout.String())
	}
	header := strings.Fields(lines[0])
	if !slices.Equal(header, []string{"USER", "UID", "GID", "HOME", "ENABLED"}) {
		t.Errorf("header = %v, want [USER UID GID HOME ENABLED]", header)
	}
}

func TestPrincipalListEmptyJSON(t *testing.T) {
	endpoint, tokenPath := startPrincipalListTestServer(t, []principalSummary{})

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"principal", "list", "--endpoint", endpoint, "--token-file", tokenPath, "--json"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %s)", code, stderr.String())
	}
	if stderr.Len() > 0 {
		t.Errorf("expected empty stderr, got: %s", stderr.String())
	}

	var decoded listPrincipalsResponse
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("stdout is not valid JSON: %v (output: %s)", err, stdout.String())
	}
	if !decoded.OK {
		t.Fatal("expected ok=true")
	}
	if len(decoded.Principals) != 0 {
		t.Errorf("expected 0 principals, got %d", len(decoded.Principals))
	}
}

func TestPrincipalListSystemFlagAccepted(t *testing.T) {
	// --system should be accepted by the flag parser.
	// It will fail at connection time because there's no daemon,
	// but the flag itself should not be "unknown".
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"principal", "list", "--system"}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected non-zero exit (no daemon running)")
	}
	if strings.Contains(stderr.String(), "unknown flag") {
		t.Fatalf("--system should not be unknown: %s", stderr.String())
	}
}

func TestCreateSessionRequest(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "test.sock")
	tokenPath := filepath.Join(dir, "admin.token")

	if err := os.WriteFile(tokenPath, []byte("test-token\n"), 0600); err != nil {
		t.Fatalf("write token: %v", err)
	}

	var capturedMethod string
	var capturedPath string
	var capturedAuth string
	var capturedBody string
	var capturedPayload string
	startTestServer(t, socketPath, func(w http.ResponseWriter, r *http.Request) {
		capturedMethod = r.Method
		capturedPath = r.URL.Path
		capturedAuth = r.Header.Get("Authorization")
		capturedBody = r.Header.Get("Content-Type")
		buf := new(strings.Builder)
		io.Copy(buf, r.Body)
		capturedPayload = buf.String()
		r.Body.Close()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(createSessionResponse{
			OK: true,
			Session: sessionJSON{
				ID:        "dhs_001",
				Workspace: "/home/user/proj",
				CreatedAt: "2024-01-01T00:00:00Z",
				ExpiresAt: "2024-01-02T00:00:00Z",
			},
			Token: "dht_session_token",
		})
	})

	client := newUnixAPIClient(socketPath, func() (string, error) {
		return readTokenFile(tokenPath)
	}, nil)

	result, err := client.createSession("/home/user/proj")
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	if capturedMethod != "POST" {
		t.Errorf("expected method POST, got %q", capturedMethod)
	}
	if capturedPath != "/sessions" {
		t.Errorf("expected path /sessions, got %q", capturedPath)
	}
	if capturedAuth != "Bearer test-token" {
		t.Errorf("expected 'Bearer test-token', got %q", capturedAuth)
	}
	if capturedBody != "application/json" {
		t.Errorf("expected 'application/json', got %q", capturedBody)
	}
	if !strings.Contains(capturedPayload, `"workspace":"/home/user/proj"`) {
		t.Errorf("expected workspace in body, got: %s", capturedPayload)
	}
	if !result.OK {
		t.Fatal("expected ok=true")
	}
	if result.Session.ID != "dhs_001" {
		t.Errorf("expected id dhs_001, got %s", result.Session.ID)
	}
	if result.Token != "dht_session_token" {
		t.Errorf("expected token dht_session_token, got %s", result.Token)
	}
}

func TestSessionCreateJSONOutput(t *testing.T) {
	socketPath := setupCLITestEnv(t)

	expectedSession := sessionJSON{
		ID:        "dhs_001",
		Workspace: "/home/user/proj",
		CreatedAt: "2024-01-01T00:00:00Z",
		ExpiresAt: "2024-01-02T00:00:00Z",
	}

	startTestServer(t, socketPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(createSessionResponse{
			OK:      true,
			Session: expectedSession,
			Token:   "dht_session_token",
		})
	})

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters(
		[]string{"session", "create", "--workspace", "/home/user/proj", "--json"},
		&stdout, &stderr,
	)

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %s)", code, stderr.String())
	}

	if stderr.Len() > 0 {
		t.Errorf("expected empty stderr, got: %s", stderr.String())
	}

	var decoded createSessionResponse
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("stdout is not valid JSON: %v (output: %s)", err, stdout.String())
	}

	if !decoded.OK {
		t.Fatal("expected ok=true")
	}
	if decoded.Session.ID != "dhs_001" {
		t.Errorf("expected id dhs_001, got %s", decoded.Session.ID)
	}
	if decoded.Session.Workspace != "/home/user/proj" {
		t.Errorf("expected workspace /home/user/proj, got %s", decoded.Session.Workspace)
	}
	if decoded.Token != "dht_session_token" {
		t.Errorf("expected token dht_session_token, got %s", decoded.Token)
	}
}

func TestSessionCreateTextOutput(t *testing.T) {
	socketPath := setupCLITestEnv(t)

	startTestServer(t, socketPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(createSessionResponse{
			OK: true,
			Session: sessionJSON{
				ID:        "dhs_001",
				Workspace: "/home/user/proj",
				CreatedAt: "2024-01-01T00:00:00Z",
				ExpiresAt: "2024-01-02T00:00:00Z",
			},
			Token: "dht_session_token",
		})
	})

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters(
		[]string{"session", "create", "--workspace", "/home/user/proj"},
		&stdout, &stderr,
	)

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %s)", code, stderr.String())
	}

	output := stdout.String()

	// Token must appear in stdout.
	if !strings.Contains(output, "dht_session_token") {
		t.Errorf("expected token in stdout: %s", output)
	}
	if !strings.Contains(output, "dhs_001") {
		t.Errorf("expected ID in stdout: %s", output)
	}
	if !strings.Contains(output, "/home/user/proj") {
		t.Errorf("expected workspace in stdout: %s", output)
	}

	// Token must NOT appear in stderr.
	if strings.Contains(stderr.String(), "dht_") {
		t.Errorf("token must not appear in stderr: %s", stderr.String())
	}
}

func TestSessionCreateTokenNotInStderr(t *testing.T) {
	socketPath := setupCLITestEnv(t)

	startTestServer(t, socketPath, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"token":"dht_must_not_leak"}`)
	})

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters(
		[]string{"session", "create", "--workspace", "/home/user/proj"},
		&stdout, &stderr,
	)

	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}

	// Token must not leak into stderr on error.
	if strings.Contains(stderr.String(), "dht_must_not_leak") {
		t.Errorf("token must not appear in stderr: %s", stderr.String())
	}
	// Token must not leak into stdout on error.
	if strings.Contains(stdout.String(), "dht_must_not_leak") {
		t.Errorf("token must not appear in stdout: %s", stdout.String())
	}
}

func TestSessionCreateMissingWorkspace(t *testing.T) {
	var stderr bytes.Buffer
	code := runCommandWithWriters(
		[]string{"session", "create"},
		&bytes.Buffer{}, &stderr,
	)
	if code != 2 {
		t.Errorf("expected exit code 2, got %d", code)
	}
}

func TestSessionCreateUnknownFlag(t *testing.T) {
	var stderr bytes.Buffer
	code := runCommandWithWriters(
		[]string{"session", "create", "--unknown"},
		&bytes.Buffer{}, &stderr,
	)
	if code != 2 {
		t.Errorf("expected exit code 2, got %d", code)
	}
}

func TestSessionCreateHTTPError(t *testing.T) {
	socketPath := setupCLITestEnv(t)

	startTestServer(t, socketPath, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	})

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters(
		[]string{"session", "create", "--workspace", "/home/user/proj"},
		&stdout, &stderr,
	)

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestSessionCreateHelpNoAPI(t *testing.T) {
	// Set DOCKER_HELPER_CONFIG to nonexistent path to prove no config read.
	t.Setenv("DOCKER_HELPER_CONFIG", "/nonexistent/path/that/does/not/exist/config.json")

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters(
		[]string{"session", "create", "--help"},
		&stdout, &stderr,
	)
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	if !strings.Contains(stdout.String(), "create") {
		t.Errorf("expected help text: %s", stdout.String())
	}
}

type errorWriter struct{}

func (errorWriter) Write(p []byte) (int, error) {
	return 0, fmt.Errorf("write error")
}

func TestSessionCreateStdoutWriteError(t *testing.T) {
	socketPath := setupCLITestEnv(t)

	startTestServer(t, socketPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(createSessionResponse{
			OK: true,
			Session: sessionJSON{
				ID:        "dhs_001",
				Workspace: "/home/user/proj",
				CreatedAt: "2024-01-01T00:00:00Z",
				ExpiresAt: "2024-01-02T00:00:00Z",
			},
			Token: "dht_secret_token",
		})
	})

	var stderr bytes.Buffer
	code := runCommandWithWriters(
		[]string{"session", "create", "--workspace", "/home/user/proj"},
		errorWriter{}, &stderr,
	)

	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}

	// Token must not appear in stderr.
	if strings.Contains(stderr.String(), "dht_secret_token") {
		t.Errorf("token must not appear in stderr: %s", stderr.String())
	}
}

func TestSessionCreateWorkspaceNoValue(t *testing.T) {
	var stderr bytes.Buffer
	code := runCommandWithWriters(
		[]string{"session", "create", "--workspace"},
		&bytes.Buffer{}, &stderr,
	)
	if code != 2 {
		t.Errorf("expected exit code 2, got %d", code)
	}
}

func TestSessionCreateWorkspaceEmptyValue(t *testing.T) {
	var stderr bytes.Buffer
	code := runCommandWithWriters(
		[]string{"session", "create", "--workspace", ""},
		&bytes.Buffer{}, &stderr,
	)
	if code != 2 {
		t.Errorf("expected exit code 2, got %d", code)
	}
}

func TestDeleteSessionRequest(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "test.sock")
	tokenPath := filepath.Join(dir, "admin.token")

	if err := os.WriteFile(tokenPath, []byte("test-token\n"), 0600); err != nil {
		t.Fatalf("write token: %v", err)
	}

	var capturedMethod string
	var capturedPath string
	var capturedAuth string
	startTestServer(t, socketPath, func(w http.ResponseWriter, r *http.Request) {
		capturedMethod = r.Method
		capturedPath = r.URL.Path
		capturedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	})

	client := newUnixAPIClient(socketPath, func() (string, error) {
		return readTokenFile(tokenPath)
	}, nil)

	if err := client.deleteSession("dhs_001"); err != nil {
		t.Fatalf("deleteSession: %v", err)
	}

	if capturedMethod != "DELETE" {
		t.Errorf("expected method DELETE, got %q", capturedMethod)
	}
	if capturedPath != "/sessions/dhs_001" {
		t.Errorf("expected path /sessions/dhs_001, got %q", capturedPath)
	}
	if capturedAuth != "Bearer test-token" {
		t.Errorf("expected 'Bearer test-token', got %q", capturedAuth)
	}
}

func TestDeleteSessionEscapedID(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "test.sock")
	tokenPath := filepath.Join(dir, "admin.token")

	if err := os.WriteFile(tokenPath, []byte("test-token\n"), 0600); err != nil {
		t.Fatalf("write token: %v", err)
	}

	testID := "dhs_001/with?special#chars"

	var capturedMethod string
	var capturedRequestURI string
	var capturedRawQuery string
	var capturedAuth string
	startTestServer(t, socketPath, func(w http.ResponseWriter, r *http.Request) {
		capturedMethod = r.Method
		capturedRequestURI = r.RequestURI
		capturedRawQuery = r.URL.RawQuery
		capturedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	})

	client := newUnixAPIClient(socketPath, func() (string, error) {
		return readTokenFile(tokenPath)
	}, nil)

	if err := client.deleteSession(testID); err != nil {
		t.Fatalf("deleteSession: %v", err)
	}

	if capturedMethod != "DELETE" {
		t.Errorf("expected method DELETE, got %q", capturedMethod)
	}
	if capturedRawQuery != "" {
		t.Errorf("expected empty RawQuery, got %q", capturedRawQuery)
	}
	expectedRequestURI := "/sessions/" + url.PathEscape(testID)
	if capturedRequestURI != expectedRequestURI {
		t.Errorf("expected RequestURI %q, got %q", expectedRequestURI, capturedRequestURI)
	}
	if capturedAuth != "Bearer test-token" {
		t.Errorf("expected 'Bearer test-token', got %q", capturedAuth)
	}
}

func TestSessionDeleteJSONOutput(t *testing.T) {
	socketPath := setupCLITestEnv(t)

	startTestServer(t, socketPath, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters(
		[]string{"session", "delete", "--id", "dhs_001", "--json"},
		&stdout, &stderr,
	)

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %s)", code, stderr.String())
	}

	var decoded map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("stdout is not valid JSON: %v (output: %s)", err, stdout.String())
	}

	if decoded["ok"] != true {
		t.Error("expected ok=true")
	}
	if decoded["id"] != "dhs_001" {
		t.Errorf("expected id dhs_001, got %v", decoded["id"])
	}
	if decoded["deleted"] != true {
		t.Error("expected deleted=true")
	}
}

func TestSessionDeleteTextOutput(t *testing.T) {
	socketPath := setupCLITestEnv(t)

	startTestServer(t, socketPath, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters(
		[]string{"session", "delete", "--id", "dhs_001"},
		&stdout, &stderr,
	)

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %s)", code, stderr.String())
	}

	output := stdout.String()
	if !strings.Contains(output, "dhs_001") {
		t.Errorf("expected ID in output: %s", output)
	}
	if !strings.Contains(output, "DELETED: true") {
		t.Errorf("expected 'DELETED: true' in output: %s", output)
	}
}

func TestSessionDeleteMissingID(t *testing.T) {
	var stderr bytes.Buffer
	code := runCommandWithWriters(
		[]string{"session", "delete"},
		&bytes.Buffer{}, &stderr,
	)
	if code != 2 {
		t.Errorf("expected exit code 2, got %d", code)
	}
}

func TestSessionDeleteIDNoValue(t *testing.T) {
	var stderr bytes.Buffer
	code := runCommandWithWriters(
		[]string{"session", "delete", "--id"},
		&bytes.Buffer{}, &stderr,
	)
	if code != 2 {
		t.Errorf("expected exit code 2, got %d", code)
	}
}

func TestSessionDeleteIDEmptyValue(t *testing.T) {
	var stderr bytes.Buffer
	code := runCommandWithWriters(
		[]string{"session", "delete", "--id", ""},
		&bytes.Buffer{}, &stderr,
	)
	if code != 2 {
		t.Errorf("expected exit code 2, got %d", code)
	}
}

func TestSessionDeleteUnknownFlag(t *testing.T) {
	var stderr bytes.Buffer
	code := runCommandWithWriters(
		[]string{"session", "delete", "--unknown"},
		&bytes.Buffer{}, &stderr,
	)
	if code != 2 {
		t.Errorf("expected exit code 2, got %d", code)
	}
}

func TestSessionDeleteHTTPError(t *testing.T) {
	socketPath := setupCLITestEnv(t)

	startTestServer(t, socketPath, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"secret":"dht_must_not_leak"}`)
	})

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters(
		[]string{"session", "delete", "--id", "dhs_001"},
		&stdout, &stderr,
	)

	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}

	if strings.Contains(stderr.String(), "dht_must_not_leak") {
		t.Errorf("marker must not appear in stderr: %s", stderr.String())
	}
	if strings.Contains(stdout.String(), "dht_must_not_leak") {
		t.Errorf("marker must not appear in stdout: %s", stdout.String())
	}
}

func TestSessionDeleteStdoutWriteError(t *testing.T) {
	socketPath := setupCLITestEnv(t)

	startTestServer(t, socketPath, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	var stderr bytes.Buffer
	code := runCommandWithWriters(
		[]string{"session", "delete", "--id", "dhs_001"},
		errorWriter{}, &stderr,
	)

	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
}

func TestSessionDeleteHelpNoAPI(t *testing.T) {
	t.Setenv("DOCKER_HELPER_CONFIG", "/nonexistent/path/that/does/not/exist/config.json")

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters(
		[]string{"session", "delete", "--help"},
		&stdout, &stderr,
	)
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	if !strings.Contains(stdout.String(), "delete") {
		t.Errorf("expected help text: %s", stdout.String())
	}
}

// ---------- apiError structured error ----------

func TestApiErrorStructured(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "test.sock")
	tokenPath := filepath.Join(dir, "admin.token")

	if err := os.WriteFile(tokenPath, []byte("test-token"), 0600); err != nil {
		t.Fatalf("write token: %v", err)
	}

	startTestServer(t, socketPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{
			"ok":      false,
			"code":    "invalid_config",
			"message": "invalid configuration",
		})
	})

	client := newUnixAPIClient(socketPath, func() (string, error) {
		return readTokenFile(tokenPath)
	}, nil)

	_, err := client.listSessions()
	if err == nil {
		t.Fatal("expected error")
	}

	var apiErr *apiError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *apiError, got %T: %v", err, err)
	}
	if apiErr.Status != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", apiErr.Status)
	}
	if apiErr.Code != "invalid_config" {
		t.Errorf("expected code 'invalid_config', got %q", apiErr.Code)
	}
	if apiErr.Message != "invalid configuration" {
		t.Errorf("expected message 'invalid configuration', got %q", apiErr.Message)
	}
	// Error string should contain "API error" for test compatibility
	if !strings.Contains(apiErr.Error(), "API error") {
		t.Errorf("expected 'API error' in error string, got: %s", apiErr.Error())
	}
}

func TestApiErrorMalformedBody(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "test.sock")
	tokenPath := filepath.Join(dir, "admin.token")

	if err := os.WriteFile(tokenPath, []byte("test-token"), 0600); err != nil {
		t.Fatalf("write token: %v", err)
	}

	startTestServer(t, socketPath, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "not-json-at-all")
	})

	client := newUnixAPIClient(socketPath, func() (string, error) {
		return readTokenFile(tokenPath)
	}, nil)

	_, err := client.listSessions()
	if err == nil {
		t.Fatal("expected error")
	}

	var apiErr *apiError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *apiError, got %T: %v", err, err)
	}
	if apiErr.Status != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", apiErr.Status)
	}
	if apiErr.Code != "" {
		t.Errorf("expected empty code for malformed body, got %q", apiErr.Code)
	}
	if !strings.Contains(apiErr.Error(), "API error") {
		t.Errorf("expected 'API error' in error string, got: %s", apiErr.Error())
	}
	// Raw body must not leak
	if strings.Contains(apiErr.Error(), "not-json-at-all") {
		t.Error("raw body must not appear in error")
	}
}

func TestApiErrorEmptyBody(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "test.sock")
	tokenPath := filepath.Join(dir, "admin.token")

	if err := os.WriteFile(tokenPath, []byte("test-token"), 0600); err != nil {
		t.Fatalf("write token: %v", err)
	}

	startTestServer(t, socketPath, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})

	client := newUnixAPIClient(socketPath, func() (string, error) {
		return readTokenFile(tokenPath)
	}, nil)

	_, err := client.listSessions()
	if err == nil {
		t.Fatal("expected error")
	}

	var apiErr *apiError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *apiError, got %T: %v", err, err)
	}
	if apiErr.Status != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", apiErr.Status)
	}
	if apiErr.Code != "" {
		t.Errorf("expected empty code for empty body, got %q", apiErr.Code)
	}
}

// ---------- delete 204 ----------

func TestDeleteSession204Success(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "test.sock")
	tokenPath := filepath.Join(dir, "admin.token")

	if err := os.WriteFile(tokenPath, []byte("test-token"), 0600); err != nil {
		t.Fatalf("write token: %v", err)
	}

	startTestServer(t, socketPath, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	client := newUnixAPIClient(socketPath, func() (string, error) {
		return readTokenFile(tokenPath)
	}, nil)

	if err := client.deleteSession("dhs_001"); err != nil {
		t.Fatalf("deleteSession: %v", err)
	}
}

// ---------- reload uses common decoder ----------

func TestReloadErrorStructured(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "test.sock")
	tokenPath := filepath.Join(dir, "admin.token")

	if err := os.WriteFile(tokenPath, []byte("test-token"), 0600); err != nil {
		t.Fatalf("write token: %v", err)
	}

	startTestServer(t, socketPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{
			"ok":      false,
			"code":    "invalid_config",
			"message": "invalid configuration",
		})
	})

	client := newUnixAPIClient(socketPath, func() (string, error) {
		return readTokenFile(tokenPath)
	}, nil)

	resp, err := client.doAuthenticatedRequest("POST", "/reload", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	_, err = client.readResponseBody(resp)
	if err == nil {
		t.Fatal("expected error")
	}

	var apiErr *apiError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *apiError, got %T: %v", err, err)
	}
	if apiErr.Status != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", apiErr.Status)
	}
	if apiErr.Code != "invalid_config" {
		t.Errorf("expected code 'invalid_config', got %q", apiErr.Code)
	}
	if apiErr.Message != "invalid configuration" {
		t.Errorf("expected message 'invalid configuration', got %q", apiErr.Message)
	}
}

// ---------- transport error remains distinguishable ----------

func TestTransportErrorNotApiError(t *testing.T) {
	client := newUnixAPIClient("/nonexistent/path.sock", func() (string, error) {
		return "token", nil
	}, nil)

	_, err := client.listSessions()
	if err == nil {
		t.Fatal("expected error for nonexistent socket")
	}

	var apiErr *apiError
	if errors.As(err, &apiErr) {
		t.Errorf("transport error should not be *apiError, got: %v", apiErr)
	}
	// Should contain "request failed" from doAuthenticatedRequest
	if !strings.Contains(err.Error(), "request failed") {
		t.Errorf("expected 'request failed' in transport error, got: %v", err)
	}
}

// ---------- principal/credential client methods ----------

// stubRoundTripper captures the last request and returns a canned response.
type stubRoundTripper struct {
	lastRequest *http.Request
	status      int
	body        string
}

func (s *stubRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	s.lastRequest = req
	return &http.Response{
		StatusCode: s.status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(s.body)),
	}, nil
}

// newStubClient creates an apiClient backed by a stub transport for unit tests.
func newStubClient(t *testing.T, status int, body string) (*apiClient, *stubRoundTripper) {
	t.Helper()
	stub := &stubRoundTripper{status: status, body: body}
	return &apiClient{
		httpClient:  &http.Client{Transport: stub},
		baseURL:     "http://localhost",
		tokenSource: func() (string, error) { return "test-token", nil },
	}, stub
}

func TestPrincipalCredentialClientRequests(t *testing.T) {
	tests := []struct {
		name       string
		call       func(*apiClient) error
		wantMethod string
		wantURI    string
		wantBody   string
	}{
		{
			name:       "createPrincipal",
			call:       func(c *apiClient) error { _, err := c.createPrincipal("bob"); return err },
			wantMethod: "POST",
			wantURI:    "/principals",
			wantBody:   `{"username":"bob"}`,
		},
		{
			name:       "listPrincipals",
			call:       func(c *apiClient) error { _, err := c.listPrincipals(); return err },
			wantMethod: "GET",
			wantURI:    "/principals",
		},
		{
			name:       "showPrincipal",
			call:       func(c *apiClient) error { _, err := c.showPrincipal("ali/ce"); return err },
			wantMethod: "GET",
			wantURI:    "/principals/ali%2Fce",
		},
		{
			name:       "setPrincipalEnabled",
			call:       func(c *apiClient) error { _, err := c.setPrincipalEnabled("bo/b", true); return err },
			wantMethod: "PATCH",
			wantURI:    "/principals/bo%2Fb",
			wantBody:   `{"enabled":true}`,
		},
		{
			name:       "addPrincipalAllowedRoot",
			call:       func(c *apiClient) error { _, err := c.addPrincipalAllowedRoot("bob", "/data"); return err },
			wantMethod: "POST",
			wantURI:    "/principals/bob/allowed-roots",
			wantBody:   `{"path":"/data"}`,
		},
		{
			name:       "removePrincipalAllowedRoot",
			call:       func(c *apiClient) error { _, err := c.removePrincipalAllowedRoot("bob", "/data"); return err },
			wantMethod: "DELETE",
			wantURI:    "/principals/bob/allowed-roots",
			wantBody:   `{"path":"/data"}`,
		},
		{
			name:       "createPrincipalCredential",
			call:       func(c *apiClient) error { _, err := c.createPrincipalCredential("bob", "laptop"); return err },
			wantMethod: "POST",
			wantURI:    "/principals/bob/credentials",
			wantBody:   `{"name":"laptop"}`,
		},
		{
			name:       "listPrincipalCredentials",
			call:       func(c *apiClient) error { _, err := c.listPrincipalCredentials("ali/ce"); return err },
			wantMethod: "GET",
			wantURI:    "/principals/ali%2Fce/credentials",
		},
		{
			name:       "revokeCredential",
			call:       func(c *apiClient) error { _, err := c.revokeCredential("dhcr_a/bc"); return err },
			wantMethod: "POST",
			wantURI:    "/credentials/dhcr_a%2Fbc/revoke",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, stub := newStubClient(t, http.StatusOK, `{"ok":true}`)

			if err := tt.call(client); err != nil {
				t.Fatalf("call error: %v", err)
			}

			if stub.lastRequest.Method != tt.wantMethod {
				t.Errorf("method = %q, want %q", stub.lastRequest.Method, tt.wantMethod)
			}
			if got := stub.lastRequest.URL.EscapedPath(); got != tt.wantURI {
				t.Errorf("EscapedPath = %q, want %q", got, tt.wantURI)
			}
			if tt.wantBody != "" {
				buf := new(strings.Builder)
				io.Copy(buf, stub.lastRequest.Body)
				if got := buf.String(); got != tt.wantBody {
					t.Errorf("body = %q, want %q", got, tt.wantBody)
				}
			}
			if stub.lastRequest.Header.Get("Authorization") != "Bearer test-token" {
				t.Errorf("Authorization = %q, want Bearer test-token", stub.lastRequest.Header.Get("Authorization"))
			}
			if tt.wantBody != "" && stub.lastRequest.Header.Get("Content-Type") != "application/json" {
				t.Errorf("Content-Type = %q, want application/json", stub.lastRequest.Header.Get("Content-Type"))
			}
		})
	}
}

func TestPrincipalCredentialClientAPIErrors(t *testing.T) {
	tests := []struct {
		name    string
		call    func(*apiClient) error
		status  int
		code    string
		message string
	}{
		{
			name:    "showPrincipalNotFound",
			call:    func(c *apiClient) error { _, err := c.showPrincipal("x"); return err },
			status:  http.StatusNotFound,
			code:    "principal_not_found",
			message: "principal not found",
		},
		{
			name:    "revokeCredentialNotFound",
			call:    func(c *apiClient) error { _, err := c.revokeCredential("dhcr_x"); return err },
			status:  http.StatusNotFound,
			code:    "credential_not_found",
			message: "credential not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := fmt.Sprintf(`{"code":%q,"message":%q}`, tt.code, tt.message)
			client, _ := newStubClient(t, tt.status, body)

			err := tt.call(client)
			if err == nil {
				t.Fatal("expected error")
			}

			var apiErr *apiError
			if !errors.As(err, &apiErr) {
				t.Fatalf("expected *apiError, got %T: %v", err, err)
			}
			if apiErr.Status != tt.status {
				t.Errorf("status = %d, want %d", apiErr.Status, tt.status)
			}
			if apiErr.Code != tt.code {
				t.Errorf("code = %q, want %q", apiErr.Code, tt.code)
			}
		})
	}
}

func TestPrincipalCredentialClientDecoding(t *testing.T) {
	t.Run("principalResponse", func(t *testing.T) {
		body, _ := json.Marshal(principalResponse{
			OK:           true,
			Username:     "alice",
			UID:          1001,
			GID:          1001,
			Home:         "/home/alice",
			Enabled:      true,
			AllowedRoots: []string{"/home/alice", "/shared"},
		})
		client, _ := newStubClient(t, http.StatusOK, string(body))

		result, err := client.showPrincipal("alice")
		if err != nil {
			t.Fatalf("showPrincipal: %v", err)
		}
		if result.Username != "alice" {
			t.Errorf("username = %q, want %q", result.Username, "alice")
		}
		if result.UID != 1001 {
			t.Errorf("uid = %d, want 1001", result.UID)
		}
		if len(result.AllowedRoots) != 2 {
			t.Errorf("expected 2 allowed roots, got %d", len(result.AllowedRoots))
		}
	})

	t.Run("credentialResponse", func(t *testing.T) {
		body, _ := json.Marshal(createCredentialResponse{
			OK: true,
			Credential: credentialJSON{
				ID:        "dhcr_abc123",
				Principal: "alice",
				Name:      "laptop",
				CreatedAt: "2024-01-01T00:00:00Z",
			},
			Token: "dhc_secret123",
		})
		client, _ := newStubClient(t, http.StatusCreated, string(body))

		result, err := client.createPrincipalCredential("alice", "laptop")
		if err != nil {
			t.Fatalf("createPrincipalCredential: %v", err)
		}
		if result.Credential.ID != "dhcr_abc123" {
			t.Errorf("id = %q, want %q", result.Credential.ID, "dhcr_abc123")
		}
		if result.Token != "dhc_secret123" {
			t.Errorf("token = %q, want %q", result.Token, "dhc_secret123")
		}
	})
}
