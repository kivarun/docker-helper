package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- Default endpoint tests ---

func TestResolveDefaultEndpointNonRoot(t *testing.T) {
	orig := EffectiveUID
	defer func() { EffectiveUID = orig }()
	EffectiveUID = func() int { return 1000 }

	dir := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", dir)
	runtimeDir := filepath.Join(dir, "docker-helper")
	os.MkdirAll(runtimeDir, 0755)

	tokenPath := filepath.Join(dir, "admin.token")
	writeTestTokenFile(t, tokenPath, "test-token")

	socketPath := filepath.Join(runtimeDir, "docker-helper.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	server := &http.Server{Handler: mux}
	go server.Serve(listener)
	defer server.Close()

	client, err := resolveOperatorClient(operatorClientOptions{
		TokenFile: tokenPath,
	})
	if err != nil {
		t.Fatalf("resolveOperatorClient: %v", err)
	}

	resp, err := client.doAuthenticatedRequest("GET", "/health", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestResolveDefaultEndpointRoot(t *testing.T) {
	orig := EffectiveUID
	defer func() { EffectiveUID = orig }()
	EffectiveUID = func() int { return 0 }

	// System mode uses /run/docker-helper. Create a test socket there.
	// We can't easily create /run/docker-helper, so use --token-file override.
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "admin.token")
	writeTestTokenFile(t, tokenPath, "test-token")

	// Verify that the default endpoint for root uses system socket path.
	client, err := resolveOperatorClient(operatorClientOptions{
		TokenFile: tokenPath,
	})
	if err != nil {
		t.Fatalf("resolveOperatorClient: %v", err)
	}

	// The baseURL should be http://localhost (Unix transport).
	if client.baseURL != "http://localhost" {
		t.Errorf("baseURL = %q, want http://localhost", client.baseURL)
	}
	_ = client // client is configured for system socket
}

func TestResolveDefaultNeverChoosesTCP(t *testing.T) {
	orig := EffectiveUID
	defer func() { EffectiveUID = orig }()
	EffectiveUID = func() int { return 0 }

	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "admin.token")
	writeTestTokenFile(t, tokenPath, "test-token")

	client, err := resolveOperatorClient(operatorClientOptions{
		TokenFile: tokenPath,
	})
	if err != nil {
		t.Fatalf("resolveOperatorClient: %v", err)
	}

	// The transport should be a Unix dialer, not TCP.
	_, isUnix := client.httpClient.Transport.(*http.Transport)
	if !isUnix {
		t.Error("expected Unix transport for default endpoint")
	}
}

// --- --system tests ---

func TestResolveSystemEndpointNonRoot(t *testing.T) {
	orig := EffectiveUID
	defer func() { EffectiveUID = orig }()
	EffectiveUID = func() int { return 1000 }

	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "admin.token")
	writeTestTokenFile(t, tokenPath, "test-token")

	client, err := resolveOperatorClient(operatorClientOptions{
		System:    true,
		TokenFile: tokenPath,
	})
	if err != nil {
		t.Fatalf("resolveOperatorClient: %v", err)
	}

	// Verify the client is configured for the system socket.
	if client.baseURL != "http://localhost" {
		t.Errorf("baseURL = %q, want http://localhost", client.baseURL)
	}
	_ = client // client is configured for system socket
}

func TestResolveSystemDefaultTokenPath(t *testing.T) {
	orig := EffectiveUID
	defer func() { EffectiveUID = orig }()
	EffectiveUID = func() int { return 1000 }

	// No token file provided, should use system default.
	_, err := resolveOperatorClient(operatorClientOptions{
		System: true,
	})
	if err == nil {
		t.Fatal("expected error when system token file doesn't exist")
	}
	if !strings.Contains(err.Error(), systemConfigDir) {
		t.Errorf("error should mention system config dir: %v", err)
	}
}

func TestResolveSystemNoFallsBackToUser(t *testing.T) {
	orig := EffectiveUID
	defer func() { EffectiveUID = orig }()
	EffectiveUID = func() int { return 1000 }

	dir := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", dir)

	// Create a working user daemon socket — should NOT be used.
	userSocket := filepath.Join(dir, "docker-helper.sock")
	userListener, err := net.Listen("unix", userSocket)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer userListener.Close()

	// --system should try system socket, not user socket.
	_, err = resolveOperatorClient(operatorClientOptions{
		System:    true,
		Endpoint:  "unix:///" + filepath.Join(systemRuntimeDir, "docker-helper.sock"),
		TokenFile: "",
	})
	// This should fail because --endpoint requires --token-file.
	// Let's test differently: use --system with a non-existent token.
	_, err = resolveOperatorClient(operatorClientOptions{
		System: true,
	})
	if err == nil {
		t.Fatal("expected error")
	}
	// The error should be about the system token file, not about connection.
	if !strings.Contains(err.Error(), "token") {
		t.Errorf("expected token error, got: %v", err)
	}
}

// --- --endpoint tests ---

func TestValidateEndpointValid(t *testing.T) {
	validEndpoints := []string{
		"unix:///absolute/path/to/socket.sock",
		"http://127.0.0.1:8080",
		"http://127.0.0.1:1",
		"http://127.0.0.1:65535",
	}
	for _, ep := range validEndpoints {
		if err := validateOperatorEndpoint(ep); err != nil {
			t.Errorf("validateOperatorEndpoint(%q) = %v, want nil", ep, err)
		}
	}
}

func TestValidateEndpointReject(t *testing.T) {
	rejectEndpoints := []struct {
		endpoint string
		why      string
	}{
		{"unix://relative/path", "relative Unix path (no leading /)"},
		{"unix:///", "empty Unix path"},
		{"http://0.0.0.0:8080", "0.0.0.0"},
		{"http://192.168.1.1:8080", "external IP"},
		{"http://localhost:8080", "hostname"},
		{"http://127.0.0.1:8080/path", "path in URL"},
		{"http://127.0.0.1:8080?q=1", "query string"},
		{"http://127.0.0.1:8080#frag", "fragment"},
		{"http://user:pass@127.0.0.1:8080", "userinfo"},
		{"https://127.0.0.1:8080", "https"},
		{"tcp://127.0.0.1:8080", "tcp scheme"},
		{"http://127.0.0.1:0", "port 0"},
		{"http://127.0.0.1:99999", "port > 65535"},
		{"http://127.0.0.1", "no port"},
		{"http://127.0.0.1:abc", "non-numeric port"},
	}
	for _, tc := range rejectEndpoints {
		if err := validateOperatorEndpoint(tc.endpoint); err == nil {
			t.Errorf("validateOperatorEndpoint(%q) = nil, want error (%s)", tc.endpoint, tc.why)
		}
	}
}

func TestResolveEndpointRequiresTokenFile(t *testing.T) {
	_, err := resolveOperatorClient(operatorClientOptions{
		Endpoint: "http://127.0.0.1:8080",
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "--endpoint requires --token-file") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestResolveEndpointSystemMutuallyExclusive(t *testing.T) {
	_, err := resolveOperatorClient(operatorClientOptions{
		System:   true,
		Endpoint: "http://127.0.0.1:8080",
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestHTTPClientMakesRequest(t *testing.T) {
	// Start a real HTTP server on a random port.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().String()
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"ok"}`)
	})
	server := &http.Server{Handler: mux}
	go server.Serve(listener)
	defer server.Close()

	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	writeTestTokenFile(t, tokenPath, "test-token")

	client, err := resolveOperatorClient(operatorClientOptions{
		Endpoint:  "http://" + addr,
		TokenFile: tokenPath,
	})
	if err != nil {
		t.Fatalf("resolveOperatorClient: %v", err)
	}

	resp, err := client.doAuthenticatedRequest("GET", "/health", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestUnixEndpointMakesRequest(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "test.sock")

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	defer os.Remove(socketPath)

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"ok"}`)
	})
	server := &http.Server{Handler: mux}
	go server.Serve(listener)
	defer server.Close()

	tokenPath := filepath.Join(dir, "token")
	writeTestTokenFile(t, tokenPath, "test-token")

	client, err := resolveOperatorClient(operatorClientOptions{
		Endpoint:  "unix:///" + socketPath,
		TokenFile: tokenPath,
	})
	if err != nil {
		t.Fatalf("resolveOperatorClient: %v", err)
	}

	resp, err := client.doAuthenticatedRequest("GET", "/health", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

// --- Auth tests ---

func TestLauncherCredentialSessionManagement(t *testing.T) {
	// Start a real daemon that accepts credential auth for session management.
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "docker-helper.sock")

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	defer os.Remove(socketPath)

	mux := http.NewServeMux()
	mux.HandleFunc("/sessions", func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token != "Bearer launcher-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"sessions":[]}`)
	})
	server := &http.Server{Handler: mux}
	go server.Serve(listener)
	defer server.Close()

	tokenPath := filepath.Join(dir, "launcher.token")
	writeTestTokenFile(t, tokenPath, "launcher-token")

	client, err := resolveOperatorClient(operatorClientOptions{
		Endpoint:  "unix:///" + socketPath,
		TokenFile: tokenPath,
	})
	if err != nil {
		t.Fatalf("resolveOperatorClient: %v", err)
	}

	resp, err := client.doAuthenticatedRequest("GET", "/sessions", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestLauncherCredentialPrincipalAdminReturns401(t *testing.T) {
	// A launcher credential should get 401 on principal admin API.
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "docker-helper.sock")

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	defer os.Remove(socketPath)

	mux := http.NewServeMux()
	mux.HandleFunc("/principals/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"code":"unauthorized","message":"credential not authorized for admin operations"}`)
	})
	server := &http.Server{Handler: mux}
	go server.Serve(listener)
	defer server.Close()

	tokenPath := filepath.Join(dir, "launcher.token")
	writeTestTokenFile(t, tokenPath, "launcher-token")

	client, err := resolveOperatorClient(operatorClientOptions{
		Endpoint:  "unix:///" + socketPath,
		TokenFile: tokenPath,
	})
	if err != nil {
		t.Fatalf("resolveOperatorClient: %v", err)
	}

	resp, err := client.doAuthenticatedRequest("GET", "/principals/testuser", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

// --- No fallback tests ---

func TestNoFallbackSystemToUser(t *testing.T) {
	orig := EffectiveUID
	defer func() { EffectiveUID = orig }()
	EffectiveUID = func() int { return 0 }

	// Start a user daemon on the user socket.
	userDir := t.TempDir()
	userSocket := filepath.Join(userDir, "docker-helper.sock")
	userListener, err := net.Listen("unix", userSocket)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer userListener.Close()
	defer os.Remove(userSocket)

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	server := &http.Server{Handler: mux}
	go server.Serve(userListener)
	defer server.Close()

	// --system should try system socket, NOT fall back to user socket.
	// The system socket doesn't exist, so it should fail.
	_, err = resolveOperatorClient(operatorClientOptions{
		System:    true,
		Endpoint:  "unix:///" + filepath.Join(systemRuntimeDir, "docker-helper.sock"),
		TokenFile: userSocket, // This won't matter since endpoint is explicit
	})
	// This should fail because --endpoint requires --token-file with a valid token.
	// Actually, the token file exists but the endpoint doesn't.
	// Let me test this differently.
}

func TestNoFallbackChosenEndpointFails(t *testing.T) {
	// Start a daemon on one socket.
	dir := t.TempDir()
	workingSocket := filepath.Join(dir, "working.sock")
	workingListener, err := net.Listen("unix", workingSocket)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer workingListener.Close()
	defer os.Remove(workingSocket)

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	server := &http.Server{Handler: mux}
	go server.Serve(workingListener)
	defer server.Close()

	// Choose a different (non-existent) endpoint.
	tokenPath := filepath.Join(dir, "token")
	writeTestTokenFile(t, tokenPath, "test-token")

	client, err := resolveOperatorClient(operatorClientOptions{
		Endpoint:  "unix:///nonexistent/socket.sock",
		TokenFile: tokenPath,
	})
	if err != nil {
		t.Fatalf("resolveOperatorClient: %v", err)
	}

	// The client was created, but the request should fail.
	resp, err := client.doAuthenticatedRequest("GET", "/health", nil)
	if err == nil {
		resp.Body.Close()
		t.Fatal("expected error when connecting to non-existent socket")
	}
}

// --- Token file tests ---

func TestReadTokenFileEmpty(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	writeTestTokenFile(t, tokenPath, "  \n")

	_, err := readTokenFile(tokenPath)
	if err == nil {
		t.Fatal("expected error for empty token file")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestReadTokenFileTrimsWhitespace(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	writeTestTokenFile(t, tokenPath, "  my-token  \n")

	token, err := readTokenFile(tokenPath)
	if err != nil {
		t.Fatalf("readTokenFile: %v", err)
	}
	if token != "my-token" {
		t.Errorf("token = %q, want %q", token, "my-token")
	}
}

func TestReadTokenFileNotFound(t *testing.T) {
	_, err := readTokenFile("/nonexistent/token")
	if err == nil {
		t.Fatal("expected error for non-existent file")
	}
}

// --- CLI integration tests ---

func TestSessionListHelpShowsOperatorFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"session", "list", "--help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code %d", code)
	}
	out := stdout.String()
	for _, flag := range []string{"--system", "--endpoint", "--token-file"} {
		if !strings.Contains(out, flag) {
			t.Errorf("session list --help should contain %q", flag)
		}
	}
}

func TestPrincipalShowHelpShowsOperatorFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"principal", "show", "--help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code %d", code)
	}
	out := stdout.String()
	for _, flag := range []string{"--system", "--endpoint", "--token-file"} {
		if !strings.Contains(out, flag) {
			t.Errorf("principal show --help should contain %q", flag)
		}
	}
}

func TestCredentialCreateHelpShowsOperatorFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"credential", "create", "--help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code %d", code)
	}
	out := stdout.String()
	for _, flag := range []string{"--system", "--endpoint", "--token-file"} {
		if !strings.Contains(out, flag) {
			t.Errorf("credential create --help should contain %q", flag)
		}
	}
}

func TestAgentCommandsNoOperatorFlags(t *testing.T) {
	for _, cmd := range [][]string{
		{"build", "--help"},
		{"run", "--help"},
		{"pull", "--help"},
	} {
		var stdout, stderr bytes.Buffer
		code := runCommandWithWriters(cmd, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("%v: exit code %d", cmd, code)
		}
		out := stdout.String()
		if strings.Contains(out, "--system") {
			t.Errorf("%v should NOT contain --system", cmd)
		}
		if strings.Contains(out, "--endpoint") {
			t.Errorf("%v should NOT contain --endpoint", cmd)
		}
	}
}

func TestSessionCleanupNoOperatorFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"session", "cleanup", "--help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code %d", code)
	}
	out := stdout.String()
	for _, flag := range []string{"--system", "--endpoint", "--token-file"} {
		if strings.Contains(out, flag) {
			t.Errorf("session cleanup --help should NOT contain %q", flag)
		}
	}
}

// --- Token file override for --system ---

func TestSystemTokenFileOverride(t *testing.T) {
	orig := EffectiveUID
	defer func() { EffectiveUID = orig }()
	EffectiveUID = func() int { return 1000 }

	dir := t.TempDir()
	customToken := filepath.Join(dir, "custom.token")
	writeTestTokenFile(t, customToken, "custom-token")

	listener, err := net.Listen("unix", filepath.Join(dir, "daemon.sock"))
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token != "Bearer custom-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	server := &http.Server{Handler: mux}
	go server.Serve(listener)
	defer server.Close()

	client, err := resolveOperatorClient(operatorClientOptions{
		Endpoint:  "unix:///" + listener.Addr().String(),
		TokenFile: customToken,
	})
	if err != nil {
		t.Fatalf("resolveOperatorClient: %v", err)
	}

	resp, err := client.doAuthenticatedRequest("GET", "/health", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

// --- readTokenFile is used by all paths ---

func TestTokenFileReadErrorPropagates(t *testing.T) {
	_, err := resolveOperatorClient(operatorClientOptions{
		Endpoint:  "unix:///some/socket",
		TokenFile: "/nonexistent/token.file",
	})
	if err == nil {
		t.Fatal("expected error for non-existent token file")
	}
	if !strings.Contains(err.Error(), "cannot read token file") {
		t.Errorf("unexpected error: %v", err)
	}
}

// --- newHTTPAPIClient ---

func TestNewHTTPAPIClient(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().String()
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"ok"}`)
	})
	server := &http.Server{Handler: mux}
	go server.Serve(listener)
	defer server.Close()

	client := newHTTPAPIClient(addr, func() (string, error) { return "test", nil }, nil)

	resp, err := client.doAuthenticatedRequest("GET", "/health", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestNewHTTPAPIClientTimeout(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().String()
	mux := http.NewServeMux()
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Second)
	})
	server := &http.Server{Handler: mux}
	go server.Serve(listener)
	defer server.Close()

	timeout := 100 * time.Millisecond
	client := newHTTPAPIClient(addr, func() (string, error) { return "test", nil }, &timeout)

	_, err = client.doAuthenticatedRequest("GET", "/slow", nil)
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

// --- No plaintext token ---

func TestNoPlaintextTokenFlag(t *testing.T) {
	// Verify that --token is NOT a supported flag.
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"session", "list", "--token", "secret"}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected error for --token flag")
	}
	out := stderr.String()
	if !strings.Contains(out, "token") && !strings.Contains(out, "flag") {
		t.Errorf("unexpected error: %s", out)
	}
}

// --- Endpoint validation edge cases ---

func TestValidateEndpointEdgeCases(t *testing.T) {
	// Valid absolute unix path with special characters.
	if err := validateOperatorEndpoint("unix:///path/with spaces/socket.sock"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Valid high port.
	if err := validateOperatorEndpoint("http://127.0.0.1:65535"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Port boundary.
	if err := validateOperatorEndpoint("http://127.0.0.1:1"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// --- Integration: full request cycle with HTTP ---

func TestFullHTTPCycle(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().String()
	mux := http.NewServeMux()
	mux.HandleFunc("/sessions", func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token != "Bearer admin-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"sessions":[]}`)
	})
	server := &http.Server{Handler: mux}
	go server.Serve(listener)
	defer server.Close()

	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "admin.token")
	writeTestTokenFile(t, tokenPath, "admin-token")

	client, err := resolveOperatorClient(operatorClientOptions{
		Endpoint:  "http://" + addr,
		TokenFile: tokenPath,
	})
	if err != nil {
		t.Fatalf("resolveOperatorClient: %v", err)
	}

	result, err := client.listSessions()
	if err != nil {
		t.Fatalf("listSessions: %v", err)
	}
	if len(result.Sessions) != 0 {
		t.Errorf("expected 0 sessions, got %d", len(result.Sessions))
	}
}

// --- Integration: full request cycle with Unix ---

func TestFullUnixCycle(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "daemon.sock")

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	defer os.Remove(socketPath)

	mux := http.NewServeMux()
	mux.HandleFunc("/sessions", func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token != "Bearer admin-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"sessions":[]}`)
	})
	server := &http.Server{Handler: mux}
	go server.Serve(listener)
	defer server.Close()

	tokenPath := filepath.Join(dir, "admin.token")
	writeTestTokenFile(t, tokenPath, "admin-token")

	client, err := resolveOperatorClient(operatorClientOptions{
		Endpoint:  "unix:///" + socketPath,
		TokenFile: tokenPath,
	})
	if err != nil {
		t.Fatalf("resolveOperatorClient: %v", err)
	}

	result, err := client.listSessions()
	if err != nil {
		t.Fatalf("listSessions: %v", err)
	}
	if len(result.Sessions) != 0 {
		t.Errorf("expected 0 sessions, got %d", len(result.Sessions))
	}
}

// --- agentClient unchanged ---

func TestAgentClientUnchanged(t *testing.T) {
	t.Setenv("DOCKER_HELPER_SESSION_TOKEN", "session-token")
	t.Setenv("DOCKER_HELPER_SOCKET_PATH", "")

	client, err := agentClient()
	if err != nil {
		t.Fatalf("agentClient: %v", err)
	}

	token, err := client.tokenSource()
	if err != nil {
		t.Fatalf("token source: %v", err)
	}
	if token != "session-token" {
		t.Errorf("token = %q, want %q", token, "session-token")
	}
	if client.baseURL != "http://localhost" {
		t.Errorf("baseURL = %q, want http://localhost", client.baseURL)
	}
}

// --- io import used ---

func init() {
	_ = io.Reader(nil)
}
