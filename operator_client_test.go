package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// --- Default endpoint tests ---

func TestResolveDefaultEndpointNonRoot(t *testing.T) {
	orig := EffectiveUID
	defer func() { EffectiveUID = orig }()
	EffectiveUID = func() int { return 1000 }

	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "xdg_config"))

	tokenPath := filepath.Join(dir, "credential.token")
	writeTestTokenFile(t, tokenPath, "test-token")

	// The non-root default endpoint is the system socket. Stub the canonical
	// system socket path to a real listening fake and prove the default
	// endpoint actually connects with the explicit token file.
	socketPath := filepath.Join(dir, "system-socket", "docker-helper.sock")
	if err := os.MkdirAll(filepath.Dir(socketPath), 0755); err != nil {
		t.Fatal(err)
	}
	origSocketPath := systemSocketPath
	systemSocketPath = socketPath
	t.Cleanup(func() { systemSocketPath = origSocketPath })

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

func TestResolveDefaultEndpointFallsBackToSystem(t *testing.T) {
	orig := EffectiveUID
	defer func() { EffectiveUID = orig }()
	EffectiveUID = func() int { return 1000 }

	dir := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", dir)

	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "xdg_config"))
	tokenPath := filepath.Join(dir, "xdg_config", "docker-helper", "credential.token")
	tokenDir := filepath.Dir(tokenPath)
	os.MkdirAll(tokenDir, 0755)
	writeTestTokenFile(t, tokenPath, "test-token")

	// The default endpoint resolves to the system socket with the installed
	// credential token.
	client, err := resolveOperatorClient(operatorClientOptions{})
	if err != nil {
		t.Fatalf("resolveOperatorClient: %v", err)
	}

	// The baseURL should be http://localhost (Unix transport).
	if client.baseURL != "http://localhost" {
		t.Errorf("baseURL = %q, want http://localhost", client.baseURL)
	}
	_ = client
}

func TestResolveSystemEndpointNonRoot(t *testing.T) {
	orig := EffectiveUID
	defer func() { EffectiveUID = orig }()
	EffectiveUID = func() int { return 1000 }

	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "admin.token")
	writeTestTokenFile(t, tokenPath, "test-token")

	client, err := resolveOperatorClient(operatorClientOptions{
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

	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "xdg_config"))

	// Non-root: no token file provided, should use credential path.
	_, err := resolveOperatorClient(operatorClientOptions{})
	if err == nil {
		t.Fatal("expected error when credential file doesn't exist")
	}
	// The error should mention the credential path, not systemConfigDir.
	if strings.Contains(err.Error(), systemConfigDir+"/admin.token") {
		t.Error("non-root should not use system admin.token path")
	}
}

// TestResolveOperatorTokenPathOwnerSelection pins the owner-credential
// selection to the exact canonical paths: root resolves the system admin
// token, non-root resolves the installed user credential. Both come from the
// existing owner's seams, so the selection does not depend on runner
// HOME/XDG/NSS specifics.
func TestResolveOperatorTokenPathOwnerSelection(t *testing.T) {
	origUID := EffectiveUID
	origCred := credentialPathFunc
	defer func() {
		EffectiveUID = origUID
		credentialPathFunc = origCred
	}()

	credPath := filepath.Join(t.TempDir(), "docker-helper", "credential.token")
	credentialPathFunc = func() (string, error) { return credPath, nil }

	tests := []struct {
		name string
		uid  int
		want string
	}{
		{"root resolves the system admin token", 0, filepath.Join(systemConfigDir, "admin.token")},
		{"non-root resolves the installed credential", 1000, credPath},
	}
	for _, tc := range tests {
		EffectiveUID = func() int { return tc.uid }
		path, err := resolveOperatorTokenPath()
		if err != nil {
			t.Fatalf("%s: resolveOperatorTokenPath: %v", tc.name, err)
		}
		if path != tc.want {
			t.Errorf("%s: resolved %q, want %q", tc.name, path, tc.want)
		}
	}
}

// TestResolveOperatorTokenPathNonRootFailureFailsClosed is the regression for
// the removed admin-token fallback: a non-root credential-path resolution
// failure is returned to the caller by both resolution stages (default system
// endpoint and explicit unix endpoint) and never selects an admin token path.
// The would-be fallback location (user config dir / admin.token) is populated
// with a valid readable token, so the pre-fix fallback behavior (resolving
// that path and constructing the client from it) would fail this test.
func TestResolveOperatorTokenPathNonRootFailureFailsClosed(t *testing.T) {
	origUID := EffectiveUID
	origCred := credentialPathFunc
	origConfigPath := getConfigPathFunc
	defer func() {
		EffectiveUID = origUID
		credentialPathFunc = origCred
		getConfigPathFunc = origConfigPath
	}()

	EffectiveUID = func() int { return 1000 }
	credErr := errors.New("cannot determine home directory: $HOME is not defined")
	credentialPathFunc = func() (string, error) { return "", credErr }

	// A readable admin token at the would-be fallback location makes the
	// undesired fallback possible and observable.
	configDir := t.TempDir()
	getConfigPathFunc = func() string { return filepath.Join(configDir, "config.json") }
	writeTestTokenFile(t, filepath.Join(configDir, "admin.token"), "admin-token-fallback-marker")

	for _, tc := range []struct {
		name string
		opts operatorClientOptions
	}{
		{"default system endpoint", operatorClientOptions{}},
		{"explicit unix endpoint", operatorClientOptions{Endpoint: "unix:///run/docker-helper/docker-helper.sock"}},
	} {
		client, err := resolveOperatorClient(tc.opts)
		if client != nil {
			t.Errorf("%s: client constructed on credential-path failure", tc.name)
		}
		if err == nil {
			t.Fatalf("%s: expected credential-path failure, got nil (fallback would use %s)",
				tc.name, filepath.Join(configDir, "admin.token"))
		}
		if !errors.Is(err, credErr) {
			t.Errorf("%s: error = %v, want the credential-path resolution error (an admin token path was selected)",
				tc.name, err)
		}
	}
}

// --- --endpoint tests ---

func TestValidateEndpointValid(t *testing.T) {
	validEndpoints := []string{
		"unix:///absolute/path/to/socket.sock",
		"unix:///path/with spaces/socket.sock",
		"/absolute/path/to/socket.sock",
		"/path/with spaces/socket.sock",
		"/var/run/docker-helper/docker-helper.sock",
		"http://127.0.0.1:8080",
		"http://127.0.0.1:1",
		"http://127.0.0.1:65535",
	}
	for _, ep := range validEndpoints {
		if err := validateEndpoint(ep); err != nil {
			t.Errorf("validateEndpoint(%q) = %v, want nil", ep, err)
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
		{"/", "empty plain path"},
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
		{"relative/path", "relative path without scheme"},
		{"", "empty string"},
	}
	for _, tc := range rejectEndpoints {
		if err := validateEndpoint(tc.endpoint); err == nil {
			t.Errorf("validateEndpoint(%q) = nil, want error (%s)", tc.endpoint, tc.why)
		}
	}
}

func TestValidateEndpointUnixRelativeErrorMessage(t *testing.T) {
	err := validateEndpoint("unix://relative/path")
	if err == nil {
		t.Fatal("expected error for relative unix path")
	}
	msg := err.Error()
	// The error message should contain the actual relative path, not a mangled one.
	if !strings.Contains(msg, "relative/path") {
		t.Errorf("error message should contain 'relative/path', got: %s", msg)
	}
	// Regression: previously strings.TrimPrefix(path, "/") would produce "arrelative/path".
	if strings.Contains(msg, "arrelative") {
		t.Errorf("error message should not mangle the path, got: %s", msg)
	}
}

func TestResolveEndpointRequiresTokenFile(t *testing.T) {
	// HTTP endpoints still require --token-file.
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

func TestResolveEndpointPlainPathUnixSocket(t *testing.T) {
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
		w.WriteHeader(http.StatusOK)
	})
	server := &http.Server{Handler: mux}
	go server.Serve(listener)
	defer server.Close()

	// Plain absolute path should work as unix socket.
	tokenPath := filepath.Join(dir, "token")
	writeTestTokenFile(t, tokenPath, "test-token")

	client, err := resolveOperatorClient(operatorClientOptions{
		Endpoint:  socketPath,
		TokenFile: tokenPath,
	})
	if err != nil {
		t.Fatalf("resolveOperatorClient with plain path = %v", err)
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

func TestResolveEndpointPlainPathNoTokenFile(t *testing.T) {
	orig := EffectiveUID
	defer func() { EffectiveUID = orig }()
	EffectiveUID = func() int { return 1000 }

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
		w.WriteHeader(http.StatusOK)
	})
	server := &http.Server{Handler: mux}
	go server.Serve(listener)
	defer server.Close()

	// Auto-resolved token for unix endpoint (non-root uses credential.token).
	// resolveOperatorTokenPath for non-root returns credentialPath() which is
	// $XDG_CONFIG_HOME/docker-helper/credential.token.
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "xdg_config"))
	tokenPath := filepath.Join(dir, "xdg_config", "docker-helper", "credential.token")
	tokenDir := filepath.Dir(tokenPath)
	os.MkdirAll(tokenDir, 0755)
	writeTestTokenFile(t, tokenPath, "test-token")

	// No TokenFile — should auto-resolve via resolveOperatorTokenPath.
	client, err := resolveOperatorClient(operatorClientOptions{
		Endpoint: socketPath,
	})
	if err != nil {
		t.Fatalf("resolveOperatorClient with plain path, no token = %v", err)
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

func TestUnixEndpointAutoToken(t *testing.T) {
	orig := EffectiveUID
	defer func() { EffectiveUID = orig }()
	EffectiveUID = func() int { return 1000 }

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
		w.WriteHeader(http.StatusOK)
	})
	server := &http.Server{Handler: mux}
	go server.Serve(listener)
	defer server.Close()

	// Auto-resolved token for unix:// scheme (non-root uses credential.token).
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "xdg_config"))
	tokenPath := filepath.Join(dir, "xdg_config", "docker-helper", "credential.token")
	tokenDir := filepath.Dir(tokenPath)
	os.MkdirAll(tokenDir, 0755)
	writeTestTokenFile(t, tokenPath, "test-token")

	// No TokenFile — should auto-resolve via resolveOperatorTokenPath.
	client, err := resolveOperatorClient(operatorClientOptions{
		Endpoint: "unix:///" + socketPath,
	})
	if err != nil {
		t.Fatalf("resolveOperatorClient with unix://, no token = %v", err)
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

// --- Agent commands have discoverable endpoint flags but no Principal --token-file ---

func TestAgentCommandsEndpointFlagsNoTokenFile(t *testing.T) {
	for _, cmd := range [][]string{
		{"build", "--help"},
		{"run", "--help"},
		{"pull", "--help"},
		{"registry", "login", "--help"},
	} {
		var stdout, stderr bytes.Buffer
		code := runCommandWithWriters(cmd, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("%v: exit code %d", cmd, code)
		}
		out := stdout.String()
		for _, flag := range []string{"--endpoint"} {
			if !strings.Contains(out, flag) {
				t.Errorf("%v --help should contain %q", cmd, flag)
			}
		}
		// Agent commands authenticate with the Session token from the
		// environment; they must NOT expose Principal --token-file semantics.
		if strings.Contains(out, "--token-file") {
			t.Errorf("%v --help should NOT contain --token-file", cmd)
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
	for _, flag := range []string{"--endpoint", "--token-file"} {
		if strings.Contains(out, flag) {
			t.Errorf("session cleanup --help should NOT contain %q", flag)
		}
	}
}

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

// TestTokenFileEmbeddedWhitespaceRejected verifies that a token file whose
// content is not a single bearer token line (embedded whitespace) is rejected
// locally with a clear diagnostic, instead of being sent to the server and
// surfacing as a generic authentication failure. This is a format-only check;
// authenticity remains server-owned.
func TestTokenFileEmbeddedWhitespaceRejected(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"two-lines":      "dht_abc\ndef\n",
		"internal-tabs":  "dht_abc\tdef\n",
		"internal-space": "dht_abc def\n",
	} {
		path := filepath.Join(dir, name+".token")
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatalf("write token file: %v", err)
		}
		_, err := resolveOperatorClient(operatorClientOptions{
			Endpoint:  "unix:///some/socket",
			TokenFile: path,
		})
		if err == nil {
			t.Fatalf("%s: expected local format error, got nil", name)
		}
		if !strings.Contains(err.Error(), "contains whitespace") {
			t.Errorf("%s: expected whitespace diagnostic, got: %v", name, err)
		}
	}
}

// TestTokenFileTrailingNewlineAccepted verifies that the ordinary trailing
// newline in a token file is trimmed and the token accepted.
func TestTokenFileTrailingNewlineAccepted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "admin.token")
	if err := os.WriteFile(path, []byte("dht_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n"), 0600); err != nil {
		t.Fatalf("write token file: %v", err)
	}
	token, err := readTokenFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "dht_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" {
		t.Errorf("unexpected token: %q", token)
	}
}

// TestAgentSessionTokenWhitespaceRejected verifies the agent CLI rejects a
// DOCKER_HELPER_SESSION_TOKEN containing whitespace with a clear local
// diagnostic.
func TestAgentSessionTokenWhitespaceRejected(t *testing.T) {
	t.Setenv("DOCKER_HELPER_SESSION_TOKEN", "dht_abc def")
	t.Setenv("DOCKER_HELPER_SOCKET_PATH", "/nonexistent/socket")
	_, err := resolveAgentClient(agentClientOptions{})
	if err == nil {
		t.Fatal("expected error for whitespace token")
	}
	if !strings.Contains(err.Error(), "contains whitespace") {
		t.Errorf("expected whitespace diagnostic, got: %v", err)
	}
}

// --- newHTTPAPIClient ---

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

// --- Integration: agentClient unchanged ---

// TestResolveDefaultEndpointSystemFallbackWithoutRuntimeDir proves the
// documented operator default survives a non-root environment without
// XDG_RUNTIME_DIR: the user runtime directory is unresolvable, so the
// default operator client resolves the system socket and authenticates with
// the installed credential instead of failing before the documented
// system-socket fallback. The system socket is proven available by a real
// listener swapped into systemSocketPath (stat-based availability), and the
// request is driven through the resolved client's transport to prove the
// actual dial target and bearer, not just the resolution outcome.
func TestResolveDefaultEndpointSystemFallbackWithoutRuntimeDir(t *testing.T) {
	origUID := EffectiveUID
	EffectiveUID = func() int { return 1000 }
	t.Cleanup(func() { EffectiveUID = origUID })

	// getRuntimeDir treats an empty value exactly like an unset variable
	// (the "dir == \"\"" branch), which is the environment under test.
	t.Setenv("XDG_RUNTIME_DIR", "")

	// The installed credential is the only operator token source: creating
	// credential.token without admin.token in the same config directory
	// makes a resolution to the user-config admin.token path fail loudly.
	xdgConfigHome := t.TempDir()
	credDir := filepath.Join(xdgConfigHome, "docker-helper")
	if err := os.MkdirAll(credDir, 0700); err != nil {
		t.Fatal(err)
	}
	writeTestTokenFile(t, filepath.Join(credDir, "credential.token"), "test-token")
	t.Setenv("XDG_CONFIG_HOME", xdgConfigHome)

	// A live system socket (real availability, no existence-seam mock).
	socketPath := filepath.Join(t.TempDir(), "system.sock")
	var bearer atomic.Value
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		bearer.Store(r.Header.Get("Authorization"))
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server := &http.Server{Handler: mux}
	go server.Serve(listener)
	defer server.Close()
	waitForDialReady(t, "unix", socketPath)

	origSystemSocket := systemSocketPath
	systemSocketPath = socketPath
	t.Cleanup(func() { systemSocketPath = origSystemSocket })

	client, err := resolveOperatorClient(operatorClientOptions{})
	if err != nil {
		t.Fatalf("resolveOperatorClient without XDG_RUNTIME_DIR must fall back to the system socket: %v", err)
	}
	resp, err := client.doAuthenticatedRequest("GET", "/health", nil)
	if err != nil {
		t.Fatalf("request through the system-socket default: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 (authenticated with the installed credential)", resp.StatusCode)
	}
	requireBearerSource(t, "default operator client without XDG_RUNTIME_DIR", bearer.Load().(string), "Bearer test-token")
}

// TestOperatorCommandDefaultSystemEndpointWithoutRuntimeDir proves the
// documented default at the command level: a non-root operator command
// without --endpoint/XDG_RUNTIME_DIR resolves the system socket and
// authenticates normally with the installed credential.
func TestOperatorCommandDefaultSystemEndpointWithoutRuntimeDir(t *testing.T) {
	origUID := EffectiveUID
	EffectiveUID = func() int { return 1000 }
	t.Cleanup(func() { EffectiveUID = origUID })

	// getRuntimeDir treats an empty value exactly like an unset variable.
	t.Setenv("XDG_RUNTIME_DIR", "")

	xdgConfigHome := t.TempDir()
	credDir := filepath.Join(xdgConfigHome, "docker-helper")
	if err := os.MkdirAll(credDir, 0700); err != nil {
		t.Fatal(err)
	}
	writeTestTokenFile(t, filepath.Join(credDir, "credential.token"), "dhc_installed-fixture-token")
	t.Setenv("XDG_CONFIG_HOME", xdgConfigHome)

	socketPath := filepath.Join(t.TempDir(), "system.sock")
	var bearer atomic.Value
	requests := 0
	mux := http.NewServeMux()
	mux.HandleFunc("GET /sessions", func(w http.ResponseWriter, r *http.Request) {
		bearer.Store(r.Header.Get("Authorization"))
		requests++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"sessions":[]}`))
	})
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server := &http.Server{Handler: mux}
	go server.Serve(listener)
	defer server.Close()
	waitForDialReady(t, "unix", socketPath)

	origSystemSocket := systemSocketPath
	systemSocketPath = socketPath
	t.Cleanup(func() { systemSocketPath = origSystemSocket })

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"session", "list"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, want 0, stderr: %s", code, stderr.String())
	}
	if requests != 1 {
		t.Fatalf("requests = %d, want exactly one GET /sessions", requests)
	}
	requireBearerSource(t, "session list default without XDG_RUNTIME_DIR", bearer.Load().(string), "Bearer dhc_installed-fixture-token")
}

// TestOperatorEndpointGrammarExitsTwo pins the operator endpoint-grammar
// contract at the representative operator command: locally knowable invalid
// forms are usage errors (exit 2) validated during Invocation.Validate, an
// explicit Unix endpoint without --token-file stays syntactically valid, and
// a runtime failure after valid syntax remains exit 1.
func TestOperatorEndpointGrammarExitsTwo(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		wantRC  int
		wantErr string
	}{
		{name: "unknown --system flag", args: []string{"--system"}, wantRC: 2, wantErr: "flag provided but not defined"},
		{name: "malformed endpoint", args: []string{"--endpoint", "bogus"}, wantRC: 2, wantErr: "unsupported endpoint scheme"},
		{name: "http endpoint without token file", args: []string{"--endpoint", "http://127.0.0.1:1"}, wantRC: 2, wantErr: "--endpoint requires --token-file for http endpoints"},
		{name: "explicitly empty endpoint", args: []string{"--endpoint", ""}, wantRC: 2, wantErr: "--endpoint value must not be empty"},
		{name: "explicitly empty endpoint equals form", args: []string{"--endpoint="}, wantRC: 2, wantErr: "--endpoint value must not be empty"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := runCommandWithWriters(append([]string{"session", "list"}, tc.args...), &stdout, &stderr)
			if code != tc.wantRC {
				t.Fatalf("exit = %d, want %d, stderr: %s", code, tc.wantRC, stderr.String())
			}
			if !strings.Contains(stderr.String(), tc.wantErr) {
				t.Errorf("stderr must name the grammar error %q, got: %s", tc.wantErr, stderr.String())
			}
		})
	}

	// An explicit Unix endpoint without --token-file is syntactically valid:
	// the failure is the runtime token resolution, not a usage error.
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"session", "list", "--endpoint", "/tmp/nonexistent.sock"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("unix endpoint without --token-file: exit = %d, want 1 (runtime), stderr: %s", code, stderr.String())
	}
	for _, grammarErr := range []string{"unknown flag", "requires --token-file", "unsupported endpoint scheme"} {
		if strings.Contains(stderr.String(), grammarErr) {
			t.Errorf("valid syntax must not fail with the grammar error %q, got: %s", grammarErr, stderr.String())
		}
	}
}

// TestOperatorEndpointGrammarMatrixCoversAllOperatorCommands proves no
// command that registers the operator flag trio was left on the
// late-validation path: every command carrying --endpoint/
// --token-file flags rejects the malformed endpoint with exit 2
// from Invocation.Validate (with the minimum required positionals supplied
// so the command-specific arity check cannot mask the grammar result).
func TestOperatorEndpointGrammarMatrixCoversAllOperatorCommands(t *testing.T) {
	type operatorCommand struct {
		path []string
		cmd  *Command
	}
	var commands []operatorCommand
	var walk func(path []string, c *Command)
	walk = func(path []string, c *Command) {
		if len(c.Subcommands) > 0 {
			for _, sub := range c.Subcommands {
				walk(append(append([]string{}, path...), sub.Name), sub)
			}
			return
		}
		if c.NewInvocation == nil {
			return
		}
		fs := flag.NewFlagSet("probe", flag.ContinueOnError)
		c.NewInvocation(fs)
		if fs.Lookup("endpoint") != nil && fs.Lookup("token-file") != nil {
			commands = append(commands, operatorCommand{path: path, cmd: c})
		}
	}
	for _, top := range rootCommand.Subcommands {
		walk([]string{top.Name}, top)
	}
	if len(commands) == 0 {
		t.Fatal("structural matrix found no operator commands; the probe is broken")
	}

	for _, oc := range commands {
		args := append(append([]string{}, oc.path...), "--endpoint", "bogus")
		for i := 0; i < oc.cmd.MinPosArgs; i++ {
			args = append(args, "x")
		}
		var stdout, stderr bytes.Buffer
		code := runCommandWithWriters(args, &stdout, &stderr)
		if code != 2 {
			t.Errorf("%v: exit = %d, want 2 for the endpoint grammar, stderr: %s", oc.path, code, stderr.String())
			continue
		}
		if !strings.Contains(stderr.String(), "unsupported endpoint scheme") {
			t.Errorf("%v: stderr must name the endpoint grammar error, got: %s", oc.path, stderr.String())
		}

		// The explicitly empty endpoint spelling is the same structural
		// grammar error on every operator command: no command may treat
		// an explicit empty value as omission.
		emptyArgs := append(append(append([]string{}, oc.path...), "--endpoint", ""), make([]string, 0, oc.cmd.MinPosArgs)...)
		for i := 0; i < oc.cmd.MinPosArgs; i++ {
			emptyArgs = append(emptyArgs, "x")
		}
		var emptyOut, emptyErr bytes.Buffer
		emptyCode := runCommandWithWriters(emptyArgs, &emptyOut, &emptyErr)
		if emptyCode != 2 {
			t.Errorf("%v: exit = %d, want 2 for the explicitly empty endpoint, stderr: %s", oc.path, emptyCode, emptyErr.String())
			continue
		}
		if !strings.Contains(emptyErr.String(), "--endpoint value must not be empty") {
			t.Errorf("%v: stderr must name the explicit-empty grammar error, got: %s", oc.path, emptyErr.String())
		}
	}
}

// --- Integration: agentClient unchanged ---

func TestAgentClientUnchanged(t *testing.T) {
	t.Setenv("DOCKER_HELPER_SESSION_TOKEN", "session-token")
	t.Setenv("DOCKER_HELPER_SOCKET_PATH", "")

	client, err := resolveAgentClient(agentClientOptions{})
	if err != nil {
		t.Fatalf("resolveAgentClient(default): %v", err)
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
