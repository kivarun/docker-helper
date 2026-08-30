package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	systemRuntimeDir = "/run/docker-helper"
	systemConfigDir  = "/etc/docker-helper"
)

// operatorClientOptions specifies how to connect to the daemon.
type operatorClientOptions struct {
	System    bool   // --system: force system daemon
	Endpoint  string // --endpoint: explicit endpoint URL
	TokenFile string // --token-file: explicit token file path
}

// resolveOperatorClient resolves the operator client based on the given options.
// It returns a configured apiClient ready to make authenticated requests.
func resolveOperatorClient(opts operatorClientOptions) (*apiClient, error) {
	if opts.System && opts.Endpoint != "" {
		return nil, fmt.Errorf("--system and --endpoint are mutually exclusive")
	}

	if opts.Endpoint != "" {
		return resolveExplicitEndpoint(opts)
	}

	if opts.System {
		return resolveSystemEndpoint(opts)
	}

	return resolveDefaultEndpoint(opts)
}

func resolveExplicitEndpoint(opts operatorClientOptions) (*apiClient, error) {
	if err := validateOperatorEndpoint(opts.Endpoint); err != nil {
		return nil, err
	}

	var socketPath string
	var isUnix bool

	if strings.HasPrefix(opts.Endpoint, "unix://") {
		socketPath = strings.TrimPrefix(opts.Endpoint, "unix://")
		isUnix = true
	} else if strings.HasPrefix(opts.Endpoint, "/") {
		// Plain absolute path — treat as unix socket.
		socketPath = opts.Endpoint
		isUnix = true
	} else {
		// http://127.0.0.1:port
		socketPath = strings.TrimPrefix(opts.Endpoint, "http://")
		isUnix = false
	}

	var tokenSource func() (string, error)

	if isUnix {
		// Auto-resolve token for unix sockets.
		tokenPath := opts.TokenFile
		if tokenPath == "" {
			tokenPath = resolveSystemModeTokenPath()
		}
		token, err := readTokenFile(tokenPath)
		if err != nil {
			return nil, err
		}
		tokenSource = func() (string, error) { return token, nil }
	} else {
		// HTTP always requires explicit token.
		if opts.TokenFile == "" {
			return nil, fmt.Errorf("--endpoint requires --token-file for http endpoints")
		}
		token, err := readTokenFile(opts.TokenFile)
		if err != nil {
			return nil, err
		}
		tokenSource = func() (string, error) { return token, nil }
	}

	if isUnix {
		return newUnixAPIClient(socketPath, tokenSource, nil), nil
	}
	return newHTTPAPIClient(socketPath, tokenSource, nil), nil
}

func resolveSystemEndpoint(opts operatorClientOptions) (*apiClient, error) {
	socketPath := filepath.Join(systemRuntimeDir, "docker-helper.sock")
	tokenPath := opts.TokenFile
	if tokenPath == "" {
		tokenPath = resolveSystemModeTokenPath()
	}

	token, err := readTokenFile(tokenPath)
	if err != nil {
		return nil, err
	}
	tokenSource := func() (string, error) { return token, nil }

	return newUnixAPIClient(socketPath, tokenSource, nil), nil
}

func resolveDefaultEndpoint(opts operatorClientOptions) (*apiClient, error) {
	runtimeDir, err := getRuntimeDir()
	if err != nil {
		return nil, err
	}
	userSocketPath := filepath.Join(runtimeDir, "docker-helper.sock")
	systemSocketPath := filepath.Join(systemRuntimeDir, "docker-helper.sock")

	userSocketExists := func() bool {
		_, err := os.Stat(userSocketPath)
		return err == nil
	}

	// Determine which socket to use.
	// If user socket exists, use it. Otherwise fall back to system socket.
	socketPath := userSocketPath
	if !userSocketExists() && systemSocketExists() {
		socketPath = systemSocketPath
	}

	tokenPath := opts.TokenFile
	if tokenPath == "" {
		if socketPath == systemSocketPath {
			tokenPath = resolveSystemModeTokenPath()
		} else {
			tokenPath = filepath.Join(getConfigDir(), "admin.token")
		}
	}

	token, err := readTokenFile(tokenPath)
	if err != nil {
		return nil, err
	}
	tokenSource := func() (string, error) { return token, nil }

	return newUnixAPIClient(socketPath, tokenSource, nil), nil
}

// systemSocketExists reports whether the system daemon socket is present.
// Can be replaced in tests.
var systemSocketExists = func() bool {
	_, err := os.Stat(filepath.Join(systemRuntimeDir, "docker-helper.sock"))
	return err == nil
}

// resolveSystemModeTokenPath returns the token file path for system daemon
// authentication: non-root users use credential.token, root uses admin.token.
func resolveSystemModeTokenPath() string {
	if EffectiveUID() == 0 {
		return filepath.Join(systemConfigDir, "admin.token")
	}
	// credentialPath can fail only if HOME is unreadable; fall back to
	// admin.token in the user config directory rather than returning an error.
	credPath, err := credentialPath()
	if err == nil {
		return credPath
	}
	return filepath.Join(getConfigDir(), "admin.token")
}

// validateOperatorEndpoint validates an explicit endpoint URL.
func validateOperatorEndpoint(endpoint string) error {
	if strings.HasPrefix(endpoint, "unix://") {
		path := strings.TrimPrefix(endpoint, "unix://")
		if !strings.HasPrefix(path, "/") {
			return fmt.Errorf("unix endpoint: path must be absolute: %s", path)
		}
		if len(path) == 1 {
			return fmt.Errorf("unix endpoint: path is empty")
		}
		return nil
	}

	// Plain absolute path — treat as unix socket.
	if strings.HasPrefix(endpoint, "/") {
		if len(endpoint) == 1 {
			return fmt.Errorf("unix endpoint: path is empty")
		}
		return nil
	}

	if !strings.HasPrefix(endpoint, "http://") {
		return fmt.Errorf("unsupported endpoint scheme (expected unix:///path, /path, or http://127.0.0.1:port)")
	}

	addr := strings.TrimPrefix(endpoint, "http://")

	if strings.ContainsAny(addr, "?#") {
		return fmt.Errorf("endpoint must not contain query or fragment")
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid endpoint address: %v", err)
	}

	if host != "127.0.0.1" {
		return fmt.Errorf("http endpoint: host must be 127.0.0.1 (got %s)", host)
	}

	portNum, err := strconv.Atoi(port)
	if err != nil || portNum < 1 || portNum > 65535 {
		return fmt.Errorf("http endpoint: invalid port %s", port)
	}

	return nil
}

// tokenHasEmbeddedWhitespace reports whether a token contains whitespace that
// would prevent it from being a single bearer token. This is a purely local
// transport-format check for errors knowable without server state; whether a
// well-formed token is authentic, revoked, or authorized is always decided by
// the server.
func tokenHasEmbeddedWhitespace(token string) bool {
	return strings.ContainsAny(token, " \t\r\n")
}

// readTokenFile reads a token from a file and validates it.
func readTokenFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("cannot read token file %s: %w", path, err)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", fmt.Errorf("token file %s is empty", path)
	}
	if tokenHasEmbeddedWhitespace(token) {
		return "", fmt.Errorf("token file %s contains whitespace; expected a single bearer token line", path)
	}
	return token, nil
}

// newHTTPAPIClient creates an HTTP client for loopback TCP endpoints.
func newHTTPAPIClient(address string, tokenSource func() (string, error), timeout *time.Duration) *apiClient {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "tcp", address)
		},
	}

	client := &http.Client{Transport: transport}
	if timeout != nil {
		client.Timeout = *timeout
	}

	return &apiClient{
		httpClient:  client,
		baseURL:     "http://" + address,
		tokenSource: tokenSource,
	}
}

// registerOperatorFlags adds --system, --endpoint, and --token-file flags to the
// given FlagSet and returns pointers to the flag values.
func registerOperatorFlags(fs *flag.FlagSet) (system *bool, endpoint *string, tokenFile *string) {
	system = fs.Bool("system", false, "Connect to system daemon")
	endpoint = fs.String("endpoint", "", "Explicit endpoint (/path/to/socket, unix:///path, or http://127.0.0.1:port)")
	tokenFile = fs.String("token-file", "", "Token file path (auto-resolved for unix sockets)")
	return
}
