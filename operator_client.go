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

// systemSocketPath is the canonical Unix socket path of the system daemon.
// Both operator and agent CLI endpoint selection resolve the same path; it is a
// variable so tests can bind a real listener at a controlled path.
var systemSocketPath = filepath.Join(systemRuntimeDir, "docker-helper.sock")

// operatorClientOptions specifies how to connect to the daemon.
type operatorClientOptions struct {
	Endpoint  string // --endpoint: explicit endpoint URL
	TokenFile string // --token-file: explicit token file path
	// EndpointSet records that --endpoint was explicitly supplied. It is
	// part of the CLI grammar (an explicitly empty endpoint is a usage
	// error); runtime resolvers and internal callers leave it false, so an
	// empty endpoint stays indistinguishable from omission there.
	EndpointSet bool
	// Timeout bounds the whole HTTP exchange (dial, request, response) when
	// non-zero; zero keeps the unbounded operator client. Only the
	// machine-facing completion roots queries set it: completion is an
	// interactive convenience and must never stall the shell on an
	// unavailable or unresponsive daemon.
	Timeout time.Duration
}

// clientTimeout returns the pointer form newUnixAPIClient and
// newHTTPAPIClient expect, or nil when no timeout was requested.
func (opts operatorClientOptions) clientTimeout() *time.Duration {
	if opts.Timeout <= 0 {
		return nil
	}
	timeout := opts.Timeout
	return &timeout
}

// validateEndpointSelection validates the endpoint-selection grammar shared
// by every command family: --system and --endpoint are mutually exclusive,
// and an explicit endpoint must carry the canonical syntax validateEndpoint
// owns. It is pure and locally knowable, so CLI invocations run it during
// Invocation.Validate (exit 2); family-specific requirements compose around
// it rather than re-owning the mutual-exclusion or syntax rules.
func validateEndpointSelection(endpoint string, endpointSet bool) error {
	if endpointSet && endpoint == "" {
		return fmt.Errorf("--endpoint value must not be empty")
	}
	if endpoint != "" {
		return validateEndpoint(endpoint)
	}
	return nil
}

// isUnixEndpoint reports whether an explicit endpoint selects a Unix socket
// (canonical unix:// spelling or a plain absolute path). An explicit
// endpoint that is not a Unix endpoint is an http:// endpoint.
func isUnixEndpoint(endpoint string) bool {
	return strings.HasPrefix(endpoint, "unix://") || strings.HasPrefix(endpoint, "/")
}

// validateOperatorEndpointOptions validates the operator-family endpoint
// grammar around the shared endpoint-selection owner: an explicit HTTP
// endpoint requires an explicit --token-file, while Unix endpoints may
// auto-resolve the appropriate operator credential. It is pure and locally
// knowable, so operator CLI invocations run it during Invocation.Validate
// (exit 2); resolveOperatorClient retains the same validation for direct and
// internal callers.
func validateOperatorEndpointOptions(opts operatorClientOptions) error {
	if err := validateEndpointSelection(opts.Endpoint, opts.EndpointSet); err != nil {
		return err
	}
	if opts.Endpoint != "" && !isUnixEndpoint(opts.Endpoint) && opts.TokenFile == "" {
		return fmt.Errorf("--endpoint requires --token-file for http endpoints")
	}
	return nil
}

// resolveOperatorClient resolves the operator client based on the given
// options and returns a configured apiClient ready to make authenticated
// requests. It is the single defensive entry boundary for operator endpoint
// options: every path — CLI invocations after their Invocation.Validate and
// direct/internal callers — is validated once by the canonical owner
// validateOperatorEndpointOptions before the family resolvers execute.
func resolveOperatorClient(opts operatorClientOptions) (*apiClient, error) {
	if err := validateOperatorEndpointOptions(opts); err != nil {
		return nil, err
	}

	if opts.Endpoint != "" {
		return resolveExplicitEndpoint(opts)
	}

	return resolveSystemEndpoint(opts)
}

// resolveExplicitEndpoint is the execution/resolution stage for an already
// validated explicit operator endpoint: it distinguishes Unix vs HTTP
// transport, auto-resolves a token for Unix endpoints, reads the explicit
// token for HTTP endpoints, and constructs the appropriate API client. The
// endpoint grammar it previously re-owned (syntax and the HTTP token-file
// requirement) is validated once by validateOperatorEndpointOptions at the
// resolveOperatorClient boundary; this stage never re-validates.
func resolveExplicitEndpoint(opts operatorClientOptions) (*apiClient, error) {
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
		// The explicit token was validated as present at the
		// resolveOperatorClient boundary.
		token, err := readTokenFile(opts.TokenFile)
		if err != nil {
			return nil, err
		}
		tokenSource = func() (string, error) { return token, nil }
	}

	if isUnix {
		return newUnixAPIClient(socketPath, tokenSource, opts.clientTimeout()), nil
	}
	return newHTTPAPIClient(socketPath, tokenSource, opts.clientTimeout()), nil
}

func resolveSystemEndpoint(opts operatorClientOptions) (*apiClient, error) {
	socketPath := systemSocketPath
	tokenPath := opts.TokenFile
	if tokenPath == "" {
		tokenPath = resolveSystemModeTokenPath()
	}

	token, err := readTokenFile(tokenPath)
	if err != nil {
		return nil, err
	}
	tokenSource := func() (string, error) { return token, nil }

	return newUnixAPIClient(socketPath, tokenSource, opts.clientTimeout()), nil
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

// validateEndpoint validates an explicit endpoint URL. This is shared transport
// syntax validation used by both operator and agent (Session) clients; it does
// not carry any authentication semantics.
func validateEndpoint(endpoint string) error {
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

// registerOperatorFlags adds --endpoint and --token-file flags to the given
// FlagSet and returns pointers to the flag values.
func registerOperatorFlags(fs *flag.FlagSet) (endpoint *explicitStringFlag, tokenFile *string) {
	// The endpoint flag is presence-aware: the CLI grammar must distinguish
	// an omitted --endpoint (default resolution) from an explicitly
	// supplied empty value (a usage error), so the shared endpoint
	// validator receives presence separately from the value.
	endpoint = &explicitStringFlag{}
	fs.Var(endpoint, "endpoint", "Explicit endpoint (/path/to/socket, unix:///path, or http://127.0.0.1:port)")
	tokenFile = fs.String("token-file", "", "Token file path (auto-resolved for unix sockets)")
	return
}
