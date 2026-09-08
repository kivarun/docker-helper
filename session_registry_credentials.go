package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/distribution/reference"
)

const dockerHubAuthConfigKey = "https://index.docker.io/v1/"

// The session Docker config directory is the one protected Session registry
// credential store: a per-Session Docker CLI config directory
// ($RUNTIME_DIR/sessions/<session-id>/docker, mode 0700) holding config.json
// in the Docker CLI config format. registry login validates the credentials
// through the Engine adapter and then persists them here exactly as the
// docker CLI login path used to; later pull operations read the stored
// credential just in time for the exact matching registry, and build
// operations resolve credentials through the request-owned BuildKit auth
// session for exactly the registry host the daemon asks about. No second
// store exists, and credentials never enter SQLite, audit, logs, or errors.

// sessionDockerAuthEntry mirrors one auths entry of the persisted Docker CLI
// config.json format. The auth field carries base64(username:password); the
// docker CLI encodes it with the standard base64 alphabet.
type sessionDockerAuthEntry struct {
	Auth          string `json:"auth,omitempty"`
	IdentityToken string `json:"identitytoken,omitempty"`
}

// sessionRegistryCredential is one Session registry credential resolved from
// the session Docker credential store in the form the Engine adapter
// consumes. Registry is the canonical store key the credential was persisted
// under; exactly one of the username/password pair or the identity token is
// populated, matching the persisted entry.
type sessionRegistryCredential struct {
	Registry      string
	Username      string
	Password      string
	IdentityToken string
}

// sessionDockerAuthConfig is the persisted config.json document shape.
type sessionDockerAuthConfig struct {
	Auths map[string]sessionDockerAuthEntry `json:"auths,omitempty"`
}

// sessionDockerAuthConfigMu serializes the read-modify-write cycles of every
// session Docker credential file. Session logins are rare and always small;
// one process-wide lock avoids a lost update between concurrent logins of
// the same session without an unbounded per-session lock table.
var sessionDockerAuthConfigMu sync.Mutex

// convertRegistryToHostname mirrors Docker CLI credentials.ConvertToHostname:
// it strips an optional scheme and path while preserving host[:port]. The
// Session store deliberately retains Docker CLI-compatible key semantics
// because the legacy pull path still consumes this same config.json.
func convertRegistryToHostname(maybeURL string) string {
	stripped := maybeURL
	if strings.Contains(stripped, "://") {
		if u, err := url.Parse(stripped); err == nil && u.Hostname() != "" {
			if u.Port() == "" {
				return u.Hostname()
			}
			return net.JoinHostPort(u.Hostname(), u.Port())
		}
		if host := registryHostFromURLFallback(stripped); host != "" {
			return host
		}
	}
	host, _, _ := strings.Cut(stripped, "/")
	return host
}

// registryHostFromURLFallback handles scheme URLs that net/url rejects,
// notably unbracketed IPv6 literals. This is the same compatibility behavior
// Docker CLI uses when normalizing registry credential addresses.
func registryHostFromURLFallback(maybeURL string) string {
	_, rest, ok := strings.Cut(maybeURL, "://")
	if !ok {
		return ""
	}
	host, _, _ := strings.Cut(rest, "/")
	if host == "" {
		return ""
	}
	if strings.Count(host, ":") > 1 && !strings.HasPrefix(host, "[") {
		portStart := strings.LastIndex(host, ":")
		addr, port := host[:portStart], host[portStart+1:]
		if addr != "" && registryPortDigits(port) {
			return net.JoinHostPort(addr, port)
		}
	}
	return host
}

func registryPortDigits(port string) bool {
	if port == "" {
		return false
	}
	for _, r := range port {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// normalizeRegistryLoginAddress returns the ServerAddress docker CLI would
// submit to the Engine for an explicit login. The exact "docker.io" spelling
// and its registry endpoint alias select Docker Hub's historical IndexServer;
// other spellings are normalized to host[:port] before the Engine call.
func normalizeRegistryLoginAddress(registryAddr string) string {
	if registryAddr == "docker.io" || registryAddr == "registry-1.docker.io" {
		return dockerHubAuthConfigKey
	}
	return convertRegistryToHostname(registryAddr)
}

// normalizeRegistryAddress returns the canonical Docker CLI config key for a
// registry credential. Every Docker Hub spelling shares the historical
// IndexServer key; all other registries use normalized host[:port].
func normalizeRegistryAddress(registryAddr string) string {
	host := convertRegistryToHostname(registryAddr)
	if host == "docker.io" || host == "index.docker.io" || host == "registry-1.docker.io" {
		return dockerHubAuthConfigKey
	}
	return host
}

// encodeSessionDockerAuth renders the persisted auth field of one credential
// in the docker CLI format.
func encodeSessionDockerAuth(username, password string) string {
	return base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
}

// decodeSessionDockerAuth decodes the persisted auth field into its
// username/password pair.
func decodeSessionDockerAuth(auth string) (username, password string, err error) {
	decoded, err := base64.StdEncoding.DecodeString(auth)
	if err != nil {
		return "", "", fmt.Errorf("cannot decode stored registry credential: %w", err)
	}
	username, password, ok := strings.Cut(string(decoded), ":")
	if !ok || username == "" {
		return "", "", fmt.Errorf("stored registry credential is malformed")
	}
	return username, password, nil
}

// readSessionDockerAuthConfig loads the session Docker credential document.
// An absent file is an empty configuration, not an error.
func readSessionDockerAuthConfig(dockerDir string) (sessionDockerAuthConfig, error) {
	var cfg sessionDockerAuthConfig
	blob, err := os.ReadFile(filepath.Join(dockerDir, "config.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, fmt.Errorf("cannot read session Docker credential file: %w", err)
	}
	if err := json.Unmarshal(blob, &cfg); err != nil {
		return cfg, fmt.Errorf("cannot parse session Docker credential file: %w", err)
	}
	return cfg, nil
}

// storeSessionRegistryCredential validates nothing itself; the caller must
// have validated the credentials through the Engine adapter first. It
// atomically replaces the stored entry for exactly one canonical registry
// key and leaves every other stored entry unchanged. The credential file is
// written 0600 inside the 0700 session Docker config directory.
func storeSessionRegistryCredential(runtimeDir, sessionID, registryAddr, username, password, identityToken string) error {
	dockerDir, err := ensureSessionDockerDir(runtimeDir, sessionID)
	if err != nil {
		return err
	}

	sessionDockerAuthConfigMu.Lock()
	defer sessionDockerAuthConfigMu.Unlock()

	cfg, err := readSessionDockerAuthConfig(dockerDir)
	if err != nil {
		return err
	}
	if cfg.Auths == nil {
		cfg.Auths = make(map[string]sessionDockerAuthEntry)
	}

	entry := sessionDockerAuthEntry{}
	if identityToken != "" {
		// A registry-issued identity token replaces the password exactly as
		// the docker CLI login path stored it.
		entry.IdentityToken = identityToken
	} else {
		entry.Auth = encodeSessionDockerAuth(username, password)
	}
	cfg.Auths[normalizeRegistryAddress(registryAddr)] = entry

	blob, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("cannot encode session Docker credential file: %w", err)
	}

	tmp, err := os.CreateTemp(dockerDir, ".dh-registry-*")
	if err != nil {
		return fmt.Errorf("cannot stage session Docker credential file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(blob); err != nil {
		tmp.Close()
		return fmt.Errorf("cannot write session Docker credential file: %w", err)
	}
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return fmt.Errorf("cannot set session Docker credential file permissions: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("cannot close session Docker credential file: %w", err)
	}
	if err := os.Rename(tmpName, filepath.Join(dockerDir, "config.json")); err != nil {
		return fmt.Errorf("cannot commit session Docker credential file: %w", err)
	}
	return nil
}

// readSessionRegistryCredential returns the stored credential entry for the
// exact canonical registry key. ok is false when nothing is stored for that
// registry; credentials stored for other registries are never returned.
func readSessionRegistryCredential(runtimeDir, sessionID, registryAddr string) (entry sessionDockerAuthEntry, ok bool, err error) {
	dockerDir := sessionDockerDir(runtimeDir, sessionID)
	sessionDockerAuthConfigMu.Lock()
	defer sessionDockerAuthConfigMu.Unlock()
	cfg, err := readSessionDockerAuthConfig(dockerDir)
	if err != nil {
		return entry, false, err
	}
	entry, ok = cfg.Auths[normalizeRegistryAddress(registryAddr)]
	return entry, ok, nil
}

// imageReferenceRegistryAddress extracts the registry address of an image
// reference with Docker reference semantics: the domain of the normalized
// reference, normalized to the canonical credential-store key. An
// unparseable reference resolves to "" and the pull proceeds
// unauthenticated, as the docker CLI pull path did for such references.
func imageReferenceRegistryAddress(imageRef string) string {
	named, err := reference.ParseNormalizedNamed(imageRef)
	if err != nil {
		return ""
	}
	return normalizeRegistryAddress(reference.Domain(named))
}

// resolveSessionRegistryCredential loads the Session's stored credential for
// the registry an image reference names and converts the persisted Docker CLI
// entry into the Engine adapter form. ok is false when the reference names no
// registry or nothing is stored for it; the caller then pulls
// unauthenticated. A persisted identity token is preferred over an auth pair,
// matching how the credential was stored.
func resolveSessionRegistryCredential(runtimeDir, sessionID, imageRef string) (credential *sessionRegistryCredential, ok bool, err error) {
	registryAddr := imageReferenceRegistryAddress(imageRef)
	if registryAddr == "" {
		return nil, false, nil
	}
	entry, entryOk, err := readSessionRegistryCredential(runtimeDir, sessionID, registryAddr)
	if err != nil {
		return nil, false, err
	}
	credential, err = sessionRegistryCredentialFromEntry(registryAddr, entry, entryOk)
	if err != nil || credential == nil {
		return nil, false, err
	}
	return credential, true, nil
}

// sessionRegistryCredentialFromEntry converts one persisted Docker CLI store
// entry into the Engine adapter form. ok is false when nothing is stored; a
// persisted identity token is preferred over an auth pair, matching how the
// credential was stored.
func sessionRegistryCredentialFromEntry(registryAddr string, entry sessionDockerAuthEntry, ok bool) (*sessionRegistryCredential, error) {
	if !ok {
		return nil, nil
	}
	credential := &sessionRegistryCredential{Registry: registryAddr}
	if entry.IdentityToken != "" {
		credential.IdentityToken = entry.IdentityToken
		return credential, nil
	}
	username, password, err := decodeSessionDockerAuth(entry.Auth)
	if err != nil {
		return nil, err
	}
	credential.Username = username
	credential.Password = password
	return credential, nil
}

// buildCredentialResolver resolves one stored Session registry credential
// for exactly the requested registry host, just in time. The Engine adapter
// invokes it only through the request-owned BuildKit auth session, for the
// registry host the daemon is actually resolving; credentials stored for
// other registries are never requested or returned.
type buildCredentialResolver func(registryHost string) (*sessionRegistryCredential, error)

// sessionBuildCredentialResolver returns the host-scoped credential resolver
// for one Session's build. Every lookup reads exactly the credential stored
// for the requested registry host from the one protected Session store;
// the store boundary canonicalizes the host, so every Docker Hub spelling
// resolves the stored Docker Hub credential. Nothing stored for the host
// degrades to anonymous authentication; a storage failure is operational
// and is never a silent anonymous fallback.
func sessionBuildCredentialResolver(runtimeDir, sessionID string) buildCredentialResolver {
	return func(registryHost string) (*sessionRegistryCredential, error) {
		entry, ok, err := readSessionRegistryCredential(runtimeDir, sessionID, registryHost)
		if err != nil {
			return nil, err
		}
		return sessionRegistryCredentialFromEntry(normalizeRegistryAddress(registryHost), entry, ok)
	}
}
