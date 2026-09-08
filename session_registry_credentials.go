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
)

// The session Docker config directory is the one protected Session registry
// credential store: a per-Session Docker CLI config directory
// ($RUNTIME_DIR/sessions/<session-id>/docker, mode 0700) holding config.json
// in the Docker CLI config format. registry login validates the credentials
// through the Engine adapter and then persists them here exactly as the
// docker CLI login path used to; later pull/build operations read the stored
// credential just in time for the exact matching registry. No second store
// exists, and credentials never enter SQLite, audit, logs, or errors.

// sessionDockerAuthEntry mirrors one auths entry of the persisted Docker CLI
// config.json format. The auth field carries base64(username:password); the
// docker CLI encodes it with the standard base64 alphabet.
type sessionDockerAuthEntry struct {
	Auth          string `json:"auth,omitempty"`
	IdentityToken string `json:"identitytoken,omitempty"`
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

// normalizeRegistryAddress canonicalizes a registry address to the host[:port]
// form used as the credential-store key: any scheme prefix and any path
// suffix are stripped (the docker CLI ConvertToHostname semantics), so the
// spellings a caller may use for one registry resolve to one key while
// distinct registries — distinct host or port — stay distinct.
func normalizeRegistryAddress(registryAddr string) string {
	stripped := registryAddr
	if strings.Contains(stripped, "://") {
		if u, err := url.Parse(stripped); err == nil && u.Hostname() != "" {
			if u.Port() == "" {
				return u.Hostname()
			}
			return net.JoinHostPort(u.Hostname(), u.Port())
		}
	}
	host, _, _ := strings.Cut(stripped, "/")
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
