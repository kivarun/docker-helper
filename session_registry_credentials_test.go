package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizeRegistryAddress(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"plain host", "registry.example.com", "registry.example.com"},
		{"host with port", "registry.example.com:5000", "registry.example.com:5000"},
		{"https scheme", "https://registry.example.com", "registry.example.com"},
		{"https scheme with port", "https://registry.example.com:5000", "registry.example.com:5000"},
		{"http scheme", "http://registry.example.com:5000", "registry.example.com:5000"},
		{"path suffix stripped", "registry.example.com/v2/", "registry.example.com"},
		{"scheme and path stripped", "https://registry.example.com/v2/", "registry.example.com"},
		{"distinct registries stay distinct", "registry.example.com:5001", "registry.example.com:5001"},
		{"hub default", "docker.io", dockerHubAuthConfigKey},
		{"hub index host", "index.docker.io", dockerHubAuthConfigKey},
		{"hub v1 url", "https://index.docker.io/v1/", dockerHubAuthConfigKey},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeRegistryAddress(tc.input); got != tc.want {
				t.Errorf("normalizeRegistryAddress(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestNormalizeRegistryLoginAddress(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"docker hub default namespace", "docker.io", dockerHubAuthConfigKey},
		{"docker hub index host remains explicit host", "index.docker.io", "index.docker.io"},
		{"docker hub index URL normalizes to host", "https://index.docker.io/v1/", "index.docker.io"},
		{"custom URL normalizes to host", "https://registry.example.com/v2/", "registry.example.com"},
		{"custom host with port", "registry.example.com:5000", "registry.example.com:5000"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeRegistryLoginAddress(tc.input); got != tc.want {
				t.Errorf("normalizeRegistryLoginAddress(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// TestNormalizeRegistryAddressNoAliasing proves the canonical form collapses
// only spellings of one registry and never merges distinct registries.
func TestNormalizeRegistryAddressNoAliasing(t *testing.T) {
	cases := []struct {
		name      string
		spellings []string
		others    []string
	}{
		{
			name:      "one host, distinct ports stay distinct",
			spellings: []string{"registry.example.com:5000", "https://registry.example.com:5000", "registry.example.com:5000/"},
			others:    []string{"registry.example.com", "registry.example.com:5001", "other.example.com:5000"},
		},
		{
			name:      "one host without port, scheme spellings collapse",
			spellings: []string{"registry.example.com", "https://registry.example.com", "http://registry.example.com/v2/"},
			others:    []string{"registry.example.com:5000", "sub.registry.example.com", "other.example.com"},
		},
		{
			name:      "docker hub aliases share the historical config key",
			spellings: []string{"docker.io", "index.docker.io", "https://index.docker.io/v1/"},
			others:    []string{"registry-1.docker.io", "other.example.com"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			first := normalizeRegistryAddress(tc.spellings[0])
			for _, spelling := range tc.spellings {
				if got := normalizeRegistryAddress(spelling); got != first {
					t.Errorf("spelling %q canonicalized to %q, want %q", spelling, got, first)
				}
			}
			for _, other := range tc.others {
				if got := normalizeRegistryAddress(other); got == first {
					t.Errorf("distinct registry %q must not alias %q", other, first)
				}
			}
		})
	}
}

func TestSessionDockerAuthRoundTrip(t *testing.T) {
	encoded := encodeSessionDockerAuth("user", "pass")
	username, password, err := decodeSessionDockerAuth(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if username != "user" || password != "pass" {
		t.Errorf("round-trip lost the pair: %q/%q", username, password)
	}

	// The persisted alphabet matches the docker CLI config format.
	blob, err := json.Marshal(map[string]sessionDockerAuthEntry{
		"registry.example.com": {Auth: encoded},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var cliConfig map[string]struct {
		Auth string `json:"auth"`
	}
	if err := json.Unmarshal(blob, &cliConfig); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if cliConfig["registry.example.com"].Auth != encoded {
		t.Errorf("persisted auth field changed: %q", cliConfig["registry.example.com"].Auth)
	}
}

// TestStoreAndReadSessionRegistryCredential proves the store/read cycle of
// the one protected credential representation.
func TestStoreAndReadSessionRegistryCredential(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}
	runtimeDir := app.Config.RuntimeDir
	sessionID := result.Session.ID

	if err := storeSessionRegistryCredential(runtimeDir, sessionID, "registry.example.com", "user", "pass", ""); err != nil {
		t.Fatalf("store: %v", err)
	}

	entry, ok, err := readSessionRegistryCredential(runtimeDir, sessionID, "registry.example.com")
	if err != nil || !ok {
		t.Fatalf("read: ok=%v err=%v", ok, err)
	}
	username, password, err := decodeSessionDockerAuth(entry.Auth)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if username != "user" || password != "pass" {
		t.Errorf("stored pair lost: %q/%q", username, password)
	}

	// A distinct registry must not read the stored credential.
	if _, ok, err := readSessionRegistryCredential(runtimeDir, sessionID, "other.example.com:5000"); err != nil || ok {
		t.Fatalf("distinct registry must not match: ok=%v err=%v", ok, err)
	}
	// A scheme spelling of the same registry resolves to the same slot.
	if _, ok, err := readSessionRegistryCredential(runtimeDir, sessionID, "https://registry.example.com"); err != nil || !ok {
		t.Fatalf("scheme spelling must resolve to the stored slot: ok=%v err=%v", ok, err)
	}

	// Nothing is stored for an unknown session.
	if _, ok, err := readSessionRegistryCredential(runtimeDir, "dhs_other", "registry.example.com"); err != nil || ok {
		t.Fatalf("foreign session must not see the credential: ok=%v err=%v", ok, err)
	}
}

func TestStoreSessionRegistryCredentialDockerHubCLIKey(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}
	runtimeDir := app.Config.RuntimeDir
	sessionID := result.Session.ID

	if err := storeSessionRegistryCredential(runtimeDir, sessionID, "docker.io", "hub-user", "hub-pass", ""); err != nil {
		t.Fatalf("store Docker Hub credential: %v", err)
	}

	cfg, err := readSessionDockerAuthConfig(sessionDockerDir(runtimeDir, sessionID))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if len(cfg.Auths) != 1 {
		t.Fatalf("expected one Docker Hub auth entry, got %d: %v", len(cfg.Auths), cfg.Auths)
	}
	if _, ok := cfg.Auths[dockerHubAuthConfigKey]; !ok {
		t.Fatalf("Docker Hub credential must use Docker CLI historical key %q: %v", dockerHubAuthConfigKey, cfg.Auths)
	}
	if _, ok := cfg.Auths["docker.io"]; ok {
		t.Fatalf("Docker Hub credential must not be stored under non-CLI key docker.io")
	}
	if _, ok := cfg.Auths["index.docker.io"]; ok {
		t.Fatalf("Docker Hub credential must not be stored under non-CLI key index.docker.io")
	}

	for _, spelling := range []string{"docker.io", "index.docker.io", "https://index.docker.io/v1/"} {
		entry, ok, err := readSessionRegistryCredential(runtimeDir, sessionID, spelling)
		if err != nil || !ok {
			t.Fatalf("Docker Hub spelling %q must resolve to stored credential: ok=%v err=%v", spelling, ok, err)
		}
		username, password, err := decodeSessionDockerAuth(entry.Auth)
		if err != nil {
			t.Fatalf("decode %q: %v", spelling, err)
		}
		if username != "hub-user" || password != "hub-pass" {
			t.Fatalf("Docker Hub spelling %q resolved wrong credential: %q/%q", spelling, username, password)
		}
	}
}

// TestStoreSessionRegistryCredentialReplacementAndPreservation proves one
// credential slot is replaced per registry and unrelated entries are kept.
func TestStoreSessionRegistryCredentialReplacementAndPreservation(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}
	runtimeDir := app.Config.RuntimeDir
	sessionID := result.Session.ID

	if err := storeSessionRegistryCredential(runtimeDir, sessionID, "registry.example.com", "old", "oldpass", ""); err != nil {
		t.Fatalf("store first: %v", err)
	}
	if err := storeSessionRegistryCredential(runtimeDir, sessionID, "other.example.com:5000", "other", "otherpass", ""); err != nil {
		t.Fatalf("store second: %v", err)
	}
	if err := storeSessionRegistryCredential(runtimeDir, sessionID, "registry.example.com", "new", "newpass", ""); err != nil {
		t.Fatalf("replace: %v", err)
	}

	entry, ok, err := readSessionRegistryCredential(runtimeDir, sessionID, "registry.example.com")
	if err != nil || !ok {
		t.Fatalf("read replaced: ok=%v err=%v", ok, err)
	}
	username, password, err := decodeSessionDockerAuth(entry.Auth)
	if err != nil {
		t.Fatalf("decode replaced: %v", err)
	}
	if username != "new" || password != "newpass" {
		t.Errorf("replaced credential lost: %q/%q", username, password)
	}

	entry, ok, err = readSessionRegistryCredential(runtimeDir, sessionID, "other.example.com:5000")
	if err != nil || !ok {
		t.Fatalf("read preserved: ok=%v err=%v", ok, err)
	}
	username, password, err = decodeSessionDockerAuth(entry.Auth)
	if err != nil {
		t.Fatalf("decode preserved: %v", err)
	}
	if username != "other" || password != "otherpass" {
		t.Errorf("unrelated credential changed: %q/%q", username, password)
	}

	// The persisted document carries exactly the two registry slots.
	cfg, err := readSessionDockerAuthConfig(sessionDockerDir(runtimeDir, sessionID))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if len(cfg.Auths) != 2 {
		t.Errorf("expected exactly 2 stored entries, got %d: %v", len(cfg.Auths), cfg.Auths)
	}
}

// TestStoreSessionRegistryCredentialIdentityToken proves a registry-issued
// identity token is stored without the password, matching the docker CLI
// login storage semantics.
func TestStoreSessionRegistryCredentialIdentityToken(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}
	runtimeDir := app.Config.RuntimeDir
	sessionID := result.Session.ID

	if err := storeSessionRegistryCredential(runtimeDir, sessionID, "registry.example.com", "user", "plainpass", "tok-123"); err != nil {
		t.Fatalf("store: %v", err)
	}

	entry, ok, err := readSessionRegistryCredential(runtimeDir, sessionID, "registry.example.com")
	if err != nil || !ok {
		t.Fatalf("read: ok=%v err=%v", ok, err)
	}
	if entry.IdentityToken != "tok-123" {
		t.Errorf("identity token lost: %q", entry.IdentityToken)
	}
	if entry.Auth != "" {
		t.Errorf("password must not be stored beside an identity token: %q", entry.Auth)
	}
}

// TestStoreSessionRegistryCredentialPermissions proves the protected
// runtime-storage semantics: the session Docker config directory stays 0700
// and the credential file is 0600.
func TestStoreSessionRegistryCredentialPermissions(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}
	runtimeDir := app.Config.RuntimeDir
	sessionID := result.Session.ID

	if err := storeSessionRegistryCredential(runtimeDir, sessionID, "registry.example.com", "user", "pass", ""); err != nil {
		t.Fatalf("store: %v", err)
	}

	dirInfo, err := os.Stat(sessionDockerDir(runtimeDir, sessionID))
	if err != nil {
		t.Fatalf("stat docker dir: %v", err)
	}
	if dirInfo.Mode().Perm() != 0700 {
		t.Errorf("docker dir mode = %o, want 0700", dirInfo.Mode().Perm())
	}

	fileInfo, err := os.Stat(filepath.Join(sessionDockerDir(runtimeDir, sessionID), "config.json"))
	if err != nil {
		t.Fatalf("stat config.json: %v", err)
	}
	if fileInfo.Mode().Perm() != 0600 {
		t.Errorf("config.json mode = %o, want 0600", fileInfo.Mode().Perm())
	}
}

// TestStoreSessionRegistryCredentialNoTempResidue proves the atomic
// replacement leaves no staging file behind.
func TestStoreSessionRegistryCredentialNoTempResidue(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}
	runtimeDir := app.Config.RuntimeDir
	sessionID := result.Session.ID

	for i := range 3 {
		if err := storeSessionRegistryCredential(runtimeDir, sessionID, "registry.example.com", "user", "pass", ""); err != nil {
			t.Fatalf("store %d: %v", i, err)
		}
	}

	entries, err := os.ReadDir(sessionDockerDir(runtimeDir, sessionID))
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, e := range entries {
		if e.Name() != "config.json" {
			t.Errorf("unexpected residue in protected credential directory: %s", e.Name())
		}
	}
}

// TestDockerfileAuthRegistries proves the FROM-line registry extraction the
// build credential projection relies on: plain and multi-stage FROM lines,
// flags, scratch, comments, and line continuations, with duplicates removed.
func TestDockerfileAuthRegistries(t *testing.T) {
	cases := []struct {
		name       string
		dockerfile string
		want       []string
	}{
		{
			name:       "plain",
			dockerfile: "FROM registry.example.com/team/base:1\nRUN echo hi\n",
			want:       []string{"registry.example.com"},
		},
		{
			name:       "docker hub",
			dockerfile: "FROM alpine:3.24\n",
			want:       []string{dockerHubAuthConfigKey},
		},
		{
			name:       "multi stage deduped",
			dockerfile: "FROM registry.example.com/a AS build\nFROM registry.example.com/b\nFROM registry.example.com/a\n",
			want:       []string{"registry.example.com"},
		},
		{
			name:       "platform flag and scratch",
			dockerfile: "FROM --platform=linux/amd64 registry.example.com/a\nFROM scratch\n",
			want:       []string{"registry.example.com"},
		},
		{
			name:       "continuation joins flags",
			dockerfile: "FROM \\\n  --platform=linux/amd64 \\\n  registry.example.com/a\n",
			want:       []string{"registry.example.com"},
		},
		{
			name:       "comments and parser directives ignored",
			dockerfile: "# syntax=docker/dockerfile:1\n# FROM registry.example.com/comment\nFROM registry.example.com/a\n",
			want:       []string{"registry.example.com"},
		},
		{
			name:       "unparseable contributes nothing",
			dockerfile: "FROM -bad-ref\n",
			want:       nil,
		},
		{
			name:       "case insensitive",
			dockerfile: "from registry.example.com/a\n",
			want:       []string{"registry.example.com"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "Dockerfile")
			if err := os.WriteFile(path, []byte(tc.dockerfile), 0o644); err != nil {
				t.Fatal(err)
			}
			got, err := dockerfileAuthRegistries(path)
			if err != nil {
				t.Fatalf("dockerfileAuthRegistries: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("registries = %v, want %v", got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Errorf("registry[%d] = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// TestResolveBuildAuthCredentials proves the credential bridge projects only
// the stored credentials the staged Dockerfile's FROM lines name: unrelated
// stored credentials are never sent, an unmatched registry builds
// unauthenticated for it, and the identity token is preferred when stored.
func TestResolveBuildAuthCredentials(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}
	runtimeDir := app.Config.RuntimeDir
	sessionID := result.Session.ID

	if err := storeSessionRegistryCredential(runtimeDir, sessionID, "registry.example.com", "user", "pass", ""); err != nil {
		t.Fatalf("store: %v", err)
	}
	if err := storeSessionRegistryCredential(runtimeDir, sessionID, "other.example.com", "other-user", "other-pass", ""); err != nil {
		t.Fatalf("store: %v", err)
	}
	if err := storeSessionRegistryCredential(runtimeDir, sessionID, "token.example.com", "ignored", "ignored", "tok-123"); err != nil {
		t.Fatalf("store: %v", err)
	}

	dockerfilePath := filepath.Join(t.TempDir(), "Dockerfile")
	dockerfile := "FROM registry.example.com/team/base:1\nFROM token.example.com/t:1\nFROM unset.example.com/x:1\nFROM alpine\n"
	if err := os.WriteFile(dockerfilePath, []byte(dockerfile), 0o644); err != nil {
		t.Fatal(err)
	}

	credentials, err := resolveBuildAuthCredentials(runtimeDir, sessionID, dockerfilePath)
	if err != nil {
		t.Fatalf("resolveBuildAuthCredentials: %v", err)
	}

	if len(credentials) != 2 {
		t.Fatalf("credentials = %d entries (%+v), want 2", len(credentials), credentials)
	}
	if credentials[0].Registry != "registry.example.com" || credentials[0].Username != "user" || credentials[0].Password != "pass" {
		t.Errorf("first credential = %+v", credentials[0])
	}
	if credentials[1].Registry != "token.example.com" || credentials[1].IdentityToken != "tok-123" {
		t.Errorf("token credential = %+v", credentials[1])
	}
	for _, credential := range credentials {
		if credential.Registry == "other.example.com" {
			t.Error("an unrelated stored credential must not be projected")
		}
	}
}

// TestResolveBuildAuthCredentialsUnreadableStore proves a store read failure
// is operational and does not silently drop credentials.
func TestResolveBuildAuthCredentialsUnreadableStore(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}
	sessionID := result.Session.ID
	dockerDir := sessionDockerDir(app.Config.RuntimeDir, sessionID)
	if _, err := ensureSessionDockerDir(app.Config.RuntimeDir, sessionID); err != nil {
		t.Fatalf("ensureSessionDockerDir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dockerDir, "config.json"), []byte("{invalid"), 0o600); err != nil {
		t.Fatal(err)
	}

	dockerfilePath := filepath.Join(t.TempDir(), "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM registry.example.com/a:1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := resolveBuildAuthCredentials(app.Config.RuntimeDir, sessionID, dockerfilePath); err == nil {
		t.Fatal("a malformed credential store must be an error, not silent unauthenticated building")
	}
}
