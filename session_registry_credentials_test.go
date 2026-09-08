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
		{"hub default", "docker.io", "docker.io"},
		{"hub index host", "index.docker.io", "index.docker.io"},
		{"hub v1 url", "https://index.docker.io/v1/", "index.docker.io"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeRegistryAddress(tc.input); got != tc.want {
				t.Errorf("normalizeRegistryAddress(%q) = %q, want %q", tc.input, got, tc.want)
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
			name:      "hub and its index host stay distinct keys",
			spellings: []string{"docker.io"},
			others:    []string{"index.docker.io"},
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
