package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// =============================================================================
// Structured allowed-root CLI: list/add/remove
// =============================================================================

func TestAllowedRootListHappyPath(t *testing.T) {
	allowedRoot := testAllowedRootDir(t)
	cfg := map[string]any{
		"allowed_roots": []string{allowedRoot},
		"session_ttl":   "12h",
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	configPath := setupConfigTestWithData(t, data)

	// Verify list output
	stdout, _ := runConfigCLI(t, 0, "config", "allowed-root", "list")
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != 1 || lines[0] != allowedRoot {
		t.Errorf("expected [%s], got %v", allowedRoot, lines)
	}

	// Verify list matches config show
	showOut, _ := runConfigCLI(t, 0, "config", "show", "allowed_roots")
	if !strings.Contains(showOut, allowedRoot) {
		t.Errorf("config show should contain %s, got: %s", allowedRoot, showOut)
	}

	// Verify config file unchanged
	verifyConfigUnchanged(t, configPath, data)
}

func TestAllowedRootAddHappyPath(t *testing.T) {
	allowedRoot := testAllowedRootDir(t)
	cfg := map[string]any{
		"allowed_roots": []string{allowedRoot},
		"session_ttl":   "12h",
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	configPath := setupConfigTestWithData(t, data)

	newRoot := testAllowedRootDir(t)
	stdout, _ := runConfigCLI(t, 0, "config", "allowed-root", "add", newRoot)
	if !strings.Contains(stdout, "added "+newRoot) {
		t.Errorf("expected 'added %s', got: %s", newRoot, stdout)
	}

	// Verify both roots present
	raw := readConfigJSON(t, configPath)
	var roots []string
	if err := json.Unmarshal(raw["allowed_roots"], &roots); err != nil {
		t.Fatalf("cannot parse allowed_roots: %v", err)
	}
	if len(roots) != 2 || !contains(roots, allowedRoot) || !contains(roots, newRoot) {
		t.Errorf("expected [%s, %s], got %v", allowedRoot, newRoot, roots)
	}
}

func TestAllowedRootRemoveHappyPath(t *testing.T) {
	allowedRoot := testAllowedRootDir(t)
	extraRoot := testAllowedRootDir(t)
	cfg := map[string]any{
		"allowed_roots": []string{allowedRoot, extraRoot},
		"session_ttl":   "12h",
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	configPath := setupConfigTestWithData(t, data)

	stdout, _ := runConfigCLI(t, 0, "config", "allowed-root", "remove", extraRoot)
	if !strings.Contains(stdout, "removed "+extraRoot) {
		t.Errorf("expected 'removed %s', got: %s", extraRoot, stdout)
	}

	// Verify only original root remains
	raw := readConfigJSON(t, configPath)
	var roots []string
	if err := json.Unmarshal(raw["allowed_roots"], &roots); err != nil {
		t.Fatalf("cannot parse allowed_roots: %v", err)
	}
	if len(roots) != 1 || roots[0] != allowedRoot {
		t.Errorf("expected [%s], got %v", allowedRoot, roots)
	}
}

func TestAllowedRootFinalRemovalRejected(t *testing.T) {
	allowedRoot := testAllowedRootDir(t)
	cfg := map[string]any{
		"allowed_roots": []string{allowedRoot},
		"session_ttl":   "12h",
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	configPath := setupConfigTestWithData(t, data)

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "allowed-root", "remove", allowedRoot}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit code 2, got %d", code)
	}
	if !strings.Contains(stderr.String(), "cannot remove the last allowed root") {
		t.Errorf("expected 'cannot remove the last allowed root', got: %s", stderr.String())
	}

	// Config unchanged
	verifyConfigUnchanged(t, configPath, data)
}

// =============================================================================
// REMOVE repair semantics
// =============================================================================

func TestAllowedRootRemoveDeletedDirectory(t *testing.T) {
	base := testAllowedRootDir(t)
	extraDir := testAllowedRootDir(t)
	// Store extraDir in config, then delete the directory.
	cfg := map[string]any{
		"allowed_roots": []string{base, extraDir},
		"session_ttl":   "12h",
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	configPath := setupConfigTestWithData(t, data)

	// Delete the extra directory
	os.RemoveAll(extraDir)

	// Remove should still work
	stdout, _ := runConfigCLI(t, 0, "config", "allowed-root", "remove", extraDir)
	if !strings.Contains(stdout, "removed "+extraDir) {
		t.Errorf("expected 'removed %s', got: %s", extraDir, stdout)
	}

	// Verify only base remains
	raw := readConfigJSON(t, configPath)
	var roots []string
	if err := json.Unmarshal(raw["allowed_roots"], &roots); err != nil {
		t.Fatalf("cannot parse allowed_roots: %v", err)
	}
	if len(roots) != 1 || roots[0] != base {
		t.Errorf("expected [%s], got %v", base, roots)
	}
}

func TestAllowedRootRemoveSymlinkSpelling(t *testing.T) {
	base := testAllowedRootDir(t)
	target := filepath.Join(base, "target")
	if err := os.MkdirAll(target, 0755); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(base, "link")
	if err := os.Symlink(target, linkPath); err != nil {
		t.Fatalf("cannot create symlink: %v", err)
	}

	// Two roots: one symlink, one regular
	cfg := map[string]any{
		"allowed_roots": []string{base, linkPath},
		"session_ttl":   "12h",
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	configPath := setupConfigTestWithData(t, data)

	// Remove by symlink path should work
	stdout, _ := runConfigCLI(t, 0, "config", "allowed-root", "remove", linkPath)
	if !strings.Contains(stdout, "removed") {
		t.Errorf("expected 'removed', got: %s", stdout)
	}

	// Verify only base remains
	raw := readConfigJSON(t, configPath)
	var roots []string
	if err := json.Unmarshal(raw["allowed_roots"], &roots); err != nil {
		t.Fatalf("cannot parse allowed_roots: %v", err)
	}
	if len(roots) != 1 || roots[0] != base {
		t.Errorf("expected [%s], got %v", base, roots)
	}
}

func TestAllowedRootRemoveSymlinkToForbiddenTarget(t *testing.T) {
	base := testAllowedRootDir(t)
	// Create a symlink to a forbidden target (/var)
	linkPath := filepath.Join(base, "escape")
	if err := os.Symlink("/var", linkPath); err != nil {
		t.Fatalf("cannot create symlink: %v", err)
	}

	cfg := map[string]any{
		"allowed_roots": []string{base, linkPath},
		"session_ttl":   "12h",
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	configPath := setupConfigTestWithData(t, data)

	// Remove by symlink path should work even though target is forbidden
	stdout, _ := runConfigCLI(t, 0, "config", "allowed-root", "remove", linkPath)
	if !strings.Contains(stdout, "removed") {
		t.Errorf("expected 'removed', got: %s", stdout)
	}

	// Verify only base remains
	raw := readConfigJSON(t, configPath)
	var roots []string
	if err := json.Unmarshal(raw["allowed_roots"], &roots); err != nil {
		t.Fatalf("cannot parse allowed_roots: %v", err)
	}
	if len(roots) != 1 || roots[0] != base {
		t.Errorf("expected [%s], got %v", base, roots)
	}
}

func TestAllowedRootRemovePreservesUnrelatedSymlinkSpelling(t *testing.T) {
	base := testAllowedRootDir(t)
	target1 := filepath.Join(base, "target1")
	target2 := filepath.Join(base, "target2")
	if err := os.MkdirAll(target1, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(target2, 0755); err != nil {
		t.Fatal(err)
	}
	link1 := filepath.Join(base, "link1")
	link2 := filepath.Join(base, "link2")
	if err := os.Symlink(target1, link1); err != nil {
		t.Fatalf("cannot create symlink: %v", err)
	}
	if err := os.Symlink(target2, link2); err != nil {
		t.Fatalf("cannot create symlink: %v", err)
	}

	cfg := map[string]any{
		"allowed_roots": []string{link1, link2},
		"session_ttl":   "12h",
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	configPath := setupConfigTestWithData(t, data)

	// Remove link1; link2 spelling must be preserved
	stdout, _ := runConfigCLI(t, 0, "config", "allowed-root", "remove", link1)
	if !strings.Contains(stdout, "removed") {
		t.Errorf("expected 'removed', got: %s", stdout)
	}

	// Verify link2 stored spelling preserved (not rewritten to canonical)
	raw := readConfigJSON(t, configPath)
	var roots []string
	if err := json.Unmarshal(raw["allowed_roots"], &roots); err != nil {
		t.Fatalf("cannot parse allowed_roots: %v", err)
	}
	if len(roots) != 1 || roots[0] != link2 {
		t.Errorf("expected [%s] (stored spelling preserved), got %v", link2, roots)
	}
}

func TestAllowedRootRemoveSymlinkLoopFailsClosed(t *testing.T) {
	base := testAllowedRootDir(t)
	loop1 := filepath.Join(base, "loop1")
	loop2 := filepath.Join(base, "loop2")
	if err := os.Symlink(loop2, loop1); err != nil {
		t.Fatalf("cannot create symlink: %v", err)
	}
	if err := os.Symlink(loop1, loop2); err != nil {
		t.Fatalf("cannot create symlink: %v", err)
	}

	cfg := map[string]any{
		"allowed_roots": []string{base, loop1},
		"session_ttl":   "12h",
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	configPath := setupConfigTestWithData(t, data)

	// Remove should fail closed on symlink loop
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "allowed-root", "remove", loop1}, &stdout, &stderr)
	if code != 1 && code != 2 {
		t.Errorf("expected exit code 1 or 2, got %d, stderr: %s", code, stderr.String())
	}

	// Config unchanged
	verifyConfigUnchanged(t, configPath, data)
}

// =============================================================================
// Strict ADD: invalid existing root causes failure
// =============================================================================

func TestAllowedRootAddWithStaleExistingRoot(t *testing.T) {
	base := testAllowedRootDir(t)
	staleDir := testAllowedRootDir(t)
	cfg := map[string]any{
		"allowed_roots": []string{base, staleDir},
		"session_ttl":   "12h",
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	configPath := setupConfigTestWithData(t, data)

	// Delete the stale directory
	os.RemoveAll(staleDir)

	// Add should fail because existing root is stale
	newRoot := testAllowedRootDir(t)
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "allowed-root", "add", newRoot}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1, got %d, stderr: %s", code, stderr.String())
	}

	// Config unchanged
	verifyConfigUnchanged(t, configPath, data)
}

// =============================================================================
// Legacy migration
// =============================================================================

func TestUnchangedSetMigratesLegacy(t *testing.T) {
	allowedRoot := testAllowedRootDir(t)
	cfg := map[string]any{
		"allowed_root": allowedRoot,
		"session_ttl":  "12h",
		"log_level":    "info",
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	configPath := setupConfigTestWithData(t, data)

	// Set log_level to same value (unchanged)
	stdout, _ := runConfigCLI(t, 0, "config", "set", "log_level", "info")
	if !strings.Contains(stdout, "unchanged") {
		t.Errorf("expected 'unchanged' in output, got: %s", stdout)
	}

	// Verify migration: allowed_root gone, allowed_roots present
	raw := readConfigJSON(t, configPath)
	if raw["allowed_root"] != nil {
		t.Error("allowed_root should be removed after migration")
	}
	var roots []string
	if err := json.Unmarshal(raw["allowed_roots"], &roots); err != nil {
		t.Fatalf("cannot parse allowed_roots: %v", err)
	}
	if len(roots) != 1 || roots[0] != allowedRoot {
		t.Errorf("expected [%s], got %v", allowedRoot, roots)
	}
}

func TestUnchangedUnsetMigratesLegacy(t *testing.T) {
	allowedRoot := testAllowedRootDir(t)
	cfg := map[string]any{
		"allowed_root": allowedRoot,
		"session_ttl":  "12h",
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	configPath := setupConfigTestWithData(t, data)

	// Unset log_level (already absent)
	stdout, _ := runConfigCLI(t, 0, "config", "unset", "log_level")
	if !strings.Contains(stdout, "unchanged") {
		t.Errorf("expected 'unchanged' in output, got: %s", stdout)
	}

	// Verify migration: allowed_root gone, allowed_roots present
	raw := readConfigJSON(t, configPath)
	if raw["allowed_root"] != nil {
		t.Error("allowed_root should be removed after migration")
	}
	var roots []string
	if err := json.Unmarshal(raw["allowed_roots"], &roots); err != nil {
		t.Fatalf("cannot parse allowed_roots: %v", err)
	}
	if len(roots) != 1 || roots[0] != allowedRoot {
		t.Errorf("expected [%s], got %v", allowedRoot, roots)
	}
}

func TestIdempotentAddMigratesLegacy(t *testing.T) {
	allowedRoot := testAllowedRootDir(t)
	cfg := map[string]any{
		"allowed_root": allowedRoot,
		"session_ttl":  "12h",
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	configPath := setupConfigTestWithData(t, data)

	// Add the same root (idempotent)
	stdout, _ := runConfigCLI(t, 0, "config", "allowed-root", "add", allowedRoot)
	if !strings.Contains(stdout, "already present") {
		t.Errorf("expected 'already present' in output, got: %s", stdout)
	}

	// Verify migration: allowed_root gone, allowed_roots present
	raw := readConfigJSON(t, configPath)
	if raw["allowed_root"] != nil {
		t.Error("allowed_root should be removed after migration")
	}
	var roots []string
	if err := json.Unmarshal(raw["allowed_roots"], &roots); err != nil {
		t.Fatalf("cannot parse allowed_roots: %v", err)
	}
	if len(roots) != 1 || roots[0] != allowedRoot {
		t.Errorf("expected [%s], got %v", allowedRoot, roots)
	}
}

func TestAmbiguousSchemaFailsUnchanged(t *testing.T) {
	allowedRoot := testAllowedRootDir(t)
	cfg := map[string]any{
		"allowed_root":  allowedRoot,
		"allowed_roots": []string{allowedRoot},
		"session_ttl":   "12h",
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	configPath := setupConfigTestWithData(t, data)

	// Set should fail
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "log_level", "info"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	if !strings.Contains(stderr.String(), "ambiguous") {
		t.Errorf("expected 'ambiguous' in error, got: %s", stderr.String())
	}

	// Config unchanged
	verifyConfigUnchanged(t, configPath, data)

	// Unset should also fail
	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "unset", "log_level"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	// Config unchanged
	verifyConfigUnchanged(t, configPath, data)
}

// =============================================================================
// Init: forbidden user-mode root
// =============================================================================

func TestInitForbiddenUserRootFailsBeforeState(t *testing.T) {
	dir := t.TempDir()

	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return filepath.Join(dir, "config.json") }
	defer func() { getConfigPathFunc = origGetConfig }()

	// Use /tmp which is forbidden
	forbiddenRoot := filepath.Join(dir, "forbidden")
	if err := os.MkdirAll(forbiddenRoot, 0755); err != nil {
		t.Fatal(err)
	}

	// Save and restore EffectiveUID
	origUID := EffectiveUID
	EffectiveUID = func() int { return 1000 }
	defer func() { EffectiveUID = origUID }()

	// Standalone user init (no system daemon, Docker accessible).
	restore := mockStandaloneUserInit()
	defer restore()

	var stdout, stderr bytes.Buffer
	err := runInit(forbiddenRoot, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for forbidden root")
	}

	// Verify no config created
	configPath := filepath.Join(dir, "config.json")
	if _, err := os.Stat(configPath); !os.IsNotExist(err) {
		t.Error("config should not be created for forbidden root")
	}

	// Verify no token created
	tokenPath := filepath.Join(dir, "admin.token")
	if _, err := os.Stat(tokenPath); !os.IsNotExist(err) {
		t.Error("token should not be created for forbidden root")
	}
}

// =============================================================================
// Transactional semantics: ADD/REMOVE use shared config transaction
// =============================================================================

func TestAllowedRootAddReloadRejectedRollback(t *testing.T) {
	configPath, _, socketPath, _, cleanup := setupReloadTestEnv(t)
	defer cleanup()

	// Set up config with allowed_roots for the test.
	allowedRoot := testAllowedRootDir(t)
	cfg := map[string]any{
		"allowed_roots": []string{allowedRoot},
		"session_ttl":   "12h",
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	original := make([]byte, len(data))
	copy(original, data)

	// Mock server: reject reload.
	mux := http.NewServeMux()
	mux.HandleFunc("POST /reload", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	})
	server := &http.Server{Handler: mux}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(socketPath)
	go server.Serve(listener)
	defer server.Close()
	waitForDialReady(t, "unix", socketPath)

	newRoot := testAllowedRootDir(t)
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "allowed-root", "add", newRoot}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d, stdout: %s stderr: %s", code, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String(), "added") {
		t.Error("must not print 'added' on reload rejection")
	}
	if !strings.Contains(stderr.String(), "rolled back") {
		t.Errorf("expected 'rolled back' in stderr, got: %s", stderr.String())
	}

	// Verify config was rolled back.
	restored, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, restored) {
		t.Error("config.json should be byte-for-byte restored after rollback")
	}
}

func TestAllowedRootRemoveReloadRejectedRollback(t *testing.T) {
	configPath, _, socketPath, _, cleanup := setupReloadTestEnv(t)
	defer cleanup()

	// Set up config with two roots.
	allowedRoot := testAllowedRootDir(t)
	extraRoot := testAllowedRootDir(t)
	cfg := map[string]any{
		"allowed_roots": []string{allowedRoot, extraRoot},
		"session_ttl":   "12h",
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	original := make([]byte, len(data))
	copy(original, data)

	// Mock server: reject reload.
	mux := http.NewServeMux()
	mux.HandleFunc("POST /reload", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	})
	server := &http.Server{Handler: mux}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(socketPath)
	go server.Serve(listener)
	defer server.Close()
	waitForDialReady(t, "unix", socketPath)

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "allowed-root", "remove", extraRoot}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d, stdout: %s stderr: %s", code, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String(), "removed") {
		t.Error("must not print 'removed' on reload rejection")
	}
	if !strings.Contains(stderr.String(), "rolled back") {
		t.Errorf("expected 'rolled back' in stderr, got: %s", stderr.String())
	}

	// Verify config was rolled back.
	restored, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, restored) {
		t.Error("config.json should be byte-for-byte restored after rollback")
	}
}

func TestAllowedRootAddDaemonNotRunning(t *testing.T) {
	configPath := setupConfigTestWithData(t, nil)

	// Set up config with one root.
	allowedRoot := testAllowedRootDir(t)
	cfg := map[string]any{
		"allowed_roots": []string{allowedRoot},
		"session_ttl":   "12h",
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}

	// Ensure XDG_RUNTIME_DIR is set so the socket path exists but daemon doesn't.
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(t.TempDir(), "runtime"))

	newRoot := testAllowedRootDir(t)
	stdout, _ := runConfigCLI(t, 0, "config", "allowed-root", "add", newRoot)
	if !strings.Contains(stdout, "added "+newRoot) {
		t.Errorf("expected 'added %s', got: %s", newRoot, stdout)
	}
	if !strings.Contains(stdout, "daemon not running") {
		t.Errorf("expected 'daemon not running' in output, got: %s", stdout)
	}

	// Verify config was persisted.
	raw := readConfigJSON(t, configPath)
	var roots []string
	if err := json.Unmarshal(raw["allowed_roots"], &roots); err != nil {
		t.Fatalf("cannot parse allowed_roots: %v", err)
	}
	if len(roots) != 2 || !contains(roots, allowedRoot) || !contains(roots, newRoot) {
		t.Errorf("expected both roots, got %v", roots)
	}
}

// =============================================================================
// Transaction regression: reload transport failure rollback
// =============================================================================

// TestAllowedRootAddTransportErrRollback verifies that when the
// reload transport fails after an allowed-root ADD, the config is rolled
// back to the original bytes and no success message is emitted.
func TestAllowedRootAddTransportErrRollback(t *testing.T) {
	configPath, _, socketPath, _, cleanup := setupReloadTestEnv(t)
	defer cleanup()

	allowedRoot := testAllowedRootDir(t)
	cfg := map[string]any{
		"allowed_roots": []string{allowedRoot},
		"session_ttl":   "12h",
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	original := make([]byte, len(data))
	copy(original, data)

	// Mock server: close connection on first /reload to simulate transport error.
	var firstRequest bool
	mux := http.NewServeMux()
	mux.HandleFunc("POST /reload", func(w http.ResponseWriter, r *http.Request) {
		if !firstRequest {
			firstRequest = true
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			conn, _, err := hijacker.Hijack()
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			conn.Close()
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	server := &http.Server{Handler: mux}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	go server.Serve(listener)
	defer func() {
		server.Close()
		os.Remove(socketPath)
	}()
	waitForDialReady(t, "unix", socketPath)

	newRoot := testAllowedRootDir(t)
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "allowed-root", "add", newRoot}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d, stdout: %s stderr: %s", code, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String(), "added") {
		t.Error("must not print 'added' on transport error")
	}
	if !strings.Contains(stderr.String(), "rolled back") {
		t.Errorf("expected 'rolled back' in stderr, got: %s", stderr.String())
	}

	restored, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, restored) {
		t.Error("config.json should be byte-for-byte restored after rollback")
	}
}

// TestAllowedRootRemoveTransportErrRollback verifies that when the
// reload transport fails after an allowed-root REMOVE, the config is rolled
// back to the original bytes and no success message is emitted.
func TestAllowedRootRemoveTransportErrRollback(t *testing.T) {
	configPath, _, socketPath, _, cleanup := setupReloadTestEnv(t)
	defer cleanup()

	allowedRoot := testAllowedRootDir(t)
	extraRoot := testAllowedRootDir(t)
	cfg := map[string]any{
		"allowed_roots": []string{allowedRoot, extraRoot},
		"session_ttl":   "12h",
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	original := make([]byte, len(data))
	copy(original, data)

	// Mock server: close connection on first /reload to simulate transport error.
	var firstRequest bool
	mux := http.NewServeMux()
	mux.HandleFunc("POST /reload", func(w http.ResponseWriter, r *http.Request) {
		if !firstRequest {
			firstRequest = true
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			conn, _, err := hijacker.Hijack()
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			conn.Close()
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	server := &http.Server{Handler: mux}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	go server.Serve(listener)
	defer func() {
		server.Close()
		os.Remove(socketPath)
	}()
	waitForDialReady(t, "unix", socketPath)

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "allowed-root", "remove", extraRoot}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d, stdout: %s stderr: %s", code, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String(), "removed") {
		t.Error("must not print 'removed' on transport error")
	}
	if !strings.Contains(stderr.String(), "rolled back") {
		t.Errorf("expected 'rolled back' in stderr, got: %s", stderr.String())
	}

	restored, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, restored) {
		t.Error("config.json should be byte-for-byte restored after rollback")
	}
}

// =============================================================================
// Transaction regression: no-op on invalid config must fail
// =============================================================================

// TestAllowedRootAddNoOpInvalidConfigFails verifies that an idempotent ADD
// ("already present") on an otherwise invalid config fails with the
// validation error rather than reporting success.
func TestAllowedRootAddNoOpInvalidConfigFails(t *testing.T) {
	allowedRoot := testAllowedRootDir(t)
	// Config has a reserved field (runtime_dir) that makes it invalid.
	cfg := map[string]any{
		"allowed_roots": []string{allowedRoot},
		"session_ttl":   "12h",
		"runtime_dir":   "/should/not/be/here",
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	configPath := setupConfigTestWithData(t, data)

	// Adding the same root should fail because the config is invalid.
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "allowed-root", "add", allowedRoot}, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("expected non-zero exit, got 0, stdout: %s", stdout.String())
	}
	if strings.Contains(stdout.String(), "already present") {
		t.Error("must not print 'already present' when config is invalid")
	}
	if !strings.Contains(stderr.String(), "runtime_dir") {
		t.Errorf("expected validation error identifying reserved field, got: %s", stderr.String())
	}

	// Config unchanged
	verifyConfigUnchanged(t, configPath, data)
}

// TestAllowedRootRemoveNoOpInvalidConfigFails verifies that an idempotent
// REMOVE ("not found") on an otherwise invalid config fails with the
// validation error rather than reporting success.
func TestAllowedRootRemoveNoOpInvalidConfigFails(t *testing.T) {
	allowedRoot := testAllowedRootDir(t)
	extraRoot := testAllowedRootDir(t)
	// Config has a reserved field that makes it invalid.
	cfg := map[string]any{
		"allowed_roots": []string{allowedRoot, extraRoot},
		"session_ttl":   "12h",
		"socket_path":   "/should/not/be/here",
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	configPath := setupConfigTestWithData(t, data)

	// Removing a non-existent root should fail because the config is invalid.
	nonExistent := testAllowedRootDir(t)
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "allowed-root", "remove", nonExistent}, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("expected non-zero exit, got 0, stdout: %s", stdout.String())
	}
	if strings.Contains(stdout.String(), "not found") {
		t.Error("must not print 'not found' when config is invalid")
	}
	if !strings.Contains(stderr.String(), "socket_path") {
		t.Errorf("expected validation error identifying reserved field, got: %s", stderr.String())
	}

	// Config unchanged
	verifyConfigUnchanged(t, configPath, data)
}

// =============================================================================
// Transaction regression: SELinux ordering
// =============================================================================

// TestSELinuxPreflightOrdering verifies the SELinux preflight ordering:
//  1. invalid config -> SELinux preparation not invoked;
//  2. valid ADD of new root -> preparation invoked;
//  3. valid ADD of already-present root -> preparation invoked even though
//     the config write is skipped (SkipWrite).
func TestSELinuxPreflightOrdering(t *testing.T) {
	t.Run("invalid_config_skips_selinux", func(t *testing.T) {
		allowedRoot := testAllowedRootDir(t)
		cfg := map[string]any{
			"allowed_roots": []string{allowedRoot},
			"session_ttl":   "12h",
			"database_path": "/should/not/be/here",
		}
		data, _ := json.MarshalIndent(cfg, "", "  ")
		configPath := setupSELinuxTestEnv(t, data)

		selinuxCalled := false
		origPreflight := selinuxAllowedRootPreflight
		selinuxAllowedRootPreflight = func(string) error {
			selinuxCalled = true
			return nil
		}
		defer func() { selinuxAllowedRootPreflight = origPreflight }()

		newRoot := testAllowedRootDir(t)
		var stdout, stderr bytes.Buffer
		code := configAllowedRootAdd(newRoot, &stdout, &stderr)
		if code == 0 {
			t.Fatalf("expected non-zero exit, got 0, stdout: %s", stdout.String())
		}
		if !strings.Contains(stderr.String(), "database_path") {
			t.Errorf("expected validation error, got: %s", stderr.String())
		}
		if selinuxCalled {
			t.Error("SELinux preparation must not be invoked when config validation fails")
		}
		// Config unchanged
		verifyConfigUnchanged(t, configPath, data)
	})

	t.Run("valid_add_new_root_invokes_selinux", func(t *testing.T) {
		allowedRoot := testAllowedRootDir(t)
		cfg := map[string]any{
			"allowed_roots": []string{allowedRoot},
			"session_ttl":   "12h",
		}
		data, _ := json.MarshalIndent(cfg, "", "  ")
		configPath := setupSELinuxTestEnv(t, data)

		// Force system mode and mock isHomeRoot to return false for test roots.
		origMode := resolveDeploymentMode
		origIsHome := isHomeRoot
		resolveDeploymentMode = func() DeploymentMode { return ModeSystem }
		isHomeRoot = func(string) bool { return false }
		defer func() {
			resolveDeploymentMode = origMode
			isHomeRoot = origIsHome
		}()

		// Prevent reload from reaching a real daemon.
		origReload := attemptReload
		attemptReload = func() reloadOutcome {
			return reloadOutcome{reloadDaemonNotRunning, nil}
		}
		defer func() { attemptReload = origReload }()

		selinuxCalled := false
		origPreflight := selinuxAllowedRootPreflight
		selinuxAllowedRootPreflight = func(string) error {
			selinuxCalled = true
			return nil
		}
		defer func() { selinuxAllowedRootPreflight = origPreflight }()

		newRoot := testAllowedRootDir(t)
		var stdout, stderr bytes.Buffer
		code := configAllowedRootAdd(newRoot, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("expected exit 0, got %d, stderr: %s, selinuxCalled=%v", code, stderr.String(), selinuxCalled)
		}
		if !selinuxCalled {
			t.Error("SELinux preparation must be invoked for valid ADD of new root")
		}
		// Verify root was added.
		raw := readConfigJSON(t, configPath)
		var roots []string
		json.Unmarshal(raw["allowed_roots"], &roots)
		if !contains(roots, newRoot) {
			t.Errorf("new root not in config, got %v", roots)
		}
	})

	t.Run("valid_add_present_root_invokes_selinux", func(t *testing.T) {
		allowedRoot := testAllowedRootDir(t)
		cfg := map[string]any{
			"allowed_roots": []string{allowedRoot},
			"session_ttl":   "12h",
		}
		data, _ := json.MarshalIndent(cfg, "", "  ")
		configPath := setupSELinuxTestEnv(t, data)

		// Force system mode and mock isHomeRoot to return false for test roots.
		origMode := resolveDeploymentMode
		origIsHome := isHomeRoot
		resolveDeploymentMode = func() DeploymentMode { return ModeSystem }
		isHomeRoot = func(string) bool { return false }
		defer func() {
			resolveDeploymentMode = origMode
			isHomeRoot = origIsHome
		}()

		selinuxCalled := false
		origPreflight := selinuxAllowedRootPreflight
		selinuxAllowedRootPreflight = func(string) error {
			selinuxCalled = true
			return nil
		}
		defer func() { selinuxAllowedRootPreflight = origPreflight }()

		// Add the same root (already present).
		var stdout, stderr bytes.Buffer
		code := configAllowedRootAdd(allowedRoot, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("expected exit 0, got %d, stderr: %s", code, stderr.String())
		}
		if !strings.Contains(stdout.String(), "already present") {
			t.Errorf("expected 'already present', got: %s", stdout.String())
		}
		if !selinuxCalled {
			t.Error("SELinux preparation must be invoked for valid ADD of already-present root (SkipWrite)")
		}
		// Config unchanged (SkipWrite).
		verifyConfigUnchanged(t, configPath, data)
	})
}

// setupSELinuxTestEnv creates a test environment for SELinux preflight tests.
// It uses os.Setenv directly to ensure DOCKER_HELPER_CONFIG survives
// across EffectiveUID changes.
func setupSELinuxTestEnv(t *testing.T, data []byte) string {
	t.Helper()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	if data == nil {
		data = []byte("")
	}
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatalf("cannot write config file: %v", err)
	}
	writeTestTokenFile(t, filepath.Join(dir, "admin.token"), "dht_testtoken123\n")

	oldConfig := os.Getenv("DOCKER_HELPER_CONFIG")
	os.Setenv("DOCKER_HELPER_CONFIG", configPath)
	t.Cleanup(func() { os.Setenv("DOCKER_HELPER_CONFIG", oldConfig) })

	// Prevent reload from reaching a real daemon.
	oldRuntime := os.Getenv("XDG_RUNTIME_DIR")
	os.Setenv("XDG_RUNTIME_DIR", "")
	t.Cleanup(func() { os.Setenv("XDG_RUNTIME_DIR", oldRuntime) })

	// Override system runtime dir so system-mode reloads don't reach
	// a real daemon at /run/docker-helper/docker-helper.sock.
	oldSystemRuntime := systemRuntimeDir
	systemRuntimeDir = filepath.Join(dir, "system-runtime")
	os.MkdirAll(systemRuntimeDir, 0755)
	t.Cleanup(func() { systemRuntimeDir = oldSystemRuntime })

	return configPath
}

// testSELinuxRootDir creates a test directory under /tmp to avoid
// isHomeRoot() returning true for home directories.
func testSELinuxRootDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join("/tmp", "docker-helper-test-selinux-"+t.Name())
	if err := os.RemoveAll(dir); err != nil {
		t.Fatalf("cannot remove old test dir: %v", err)
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("cannot create test dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// =============================================================================
// Transaction regression: shared rollback/re-reload path
// =============================================================================

// TestAllowedRootAddRollbackRereload verifies that the shared
// rollback/re-reload path is authoritative for allowed-root ADD:
// when the first reload fails but the re-reload after restoration succeeds,
// the config is rolled back and the daemon is synchronized.
func TestAllowedRootAddRollbackRereload(t *testing.T) {
	configPath, _, socketPath, _, cleanup := setupReloadTestEnv(t)
	defer cleanup()

	allowedRoot := testAllowedRootDir(t)
	cfg := map[string]any{
		"allowed_roots": []string{allowedRoot},
		"session_ttl":   "12h",
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	original := make([]byte, len(data))
	copy(original, data)

	// Mock server: first reload returns 400, second returns 200.
	var reloadCount int
	mux := http.NewServeMux()
	mux.HandleFunc("POST /reload", func(w http.ResponseWriter, r *http.Request) {
		reloadCount++
		if reloadCount == 1 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	server := &http.Server{Handler: mux}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(socketPath)
	go server.Serve(listener)
	defer server.Close()
	waitForDialReady(t, "unix", socketPath)

	newRoot := testAllowedRootDir(t)
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "allowed-root", "add", newRoot}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d, stdout: %s stderr: %s", code, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String(), "added") {
		t.Error("must not print 'added' on reload rejection")
	}
	if !strings.Contains(stderr.String(), "rolled back") {
		t.Errorf("expected 'rolled back' in stderr, got: %s", stderr.String())
	}

	// Verify two reload requests were made.
	if reloadCount != 2 {
		t.Errorf("expected 2 reload requests, got %d", reloadCount)
	}

	// Verify config was rolled back.
	restored, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, restored) {
		t.Error("config.json should be byte-for-byte restored after rollback")
	}
}

// TestAllowedRootRemoveRollbackRereload verifies that the shared
// rollback/re-reload path is authoritative for allowed-root REMOVE.
func TestAllowedRootRemoveRollbackRereload(t *testing.T) {
	configPath, _, socketPath, _, cleanup := setupReloadTestEnv(t)
	defer cleanup()

	allowedRoot := testAllowedRootDir(t)
	extraRoot := testAllowedRootDir(t)
	cfg := map[string]any{
		"allowed_roots": []string{allowedRoot, extraRoot},
		"session_ttl":   "12h",
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	original := make([]byte, len(data))
	copy(original, data)

	// Mock server: first reload returns 400, second returns 200.
	var reloadCount int
	mux := http.NewServeMux()
	mux.HandleFunc("POST /reload", func(w http.ResponseWriter, r *http.Request) {
		reloadCount++
		if reloadCount == 1 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	server := &http.Server{Handler: mux}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(socketPath)
	go server.Serve(listener)
	defer server.Close()
	waitForDialReady(t, "unix", socketPath)

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "allowed-root", "remove", extraRoot}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d, stdout: %s stderr: %s", code, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String(), "removed") {
		t.Error("must not print 'removed' on reload rejection")
	}
	if !strings.Contains(stderr.String(), "rolled back") {
		t.Errorf("expected 'rolled back' in stderr, got: %s", stderr.String())
	}

	// Verify two reload requests were made.
	if reloadCount != 2 {
		t.Errorf("expected 2 reload requests, got %d", reloadCount)
	}

	// Verify config was rolled back.
	restored, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, restored) {
		t.Error("config.json should be byte-for-byte restored after rollback")
	}
}

// =============================================================================
// Helpers
// =============================================================================

func contains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

func verifyConfigUnchanged(t *testing.T, configPath string, originalData []byte) {
	t.Helper()
	currentData, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("cannot read config: %v", err)
	}
	if !bytes.Equal(currentData, originalData) {
		t.Errorf("config should be byte-for-byte unchanged.\noriginal: %s\ncurrent:  %s", string(originalData), string(currentData))
	}
}

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	db, err := openDatabase(dbPath)
	if err != nil {
		t.Fatalf("openDatabase() error: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initializeDatabase() error: %v", err)
	}
	return db
}
