package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
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
