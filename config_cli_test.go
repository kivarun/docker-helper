package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setupConfigTest(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	adminTokenPath := filepath.Join(dir, "admin.token")
	os.WriteFile(configPath, []byte(""), 0600)
	os.WriteFile(adminTokenPath, []byte("dht_testtoken123\n"), 0600)
	t.Setenv("DOCKER_HELPER_CONFIG", configPath)
	t.Setenv("XDG_RUNTIME_DIR", "")
	return configPath
}

func setupConfigTestWithData(t *testing.T, data []byte) string {
	t.Helper()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	adminTokenPath := filepath.Join(dir, "admin.token")
	os.WriteFile(configPath, data, 0600)
	os.WriteFile(adminTokenPath, []byte("dht_testtoken123\n"), 0600)
	t.Setenv("DOCKER_HELPER_CONFIG", configPath)
	return configPath
}

func setupConfigTestWithRuntime(t *testing.T, data []byte) string {
	t.Helper()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	adminTokenPath := filepath.Join(dir, "admin.token")
	runtimeDir := filepath.Join(dir, "runtime")
	os.MkdirAll(runtimeDir, 0700)
	os.WriteFile(configPath, data, 0600)
	os.WriteFile(adminTokenPath, []byte("dht_testtoken123\n"), 0600)
	t.Setenv("DOCKER_HELPER_CONFIG", configPath)
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)
	return configPath
}

func readConfigJSON(t *testing.T, path string) map[string]json.RawMessage {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read config: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("cannot parse config: %v", err)
	}
	return raw
}

// Req 1: config without subcommand rejected
func TestConfigNoSubcommand(t *testing.T) {
	setupConfigTest(t)
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit code 2, got %d", code)
	}
	if !strings.Contains(stderr.String(), "subcommand required") {
		t.Errorf("expected subcommand required error, got: %s", stderr.String())
	}
}

// Req 2: unknown config subcommand rejected
func TestConfigUnknownSubcommand(t *testing.T) {
	setupConfigTest(t)
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "unknown"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit code 2, got %d", code)
	}
	if !strings.Contains(stderr.String(), "unknown") {
		t.Errorf("expected unknown error, got: %s", stderr.String())
	}
}

// Req 3: show/set/unset reject missing/extra positional args
func TestConfigSubcommandsArgCount(t *testing.T) {
	setupConfigTest(t)

	// show with extra args
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "show", "a", "b"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("show extra args: expected exit code 2, got %d", code)
	}
	if !strings.Contains(stderr.String(), "expected") {
		t.Errorf("expected arg count error, got: %s", stderr.String())
	}

	// set with missing args
	code = runCommandWithWriters([]string{"config", "set", "field"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("set missing args: expected exit code 2, got %d", code)
	}

	// set with extra args
	code = runCommandWithWriters([]string{"config", "set", "a", "b", "c"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("set extra args: expected exit code 2, got %d", code)
	}

	// unset with no args
	code = runCommandWithWriters([]string{"config", "unset"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("unset no args: expected exit code 2, got %d", code)
	}

	// unset with extra args
	code = runCommandWithWriters([]string{"config", "unset", "a", "b"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("unset extra args: expected exit code 2, got %d", code)
	}
}

// Req 4: existing no-positional-arg commands still reject positionals
func TestExistingCommandsRejectPositionals(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"serve", "extra"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("serve positional: expected exit code 2, got %d", code)
	}
	if !strings.Contains(stderr.String(), "unexpected argument") {
		t.Errorf("expected unexpected argument error, got: %s", stderr.String())
	}

	code = runCommandWithWriters([]string{"version", "extra"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("version positional: expected exit code 2, got %d", code)
	}
}

// Req 5: help and unknown-flag handling still work
func TestConfigHelpAndFlags(t *testing.T) {
	setupConfigTest(t)

	// help on config show
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "show", "--help"}, &stdout, &stderr)
	if code != 0 {
		t.Errorf("show --help: expected exit code 0, got %d", code)
	}
	if !strings.Contains(stdout.String(), "Usage:") {
		t.Errorf("expected help output, got: %s", stdout.String())
	}

	// help on config set
	code = runCommandWithWriters([]string{"config", "set", "--help"}, &stdout, &stderr)
	if code != 0 {
		t.Errorf("set --help: expected exit code 0, got %d", code)
	}

	// unknown flag on show
	code = runCommandWithWriters([]string{"config", "show", "--unknown"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("show --unknown: expected exit code 2, got %d", code)
	}
}

// Req 6: general show returns valid JSON with effective values and redacted token
func TestConfigShowAllJSON(t *testing.T) {
	cfg := `{
  "allowed_root": "/home/user/work",
  "session_ttl": "12h",
  "log_level": "debug",
  "audit_enabled": false
}`
	setupConfigTestWithData(t, []byte(cfg))
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "show"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr: %s", code, stderr.String())
	}

	var result map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v, output: %s", err, stdout.String())
	}

	if result["allowed_root"] != "/home/user/work" {
		t.Errorf("allowed_root = %v", result["allowed_root"])
	}
	if result["session_ttl"] != "12h" {
		t.Errorf("session_ttl = %v", result["session_ttl"])
	}
	if result["log_level"] != "debug" {
		t.Errorf("log_level = %v", result["log_level"])
	}
	if result["audit_enabled"] != false {
		t.Errorf("audit_enabled = %v", result["audit_enabled"])
	}
	if result["audit_enabled_source"] != "explicit" {
		t.Errorf("audit_enabled_source = %v", result["audit_enabled_source"])
	}
	if result["admin_token"] != "<redacted>" {
		t.Errorf("admin_token = %v, expected <redacted>", result["admin_token"])
	}
}

// Req 7: general show never contains real token
func TestConfigShowAllRedactedToken(t *testing.T) {
	cfg := `{
  "allowed_root": "/home/user/work",
  "session_ttl": "24h"
}`
	setupConfigTestWithData(t, []byte(cfg))
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "show"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if strings.Contains(stdout.String(), "dht_testtoken123") {
		t.Error("real token must not appear in general show output")
	}
	if !strings.Contains(stdout.String(), "<redacted>") {
		t.Error("expected <redacted> in output")
	}
}

// Req 8: single-field show returns only scalar value + newline
func TestConfigShowSingleField(t *testing.T) {
	cfg := `{
  "allowed_root": "/home/user/work",
  "session_ttl": "12h",
  "log_level": "warn"
}`
	setupConfigTestWithData(t, []byte(cfg))
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "show", "allowed_root"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr: %s", code, stderr.String())
	}
	if stdout.String() != "/home/user/work\n" {
		t.Errorf("expected '/home/user/work\\n', got %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "show", "session_ttl"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if stdout.String() != "12h\n" {
		t.Errorf("expected '12h\\n', got %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "show", "log_level"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if stdout.String() != "warn\n" {
		t.Errorf("expected 'warn\\n', got %q", stdout.String())
	}
}

// Req 9: show admin_token returns complete real token
func TestConfigShowAdminToken(t *testing.T) {
	cfg := `{
  "allowed_root": "/home/user/work",
  "session_ttl": "12h"
}`
	setupConfigTestWithData(t, []byte(cfg))
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "show", "admin_token"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr: %s", code, stderr.String())
	}
	if stdout.String() != "dht_testtoken123\n" {
		t.Errorf("expected 'dht_testtoken123\\n', got %q", stdout.String())
	}
}

// Req 10: each writable field set with correct JSON type
func TestConfigSetWritableFields(t *testing.T) {
	cfg := `{
  "allowed_root": "/home/user/work",
  "session_ttl": "12h"
}`
	configPath := setupConfigTestWithData(t, []byte(cfg))

	// set allowed_root
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "allowed_root", "/new/path"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("set allowed_root: expected exit code 0, got %d, stderr: %s", code, stderr.String())
	}
	raw := readConfigJSON(t, configPath)
	var v string
	json.Unmarshal(raw["allowed_root"], &v)
	if v != "/new/path" {
		t.Errorf("allowed_root = %q, want /new/path", v)
	}

	// set session_ttl
	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "set", "session_ttl", "24h"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("set session_ttl: expected exit code 0, got %d", code)
	}
	raw = readConfigJSON(t, configPath)
	json.Unmarshal(raw["session_ttl"], &v)
	if v != "24h" {
		t.Errorf("session_ttl = %q, want 24h", v)
	}

	// set log_level
	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "set", "log_level", "debug"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("set log_level: expected exit code 0, got %d", code)
	}
	raw = readConfigJSON(t, configPath)
	json.Unmarshal(raw["log_level"], &v)
	if v != "debug" {
		t.Errorf("log_level = %q, want debug", v)
	}

	// set audit_enabled
	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "set", "audit_enabled", "true"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("set audit_enabled: expected exit code 0, got %d", code)
	}
	raw = readConfigJSON(t, configPath)
	var b bool
	json.Unmarshal(raw["audit_enabled"], &b)
	if !b {
		t.Errorf("audit_enabled = %v, want true", b)
	}
}

// Req 11: invalid durations/levels/booleans/paths/fields/read-only rejected
func TestConfigSetValidation(t *testing.T) {
	cfg := `{
  "allowed_root": "/home/user/work",
  "session_ttl": "12h"
}`
	setupConfigTestWithData(t, []byte(cfg))

	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{"invalid duration", []string{"config", "set", "session_ttl", "notaduration"}, "invalid"},
		{"negative duration", []string{"config", "set", "session_ttl", "-1h"}, "positive"},
		{"invalid log_level", []string{"config", "set", "log_level", "verbose"}, "invalid"},
		{"invalid audit_enabled", []string{"config", "set", "audit_enabled", "yes"}, "true or false"},
		{"empty allowed_root", []string{"config", "set", "allowed_root", ""}, "non-empty"},
		{"relative allowed_root", []string{"config", "set", "allowed_root", "relative"}, "absolute"},
		{"unknown field", []string{"config", "set", "unknown_field", "val"}, "unknown field"},
		{"read-only field", []string{"config", "set", "config_path", "val"}, "read-only"},
		{"admin_token read-only", []string{"config", "set", "admin_token", "val"}, "read-only"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := runCommandWithWriters(tt.args, &stdout, &stderr)
			if code != 2 {
				t.Errorf("expected exit code 2, got %d", code)
			}
			if !strings.Contains(stderr.String(), tt.wantErr) {
				t.Errorf("expected error containing %q, got: %s", tt.wantErr, stderr.String())
			}
		})
	}
}

// Req 12: invalid operations leave config.json byte-for-byte unchanged
func TestConfigSetInvalidPreservesFile(t *testing.T) {
	cfg := []byte(`{
  "allowed_root": "/home/user/work",
  "session_ttl": "12h"
}`)
	configPath := setupConfigTestWithData(t, cfg)

	var stdout, stderr bytes.Buffer
	runCommandWithWriters([]string{"config", "set", "session_ttl", "notaduration"}, &stdout, &stderr)

	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("cannot read config: %v", err)
	}
	if !bytes.Equal(data, cfg) {
		t.Errorf("config file changed after invalid set:\nbefore: %s\nafter:  %s", cfg, data)
	}
}

// Req 13: unset removes member rather than writing zero value
func TestConfigUnsetRemovesMember(t *testing.T) {
	cfg := `{
  "allowed_root": "/home/user/work",
  "session_ttl": "12h",
  "log_level": "debug"
}`
	configPath := setupConfigTestWithData(t, []byte(cfg))

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "unset", "log_level"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	raw := readConfigJSON(t, configPath)
	if _, ok := raw["log_level"]; ok {
		t.Error("log_level should be removed, not present")
	}
}

// Req 14: unsetting audit_enabled restores log_level-derived behavior
func TestConfigUnsetAuditEnabledRestoresLogLevel(t *testing.T) {
	cfg := `{
  "allowed_root": "/home/user/work",
  "session_ttl": "12h",
  "log_level": "debug",
  "audit_enabled": false
}`
	setupConfigTestWithData(t, []byte(cfg))

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "unset", "audit_enabled"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	// Now show audit_enabled - should be derived from log_level=debug
	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "show", "audit_enabled"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("show audit_enabled: expected exit code 0, got %d", code)
	}
	if stdout.String() != "true\n" {
		t.Errorf("expected 'true\\n' (debug enables audit), got %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "show", "audit_enabled_source"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("show audit_enabled_source: expected exit code 0, got %d", code)
	}
	if stdout.String() != "log_level\n" {
		t.Errorf("expected 'log_level\\n', got %q", stdout.String())
	}
}

// Req 15: unsetting log_level restores info
func TestConfigUnsetLogLevelRestoresInfo(t *testing.T) {
	cfg := `{
  "allowed_root": "/home/user/work",
  "session_ttl": "12h",
  "log_level": "warn"
}`
	setupConfigTestWithData(t, []byte(cfg))

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "unset", "log_level"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "show", "log_level"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if stdout.String() != "info\n" {
		t.Errorf("expected 'info\\n', got %q", stdout.String())
	}
}

// Req 16: unknown JSON members survive set/unset
func TestConfigPreservesUnknownMembers(t *testing.T) {
	cfg := `{
  "allowed_root": "/home/user/work",
  "session_ttl": "12h",
  "custom_field": "custom_value",
  "nested": {"key": "val"}
}`
	configPath := setupConfigTestWithData(t, []byte(cfg))

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "log_level", "debug"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	raw := readConfigJSON(t, configPath)
	if _, ok := raw["custom_field"]; !ok {
		t.Error("custom_field should be preserved after set")
	}
	if _, ok := raw["nested"]; !ok {
		t.Error("nested should be preserved after set")
	}

	// Now unset log_level and check preservation
	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "unset", "log_level"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	raw = readConfigJSON(t, configPath)
	if _, ok := raw["custom_field"]; !ok {
		t.Error("custom_field should be preserved after unset")
	}
	if _, ok := raw["nested"]; !ok {
		t.Error("nested should be preserved after unset")
	}
}

// Req 17: successful config.json has mode 0600
func TestConfigFileMode0600(t *testing.T) {
	cfg := `{
  "allowed_root": "/home/user/work",
  "session_ttl": "12h"
}`
	configPath := setupConfigTestWithData(t, []byte(cfg))

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "log_level", "debug"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	info, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("cannot stat config: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("expected mode 0600, got %o", info.Mode().Perm())
	}
}

// Req 18: successful set/unset writes nothing
func TestConfigSetUnsetSilent(t *testing.T) {
	cfg := `{
  "allowed_root": "/home/user/work",
  "session_ttl": "12h",
  "log_level": "debug"
}`
	setupConfigTestWithData(t, []byte(cfg))

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "log_level", "warn"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if stdout.Len() > 0 {
		t.Errorf("set should be silent, got stdout: %s", stdout.String())
	}
	if stderr.Len() > 0 {
		t.Errorf("set should be silent, got stderr: %s", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "unset", "log_level"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if stdout.Len() > 0 {
		t.Errorf("unset should be silent, got stdout: %s", stdout.String())
	}
	if stderr.Len() > 0 {
		t.Errorf("unset should be silent, got stderr: %s", stderr.String())
	}
}

// Req 19: stdout/stderr separation
func TestConfigStdoutStderrSeparation(t *testing.T) {
	cfg := `{
  "allowed_root": "/home/user/work",
  "session_ttl": "12h"
}`
	setupConfigTestWithData(t, []byte(cfg))

	// Error goes to stderr, nothing to stdout
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "show", "unknown_field"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit code 2, got %d", code)
	}
	if stdout.Len() > 0 {
		t.Errorf("error should go to stderr, got stdout: %s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "unknown field") {
		t.Errorf("expected error on stderr, got: %s", stderr.String())
	}

	// Success goes to stdout, nothing to stderr
	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "show", "allowed_root"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if stderr.Len() > 0 {
		t.Errorf("success should not write to stderr, got: %s", stderr.String())
	}
	if stdout.String() != "/home/user/work\n" {
		t.Errorf("expected '/home/user/work\\n', got %q", stdout.String())
	}
}

// Req 20: no config command writes to process-global stdout/stderr
func TestConfigNoGlobalStdio(t *testing.T) {
	cfg := `{
  "allowed_root": "/home/user/work",
  "session_ttl": "12h"
}`
	setupConfigTestWithData(t, []byte(cfg))

	// Redirect os.Stdout/os.Stderr to capture any writes
	oldStdout := os.Stdout
	oldStderr := os.Stderr
	defer func() {
		os.Stdout = oldStdout
		os.Stderr = oldStderr
	}()

	r, w, _ := os.Pipe()
	os.Stdout = w
	r2, w2, _ := os.Pipe()
	os.Stderr = w2

	var stdout, stderr bytes.Buffer
	runCommandWithWriters([]string{"config", "show"}, &stdout, &stderr)
	w.Close()
	w2.Close()

	var capturedStdout, capturedStderr bytes.Buffer
	r.Read(capturedStdout.Bytes())
	r2.Read(capturedStderr.Bytes())
	r.ReadFrom(&bytes.Buffer{})
	r2.ReadFrom(&bytes.Buffer{})

	if capturedStdout.Len() > 0 {
		t.Errorf("config show wrote to os.Stdout: %s", capturedStdout.String())
	}
	if capturedStderr.Len() > 0 {
		t.Errorf("config show wrote to os.Stderr: %s", capturedStderr.String())
	}

	// Test set too
	os.Stdout, _, _ = os.Pipe()
	os.Stderr, _, _ = os.Pipe()
	runCommandWithWriters([]string{"config", "set", "log_level", "debug"}, &stdout, &stderr)
}

// Req 21: config set/unset do not create runtime/state directories
func TestConfigSetUnsetNoDirCreation(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	adminTokenPath := filepath.Join(dir, "admin.token")
	runtimeDir := filepath.Join(dir, "nonexistent_runtime")
	stateDir := filepath.Join(dir, "nonexistent_state")

	os.WriteFile(configPath, []byte(`{
  "allowed_root": "/home/user/work",
  "session_ttl": "12h"
}`), 0600)
	os.WriteFile(adminTokenPath, []byte("dht_testtoken123\n"), 0600)

	t.Setenv("DOCKER_HELPER_CONFIG", configPath)
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)
	t.Setenv("XDG_STATE_HOME", stateDir)

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "log_level", "debug"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr: %s", code, stderr.String())
	}

	if _, err := os.Stat(runtimeDir); !os.IsNotExist(err) {
		t.Error("config set should not create runtime directory")
	}
	if _, err := os.Stat(stateDir); !os.IsNotExist(err) {
		t.Error("config set should not create state directory")
	}

	// Also test unset
	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "unset", "log_level"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if _, err := os.Stat(runtimeDir); !os.IsNotExist(err) {
		t.Error("config unset should not create runtime directory")
	}
}

// Additional: show unknown field returns exit 2 with empty stdout
func TestConfigShowUnknownField(t *testing.T) {
	setupConfigTest(t)
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "show", "nonexistent"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit code 2, got %d", code)
	}
	if stdout.Len() > 0 {
		t.Errorf("expected empty stdout, got: %s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "unknown field") {
		t.Errorf("expected unknown field error, got: %s", stderr.String())
	}
}

// Additional: unset required field rejected
func TestConfigUnsetRequiredField(t *testing.T) {
	cfg := `{
  "allowed_root": "/home/user/work",
  "session_ttl": "12h"
}`
	setupConfigTestWithData(t, []byte(cfg))

	for _, field := range []string{"allowed_root", "session_ttl"} {
		t.Run(field, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := runCommandWithWriters([]string{"config", "unset", field}, &stdout, &stderr)
			if code != 2 {
				t.Errorf("expected exit code 2, got %d", code)
			}
			if !strings.Contains(stderr.String(), "required") {
				t.Errorf("expected required error, got: %s", stderr.String())
			}
		})
	}
}

// Additional: unset read-only field rejected
func TestConfigUnsetReadOnlyField(t *testing.T) {
	setupConfigTest(t)
	for _, field := range []string{"config_path", "admin_token", "audit_enabled_source"} {
		t.Run(field, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := runCommandWithWriters([]string{"config", "unset", field}, &stdout, &stderr)
			if code != 2 {
				t.Errorf("expected exit code 2, got %d", code)
			}
			if !strings.Contains(stderr.String(), "read-only") {
				t.Errorf("expected read-only error, got: %s", stderr.String())
			}
		})
	}
}

// Additional: runtime-dependent fields fail without XDG_RUNTIME_DIR
func TestConfigShowRuntimeDependentNoRuntimeDir(t *testing.T) {
	cfg := `{
  "allowed_root": "/home/user/work",
  "session_ttl": "12h"
}`
	t.Setenv("XDG_RUNTIME_DIR", "")
	setupConfigTestWithData(t, []byte(cfg))

	for _, field := range []string{"runtime_dir", "socket_path", "lock_path"} {
		t.Run(field, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := runCommandWithWriters([]string{"config", "show", field}, &stdout, &stderr)
			if code != 1 {
				t.Errorf("expected exit code 1, got %d", code)
			}
			if !strings.Contains(stderr.String(), "XDG_RUNTIME_DIR") {
				t.Errorf("expected XDG_RUNTIME_DIR error, got: %s", stderr.String())
			}
		})
	}
}

// Additional: runtime-dependent fields work with XDG_RUNTIME_DIR
func TestConfigShowRuntimeDependentWithRuntimeDir(t *testing.T) {
	cfg := `{
  "allowed_root": "/home/user/work",
  "session_ttl": "12h"
}`
	runtimeDir := "/tmp/test-runtime"
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)
	setupConfigTestWithData(t, []byte(cfg))

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "show", "runtime_dir"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr: %s", code, stderr.String())
	}
	if stdout.String() != filepath.Join(runtimeDir, "docker-helper")+"\n" {
		t.Errorf("expected runtime dir, got %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "show", "socket_path"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if stdout.String() != filepath.Join(runtimeDir, "docker-helper", "docker-helper.sock")+"\n" {
		t.Errorf("expected socket path, got %q", stdout.String())
	}
}

// Additional: show with no args and no XDG_RUNTIME_DIR shows empty runtime fields
func TestConfigShowAllNoRuntimeDir(t *testing.T) {
	cfg := `{
  "allowed_root": "/home/user/work",
  "session_ttl": "12h"
}`
	t.Setenv("XDG_RUNTIME_DIR", "")
	setupConfigTestWithData(t, []byte(cfg))
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "show"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr: %s", code, stderr.String())
	}
	var result map[string]any
	json.Unmarshal(stdout.Bytes(), &result)
	if result["runtime_dir"] != "" {
		t.Errorf("runtime_dir should be empty, got %v", result["runtime_dir"])
	}
	if result["socket_path"] != "" {
		t.Errorf("socket_path should be empty, got %v", result["socket_path"])
	}
	if result["lock_path"] != "" {
		t.Errorf("lock_path should be empty, got %v", result["lock_path"])
	}
}

// Additional: show with no args and XDG_RUNTIME_DIR set
func TestConfigShowAllWithRuntimeDir(t *testing.T) {
	cfg := `{
  "allowed_root": "/home/user/work",
  "session_ttl": "12h"
}`
	runtimeDir := "/tmp/test-runtime"
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)
	setupConfigTestWithData(t, []byte(cfg))
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "show"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr: %s", code, stderr.String())
	}
	var result map[string]any
	json.Unmarshal(stdout.Bytes(), &result)
	if result["runtime_dir"] != filepath.Join(runtimeDir, "docker-helper") {
		t.Errorf("runtime_dir = %v", result["runtime_dir"])
	}
	if result["socket_path"] != filepath.Join(runtimeDir, "docker-helper", "docker-helper.sock") {
		t.Errorf("socket_path = %v", result["socket_path"])
	}
}

// Additional: audit_enabled defaults from log_level when absent
func TestConfigAuditEnabledDefault(t *testing.T) {
	cfg := `{
  "allowed_root": "/home/user/work",
  "session_ttl": "12h"
}`
	setupConfigTestWithData(t, []byte(cfg))
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "show", "audit_enabled"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if stdout.String() != "false\n" {
		t.Errorf("expected 'false\\n' (info disables audit), got %q", stdout.String())
	}

	// With log_level=debug
	cfg2 := `{
  "allowed_root": "/home/user/work",
  "session_ttl": "12h",
  "log_level": "debug"
}`
	configPath := setupConfigTestWithData(t, []byte(cfg2))
	_ = configPath
	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "show", "audit_enabled"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if stdout.String() != "true\n" {
		t.Errorf("expected 'true\\n' (debug enables audit), got %q", stdout.String())
	}
}
