package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// setupConfigTestWithData creates a temp config environment: a config file
// with the given JSON data (nil = empty), an admin token beside it, and
// DOCKER_HELPER_CONFIG pointed at the config file. It returns the config
// path.
func setupConfigTestWithData(t *testing.T, data []byte) string {
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
	t.Setenv("DOCKER_HELPER_CONFIG", configPath)

	// Isolate from host XDG_RUNTIME_DIR so tests cannot reach a real
	// user-mode docker-helper socket. Tests that need XDG_RUNTIME_DIR
	// empty must set it AFTER calling this helper.
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(dir, "runtime"))
	if err := os.MkdirAll(filepath.Join(dir, "runtime", "docker-helper"), 0700); err != nil {
		t.Fatalf("cannot create runtime dir: %v", err)
	}

	// Prevent tests from reaching a real system daemon.
	origSocket := systemSocketExists
	systemSocketExists = func() bool { return false }
	t.Cleanup(func() { systemSocketExists = origSocket })

	return configPath
}

func setupConfigTest(t *testing.T) string {
	t.Helper()
	configPath := setupConfigTestWithData(t, nil)
	t.Setenv("XDG_RUNTIME_DIR", "")
	return configPath
}

// runConfigCLI runs docker-helper with the given args, capturing stdout and
// stderr, and fails the test unless the exit code is wantCode.
func runConfigCLI(t *testing.T, wantCode int, args ...string) (string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	if code := runCommandWithWriters(args, &stdout, &stderr); code != wantCode {
		t.Fatalf("expected exit code %d, got %d, stderr: %s", wantCode, code, stderr.String())
	}
	return stdout.String(), stderr.String()
}

// Req 1: config without or with an unknown subcommand is rejected
func TestConfigSubcommandDispatch(t *testing.T) {
	setupConfigTest(t)

	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{"no subcommand", []string{"config"}, "subcommand required"},
		{"unknown subcommand", []string{"config", "unknown"}, "unknown"},
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

// Req 3: show/set/unset reject missing/extra positional args
func TestConfigSubcommandsArgCount(t *testing.T) {
	setupConfigTest(t)

	tests := []struct {
		name string
		args []string
	}{
		{"show extra args", []string{"config", "show", "a", "b"}},
		{"set missing args", []string{"config", "set", "field"}},
		{"set extra args", []string{"config", "set", "a", "b", "c"}},
		{"unset no args", []string{"config", "unset"}},
		{"unset extra args", []string{"config", "unset", "a", "b"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := runCommandWithWriters(tt.args, &stdout, &stderr)
			if code != 2 {
				t.Errorf("expected exit code 2, got %d", code)
			}
			if !strings.Contains(stderr.String(), "expected") {
				t.Errorf("expected arg count error, got: %s", stderr.String())
			}
		})
	}
}

// Req 4: existing no-positional-arg commands still reject positionals
func TestExistingCommandsRejectPositionals(t *testing.T) {
	for _, cmd := range []string{"serve", "version"} {
		t.Run(cmd, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := runCommandWithWriters([]string{cmd, "extra"}, &stdout, &stderr)
			if code != 2 {
				t.Errorf("expected exit code 2, got %d", code)
			}
			if !strings.Contains(stderr.String(), "unexpected argument") {
				t.Errorf("expected unexpected argument error, got: %s", stderr.String())
			}
		})
	}
}

// Req 6: general show returns valid JSON with effective values and redacted token
func TestConfigShowAllJSON(t *testing.T) {
	cfg := `{
  "allowed_roots": ["/home/user/work"],
  "session_ttl": "12h",
  "log_level": "debug",
  "audit_enabled": false
}`
	setupConfigTestWithData(t, []byte(cfg))
	stdout, _ := runConfigCLI(t, 0, "config", "show")

	var result map[string]any
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("invalid JSON: %v, output: %s", err, stdout)
	}

	if result["allowed_roots"] == nil {
		t.Error("allowed_roots is nil")
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
  "allowed_roots": ["/home/user/work"],
  "session_ttl": "24h"
}`
	setupConfigTestWithData(t, []byte(cfg))
	stdout, _ := runConfigCLI(t, 0, "config", "show")
	if strings.Contains(stdout, "dht_testtoken123") {
		t.Error("real token must not appear in general show output")
	}
	if !strings.Contains(stdout, "<redacted>") {
		t.Error("expected <redacted> in output")
	}
}

// Req 8: single-field show returns only scalar value + newline
func TestConfigShowSingleField(t *testing.T) {
	cfg := `{
  "allowed_roots": ["/home/user/work"],
  "session_ttl": "12h",
  "log_level": "warn"
}`
	setupConfigTestWithData(t, []byte(cfg))

	tests := []struct {
		field string
		want  string
	}{
		{"allowed_roots", "[\n  \"/home/user/work\"\n]\n"},
		{"session_ttl", "12h\n"},
		{"log_level", "warn\n"},
	}
	for _, tt := range tests {
		t.Run(tt.field, func(t *testing.T) {
			stdout, _ := runConfigCLI(t, 0, "config", "show", tt.field)
			if stdout != tt.want {
				t.Errorf("expected %q, got %q", tt.want, stdout)
			}
		})
	}
}

// Req 9: show admin_token returns complete real token
func TestConfigShowAdminToken(t *testing.T) {
	cfg := `{
  "allowed_roots": ["/home/user/work"],
  "session_ttl": "12h"
}`
	setupConfigTestWithData(t, []byte(cfg))
	stdout, _ := runConfigCLI(t, 0, "config", "show", "admin_token")
	if stdout != "dht_testtoken123\n" {
		t.Errorf("expected 'dht_testtoken123\\n', got %q", stdout)
	}
}

// Req 10: core writable field types are handled correctly
func TestConfigSetCoreFieldTypes(t *testing.T) {
	allowedRoot := testAllowedRootDir(t)
	cfg := `{
  "allowed_roots": ["` + allowedRoot + `"],
  "session_ttl": "12h"
}`
	configPath := setupConfigTestWithData(t, []byte(cfg))

	tests := []struct {
		field string
		value string
		check func(map[string]json.RawMessage)
	}{
		{
			"session_ttl", "24h",
			func(raw map[string]json.RawMessage) {
				var v string
				json.Unmarshal(raw["session_ttl"], &v)
				if v != "24h" {
					t.Errorf("session_ttl = %q, want 24h", v)
				}
			},
		},
		{
			"log_level", "debug",
			func(raw map[string]json.RawMessage) {
				var v string
				json.Unmarshal(raw["log_level"], &v)
				if v != "debug" {
					t.Errorf("log_level = %q, want debug", v)
				}
			},
		},
		{
			"audit_enabled", "true",
			func(raw map[string]json.RawMessage) {
				var b bool
				json.Unmarshal(raw["audit_enabled"], &b)
				if !b {
					t.Errorf("audit_enabled = %v, want true", b)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.field, func(t *testing.T) {
			runConfigCLI(t, 0, "config", "set", tt.field, tt.value)
			raw := readConfigJSON(t, configPath)
			tt.check(raw)
		})
	}
}

// Req 11: invalid durations/levels/booleans/paths/fields/read-only rejected
func TestConfigSetValidation(t *testing.T) {
	cfg := `{
  "allowed_roots": ["/home/user/work"],
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
		{"invalid shutdown_timeout", []string{"config", "set", "shutdown_timeout", "notaduration"}, "invalid"},
		{"shutdown_timeout over maximum", []string{"config", "set", "shutdown_timeout", "45s"}, "exceeds the maximum"},
		{"invalid log_level", []string{"config", "set", "log_level", "verbose"}, "invalid"},
		{"invalid audit_enabled", []string{"config", "set", "audit_enabled", "yes"}, "true or false"},
		{"allowed_root scalar rejected", []string{"config", "set", "allowed_root", "/home/user/work"}, "no longer settable"},
		{"allowed_roots managed via structured", []string{"config", "set", "allowed_roots", "/home/user/work"}, "structured commands"},
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
  "allowed_roots": ["/home/user/work"],
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
  "allowed_roots": ["/home/user/work"],
  "session_ttl": "12h",
  "log_level": "debug"
}`
	configPath := setupConfigTestWithData(t, []byte(cfg))

	runConfigCLI(t, 0, "config", "unset", "log_level")
	raw := readConfigJSON(t, configPath)
	if _, ok := raw["log_level"]; ok {
		t.Error("log_level should be removed, not present")
	}
}

// Req 14: unsetting audit_enabled restores log_level-derived behavior
func TestConfigUnsetAuditEnabledRestoresLogLevel(t *testing.T) {
	cfg := `{
  "allowed_roots": ["/home/user/work"],
  "session_ttl": "12h",
  "log_level": "debug",
  "audit_enabled": false
}`
	setupConfigTestWithData(t, []byte(cfg))

	runConfigCLI(t, 0, "config", "unset", "audit_enabled")

	// Now show audit_enabled - should be derived from log_level=debug
	stdout, _ := runConfigCLI(t, 0, "config", "show", "audit_enabled")
	if stdout != "true\n" {
		t.Errorf("expected 'true\\n' (debug enables audit), got %q", stdout)
	}

	stdout, _ = runConfigCLI(t, 0, "config", "show", "audit_enabled_source")
	if stdout != "log_level\n" {
		t.Errorf("expected 'log_level\\n', got %q", stdout)
	}
}

// Req 15: unsetting log_level restores info
func TestConfigUnsetLogLevelRestoresInfo(t *testing.T) {
	cfg := `{
  "allowed_roots": ["/home/user/work"],
  "session_ttl": "12h",
  "log_level": "warn"
}`
	setupConfigTestWithData(t, []byte(cfg))

	runConfigCLI(t, 0, "config", "unset", "log_level")

	stdout, _ := runConfigCLI(t, 0, "config", "show", "log_level")
	if stdout != "info\n" {
		t.Errorf("expected 'info\\n', got %q", stdout)
	}
}

// Req 16: unknown JSON members survive set/unset
func TestConfigPreservesUnknownMembers(t *testing.T) {
	cfg := `{
  "allowed_roots": ["/home/user/work"],
  "session_ttl": "12h",
  "custom_field": "custom_value",
  "nested": {"key": "val"}
}`
	configPath := setupConfigTestWithData(t, []byte(cfg))

	runConfigCLI(t, 0, "config", "set", "log_level", "debug")
	raw := readConfigJSON(t, configPath)
	if _, ok := raw["custom_field"]; !ok {
		t.Error("custom_field should be preserved after set")
	}
	if _, ok := raw["nested"]; !ok {
		t.Error("nested should be preserved after set")
	}

	// Now unset log_level and check preservation
	runConfigCLI(t, 0, "config", "unset", "log_level")
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
  "allowed_roots": ["/home/user/work"],
  "session_ttl": "12h"
}`
	configPath := setupConfigTestWithData(t, []byte(cfg))

	runConfigCLI(t, 0, "config", "set", "log_level", "debug")
	info, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("cannot stat config: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("expected mode 0600, got %o", info.Mode().Perm())
	}
}

// Req 18: successful set/unset prints feedback
func TestConfigSetUnsetFeedback(t *testing.T) {
	cfg := `{
  "allowed_roots": ["/home/user/work"],
  "session_ttl": "12h",
  "log_level": "debug"
}`
	setupConfigTestWithData(t, []byte(cfg))

	stdout, stderr := runConfigCLI(t, 0, "config", "set", "log_level", "warn")
	if !strings.HasPrefix(stdout, "updated log_level=warn\n") {
		t.Errorf("set stdout = %q, want output starting with 'updated log_level=warn\\n'", stdout)
	}
	if stderr != "" {
		t.Errorf("set should not write to stderr, got: %s", stderr)
	}

	stdout, stderr = runConfigCLI(t, 0, "config", "unset", "log_level")
	if !strings.HasPrefix(stdout, "unset log_level\n") {
		t.Errorf("unset stdout = %q, want output starting with 'unset log_level\\n'", stdout)
	}
	if stderr != "" {
		t.Errorf("unset should not write to stderr, got: %s", stderr)
	}
}

// Req 19: stdout/stderr separation
func TestConfigStdoutStderrSeparation(t *testing.T) {
	cfg := `{
  "allowed_roots": ["/home/user/work"],
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
	successOut, successErr := runConfigCLI(t, 0, "config", "show", "allowed_roots")
	if successErr != "" {
		t.Errorf("success should not write to stderr, got: %s", successErr)
	}
	if !strings.Contains(successOut, "/home/user/work") {
		t.Errorf("expected '/home/user/work' in output, got %q", successOut)
	}
}

// Req 20: no config command writes to process-global stdout/stderr
func TestConfigNoGlobalStdio(t *testing.T) {
	cfg := `{
  "allowed_roots": ["/home/user/work"],
  "session_ttl": "12h",
  "log_level": "debug"
}`
	setupConfigTestWithData(t, []byte(cfg))

	// Replace os.Stdout and os.Stderr with pipes to capture global writes.
	oldStdout := os.Stdout
	oldStderr := os.Stderr
	rOut, wOut, _ := os.Pipe()
	rErr, wErr, _ := os.Pipe()
	os.Stdout = wOut
	os.Stderr = wErr
	defer func() {
		os.Stdout = oldStdout
		os.Stderr = oldStderr
	}()

	readPipe := func(r *os.File) string {
		data, _ := io.ReadAll(r)
		r.Close()
		return string(data)
	}

	// 1) Successful show
	var stdout1, stderr1 bytes.Buffer
	code1 := runCommandWithWriters([]string{"config", "show", "allowed_roots"}, &stdout1, &stderr1)
	wOut.Close()
	wErr.Close()
	globalStdout1 := readPipe(rOut)
	globalStderr1 := readPipe(rErr)

	if code1 != 0 {
		t.Errorf("show: expected exit 0, got %d", code1)
	}
	if !strings.Contains(stdout1.String(), "/home/user/work") {
		t.Errorf("show stdout = %q, want '/home/user/work' in output", stdout1.String())
	}
	if stderr1.Len() > 0 {
		t.Errorf("show stderr = %q", stderr1.String())
	}
	if globalStdout1 != "" {
		t.Errorf("show wrote to os.Stdout: %q", globalStdout1)
	}
	if globalStderr1 != "" {
		t.Errorf("show wrote to os.Stderr: %q", globalStderr1)
	}

	// Reset pipes for next invocation
	rOut2, wOut2, _ := os.Pipe()
	rErr2, wErr2, _ := os.Pipe()
	os.Stdout = wOut2
	os.Stderr = wErr2

	// 2) Successful silent set
	var stdout2, stderr2 bytes.Buffer
	code2 := runCommandWithWriters([]string{"config", "set", "log_level", "warn"}, &stdout2, &stderr2)
	wOut2.Close()
	wErr2.Close()
	globalStdout2 := readPipe(rOut2)
	globalStderr2 := readPipe(rErr2)

	if code2 != 0 {
		t.Errorf("set: expected exit 0, got %d", code2)
	}
	if !strings.HasPrefix(stdout2.String(), "updated log_level=warn\n") {
		t.Errorf("set stdout = %q, want output starting with 'updated log_level=warn\\n'", stdout2.String())
	}
	if stderr2.Len() > 0 {
		t.Errorf("set stderr = %q", stderr2.String())
	}
	if globalStdout2 != "" {
		t.Errorf("set wrote to os.Stdout: %q", globalStdout2)
	}
	if globalStderr2 != "" {
		t.Errorf("set wrote to os.Stderr: %q", globalStderr2)
	}

	// Reset pipes for next invocation
	rOut3, wOut3, _ := os.Pipe()
	rErr3, wErr3, _ := os.Pipe()
	os.Stdout = wOut3
	os.Stderr = wErr3

	// 3) Failing command (unknown field)
	var stdout3, stderr3 bytes.Buffer
	code3 := runCommandWithWriters([]string{"config", "show", "nonexistent"}, &stdout3, &stderr3)
	wOut3.Close()
	wErr3.Close()
	globalStdout3 := readPipe(rOut3)
	globalStderr3 := readPipe(rErr3)

	if code3 != 2 {
		t.Errorf("fail: expected exit 2, got %d", code3)
	}
	if stdout3.Len() > 0 {
		t.Errorf("fail stdout = %q", stdout3.String())
	}
	if !strings.Contains(stderr3.String(), "unknown field") {
		t.Errorf("fail stderr = %q", stderr3.String())
	}
	if globalStdout3 != "" {
		t.Errorf("fail wrote to os.Stdout: %q", globalStdout3)
	}
	if globalStderr3 != "" {
		t.Errorf("fail wrote to os.Stderr: %q", globalStderr3)
	}
}

// Req 21: config set/unset do not create runtime/state directories
func TestConfigSetUnsetNoDirCreation(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	adminTokenPath := filepath.Join(dir, "admin.token")
	runtimeDir := filepath.Join(dir, "nonexistent_runtime")
	stateDir := filepath.Join(dir, "nonexistent_state")

	if err := os.WriteFile(configPath, []byte(`{
  "allowed_roots": ["/home/user/work"],
  "session_ttl": "12h"
}`), 0600); err != nil {
		t.Fatalf("cannot write config file: %v", err)
	}
	writeTestTokenFile(t, adminTokenPath, "dht_testtoken123\n")

	t.Setenv("DOCKER_HELPER_CONFIG", configPath)
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)
	t.Setenv("XDG_STATE_HOME", stateDir)

	// Prevent reaching a real system daemon.
	origSocket := systemSocketExists
	systemSocketExists = func() bool { return false }
	t.Cleanup(func() { systemSocketExists = origSocket })

	runConfigCLI(t, 0, "config", "set", "log_level", "debug")

	if _, err := os.Stat(runtimeDir); !os.IsNotExist(err) {
		t.Error("config set should not create runtime directory")
	}
	if _, err := os.Stat(stateDir); !os.IsNotExist(err) {
		t.Error("config set should not create state directory")
	}

	// Also test unset
	runConfigCLI(t, 0, "config", "unset", "log_level")
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
  "allowed_roots": ["/home/user/work"],
  "session_ttl": "12h"
}`
	setupConfigTestWithData(t, []byte(cfg))

	for _, field := range []string{"allowed_roots", "session_ttl"} {
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
  "allowed_roots": ["/home/user/work"],
  "session_ttl": "12h"
}`
	setupConfigTestWithData(t, []byte(cfg))
	t.Setenv("XDG_RUNTIME_DIR", "")

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
  "allowed_roots": ["/home/user/work"],
  "session_ttl": "12h"
}`
	runtimeDir := "/tmp/test-runtime"
	setupConfigTestWithData(t, []byte(cfg))
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)

	stdout, _ := runConfigCLI(t, 0, "config", "show", "runtime_dir")
	if stdout != filepath.Join(runtimeDir, "docker-helper")+"\n" {
		t.Errorf("expected runtime dir, got %q", stdout)
	}

	stdout, _ = runConfigCLI(t, 0, "config", "show", "socket_path")
	if stdout != filepath.Join(runtimeDir, "docker-helper", "docker-helper.sock")+"\n" {
		t.Errorf("expected socket path, got %q", stdout)
	}
}

// Additional: show with no args and no XDG_RUNTIME_DIR shows empty runtime fields
func TestConfigShowAllNoRuntimeDir(t *testing.T) {
	cfg := `{
  "allowed_roots": ["/home/user/work"],
  "session_ttl": "12h"
}`
	setupConfigTestWithData(t, []byte(cfg))
	t.Setenv("XDG_RUNTIME_DIR", "")
	stdout, _ := runConfigCLI(t, 0, "config", "show")
	var result map[string]any
	json.Unmarshal([]byte(stdout), &result)
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
  "allowed_roots": ["/home/user/work"],
  "session_ttl": "12h"
}`
	runtimeDir := "/tmp/test-runtime"
	setupConfigTestWithData(t, []byte(cfg))
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)
	stdout, _ := runConfigCLI(t, 0, "config", "show")
	var result map[string]any
	json.Unmarshal([]byte(stdout), &result)
	if result["runtime_dir"] != filepath.Join(runtimeDir, "docker-helper") {
		t.Errorf("runtime_dir = %v", result["runtime_dir"])
	}
	if result["socket_path"] != filepath.Join(runtimeDir, "docker-helper", "docker-helper.sock") {
		t.Errorf("socket_path = %v", result["socket_path"])
	}
}

// --- Regression tests ---

// Regression 1: custom DOCKER_HELPER_CONFIG relocates config_dir and admin_token_path
func TestRegressionCustomConfigRelocatesPaths(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "custom", "config.json")
	adminTokenPath := filepath.Join(dir, "custom", "admin.token")
	if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
		t.Fatalf("cannot create config dir: %v", err)
	}
	if err := os.WriteFile(configPath, []byte(`{
  "allowed_roots": ["/home/user/work"],
  "session_ttl": "12h"
}`), 0600); err != nil {
		t.Fatalf("cannot write config file: %v", err)
	}
	writeTestTokenFile(t, adminTokenPath, "dht_testtoken123\n")
	t.Setenv("DOCKER_HELPER_CONFIG", configPath)
	t.Setenv("XDG_RUNTIME_DIR", "")

	stdout, _ := runConfigCLI(t, 0, "config", "show")
	var result map[string]any
	json.Unmarshal([]byte(stdout), &result)
	if result["config_dir"] != filepath.Join(dir, "custom") {
		t.Errorf("config_dir = %v, want %s", result["config_dir"], filepath.Join(dir, "custom"))
	}
	if result["admin_token_path"] != filepath.Join(dir, "custom", "admin.token") {
		t.Errorf("admin_token_path = %v, want %s", result["admin_token_path"], filepath.Join(dir, "custom", "admin.token"))
	}
}

// Regression 2: init, daemon config loading, and config show resolve the same token path
func TestRegressionConsistentTokenPath(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "myconfig", "config.json")
	if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
		t.Fatalf("cannot create config dir: %v", err)
	}
	if err := os.WriteFile(configPath, []byte(`{
  "allowed_roots": ["/home/user/work"],
  "session_ttl": "12h"
}`), 0600); err != nil {
		t.Fatalf("cannot write config file: %v", err)
	}
	t.Setenv("DOCKER_HELPER_CONFIG", configPath)

	stdout, _ := runConfigCLI(t, 0, "config", "show", "admin_token_path")
	gotPath := strings.TrimSpace(stdout)
	wantPath := filepath.Join(dir, "myconfig", "admin.token")
	if gotPath != wantPath {
		t.Errorf("admin_token_path = %q, want %q", gotPath, wantPath)
	}
}

// Regression 3: config show admin_token reads the token beside the overridden config file
func TestRegressionAdminTokenWithCustomConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "myconfig", "config.json")
	adminTokenPath := filepath.Join(dir, "myconfig", "admin.token")
	if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
		t.Fatalf("cannot create config dir: %v", err)
	}
	if err := os.WriteFile(configPath, []byte(`{
  "allowed_roots": ["/home/user/work"],
  "session_ttl": "12h"
}`), 0600); err != nil {
		t.Fatalf("cannot write config file: %v", err)
	}
	writeTestTokenFile(t, adminTokenPath, "dht_custom_token_here\n")
	t.Setenv("DOCKER_HELPER_CONFIG", configPath)

	stdout, _ := runConfigCLI(t, 0, "config", "show", "admin_token")
	if stdout != "dht_custom_token_here\n" {
		t.Errorf("admin_token = %q, want 'dht_custom_token_here\\n'", stdout)
	}
}

// Regression 4b: set rejects when the existing document has an invalid type for a known field
func TestRegressionSetRejectsInvalidType(t *testing.T) {
	cfg := `{
  "allowed_roots": ["/home/user/work"],
  "session_ttl": "12h",
  "audit_enabled": "not_a_boolean"
}`
	setupConfigTestWithData(t, []byte(cfg))

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "log_level", "debug"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1 (invalid existing config), got %d, stderr: %s", code, stderr.String())
	}
}

// Regression 6: top-level null and non-object JSON return errors without panic
func TestRegressionNullAndNonObjectJSON(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{"null", "null"},
		{"array", "[1, 2, 3]"},
		{"string", `"just a string"`},
		{"number", "42"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			configPath := filepath.Join(dir, "config.json")
			adminTokenPath := filepath.Join(dir, "admin.token")
			if err := os.WriteFile(configPath, []byte(tt.data), 0600); err != nil {
				t.Fatalf("cannot write config file: %v", err)
			}
			writeTestTokenFile(t, adminTokenPath, "dht_testtoken123\n")
			t.Setenv("DOCKER_HELPER_CONFIG", configPath)

			var stdout, stderr bytes.Buffer
			code := runCommandWithWriters([]string{"config", "show"}, &stdout, &stderr)
			if code != 1 {
				t.Errorf("show: expected exit code 1, got %d", code)
			}

			// Also test set
			stdout.Reset()
			stderr.Reset()
			code = runCommandWithWriters([]string{"config", "set", "log_level", "debug"}, &stdout, &stderr)
			if code != 1 {
				t.Errorf("set: expected exit code 1, got %d", code)
			}

			// Also test unset
			stdout.Reset()
			stderr.Reset()
			code = runCommandWithWriters([]string{"config", "unset", "log_level"}, &stdout, &stderr)
			if code != 1 {
				t.Errorf("unset: expected exit code 1, got %d", code)
			}
		})
	}
}

// Regression 7: every rejected update leaves config.json byte-for-byte unchanged
func TestRegressionRejectedUpdatePreservesFile(t *testing.T) {
	cfg := []byte(`{
  "allowed_roots": ["/home/user/work"],
  "session_ttl": "12h",
  "log_level": "debug",
  "audit_enabled": "not_a_boolean"
}`)
	configPath := setupConfigTestWithData(t, cfg)

	// Try to set a field - should fail because audit_enabled has wrong type
	var stdout, stderr bytes.Buffer
	runCommandWithWriters([]string{"config", "set", "log_level", "warn"}, &stdout, &stderr)

	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("cannot read config: %v", err)
	}
	if !bytes.Equal(data, cfg) {
		t.Errorf("config file changed after rejected set:\nbefore: %s\nafter:  %s", cfg, data)
	}

	// Try to unset a field - should also fail
	stdout.Reset()
	stderr.Reset()
	runCommandWithWriters([]string{"config", "unset", "log_level"}, &stdout, &stderr)

	data, err = os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("cannot read config: %v", err)
	}
	if !bytes.Equal(data, cfg) {
		t.Errorf("config file changed after rejected unset:\nbefore: %s\nafter:  %s", cfg, data)
	}
}

// Regression 9: lazy computed-field show works without config.json and without XDG_RUNTIME_DIR
func TestRegressionLazyComputedFieldShow(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	adminTokenPath := filepath.Join(dir, "admin.token")
	// Do NOT create config.json
	writeTestTokenFile(t, adminTokenPath, "dht_testtoken123\n")
	t.Setenv("DOCKER_HELPER_CONFIG", configPath)
	t.Setenv("XDG_RUNTIME_DIR", "")

	// config_path should work without config.json
	stdout, _ := runConfigCLI(t, 0, "config", "show", "config_path")
	if stdout != configPath+"\n" {
		t.Errorf("config_path = %q, want %q", stdout, configPath+"\n")
	}

	// config_dir should work without config.json
	stdout, _ = runConfigCLI(t, 0, "config", "show", "config_dir")
	if stdout != dir+"\n" {
		t.Errorf("config_dir = %q, want %q", stdout, dir+"\n")
	}

	// admin_token_path should work without config.json
	stdout, _ = runConfigCLI(t, 0, "config", "show", "admin_token_path")
	if stdout != adminTokenPath+"\n" {
		t.Errorf("admin_token_path = %q, want %q", stdout, adminTokenPath+"\n")
	}

	// admin_token should work without config.json
	stdout, _ = runConfigCLI(t, 0, "config", "show", "admin_token")
	if stdout != "dht_testtoken123\n" {
		t.Errorf("admin_token = %q, want 'dht_testtoken123\\n'", stdout)
	}
}

// Regression 11: the repaired global-stdio test fails if any command writes outside injected writers
// This is covered by TestConfigNoGlobalStdio which now properly captures and asserts.

// --- Reserved field regression tests ---

// Regression: every reserved field is rejected when present in config.json
func TestRegressionReservedFieldsRejected(t *testing.T) {
	reservedFields := []string{
		"audit_enabled_source",
		"config_path",
		"config_dir",
		"runtime_dir",
		"socket_path",
		"lock_path",
		"state_dir",
		"database_path",
		"admin_token_path",
		"admin_token",
	}

	for _, field := range reservedFields {
		t.Run(field, func(t *testing.T) {
			cfg := fmt.Sprintf(`{
  "allowed_roots": ["/home/user/work"],
  "session_ttl": "12h",
  "%s": "should_not_be_here"
}`, field)
			configPath := setupConfigTestWithData(t, []byte(cfg))

			// config show must reject
			var stdout, stderr bytes.Buffer
			code := runCommandWithWriters([]string{"config", "show"}, &stdout, &stderr)
			if code != 1 {
				t.Errorf("show: expected exit code 1, got %d, stderr: %s", code, stderr.String())
			}
			if !strings.Contains(stderr.String(), field) {
				t.Errorf("show: error must identify field %q, got: %s", field, stderr.String())
			}
			if !strings.Contains(stderr.String(), "computed and cannot be configured") {
				t.Errorf("show: error must say 'computed and cannot be configured', got: %s", stderr.String())
			}

			// config set must also reject (without modifying file)
			stdout.Reset()
			stderr.Reset()
			code = runCommandWithWriters([]string{"config", "set", "log_level", "debug"}, &stdout, &stderr)
			if code != 1 {
				t.Errorf("set: expected exit code 1, got %d, stderr: %s", code, stderr.String())
			}

			// config unset must also reject
			stdout.Reset()
			stderr.Reset()
			code = runCommandWithWriters([]string{"config", "unset", "log_level"}, &stdout, &stderr)
			if code != 1 {
				t.Errorf("unset: expected exit code 1, got %d, stderr: %s", code, stderr.String())
			}

			// File must be unchanged
			data, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatalf("cannot read config: %v", err)
			}
			if !bytes.Equal(data, []byte(cfg)) {
				t.Errorf("config file was modified after rejected operations")
			}
		})
	}
}

// Regression: the four bootstrapping show queries remain lazy with a malformed config.
// The missing-config case is covered by TestRegressionLazyComputedFieldShow.
func TestRegressionBootstrapQueriesLazy(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	adminTokenPath := filepath.Join(dir, "admin.token")
	// Write token but NOT config.json
	writeTestTokenFile(t, adminTokenPath, "dht_lazy_token\n")
	t.Setenv("DOCKER_HELPER_CONFIG", configPath)
	t.Setenv("XDG_RUNTIME_DIR", "")

	queries := []struct {
		field  string
		expect string
	}{
		{"config_path", configPath + "\n"},
		{"config_dir", dir + "\n"},
		{"admin_token_path", adminTokenPath + "\n"},
		{"admin_token", "dht_lazy_token\n"},
	}

	// Test with malformed config.json
	if err := os.WriteFile(configPath, []byte("not json at all"), 0600); err != nil {
		t.Fatalf("cannot write malformed config: %v", err)
	}
	for _, q := range queries {
		t.Run(q.field+"_malformed", func(t *testing.T) {
			stdout, _ := runConfigCLI(t, 0, "config", "show", q.field)
			if stdout != q.expect {
				t.Errorf("got %q, want %q", stdout, q.expect)
			}
		})
	}
}

// Regression: getConfigDir follows getConfigPath
func TestRegressionGetConfigDirFollowsGetConfigPath(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "custom", "config.json")
	os.MkdirAll(filepath.Dir(configPath), 0755)
	t.Setenv("DOCKER_HELPER_CONFIG", configPath)

	gotDir := getConfigDir()
	wantDir := filepath.Dir(getConfigPath())
	if gotDir != wantDir {
		t.Errorf("getConfigDir() = %q, want %q (filepath.Dir(getConfigPath()))", gotDir, wantDir)
	}
}

// Regression: init, daemon loaders, and config show use the same overridden paths
func TestRegressionInitDaemonConfigShowConsistent(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "myconfig", "config.json")
	xdgOther := filepath.Join(dir, "xdg_other")
	t.Setenv("DOCKER_HELPER_CONFIG", configPath)
	t.Setenv("XDG_CONFIG_HOME", xdgOther)
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(dir, "runtime"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))

	// 1) Run init - should create files at DOCKER_HELPER_CONFIG, not XDG_CONFIG_HOME
	allowedRoot := testAllowedRootDir(t)

	// Standalone user init (no system daemon, Docker accessible).
	restore := mockStandaloneUserInit()
	defer restore()

	if err := runInit(allowedRoot, io.Discard, io.Discard); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	// Verify config.json was created at DOCKER_HELPER_CONFIG
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Error("init did not create config.json at DOCKER_HELPER_CONFIG")
	}

	// Verify admin.token was created beside config.json
	adminTokenPath := filepath.Join(dir, "myconfig", "admin.token")
	if _, err := os.Stat(adminTokenPath); os.IsNotExist(err) {
		t.Error("init did not create admin.token beside config.json")
	}

	// Verify NO files were created under XDG_CONFIG_HOME
	xdgDhDir := filepath.Join(xdgOther, "docker-helper")
	if _, err := os.Stat(xdgDhDir); !os.IsNotExist(err) {
		t.Errorf("init created files under XDG_CONFIG_HOME: %s", xdgDhDir)
	}

	// 2) Verify daemon config loader uses the same paths
	cfg, err := loadAndPrepareRuntimeConfig()
	if err != nil {
		t.Fatalf("loadAndPrepareRuntimeConfig failed: %v", err)
	}
	if cfg.AdminTokenPath != adminTokenPath {
		t.Errorf("loadAndPrepareRuntimeConfig AdminTokenPath = %q, want %q", cfg.AdminTokenPath, adminTokenPath)
	}

	// 3) Verify token loading works
	if _, err := loadAdminToken(cfg.AdminTokenPath); err != nil {
		t.Fatalf("loadAdminToken failed: %v", err)
	}

	// 4) Verify config show reports the same paths
	stdout, _ := runConfigCLI(t, 0, "config", "show", "config_path")
	if strings.TrimSpace(stdout) != configPath {
		t.Errorf("config show config_path = %q, want %q", stdout, configPath)
	}

	stdout, _ = runConfigCLI(t, 0, "config", "show", "config_dir")
	if strings.TrimSpace(stdout) != filepath.Join(dir, "myconfig") {
		t.Errorf("config show config_dir = %q, want %q", stdout, filepath.Join(dir, "myconfig"))
	}

	stdout, _ = runConfigCLI(t, 0, "config", "show", "admin_token_path")
	if strings.TrimSpace(stdout) != adminTokenPath {
		t.Errorf("config show admin_token_path = %q, want %q", stdout, adminTokenPath)
	}

	// 5) Verify config show admin_token reads the real token
	tokenData, _ := os.ReadFile(adminTokenPath)
	realToken := strings.TrimSpace(string(tokenData))
	stdout, _ = runConfigCLI(t, 0, "config", "show", "admin_token")
	if strings.TrimSpace(stdout) != realToken {
		t.Errorf("config show admin_token = %q, want %q", stdout, realToken)
	}
}

// Regression: non-bootstrap fields validate config.json before returning a value
func TestRegressionNonBootstrapFieldsValidateConfig(t *testing.T) {
	// Fields that must validate config.json before returning a value.
	nonBootstrapFields := []string{
		"allowed_roots",
		"session_ttl",
		"log_level",
		"audit_enabled",
		"audit_enabled_source",
		"runtime_dir",
		"socket_path",
		"lock_path",
		"state_dir",
		"database_path",
	}

	// Bootstrap fields that must NOT validate config.json.
	bootstrapFields := []string{
		"config_path",
		"config_dir",
		"admin_token_path",
		"admin_token",
	}

	// 1) Every non-bootstrap field validates config.json before returning a value.
	//    If config.json contains a reserved field, the query must fail.
	for _, field := range nonBootstrapFields {
		t.Run(field+"_reserved_field_rejected", func(t *testing.T) {
			cfg := `{
  "allowed_roots": ["/home/user/work"],
  "session_ttl": "12h",
  "database_path": "/should/not/be/here"
}`
			setupConfigTestWithData(t, []byte(cfg))
			t.Setenv("XDG_RUNTIME_DIR", "/tmp/runtime")

			var stdout, stderr bytes.Buffer
			code := runCommandWithWriters([]string{"config", "show", field}, &stdout, &stderr)
			if code != 1 {
				t.Errorf("expected exit code 1, got %d, stderr: %s", code, stderr.String())
			}
			if stdout.Len() > 0 {
				t.Errorf("stdout must be empty on failure, got: %s", stdout.String())
			}
			if !strings.Contains(stderr.String(), "database_path") {
				t.Errorf("error must identify offending field, got: %s", stderr.String())
			}
		})
	}

	// 2) runtime_dir, socket_path, lock_path no longer bypass reserved-field validation.
	for _, field := range []string{"runtime_dir", "socket_path", "lock_path"} {
		t.Run(field+"_no_bypass", func(t *testing.T) {
			cfg := `{
  "allowed_roots": ["/home/user/work"],
  "session_ttl": "12h",
  "socket_path": "/should/not/be/here"
}`
			setupConfigTestWithData(t, []byte(cfg))
			t.Setenv("XDG_RUNTIME_DIR", "/tmp/runtime")

			var stdout, stderr bytes.Buffer
			code := runCommandWithWriters([]string{"config", "show", field}, &stdout, &stderr)
			if code != 1 {
				t.Errorf("expected exit code 1, got %d", code)
			}
			if !strings.Contains(stderr.String(), "socket_path") {
				t.Errorf("error must identify offending field, got: %s", stderr.String())
			}
		})
	}

	// 3) The four bootstrap fields still work with reserved-field-containing config.json.
	for _, field := range bootstrapFields {
		t.Run(field+"_bootstrap_works", func(t *testing.T) {
			dir := t.TempDir()
			configPath := filepath.Join(dir, "config.json")
			adminTokenPath := filepath.Join(dir, "admin.token")
			os.WriteFile(configPath, []byte(`{
  "allowed_roots": ["/home/user/work"],
  "session_ttl": "12h",
  "database_path": "/should/not/be/here"
}`), 0600)
			writeTestTokenFile(t, adminTokenPath, "dht_bootstrap_token\n")
			t.Setenv("DOCKER_HELPER_CONFIG", configPath)
			t.Setenv("XDG_RUNTIME_DIR", "")

			var stdout, stderr bytes.Buffer
			code := runCommandWithWriters([]string{"config", "show", field}, &stdout, &stderr)
			if code != 0 {
				t.Errorf("bootstrap field %s: expected exit 0, got %d, stderr: %s", field, code, stderr.String())
			}
			if stdout.Len() == 0 {
				t.Errorf("bootstrap field %s: expected non-empty stdout", field)
			}
		})
	}

	// 4) Valid configurations retain the existing output for all fields.
	t.Run("valid_config_all_fields", func(t *testing.T) {
		cfg := `{
  "allowed_roots": ["/home/user/work"],
  "session_ttl": "12h",
  "log_level": "debug"
}`
		setupConfigTestWithData(t, []byte(cfg))
		t.Setenv("XDG_RUNTIME_DIR", "/tmp/runtime")

		for _, field := range nonBootstrapFields {
			t.Run(field, func(t *testing.T) {
				var stdout, stderr bytes.Buffer
				code := runCommandWithWriters([]string{"config", "show", field}, &stdout, &stderr)
				if code != 0 {
					t.Errorf("expected exit 0, got %d, stderr: %s", code, stderr.String())
				}
				if stdout.Len() == 0 {
					t.Errorf("expected non-empty stdout, got empty")
				}
			})
		}
	})
}

// Regression: set prints updated when it adds a previously absent member
func TestRegressionSetPrintsUpdated(t *testing.T) {
	cfg := `{
  "allowed_roots": ["/home/user/work"],
  "session_ttl": "12h"
}`
	setupConfigTestWithData(t, []byte(cfg))

	stdout, _ := runConfigCLI(t, 0, "config", "set", "log_level", "debug")
	if !strings.HasPrefix(stdout, "updated log_level=debug\n") {
		t.Errorf("expected 'updated log_level=debug\\n', got %q", stdout)
	}
}

// Regression: set prints unchanged when the explicit JSON value is identical
func TestRegressionSetPrintsUnchanged(t *testing.T) {
	cfg := `{
  "allowed_roots": ["/home/user/work"],
  "session_ttl": "12h",
  "log_level": "debug"
}`
	configPath := setupConfigTestWithData(t, []byte(cfg))

	stdout, _ := runConfigCLI(t, 0, "config", "set", "log_level", "debug")
	if stdout != "unchanged log_level=debug\n" {
		t.Errorf("expected 'unchanged log_level=debug\\n', got %q", stdout)
	}

	// Verify file was not rewritten (mtime unchanged)
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("cannot read config: %v", err)
	}
	if !bytes.Equal(data, []byte(cfg)) {
		t.Error("unchanged set should not rewrite config.json")
	}
}

// Regression: effective value without explicit member still counts as update
func TestRegressionSetEffectiveValueCountsAsUpdate(t *testing.T) {
	cfg := `{
  "allowed_roots": ["/home/user/work"],
  "session_ttl": "12h",
  "log_level": "debug"
}`
	setupConfigTestWithData(t, []byte(cfg))

	// audit_enabled resolves to true via log_level=debug, but is not explicit
	stdout, _ := runConfigCLI(t, 0, "config", "set", "audit_enabled", "true")
	if !strings.HasPrefix(stdout, "updated audit_enabled=true\n") {
		t.Errorf("expected 'updated audit_enabled=true\\n', got %q", stdout)
	}
}

// Regression: unset prints unchanged when the member is absent
func TestRegressionUnsetPrintsUnchanged(t *testing.T) {
	cfg := `{
  "allowed_roots": ["/home/user/work"],
  "session_ttl": "12h"
}`
	configPath := setupConfigTestWithData(t, []byte(cfg))

	stdout, _ := runConfigCLI(t, 0, "config", "unset", "log_level")
	if stdout != "unchanged log_level is already unset\n" {
		t.Errorf("expected 'unchanged log_level is already unset\\n', got %q", stdout)
	}

	// Verify file was not rewritten
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("cannot read config: %v", err)
	}
	if !bytes.Equal(data, []byte(cfg)) {
		t.Error("unchanged unset should not rewrite config.json")
	}
}

// Regression: failure paths leave stdout empty
func TestRegressionFailurePathsEmptyStdout(t *testing.T) {
	cfg := `{
  "allowed_roots": ["/home/user/work"],
  "session_ttl": "12h"
}`
	setupConfigTestWithData(t, []byte(cfg))

	tests := []struct {
		name string
		args []string
	}{
		{"set invalid value", []string{"config", "set", "log_level", "invalid"}},
		{"set read-only", []string{"config", "set", "config_path", "/tmp"}},
		{"unset required", []string{"config", "unset", "allowed_roots"}},
		{"show unknown", []string{"config", "show", "nonexistent"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			runCommandWithWriters(tt.args, &stdout, &stderr)
			if stdout.Len() > 0 {
				t.Errorf("failure should leave stdout empty, got: %s", stdout.String())
			}
			if stderr.Len() == 0 {
				t.Error("failure should write to stderr")
			}
		})
	}
}

// Regression: unchanged set/unset with another invalid known field
func TestRegressionUnchangedMutationWithInvalidField(t *testing.T) {
	cfg := `{
  "allowed_roots": ["/home/user/work"],
  "session_ttl": "12h",
  "log_level": "debug",
  "audit_enabled": "not_a_boolean"
}`
	setupConfigTestWithData(t, []byte(cfg))

	for _, args := range [][]string{
		{"config", "set", "log_level", "debug"},
		{"config", "unset", "log_level"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := runCommandWithWriters(args, &stdout, &stderr)
			if code != 1 {
				t.Errorf("expected exit code 1, got %d, stderr: %s", code, stderr.String())
			}
			if stdout.Len() > 0 {
				t.Errorf("stdout must be empty on failure, got: %s", stdout.String())
			}
			if !strings.Contains(stderr.String(), "audit_enabled") {
				t.Errorf("error must identify offending field, got: %s", stderr.String())
			}
		})
	}
}

// Regression: valid unchanged operations still avoid replacing the file
func TestRegressionValidUnchangedAvoidsFileReplace(t *testing.T) {
	cfg := []byte(`{
  "allowed_roots": ["/home/user/work"],
  "session_ttl": "12h",
  "log_level": "debug"
}`)
	configPath := setupConfigTestWithData(t, cfg)

	// Get original file info
	info1, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("cannot stat config: %v", err)
	}

	// unchanged set
	stdout, _ := runConfigCLI(t, 0, "config", "set", "log_level", "debug")
	if stdout != "unchanged log_level=debug\n" {
		t.Errorf("expected 'unchanged log_level=debug\\n', got %q", stdout)
	}

	// Verify file was not rewritten
	info2, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("cannot stat config: %v", err)
	}
	if info2.ModTime() != info1.ModTime() {
		t.Error("unchanged set should not rewrite config.json")
	}

	// unchanged unset
	stdout, _ = runConfigCLI(t, 0, "config", "unset", "audit_enabled")
	if stdout != "unchanged audit_enabled is already unset\n" {
		t.Errorf("expected 'unchanged audit_enabled is already unset\\n', got %q", stdout)
	}

	// Verify file was not rewritten
	info3, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("cannot stat config: %v", err)
	}
	if info3.ModTime() != info1.ModTime() {
		t.Error("unchanged unset should not rewrite config.json")
	}
}

// Regression: changing or removing the invalid field itself can still repair the config
func TestRegressionRepairInvalidField(t *testing.T) {
	cfg := `{
  "allowed_roots": ["/home/user/work"],
  "session_ttl": "12h",
  "log_level": "debug",
  "audit_enabled": "not_a_boolean"
}`
	setupConfigTestWithData(t, []byte(cfg))

	// Repair by setting audit_enabled to a valid value
	stdout, _ := runConfigCLI(t, 0, "config", "set", "audit_enabled", "true")
	if !strings.HasPrefix(stdout, "updated audit_enabled=true\n") {
		t.Errorf("expected 'updated audit_enabled=true\\n', got %q", stdout)
	}

	// Repair by unsetting the invalid field
	cfg2 := `{
  "allowed_roots": ["/home/user/work"],
  "session_ttl": "12h",
  "log_level": "debug",
  "audit_enabled": "not_a_boolean"
}`
	configPath := setupConfigTestWithData(t, []byte(cfg2))

	stdout, _ = runConfigCLI(t, 0, "config", "unset", "audit_enabled")
	if !strings.HasPrefix(stdout, "unset audit_enabled\n") {
		t.Errorf("expected 'unset audit_enabled\\n', got %q", stdout)
	}

	// Verify the file is now valid
	raw := readConfigJSON(t, configPath)
	if _, ok := raw["audit_enabled"]; ok {
		t.Error("audit_enabled should be removed")
	}
}

// --- Help tests ---

func TestConfigShowHelp(t *testing.T) {
	stdout, stderr := runConfigCLI(t, 0, "config", "show", "--help")
	if stderr != "" {
		t.Errorf("stderr should be empty, got: %s", stderr)
	}

	out := stdout
	if !strings.Contains(out, "Without FIELD") {
		t.Error("help should explain general behavior")
	}
	if !strings.Contains(out, "With FIELD") {
		t.Error("help should explain single-field behavior")
	}
	if !strings.Contains(out, "redacts admin_token") {
		t.Error("help should mention token redaction")
	}
	if !strings.Contains(out, "config show admin_token") {
		t.Error("help should mention admin_token exception")
	}

	// Check all fields from the authoritative registry are listed
	for _, f := range configFields {
		if !strings.Contains(out, f.name) {
			t.Errorf("help should list field %q", f.name)
		}
	}
}

func TestConfigSetHelp(t *testing.T) {
	stdout, stderr := runConfigCLI(t, 0, "config", "set", "--help")
	if stderr != "" {
		t.Errorf("stderr should be empty, got: %s", stderr)
	}

	out := stdout
	for _, f := range configFields {
		if f.writable && f.name != "allowed_roots" && !strings.Contains(out, f.name) {
			t.Errorf("help should list writable field %q", f.name)
		}
	}
	if !strings.Contains(out, "allowed-root") {
		t.Error("help should mention allowed-root structured commands")
	}
	if !strings.Contains(out, "duration") {
		t.Error("help should mention duration validation")
	}
	if !strings.Contains(out, "updated") {
		t.Error("help should mention updated feedback")
	}
	if !strings.Contains(out, "unchanged") {
		t.Error("help should mention unchanged feedback")
	}
	if !strings.Contains(out, "daemon") {
		t.Error("help should mention daemon reload behavior")
	}
}

func TestConfigUnsetHelp(t *testing.T) {
	stdout, stderr := runConfigCLI(t, 0, "config", "unset", "--help")
	if stderr != "" {
		t.Errorf("stderr should be empty, got: %s", stderr)
	}

	out := stdout
	if !strings.Contains(out, "log_level") {
		t.Error("help should list log_level")
	}
	if !strings.Contains(out, "audit_enabled") {
		t.Error("help should list audit_enabled")
	}
	if !strings.Contains(out, "info") {
		t.Error("help should mention default info")
	}
	if !strings.Contains(out, "derived") {
		t.Error("help should mention derived behavior for audit_enabled")
	}
	if !strings.Contains(out, "unset") {
		t.Error("help should mention unset feedback")
	}
	if !strings.Contains(out, "unchanged") {
		t.Error("help should mention unchanged feedback")
	}
	// Must not list required fields as unsettable
	if strings.Contains(out, "allowed_root") {
		t.Error("help must not list allowed_root as unsettable")
	}
	if strings.Contains(out, "session_ttl") {
		t.Error("help must not list session_ttl as unsettable")
	}
}

func TestConfigHelpNoConfigNeeded(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	t.Setenv("DOCKER_HELPER_CONFIG", configPath)
	t.Setenv("XDG_RUNTIME_DIR", "")
	// config.json does not exist

	for _, args := range [][]string{
		{"config", "show", "--help"},
		{"config", "set", "--help"},
		{"config", "unset", "--help"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			stdout, _ := runConfigCLI(t, 0, args...)
			if !strings.Contains(stdout, "Usage:") {
				t.Error("expected help output")
			}
		})
	}
}

func TestConfigHelpNoDirCreation(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "custom", "config.json")
	runtimeDir := filepath.Join(dir, "runtime")
	stateDir := filepath.Join(dir, "state")
	t.Setenv("DOCKER_HELPER_CONFIG", configPath)
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)
	t.Setenv("XDG_STATE_HOME", stateDir)

	for _, args := range [][]string{
		{"config", "show", "--help"},
		{"config", "set", "--help"},
		{"config", "unset", "--help"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			runCommandWithWriters(args, &stdout, &stderr)

			if _, err := os.Stat(filepath.Dir(configPath)); !os.IsNotExist(err) {
				t.Error("help should not create config directory")
			}
			if _, err := os.Stat(runtimeDir); !os.IsNotExist(err) {
				t.Error("help should not create runtime directory")
			}
			if _, err := os.Stat(stateDir); !os.IsNotExist(err) {
				t.Error("help should not create state directory")
			}
		})
	}
}

func TestConfigHelpStdoutStderrSeparation(t *testing.T) {
	for _, args := range [][]string{
		{"config", "show", "--help"},
		{"config", "set", "--help"},
		{"config", "unset", "--help"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			stdout, stderr := runConfigCLI(t, 0, args...)
			if stderr != "" {
				t.Errorf("help should not write to stderr, got: %s", stderr)
			}
			if !strings.Contains(stdout, "Usage:") {
				t.Error("help should write to stdout")
			}
		})
	}
}

func TestConfigFieldRegistryInvariants(t *testing.T) {
	// Names are unique.
	seen := make(map[string]bool)
	for _, f := range configFields {
		if seen[f.name] {
			t.Errorf("duplicate field name %q", f.name)
		}
		seen[f.name] = true
	}

	// Required fields are always writable.
	for _, f := range configFields {
		if f.required && !f.writable {
			t.Errorf("required field %q must be writable", f.name)
		}
	}

	// http_address is registered as writable.
	spec, ok := lookupConfigField("http_address")
	if !ok || !spec.writable {
		t.Error("http_address must be writable")
	}
}

func TestConfigHelpUnknownFlagStillRejected(t *testing.T) {
	for _, args := range [][]string{
		{"config", "show", "--unknown"},
		{"config", "set", "--unknown"},
		{"config", "unset", "--unknown"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := runCommandWithWriters(args, &stdout, &stderr)
			if code != 2 {
				t.Errorf("expected exit code 2, got %d", code)
			}
		})
	}
}

// TestLoadAndPrepareRuntimeConfigRejectsInvalidConfig verifies that loadAndPrepareRuntimeConfig rejects
// missing, empty, relative, or non-positive required fields.
func TestLoadAndPrepareRuntimeConfigRejectsInvalidConfig(t *testing.T) {
	tests := []struct {
		name    string
		cfg     string   // %s is replaced with a policy-legal allowed root
		wantErr []string // substrings expected in the error; empty means any error
	}{
		{name: "missing allowed_root", cfg: `{"session_ttl":"12h"}`, wantErr: []string{"allowed_root"}},
		{name: "empty allowed_roots", cfg: `{"allowed_root":"","session_ttl":"12h"}`},
		{name: "relative allowed_roots", cfg: `{"allowed_roots": ["relative/path"],"session_ttl":"12h"}`},
		{name: "missing session_ttl", cfg: `{"allowed_roots": ["%s"]}`, wantErr: []string{"session_ttl"}},
		{name: "zero session_ttl", cfg: `{"allowed_roots": ["/tmp"],"session_ttl":"0s"}`},
		{name: "negative session_ttl", cfg: `{"allowed_roots": ["/tmp"],"session_ttl":"-1h"}`},
		{name: "deprecated build_log_max_bytes", cfg: `{"allowed_roots": ["%s"],"session_ttl":"12h","build_log_max_bytes":8192}`, wantErr: []string{"build_log_max_bytes", "operation_log_max_bytes"}},
		{name: "deprecated and new key both present", cfg: `{"allowed_roots": ["%s"],"session_ttl":"12h","build_log_max_bytes":8192,"operation_log_max_bytes":16384}`, wantErr: []string{"build_log_max_bytes"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			configPath := filepath.Join(dir, "config.json")
			cfg := tt.cfg
			if strings.Contains(cfg, "%s") {
				cfg = fmt.Sprintf(cfg, testAllowedRootDir(t))
			}
			if err := os.WriteFile(configPath, []byte(cfg), 0600); err != nil {
				t.Fatalf("cannot write config: %v", err)
			}
			t.Setenv("DOCKER_HELPER_CONFIG", configPath)
			t.Setenv("XDG_RUNTIME_DIR", filepath.Join(dir, "runtime"))
			t.Setenv("XDG_STATE_HOME", dir)
			if err := os.MkdirAll(filepath.Join(dir, "runtime"), 0700); err != nil {
				t.Fatal(err)
			}

			_, err := loadAndPrepareRuntimeConfig()
			if err == nil {
				t.Fatal("expected error")
			}
			for _, want := range tt.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("expected error to contain %q, got: %v", want, err)
				}
			}
		})
	}
}

func TestLoadAndPrepareRuntimeConfigAcceptsValidConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	allowedRoot := testAllowedRootDir(t)
	cfg := map[string]any{
		"allowed_root": allowedRoot,
		"session_ttl":  "12h",
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DOCKER_HELPER_CONFIG", configPath)
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(dir, "runtime"))
	t.Setenv("XDG_STATE_HOME", dir)
	if err := os.MkdirAll(filepath.Join(dir, "runtime"), 0700); err != nil {
		t.Fatal(err)
	}

	c, err := loadAndPrepareRuntimeConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.AllowedRoots[0] != allowedRoot {
		t.Errorf("AllowedRoot = %q, want %q", c.AllowedRoots[0], allowedRoot)
	}
}

// TestReloadRejectsInvalidConfig verifies that the reload handler rejects
// invalid configurations (empty allowed_roots, non-positive session_ttl).
func TestReloadRejectsInvalidConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  string
	}{
		{name: "empty_root", cfg: `{"allowed_root":"","session_ttl":"12h"}`},
		{name: "negative_ttl", cfg: `{"allowed_roots": ["%s"],"session_ttl":"-1h"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, socketPath, _, cleanup := setupReloadTestEnv(t)
			defer cleanup()

			cfg, err := loadAndPrepareRuntimeConfig()
			if err != nil {
				t.Fatal(err)
			}
			adminHash, err := loadAdminToken(cfg.AdminTokenPath)
			if err != nil {
				t.Fatal(err)
			}

			db, err := openDatabase(cfg.DatabasePath)
			if err != nil {
				t.Fatal(err)
			}
			if err := initializeDatabase(db); err != nil {
				t.Fatal(err)
			}
			defer db.Close()

			app := &App{
				Config:         cfg,
				DB:             db,
				AdminTokenHash: adminHash,
			}

			mux := http.NewServeMux()
			mux.HandleFunc("POST /reload", withRequestID(app.handleReload))

			server := &http.Server{Handler: mux}
			listener, err := net.Listen("unix", socketPath)
			if err != nil {
				t.Fatal(err)
			}
			defer os.Remove(socketPath)

			go server.Serve(listener)
			defer server.Close()
			waitForDialReady(t, "unix", socketPath)

			configPath := getConfigPath()
			cfgBytes := []byte(tt.cfg)
			if strings.Contains(tt.cfg, "%s") {
				cfgBytes = []byte(fmt.Sprintf(tt.cfg, testAllowedRootDir(t)))
			}
			if err := os.WriteFile(configPath, cfgBytes, 0600); err != nil {
				t.Fatal(err)
			}

			transport := &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return net.DialTimeout("unix", socketPath, 2*time.Second)
				},
			}
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second}

			req, err := http.NewRequest("POST", "http://localhost/reload", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer test-admin-token")

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				t.Fatal("expected reload to reject invalid config")
			}
		})
	}
}

// --- Deprecated field tests ---

// Deprecated 1: config file with old build_log_max_bytes rejected by daemon
// TestDeprecatedBuildLogMaxBytesCLIOperations verifies that the CLI show/set/
// unset subcommands all reject the renamed build_log_max_bytes key with exit
// code 2, empty stdout, and a stderr diagnostic naming both the old and new key.
func TestDeprecatedBuildLogMaxBytesCLIOperations(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "show", args: []string{"config", "show", "build_log_max_bytes"}},
		{name: "set", args: []string{"config", "set", "build_log_max_bytes", "123"}},
		{name: "unset", args: []string{"config", "unset", "build_log_max_bytes"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowedRoot := testAllowedRootDir(t)
			cfg := fmt.Sprintf(`{
  "allowed_roots": ["%s"],
  "session_ttl": "12h"
}`, allowedRoot)
			setupConfigTestWithData(t, []byte(cfg))

			var stdout, stderr bytes.Buffer
			code := runCommandWithWriters(tt.args, &stdout, &stderr)
			if code != 2 {
				t.Errorf("expected exit code 2, got %d", code)
			}
			if stdout.Len() > 0 {
				t.Errorf("stdout must be empty, got: %s", stdout.String())
			}
			if !strings.Contains(stderr.String(), "build_log_max_bytes") {
				t.Errorf("stderr must mention deprecated key, got: %s", stderr.String())
			}
			if !strings.Contains(stderr.String(), "operation_log_max_bytes") {
				t.Errorf("stderr must mention new key, got: %s", stderr.String())
			}
		})
	}
}

// Deprecated 6: new operation_log_max_bytes still works
func TestDeprecatedOperationLogMaxBytesWorks(t *testing.T) {
	allowedRoot := testAllowedRootDir(t)
	cfg := `{
  "allowed_roots": ["` + allowedRoot + `"],
  "session_ttl": "12h",
  "operation_log_max_bytes": 8192
}`
	setupConfigTestWithData(t, []byte(cfg))

	stdout, _ := runConfigCLI(t, 0, "config", "show", "operation_log_max_bytes")
	if stdout != "8192\n" {
		t.Errorf("expected '8192\\n', got %q", stdout)
	}
}

func TestConfigShowEffectiveInvariant(t *testing.T) {
	cfg := `{
  "allowed_roots": ["/home/user/work"],
  "session_ttl": "12h"
}`
	setupConfigTestWithData(t, []byte(cfg))
	t.Setenv("XDG_RUNTIME_DIR", "")

	stdout, _ := runConfigCLI(t, 0, "config", "show")

	var result map[string]any
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	checkField := func(key string, expected any) {
		t.Helper()
		if v, ok := result[key]; !ok {
			t.Errorf("missing key %q", key)
		} else if v != expected {
			t.Errorf("%s = %v, want %v", key, v, expected)
		}
	}

	checkField("log_level", "info")
	checkField("audit_enabled", false)
	checkField("audit_enabled_source", "log_level")
	checkField("shutdown_timeout", "30s")
	checkField("operation_retention_ttl", "10m")
	checkField("operation_max_completed", float64(200))
	checkField("trusted_ca_injection", "disabled")

	// operation_log_max_bytes is int64, JSON encodes as number
	if v, ok := result["operation_log_max_bytes"]; !ok {
		t.Error("missing key operation_log_max_bytes")
	} else {
		switch val := v.(type) {
		case float64:
			if int64(val) != 4194304 {
				t.Errorf("operation_log_max_bytes = %v, want 4194304", val)
			}
		case json.Number:
			if val.String() != "4194304" {
				t.Errorf("operation_log_max_bytes = %v, want 4194304", val)
			}
		default:
			t.Errorf("operation_log_max_bytes = %v (%T), want 4194304", val, val)
		}
	}

	fields := []string{
		"log_level",
		"audit_enabled",
		"audit_enabled_source",
		"shutdown_timeout",
		"operation_retention_ttl",
		"operation_max_completed",
		"operation_log_max_bytes",
		"trusted_ca_injection",
	}

	for _, field := range fields {
		t.Run(field, func(t *testing.T) {
			fieldOut, _ := runConfigCLI(t, 0, "config", "show", field)
			fieldVal := strings.TrimSpace(fieldOut)

			// For numeric fields, compare as strings since JSON encoding differs
			switch field {
			case "operation_max_completed":
				if fieldVal != "200" {
					t.Errorf("show %s = %q, want %q", field, fieldVal, "200")
				}
			case "operation_log_max_bytes":
				if fieldVal != "4194304" {
					t.Errorf("show %s = %q, want %q", field, fieldVal, "4194304")
				}
			default:
				expectedVal := fmt.Sprintf("%v", result[field])
				if fieldVal != expectedVal {
					t.Errorf("show %s = %q, want %q", field, fieldVal, expectedVal)
				}
			}
		})
	}
}

// TestConfigAllowedRootCommandTree verifies that config allowed-root uses
// the Command.Subcommands framework with proper arity enforcement.
func TestConfigAllowedRootCommandTree(t *testing.T) {
	t.Run("no_subcommand_exit_2", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := runCommandWithWriters([]string{"config", "allowed-root"}, &stdout, &stderr)
		if code != 2 {
			t.Errorf("expected exit 2, got %d", code)
		}
		if !strings.Contains(stderr.String(), "subcommand") && !strings.Contains(stderr.String(), "Usage:") {
			t.Errorf("expected subcommand error, got: %s", stderr.String())
		}
	})

	t.Run("unknown_subcommand_exit_2", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := runCommandWithWriters([]string{"config", "allowed-root", "unknown"}, &stdout, &stderr)
		if code != 2 {
			t.Errorf("expected exit 2, got %d", code)
		}
		if !strings.Contains(stderr.String(), "unknown") {
			t.Errorf("expected unknown subcommand error, got: %s", stderr.String())
		}
	})

	t.Run("list_extra_arg_exit_2", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := runCommandWithWriters([]string{"config", "allowed-root", "list", "extra"}, &stdout, &stderr)
		if code != 2 {
			t.Errorf("expected exit 2, got %d", code)
		}
	})

	t.Run("add_no_path_exit_2", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := runCommandWithWriters([]string{"config", "allowed-root", "add"}, &stdout, &stderr)
		if code != 2 {
			t.Errorf("expected exit 2, got %d", code)
		}
	})

	t.Run("add_extra_arg_exit_2", func(t *testing.T) {
		allowedRoot := testAllowedRootDir(t)
		var stdout, stderr bytes.Buffer
		code := runCommandWithWriters([]string{"config", "allowed-root", "add", allowedRoot, "extra"}, &stdout, &stderr)
		if code != 2 {
			t.Errorf("expected exit 2, got %d", code)
		}
	})

	t.Run("remove_no_path_exit_2", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := runCommandWithWriters([]string{"config", "allowed-root", "remove"}, &stdout, &stderr)
		if code != 2 {
			t.Errorf("expected exit 2, got %d", code)
		}
	})

	t.Run("remove_extra_arg_exit_2", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := runCommandWithWriters([]string{"config", "allowed-root", "remove", "/some/path", "extra"}, &stdout, &stderr)
		if code != 2 {
			t.Errorf("expected exit 2, got %d", code)
		}
	})

	t.Run("list_reaches_implementation", func(t *testing.T) {
		allowedRoot := testAllowedRootDir(t)
		cfg := map[string]any{
			"allowed_roots": []string{allowedRoot},
			"session_ttl":   "12h",
		}
		data, _ := json.MarshalIndent(cfg, "", "  ")
		setupConfigTestWithData(t, data)

		var stdout, stderr bytes.Buffer
		code := runCommandWithWriters([]string{"config", "allowed-root", "list"}, &stdout, &stderr)
		if code != 0 {
			t.Errorf("expected exit 0, got %d, stderr: %s", code, stderr.String())
		}
		if !strings.Contains(stdout.String(), allowedRoot) {
			t.Errorf("expected %s in output, got: %s", allowedRoot, stdout.String())
		}
	})

	t.Run("add_reaches_implementation", func(t *testing.T) {
		allowedRoot := testAllowedRootDir(t)
		cfg := map[string]any{
			"allowed_roots": []string{allowedRoot},
			"session_ttl":   "12h",
		}
		data, _ := json.MarshalIndent(cfg, "", "  ")
		configPath := setupConfigTestWithData(t, data)

		newRoot := testAllowedRootDir(t)
		var stdout, stderr bytes.Buffer
		code := runCommandWithWriters([]string{"config", "allowed-root", "add", newRoot}, &stdout, &stderr)
		if code != 0 {
			t.Errorf("expected exit 0, got %d, stderr: %s", code, stderr.String())
		}
		if !strings.Contains(stdout.String(), "added") {
			t.Errorf("expected 'added' in output, got: %s", stdout.String())
		}
		// Verify config was updated.
		raw := readConfigJSON(t, configPath)
		var roots []string
		if err := json.Unmarshal(raw["allowed_roots"], &roots); err != nil {
			t.Fatalf("cannot parse allowed_roots: %v", err)
		}
		if !slices.Contains(roots, newRoot) {
			t.Errorf("expected %s in allowed_roots, got: %v", newRoot, roots)
		}
	})

	t.Run("remove_reaches_implementation", func(t *testing.T) {
		allowedRoot := testAllowedRootDir(t)
		extraRoot := testAllowedRootDir(t)
		cfg := map[string]any{
			"allowed_roots": []string{allowedRoot, extraRoot},
			"session_ttl":   "12h",
		}
		data, _ := json.MarshalIndent(cfg, "", "  ")
		configPath := setupConfigTestWithData(t, data)

		var stdout, stderr bytes.Buffer
		code := runCommandWithWriters([]string{"config", "allowed-root", "remove", extraRoot}, &stdout, &stderr)
		if code != 0 {
			t.Errorf("expected exit 0, got %d, stderr: %s", code, stderr.String())
		}
		if !strings.Contains(stdout.String(), "removed") {
			t.Errorf("expected 'removed' in output, got: %s", stdout.String())
		}
		// Verify config was updated.
		raw := readConfigJSON(t, configPath)
		var roots []string
		if err := json.Unmarshal(raw["allowed_roots"], &roots); err != nil {
			t.Fatalf("cannot parse allowed_roots: %v", err)
		}
		if len(roots) != 1 || roots[0] != allowedRoot {
			t.Errorf("expected [%s], got: %v", allowedRoot, roots)
		}
	})
}
