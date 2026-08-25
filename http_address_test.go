package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- Config field tests ---

func TestHTTPAddressDefaultSystem(t *testing.T) {
	orig := EffectiveUID
	defer func() { EffectiveUID = orig }()
	EffectiveUID = func() int { return 0 }

	got := resolveHTTPAddress("")
	if got != DefaultHTTPAddress {
		t.Errorf("resolveHTTPAddress(\"\") = %q, want %q", got, DefaultHTTPAddress)
	}
}

func TestHTTPAddressCustomSystem(t *testing.T) {
	// Validate custom http_address by loading config in user mode.
	// Config decoding and validation are mode-independent;
	// only TCP listener creation depends on mode.
	orig := EffectiveUID
	defer func() { EffectiveUID = orig }()
	EffectiveUID = func() int { return 1000 }

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	data := map[string]any{
		"allowed_root": testAllowedRootDir(t),
		"session_ttl":  "1h",
		"http_address": "127.0.0.1:54321",
	}
	writeConfig(t, configPath, data)

	t.Setenv("DOCKER_HELPER_CONFIG", configPath)
	t.Setenv("XDG_RUNTIME_DIR", dir)

	cfg, err := loadAndPrepareRuntimeConfig()
	if err != nil {
		t.Fatalf("loadAndPrepareRuntimeConfig: %v", err)
	}
	if cfg.HTTPAddress != "127.0.0.1:54321" {
		t.Errorf("HTTPAddress = %q, want %q", cfg.HTTPAddress, "127.0.0.1:54321")
	}
}

func TestHTTPAddressUserModeEmpty(t *testing.T) {
	orig := EffectiveUID
	defer func() { EffectiveUID = orig }()
	EffectiveUID = func() int { return 1000 }

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	data := map[string]any{
		"allowed_root": testAllowedRootDir(t),
		"session_ttl":  "1h",
	}
	writeConfig(t, configPath, data)

	t.Setenv("DOCKER_HELPER_CONFIG", configPath)
	t.Setenv("XDG_RUNTIME_DIR", dir)

	cfg, err := loadAndPrepareRuntimeConfig()
	if err != nil {
		t.Fatalf("loadAndPrepareRuntimeConfig: %v", err)
	}
	// In user mode, HTTPAddress is still set to the default value
	// (it's just not used for TCP listener creation).
	if cfg.HTTPAddress != DefaultHTTPAddress {
		t.Errorf("HTTPAddress = %q, want %q", cfg.HTTPAddress, DefaultHTTPAddress)
	}
}

// --- Validation tests ---

func TestValidateHTTPAddressValid(t *testing.T) {
	valid := []string{
		"127.0.0.1:80",
		"127.0.0.1:1",
		"127.0.0.1:65535",
		"127.0.0.1:52375",
	}
	for _, addr := range valid {
		if err := validateHTTPAddress(addr); err != nil {
			t.Errorf("validateHTTPAddress(%q) = %v, want nil", addr, err)
		}
	}
}

func TestValidateHTTPAddressInvalid(t *testing.T) {
	invalid := []struct {
		addr string
		why  string
	}{
		{"0.0.0.0:8080", "0.0.0.0"},
		{"localhost:8080", "hostname"},
		{"192.168.1.1:8080", "external IP"},
		{"[::1]:8080", "IPv6"},
		{"127.0.0.1:0", "port 0"},
		{"127.0.0.1:65536", "port > 65535"},
		{"127.0.0.1:99999", "port > 65535"},
		{"127.0.0.1:abc", "non-numeric port"},
		{"127.0.0.1", "missing port"},
		{"http://127.0.0.1:8080", "scheme"},
		{"", "empty"},
	}
	for _, tc := range invalid {
		if err := validateHTTPAddress(tc.addr); err == nil {
			t.Errorf("validateHTTPAddress(%q) = nil, want error (%s)", tc.addr, tc.why)
		}
	}
}

// --- Hand-edited invalid config rejected ---

func TestLoadAndPrepareRuntimeConfigRejectsInvalidHTTPAddress(t *testing.T) {
	orig := EffectiveUID
	defer func() { EffectiveUID = orig }()
	EffectiveUID = func() int { return 0 }

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	data := map[string]any{
		"allowed_root": testAllowedRootDir(t),
		"session_ttl":  "1h",
		"http_address": "0.0.0.0:8080",
	}
	writeConfig(t, configPath, data)

	t.Setenv("DOCKER_HELPER_CONFIG", configPath)
	t.Setenv("XDG_RUNTIME_DIR", dir)

	_, err := loadAndPrepareRuntimeConfig()
	if err == nil {
		t.Fatal("expected error for invalid http_address")
	}
	if !strings.Contains(err.Error(), "127.0.0.1") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLoadAndPrepareRuntimeConfigRejectsInvalidPort(t *testing.T) {
	orig := EffectiveUID
	defer func() { EffectiveUID = orig }()
	EffectiveUID = func() int { return 0 }

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	data := map[string]any{
		"allowed_root": testAllowedRootDir(t),
		"session_ttl":  "1h",
		"http_address": "127.0.0.1:99999",
	}
	writeConfig(t, configPath, data)

	t.Setenv("DOCKER_HELPER_CONFIG", configPath)
	t.Setenv("XDG_RUNTIME_DIR", dir)

	_, err := loadAndPrepareRuntimeConfig()
	if err == nil {
		t.Fatal("expected error for invalid port")
	}
}

// --- config set tests ---

func TestConfigSetHTTPAddressSystem(t *testing.T) {
	orig := EffectiveUID
	defer func() { EffectiveUID = orig }()
	EffectiveUID = func() int { return 0 }

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	data := map[string]any{
		"allowed_root": testAllowedRootDir(t),
		"session_ttl":  "1h",
	}
	writeConfig(t, configPath, data)

	t.Setenv("DOCKER_HELPER_CONFIG", configPath)
	t.Setenv("XDG_RUNTIME_DIR", dir)

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "http_address", "127.0.0.1:54321"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("config set exited %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "updated") {
		t.Errorf("expected 'updated' in output: %s", stdout.String())
	}

	// Verify the value was written.
	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var cfg map[string]any
	json.Unmarshal(raw, &cfg)
	if cfg["http_address"] != "127.0.0.1:54321" {
		t.Errorf("http_address = %v, want 127.0.0.1:54321", cfg["http_address"])
	}
}

func TestConfigSetHTTPAddressUserModeRejected(t *testing.T) {
	orig := EffectiveUID
	defer func() { EffectiveUID = orig }()
	EffectiveUID = func() int { return 1000 }

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	data := map[string]any{
		"allowed_root": testAllowedRootDir(t),
		"session_ttl":  "1h",
	}
	writeConfig(t, configPath, data)

	t.Setenv("DOCKER_HELPER_CONFIG", configPath)
	t.Setenv("XDG_RUNTIME_DIR", dir)

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "http_address", "127.0.0.1:54321"}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected error for user mode config set http_address")
	}
	if !strings.Contains(stderr.String(), "system mode") {
		t.Errorf("expected 'system mode' in error: %s", stderr.String())
	}
}

func TestConfigSetHTTPAddressInvalidHost(t *testing.T) {
	orig := EffectiveUID
	defer func() { EffectiveUID = orig }()
	EffectiveUID = func() int { return 0 }

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	data := map[string]any{
		"allowed_root": testAllowedRootDir(t),
		"session_ttl":  "1h",
	}
	writeConfig(t, configPath, data)

	t.Setenv("DOCKER_HELPER_CONFIG", configPath)
	t.Setenv("XDG_RUNTIME_DIR", dir)

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "http_address", "0.0.0.0:8080"}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected error for invalid host")
	}
}

func TestConfigSetHTTPAddressInvalidPort(t *testing.T) {
	orig := EffectiveUID
	defer func() { EffectiveUID = orig }()
	EffectiveUID = func() int { return 0 }

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	data := map[string]any{
		"allowed_root": testAllowedRootDir(t),
		"session_ttl":  "1h",
	}
	writeConfig(t, configPath, data)

	t.Setenv("DOCKER_HELPER_CONFIG", configPath)
	t.Setenv("XDG_RUNTIME_DIR", dir)

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "http_address", "127.0.0.1:0"}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected error for port 0")
	}
}

// --- config unset tests ---

func TestConfigUnsetHTTPAddress(t *testing.T) {
	orig := EffectiveUID
	defer func() { EffectiveUID = orig }()
	EffectiveUID = func() int { return 0 }

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	data := map[string]any{
		"allowed_root": testAllowedRootDir(t),
		"session_ttl":  "1h",
		"http_address": "127.0.0.1:54321",
	}
	writeConfig(t, configPath, data)

	t.Setenv("DOCKER_HELPER_CONFIG", configPath)
	t.Setenv("XDG_RUNTIME_DIR", dir)

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "unset", "http_address"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("config unset exited %d: %s", code, stderr.String())
	}
	if strings.Contains(stdout.String(), "updated") {
		t.Error("must not print 'updated' on unset")
	}
	if !strings.Contains(stdout.String(), "unset http_address") {
		t.Errorf("expected 'unset http_address' in stdout, got: %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "restart required") {
		t.Errorf("expected 'restart required' in stdout, got: %s", stdout.String())
	}

	// Verify the value was removed.
	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var cfg map[string]any
	json.Unmarshal(raw, &cfg)
	if _, ok := cfg["http_address"]; ok {
		t.Error("http_address should be removed after unset")
	}

	// After unset, effective value should be default.
	var stdout2 bytes.Buffer
	code = runCommandWithWriters([]string{"config", "show", "http_address"}, &stdout2, &stderr)
	if code != 0 {
		t.Fatalf("config show exited %d: %s", code, stderr.String())
	}
	if strings.TrimSpace(stdout2.String()) != DefaultHTTPAddress {
		t.Errorf("http_address = %q, want %q", stdout2.String(), DefaultHTTPAddress)
	}
}

// --- config show tests ---

func TestConfigShowHTTPAddressDefault(t *testing.T) {
	orig := EffectiveUID
	defer func() { EffectiveUID = orig }()
	EffectiveUID = func() int { return 0 }

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	data := map[string]any{
		"allowed_root": testAllowedRootDir(t),
		"session_ttl":  "1h",
	}
	writeConfig(t, configPath, data)

	t.Setenv("DOCKER_HELPER_CONFIG", configPath)
	t.Setenv("XDG_RUNTIME_DIR", dir)

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "show", "http_address"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("config show exited %d: %s", code, stderr.String())
	}
	if strings.TrimSpace(stdout.String()) != DefaultHTTPAddress {
		t.Errorf("http_address = %q, want %q", stdout.String(), DefaultHTTPAddress)
	}
}

func TestConfigShowHTTPAddressCustom(t *testing.T) {
	orig := EffectiveUID
	defer func() { EffectiveUID = orig }()
	EffectiveUID = func() int { return 0 }

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	data := map[string]any{
		"allowed_root": testAllowedRootDir(t),
		"session_ttl":  "1h",
		"http_address": "127.0.0.1:54321",
	}
	writeConfig(t, configPath, data)

	t.Setenv("DOCKER_HELPER_CONFIG", configPath)
	t.Setenv("XDG_RUNTIME_DIR", dir)

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "show", "http_address"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("config show exited %d: %s", code, stderr.String())
	}
	if strings.TrimSpace(stdout.String()) != "127.0.0.1:54321" {
		t.Errorf("http_address = %q, want %q", stdout.String(), "127.0.0.1:54321")
	}
}

func TestConfigShowHTTPAddressUserModeEmpty(t *testing.T) {
	orig := EffectiveUID
	defer func() { EffectiveUID = orig }()
	EffectiveUID = func() int { return 1000 }

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	data := map[string]any{
		"allowed_root": testAllowedRootDir(t),
		"session_ttl":  "1h",
	}
	writeConfig(t, configPath, data)

	t.Setenv("DOCKER_HELPER_CONFIG", configPath)
	t.Setenv("XDG_RUNTIME_DIR", dir)

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "show", "http_address"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("config show exited %d: %s", code, stderr.String())
	}
	if strings.TrimSpace(stdout.String()) != "" {
		t.Errorf("http_address = %q, want empty", stdout.String())
	}
}

// --- Listener tests ---

func TestPrepareListenersSystemCustomAddress(t *testing.T) {
	orig := EffectiveUID
	defer func() { EffectiveUID = orig }()
	EffectiveUID = func() int { return 0 }

	dir := t.TempDir()
	socketPath := filepath.Join(dir, "test.sock")
	defer os.Remove(socketPath)

	unixListener, tcpListener, err := prepareListeners(ModeSystem, socketPath, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("prepareListeners: %v", err)
	}
	defer cleanupListeners(unixListener, tcpListener, socketPath)

	if unixListener == nil {
		t.Fatal("unixListener should not be nil")
	}
	if tcpListener == nil {
		t.Fatal("tcpListener should not be nil in system mode")
	}

	// Verify TCP listener is on 127.0.0.1.
	tcpAddr := tcpListener.Addr().String()
	if !strings.HasPrefix(tcpAddr, "127.0.0.1:") {
		t.Errorf("TCP address = %q, should start with 127.0.0.1:", tcpAddr)
	}
}

func TestPrepareListenersUserModeNoTCP(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "test.sock")
	defer os.Remove(socketPath)

	unixListener, tcpListener, err := prepareListeners(ModeUser, socketPath, DefaultHTTPAddress)
	if err != nil {
		t.Fatalf("prepareListeners: %v", err)
	}
	defer cleanupListeners(unixListener, tcpListener, socketPath)

	if unixListener == nil {
		t.Fatal("unixListener should not be nil")
	}
	if tcpListener != nil {
		t.Fatal("tcpListener should be nil in user mode")
	}
}

// --- resolveHTTPAddress tests ---

func TestResolveHTTPAddressConfigured(t *testing.T) {
	got := resolveHTTPAddress("127.0.0.1:54321")
	if got != "127.0.0.1:54321" {
		t.Errorf("resolveHTTPAddress = %q, want %q", got, "127.0.0.1:54321")
	}
}

func TestResolveHTTPAddressDefaultSystem(t *testing.T) {
	orig := EffectiveUID
	defer func() { EffectiveUID = orig }()
	EffectiveUID = func() int { return 0 }

	got := resolveHTTPAddress("")
	if got != DefaultHTTPAddress {
		t.Errorf("resolveHTTPAddress = %q, want %q", got, DefaultHTTPAddress)
	}
}

func TestResolveHTTPAddressDefaultUser(t *testing.T) {
	orig := EffectiveUID
	defer func() { EffectiveUID = orig }()
	EffectiveUID = func() int { return 1000 }

	got := resolveHTTPAddress("")
	if got != "" {
		t.Errorf("resolveHTTPAddress = %q, want empty", got)
	}
}

// --- helper ---

func writeConfig(t *testing.T, path string, data any) {
	t.Helper()
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}
