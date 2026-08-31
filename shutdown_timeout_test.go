package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// setupShutdownTimeoutConfig writes a minimal user-mode config with an optional
// shutdown_timeout value ("" omits the key) and isolates the daemon load seams.
func setupShutdownTimeoutConfig(t *testing.T, shutdownTimeout string) {
	t.Helper()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")

	cfg := map[string]any{
		"allowed_root": testAllowedRootDir(t),
		"session_ttl":  "12h",
		"log_level":    "info",
	}
	if shutdownTimeout != "" {
		cfg["shutdown_timeout"] = shutdownTimeout
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
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config"))

	// Prevent reaching a real system daemon.
	origSocket := systemSocketExists
	systemSocketExists = func() bool { return false }
	t.Cleanup(func() { systemSocketExists = origSocket })
}

// TestShutdownTimeoutLegacyUpgradeBoundedAtLoad proves Release 1 (v1.0.2)
// configs with shutdown_timeout above the Release 2 maximum still load and the
// runtime value is bounded to the maximum, with an operational warning. It
// guards the upgrade-compatibility contract: an existing valid Release 1
// config (e.g. "60s") must not make the daemon fail startup.
func TestShutdownTimeoutLegacyUpgradeBoundedAtLoad(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		effective time.Duration
		warn      bool
	}{
		{name: "absent defaults to maximum", value: "", effective: 30 * time.Second, warn: false},
		{name: "within maximum unchanged", value: "20s", effective: 20 * time.Second, warn: false},
		{name: "at maximum unchanged", value: "30s", effective: 30 * time.Second, warn: false},
		{name: "legacy above maximum bounded", value: "60s", effective: 30 * time.Second, warn: true},
		{name: "legacy far above maximum bounded", value: "1h", effective: 30 * time.Second, warn: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setupShutdownTimeoutConfig(t, tt.value)

			opBuf := &bytes.Buffer{}
			initLoggers(opBuf, io.Discard, slog.LevelInfo, false)

			cfg, err := loadAndPrepareRuntimeConfig()
			if err != nil {
				t.Fatalf("config must load (upgrade compatibility): %v", err)
			}
			if cfg.ShutdownTimeout != tt.effective {
				t.Errorf("runtime shutdown_timeout = %s, want %s", cfg.ShutdownTimeout, tt.effective)
			}
			gotWarn := strings.Contains(opBuf.String(), "shutdown_timeout exceeds the maximum")
			if gotWarn != tt.warn {
				t.Errorf("warning emitted = %v, want %v; op log:\n%s", gotWarn, tt.warn, opBuf.String())
			}
		})
	}
}

// TestShutdownTimeoutConfigShowBoundsLegacy proves `config show` reports the
// effective bounded value, not the legacy oversized configured value.
func TestShutdownTimeoutConfigShowBoundsLegacy(t *testing.T) {
	tests := []struct {
		name       string
		configured string
		effective  string
	}{
		{name: "legacy above maximum shown bounded", configured: "60s", effective: "30s"},
		{name: "within maximum shown unchanged", configured: "20s", effective: "20s"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := `{
  "allowed_roots": ["/home/user/work"],
  "session_ttl": "12h",
  "shutdown_timeout": "` + tt.configured + `"
}`
			setupConfigTestWithData(t, []byte(cfg))

			stdout, _ := runConfigCLI(t, 0, "config", "show")
			var result map[string]any
			if err := json.Unmarshal([]byte(stdout), &result); err != nil {
				t.Fatalf("invalid JSON: %v", err)
			}
			if v, ok := result["shutdown_timeout"]; !ok || v != tt.effective {
				t.Errorf("config show shutdown_timeout = %v, want %q", v, tt.effective)
			}

			fieldOut, _ := runConfigCLI(t, 0, "config", "show", "shutdown_timeout")
			if strings.TrimSpace(fieldOut) != tt.effective {
				t.Errorf("config show shutdown_timeout = %q, want %q", strings.TrimSpace(fieldOut), tt.effective)
			}
		})
	}
}

// TestShutdownTimeoutLegacyAllowsOtherConfigSet proves a legacy oversized
// shutdown_timeout does not block other `config set` operations, and the
// operator can lower it to a valid value.
func TestShutdownTimeoutLegacyAllowsOtherConfigSet(t *testing.T) {
	cfg := `{
  "allowed_roots": ["/home/user/work"],
  "session_ttl": "12h",
  "shutdown_timeout": "60s"
}`
	configPath := setupConfigTestWithData(t, []byte(cfg))

	// Other fields remain settable while a legacy oversized value is present.
	runConfigCLI(t, 0, "config", "set", "log_level", "debug")
	raw := readConfigJSON(t, configPath)
	if got := string(raw["log_level"]); !strings.Contains(got, "debug") {
		t.Errorf("log_level after set = %q, want debug", got)
	}

	// The operator can lower shutdown_timeout to a value within the maximum.
	runConfigCLI(t, 0, "config", "set", "shutdown_timeout", "30s")
	raw = readConfigJSON(t, configPath)
	if got := string(raw["shutdown_timeout"]); !strings.Contains(got, "30s") {
		t.Errorf("shutdown_timeout after set = %q, want 30s", got)
	}
}
