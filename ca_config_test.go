package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCAInjectionDefaultDisabled(t *testing.T) {
	cfg := `{
  "allowed_root": "/tmp/work",
  "session_ttl": "12h"
}`
	_ = setupConfigTestWithData(t, []byte(cfg))
	t.Setenv("XDG_RUNTIME_DIR", "")

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "show", "trusted_ca_injection"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr: %s", code, stderr.String())
	}
	if stdout.String() != "disabled\n" {
		t.Errorf("expected 'disabled\\n', got %q", stdout.String())
	}
}

func TestCAConfigShowSetUnset(t *testing.T) {
	configPath, caPath, _, _ := setupCAConfigTest(t)

	cfg := map[string]any{
		"allowed_root":         "/tmp/work",
		"session_ttl":          "12h",
		"trusted_ca_path":      caPath,
		"trusted_ca_injection": "auto",
	}
	writeCAConfig(t, configPath, cfg)

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "show", "trusted_ca_path"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("show trusted_ca_path: expected 0, got %d, stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), caPath) {
		t.Errorf("expected CA path in output, got: %s", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "show", "trusted_ca_injection"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("show trusted_ca_injection: expected 0, got %d", code)
	}
	if stdout.String() != "auto\n" {
		t.Errorf("expected 'auto\\n', got %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "set", "trusted_ca_injection", "disabled"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("set disabled: expected 0, got %d, stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "updated") {
		t.Errorf("expected 'updated' in output, got: %s", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "unset", "trusted_ca_injection"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("unset: expected 0, got %d, stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "unset") {
		t.Errorf("expected 'unset' in output, got: %s", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "show", "trusted_ca_injection"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("show after unset: expected 0, got %d", code)
	}
	if stdout.String() != "disabled\n" {
		t.Errorf("expected 'disabled\\n' after unset, got %q", stdout.String())
	}
}

func TestCAConfigInvalidMode(t *testing.T) {
	cfg := `{
  "allowed_root": "/tmp/work",
  "session_ttl": "12h",
  "trusted_ca_injection": "invalid"
}`
	setupConfigTestWithData(t, []byte(cfg))
	t.Setenv("XDG_RUNTIME_DIR", "")

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "show"}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected non-zero exit code for invalid mode")
	}
	if !strings.Contains(stderr.String(), "trusted_ca_injection") {
		t.Errorf("expected error about trusted_ca_injection, got: %s", stderr.String())
	}
}

func TestCAConfigAutoWithoutPath(t *testing.T) {
	cfg := `{
  "allowed_root": "/tmp/work",
  "session_ttl": "12h",
  "trusted_ca_injection": "auto"
}`
	setupConfigTestWithData(t, []byte(cfg))
	t.Setenv("XDG_RUNTIME_DIR", "")

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "show"}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected non-zero exit code for auto without path")
	}
	if !strings.Contains(stderr.String(), "trusted_ca_path") {
		t.Errorf("expected error about trusted_ca_path, got: %s", stderr.String())
	}
}

func TestCAConfigRelativePath(t *testing.T) {
	cfg := `{
  "allowed_root": "/tmp/work",
  "session_ttl": "12h",
  "trusted_ca_path": "relative/path.crt",
  "trusted_ca_injection": "disabled"
}`
	setupConfigTestWithData(t, []byte(cfg))
	t.Setenv("XDG_RUNTIME_DIR", "")

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "show"}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected non-zero exit code for relative path")
	}
}

func TestCAConfigInvalidCA(t *testing.T) {
	tests := []struct {
		name    string
		caSetup func(t *testing.T) string // returns caPath
		errSub  string
	}{
		{
			name: "missing file",
			caSetup: func(t *testing.T) string {
				return "/nonexistent/ca.crt"
			},
			errSub: "cannot access trusted_ca_path",
		},
		{
			name: "directory instead of regular file",
			caSetup: func(t *testing.T) string {
				d := t.TempDir()
				return d
			},
			errSub: "trusted_ca_path must be a regular file",
		},
		{
			name: "malformed PEM",
			caSetup: func(t *testing.T) string {
				caPath := filepath.Join(t.TempDir(), "malformed.crt")
				if err := os.WriteFile(caPath, []byte("not valid PEM data"), 0644); err != nil {
					t.Fatal(err)
				}
				return caPath
			},
			errSub: "does not contain valid PEM",
		},
		{
			name: "two certificates",
			caSetup: func(t *testing.T) string {
				dir := t.TempDir()
				ca1 := filepath.Join(dir, "ca1.pem")
				ca2 := filepath.Join(dir, "ca2.pem")
				generateTestCAPEM(t, ca1)
				generateTestCAPEM(t, ca2)
				data1, err := os.ReadFile(ca1)
				if err != nil {
					t.Fatal(err)
				}
				data2, err := os.ReadFile(ca2)
				if err != nil {
					t.Fatal(err)
				}
				caPath := filepath.Join(dir, "multi-ca.crt")
				if err := os.WriteFile(caPath, append(data1, data2...), 0644); err != nil {
					t.Fatal(err)
				}
				return caPath
			},
			errSub: "extra content after certificate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			configPath := filepath.Join(dir, "config.json")
			runtimeDir := filepath.Join(dir, "runtime")

			caPath := tt.caSetup(t)

			writeCAConfig(t, configPath, map[string]any{
				"allowed_root":         "/tmp/work",
				"session_ttl":          "12h",
				"trusted_ca_path":      caPath,
				"trusted_ca_injection": "auto",
			})

			t.Setenv("DOCKER_HELPER_CONFIG", configPath)
			t.Setenv("XDG_RUNTIME_DIR", runtimeDir)
			t.Setenv("XDG_STATE_HOME", "")

			_, err := loadConfig()
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.errSub) {
				t.Fatalf("expected error containing %q, got: %v", tt.errSub, err)
			}
		})
	}
}

func TestCAConfigAutoEmptyPath(t *testing.T) {
	cfg := `{
  "allowed_root": "/tmp/work",
  "session_ttl": "12h",
  "trusted_ca_path": "",
  "trusted_ca_injection": "auto"
}`
	setupConfigTestWithData(t, []byte(cfg))
	t.Setenv("XDG_RUNTIME_DIR", "")

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "show"}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected non-zero exit code for auto with empty path")
	}
}

func TestCAConfigSetValidation(t *testing.T) {
	configPath, caPath, _, _ := setupCAConfigTest(t)

	writeCAConfig(t, configPath, map[string]any{
		"allowed_root": "/tmp/work",
		"session_ttl":  "12h",
	})

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "trusted_ca_path", "relative/path"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit code 2 for relative path, got %d", code)
	}

	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "set", "trusted_ca_injection", "invalid"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit code 2 for invalid mode, got %d", code)
	}

	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "set", "trusted_ca_path", caPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr: %s", code, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "set", "trusted_ca_injection", "auto"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr: %s", code, stderr.String())
	}
}

func TestCAUnsetPathWhenAutoActive(t *testing.T) {
	configPath, caPath, _, _ := setupCAConfigTest(t)

	writeCAConfig(t, configPath, map[string]any{
		"allowed_root":         "/tmp/work",
		"session_ttl":          "12h",
		"trusted_ca_path":      caPath,
		"trusted_ca_injection": "auto",
	})

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "unset", "trusted_ca_path"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1 for unset path when auto, got %d, stderr: %s", code, stderr.String())
	}
}

func TestCAInitNoInjectionDefault(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	t.Setenv("DOCKER_HELPER_CONFIG", configPath)
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(dir, "runtime"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))

	allowedRoot := filepath.Join(dir, "workspaces")
	if err := os.MkdirAll(allowedRoot, 0755); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"init", "--allowed-root", allowedRoot}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("init exited %d, stderr: %s", code, stderr.String())
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(string(data), "trusted_ca") {
		t.Error("init should not include trusted_ca fields by default")
	}
}

func TestCAConfigShowAllIncludesNewFields(t *testing.T) {
	configPath, caPath, _, _ := setupCAConfigTest(t)

	writeCAConfig(t, configPath, map[string]any{
		"allowed_root":         "/tmp/work",
		"session_ttl":          "12h",
		"trusted_ca_path":      caPath,
		"trusted_ca_injection": "auto",
	})

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "show"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr: %s", code, stderr.String())
	}

	var result map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if result["trusted_ca_path"] != caPath {
		t.Errorf("trusted_ca_path = %v, want %s", result["trusted_ca_path"], caPath)
	}
	if result["trusted_ca_injection"] != "auto" {
		t.Errorf("trusted_ca_injection = %v, want auto", result["trusted_ca_injection"])
	}
}

func TestCAConfigShowDefaults(t *testing.T) {
	cfg := `{
  "allowed_root": "/tmp/work",
  "session_ttl": "12h"
}`
	setupConfigTestWithData(t, []byte(cfg))
	t.Setenv("XDG_RUNTIME_DIR", "")

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "show"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr: %s", code, stderr.String())
	}

	var result map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if result["trusted_ca_injection"] != "disabled" {
		t.Errorf("trusted_ca_injection = %v, want disabled", result["trusted_ca_injection"])
	}
	if result["trusted_ca_path"] != "" {
		t.Errorf("trusted_ca_path = %v, want empty", result["trusted_ca_path"])
	}
}
