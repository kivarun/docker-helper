package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- detectLSM matrix ---

func TestDetectLSMMatrix(t *testing.T) {
	tests := []struct {
		name             string
		apparmorActive   bool
		apparmorErr      error
		selinuxActive    bool
		selinuxEnforcing bool
		selinuxErr       error
		wantBackend      LSMBackend
		wantErr          bool
		errContains      string
	}{
		{
			name:           "AppArmor only",
			apparmorActive: true,
			selinuxActive:  false,
			wantBackend:    LSMAppArmor,
			wantErr:        false,
		},
		{
			name:             "SELinux enforcing only",
			apparmorActive:   false,
			selinuxActive:    true,
			selinuxEnforcing: true,
			wantBackend:      LSMSelinux,
			wantErr:          false,
		},
		{
			name:           "neither active",
			apparmorActive: false,
			selinuxActive:  false,
			wantBackend:    LSMNone,
			wantErr:        false,
		},
		{
			name:             "SELinux permissive only",
			apparmorActive:   false,
			selinuxActive:    true,
			selinuxEnforcing: false,
			wantBackend:      LSMNone,
			wantErr:          true,
			errContains:      "permissive",
		},
		{
			name:             "both AppArmor and enforcing SELinux",
			apparmorActive:   true,
			selinuxActive:    true,
			selinuxEnforcing: true,
			wantBackend:      LSMNone,
			wantErr:          true,
			errContains:      "both",
		},
		{
			name:           "AppArmor detection error",
			apparmorActive: false,
			apparmorErr:    os.ErrNotExist,
			selinuxActive:  false,
			wantBackend:    LSMNone,
			wantErr:        true,
			errContains:    "cannot determine AppArmor",
		},
		{
			name:           "SELinux detection error",
			apparmorActive: false,
			selinuxActive:  false,
			selinuxErr:     os.ErrPermission,
			wantBackend:    LSMNone,
			wantErr:        true,
			errContains:    "cannot determine SELinux",
		},
		{
			name:             "AppArmor active with SELinux permissive",
			apparmorActive:   true,
			selinuxActive:    true,
			selinuxEnforcing: false,
			wantBackend:      LSMAppArmor,
			wantErr:          false,
		},
		{
			name:             "AppArmor inactive with SELinux permissive",
			apparmorActive:   false,
			selinuxActive:    true,
			selinuxEnforcing: false,
			wantBackend:      LSMNone,
			wantErr:          true,
			errContains:      "permissive",
		},
	}

	origAA := apparmorLSMActive
	origSEL := selinuxEnabled
	defer func() {
		apparmorLSMActive = origAA
		selinuxEnabled = origSEL
	}()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			apparmorLSMActive = func() (bool, error) {
				return tc.apparmorActive, tc.apparmorErr
			}
			selinuxEnabled = func() (bool, bool, error) {
				return tc.selinuxActive, tc.selinuxEnforcing, tc.selinuxErr
			}

			got, err := detectLSM()
			if got != tc.wantBackend {
				t.Errorf("backend: got %q, want %q", got, tc.wantBackend)
			}
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tc.errContains != "" && !strings.Contains(err.Error(), tc.errContains) {
					t.Errorf("error %q does not contain %q", err.Error(), tc.errContains)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// --- requireMACBackend ---

func TestRequireMACBackendAppArmor(t *testing.T) {
	origAA := apparmorLSMActive
	origSEL := selinuxEnabled
	apparmorLSMActive = func() (bool, error) { return true, nil }
	selinuxEnabled = func() (bool, bool, error) { return false, false, nil }
	defer func() {
		apparmorLSMActive = origAA
		selinuxEnabled = origSEL
	}()

	if err := requireMACBackend(); err != nil {
		t.Fatalf("expected nil, got: %v", err)
	}
}

func TestRequireMACBackendSELinux(t *testing.T) {
	origAA := apparmorLSMActive
	origSEL := selinuxEnabled
	apparmorLSMActive = func() (bool, error) { return false, nil }
	selinuxEnabled = func() (bool, bool, error) { return true, true, nil }
	defer func() {
		apparmorLSMActive = origAA
		selinuxEnabled = origSEL
	}()

	if err := requireMACBackend(); err != nil {
		t.Fatalf("expected nil, got: %v", err)
	}
}

func TestRequireMACBackendNone(t *testing.T) {
	origAA := apparmorLSMActive
	origSEL := selinuxEnabled
	apparmorLSMActive = func() (bool, error) { return false, nil }
	selinuxEnabled = func() (bool, bool, error) { return false, false, nil }
	defer func() {
		apparmorLSMActive = origAA
		selinuxEnabled = origSEL
	}()

	err := requireMACBackend()
	if err == nil {
		t.Fatal("expected error when no backend is active")
	}
	if !strings.Contains(err.Error(), "no MAC backend active") {
		t.Errorf("expected 'no MAC backend active' in error, got: %v", err)
	}
}

func TestRequireMACBackendBoth(t *testing.T) {
	origAA := apparmorLSMActive
	origSEL := selinuxEnabled
	apparmorLSMActive = func() (bool, error) { return true, nil }
	selinuxEnabled = func() (bool, bool, error) { return true, true, nil }
	defer func() {
		apparmorLSMActive = origAA
		selinuxEnabled = origSEL
	}()

	err := requireMACBackend()
	if err == nil {
		t.Fatal("expected error when both backends are active")
	}
	if !strings.Contains(err.Error(), "both") {
		t.Errorf("expected 'both' in error, got: %v", err)
	}
}

func TestRequireMACBackendPermissive(t *testing.T) {
	origAA := apparmorLSMActive
	origSEL := selinuxEnabled
	apparmorLSMActive = func() (bool, error) { return false, nil }
	selinuxEnabled = func() (bool, bool, error) { return true, false, nil }
	defer func() {
		apparmorLSMActive = origAA
		selinuxEnabled = origSEL
	}()

	err := requireMACBackend()
	if err == nil {
		t.Fatal("expected error when SELinux is permissive")
	}
	if !strings.Contains(err.Error(), "permissive") {
		t.Errorf("expected 'permissive' in error, got: %v", err)
	}
}

// --- requireMACConfinement ---

func TestRequireMACConfinementAppArmorEnforce(t *testing.T) {
	origAA := apparmorLSMActive
	origAAConf := apparmorProcessConfinement
	origSEL := selinuxEnabled
	apparmorLSMActive = func() (bool, error) { return true, nil }
	apparmorProcessConfinement = func() (string, error) {
		return "docker-helper-system (enforce)", nil
	}
	selinuxEnabled = func() (bool, bool, error) { return false, false, nil }
	defer func() {
		apparmorLSMActive = origAA
		apparmorProcessConfinement = origAAConf
		selinuxEnabled = origSEL
	}()

	if err := requireMACConfinement(); err != nil {
		t.Fatalf("expected nil for AppArmor enforce, got: %v", err)
	}
}

func TestRequireMACConfinementAppArmorUnconfined(t *testing.T) {
	origAA := apparmorLSMActive
	origAAConf := apparmorProcessConfinement
	origSEL := selinuxEnabled
	apparmorLSMActive = func() (bool, error) { return true, nil }
	apparmorProcessConfinement = func() (string, error) { return "unconfined", nil }
	selinuxEnabled = func() (bool, bool, error) { return false, false, nil }
	defer func() {
		apparmorLSMActive = origAA
		apparmorProcessConfinement = origAAConf
		selinuxEnabled = origSEL
	}()

	err := requireMACConfinement()
	if err == nil {
		t.Fatal("expected error when AppArmor unconfined")
	}
	if !strings.Contains(err.Error(), "not confined") {
		t.Errorf("expected 'not confined' in error, got: %v", err)
	}
}

func TestRequireMACConfinementSELinuxCorrect(t *testing.T) {
	origAA := apparmorLSMActive
	origSEL := selinuxEnabled
	origSELType := selinuxProcessType
	apparmorLSMActive = func() (bool, error) { return false, nil }
	selinuxEnabled = func() (bool, bool, error) { return true, true, nil }
	selinuxProcessType = func() (string, error) {
		return "system_u:system_r:docker_helper_t:s0", nil
	}
	defer func() {
		apparmorLSMActive = origAA
		selinuxEnabled = origSEL
		selinuxProcessType = origSELType
	}()

	if err := requireMACConfinement(); err != nil {
		t.Fatalf("expected nil for correct SELinux type, got: %v", err)
	}
}

func TestRequireMACConfinementSELinuxWrongType(t *testing.T) {
	origAA := apparmorLSMActive
	origSEL := selinuxEnabled
	origSELType := selinuxProcessType
	apparmorLSMActive = func() (bool, error) { return false, nil }
	selinuxEnabled = func() (bool, bool, error) { return true, true, nil }
	selinuxProcessType = func() (string, error) {
		return "system_u:system_r:unconfined_t:s0", nil
	}
	defer func() {
		apparmorLSMActive = origAA
		selinuxEnabled = origSEL
		selinuxProcessType = origSELType
	}()

	err := requireMACConfinement()
	if err == nil {
		t.Fatal("expected error for wrong SELinux type")
	}
	if !strings.Contains(err.Error(), "not confined") {
		t.Errorf("expected 'not confined' in error, got: %v", err)
	}
}

func TestRequireMACConfinementSELinuxNotEnforcing(t *testing.T) {
	origAA := apparmorLSMActive
	origSEL := selinuxEnabled
	origSELType := selinuxProcessType
	apparmorLSMActive = func() (bool, error) { return false, nil }
	selinuxEnabled = func() (bool, bool, error) { return true, true, nil }
	selinuxProcessType = func() (string, error) {
		t.Fatal("process type should not be read when SELinux is permissive at detectLSM level")
		return "", nil
	}
	defer func() {
		apparmorLSMActive = origAA
		selinuxEnabled = origSEL
		selinuxProcessType = origSELType
	}()

	// At detectLSM level, permissive SELinux fails before confinement check.
	selinuxEnabled = func() (bool, bool, error) { return true, false, nil }
	err := requireMACConfinement()
	if err == nil {
		t.Fatal("expected error when SELinux is permissive")
	}
}

func TestRequireMACConfinementNone(t *testing.T) {
	origAA := apparmorLSMActive
	origSEL := selinuxEnabled
	apparmorLSMActive = func() (bool, error) { return false, nil }
	selinuxEnabled = func() (bool, bool, error) { return false, false, nil }
	defer func() {
		apparmorLSMActive = origAA
		selinuxEnabled = origSEL
	}()

	err := requireMACConfinement()
	if err == nil {
		t.Fatal("expected error when no backend is active")
	}
	if !strings.Contains(err.Error(), "no MAC backend active") {
		t.Errorf("expected 'no MAC backend active' in error, got: %v", err)
	}
}

func TestRequireMACConfinementBoth(t *testing.T) {
	origAA := apparmorLSMActive
	origSEL := selinuxEnabled
	apparmorLSMActive = func() (bool, error) { return true, nil }
	selinuxEnabled = func() (bool, bool, error) { return true, true, nil }
	defer func() {
		apparmorLSMActive = origAA
		selinuxEnabled = origSEL
	}()

	err := requireMACConfinement()
	if err == nil {
		t.Fatal("expected error when both backends are active")
	}
	if !strings.Contains(err.Error(), "both") {
		t.Errorf("expected 'both' in error, got: %v", err)
	}
}

// --- requireSELinuxConfinement (direct) ---

func TestRequireSELinuxConfinementNotEnabled(t *testing.T) {
	origSEL := selinuxEnabled
	selinuxEnabled = func() (bool, bool, error) { return false, false, nil }
	defer func() { selinuxEnabled = origSEL }()

	err := requireSELinuxConfinement()
	if err == nil {
		t.Fatal("expected error when SELinux is not enabled")
	}
	if !strings.Contains(err.Error(), "not enabled") {
		t.Errorf("expected 'not enabled' in error, got: %v", err)
	}
}

func TestRequireSELinuxConfinementNotEnforcing(t *testing.T) {
	origSEL := selinuxEnabled
	selinuxEnabled = func() (bool, bool, error) { return true, false, nil }
	defer func() { selinuxEnabled = origSEL }()

	err := requireSELinuxConfinement()
	if err == nil {
		t.Fatal("expected error when SELinux is not enforcing")
	}
	if !strings.Contains(err.Error(), "enforcing") {
		t.Errorf("expected 'enforcing' in error, got: %v", err)
	}
}

func TestRequireSELinuxConfinementReadError(t *testing.T) {
	origSEL := selinuxEnabled
	selinuxEnabled = func() (bool, bool, error) {
		return false, false, os.ErrPermission
	}
	defer func() { selinuxEnabled = origSEL }()

	err := requireSELinuxConfinement()
	if err == nil {
		t.Fatal("expected error on read failure")
	}
	if !strings.Contains(err.Error(), "cannot determine SELinux") {
		t.Errorf("expected 'cannot determine SELinux' in error, got: %v", err)
	}
}

func TestRequireSELinuxConfinementProcessTypeReadError(t *testing.T) {
	origSEL := selinuxEnabled
	origType := selinuxProcessType
	selinuxEnabled = func() (bool, bool, error) { return true, true, nil }
	selinuxProcessType = func() (string, error) {
		return "", os.ErrNotExist
	}
	defer func() {
		selinuxEnabled = origSEL
		selinuxProcessType = origType
	}()

	err := requireSELinuxConfinement()
	if err == nil {
		t.Fatal("expected error on process type read failure")
	}
	if !strings.Contains(err.Error(), "cannot determine SELinux process context") {
		t.Errorf("expected 'cannot determine SELinux process context' in error, got: %v", err)
	}
}

// --- currentBackend ---

func TestCurrentBackend(t *testing.T) {
	tests := []struct {
		name             string
		apparmorActive   bool
		selinuxActive    bool
		selinuxEnforcing bool
		want             LSMBackend
	}{
		{"AppArmor", true, false, false, LSMAppArmor},
		{"SELinux", false, true, true, LSMSelinux},
		{"None", false, false, false, LSMNone},
		{"Permissive", false, true, false, LSMNone},
	}

	origAA := apparmorLSMActive
	origSEL := selinuxEnabled
	defer func() {
		apparmorLSMActive = origAA
		selinuxEnabled = origSEL
	}()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			apparmorLSMActive = func() (bool, error) { return tc.apparmorActive, nil }
			selinuxEnabled = func() (bool, bool, error) {
				return tc.selinuxActive, tc.selinuxEnforcing, nil
			}

			got := currentBackend()
			if got != tc.want {
				t.Errorf("backend: got %q, want %q", got, tc.want)
			}
		})
	}
}

// --- Integration: serve preflight (SELinux path) ---

func TestServeSystemModePreflightSELinuxEnforcing(t *testing.T) {
	origAA := apparmorLSMActive
	origSEL := selinuxEnabled
	origSELType := selinuxProcessType
	apparmorLSMActive = func() (bool, error) { return false, nil }
	selinuxEnabled = func() (bool, bool, error) { return true, true, nil }
	selinuxProcessType = func() (string, error) {
		return "system_u:system_r:docker_helper_t:s0", nil
	}
	defer func() {
		apparmorLSMActive = origAA
		selinuxEnabled = origSEL
		selinuxProcessType = origSELType
	}()

	origUID := EffectiveUID
	origGetConfig := getConfigPathFunc
	EffectiveUID = func() int { return 0 }
	defer func() {
		EffectiveUID = origUID
		getConfigPathFunc = origGetConfig
	}()

	allowedRoot := testAllowedRootDir(t)
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.json")
	configData := fmt.Sprintf(`{"allowed_root":%q,"session_ttl":"12h"}`, allowedRoot)
	if err := os.WriteFile(configPath, []byte(configData), 0600); err != nil {
		t.Fatal(err)
	}
	getConfigPathFunc = func() string { return configPath }

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"serve"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	// SELinux preflight passed — error is from a later startup step.
	stderrStr := stderr.String()
	if strings.Contains(stderrStr, "MAC backend") {
		t.Errorf("MAC preflight should not pass with correct confinement, got: %s", stderrStr)
	}
	if strings.Contains(stderrStr, "SELinux") {
		t.Errorf("SELinux preflight should not block enforcing mode, got: %s", stderrStr)
	}
}

func TestServeSystemModePreflightSELinuxPermissive(t *testing.T) {
	origAA := apparmorLSMActive
	origSEL := selinuxEnabled
	apparmorLSMActive = func() (bool, error) { return false, nil }
	selinuxEnabled = func() (bool, bool, error) { return true, false, nil }
	defer func() {
		apparmorLSMActive = origAA
		selinuxEnabled = origSEL
	}()

	origUID := EffectiveUID
	origGetConfig := getConfigPathFunc
	EffectiveUID = func() int { return 0 }
	defer func() {
		EffectiveUID = origUID
		getConfigPathFunc = origGetConfig
	}()

	getConfigPathFunc = func() string { return "/nonexistent/config.json" }

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"serve"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	stderrStr := stderr.String()
	if !strings.Contains(stderrStr, "permissive") {
		t.Errorf("expected 'permissive' in stderr, got: %s", stderrStr)
	}
	if strings.Contains(stderrStr, "configuration not found") {
		t.Error("loadConfig must not be called before MAC preflight")
	}
}

func TestServeSystemModePreflightBothActive(t *testing.T) {
	origAA := apparmorLSMActive
	origSEL := selinuxEnabled
	apparmorLSMActive = func() (bool, error) { return true, nil }
	selinuxEnabled = func() (bool, bool, error) { return true, true, nil }
	defer func() {
		apparmorLSMActive = origAA
		selinuxEnabled = origSEL
	}()

	origUID := EffectiveUID
	origGetConfig := getConfigPathFunc
	EffectiveUID = func() int { return 0 }
	defer func() {
		EffectiveUID = origUID
		getConfigPathFunc = origGetConfig
	}()

	getConfigPathFunc = func() string { return "/nonexistent/config.json" }

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"serve"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	stderrStr := stderr.String()
	if !strings.Contains(stderrStr, "both") {
		t.Errorf("expected 'both' in stderr, got: %s", stderrStr)
	}
	if strings.Contains(stderrStr, "configuration not found") {
		t.Error("loadConfig must not be called before MAC preflight")
	}
}

// --- Integration: init preflight (SELinux path) ---

func TestInitSystemModePreflightSELinuxEnforcing(t *testing.T) {
	origAA := apparmorLSMActive
	origSEL := selinuxEnabled
	apparmorLSMActive = func() (bool, error) { return false, nil }
	selinuxEnabled = func() (bool, bool, error) { return true, true, nil }
	defer func() {
		apparmorLSMActive = origAA
		selinuxEnabled = origSEL
	}()

	origUID := EffectiveUID
	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return "/nonexistent/config.json" }
	EffectiveUID = func() int { return 0 }
	defer func() {
		EffectiveUID = origUID
		getConfigPathFunc = origGetConfig
	}()

	rootDir := testAllowedRootDir(t)

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"init", "--allowed-root", rootDir}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	// SELinux backend is active, so MAC preflight passes.
	// Error should be from AppArmor-specific init, not MAC detection.
	if strings.Contains(stderr.String(), "no MAC backend") {
		t.Errorf("MAC backend should be detected, got: %s", stderr.String())
	}
}

func TestInitSystemModePreflightSELinuxPermissive(t *testing.T) {
	origAA := apparmorLSMActive
	origSEL := selinuxEnabled
	apparmorLSMActive = func() (bool, error) { return false, nil }
	selinuxEnabled = func() (bool, bool, error) { return true, false, nil }
	defer func() {
		apparmorLSMActive = origAA
		selinuxEnabled = origSEL
	}()

	origUID := EffectiveUID
	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return "/nonexistent/config.json" }
	EffectiveUID = func() int { return 0 }
	defer func() {
		EffectiveUID = origUID
		getConfigPathFunc = origGetConfig
	}()

	rootDir := testAllowedRootDir(t)

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"init", "--allowed-root", rootDir}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	if !strings.Contains(stderr.String(), "permissive") {
		t.Errorf("expected 'permissive' in stderr, got: %s", stderr.String())
	}
}

// --- Integration: user mode must not require MAC ---

func TestServeUserModeNoMACCheck(t *testing.T) {
	origAA := apparmorLSMActive
	origSEL := selinuxEnabled
	apparmorLSMActive = func() (bool, error) { return false, nil }
	selinuxEnabled = func() (bool, bool, error) { return false, false, nil }
	defer func() {
		apparmorLSMActive = origAA
		selinuxEnabled = origSEL
	}()

	origUID := EffectiveUID
	origGetConfig := getConfigPathFunc
	EffectiveUID = func() int { return 1000 }
	defer func() {
		EffectiveUID = origUID
		getConfigPathFunc = origGetConfig
	}()

	allowedRoot := testAllowedRootDir(t)
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.json")
	configData := fmt.Sprintf(`{"allowed_root":%q,"session_ttl":"12h"}`, allowedRoot)
	if err := os.WriteFile(configPath, []byte(configData), 0600); err != nil {
		t.Fatal(err)
	}
	getConfigPathFunc = func() string { return configPath }

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"serve"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	// User mode should not produce any MAC backend error.
	if strings.Contains(stderr.String(), "MAC backend") {
		t.Errorf("user mode should not check MAC backend, got: %s", stderr.String())
	}
}

func TestInitUserModeNoMACCheck(t *testing.T) {
	origAA := apparmorLSMActive
	origSEL := selinuxEnabled
	apparmorLSMActive = func() (bool, error) { return false, nil }
	selinuxEnabled = func() (bool, bool, error) { return false, false, nil }
	defer func() {
		apparmorLSMActive = origAA
		selinuxEnabled = origSEL
	}()

	origUID := EffectiveUID
	origGetConfig := getConfigPathFunc
	EffectiveUID = func() int { return 1000 }
	defer func() {
		EffectiveUID = origUID
		getConfigPathFunc = origGetConfig
	}()

	restore := mockStandaloneUserInit()
	defer restore()

	rootDir := testAllowedRootDir(t)
	configDir := t.TempDir()
	configPath := filepath.Join(configDir, "config.json")
	getConfigPathFunc = func() string { return configPath }

	var stdout, stderr bytes.Buffer
	if err := runInit(rootDir, &stdout, &stderr); err != nil {
		t.Errorf("runInit failed: %v", err)
	}
	if strings.Contains(stderr.String(), "MAC backend") {
		t.Errorf("user mode init should not check MAC backend, got: %s", stderr.String())
	}
}

// --- Integration: AppArmor path still works through MAC abstraction ---

func TestServeSystemModePreflightAppArmorViaMAC(t *testing.T) {
	origAA := apparmorLSMActive
	origAAConf := apparmorProcessConfinement
	origSEL := selinuxEnabled
	apparmorLSMActive = func() (bool, error) { return true, nil }
	apparmorProcessConfinement = func() (string, error) {
		return "docker-helper-system (enforce)", nil
	}
	selinuxEnabled = func() (bool, bool, error) { return false, false, nil }
	defer func() {
		apparmorLSMActive = origAA
		apparmorProcessConfinement = origAAConf
		selinuxEnabled = origSEL
	}()

	origUID := EffectiveUID
	origGetConfig := getConfigPathFunc
	EffectiveUID = func() int { return 0 }
	defer func() {
		EffectiveUID = origUID
		getConfigPathFunc = origGetConfig
	}()

	allowedRoot := testAllowedRootDir(t)
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.json")
	configData := fmt.Sprintf(`{"allowed_root":%q,"session_ttl":"12h"}`, allowedRoot)
	if err := os.WriteFile(configPath, []byte(configData), 0600); err != nil {
		t.Fatal(err)
	}
	getConfigPathFunc = func() string { return configPath }

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"serve"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	// AppArmor preflight passed via MAC abstraction — error is from later step.
	if strings.Contains(stderr.String(), "MAC backend") {
		t.Errorf("MAC preflight should not block AppArmor enforce mode, got: %s", stderr.String())
	}
}

func TestInitSystemModePreflightAppArmorViaMAC(t *testing.T) {
	origAA := apparmorLSMActive
	origSEL := selinuxEnabled
	apparmorLSMActive = func() (bool, error) { return true, nil }
	selinuxEnabled = func() (bool, bool, error) { return false, false, nil }
	defer func() {
		apparmorLSMActive = origAA
		selinuxEnabled = origSEL
	}()

	origUID := EffectiveUID
	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return "/nonexistent/config.json" }
	EffectiveUID = func() int { return 0 }
	defer func() {
		EffectiveUID = origUID
		getConfigPathFunc = origGetConfig
	}()

	rootDir := testAllowedRootDir(t)

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"init", "--allowed-root", rootDir}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	// AppArmor backend detected via MAC — error is from AppArmor-specific init.
	if strings.Contains(stderr.String(), "no MAC backend") {
		t.Errorf("MAC backend should be detected, got: %s", stderr.String())
	}
}

// --- Error propagation ---

func TestDetectLSMAppArmorReadError(t *testing.T) {
	origAA := apparmorLSMActive
	apparmorLSMActive = func() (bool, error) {
		return false, &os.PathError{Op: "read", Path: "/sys/module/apparmor/parameters/enabled", Err: os.ErrPermission}
	}
	defer func() { apparmorLSMActive = origAA }()

	_, err := detectLSM()
	if err == nil {
		t.Fatal("expected error on AppArmor read failure")
	}
	if !errors.Is(err, os.ErrPermission) {
		t.Errorf("error should wrap os.ErrPermission, got: %v", err)
	}
}

func TestDetectLSMSelinuxReadError(t *testing.T) {
	origAA := apparmorLSMActive
	origSEL := selinuxEnabled
	apparmorLSMActive = func() (bool, error) { return false, nil }
	selinuxEnabled = func() (bool, bool, error) {
		return false, false, &os.PathError{Op: "read", Path: "/sys/fs/selinux/enforce", Err: os.ErrPermission}
	}
	defer func() {
		apparmorLSMActive = origAA
		selinuxEnabled = origSEL
	}()

	_, err := detectLSM()
	if err == nil {
		t.Fatal("expected error on SELinux read failure")
	}
	if !errors.Is(err, os.ErrPermission) {
		t.Errorf("error should wrap os.ErrPermission, got: %v", err)
	}
}
