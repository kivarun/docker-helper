package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRequireAppArmorActiveWhenActive(t *testing.T) {
	orig := apparmorLSMActive
	apparmorLSMActive = func() (bool, error) { return true, nil }
	defer func() { apparmorLSMActive = orig }()

	if err := requireAppArmorActive(); err != nil {
		t.Fatalf("expected nil, got: %v", err)
	}
}

func TestRequireAppArmorActiveWhenInactive(t *testing.T) {
	orig := apparmorLSMActive
	apparmorLSMActive = func() (bool, error) { return false, nil }
	defer func() { apparmorLSMActive = orig }()

	err := requireAppArmorActive()
	if err == nil {
		t.Fatal("expected error when AppArmor is inactive")
	}
	if !strings.Contains(err.Error(), "not active") {
		t.Errorf("expected 'not active' in error, got: %v", err)
	}
}

func TestRequireAppArmorActiveReadError(t *testing.T) {
	orig := apparmorLSMActive
	apparmorLSMActive = func() (bool, error) {
		return false, os.ErrNotExist
	}
	defer func() { apparmorLSMActive = orig }()

	err := requireAppArmorActive()
	if err == nil {
		t.Fatal("expected error when LSM status is unreadable")
	}
	if !strings.Contains(err.Error(), "cannot determine") {
		t.Errorf("expected 'cannot determine' in error, got: %v", err)
	}
}

func TestRequireAppArmorConfinementEnforce(t *testing.T) {
	origActive := apparmorLSMActive
	origConfinement := apparmorProcessConfinement
	apparmorLSMActive = func() (bool, error) { return true, nil }
	apparmorProcessConfinement = func() (string, error) {
		return "docker-helper-system (enforce)", nil
	}
	defer func() {
		apparmorLSMActive = origActive
		apparmorProcessConfinement = origConfinement
	}()

	if err := requireAppArmorConfinement(); err != nil {
		t.Fatalf("expected nil for enforce mode, got: %v", err)
	}
}

func TestRequireAppArmorConfinementUnconfined(t *testing.T) {
	origActive := apparmorLSMActive
	origConfinement := apparmorProcessConfinement
	apparmorLSMActive = func() (bool, error) { return true, nil }
	apparmorProcessConfinement = func() (string, error) {
		return "unconfined", nil
	}
	defer func() {
		apparmorLSMActive = origActive
		apparmorProcessConfinement = origConfinement
	}()

	err := requireAppArmorConfinement()
	if err == nil {
		t.Fatal("expected error when unconfined")
	}
	if !strings.Contains(err.Error(), "not confined") {
		t.Errorf("expected 'not confined' in error, got: %v", err)
	}
}

func TestRequireAppArmorConfinementComplain(t *testing.T) {
	origActive := apparmorLSMActive
	origConfinement := apparmorProcessConfinement
	apparmorLSMActive = func() (bool, error) { return true, nil }
	apparmorProcessConfinement = func() (string, error) {
		return "docker-helper-system (complain)", nil
	}
	defer func() {
		apparmorLSMActive = origActive
		apparmorProcessConfinement = origConfinement
	}()

	err := requireAppArmorConfinement()
	if err == nil {
		t.Fatal("expected error when in complain mode")
	}
	if !strings.Contains(err.Error(), "not confined") {
		t.Errorf("expected 'not confined' in error, got: %v", err)
	}
}

func TestRequireAppArmorConfinementInactive(t *testing.T) {
	origActive := apparmorLSMActive
	origConfinement := apparmorProcessConfinement
	apparmorLSMActive = func() (bool, error) { return false, nil }
	apparmorProcessConfinement = func() (string, error) {
		t.Fatal("confinement should not be read when LSM is inactive")
		return "", nil
	}
	defer func() {
		apparmorLSMActive = origActive
		apparmorProcessConfinement = origConfinement
	}()

	err := requireAppArmorConfinement()
	if err == nil {
		t.Fatal("expected error when LSM is inactive")
	}
}

func TestRequireAppArmorConfinementWrongProfile(t *testing.T) {
	origActive := apparmorLSMActive
	origConfinement := apparmorProcessConfinement
	apparmorLSMActive = func() (bool, error) { return true, nil }
	apparmorProcessConfinement = func() (string, error) {
		return "other-profile (enforce)", nil
	}
	defer func() {
		apparmorLSMActive = origActive
		apparmorProcessConfinement = origConfinement
	}()

	err := requireAppArmorConfinement()
	if err == nil {
		t.Fatal("expected error for wrong profile")
	}
	if !strings.Contains(err.Error(), "not confined") {
		t.Errorf("expected 'not confined' in error, got: %v", err)
	}
}

// --- Integration: serve preflight ---

// TestServeSystemModePreflightInactive verifies that the MAC backend preflight
// runs before loadConfig. It uses a nonexistent config path: if loadConfig
// were called first, the error would be about missing config, not MAC backend.
// The "MAC backend" error proves preflight ran before loadConfig.
func TestServeSystemModePreflightInactive(t *testing.T) {
	origActive := apparmorLSMActive
	apparmorLSMActive = func() (bool, error) { return false, nil }
	defer func() { apparmorLSMActive = origActive }()

	mockSELinuxInactive(t)

	origUID := EffectiveUID
	origGetConfig := getConfigPathFunc
	EffectiveUID = func() int { return 0 }
	defer func() {
		EffectiveUID = origUID
		getConfigPathFunc = origGetConfig
	}()

	// Nonexistent config path: if loadConfig ran before preflight, the error
	// would be "configuration not found", not "MAC backend".
	getConfigPathFunc = func() string { return "/nonexistent/docker-helper/config.json" }

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"serve"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	stderrStr := stderr.String()
	if !strings.Contains(stderrStr, "MAC backend") {
		t.Errorf("expected 'MAC backend' in stderr, got: %s", stderrStr)
	}
	if strings.Contains(stderrStr, "configuration not found") {
		t.Error("loadConfig must not be called before MAC preflight (got config error instead of MAC backend error)")
	}
}

// TestServeSystemModePreflightUnconfined verifies that the confinement check
// runs before loadConfig. It uses a nonexistent config path: if loadConfig
// were called first, the error would be about missing config, not confinement.
func TestServeSystemModePreflightUnconfined(t *testing.T) {
	origActive := apparmorLSMActive
	origConfinement := apparmorProcessConfinement
	apparmorLSMActive = func() (bool, error) { return true, nil }
	apparmorProcessConfinement = func() (string, error) { return "unconfined", nil }
	defer func() {
		apparmorLSMActive = origActive
		apparmorProcessConfinement = origConfinement
	}()

	mockSELinuxInactive(t)

	origUID := EffectiveUID
	origGetConfig := getConfigPathFunc
	EffectiveUID = func() int { return 0 }
	defer func() {
		EffectiveUID = origUID
		getConfigPathFunc = origGetConfig
	}()

	// Nonexistent config path: if loadConfig ran before preflight, the error
	// would be "configuration not found", not "not confined".
	getConfigPathFunc = func() string { return "/nonexistent/docker-helper/config.json" }

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"serve"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	stderrStr := stderr.String()
	if !strings.Contains(stderrStr, "not confined") {
		t.Errorf("expected 'not confined' in stderr, got: %s", stderrStr)
	}
	if strings.Contains(stderrStr, "configuration not found") {
		t.Error("loadConfig must not be called before AppArmor preflight (got config error instead of confinement error)")
	}
}

// TestServeSystemModePreflightEnforce verifies that a process confined in
// the correct profile passes the AppArmor preflight and proceeds to the
// next startup check (lock, admin token, etc.). This proves the preflight
// does not block a properly confined process.
func TestServeSystemModePreflightEnforce(t *testing.T) {
	origActive := apparmorLSMActive
	origConfinement := apparmorProcessConfinement
	apparmorLSMActive = func() (bool, error) { return true, nil }
	apparmorProcessConfinement = func() (string, error) {
		return "docker-helper-system (enforce)", nil
	}
	defer func() {
		apparmorLSMActive = origActive
		apparmorProcessConfinement = origConfinement
	}()

	mockSELinuxInactive(t)

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
	// AppArmor preflight passed — error is from a later startup step, not AppArmor.
	if strings.Contains(stderr.String(), "AppArmor") {
		t.Errorf("AppArmor preflight should not block enforce mode, got: %s", stderr.String())
	}
}

// --- Integration: init preflight ---

func TestInitSystemModePreflightInactive(t *testing.T) {
	mockApparmorActive(t, false)
	mockSELinuxInactive(t)

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
	if !strings.Contains(stderr.String(), "MAC backend") {
		t.Errorf("expected 'MAC backend' in stderr, got: %s", stderr.String())
	}
}

// --- Integration: AppArmor CLI preflight ---

func TestApparmorRootListInactive(t *testing.T) {
	mockApparmorActive(t, false)
	origUID := EffectiveUID
	EffectiveUID = func() int { return 0 }
	defer func() { EffectiveUID = origUID }()

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"apparmor", "root", "list"}, &stdout, &stderr)
	if code != 0 {
		t.Errorf("expected exit code 0 (list reads managed fragment, does not require active LSM), got %d (stderr: %s)", code, stderr.String())
	}
}

func TestApparmorRootAddInactive(t *testing.T) {
	mockApparmorActive(t, false)
	origUID := EffectiveUID
	EffectiveUID = func() int { return 0 }
	defer func() { EffectiveUID = origUID }()

	rootDir := testAllowedRootDir(t)

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"apparmor", "root", "add", rootDir}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	if !strings.Contains(stderr.String(), "not active") {
		t.Errorf("expected 'not active' in stderr, got: %s", stderr.String())
	}
}

func TestApparmorRootRemoveInactive(t *testing.T) {
	mockApparmorActive(t, false)
	origUID := EffectiveUID
	EffectiveUID = func() int { return 0 }
	defer func() { EffectiveUID = origUID }()

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"apparmor", "root", "remove", "/nonexistent"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	if !strings.Contains(stderr.String(), "not active") {
		t.Errorf("expected 'not active' in stderr, got: %s", stderr.String())
	}
}

func TestApparmorCheckInactive(t *testing.T) {
	mockApparmorActive(t, false)
	origUID := EffectiveUID
	EffectiveUID = func() int { return 0 }
	defer func() { EffectiveUID = origUID }()

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"apparmor", "check"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	if !strings.Contains(stderr.String(), "not active") {
		t.Errorf("expected 'not active' in stderr, got: %s", stderr.String())
	}
}

// --- User mode should not trigger AppArmor checks ---

func TestServeUserModeNoAppArmorCheck(t *testing.T) {
	origActive := apparmorLSMActive
	apparmorLSMActive = func() (bool, error) { return false, nil }
	defer func() { apparmorLSMActive = origActive }()

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
	// User mode should not produce any AppArmor LSM error.
	if strings.Contains(stderr.String(), "AppArmor LSM") {
		t.Errorf("user mode should not check AppArmor LSM, got: %s", stderr.String())
	}
}

func TestInitUserModeNoAppArmorCheck(t *testing.T) {
	origActive := apparmorLSMActive
	apparmorLSMActive = func() (bool, error) { return false, nil }
	defer func() { apparmorLSMActive = origActive }()

	origUID := EffectiveUID
	origGetConfig := getConfigPathFunc
	EffectiveUID = func() int { return 1000 }
	defer func() {
		EffectiveUID = origUID
		getConfigPathFunc = origGetConfig
	}()

	// Standalone user init (no system daemon, Docker accessible).
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
	if strings.Contains(stderr.String(), "AppArmor LSM") {
		t.Errorf("user mode init should not check AppArmor LSM, got: %s", stderr.String())
	}
}
