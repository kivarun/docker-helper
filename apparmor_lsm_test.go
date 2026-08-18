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

func TestServeSystemModePreflightInactive(t *testing.T) {
	origActive := apparmorLSMActive
	apparmorLSMActive = func() (bool, error) { return false, nil }
	defer func() { apparmorLSMActive = origActive }()

	origUID := EffectiveUID
	origGetConfig := getConfigPathFunc
	EffectiveUID = func() int { return 0 }
	defer func() {
		EffectiveUID = origUID
		getConfigPathFunc = origGetConfig
	}()

	// Create a minimal valid config so serve reaches the AppArmor check.
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
	combined := stderr.String() + stdout.String()
	if !strings.Contains(combined, "not active") && !strings.Contains(combined, "AppArmor") {
		t.Errorf("expected AppArmor error, got: %s", combined)
	}
}

func TestServeSystemModePreflightUnconfined(t *testing.T) {
	origActive := apparmorLSMActive
	origConfinement := apparmorProcessConfinement
	apparmorLSMActive = func() (bool, error) { return true, nil }
	apparmorProcessConfinement = func() (string, error) { return "unconfined", nil }
	defer func() {
		apparmorLSMActive = origActive
		apparmorProcessConfinement = origConfinement
	}()

	origUID := EffectiveUID
	origGetConfig := getConfigPathFunc
	EffectiveUID = func() int { return 0 }
	defer func() {
		EffectiveUID = origUID
		getConfigPathFunc = origGetConfig
	}()

	// Create a minimal valid config so serve reaches the AppArmor check.
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
	combined := stderr.String() + stdout.String()
	if !strings.Contains(combined, "not confined") && !strings.Contains(combined, "AppArmor") {
		t.Errorf("expected confinement error, got: %s", combined)
	}
}

// --- Integration: init preflight ---

func TestInitSystemModePreflightInactive(t *testing.T) {
	origActive := apparmorLSMActive
	apparmorLSMActive = func() (bool, error) { return false, nil }
	defer func() { apparmorLSMActive = origActive }()

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
	combined := stderr.String() + stdout.String()
	if !strings.Contains(combined, "not active") && !strings.Contains(combined, "AppArmor") {
		t.Errorf("expected AppArmor error, got: %s", combined)
	}
}

// --- Integration: AppArmor CLI preflight ---

func TestApparmorRootListInactive(t *testing.T) {
	origActive := apparmorLSMActive
	apparmorLSMActive = func() (bool, error) { return false, nil }
	defer func() { apparmorLSMActive = origActive }()

	origUID := EffectiveUID
	EffectiveUID = func() int { return 0 }
	defer func() {
		EffectiveUID = origUID
	}()

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"apparmor", "root", "list"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	combined := stderr.String() + stdout.String()
	if !strings.Contains(combined, "not active") && !strings.Contains(combined, "AppArmor") {
		t.Errorf("expected AppArmor error, got: %s", combined)
	}
}

func TestApparmorCheckInactive(t *testing.T) {
	origActive := apparmorLSMActive
	apparmorLSMActive = func() (bool, error) { return false, nil }
	defer func() { apparmorLSMActive = origActive }()

	origUID := EffectiveUID
	EffectiveUID = func() int { return 0 }
	defer func() {
		EffectiveUID = origUID
	}()

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"apparmor", "check"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	combined := stderr.String() + stdout.String()
	if !strings.Contains(combined, "not active") && !strings.Contains(combined, "AppArmor") {
		t.Errorf("expected AppArmor error, got: %s", combined)
	}
}

// --- User mode should not trigger AppArmor checks ---

func TestServeUserModeNoAppArmorCheck(t *testing.T) {
	// Even with AppArmor seams set to error, user mode should not fail
	// on AppArmor preflight.
	origActive := apparmorLSMActive
	apparmorLSMActive = func() (bool, error) { return false, nil }
	defer func() { apparmorLSMActive = origActive }()

	origUID := EffectiveUID
	origGetConfig := getConfigPathFunc
	// Non-root = user mode
	EffectiveUID = func() int { return 1000 }
	defer func() {
		EffectiveUID = origUID
		getConfigPathFunc = origGetConfig
	}()

	// Create a valid config so serve reaches past config loading.
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
	// Should fail (missing admin token), but NOT with AppArmor error.
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	// Verify no AppArmor-related error in stderr (not in help text).
	stderrStr := stderr.String()
	if strings.Contains(stderrStr, "AppArmor LSM") || strings.Contains(stderrStr, "not confined") {
		t.Errorf("user mode should not produce AppArmor error, got: %s", stderrStr)
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

	rootDir := testAllowedRootDir(t)
	configDir := t.TempDir()
	configPath := filepath.Join(configDir, "config.json")
	getConfigPathFunc = func() string { return configPath }

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"init", "--allowed-root", rootDir}, &stdout, &stderr)
	if code != 0 {
		t.Errorf("expected exit code 0, got %d (stderr: %s)", code, stderr.String())
	}
	// Verify no AppArmor-related error (check stderr specifically, not paths).
	if strings.Contains(stderr.String(), "AppArmor") {
		t.Errorf("user mode init should not produce AppArmor error, got: %s", stderr.String())
	}
}
