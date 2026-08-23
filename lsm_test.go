package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
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
			wantBackend:      LSMSELinux,
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
			name:             "both AppArmor and permissive SELinux",
			apparmorActive:   true,
			selinuxActive:    true,
			selinuxEnforcing: false,
			wantBackend:      LSMNone,
			wantErr:          true,
			errContains:      "both",
		},
		{
			name:           "AppArmor detection error (not ENOENT)",
			apparmorActive: false,
			apparmorErr:    os.ErrPermission,
			selinuxActive:  false,
			wantBackend:    LSMNone,
			wantErr:        true,
			errContains:    "cannot determine AppArmor",
		},
		{
			name:             "AppArmor ENOENT with SELinux enforcing",
			apparmorActive:   false,
			apparmorErr:      os.ErrNotExist,
			selinuxActive:    true,
			selinuxEnforcing: true,
			wantBackend:      LSMSELinux,
			wantErr:          false,
		},
		{
			name:           "AppArmor ENOENT with no SELinux",
			apparmorActive: false,
			apparmorErr:    os.ErrNotExist,
			selinuxActive:  false,
			wantBackend:    LSMNone,
			wantErr:        false,
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
			name:           "SELinux malformed enforce value",
			apparmorActive: false,
			selinuxActive:  false,
			selinuxErr:     &malformedEnforceError{},
			wantBackend:    LSMNone,
			wantErr:        true,
			errContains:    "unexpected SELinux enforce",
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

// malformedEnforceError is a test double for malformed SELinux enforce values.
type malformedEnforceError struct{}

func (e *malformedEnforceError) Error() string {
	return `unexpected SELinux enforce value "2" (expected 0 or 1)`
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
	origSELCtx := selinuxProcessContext
	apparmorLSMActive = func() (bool, error) { return false, nil }
	selinuxEnabled = func() (bool, bool, error) { return true, true, nil }
	selinuxProcessContext = func() (string, error) {
		return "system_u:system_r:docker_helper_t:s0", nil
	}
	defer func() {
		apparmorLSMActive = origAA
		selinuxEnabled = origSEL
		selinuxProcessContext = origSELCtx
	}()

	if err := requireMACConfinement(); err != nil {
		t.Fatalf("expected nil for correct SELinux type, got: %v", err)
	}
}

func TestRequireMACConfinementSELinuxWrongType(t *testing.T) {
	origAA := apparmorLSMActive
	origSEL := selinuxEnabled
	origSELCtx := selinuxProcessContext
	apparmorLSMActive = func() (bool, error) { return false, nil }
	selinuxEnabled = func() (bool, bool, error) { return true, true, nil }
	selinuxProcessContext = func() (string, error) {
		return "system_u:system_r:unconfined_t:s0", nil
	}
	defer func() {
		apparmorLSMActive = origAA
		selinuxEnabled = origSEL
		selinuxProcessContext = origSELCtx
	}()

	err := requireMACConfinement()
	if err == nil {
		t.Fatal("expected error for wrong SELinux type")
	}
	if !strings.Contains(err.Error(), "not confined") {
		t.Errorf("expected 'not confined' in error, got: %v", err)
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

// --- parseSELinuxType ---

func TestParseSELinuxType(t *testing.T) {
	tests := []struct {
		name    string
		ctx     string
		want    string
		wantErr bool
	}{
		{"standard", "system_u:system_r:docker_helper_t:s0", "docker_helper_t", false},
		{"different user", "unconfined_u:system_r:docker_helper_t:s0", "docker_helper_t", false},
		{"with MCS range", "system_u:system_r:docker_helper_t:s0:c1", "docker_helper_t", false},
		{"with MLS range", "system_u:system_r:docker_helper_t:s0-s0:c0.c1023", "docker_helper_t", false},
		{"wrong type", "system_u:system_r:other_t:s0", "other_t", false},
		{"no range", "system_u:system_r:docker_helper_t", "docker_helper_t", false},
		{"malformed two fields", "user:role", "", true},
		{"malformed one field", "user", "", true},
		{"empty", "", "", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseSELinuxType(tc.ctx)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("type: got %q, want %q", got, tc.want)
			}
		})
	}
}

// --- SELinux confinement with TYPE parsing ---

func TestSELinuxConfinementTypeVariants(t *testing.T) {
	tests := []struct {
		name    string
		ctx     string
		wantErr bool
	}{
		{"standard s0", "system_u:system_r:docker_helper_t:s0", false},
		{"unconfined user", "unconfined_u:system_r:docker_helper_t:s0", false},
		{"MCS range c1", "system_u:system_r:docker_helper_t:s0:c1", false},
		{"MLS range", "system_u:system_r:docker_helper_t:s0-s0:c0.c1023", false},
		{"wrong type", "system_u:system_r:other_t:s0", true},
		{"malformed", "bad-context", true},
	}

	origAA := apparmorLSMActive
	origSEL := selinuxEnabled
	origSELCtx := selinuxProcessContext
	defer func() {
		apparmorLSMActive = origAA
		selinuxEnabled = origSEL
		selinuxProcessContext = origSELCtx
	}()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			apparmorLSMActive = func() (bool, error) { return false, nil }
			selinuxEnabled = func() (bool, bool, error) { return true, true, nil }
			selinuxProcessContext = func() (string, error) { return tc.ctx, nil }

			err := requireSELinuxConfinement()
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
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

func TestRequireSELinuxConfinementProcessContextReadError(t *testing.T) {
	origSEL := selinuxEnabled
	origCtx := selinuxProcessContext
	selinuxEnabled = func() (bool, bool, error) { return true, true, nil }
	selinuxProcessContext = func() (string, error) {
		return "", os.ErrNotExist
	}
	defer func() {
		selinuxEnabled = origSEL
		selinuxProcessContext = origCtx
	}()

	err := requireSELinuxConfinement()
	if err == nil {
		t.Fatal("expected error on process context read failure")
	}
	if !strings.Contains(err.Error(), "cannot determine SELinux process context") {
		t.Errorf("expected 'cannot determine SELinux process context' in error, got: %v", err)
	}
}

// --- SELinux enforce value parsing ---

func TestParseSELinuxEnforceValue(t *testing.T) {
	tests := []struct {
		name          string
		data          []byte
		wantEnforcing bool
		wantErr       bool
		errContains   string
	}{
		{"enforcing", []byte("1"), true, false, ""},
		{"permissive", []byte("0"), false, false, ""},
		{"enforcing with newline", []byte("1\n"), true, false, ""},
		{"permissive with newline", []byte("0\n"), false, false, ""},
		{"malformed value 2", []byte("2"), false, true, "unexpected SELinux enforce"},
		{"malformed string", []byte("yes"), false, true, "unexpected SELinux enforce"},
		{"empty", []byte(""), false, true, "unexpected SELinux enforce"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			enforcing, err := parseSELinuxEnforceValue(tc.data)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tc.errContains != "" && !strings.Contains(err.Error(), tc.errContains) {
					t.Errorf("error %q does not contain %q", err.Error(), tc.errContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if enforcing != tc.wantEnforcing {
				t.Errorf("enforcing: got %v, want %v", enforcing, tc.wantEnforcing)
			}
		})
	}
}

// --- Integration: serve preflight (SELinux path) ---

func TestServeSystemModePreflightSELinuxEnforcing(t *testing.T) {
	origAA := apparmorLSMActive
	origSEL := selinuxEnabled
	origSELCtx := selinuxProcessContext
	apparmorLSMActive = func() (bool, error) { return false, nil }
	selinuxEnabled = func() (bool, bool, error) { return true, true, nil }
	selinuxProcessContext = func() (string, error) {
		return "system_u:system_r:docker_helper_t:s0", nil
	}
	defer func() {
		apparmorLSMActive = origAA
		selinuxEnabled = origSEL
		selinuxProcessContext = origSELCtx
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
	opLog := stderr.String()
	if strings.Contains(opLog, "MAC backend") {
		t.Errorf("MAC preflight should not block with correct confinement, got: %s", opLog)
	}
	if strings.Contains(opLog, "SELinux") {
		t.Errorf("SELinux preflight should not block enforcing mode, got: %s", opLog)
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
	opLog := stderr.String()
	if !strings.Contains(opLog, "permissive") {
		t.Errorf("expected 'permissive' in operational log, got: %s", opLog)
	}
	if strings.Contains(opLog, "configuration not found") {
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
	opLog := stderr.String()
	if !strings.Contains(opLog, "both") {
		t.Errorf("expected 'both' in operational log, got: %s", opLog)
	}
	if strings.Contains(opLog, "configuration not found") {
		t.Error("loadConfig must not be called before MAC preflight")
	}
}

func TestServeSystemModePreflightBothAppArmorPermissiveSELinux(t *testing.T) {
	origAA := apparmorLSMActive
	origSEL := selinuxEnabled
	apparmorLSMActive = func() (bool, error) { return true, nil }
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
	opLog := stderr.String()
	if !strings.Contains(opLog, "both") {
		t.Errorf("expected 'both' in operational log (AppArmor + permissive SELinux must fail), got: %s", opLog)
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
	EffectiveUID = func() int { return 0 }
	defer func() {
		EffectiveUID = origUID
		getConfigPathFunc = origGetConfig
	}()

	rootDir := testAllowedRootDir(t)
	configDir := t.TempDir()
	configPath := filepath.Join(configDir, "config.json")
	getConfigPathFunc = func() string { return configPath }

	// Test initSystem directly with a mock core to avoid
	// /var/lib/docker-helper creation (requires root).
	var coreCalled string
	err := initSystem(rootDir, &bytes.Buffer{}, &bytes.Buffer{},
		newSELinuxSystemInitBackend(nil, func(path string) (string, error) { return path, nil }),
		func(ar string, so, se io.Writer) error {
			coreCalled = ar
			return nil
		},
	)
	if err != nil {
		t.Fatalf("initSystem failed: %v", err)
	}
	if coreCalled != rootDir {
		t.Errorf("core called with %q, want %q", coreCalled, rootDir)
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

func TestDetectLSMSELinuxReadError(t *testing.T) {
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
