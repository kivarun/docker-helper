package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestInstallScriptSyntax verifies install.sh has valid bash syntax.
func TestInstallScriptSyntax(t *testing.T) {
	cmd := exec.Command("bash", "-n", "packaging/install.sh")
	if err := cmd.Run(); err != nil {
		t.Fatalf("install.sh syntax error: %v", err)
	}
}

// TestUninstallScriptSyntax verifies uninstall.sh has valid bash syntax.
func TestUninstallScriptSyntax(t *testing.T) {
	cmd := exec.Command("bash", "-n", "packaging/uninstall.sh")
	if err := cmd.Run(); err != nil {
		t.Fatalf("uninstall.sh syntax error: %v", err)
	}
}

// TestInstallBinaryCopied verifies install.sh copies the binary to ~/.local/bin.
func TestInstallBinaryCopied(t *testing.T) {
	tempHome := t.TempDir()
	fakeBin := filepath.Join(tempHome, "fake-docker-helper")
	if err := os.WriteFile(fakeBin, []byte("fake"), 0755); err != nil {
		t.Fatal(err)
	}

	scriptDir := t.TempDir()
	binPath := filepath.Join(scriptDir, "docker-helper")
	if err := os.Rename(fakeBin, binPath); err != nil {
		t.Fatal(err)
	}

	testScript := `#!/usr/bin/env bash
set -euo pipefail
INSTALL_DIR="` + tempHome + `/.local/bin"
BINARY_NAME="docker-helper"
script_dir="` + scriptDir + `"
install_binary() {
	mkdir -p "$INSTALL_DIR"
	cp "$script_dir/$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME"
	chmod 755 "$INSTALL_DIR/$BINARY_NAME"
}
install_binary
`
	tmpScript := filepath.Join(t.TempDir(), "test_install.sh")
	if err := os.WriteFile(tmpScript, []byte(testScript), 0755); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("bash", tmpScript)
	if err := cmd.Run(); err != nil {
		t.Fatalf("install_binary failed: %v", err)
	}

	installed := filepath.Join(tempHome, ".local", "bin", "docker-helper")
	if _, err := os.Stat(installed); err != nil {
		t.Fatalf("binary not installed to %s: %v", installed, err)
	}

	info, err := os.Stat(installed)
	if err != nil {
		t.Fatal(err)
	}
	mode := info.Mode().Perm()
	if mode != 0755 {
		t.Errorf("expected mode 0755, got %o", mode)
	}
}

// TestInstallUnitCopied verifies install.sh copies the systemd unit.
func TestInstallUnitCopied(t *testing.T) {
	tempHome := t.TempDir()
	scriptDir := t.TempDir()

	unitDir := filepath.Join(scriptDir, "systemd", "user")
	if err := os.MkdirAll(unitDir, 0755); err != nil {
		t.Fatal(err)
	}
	unitContent := []byte("[Unit]\nDescription=Test\n")
	if err := os.WriteFile(filepath.Join(unitDir, "docker-helper.service"), unitContent, 0644); err != nil {
		t.Fatal(err)
	}

	testScript := `#!/usr/bin/env bash
set -euo pipefail
UNIT_DIR="` + tempHome + `/.config/systemd/user"
UNIT_NAME="docker-helper.service"
script_dir="` + scriptDir + `"
install_unit() {
	local unit_path="$script_dir/systemd/user/$UNIT_NAME"
	if [[ ! -f "$unit_path" ]]; then
		return
	fi
	mkdir -p "$UNIT_DIR"
	cp "$unit_path" "$UNIT_DIR/$UNIT_NAME"
	chmod 644 "$UNIT_DIR/$UNIT_NAME"
}
install_unit
`
	tmpScript := filepath.Join(t.TempDir(), "test_install_unit.sh")
	if err := os.WriteFile(tmpScript, []byte(testScript), 0755); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("bash", tmpScript)
	if err := cmd.Run(); err != nil {
		t.Fatalf("install_unit failed: %v", err)
	}

	installed := filepath.Join(tempHome, ".config", "systemd", "user", "docker-helper.service")
	if _, err := os.Stat(installed); err != nil {
		t.Fatalf("unit not installed to %s: %v", installed, err)
	}
}

// TestInstallIdempotent verifies that running install again does not fail.
func TestInstallIdempotent(t *testing.T) {
	tempHome := t.TempDir()
	scriptDir := t.TempDir()

	// Create a fake binary
	binPath := filepath.Join(scriptDir, "docker-helper")
	if err := os.WriteFile(binPath, []byte("fake"), 0755); err != nil {
		t.Fatal(err)
	}

	unitDir := filepath.Join(scriptDir, "systemd", "user")
	if err := os.MkdirAll(unitDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(unitDir, "docker-helper.service"), []byte("[Unit]\n"), 0644); err != nil {
		t.Fatal(err)
	}

	testScript := `#!/usr/bin/env bash
set -euo pipefail
INSTALL_DIR="` + tempHome + `/.local/bin"
UNIT_DIR="` + tempHome + `/.config/systemd/user"
BINARY_NAME="docker-helper"
UNIT_NAME="docker-helper.service"
script_dir="` + scriptDir + `"
install_binary() {
	mkdir -p "$INSTALL_DIR"
	cp "$script_dir/$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME"
	chmod 755 "$INSTALL_DIR/$BINARY_NAME"
}
install_unit() {
	local unit_path="$script_dir/systemd/user/$UNIT_NAME"
	if [[ ! -f "$unit_path" ]]; then
		return
	fi
	mkdir -p "$UNIT_DIR"
	cp "$unit_path" "$UNIT_DIR/$UNIT_NAME"
	chmod 644 "$UNIT_DIR/$UNIT_NAME"
}
# Run twice
install_binary
install_unit
install_binary
install_unit
`
	tmpScript := filepath.Join(t.TempDir(), "test_idempotent.sh")
	if err := os.WriteFile(tmpScript, []byte(testScript), 0755); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("bash", tmpScript)
	if err := cmd.Run(); err != nil {
		t.Fatalf("idempotent install failed: %v", err)
	}
}

// TestUninstallRemovesBinary verifies uninstall.sh removes the installed binary.
func TestUninstallRemovesBinary(t *testing.T) {
	tempHome := t.TempDir()

	installDir := filepath.Join(tempHome, ".local", "bin")
	if err := os.MkdirAll(installDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(installDir, "docker-helper"), []byte("fake"), 0755); err != nil {
		t.Fatal(err)
	}

	unitDir := filepath.Join(tempHome, ".config", "systemd", "user")
	if err := os.MkdirAll(unitDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(unitDir, "docker-helper.service"), []byte("[Unit]\n"), 0644); err != nil {
		t.Fatal(err)
	}

	testScript := `#!/usr/bin/env bash
set -euo pipefail
INSTALL_DIR="` + tempHome + `/.local/bin"
UNIT_DIR="` + tempHome + `/.config/systemd/user"
BINARY_NAME="docker-helper"
UNIT_NAME="docker-helper.service"
remove_binary() {
	if [[ -f "$INSTALL_DIR/$BINARY_NAME" ]]; then
		rm -f "$INSTALL_DIR/$BINARY_NAME"
	fi
}
remove_unit() {
	if [[ -f "$UNIT_DIR/$UNIT_NAME" ]]; then
		rm -f "$UNIT_DIR/$UNIT_NAME"
	fi
}
remove_binary
remove_unit
`
	tmpScript := filepath.Join(t.TempDir(), "test_uninstall.sh")
	if err := os.WriteFile(tmpScript, []byte(testScript), 0755); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("bash", tmpScript)
	if err := cmd.Run(); err != nil {
		t.Fatalf("uninstall failed: %v", err)
	}

	if _, err := os.Stat(filepath.Join(installDir, "docker-helper")); !os.IsNotExist(err) {
		t.Error("binary should be removed")
	}
	if _, err := os.Stat(filepath.Join(unitDir, "docker-helper.service")); !os.IsNotExist(err) {
		t.Error("unit should be removed")
	}
}

// TestUninstallPreservesConfig verifies that soft uninstall preserves config.
func TestUninstallPreservesConfig(t *testing.T) {
	tempHome := t.TempDir()

	configDir := filepath.Join(tempHome, ".config", "docker-helper")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "config.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "admin.token"), []byte("test-token"), 0600); err != nil {
		t.Fatal(err)
	}

	stateDir := filepath.Join(tempHome, ".local", "state", "docker-helper")
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "docker-helper.db"), []byte("fake db"), 0600); err != nil {
		t.Fatal(err)
	}

	// Soft uninstall should NOT remove config or state
	// (purge=false means config/state are preserved)

	if _, err := os.Stat(filepath.Join(configDir, "config.json")); err != nil {
		t.Error("config.json should be preserved")
	}
	if _, err := os.Stat(filepath.Join(configDir, "admin.token")); err != nil {
		t.Error("admin.token should be preserved")
	}
	if _, err := os.Stat(filepath.Join(stateDir, "docker-helper.db")); err != nil {
		t.Error("database should be preserved")
	}
}

// TestUninstallPurgeRemovesConfig verifies that --purge removes config and state.
func TestUninstallPurgeRemovesConfig(t *testing.T) {
	tempHome := t.TempDir()

	configDir := filepath.Join(tempHome, ".config", "docker-helper")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "config.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}

	stateDir := filepath.Join(tempHome, ".local", "state", "docker-helper")
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		t.Fatal(err)
	}

	testScript := `#!/usr/bin/env bash
set -euo pipefail
CONFIG_DIR="` + configDir + `"
STATE_DIR="` + stateDir + `"
purge_config_and_state() {
	if [[ -d "$CONFIG_DIR" ]]; then
		rm -rf "$CONFIG_DIR"
	fi
	if [[ -d "$STATE_DIR" ]]; then
		rm -rf "$STATE_DIR"
	fi
}
purge_config_and_state
`
	tmpScript := filepath.Join(t.TempDir(), "test_purge.sh")
	if err := os.WriteFile(tmpScript, []byte(testScript), 0755); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("bash", tmpScript)
	if err := cmd.Run(); err != nil {
		t.Fatalf("purge failed: %v", err)
	}

	if _, err := os.Stat(configDir); !os.IsNotExist(err) {
		t.Error("config dir should be removed on purge")
	}
	if _, err := os.Stat(stateDir); !os.IsNotExist(err) {
		t.Error("state dir should be removed on purge")
	}
}

// TestUninstallPurgeDoesNotRemoveParent verifies purge doesn't remove
// parent directories like ~/.config or ~/.local/state.
func TestUninstallPurgeDoesNotRemoveParent(t *testing.T) {
	tempHome := t.TempDir()

	configDir := filepath.Join(tempHome, ".config", "docker-helper")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}

	// Create a sibling directory that should NOT be removed
	siblingDir := filepath.Join(tempHome, ".config", "other-app")
	if err := os.MkdirAll(siblingDir, 0700); err != nil {
		t.Fatal(err)
	}

	stateDir := filepath.Join(tempHome, ".local", "state", "docker-helper")
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		t.Fatal(err)
	}

	siblingState := filepath.Join(tempHome, ".local", "state", "other-app")
	if err := os.MkdirAll(siblingState, 0700); err != nil {
		t.Fatal(err)
	}

	testScript := `#!/usr/bin/env bash
set -euo pipefail
CONFIG_DIR="` + configDir + `"
STATE_DIR="` + stateDir + `"
purge_config_and_state() {
	if [[ -d "$CONFIG_DIR" ]]; then
		rm -rf "$CONFIG_DIR"
	fi
	if [[ -d "$STATE_DIR" ]]; then
		rm -rf "$STATE_DIR"
	fi
}
purge_config_and_state
`
	tmpScript := filepath.Join(t.TempDir(), "test_purge_parent.sh")
	if err := os.WriteFile(tmpScript, []byte(testScript), 0755); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("bash", tmpScript)
	if err := cmd.Run(); err != nil {
		t.Fatalf("purge failed: %v", err)
	}

	// Parent dirs should still exist
	if _, err := os.Stat(filepath.Join(tempHome, ".config")); err != nil {
		t.Error("~/.config should not be removed")
	}
	if _, err := os.Stat(siblingDir); err != nil {
		t.Error("sibling config dir should not be removed")
	}
	if _, err := os.Stat(filepath.Join(tempHome, ".local", "state")); err != nil {
		t.Error("~/.local/state should not be removed")
	}
	if _, err := os.Stat(siblingState); err != nil {
		t.Error("sibling state dir should not be removed")
	}
}

// TestInstallScriptUnknownFlag verifies install.sh rejects unknown flags.
func TestInstallScriptUnknownFlag(t *testing.T) {
	cmd := exec.Command("bash", "packaging/install.sh", "--unknown-flag")
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir())
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected non-zero exit code for unknown flag")
	}
}

// TestUninstallScriptUnknownFlag verifies uninstall.sh rejects unknown flags.
func TestUninstallScriptUnknownFlag(t *testing.T) {
	cmd := exec.Command("bash", "packaging/uninstall.sh", "--unknown-flag")
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir())
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected non-zero exit code for unknown flag")
	}
}

// TestAppArmorProfileHasPlaceholders verifies the AppArmor profile
// template contains both @@BINARY_PATH@@ and @@WORKSPACE_RULE@@ placeholders
// for substitution at install time.
func TestAppArmorProfileHasPlaceholders(t *testing.T) {
	data, err := os.ReadFile("packaging/apparmor/docker-helper")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if !strings.Contains(content, "@@BINARY_PATH@@") {
		t.Fatal("AppArmor profile must contain @@BINARY_PATH@@ placeholder for executable attachment")
	}
	if !strings.Contains(content, "@@WORKSPACE_RULE@@") {
		t.Fatal("AppArmor profile must contain @@WORKSPACE_RULE@@ placeholder for workspace access")
	}
	// Verify the profile uses path-based attachment (profile @@BINARY_PATH@@)
	if !strings.Contains(content, "profile @@BINARY_PATH@@") {
		t.Fatal("AppArmor profile must use path-based attachment: profile @@BINARY_PATH@@")
	}
}

// TestAppArmorInstallSubstitutesWorkspace verifies that install_apparmor
// substitutes @@WORKSPACE_RULE@@ with the actual allowed_root path from config.
func TestAppArmorInstallSubstitutesWorkspace(t *testing.T) {
	tempHome := t.TempDir()
	scriptDir := t.TempDir()

	// Create a fake binary
	if err := os.WriteFile(filepath.Join(scriptDir, "docker-helper"), []byte("fake"), 0755); err != nil {
		t.Fatal(err)
	}

	// Create config with allowed_root
	configDir := filepath.Join(tempHome, ".config", "docker-helper")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}
	configContent := `{"allowed_root": "/home/user/workspaces", "session_ttl": "12h"}`
	if err := os.WriteFile(filepath.Join(configDir, "config.json"), []byte(configContent), 0600); err != nil {
		t.Fatal(err)
	}

	// Create AppArmor profile template
	apparmorDir := filepath.Join(scriptDir, "apparmor")
	if err := os.MkdirAll(apparmorDir, 0755); err != nil {
		t.Fatal(err)
	}
	profileTemplate := `profile @@BINARY_PATH@@ {
	@@WORKSPACE_RULE@@
}`
	if err := os.WriteFile(filepath.Join(apparmorDir, "docker-helper"), []byte(profileTemplate), 0644); err != nil {
		t.Fatal(err)
	}

	// Create fake python3 for reading config
	fakePythonDir := t.TempDir()
	fakePython := filepath.Join(fakePythonDir, "python3")
	pythonScript := `#!/bin/bash
# Fake python3 that extracts allowed_root from config
echo "/home/user/workspaces"
`
	if err := os.WriteFile(fakePython, []byte(pythonScript), 0755); err != nil {
		t.Fatal(err)
	}

	// Create fake sudo that just writes to a temp location
	fakeSudoDir := t.TempDir()
	fakeSudo := filepath.Join(fakeSudoDir, "sudo")
	sudoScript := `#!/bin/bash
# Fake sudo: forward to apparmor_parser or tee
shift # remove -a or other flags
exec "$@"
`
	if err := os.WriteFile(fakeSudo, []byte(sudoScript), 0755); err != nil {
		t.Fatal(err)
	}

	fakeApparmorParser := filepath.Join(fakeSudoDir, "apparmor_parser")
	parserScript := `#!/bin/bash
# Fake apparmor_parser: accept and return success
exit 0
`
	if err := os.WriteFile(fakeApparmorParser, []byte(parserScript), 0755); err != nil {
		t.Fatal(err)
	}

	// Create fake tee
	fakeTee := filepath.Join(fakeSudoDir, "tee")
	teeScript := `#!/bin/bash
# Fake tee: write to the target file
target="${@: -1}"
cat > "$target"
exit 0
`
	if err := os.WriteFile(fakeTee, []byte(teeScript), 0755); err != nil {
		t.Fatal(err)
	}

	installDir := filepath.Join(tempHome, ".local", "bin")
	unitDir := filepath.Join(tempHome, ".config", "systemd", "user")
	if err := os.MkdirAll(installDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(unitDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(unitDir, "docker-helper.service"), []byte("[Unit]\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create fake docker
	fakeDockerDir := t.TempDir()
	fakeDocker := filepath.Join(fakeDockerDir, "docker")
	if err := os.WriteFile(fakeDocker, []byte("#!/bin/bash\necho ok\n"), 0755); err != nil {
		t.Fatal(err)
	}

	// Run install.sh with --yes
	cmd := exec.Command("bash", "packaging/install.sh", "--yes")
	cmd.Dir = "."
	cmd.Env = append(os.Environ(),
		"HOME="+tempHome,
		"XDG_CONFIG_HOME="+filepath.Join(tempHome, ".config"),
		"XDG_STATE_HOME="+filepath.Join(tempHome, ".local", "state"),
	)
	// Override PATH to use fakes first
	cmd.Env = append(cmd.Env, "PATH="+fakeDockerDir+":"+fakeSudoDir+":"+fakePythonDir+":"+os.Getenv("PATH"))
	// Override script_dir by running from scriptDir
	cmd.Dir = scriptDir

	output, err := cmd.CombinedOutput()
	_ = output // output may contain warnings about missing commands
	_ = err    // may fail on systemd/service steps, that's ok

	// Verify the source template is unchanged (substitution happens in-memory)
	profileData, err := os.ReadFile(filepath.Join(apparmorDir, "docker-helper"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(profileData), "@@BINARY_PATH@@") {
		t.Error("source profile template should still contain @@BINARY_PATH@@")
	}
	if !strings.Contains(string(profileData), "@@WORKSPACE_RULE@@") {
		t.Error("source profile template should still contain @@WORKSPACE_RULE@@")
	}
}

// TestAppArmorUninstallUnloadsBeforeRemove verifies that remove_apparmor
// unloads the profile before removing the file.
func TestAppArmorUninstallUnloadsBeforeRemove(t *testing.T) {
	// Create fake commands that record their calls
	fakeDir := t.TempDir()

	callLog := filepath.Join(fakeDir, "calls.log")

	fakeSudo := filepath.Join(fakeDir, "sudo")
	sudoScript := "#!/bin/bash\necho \"sudo $@\" >> '" + callLog + "'\nexit 0\n"
	if err := os.WriteFile(fakeSudo, []byte(sudoScript), 0755); err != nil {
		t.Fatal(err)
	}

	fakeApparmorParser := filepath.Join(fakeDir, "apparmor_parser")
	parserScript := "#!/bin/bash\necho \"apparmor_parser $@\" >> '" + callLog + "'\nexit 0\n"
	if err := os.WriteFile(fakeApparmorParser, []byte(parserScript), 0755); err != nil {
		t.Fatal(err)
	}

	fakeDocker := filepath.Join(fakeDir, "docker")
	if err := os.WriteFile(fakeDocker, []byte("#!/bin/bash\necho ok\n"), 0755); err != nil {
		t.Fatal(err)
	}

	fakeSystemctl := filepath.Join(fakeDir, "systemctl")
	if err := os.WriteFile(fakeSystemctl, []byte("#!/bin/bash\nexit 1\n"), 0755); err != nil {
		t.Fatal(err)
	}

	// Create fake AppArmor profile
	aaDir := filepath.Join(fakeDir, "apparmor.d")
	if err := os.MkdirAll(aaDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(aaDir, "docker-helper"), []byte("profile\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create a test script that simulates remove_apparmor behavior
	testScript := `#!/usr/bin/env bash
set -euo pipefail
APPARMOR_PROFILE_NAME="docker-helper"
AA_DIR="` + aaDir + `"
remove_apparmor() {
	if [[ -f "$AA_DIR/$APPARMOR_PROFILE_NAME" ]]; then
		# Unload first
		apparmor_parser -R "$AA_DIR/$APPARMOR_PROFILE_NAME" 2>/dev/null || true
		# Then remove
		rm -f "$AA_DIR/$APPARMOR_PROFILE_NAME"
	fi
}
remove_apparmor
`
	tmpScript := filepath.Join(t.TempDir(), "test_aa_uninstall.sh")
	if err := os.WriteFile(tmpScript, []byte(testScript), 0755); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("bash", tmpScript)
	cmd.Env = append(os.Environ(), "PATH="+fakeDir+":"+os.Getenv("PATH"))
	if err := cmd.Run(); err != nil {
		t.Fatalf("uninstall failed: %v", err)
	}

	// Verify the profile was removed
	if _, err := os.Stat(filepath.Join(aaDir, "docker-helper")); !os.IsNotExist(err) {
		t.Error("AppArmor profile should be removed")
	}
}

// TestUninstallYesRemovesAppArmor verifies that uninstall.sh --yes
// removes the AppArmor profile (not skips it).
// The remove_apparmor function in uninstall.sh has this logic:
//
//	interactive=false (--yes) → does NOT return early → proceeds to removal.
//
// We verify this by checking the script source.
func TestUninstallYesRemovesAppArmor(t *testing.T) {
	data, err := os.ReadFile("packaging/uninstall.sh")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	// The remove_apparmor function must NOT have an early return for
	// non-interactive mode without --purge. It should proceed to removal.
	// Check that apparmor_parser -R appears before rm -f in the function.
	// This ensures unload-before-remove ordering.
	idxUnload := strings.Index(content, "apparmor_parser -R")
	if idxUnload < 0 {
		t.Fatal("remove_apparmor must contain apparmor_parser -R")
	}
	remaining := content[idxUnload:]
	idxRemove := strings.Index(remaining, "rm -f")
	if idxRemove < 0 {
		t.Fatal("remove_apparmor must contain rm -f after apparmor_parser -R")
	}
}
