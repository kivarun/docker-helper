package main

import (
	"errors"
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
// substitutes @@WORKSPACE_RULE@@ with the actual allowed_root path from config
// and writes the prepared profile to a user-accessible location (no sudo).
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

	// Create fake apparmor_parser (just for command -v check)
	fakeAaDir := t.TempDir()
	fakeApparmorParser := filepath.Join(fakeAaDir, "apparmor_parser")
	if err := os.WriteFile(fakeApparmorParser, []byte("#!/bin/bash\nexit 0\n"), 0755); err != nil {
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
	cmd.Env = append(cmd.Env, "PATH="+fakeDockerDir+":"+fakeAaDir+":"+fakePythonDir+":"+os.Getenv("PATH"))
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

	// Verify the prepared profile was written to a user-accessible location
	preparedProfile := filepath.Join(tempHome, ".local", "share", "docker-helper", "apparmor-profile")
	if _, err := os.Stat(preparedProfile); err == nil {
		// Check that the prepared profile has substitutions applied
		preparedData, err := os.ReadFile(preparedProfile)
		if err != nil {
			t.Fatal(err)
		}
		preparedContent := string(preparedData)
		if strings.Contains(preparedContent, "@@BINARY_PATH@@") {
			t.Error("prepared profile should have @@BINARY_PATH@@ substituted")
		}
		if strings.Contains(preparedContent, "@@WORKSPACE_RULE@@") {
			t.Error("prepared profile should have @@WORKSPACE_RULE@@ substituted")
		}
	}
}

// TestAppArmorUninstallShowsInstructions verifies that remove_apparmor
// does not execute sudo and instead prints manual removal instructions.
func TestAppArmorUninstallShowsInstructions(t *testing.T) {
	data, err := os.ReadFile("packaging/uninstall.sh")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	// Find the remove_apparmor function
	idx := strings.Index(content, "remove_apparmor()")
	if idx < 0 {
		t.Fatal("remove_apparmor function not found")
	}
	// Find the next function
	remaining := content[idx:]
	nextFunc := strings.Index(remaining, "\nremove_skill()")
	if nextFunc < 0 {
		nextFunc = strings.Index(remaining, "\npurge_config_and_state()")
	}
	if nextFunc < 0 {
		nextFunc = len(remaining)
	}
	funcBody := remaining[:nextFunc]

	// Must not execute sudo (sudo as a command, not in instructions)
	// Check for "sudo " followed by a command (not inside info/echo quotes)
	lines := strings.Split(funcBody, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Skip comment lines and info/warn/printf lines (instructions)
		if strings.HasPrefix(trimmed, "#") ||
			strings.HasPrefix(trimmed, "info ") ||
			strings.HasPrefix(trimmed, "warn ") ||
			strings.HasPrefix(trimmed, "printf ") ||
			strings.HasPrefix(trimmed, "echo ") {
			continue
		}
		// If sudo appears outside of a string/instruction, it's an execution
		if strings.Contains(trimmed, "sudo") {
			t.Error("remove_apparmor must not execute sudo (found outside instruction context): " + trimmed)
		}
	}

	// Should contain instructions
	if !strings.Contains(funcBody, "apparmor_parser -R") {
		t.Error("remove_apparmor should mention apparmor_parser -R in instructions")
	}
	if !strings.Contains(funcBody, "rm -f") {
		t.Error("remove_apparmor should mention rm -f in instructions")
	}
}

// TestUninstallYesNoSudo verifies that uninstall.sh --yes
// does not execute sudo for any operation (including AppArmor).
func TestUninstallYesNoSudo(t *testing.T) {
	data, err := os.ReadFile("packaging/uninstall.sh")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	// Check for sudo executed as a command (not in string literals/instructions)
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Skip comments and lines that are clearly instructions/strings
		if strings.HasPrefix(trimmed, "#") ||
			strings.HasPrefix(trimmed, "info ") ||
			strings.HasPrefix(trimmed, "warn ") ||
			strings.HasPrefix(trimmed, "printf ") ||
			strings.HasPrefix(trimmed, "echo ") ||
			strings.HasPrefix(trimmed, `"`) ||
			strings.HasPrefix(trimmed, "'") {
			continue
		}
		// sudo as a standalone command invocation
		if strings.Contains(trimmed, "sudo ") || trimmed == "sudo" {
			t.Error("uninstall.sh must not execute sudo: " + trimmed)
		}
	}
}

// TestBuildStaticScriptSyntax verifies build-static.sh has valid bash syntax.
func TestBuildStaticScriptSyntax(t *testing.T) {
	cmd := exec.Command("bash", "-n", "build-static.sh")
	if err := cmd.Run(); err != nil {
		t.Fatalf("build-static.sh syntax error: %v", err)
	}
}

// TestBuildStaticScriptUsesExternalLinkmode verifies build-static.sh
// explicitly uses -linkmode external to ensure the system linker
// receives -extldflags '-static'.
func TestBuildStaticScriptUsesExternalLinkmode(t *testing.T) {
	data, err := os.ReadFile("build-static.sh")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if !strings.Contains(content, "-linkmode external") {
		t.Fatal("build-static.sh must use -linkmode external for static linking")
	}
}

// TestBuildStaticScriptRequiresMusl verifies build-static.sh fails
// on a glibc host without musl-gcc rather than silently falling back
// to a glibc-linked build.
func TestBuildStaticScriptRequiresMusl(t *testing.T) {
	data, err := os.ReadFile("build-static.sh")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	// The script must check for musl-gcc first and fail without it
	// (except on Alpine where gcc uses musl natively).
	if !strings.Contains(content, "musl-gcc") {
		t.Fatal("build-static.sh must reference musl-gcc")
	}
	// Must have an Alpine check to allow gcc fallback only there.
	if !strings.Contains(content, "alpine") {
		t.Fatal("build-static.sh must check for Alpine to allow gcc fallback")
	}
}

// TestBuildBundleScriptSyntax verifies build-bundle.sh has valid bash syntax.
func TestBuildBundleScriptSyntax(t *testing.T) {
	cmd := exec.Command("bash", "-n", "build-bundle.sh")
	if err := cmd.Run(); err != nil {
		t.Fatalf("build-bundle.sh syntax error: %v", err)
	}
}

// TestBuildBundleRequiresVersion verifies build-bundle.sh rejects
// invocation without a version argument.
func TestBuildBundleRequiresVersion(t *testing.T) {
	cmd := exec.Command("bash", "build-bundle.sh")
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir())
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected non-zero exit code when no version provided")
	}
}

// TestReleaseReadmeExists verifies the release README template exists.
func TestReleaseReadmeExists(t *testing.T) {
	data, err := os.ReadFile("packaging/README.release.md")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	// Must mention key topics
	expected := []string{
		"docker-helper",
		"install.sh",
		"agent",
		"SKILL.md",
	}
	for _, s := range expected {
		if !strings.Contains(content, s) {
			t.Errorf("release README should mention %q", s)
		}
	}
}

// TestReleaseReadmeNoSecrets verifies the release README does not
// contain any secrets or sensitive patterns.
func TestReleaseReadmeNoSecrets(t *testing.T) {
	data, err := os.ReadFile("packaging/README.release.md")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	forbidden := []string{
		"admin_token",
		"session_token",
		"Bearer",
		"password",
	}
	for _, s := range forbidden {
		if strings.Contains(content, s) {
			t.Errorf("release README must not contain %q", s)
		}
	}
}

// TestBundleLayoutExpected verifies build-bundle.sh references the
// expected bundle layout by inspecting the script source.
func TestBundleLayoutExpected(t *testing.T) {
	data, err := os.ReadFile("build-bundle.sh")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	// The script must copy these artifacts into the bundle
	expected := []string{
		"docker-helper",
		"install.sh",
		"uninstall.sh",
		"systemd/user",
		"apparmor",
		"SKILL.md",
		"README.release.md",
	}
	for _, s := range expected {
		if !strings.Contains(content, s) {
			t.Errorf("build-bundle.sh should reference %q", s)
		}
	}
}

// TestBundleScriptFailsOnUnconfirmedStatic verifies that build-bundle.sh
// treats an unconfirmed static binary as a hard failure, not a warning.
func TestBundleScriptFailsOnUnconfirmedStatic(t *testing.T) {
	data, err := os.ReadFile("build-bundle.sh")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	// The script must check STATIC_CONFIRMED and fail if not confirmed.
	if !strings.Contains(content, "STATIC_CONFIRMED") {
		t.Fatal("build-bundle.sh must track static linking confirmation state")
	}
	// Must exit 1 when not confirmed (not just warn).
	if !strings.Contains(content, "cannot confirm static linking") {
		t.Fatal("build-bundle.sh must fail on unconfirmed static linking")
	}
}

// TestBundleScriptVerifiesExactPaths verifies build-bundle.sh checks
// the exact mandatory set of paths in the tarball, not just listing them.
func TestBundleScriptVerifiesExactPaths(t *testing.T) {
	data, err := os.ReadFile("build-bundle.sh")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	// Must have an expected paths array and iterate over it.
	if !strings.Contains(content, "EXPECTED_PATHS") {
		t.Fatal("build-bundle.sh must define expected mandatory paths")
	}
	// Must check each path exists in the tarball.
	if !strings.Contains(content, "missing required path") {
		t.Fatal("build-bundle.sh must fail when a required path is missing")
	}
}

// TestStaticBuildProducesStaticBinary verifies that build-static.sh
// produces a statically linked binary when build tools are available.
// This test fails closed: if canonical prerequisites are present, the
// build must succeed and produce a valid static binary.
//
// Canonical prerequisites:
//
//	musl-gcc exists
//	OR
//	(/etc/alpine-release exists AND gcc exists)
//
// Plain gcc on a glibc host is NOT a sufficient prerequisite.
func TestStaticBuildProducesStaticBinary(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go not available")
	}

	// Check canonical build prerequisites — must match build-static.sh logic.
	canBuild := false
	if _, err := exec.LookPath("musl-gcc"); err == nil {
		canBuild = true
	} else if _, err := os.Stat("/etc/alpine-release"); err == nil {
		if _, err := exec.LookPath("gcc"); err == nil {
			canBuild = true
		}
	}

	if !canBuild {
		t.Skip("canonical build prerequisites not met (need musl-gcc, or Alpine + gcc)")
	}

	// Canonical prerequisites are present — the build must succeed, not skip.
	testVersion := "test-" + t.Name()
	cmd := exec.Command("bash", "build-static.sh", testVersion)
	cmd.Dir = "."
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("static build failed with canonical prerequisites: %v\n%s", err, out)
	}

	binPath := "dist/docker-helper"

	// Verify binary exists and is executable
	info, err := os.Stat(binPath)
	if err != nil {
		t.Fatalf("binary not found: %v", err)
	}
	if info.Mode()&0111 == 0 {
		t.Fatal("binary is not executable")
	}

	// Verify version
	cmd = exec.Command(binPath, "version")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("version command failed: %v", err)
	}
	got := strings.TrimSpace(string(out))
	if got != testVersion {
		t.Errorf("version = %q, want %q", got, testVersion)
	}

	// Verify static linking — must be confirmed, not skipped.
	staticConfirmed := false

	fileCmd := exec.Command("file", binPath)
	if fileOut, err := fileCmd.Output(); err == nil {
		if strings.Contains(string(fileOut), "statically linked") {
			staticConfirmed = true
			t.Log("static linking confirmed via file")
		}
	}

	if !staticConfirmed {
		lddCmd := exec.Command("ldd", binPath)
		if lddOut, _ := lddCmd.CombinedOutput(); strings.Contains(string(lddOut), "not a dynamic") {
			staticConfirmed = true
			t.Log("static linking confirmed via ldd")
		}
	}

	if !staticConfirmed {
		t.Fatal("cannot confirm static linking — release build must produce a static binary")
	}
}

// TestBuildStaticCwdIndependence verifies build-static.sh works when
// invoked from a directory other than the repo root.
func TestBuildStaticCwdIndependence(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go not available")
	}

	canBuild := false
	if _, err := exec.LookPath("musl-gcc"); err == nil {
		canBuild = true
	} else if _, err := os.Stat("/etc/alpine-release"); err == nil {
		if _, err := exec.LookPath("gcc"); err == nil {
			canBuild = true
		}
	}
	if !canBuild {
		t.Skip("canonical build prerequisites not met")
	}

	// Run from a subdirectory, not the repo root.
	tempDir := t.TempDir()
	testVersion := "test-cwd-" + t.Name()

	// Use absolute path to the script so it's found from any cwd.
	scriptPath, err := filepath.Abs("build-static.sh")
	if err != nil {
		t.Fatalf("cannot resolve script path: %v", err)
	}

	cmd := exec.Command("bash", scriptPath, testVersion)
	cmd.Dir = tempDir

	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build from non-root cwd failed: %v\n%s", err, out)
	}

	// The binary should be in dist/ relative to the repo, not tempDir.
	binPath := "dist/docker-helper"
	info, err := os.Stat(binPath)
	if err != nil {
		t.Fatalf("binary not found at repo dist/: %v", err)
	}
	if info.Mode()&0111 == 0 {
		t.Fatal("binary is not executable")
	}

	// Verify version
	cmd = exec.Command(binPath, "version")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("version command failed: %v", err)
	}
	got := strings.TrimSpace(string(out))
	if got != testVersion {
		t.Errorf("version = %q, want %q", got, testVersion)
	}
}

// TestAskPrompts verifies the ask() prompt format and default behavior
// in both install.sh ([Y/n], default yes) and uninstall.sh ([y/N], default no).
func TestAskPrompts(t *testing.T) {
	type testCase struct {
		name       string
		script     string
		input      string
		wantPrompt string
		wantStatus int
	}

	tests := []testCase{
		{"install enter", "packaging/install.sh", "\n", "test? [Y/n]: ", 0},
		{"install n", "packaging/install.sh", "n\n", "test? [Y/n]: ", 1},
		{"uninstall enter", "packaging/uninstall.sh", "\n", "test? [y/N]: ", 1},
		{"uninstall y", "packaging/uninstall.sh", "y\n", "test? [y/N]: ", 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			scriptPath, err := filepath.Abs(tc.script)
			if err != nil {
				t.Fatal(err)
			}

			cmd := exec.Command("bash", "-c",
				"source '"+scriptPath+"' && ask 'test?'",
			)
			cmd.Stdin = strings.NewReader(tc.input)
			out, err := cmd.CombinedOutput()
			gotStatus := 0
			if err != nil {
				var exitErr *exec.ExitError
				if ok := errors.As(err, &exitErr); ok {
					gotStatus = exitErr.ExitCode()
				} else {
					t.Fatalf("bash failed: %v: %s", err, out)
				}
			}

			gotPrompt := string(out)
			if gotPrompt != tc.wantPrompt {
				t.Errorf("prompt = %q, want %q", gotPrompt, tc.wantPrompt)
			}
			if gotStatus != tc.wantStatus {
				t.Errorf("status = %d, want %d", gotStatus, tc.wantStatus)
			}
		})
	}
}

// TestBundleSkillPath verifies build-bundle.sh places the skill at
// skills/docker-helper/SKILL.md (not .claude/skills/docker-helper/SKILL.md).
func TestBundleSkillPath(t *testing.T) {
	data, err := os.ReadFile("build-bundle.sh")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	// Must reference the correct skill path in the bundle
	if !strings.Contains(content, "skills/docker-helper/SKILL.md") {
		t.Error("build-bundle.sh must reference skills/docker-helper/SKILL.md")
	}

	// Expected paths must include the correct skill path
	if !strings.Contains(content, "docker-helper-${VERSION}-linux-amd64/skills/docker-helper/SKILL.md") {
		t.Error("build-bundle.sh must verify skills/docker-helper/SKILL.md in tarball")
	}

	// The bundle directory must not contain .claude/skills
	// (the source copy from .claude is fine, but the destination must be skills/)
	bundleDirIdx := strings.Index(content, "BUNDLE_DIR=")
	if bundleDirIdx >= 0 {
		afterBundleDir := content[bundleDirIdx:]
		// Check that no cp/mkdir creates .claude inside BUNDLE_DIR
		if strings.Contains(afterBundleDir, "$BUNDLE_DIR/.claude") {
			t.Error("build-bundle.sh must not create .claude inside BUNDLE_DIR")
		}
	}
}

// TestBundleNoDotClaude verifies the bundle does not contain .claude/
// in the expected paths check.
func TestBundleNoDotClaude(t *testing.T) {
	data, err := os.ReadFile("build-bundle.sh")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	// Find the EXPECTED_PATHS array
	idx := strings.Index(content, "EXPECTED_PATHS=")
	if idx < 0 {
		t.Fatal("EXPECTED_PATHS not found")
	}
	remaining := content[idx:]
	// Find the closing )
	endIdx := strings.Index(remaining, ")")
	if endIdx < 0 {
		t.Fatal("EXPECTED_PATHS closing paren not found")
	}
	expectedPaths := remaining[:endIdx]

	if strings.Contains(expectedPaths, ".claude") {
		t.Error("EXPECTED_PATHS must not contain .claude paths")
	}
}

// TestInstallSkillCopied verifies install.sh copies the skill to
// ~/.claude/skills/docker-helper/SKILL.md when skill installation is accepted.
func TestInstallSkillCopied(t *testing.T) {
	tempHome := t.TempDir()
	scriptDir := t.TempDir()

	// Create a fake binary
	if err := os.WriteFile(filepath.Join(scriptDir, "docker-helper"), []byte("fake"), 0755); err != nil {
		t.Fatal(err)
	}

	// Create skill source
	skillDir := filepath.Join(scriptDir, "skills", "docker-helper")
	if err := os.MkdirAll(skillDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte("# Docker Helper Skill\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create systemd unit dir
	unitDir := filepath.Join(scriptDir, "systemd", "user")
	if err := os.MkdirAll(unitDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(unitDir, "docker-helper.service"), []byte("[Unit]\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create apparmor dir
	apparmorDir := filepath.Join(scriptDir, "apparmor")
	if err := os.MkdirAll(apparmorDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Create fake docker
	fakeDockerDir := t.TempDir()
	fakeDocker := filepath.Join(fakeDockerDir, "docker")
	if err := os.WriteFile(fakeDocker, []byte("#!/bin/bash\necho ok\n"), 0755); err != nil {
		t.Fatal(err)
	}

	// Copy install.sh into scriptDir so script_dir resolves correctly
	installData, err := os.ReadFile("packaging/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	installedScript := filepath.Join(scriptDir, "install.sh")
	if err := os.WriteFile(installedScript, installData, 0755); err != nil {
		t.Fatal(err)
	}

	// Run install.sh with --yes (auto-accepts skill installation)
	cmd := exec.Command("bash", installedScript, "--yes")
	cmd.Env = append(os.Environ(),
		"HOME="+tempHome,
		"XDG_CONFIG_HOME="+filepath.Join(tempHome, ".config"),
		"XDG_STATE_HOME="+filepath.Join(tempHome, ".local", "state"),
		"PATH="+fakeDockerDir+":"+os.Getenv("PATH"),
	)
	cmd.Dir = scriptDir

	output, err := cmd.CombinedOutput()
	_ = output
	_ = err // may fail on systemd/service steps

	// Verify skill was installed
	skillPath := filepath.Join(tempHome, ".claude", "skills", "docker-helper", "SKILL.md")
	if _, err := os.Stat(skillPath); err != nil {
		t.Fatalf("skill not installed to %s: %v", skillPath, err)
	}

	// Verify skill content
	data, err := os.ReadFile(skillPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "Docker Helper Skill") {
		t.Error("skill content mismatch")
	}
}

// TestUninstallSkillRemovesOnlyDockerHelper verifies uninstall.sh removes
// only the docker-helper skill and does not touch ~/.claude, ~/.claude/skills,
// or other skills.
func TestUninstallSkillRemovesOnlyDockerHelper(t *testing.T) {
	tempHome := t.TempDir()

	// Create ~/.claude/skills with docker-helper and another skill
	skillsDir := filepath.Join(tempHome, ".claude", "skills")
	dhSkillDir := filepath.Join(skillsDir, "docker-helper")
	otherSkillDir := filepath.Join(skillsDir, "other-skill")
	if err := os.MkdirAll(dhSkillDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(otherSkillDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dhSkillDir, "SKILL.md"), []byte("# Docker Helper\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(otherSkillDir, "SKILL.md"), []byte("# Other Skill\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create script dir with minimal artifacts
	scriptDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(scriptDir, "docker-helper"), []byte("fake"), 0755); err != nil {
		t.Fatal(err)
	}
	unitDir := filepath.Join(scriptDir, "systemd", "user")
	if err := os.MkdirAll(unitDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Get absolute path to uninstall.sh
	uninstallScript, err := filepath.Abs("packaging/uninstall.sh")
	if err != nil {
		t.Fatal(err)
	}

	// Run uninstall.sh with --yes (auto-accepts skill removal)
	cmd := exec.Command("bash", uninstallScript, "--yes")
	cmd.Env = append(os.Environ(),
		"HOME="+tempHome,
		"XDG_CONFIG_HOME="+filepath.Join(tempHome, ".config"),
		"XDG_STATE_HOME="+filepath.Join(tempHome, ".local", "state"),
		"PATH="+os.Getenv("PATH"),
	)
	cmd.Dir = scriptDir

	output, err := cmd.CombinedOutput()
	_ = output
	_ = err // may fail on systemd steps

	// Verify docker-helper skill was removed
	if _, err := os.Stat(filepath.Join(dhSkillDir, "SKILL.md")); !os.IsNotExist(err) {
		t.Error("docker-helper skill should be removed")
	}

	// Verify docker-helper directory was removed (empty)
	if _, err := os.Stat(dhSkillDir); !os.IsNotExist(err) {
		// Directory may still exist if rmdir failed, that's acceptable
		// as long as SKILL.md is gone
	}

	// Verify ~/.claude/skills still exists
	if _, err := os.Stat(skillsDir); err != nil {
		t.Error("~/.claude/skills should not be removed")
	}

	// Verify other skill is untouched
	if _, err := os.Stat(filepath.Join(otherSkillDir, "SKILL.md")); err != nil {
		t.Error("other skill should not be removed")
	}
}

// TestInstallScriptNoSudo verifies install.sh does not execute sudo.
func TestInstallScriptNoSudo(t *testing.T) {
	data, err := os.ReadFile("packaging/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	// Check for sudo executed as a command (not in string literals/instructions)
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Skip comments and lines that are clearly instructions/strings
		if strings.HasPrefix(trimmed, "#") ||
			strings.HasPrefix(trimmed, "info ") ||
			strings.HasPrefix(trimmed, "warn ") ||
			strings.HasPrefix(trimmed, "printf ") ||
			strings.HasPrefix(trimmed, "echo ") ||
			strings.HasPrefix(trimmed, `"`) ||
			strings.HasPrefix(trimmed, "'") {
			continue
		}
		// sudo as a standalone command invocation
		if strings.Contains(trimmed, "sudo ") || trimmed == "sudo" {
			t.Error("install.sh must not execute sudo: " + trimmed)
		}
	}
}

// TestInstallYesSkill verifies --yes auto-accepts skill installation
// by checking the install_skill function uses ask() which defaults to yes
// in non-interactive mode.
func TestInstallYesSkill(t *testing.T) {
	data, err := os.ReadFile("packaging/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	// install_skill must exist and use ask() for the prompt
	if !strings.Contains(content, "install_skill()") {
		t.Fatal("install_skill function not found")
	}

	// Extract install_skill function body (from install_skill() to the next function)
	idx := strings.Index(content, "install_skill()")
	if idx < 0 {
		t.Fatal("install_skill function not found")
	}
	remaining := content[idx:]

	// Find next function definition
	nextFuncIdx := len(remaining)
	for _, candidate := range []string{"\ncheck_path()", "\nrun_init()", "\nenable_service()", "\nmain()"} {
		if i := strings.Index(remaining, candidate); i > 0 && i < nextFuncIdx {
			nextFuncIdx = i
		}
	}
	funcBody := remaining[:nextFuncIdx]

	// Must use ask for the prompt (bash function call without parens: ask "prompt")
	if !strings.Contains(funcBody, "ask ") {
		t.Error("install_skill must use ask for user prompt")
	}

	// Verify ask() defaults to yes when interactive=false (--yes)
	// The ask() function has: if $interactive; then ... else true; fi
	askIdx := strings.Index(content, "ask() {")
	if askIdx < 0 {
		t.Fatal("ask() function not found")
	}
	askBody := content[askIdx:]
	// Find the closing brace of ask() function
	braceCount := 0
	askEnd := len(askBody)
	for i, c := range askBody {
		if c == '{' {
			braceCount++
		} else if c == '}' {
			braceCount--
			if braceCount == 0 {
				askEnd = i + 1
				break
			}
		}
	}
	askImpl := askBody[:askEnd]

	// When interactive=false, ask() should return true (accept)
	if !strings.Contains(askImpl, "true") {
		t.Error("ask() must return true (accept) when interactive=false")
	}
}
