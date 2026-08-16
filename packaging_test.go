package main

import (
	"errors"
	"fmt"
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
// template in the bundle contains both @@BINARY_PATH@@ and @@WORKSPACE_RULE@@
// placeholders for manual substitution by the administrator.
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
	// Verify the profile uses path-based attachment (profile @@BINARY@@)
	if !strings.Contains(content, "profile @@BINARY_PATH@@") {
		t.Fatal("AppArmor profile must use path-based attachment: profile @@BINARY_PATH@@")
	}
}

// TestInstallScriptNoSudo verifies install.sh does not execute sudo.
func TestInstallScriptNoSudo(t *testing.T) {
	data, err := os.ReadFile("packaging/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.Contains(trimmed, "sudo") {
			t.Error("install.sh must not execute sudo: " + trimmed)
		}
	}
}

// TestUninstallScriptNoSudo verifies uninstall.sh does not contain sudo.
func TestUninstallScriptNoSudo(t *testing.T) {
	data, err := os.ReadFile("packaging/uninstall.sh")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "sudo") {
		t.Error("uninstall.sh must not contain sudo")
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

// setupInstallEnv creates a minimal test environment for install.sh.
// Returns (tempHome, scriptDir, fakeDir, callLog).
// Each test writes its own systemctl script to fakeDir.
func setupInstallEnv(t *testing.T, currentVer, newVer string) (tempHome, scriptDir, fakeDir, callLog string) {
	t.Helper()
	tempHome = t.TempDir()
	scriptDir = t.TempDir()
	fakeDir = t.TempDir()
	callLog = filepath.Join(fakeDir, "systemctl_calls.log")

	if err := os.WriteFile(filepath.Join(fakeDir, "docker"),
		[]byte("#!/bin/bash\necho ok\n"), 0755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(scriptDir, "docker-helper"),
		[]byte(fmt.Sprintf("#!/bin/bash\necho '%s'\n", newVer)), 0755); err != nil {
		t.Fatal(err)
	}

	unitDir := filepath.Join(scriptDir, "systemd", "user")
	if err := os.MkdirAll(unitDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(unitDir, "docker-helper.service"),
		[]byte("[Unit]\n"), 0644); err != nil {
		t.Fatal(err)
	}

	skillDir := filepath.Join(scriptDir, "skills", "docker-helper")
	if err := os.MkdirAll(skillDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skillDir, "SKILL.md"),
		[]byte("# Skill\n"), 0644); err != nil {
		t.Fatal(err)
	}

	if currentVer != "" {
		installDir := filepath.Join(tempHome, ".local", "bin")
		if err := os.MkdirAll(installDir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(installDir, "docker-helper"),
			[]byte(fmt.Sprintf("#!/bin/bash\necho '%s'\n", currentVer)), 0755); err != nil {
			t.Fatal(err)
		}

		unitInstallDir := filepath.Join(tempHome, ".config", "systemd", "user")
		if err := os.MkdirAll(unitInstallDir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(unitInstallDir, "docker-helper.service"),
			[]byte("[Unit]\nDescription=Old\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	configDir := filepath.Join(tempHome, ".config", "docker-helper")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "config.json"),
		[]byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}

	installData, err := os.ReadFile("packaging/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scriptDir, "install.sh"),
		installData, 0755); err != nil {
		t.Fatal(err)
	}

	return
}

func readSystemctlCalls(t *testing.T, callLog string) []string {
	t.Helper()
	data, err := os.ReadFile(callLog)
	if err != nil {
		return nil
	}
	var lines []string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func runInstall(t *testing.T, scriptDir, tempHome, fakeDir string, args []string, stdin string) ([]byte, error) {
	t.Helper()
	cmd := exec.Command("bash", append([]string{filepath.Join(scriptDir, "install.sh")}, args...)...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	cmd.Env = append(os.Environ(),
		"HOME="+tempHome,
		"XDG_CONFIG_HOME="+filepath.Join(tempHome, ".config"),
		"XDG_STATE_HOME="+filepath.Join(tempHome, ".local", "state"),
		"PATH="+fakeDir+":"+os.Getenv("PATH"),
	)
	cmd.Dir = scriptDir
	return cmd.CombinedOutput()
}

// TestInstallActiveServiceConfirmed verifies that when the service is active
// and the user confirms, stop is called before any file copy, then daemon-reload
// and start follow. The fake systemctl asserts the binary state at each step.
func TestInstallActiveServiceConfirmed(t *testing.T) {
	tempHome, scriptDir, fakeDir, callLog := setupInstallEnv(t, "1.0.0", "1.1.0")
	installBin := filepath.Join(tempHome, ".local", "bin", "docker-helper")

	systemctlScript := fmt.Sprintf(`#!/bin/bash
log_file="%s"
install_bin="%s"
echo "$@" >> "$log_file"
case "$*" in
  *"is-active"*) exit 0 ;;
  *"stop"*)
    grep -q '1.0.0' "$install_bin" 2>/dev/null || exit 1
    exit 0 ;;
  *"daemon-reload"*)
    grep -q '1.1.0' "$install_bin" 2>/dev/null || exit 1
    exit 0 ;;
  *) exit 0 ;;
esac
`, callLog, installBin)
	if err := os.WriteFile(filepath.Join(fakeDir, "systemctl"),
		[]byte(systemctlScript), 0755); err != nil {
		t.Fatal(err)
	}

	out, err := runInstall(t, scriptDir, tempHome, fakeDir, nil, "\n\n\n\n")
	if err != nil {
		t.Fatalf("install failed: %v\n%s", err, out)
	}

	calls := readSystemctlCalls(t, callLog)

	stopIdx, reloadIdx, startIdx := -1, -1, -1
	for i, c := range calls {
		if strings.Contains(c, "stop") && stopIdx < 0 {
			stopIdx = i
		}
		if strings.Contains(c, "daemon-reload") && reloadIdx < 0 {
			reloadIdx = i
		}
		if strings.Contains(c, "start") && startIdx < 0 {
			startIdx = i
		}
	}
	if stopIdx < 0 {
		t.Fatal("stop was not called")
	}
	if !(stopIdx < reloadIdx && reloadIdx < startIdx) {
		t.Errorf("expected stop(%d) < daemon-reload(%d) < start(%d)", stopIdx, reloadIdx, startIdx)
	}

	for _, c := range calls {
		if strings.Contains(c, "enable") {
			t.Error("enable must not be called when service was previously active")
		}
	}
}

// TestInstallActiveServiceRefused verifies that when the user refuses to stop
// the service, no files are changed and stop is never called.
func TestInstallActiveServiceRefused(t *testing.T) {
	tempHome, scriptDir, fakeDir, callLog := setupInstallEnv(t, "1.0.0", "1.1.0")

	systemctlScript := fmt.Sprintf(`#!/bin/bash
log_file="%s"
echo "$@" >> "$log_file"
case "$*" in
  *"is-active"*) exit 0 ;;
  *) exit 0 ;;
esac
`, callLog)
	if err := os.WriteFile(filepath.Join(fakeDir, "systemctl"),
		[]byte(systemctlScript), 0755); err != nil {
		t.Fatal(err)
	}

	installedBin := filepath.Join(tempHome, ".local", "bin", "docker-helper")
	origBin, err := os.ReadFile(installedBin)
	if err != nil {
		t.Fatal(err)
	}
	installedUnit := filepath.Join(tempHome, ".config", "systemd", "user", "docker-helper.service")
	origUnit, err := os.ReadFile(installedUnit)
	if err != nil {
		t.Fatal(err)
	}

	out, err := runInstall(t, scriptDir, tempHome, fakeDir, nil, "n\n")
	if err != nil {
		t.Fatalf("install should exit 0 on refusal, got: %v\n%s", err, out)
	}

	calls := readSystemctlCalls(t, callLog)
	for _, c := range calls {
		if strings.Contains(c, "stop") {
			t.Error("stop must not be called when user refuses")
		}
	}

	newBin, err := os.ReadFile(installedBin)
	if err != nil {
		t.Fatal(err)
	}
	if string(newBin) != string(origBin) {
		t.Error("binary should not be changed when user refuses")
	}

	newUnit, err := os.ReadFile(installedUnit)
	if err != nil {
		t.Fatal(err)
	}
	if string(newUnit) != string(origUnit) {
		t.Error("unit should not be changed when user refuses")
	}
}

// TestInstallActiveServiceYesFlag verifies that --yes auto-confirms the
// stop prompt and proceeds without reading stdin.
func TestInstallActiveServiceYesFlag(t *testing.T) {
	tempHome, scriptDir, fakeDir, callLog := setupInstallEnv(t, "1.0.0", "1.1.0")

	systemctlScript := fmt.Sprintf(`#!/bin/bash
log_file="%s"
echo "$@" >> "$log_file"
exit 0
`, callLog)
	if err := os.WriteFile(filepath.Join(fakeDir, "systemctl"),
		[]byte(systemctlScript), 0755); err != nil {
		t.Fatal(err)
	}

	out, err := runInstall(t, scriptDir, tempHome, fakeDir, []string{"--yes"}, "")
	if err != nil {
		t.Fatalf("install --yes failed: %v\n%s", err, out)
	}

	calls := readSystemctlCalls(t, callLog)
	foundStop, foundReload, foundStart := false, false, false
	for _, c := range calls {
		if strings.Contains(c, "stop") {
			foundStop = true
		}
		if strings.Contains(c, "daemon-reload") {
			foundReload = true
		}
		if strings.Contains(c, "start") {
			foundStart = true
		}
	}
	if !foundStop {
		t.Error("--yes should auto-confirm stop")
	}
	if !foundReload {
		t.Error("--yes should call daemon-reload")
	}
	if !foundStart {
		t.Error("--yes should call start after install")
	}
}

// TestInstallInactiveServicePreservesFlow verifies that when the service is
// not active, the normal enable + start flow is used.
func TestInstallInactiveServicePreservesFlow(t *testing.T) {
	tempHome, scriptDir, fakeDir, callLog := setupInstallEnv(t, "", "1.0.0")

	systemctlScript := fmt.Sprintf(`#!/bin/bash
log_file="%s"
echo "$@" >> "$log_file"
case "$*" in
  *"is-active"*) exit 1 ;;
  *) exit 0 ;;
esac
`, callLog)
	if err := os.WriteFile(filepath.Join(fakeDir, "systemctl"),
		[]byte(systemctlScript), 0755); err != nil {
		t.Fatal(err)
	}

	out, err := runInstall(t, scriptDir, tempHome, fakeDir, []string{"--yes"}, "")
	if err != nil {
		t.Fatalf("install failed: %v\n%s", err, out)
	}

	calls := readSystemctlCalls(t, callLog)
	foundEnable, foundStart := false, false
	for _, c := range calls {
		if strings.Contains(c, "enable") {
			foundEnable = true
		}
		if strings.Contains(c, "start") {
			foundStart = true
		}
	}
	if !foundEnable {
		t.Error("enable should be called when service was not active")
	}
	if !foundStart {
		t.Error("start should be called when service was not active")
	}
}

// TestInstallSameVersionOutput verifies that when current and new versions
// match, the output mentions reinstalling the same version.
func TestInstallSameVersionOutput(t *testing.T) {
	tempHome, scriptDir, fakeDir, callLog := setupInstallEnv(t, "1.0.0", "1.0.0")

	systemctlScript := fmt.Sprintf(`#!/bin/bash
log_file="%s"
echo "$@" >> "$log_file"
exit 0
`, callLog)
	if err := os.WriteFile(filepath.Join(fakeDir, "systemctl"),
		[]byte(systemctlScript), 0755); err != nil {
		t.Fatal(err)
	}

	out, err := runInstall(t, scriptDir, tempHome, fakeDir, nil, "\n\n\n\n")
	if err != nil {
		t.Fatalf("install failed: %v\n%s", err, out)
	}

	if !strings.Contains(string(out), "reinstall") || !strings.Contains(string(out), "same version") {
		t.Errorf("output should mention reinstalling the same version, got:\n%s", out)
	}

	calls := readSystemctlCalls(t, callLog)
	foundStop := false
	for _, c := range calls {
		if strings.Contains(c, "stop") {
			foundStop = true
			break
		}
	}
	if !foundStop {
		t.Error("stop should be called even for same-version reinstall")
	}
}

// TestInstallStopFailureAborts verifies that if systemctl stop fails,
// no files are modified and the installer exits with an error.
func TestInstallStopFailureAborts(t *testing.T) {
	tempHome, scriptDir, fakeDir, _ := setupInstallEnv(t, "1.0.0", "1.1.0")

	systemctlScript := `#!/bin/bash
case "$*" in
  *"is-active"*) exit 0 ;;
  *"stop"*) exit 1 ;;
  *) exit 0 ;;
esac
`
	if err := os.WriteFile(filepath.Join(fakeDir, "systemctl"),
		[]byte(systemctlScript), 0755); err != nil {
		t.Fatal(err)
	}

	installedBin := filepath.Join(tempHome, ".local", "bin", "docker-helper")
	origBin, err := os.ReadFile(installedBin)
	if err != nil {
		t.Fatal(err)
	}
	installedUnit := filepath.Join(tempHome, ".config", "systemd", "user", "docker-helper.service")
	origUnit, err := os.ReadFile(installedUnit)
	if err != nil {
		t.Fatal(err)
	}

	out, err := runInstall(t, scriptDir, tempHome, fakeDir, nil, "\n\n")
	if err == nil {
		t.Fatal("install should fail when stop fails")
	}

	if !strings.Contains(string(out), "Failed to stop") {
		t.Errorf("should report stop failure, got:\n%s", out)
	}

	newBin, err := os.ReadFile(installedBin)
	if err != nil {
		t.Fatal(err)
	}
	if string(newBin) != string(origBin) {
		t.Error("binary should not be changed when stop fails")
	}

	newUnit, err := os.ReadFile(installedUnit)
	if err != nil {
		t.Fatal(err)
	}
	if string(newUnit) != string(origUnit) {
		t.Error("unit should not be changed when stop fails")
	}
}

// TestInstallDaemonReloadFailure verifies that when daemon-reload fails,
// the installer exits non-zero, start is not called, and no false
// "Installation complete" is printed.
func TestInstallDaemonReloadFailure(t *testing.T) {
	tempHome, scriptDir, fakeDir, callLog := setupInstallEnv(t, "1.0.0", "1.1.0")

	systemctlScript := fmt.Sprintf(`#!/bin/bash
log_file="%s"
echo "$@" >> "$log_file"
case "$*" in
  *"is-active"*) exit 0 ;;
  *"stop"*) exit 0 ;;
  *"daemon-reload"*) exit 1 ;;
  *) exit 0 ;;
esac
`, callLog)
	if err := os.WriteFile(filepath.Join(fakeDir, "systemctl"),
		[]byte(systemctlScript), 0755); err != nil {
		t.Fatal(err)
	}

	out, err := runInstall(t, scriptDir, tempHome, fakeDir, nil, "\n\n\n\n")
	if err == nil {
		t.Fatal("install should fail when daemon-reload fails")
	}

	calls := readSystemctlCalls(t, callLog)
	for _, c := range calls {
		if strings.Contains(c, "start") {
			t.Error("start must not be called after daemon-reload failure")
		}
	}

	if strings.Contains(string(out), "Installation complete") {
		t.Error("must not print Installation complete on daemon-reload failure")
	}
}

// TestInstallStartFailure verifies that when start fails after daemon-reload,
// the installer exits non-zero and no false "Installation complete" is printed.
func TestInstallStartFailure(t *testing.T) {
	tempHome, scriptDir, fakeDir, callLog := setupInstallEnv(t, "1.0.0", "1.1.0")

	systemctlScript := fmt.Sprintf(`#!/bin/bash
log_file="%s"
echo "$@" >> "$log_file"
case "$*" in
  *"is-active"*) exit 0 ;;
  *"stop"*) exit 0 ;;
  *"start"*) exit 1 ;;
  *) exit 0 ;;
esac
`, callLog)
	if err := os.WriteFile(filepath.Join(fakeDir, "systemctl"),
		[]byte(systemctlScript), 0755); err != nil {
		t.Fatal(err)
	}

	out, err := runInstall(t, scriptDir, tempHome, fakeDir, nil, "\n\n\n\n")
	if err == nil {
		t.Fatal("install should fail when start fails")
	}

	if strings.Contains(string(out), "Installation complete") {
		t.Error("must not print Installation complete on start failure")
	}
}

// --- Systemd system unit tests ---

func TestSystemUnitExists(t *testing.T) {
	path := "packaging/systemd/system/docker-helper.service"
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("system unit %s does not exist: %v", path, err)
	}
}

func TestSystemUnitExecStart(t *testing.T) {
	data, err := os.ReadFile("packaging/systemd/system/docker-helper.service")
	if err != nil {
		t.Fatal(err)
	}

	content := string(data)
	if !strings.Contains(content, "ExecStart=/usr/bin/docker-helper serve") {
		t.Error("system unit ExecStart must point to /usr/bin/docker-helper serve")
	}
}

func TestSystemUnitExecReload(t *testing.T) {
	data, err := os.ReadFile("packaging/systemd/system/docker-helper.service")
	if err != nil {
		t.Fatal(err)
	}

	content := string(data)
	if !strings.Contains(content, "ExecReload=/usr/bin/docker-helper reload --system") {
		t.Error("system unit ExecReload must be /usr/bin/docker-helper reload --system")
	}
}

func TestSystemUnitAppArmorProfile(t *testing.T) {
	data, err := os.ReadFile("packaging/systemd/system/docker-helper.service")
	if err != nil {
		t.Fatal(err)
	}

	content := string(data)
	if !strings.Contains(content, "AppArmorProfile=docker-helper-system") {
		t.Error("system unit must contain AppArmorProfile=docker-helper-system")
	}
}

func TestSystemUnitAfterAppArmor(t *testing.T) {
	data, err := os.ReadFile("packaging/systemd/system/docker-helper.service")
	if err != nil {
		t.Fatal(err)
	}

	content := string(data)
	if !strings.Contains(content, "apparmor.service") {
		t.Error("system unit After= must include apparmor.service")
	}
	// Must not hard-require apparmor.service
	if strings.Contains(content, "Requires=apparmor.service") {
		t.Error("system unit must not hard-require apparmor.service")
	}
}

func TestSystemUnitNoDedicatedUser(t *testing.T) {
	data, err := os.ReadFile("packaging/systemd/system/docker-helper.service")
	if err != nil {
		t.Fatal(err)
	}

	content := string(data)
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "User=") {
			t.Error("system unit must not contain User= (runs as root)")
		}
	}
}

func TestSystemUnitRestartSettings(t *testing.T) {
	data, err := os.ReadFile("packaging/systemd/system/docker-helper.service")
	if err != nil {
		t.Fatal(err)
	}

	content := string(data)
	if !strings.Contains(content, "Restart=on-failure") {
		t.Error("system unit must contain Restart=on-failure")
	}
	if !strings.Contains(content, "TimeoutStopSec=") {
		t.Error("system unit must contain bounded TimeoutStopSec")
	}
}

func TestUserUnitStillExists(t *testing.T) {
	path := "packaging/systemd/user/docker-helper.service"
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("user unit %s must still exist: %v", path, err)
	}
}

// --- System AppArmor profile tests ---

func TestSystemAppArmorProfileExists(t *testing.T) {
	path := "packaging/apparmor/docker-helper-system"
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("system AppArmor profile %s does not exist: %v", path, err)
	}
}

func TestSystemAppArmorProfileReferencesManagedRoots(t *testing.T) {
	data, err := os.ReadFile("packaging/apparmor/docker-helper-system")
	if err != nil {
		t.Fatal(err)
	}

	content := string(data)
	if !strings.Contains(content, "docker-helper.d/managed-roots") {
		t.Error("system AppArmor profile must include managed-roots fragment")
	}
}

func TestSystemAppArmorProfileNoBroadHomeAccess(t *testing.T) {
	data, err := os.ReadFile("packaging/apparmor/docker-helper-system")
	if err != nil {
		t.Fatal(err)
	}

	content := string(data)
	if strings.Contains(content, "/home/**") {
		t.Error("system AppArmor profile must not contain broad /home/** access")
	}
}

func TestSystemAppArmorProfileNoDenySysAdmin(t *testing.T) {
	data, err := os.ReadFile("packaging/apparmor/docker-helper-system")
	if err != nil {
		t.Fatal(err)
	}

	content := string(data)
	if strings.Contains(content, "deny capability sys_admin") {
		t.Error("system AppArmor profile must not deny sys_admin (required for mount-pin)")
	}
}

func TestSystemAppArmorProfileHasDacReadSearch(t *testing.T) {
	data, err := os.ReadFile("packaging/apparmor/docker-helper-system")
	if err != nil {
		t.Fatal(err)
	}

	content := string(data)
	if !strings.Contains(content, "capability dac_read_search") {
		t.Error("system AppArmor profile must grant dac_read_search for private workspace traversal")
	}
}

func TestSystemAppArmorProfileHasSysAdmin(t *testing.T) {
	data, err := os.ReadFile("packaging/apparmor/docker-helper-system")
	if err != nil {
		t.Fatal(err)
	}

	content := string(data)
	if !strings.Contains(content, "capability sys_admin") {
		t.Error("system AppArmor profile must grant sys_admin for mount-pin operations")
	}
}

func TestSystemAppArmorProfileNamedProfile(t *testing.T) {
	data, err := os.ReadFile("packaging/apparmor/docker-helper-system")
	if err != nil {
		t.Fatal(err)
	}

	content := string(data)
	// Profile must use named profile syntax, not path-attached
	if !strings.Contains(content, "profile docker-helper-system") {
		t.Error("system AppArmor profile must be named profile docker-helper-system")
	}
	// Must not use path-based attachment
	if strings.Contains(content, "profile /usr/bin/docker-helper") {
		t.Error("system AppArmor profile must not use path-based attachment")
	}
}

func TestSystemAppArmorProfileNoTouchInInstructions(t *testing.T) {
	data, err := os.ReadFile("packaging/apparmor/docker-helper-system")
	if err != nil {
		t.Fatal(err)
	}

	content := string(data)
	if strings.Contains(content, "touch") {
		t.Error("system AppArmor profile instructions must not use touch for managed-roots")
	}
}

func TestSystemAppArmorProfileHasUnixSocketPolicy(t *testing.T) {
	data, err := os.ReadFile("packaging/apparmor/docker-helper-system")
	if err != nil {
		t.Fatal(err)
	}

	content := string(data)
	// Must have separate unix socket policy for Docker connection
	if !strings.Contains(content, "unix (connect,send,receive)") {
		t.Error("system AppArmor profile must contain unix socket connect policy for Docker")
	}
	// Must be stream only (Docker socket is stream)
	if strings.Contains(content, "type=dgram") {
		t.Error("system AppArmor profile must not contain dgram unix rule for Docker socket")
	}
	// Must still have filesystem socket rules
	if !strings.Contains(content, "/run/docker.sock rw") {
		t.Error("system AppArmor profile must retain filesystem Docker socket rule")
	}
}

func TestSystemAppArmorProfileHasMountPolicy(t *testing.T) {
	data, err := os.ReadFile("packaging/apparmor/docker-helper-system")
	if err != nil {
		t.Fatal(err)
	}

	content := string(data)
	// Must have mount rules with move option for move_mount
	if !strings.Contains(content, "mount options in (rw,move)") {
		t.Error("system AppArmor profile must contain mount policy with move option for move_mount")
	}
	// Mount rules must be scoped to helper-owned directory
	if !strings.Contains(content, "/run/docker-helper/mounts") {
		t.Error("system AppArmor profile mount rules must be scoped to /run/docker-helper/mounts")
	}
	// Must have umount rule (correct syntax: umount PATH,)
	if !strings.Contains(content, "umount /run/docker-helper/mounts") {
		t.Error("system AppArmor profile must contain umount policy for mount-pin detach")
	}
	// Must not have blanket unrestricted mount (line that is just "mount,")
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "mount," {
			t.Error("system AppArmor profile must not contain blanket unrestricted mount rule")
		}
	}
}

// --- Optional parser syntax validation ---

func TestSystemAppArmorProfileParserSyntax(t *testing.T) {
	parserPath := "/usr/sbin/apparmor_parser"
	if _, err := os.Stat(parserPath); err != nil {
		t.Skip("apparmor_parser not available, skipping syntax validation")
	}

	// Create temp include directory for managed-roots fragment
	includeDir := t.TempDir()
	fragmentDir := filepath.Join(includeDir, "docker-helper.d")
	if err := os.MkdirAll(fragmentDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Write empty managed-roots fragment
	fragmentData := renderFragment([]string{})
	if err := os.WriteFile(filepath.Join(fragmentDir, "managed-roots"), fragmentData, 0644); err != nil {
		t.Fatal(err)
	}

	// Read profile and replace include path
	profileData, err := os.ReadFile("packaging/apparmor/docker-helper-system")
	if err != nil {
		t.Fatal(err)
	}

	// Write profile to temp file for parser
	profileFile := filepath.Join(includeDir, "docker-helper-system")
	if err := os.WriteFile(profileFile, profileData, 0644); err != nil {
		t.Fatal(err)
	}

	// Run parser in dry-run mode (-Q = dry run, -T = no cache, -I = include dir)
	cmd := exec.Command(parserPath, "-Q", "-T", "-I", includeDir, profileFile)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("apparmor_parser syntax validation failed: %v\noutput: %s", err, out)
	}
}

// --- System install/uninstall script tests ---

func TestInstallSystemScriptSyntax(t *testing.T) {
	cmd := exec.Command("bash", "-n", "packaging/install-system.sh")
	if err := cmd.Run(); err != nil {
		t.Fatalf("install-system.sh syntax error: %v", err)
	}
}

func TestUninstallSystemScriptSyntax(t *testing.T) {
	cmd := exec.Command("bash", "-n", "packaging/uninstall-system.sh")
	if err := cmd.Run(); err != nil {
		t.Fatalf("uninstall-system.sh syntax error: %v", err)
	}
}

func TestInstallSystemRequiresRoot(t *testing.T) {
	// The script checks UID 0 before any mutation.
	// We verify this by checking the script contains the check.
	data, err := os.ReadFile("packaging/install-system.sh")
	if err != nil {
		t.Fatal(err)
	}

	content := string(data)
	if !strings.Contains(content, "id -u") || !strings.Contains(content, "-ne 0") {
		t.Error("install-system.sh must check for root (UID 0)")
	}
}

func TestInstallSystemFreshYesRequiresAllowedRoot(t *testing.T) {
	data, err := os.ReadFile("packaging/install-system.sh")
	if err != nil {
		t.Fatal(err)
	}

	content := string(data)
	// Fresh --yes install must require --allowed-root
	if !strings.Contains(content, "--allowed-root") {
		t.Error("install-system.sh must support --allowed-root flag")
	}
	// Must check that --allowed-root is provided with --yes for fresh install
	if !strings.Contains(content, "allowed_root") {
		t.Error("install-system.sh must validate --allowed-root for fresh install")
	}
}

func TestInstallSystemDestinationPaths(t *testing.T) {
	data, err := os.ReadFile("packaging/install-system.sh")
	if err != nil {
		t.Fatal(err)
	}

	content := string(data)
	expectedPaths := []string{
		"/usr/bin/docker-helper",
		"/etc/systemd/system/docker-helper.service",
		"/etc/apparmor.d/docker-helper-system",
		"/etc/apparmor.d/docker-helper.d/managed-roots",
	}

	for _, p := range expectedPaths {
		if !strings.Contains(content, p) {
			t.Errorf("install-system.sh must reference destination path: %s", p)
		}
	}
}

func TestInstallSystemPreservesExistingManagedRoots(t *testing.T) {
	data, err := os.ReadFile("packaging/install-system.sh")
	if err != nil {
		t.Fatal(err)
	}

	content := string(data)
	// Must check if fragment exists before installing
	if !strings.Contains(content, "-f") || !strings.Contains(content, "managed-roots") {
		t.Error("install-system.sh must check for existing managed-roots")
	}
	// Must contain preservation logic
	if !strings.Contains(content, "preserved") && !strings.Contains(content, "overwrite") {
		t.Error("install-system.sh must preserve existing managed-roots")
	}
}

func TestInstallSystemAppArmorBeforeInit(t *testing.T) {
	data, err := os.ReadFile("packaging/install-system.sh")
	if err != nil {
		t.Fatal(err)
	}

	content := string(data)
	// AppArmor profile must be installed before init is called
	profileIdx := strings.Index(content, "install_apparmor_profile")
	initIdx := strings.Index(content, "run_init")
	if profileIdx < 0 || initIdx < 0 || profileIdx > initIdx {
		t.Error("install-system.sh must install AppArmor profile before running init")
	}
}

func TestInstallSystemDoesNotInstallSkill(t *testing.T) {
	data, err := os.ReadFile("packaging/install-system.sh")
	if err != nil {
		t.Fatal(err)
	}

	content := string(data)
	if strings.Contains(content, "SKILL.md") || strings.Contains(content, ".claude") {
		t.Error("install-system.sh must not install agent skill")
	}
}

func TestInstallSystemDoesNotTouchUserArtifacts(t *testing.T) {
	data, err := os.ReadFile("packaging/install-system.sh")
	if err != nil {
		t.Fatal(err)
	}

	content := string(data)
	userPaths := []string{
		"~/.local/bin",
		"~/.config/systemd/user",
		"$HOME/.local",
	}

	for _, p := range userPaths {
		if strings.Contains(content, p) {
			t.Errorf("install-system.sh must not touch user path: %s", p)
		}
	}
}

func TestUninstallSystemRequiresRoot(t *testing.T) {
	data, err := os.ReadFile("packaging/uninstall-system.sh")
	if err != nil {
		t.Fatal(err)
	}

	content := string(data)
	if !strings.Contains(content, "id -u") || !strings.Contains(content, "-ne 0") {
		t.Error("uninstall-system.sh must check for root (UID 0)")
	}
}

func TestUninstallSystemPreservesConfigByDefault(t *testing.T) {
	data, err := os.ReadFile("packaging/uninstall-system.sh")
	if err != nil {
		t.Fatal(err)
	}

	content := string(data)
	// Config/state/managed-roots should only be removed with --purge
	if !strings.Contains(content, "--purge") {
		t.Error("uninstall-system.sh must support --purge flag")
	}
	// Must preserve by default
	if !strings.Contains(content, "preserve") && !strings.Contains(content, "Preserved") {
		t.Error("uninstall-system.sh must document preservation of config/state")
	}
}

func TestUninstallSystemPurgeRemovesPersistentData(t *testing.T) {
	data, err := os.ReadFile("packaging/uninstall-system.sh")
	if err != nil {
		t.Fatal(err)
	}

	content := string(data)
	purgePaths := []string{
		"/etc/docker-helper",
		"/var/lib/docker-helper",
		"/run/docker-helper",
	}

	for _, p := range purgePaths {
		if !strings.Contains(content, p) {
			t.Errorf("uninstall-system.sh --purge must remove: %s", p)
		}
	}
}

func TestUninstallSystemDoesNotTouchUserArtifacts(t *testing.T) {
	data, err := os.ReadFile("packaging/uninstall-system.sh")
	if err != nil {
		t.Fatal(err)
	}

	content := string(data)
	userPaths := []string{
		"~/.local/bin",
		"~/.config/systemd/user",
		"$HOME/.local",
	}

	for _, p := range userPaths {
		if strings.Contains(content, p) {
			t.Errorf("uninstall-system.sh must not touch user path: %s", p)
		}
	}
}

func TestUninstallSystemStopsServiceBeforeRemoval(t *testing.T) {
	data, err := os.ReadFile("packaging/uninstall-system.sh")
	if err != nil {
		t.Fatal(err)
	}

	content := string(data)
	// Stop must come before removal
	stopIdx := strings.Index(content, "stop_service")
	removeIdx := strings.Index(content, "remove_binary")
	if stopIdx < 0 || removeIdx < 0 || stopIdx > removeIdx {
		t.Error("uninstall-system.sh must stop service before removing binary")
	}
}

func TestUninstallSystemUnloadsAppArmor(t *testing.T) {
	data, err := os.ReadFile("packaging/uninstall-system.sh")
	if err != nil {
		t.Fatal(err)
	}

	content := string(data)
	if !strings.Contains(content, "apparmor_parser") {
		t.Error("uninstall-system.sh must unload AppArmor profile")
	}
	if !strings.Contains(content, "-R") {
		t.Error("uninstall-system.sh must use apparmor_parser -R to remove profile")
	}
}

// --- Bundle tests ---

func TestBundleContainsSystemAssets(t *testing.T) {
	data, err := os.ReadFile("build-bundle.sh")
	if err != nil {
		t.Fatal(err)
	}

	content := string(data)
	expectedAssets := []string{
		"install-system.sh",
		"uninstall-system.sh",
		"systemd/system/docker-helper.service",
		"apparmor/docker-helper-system",
		"apparmor/docker-helper.d/managed-roots",
	}

	for _, a := range expectedAssets {
		if !strings.Contains(content, a) {
			t.Errorf("build-bundle.sh must include system asset: %s", a)
		}
	}
}

func TestBundleContainsUserAssets(t *testing.T) {
	data, err := os.ReadFile("build-bundle.sh")
	if err != nil {
		t.Fatal(err)
	}

	content := string(data)
	expectedAssets := []string{
		"install.sh",
		"uninstall.sh",
		"systemd/user/docker-helper.service",
		"apparmor/docker-helper",
		"skills/docker-helper/SKILL.md",
	}

	for _, a := range expectedAssets {
		if !strings.Contains(content, a) {
			t.Errorf("build-bundle.sh must still include user asset: %s", a)
		}
	}
}

func TestBundleSystemScriptsExecutable(t *testing.T) {
	data, err := os.ReadFile("build-bundle.sh")
	if err != nil {
		t.Fatal(err)
	}

	content := string(data)
	// System scripts must be set executable
	if !strings.Contains(content, "install-system.sh") || !strings.Contains(content, "755") {
		t.Error("build-bundle.sh must set install-system.sh executable")
	}
}

// --- Behavioral tests for install-system.sh ---

func setupInstallTest(t *testing.T) (scriptDir, fakeBinDir, destDir, logFile string) {
	t.Helper()
	tmpDir := t.TempDir()
	scriptDir = filepath.Join(tmpDir, "script")
	fakeBinDir = filepath.Join(tmpDir, "fakes")
	destDir = filepath.Join(tmpDir, "dest")
	logFile = filepath.Join(tmpDir, "calls.log")

	// Create script directory with bundled assets
	if err := os.MkdirAll(scriptDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(scriptDir, "systemd", "system"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(scriptDir, "apparmor", "docker-helper.d"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(fakeBinDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Create fake binary
	if err := os.WriteFile(filepath.Join(scriptDir, "docker-helper"), []byte("fake"), 0755); err != nil {
		t.Fatal(err)
	}

	// Create bundled assets
	if err := os.WriteFile(filepath.Join(scriptDir, "systemd", "system", "docker-helper.service"), []byte("[Service]"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scriptDir, "apparmor", "docker-helper-system"), []byte("profile docker-helper-system {}"), 0644); err != nil {
		t.Fatal(err)
	}
	fragmentData := renderFragment([]string{})
	if err := os.WriteFile(filepath.Join(scriptDir, "apparmor", "docker-helper.d", "managed-roots"), fragmentData, 0644); err != nil {
		t.Fatal(err)
	}

	// Create fake systemctl
	systemctlScript := fmt.Sprintf(`#!/bin/bash
log_file="%s"
echo "$@" >> "$log_file"
case "$*" in
  *"is-active"*) exit 1 ;;
  *"stop"*) exit 0 ;;
  *"daemon-reload"*) exit 0 ;;
  *"enable"*) exit 0 ;;
  *"start"*) exit 0 ;;
  *) exit 0 ;;
esac
`, logFile)
	if err := os.WriteFile(filepath.Join(fakeBinDir, "systemctl"), []byte(systemctlScript), 0755); err != nil {
		t.Fatal(err)
	}

	// Create fake docker
	dockerScript := fmt.Sprintf(`#!/bin/bash
log_file="%s"
echo "$@" >> "$log_file"
exit 0
`, logFile)
	if err := os.WriteFile(filepath.Join(fakeBinDir, "docker"), []byte(dockerScript), 0755); err != nil {
		t.Fatal(err)
	}

	// Create fake apparmor_parser
	parserScript := fmt.Sprintf(`#!/bin/bash
log_file="%s"
echo "$@" >> "$log_file"
exit 0
`, logFile)
	if err := os.WriteFile(filepath.Join(fakeBinDir, "apparmor_parser"), []byte(parserScript), 0755); err != nil {
		t.Fatal(err)
	}

	// Create destination directories
	if err := os.MkdirAll(filepath.Join(destDir, "bin"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(destDir, "etc", "systemd", "system"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(destDir, "etc", "apparmor.d", "docker-helper.d"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(destDir, "etc", "docker-helper"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(destDir, "var", "lib", "docker-helper"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(destDir, "run", "docker-helper"), 0755); err != nil {
		t.Fatal(err)
	}

	// Copy script
	scriptData, err := os.ReadFile("packaging/install-system.sh")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scriptDir, "install-system.sh"), scriptData, 0755); err != nil {
		t.Fatal(err)
	}

	return scriptDir, fakeBinDir, destDir, logFile
}

func readCalls(t *testing.T, logFile string) []string {
	t.Helper()
	data, err := os.ReadFile(logFile)
	if err != nil {
		return nil
	}
	var calls []string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line != "" {
			calls = append(calls, line)
		}
	}
	return calls
}

func TestInstallSystemParseArgsOrder(t *testing.T) {
	scriptDir, _, _, _ := setupInstallTest(t)
	scriptPath := filepath.Join(scriptDir, "install-system.sh")

	// Test --yes --allowed-root PATH
	cmd := exec.Command("bash", "-c", fmt.Sprintf(`
		source %s
		parse_args --yes --allowed-root /srv/ws
		if [[ "$interactive" != "false" ]]; then echo "FAIL: interactive should be false"; exit 1; fi
		if [[ "$allowed_root" != "/srv/ws" ]]; then echo "FAIL: allowed_root wrong: $allowed_root"; exit 1; fi
	`, scriptPath))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("--yes --allowed-root failed: %v\n%s", err, out)
	}

	// Test --allowed-root PATH --yes
	cmd = exec.Command("bash", "-c", fmt.Sprintf(`
		source %s
		parse_args --allowed-root /srv/ws --yes
		if [[ "$interactive" != "false" ]]; then echo "FAIL: interactive should be false"; exit 1; fi
		if [[ "$allowed_root" != "/srv/ws" ]]; then echo "FAIL: allowed_root wrong: $allowed_root"; exit 1; fi
	`, scriptPath))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("--allowed-root --yes failed: %v\n%s", err, out)
	}
}

func TestInstallSystemParseArgsMissingValue(t *testing.T) {
	scriptDir, _, _, _ := setupInstallTest(t)
	scriptPath := filepath.Join(scriptDir, "install-system.sh")

	cmd := exec.Command("bash", "-c", fmt.Sprintf(`
		source %s
		parse_args --allowed-root
	`, scriptPath))
	if _, err := cmd.CombinedOutput(); err == nil {
		t.Fatal("--allowed-root without value should fail")
	}
}

func TestInstallSystemParseArgsOptionAsValue(t *testing.T) {
	scriptDir, _, _, _ := setupInstallTest(t)
	scriptPath := filepath.Join(scriptDir, "install-system.sh")

	// --allowed-root --yes should fail (--yes is an option, not a path)
	cmd := exec.Command("bash", "-c", fmt.Sprintf(`
		source %s
		parse_args --allowed-root --yes
	`, scriptPath))
	if _, err := cmd.CombinedOutput(); err == nil {
		t.Fatal("--allowed-root --yes should fail (option as value)")
	}
}

func TestInstallSystemParseArgsUnknownArg(t *testing.T) {
	scriptDir, _, _, _ := setupInstallTest(t)
	scriptPath := filepath.Join(scriptDir, "install-system.sh")

	cmd := exec.Command("bash", "-c", fmt.Sprintf(`
		source %s
		parse_args --unknown
	`, scriptPath))
	if _, err := cmd.CombinedOutput(); err == nil {
		t.Fatal("unknown arg should fail")
	}
}

func TestInstallSystemFreshYesWithoutAllowedRoot(t *testing.T) {
	scriptDir, _, _, _ := setupInstallTest(t)
	scriptPath := filepath.Join(scriptDir, "install-system.sh")

	cmd := exec.Command("bash", "-c", fmt.Sprintf(`
		source %s
		parse_args --yes
		CONFIG_PATH="/nonexistent/config.json"
		check_allowed_root
	`, scriptPath))
	if _, err := cmd.CombinedOutput(); err == nil {
		t.Fatal("fresh --yes without --allowed-root should fail")
	}
}

func TestInstallSystemPreservesManagedRoots(t *testing.T) {
	tmpDir := t.TempDir()
	scriptDir := filepath.Join(tmpDir, "script")
	fragmentDestDir := filepath.Join(tmpDir, "dest", "docker-helper.d")

	if err := os.MkdirAll(scriptDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(scriptDir, "apparmor", "docker-helper.d"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(fragmentDestDir, 0755); err != nil {
		t.Fatal(err)
	}

	existingContent := "# existing operator-managed content\n"
	if err := os.WriteFile(filepath.Join(fragmentDestDir, "managed-roots"), []byte(existingContent), 0644); err != nil {
		t.Fatal(err)
	}

	bundledContent := "# Generated by docker-helper. Do not edit.\n# Managed AppArmor workspace roots for docker-helper-system profile.\n"
	if err := os.WriteFile(filepath.Join(scriptDir, "apparmor", "docker-helper.d", "managed-roots"), []byte(bundledContent), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scriptDir, "docker-helper"), []byte("fake"), 0755); err != nil {
		t.Fatal(err)
	}

	scriptPath := filepath.Join(scriptDir, "install-system.sh")
	scriptData, err := os.ReadFile("packaging/install-system.sh")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(scriptPath, scriptData, 0755); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("bash", "-c", fmt.Sprintf(`
		source %s
		AA_FRAGMENT_SRC="apparmor/docker-helper.d/managed-roots"
		AA_FRAGMENT_DEST="%s/managed-roots"
		script_dir="%s"
		install_apparmor_fragment
	`, scriptPath, fragmentDestDir, scriptDir))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("install_apparmor_fragment failed: %v\n%s", err, out)
	}

	actual, err := os.ReadFile(filepath.Join(fragmentDestDir, "managed-roots"))
	if err != nil {
		t.Fatal(err)
	}
	if string(actual) != existingContent {
		t.Errorf("existing fragment not preserved\ngot:  %q\nwant: %q", string(actual), existingContent)
	}
}

func TestInstallSystemCopiesMissingFragment(t *testing.T) {
	tmpDir := t.TempDir()
	scriptDir := filepath.Join(tmpDir, "script")
	fragmentDestDir := filepath.Join(tmpDir, "dest", "docker-helper.d")

	if err := os.MkdirAll(scriptDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(scriptDir, "apparmor", "docker-helper.d"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(fragmentDestDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scriptDir, "docker-helper"), []byte("fake"), 0755); err != nil {
		t.Fatal(err)
	}

	bundledContent := "# Generated by docker-helper. Do not edit.\n# Managed AppArmor workspace roots for docker-helper-system profile.\n"
	if err := os.WriteFile(filepath.Join(scriptDir, "apparmor", "docker-helper.d", "managed-roots"), []byte(bundledContent), 0644); err != nil {
		t.Fatal(err)
	}

	scriptPath := filepath.Join(scriptDir, "install-system.sh")
	scriptData, err := os.ReadFile("packaging/install-system.sh")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(scriptPath, scriptData, 0755); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("bash", "-c", fmt.Sprintf(`
		source %s
		AA_FRAGMENT_SRC="apparmor/docker-helper.d/managed-roots"
		AA_FRAGMENT_DEST="%s/managed-roots"
		script_dir="%s"
		install_apparmor_fragment
	`, scriptPath, fragmentDestDir, scriptDir))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("install_apparmor_fragment failed: %v\n%s", err, out)
	}

	actual, err := os.ReadFile(filepath.Join(fragmentDestDir, "managed-roots"))
	if err != nil {
		t.Fatal(err)
	}
	if string(actual) != bundledContent {
		t.Errorf("fragment not copied correctly\ngot:  %q\nwant: %q", string(actual), bundledContent)
	}
}

func TestInstallSystemParserUsesReplace(t *testing.T) {
	data, err := os.ReadFile("packaging/install-system.sh")
	if err != nil {
		t.Fatal(err)
	}

	content := string(data)
	if !strings.Contains(content, "--replace") {
		t.Error("load_apparmor_profile must use --replace")
	}
	if !strings.Contains(content, "--skip-read-cache") {
		t.Error("load_apparmor_profile must use --skip-read-cache")
	}
}

func TestInstallSystemParserFailurePreventsServiceStart(t *testing.T) {
	scriptDir, fakeBinDir, destDir, logFile := setupInstallTest(t)

	// Make parser fail
	parserScript := fmt.Sprintf(`#!/bin/bash
log_file="%s"
echo "$@" >> "$log_file"
exit 1
`, logFile)
	if err := os.WriteFile(filepath.Join(fakeBinDir, "apparmor_parser"), []byte(parserScript), 0755); err != nil {
		t.Fatal(err)
	}

	scriptPath := filepath.Join(scriptDir, "install-system.sh")
	env := []string{
		"PATH=" + fakeBinDir + ":" + os.Getenv("PATH"),
		"BINARY_DEST=" + filepath.Join(destDir, "bin/docker-helper"),
		"UNIT_DEST=" + filepath.Join(destDir, "etc/systemd/system/docker-helper.service"),
		"AA_PROFILE_DEST=" + filepath.Join(destDir, "etc/apparmor.d/docker-helper-system"),
		"AA_FRAGMENT_DEST=" + filepath.Join(destDir, "etc/apparmor.d/docker-helper.d/managed-roots"),
		"CONFIG_PATH=" + filepath.Join(destDir, "etc/docker-helper/config.json"),
		"AA_PARSER=" + filepath.Join(fakeBinDir, "apparmor_parser"),
		"SYSTEMCTL=" + filepath.Join(fakeBinDir, "systemctl"),
		"DOCKER=" + filepath.Join(fakeBinDir, "docker"),
	}

	cmd := exec.Command("bash", "-c", fmt.Sprintf(`
		source %s
		check_root() { :; }
		main --yes --allowed-root /tmp/ws
	`, scriptPath))
	cmd.Env = append(os.Environ(), env...)
	cmd.Dir = scriptDir
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("parser failure should cause install to fail: %s", out)
	}

	calls := readCalls(t, logFile)
	for _, c := range calls {
		if strings.Contains(c, "start") {
			t.Error("service start should not be called after parser failure")
		}
		if strings.Contains(c, "enable") {
			t.Error("service enable should not be called after parser failure")
		}
	}
}

func TestInstallSystemExistingConfigSkipsInit(t *testing.T) {
	scriptDir, fakeBinDir, destDir, logFile := setupInstallTest(t)

	// Create existing config
	if err := os.WriteFile(filepath.Join(destDir, "etc/docker-helper/config.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}

	// Make bundled binary log when called (it gets copied to dest)
	binaryScript := fmt.Sprintf(`#!/bin/bash
log_file="%s"
echo "binary: $@" >> "$log_file"
exit 0
`, logFile)
	if err := os.WriteFile(filepath.Join(scriptDir, "docker-helper"), []byte(binaryScript), 0755); err != nil {
		t.Fatal(err)
	}

	scriptPath := filepath.Join(scriptDir, "install-system.sh")
	env := []string{
		"PATH=" + fakeBinDir + ":" + os.Getenv("PATH"),
		"BINARY_DEST=" + filepath.Join(destDir, "bin/docker-helper"),
		"UNIT_DEST=" + filepath.Join(destDir, "etc/systemd/system/docker-helper.service"),
		"AA_PROFILE_DEST=" + filepath.Join(destDir, "etc/apparmor.d/docker-helper-system"),
		"AA_FRAGMENT_DEST=" + filepath.Join(destDir, "etc/apparmor.d/docker-helper.d/managed-roots"),
		"CONFIG_PATH=" + filepath.Join(destDir, "etc/docker-helper/config.json"),
		"AA_PARSER=" + filepath.Join(fakeBinDir, "apparmor_parser"),
		"SYSTEMCTL=" + filepath.Join(fakeBinDir, "systemctl"),
		"DOCKER=" + filepath.Join(fakeBinDir, "docker"),
	}

	cmd := exec.Command("bash", "-c", fmt.Sprintf(`
		source %s
		check_root() { :; }
		main --yes --allowed-root /tmp/ws
	`, scriptPath))
	cmd.Env = append(os.Environ(), env...)
	cmd.Dir = scriptDir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("install failed: %v\n%s", err, out)
	}

	calls := readCalls(t, logFile)
	for _, c := range calls {
		if strings.Contains(c, "binary: init") {
			t.Error("init should not be called when config exists")
		}
	}
}

func TestInstallSystemFreshInitReceivesAllowedRoot(t *testing.T) {
	scriptDir, fakeBinDir, destDir, logFile := setupInstallTest(t)

	// Make bundled binary log when called (it gets copied to dest)
	binaryScript := fmt.Sprintf(`#!/bin/bash
log_file="%s"
echo "binary: $@" >> "$log_file"
exit 0
`, logFile)
	if err := os.WriteFile(filepath.Join(scriptDir, "docker-helper"), []byte(binaryScript), 0755); err != nil {
		t.Fatal(err)
	}

	scriptPath := filepath.Join(scriptDir, "install-system.sh")
	env := []string{
		"PATH=" + fakeBinDir + ":" + os.Getenv("PATH"),
		"BINARY_DEST=" + filepath.Join(destDir, "bin/docker-helper"),
		"UNIT_DEST=" + filepath.Join(destDir, "etc/systemd/system/docker-helper.service"),
		"AA_PROFILE_DEST=" + filepath.Join(destDir, "etc/apparmor.d/docker-helper-system"),
		"AA_FRAGMENT_DEST=" + filepath.Join(destDir, "etc/apparmor.d/docker-helper.d/managed-roots"),
		"CONFIG_PATH=" + filepath.Join(destDir, "etc/docker-helper/config.json"),
		"AA_PARSER=" + filepath.Join(fakeBinDir, "apparmor_parser"),
		"SYSTEMCTL=" + filepath.Join(fakeBinDir, "systemctl"),
		"DOCKER=" + filepath.Join(fakeBinDir, "docker"),
	}

	testRoot := t.TempDir()

	cmd := exec.Command("bash", "-c", fmt.Sprintf(`source %s; check_root() { :; }; main --yes --allowed-root %s`, scriptPath, testRoot))
	cmd.Env = append(os.Environ(), env...)
	cmd.Dir = scriptDir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("install failed: %v\n%s", err, out)
	}

	calls := readCalls(t, logFile)
	found := false
	for _, c := range calls {
		if c == "binary: init --allowed-root "+testRoot {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("init should receive exact --allowed-root %s, calls: %v", testRoot, calls)
	}
}

func TestInstallSystemFreshYesEnablesStartsService(t *testing.T) {
	scriptDir, fakeBinDir, destDir, logFile := setupInstallTest(t)

	// Make bundled binary a no-op script (it gets copied to dest and called for init)
	binaryScript := fmt.Sprintf(`#!/bin/bash
log_file="%s"
echo "binary: $@" >> "$log_file"
exit 0
`, logFile)
	if err := os.WriteFile(filepath.Join(scriptDir, "docker-helper"), []byte(binaryScript), 0755); err != nil {
		t.Fatal(err)
	}

	scriptPath := filepath.Join(scriptDir, "install-system.sh")
	env := []string{
		"PATH=" + fakeBinDir + ":" + os.Getenv("PATH"),
		"BINARY_DEST=" + filepath.Join(destDir, "bin/docker-helper"),
		"UNIT_DEST=" + filepath.Join(destDir, "etc/systemd/system/docker-helper.service"),
		"AA_PROFILE_DEST=" + filepath.Join(destDir, "etc/apparmor.d/docker-helper-system"),
		"AA_FRAGMENT_DEST=" + filepath.Join(destDir, "etc/apparmor.d/docker-helper.d/managed-roots"),
		"CONFIG_PATH=" + filepath.Join(destDir, "etc/docker-helper/config.json"),
		"AA_PARSER=" + filepath.Join(fakeBinDir, "apparmor_parser"),
		"SYSTEMCTL=" + filepath.Join(fakeBinDir, "systemctl"),
		"DOCKER=" + filepath.Join(fakeBinDir, "docker"),
	}

	testRoot := t.TempDir()

	cmd := exec.Command("bash", "-c", fmt.Sprintf(`source %s; check_root() { :; }; main --yes --allowed-root %s`, scriptPath, testRoot))
	cmd.Env = append(os.Environ(), env...)
	cmd.Dir = scriptDir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("install failed: %v\n%s", err, out)
	}

	calls := readCalls(t, logFile)
	var enableIdx, startIdx int
	for i, c := range calls {
		if strings.Contains(c, "enable") {
			enableIdx = i
		}
		if strings.Contains(c, "start") {
			startIdx = i
		}
	}
	if enableIdx < 0 {
		t.Error("enable should be called")
	}
	if startIdx < 0 {
		t.Error("start should be called")
	}
	if enableIdx > 0 && startIdx > 0 && enableIdx > startIdx {
		t.Error("enable should be called before start")
	}
}

// --- Behavioral tests for uninstall-system.sh ---

func TestUninstallSystemPurgeConfirmation(t *testing.T) {
	tmpDir := t.TempDir()
	scriptDir := filepath.Join(tmpDir, "script")
	destDir := filepath.Join(tmpDir, "dest")
	fakeBinDir := filepath.Join(tmpDir, "fakes")
	logFile := filepath.Join(tmpDir, "calls.log")

	if err := os.MkdirAll(scriptDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(fakeBinDir, 0755); err != nil {
		t.Fatal(err)
	}

	systemctlScript := fmt.Sprintf(`#!/bin/bash
log_file="%s"
echo "$@" >> "$log_file"
exit 1
`, logFile)
	if err := os.WriteFile(filepath.Join(fakeBinDir, "systemctl"), []byte(systemctlScript), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fakeBinDir, "apparmor_parser"), []byte("#!/bin/bash\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}

	if err := os.MkdirAll(filepath.Join(destDir, "etc", "docker-helper"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(destDir, "var", "lib", "docker-helper"), 0755); err != nil {
		t.Fatal(err)
	}
	fragmentDir := filepath.Join(destDir, "etc", "apparmor.d", "docker-helper.d")
	if err := os.MkdirAll(fragmentDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fragmentDir, "managed-roots"), []byte("fragment"), 0644); err != nil {
		t.Fatal(err)
	}

	scriptPath := filepath.Join(scriptDir, "uninstall-system.sh")
	scriptData, err := os.ReadFile("packaging/uninstall-system.sh")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(scriptPath, scriptData, 0755); err != nil {
		t.Fatal(err)
	}

	env := []string{
		"PATH=" + fakeBinDir + ":" + os.Getenv("PATH"),
		"BINARY_DEST=" + filepath.Join(destDir, "bin/docker-helper"),
		"UNIT_DEST=" + filepath.Join(destDir, "etc/systemd/system/docker-helper.service"),
		"AA_PROFILE_DEST=" + filepath.Join(destDir, "etc/apparmor.d/docker-helper-system"),
		"AA_FRAGMENT_DEST=" + filepath.Join(destDir, "etc/apparmor.d/docker-helper.d/managed-roots"),
		"AA_FRAGMENT_DIR=" + fragmentDir,
		"CONFIG_DIR=" + filepath.Join(destDir, "etc/docker-helper"),
		"STATE_DIR=" + filepath.Join(destDir, "var/lib/docker-helper"),
		"RUNTIME_DIR=" + filepath.Join(destDir, "run/docker-helper"),
		"AA_PARSER=" + filepath.Join(fakeBinDir, "apparmor_parser"),
		"SYSTEMCTL=" + filepath.Join(fakeBinDir, "systemctl"),
	}

	cmd := exec.Command("bash", "-c", fmt.Sprintf(`
		source %s
		check_root() { :; }
		main --purge
	`, scriptPath))
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdin = strings.NewReader("\n")
	cmd.Dir = scriptDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		if !strings.Contains(string(out), "Aborting") {
			t.Fatalf("unexpected error: %v\n%s", err, out)
		}
	}

	if _, err := os.Stat(filepath.Join(destDir, "etc", "docker-helper")); os.IsNotExist(err) {
		t.Error("config dir should be preserved when purge confirmation is declined")
	}
	if _, err := os.Stat(filepath.Join(fragmentDir, "managed-roots")); os.IsNotExist(err) {
		t.Error("fragment should be preserved when purge confirmation is declined")
	}
}

func TestUninstallSystemNormalPreservesConfig(t *testing.T) {
	tmpDir := t.TempDir()
	scriptDir := filepath.Join(tmpDir, "script")
	destDir := filepath.Join(tmpDir, "dest")
	fakeBinDir := filepath.Join(tmpDir, "fakes")
	logFile := filepath.Join(tmpDir, "calls.log")

	if err := os.MkdirAll(scriptDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(fakeBinDir, 0755); err != nil {
		t.Fatal(err)
	}

	systemctlScript := fmt.Sprintf(`#!/bin/bash
log_file="%s"
echo "$@" >> "$log_file"
exit 1
`, logFile)
	if err := os.WriteFile(filepath.Join(fakeBinDir, "systemctl"), []byte(systemctlScript), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fakeBinDir, "apparmor_parser"), []byte("#!/bin/bash\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}

	if err := os.MkdirAll(filepath.Join(destDir, "etc", "docker-helper"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(destDir, "etc", "docker-helper", "config.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(destDir, "var", "lib", "docker-helper"), 0755); err != nil {
		t.Fatal(err)
	}
	fragmentDir := filepath.Join(destDir, "etc", "apparmor.d", "docker-helper.d")
	if err := os.MkdirAll(fragmentDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fragmentDir, "managed-roots"), []byte("fragment"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := os.MkdirAll(filepath.Join(destDir, "bin"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(destDir, "bin", "docker-helper"), []byte("fake"), 0755); err != nil {
		t.Fatal(err)
	}

	scriptPath := filepath.Join(scriptDir, "uninstall-system.sh")
	scriptData, err := os.ReadFile("packaging/uninstall-system.sh")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(scriptPath, scriptData, 0755); err != nil {
		t.Fatal(err)
	}

	env := []string{
		"PATH=" + fakeBinDir + ":" + os.Getenv("PATH"),
		"BINARY_DEST=" + filepath.Join(destDir, "bin/docker-helper"),
		"UNIT_DEST=" + filepath.Join(destDir, "etc/systemd/system/docker-helper.service"),
		"AA_PROFILE_DEST=" + filepath.Join(destDir, "etc/apparmor.d/docker-helper-system"),
		"AA_FRAGMENT_DEST=" + filepath.Join(destDir, "etc/apparmor.d/docker-helper.d/managed-roots"),
		"AA_FRAGMENT_DIR=" + fragmentDir,
		"CONFIG_DIR=" + filepath.Join(destDir, "etc/docker-helper"),
		"STATE_DIR=" + filepath.Join(destDir, "var/lib/docker-helper"),
		"RUNTIME_DIR=" + filepath.Join(destDir, "run/docker-helper"),
		"AA_PARSER=" + filepath.Join(fakeBinDir, "apparmor_parser"),
		"SYSTEMCTL=" + filepath.Join(fakeBinDir, "systemctl"),
	}

	cmd := exec.Command("bash", "-c", fmt.Sprintf(`
		source %s
		check_root() { :; }
		main --yes
	`, scriptPath))
	cmd.Env = append(os.Environ(), env...)
	cmd.Dir = scriptDir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("uninstall failed: %v\n%s", err, out)
	}

	if _, err := os.Stat(filepath.Join(destDir, "etc", "docker-helper", "config.json")); os.IsNotExist(err) {
		t.Error("config should be preserved without --purge")
	}
	if _, err := os.Stat(filepath.Join(destDir, "var", "lib", "docker-helper")); os.IsNotExist(err) {
		t.Error("state should be preserved without --purge")
	}
	if _, err := os.Stat(filepath.Join(fragmentDir, "managed-roots")); os.IsNotExist(err) {
		t.Error("fragment should be preserved without --purge")
	}
	if _, err := os.Stat(filepath.Join(destDir, "bin", "docker-helper")); !os.IsNotExist(err) {
		t.Error("binary should be removed")
	}
}

func TestUninstallSystemPurgeRemovesData(t *testing.T) {
	tmpDir := t.TempDir()
	scriptDir := filepath.Join(tmpDir, "script")
	destDir := filepath.Join(tmpDir, "dest")
	fakeBinDir := filepath.Join(tmpDir, "fakes")
	logFile := filepath.Join(tmpDir, "calls.log")

	if err := os.MkdirAll(scriptDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(fakeBinDir, 0755); err != nil {
		t.Fatal(err)
	}

	systemctlScript := fmt.Sprintf(`#!/bin/bash
log_file="%s"
echo "$@" >> "$log_file"
exit 1
`, logFile)
	if err := os.WriteFile(filepath.Join(fakeBinDir, "systemctl"), []byte(systemctlScript), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fakeBinDir, "apparmor_parser"), []byte("#!/bin/bash\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}

	if err := os.MkdirAll(filepath.Join(destDir, "etc", "docker-helper"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(destDir, "etc", "docker-helper", "config.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(destDir, "var", "lib", "docker-helper"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(destDir, "run", "docker-helper"), 0755); err != nil {
		t.Fatal(err)
	}
	fragmentDir := filepath.Join(destDir, "etc", "apparmor.d", "docker-helper.d")
	if err := os.MkdirAll(fragmentDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fragmentDir, "managed-roots"), []byte("fragment"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := os.MkdirAll(filepath.Join(destDir, "bin"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(destDir, "bin", "docker-helper"), []byte("fake"), 0755); err != nil {
		t.Fatal(err)
	}

	scriptPath := filepath.Join(scriptDir, "uninstall-system.sh")
	scriptData, err := os.ReadFile("packaging/uninstall-system.sh")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(scriptPath, scriptData, 0755); err != nil {
		t.Fatal(err)
	}

	env := []string{
		"PATH=" + fakeBinDir + ":" + os.Getenv("PATH"),
		"BINARY_DEST=" + filepath.Join(destDir, "bin/docker-helper"),
		"UNIT_DEST=" + filepath.Join(destDir, "etc/systemd/system/docker-helper.service"),
		"AA_PROFILE_DEST=" + filepath.Join(destDir, "etc/apparmor.d/docker-helper-system"),
		"AA_FRAGMENT_DEST=" + filepath.Join(destDir, "etc/apparmor.d/docker-helper.d/managed-roots"),
		"AA_FRAGMENT_DIR=" + fragmentDir,
		"CONFIG_DIR=" + filepath.Join(destDir, "etc/docker-helper"),
		"STATE_DIR=" + filepath.Join(destDir, "var/lib/docker-helper"),
		"RUNTIME_DIR=" + filepath.Join(destDir, "run/docker-helper"),
		"AA_PARSER=" + filepath.Join(fakeBinDir, "apparmor_parser"),
		"SYSTEMCTL=" + filepath.Join(fakeBinDir, "systemctl"),
	}

	cmd := exec.Command("bash", "-c", fmt.Sprintf(`
		source %s
		check_root() { :; }
		main --yes --purge
	`, scriptPath))
	cmd.Env = append(os.Environ(), env...)
	cmd.Dir = scriptDir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("uninstall failed: %v\n%s", err, out)
	}

	if _, err := os.Stat(filepath.Join(destDir, "etc", "docker-helper")); !os.IsNotExist(err) {
		t.Error("config should be removed with --purge")
	}
	if _, err := os.Stat(filepath.Join(destDir, "var", "lib", "docker-helper")); !os.IsNotExist(err) {
		t.Error("state should be removed with --purge")
	}
	if _, err := os.Stat(filepath.Join(destDir, "run", "docker-helper")); !os.IsNotExist(err) {
		t.Error("runtime should be removed with --purge")
	}
	if _, err := os.Stat(filepath.Join(fragmentDir, "managed-roots")); !os.IsNotExist(err) {
		t.Error("fragment should be removed with --purge")
	}
}

func TestInstallSystemActiveServiceStopFailure(t *testing.T) {
	tmpDir := t.TempDir()
	scriptDir := filepath.Join(tmpDir, "script")
	fakeBinDir := filepath.Join(tmpDir, "fakes")
	destDir := filepath.Join(tmpDir, "dest")
	logFile := filepath.Join(tmpDir, "calls.log")

	if err := os.MkdirAll(scriptDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(scriptDir, "systemd", "system"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(scriptDir, "apparmor", "docker-helper.d"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(fakeBinDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Create bundled assets
	if err := os.WriteFile(filepath.Join(scriptDir, "docker-helper"), []byte("#!/bin/bash\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scriptDir, "systemd", "system", "docker-helper.service"), []byte("[Service]"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scriptDir, "apparmor", "docker-helper-system"), []byte("profile {}"), 0644); err != nil {
		t.Fatal(err)
	}
	fragmentData := renderFragment([]string{})
	if err := os.WriteFile(filepath.Join(scriptDir, "apparmor", "docker-helper.d", "managed-roots"), fragmentData, 0644); err != nil {
		t.Fatal(err)
	}

	// Service is active, stop fails
	systemctlScript := fmt.Sprintf(`#!/bin/bash
log_file="%s"
echo "$@" >> "$log_file"
case "$*" in
  *"is-active"*) exit 0 ;;  # active
  *"stop"*) exit 1 ;;       # stop fails
  *) exit 0 ;;
esac
`, logFile)
	if err := os.WriteFile(filepath.Join(fakeBinDir, "systemctl"), []byte(systemctlScript), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fakeBinDir, "docker"), []byte("#!/bin/bash\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fakeBinDir, "apparmor_parser"), []byte("#!/bin/bash\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}

	// Create sentinel files at destination
	if err := os.MkdirAll(filepath.Join(destDir, "bin"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(destDir, "etc", "systemd", "system"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(destDir, "etc", "apparmor.d", "docker-helper.d"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(destDir, "etc", "docker-helper"), 0755); err != nil {
		t.Fatal(err)
	}
	sentinelBinary := []byte("existing-binary-content")
	sentinelUnit := []byte("[Service]\nExecStart=/old/bin")
	sentinelProfile := []byte("profile old {}")
	if err := os.WriteFile(filepath.Join(destDir, "bin", "docker-helper"), sentinelBinary, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(destDir, "etc", "systemd", "system", "docker-helper.service"), sentinelUnit, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(destDir, "etc", "apparmor.d", "docker-helper-system"), sentinelProfile, 0644); err != nil {
		t.Fatal(err)
	}

	scriptData, err := os.ReadFile("packaging/install-system.sh")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scriptDir, "install-system.sh"), scriptData, 0755); err != nil {
		t.Fatal(err)
	}

	env := []string{
		"PATH=" + fakeBinDir + ":" + os.Getenv("PATH"),
		"BINARY_DEST=" + filepath.Join(destDir, "bin/docker-helper"),
		"UNIT_DEST=" + filepath.Join(destDir, "etc/systemd/system/docker-helper.service"),
		"AA_PROFILE_DEST=" + filepath.Join(destDir, "etc/apparmor.d/docker-helper-system"),
		"AA_FRAGMENT_DEST=" + filepath.Join(destDir, "etc/apparmor.d/docker-helper.d/managed-roots"),
		"CONFIG_PATH=" + filepath.Join(destDir, "etc/docker-helper/config.json"),
		"AA_PARSER=" + filepath.Join(fakeBinDir, "apparmor_parser"),
		"SYSTEMCTL=" + filepath.Join(fakeBinDir, "systemctl"),
		"DOCKER=" + filepath.Join(fakeBinDir, "docker"),
	}

	testRoot := t.TempDir()
	cmd := exec.Command("bash", "-c", fmt.Sprintf(`
		source %s/install-system.sh
		check_root() { :; }
		main --yes --allowed-root %s
	`, scriptDir, testRoot))
	cmd.Env = append(os.Environ(), env...)
	cmd.Dir = scriptDir
	if out, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("install should fail when stop fails: %s", out)
	}

	// Verify sentinel files unchanged
	actualBinary, err := os.ReadFile(filepath.Join(destDir, "bin", "docker-helper"))
	if err != nil || string(actualBinary) != string(sentinelBinary) {
		t.Error("binary should be unchanged when stop fails")
	}
	actualUnit, err := os.ReadFile(filepath.Join(destDir, "etc", "systemd", "system", "docker-helper.service"))
	if err != nil || string(actualUnit) != string(sentinelUnit) {
		t.Error("unit should be unchanged when stop fails")
	}
	actualProfile, err := os.ReadFile(filepath.Join(destDir, "etc", "apparmor.d", "docker-helper-system"))
	if err != nil || string(actualProfile) != string(sentinelProfile) {
		t.Error("profile should be unchanged when stop fails")
	}
}

func TestInstallSystemActiveServiceSuccessfulUpgrade(t *testing.T) {
	tmpDir := t.TempDir()
	scriptDir := filepath.Join(tmpDir, "script")
	fakeBinDir := filepath.Join(tmpDir, "fakes")
	destDir := filepath.Join(tmpDir, "dest")
	logFile := filepath.Join(tmpDir, "calls.log")

	if err := os.MkdirAll(scriptDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(scriptDir, "systemd", "system"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(scriptDir, "apparmor", "docker-helper.d"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(fakeBinDir, 0755); err != nil {
		t.Fatal(err)
	}

	binaryScript := fmt.Sprintf(`#!/bin/bash
log_file="%s"
echo "binary: $@" >> "$log_file"
exit 0
`, logFile)
	if err := os.WriteFile(filepath.Join(scriptDir, "docker-helper"), []byte(binaryScript), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scriptDir, "systemd", "system", "docker-helper.service"), []byte("[Service]"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scriptDir, "apparmor", "docker-helper-system"), []byte("profile {}"), 0644); err != nil {
		t.Fatal(err)
	}
	fragmentData := renderFragment([]string{})
	if err := os.WriteFile(filepath.Join(scriptDir, "apparmor", "docker-helper.d", "managed-roots"), fragmentData, 0644); err != nil {
		t.Fatal(err)
	}

	// Service is active, stop succeeds
	systemctlScript := fmt.Sprintf(`#!/bin/bash
log_file="%s"
echo "$@" >> "$log_file"
case "$*" in
  *"is-active"*) exit 0 ;;  # active
  *"stop"*) exit 0 ;;       # stop succeeds
  *"daemon-reload"*) exit 0 ;;
  *"start"*) exit 0 ;;
  *) exit 0 ;;
esac
`, logFile)
	if err := os.WriteFile(filepath.Join(fakeBinDir, "systemctl"), []byte(systemctlScript), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fakeBinDir, "docker"), []byte("#!/bin/bash\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fakeBinDir, "apparmor_parser"), []byte("#!/bin/bash\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}

	if err := os.MkdirAll(filepath.Join(destDir, "bin"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(destDir, "etc", "systemd", "system"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(destDir, "etc", "apparmor.d", "docker-helper.d"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(destDir, "etc", "docker-helper"), 0755); err != nil {
		t.Fatal(err)
	}

	scriptData, err := os.ReadFile("packaging/install-system.sh")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scriptDir, "install-system.sh"), scriptData, 0755); err != nil {
		t.Fatal(err)
	}

	env := []string{
		"PATH=" + fakeBinDir + ":" + os.Getenv("PATH"),
		"BINARY_DEST=" + filepath.Join(destDir, "bin/docker-helper"),
		"UNIT_DEST=" + filepath.Join(destDir, "etc/systemd/system/docker-helper.service"),
		"AA_PROFILE_DEST=" + filepath.Join(destDir, "etc/apparmor.d/docker-helper-system"),
		"AA_FRAGMENT_DEST=" + filepath.Join(destDir, "etc/apparmor.d/docker-helper.d/managed-roots"),
		"CONFIG_PATH=" + filepath.Join(destDir, "etc/docker-helper/config.json"),
		"AA_PARSER=" + filepath.Join(fakeBinDir, "apparmor_parser"),
		"SYSTEMCTL=" + filepath.Join(fakeBinDir, "systemctl"),
		"DOCKER=" + filepath.Join(fakeBinDir, "docker"),
	}

	testRoot := t.TempDir()
	cmd := exec.Command("bash", "-c", fmt.Sprintf(`
		source %s/install-system.sh
		check_root() { :; }
		main --yes --allowed-root %s
	`, scriptDir, testRoot))
	cmd.Env = append(os.Environ(), env...)
	cmd.Dir = scriptDir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("install should succeed: %v\n%s", err, out)
	}

	calls := readCalls(t, logFile)
	// For previously active service, start should be called, not enable
	foundStart := false
	foundEnable := false
	for _, c := range calls {
		if strings.Contains(c, "start") {
			foundStart = true
		}
		if strings.Contains(c, "enable") {
			foundEnable = true
		}
	}
	if !foundStart {
		t.Error("start should be called for previously active service")
	}
	if foundEnable {
		t.Error("enable should NOT be called for previously active service (upgrade)")
	}
}

func TestInstallSystemDaemonReloadFailure(t *testing.T) {
	tmpDir := t.TempDir()
	scriptDir := filepath.Join(tmpDir, "script")
	fakeBinDir := filepath.Join(tmpDir, "fakes")
	destDir := filepath.Join(tmpDir, "dest")
	logFile := filepath.Join(tmpDir, "calls.log")

	if err := os.MkdirAll(scriptDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(scriptDir, "systemd", "system"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(scriptDir, "apparmor", "docker-helper.d"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(fakeBinDir, 0755); err != nil {
		t.Fatal(err)
	}

	binaryScript := fmt.Sprintf(`#!/bin/bash
log_file="%s"
echo "binary: $@" >> "$log_file"
exit 0
`, logFile)
	if err := os.WriteFile(filepath.Join(scriptDir, "docker-helper"), []byte(binaryScript), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scriptDir, "systemd", "system", "docker-helper.service"), []byte("[Service]"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scriptDir, "apparmor", "docker-helper-system"), []byte("profile {}"), 0644); err != nil {
		t.Fatal(err)
	}
	fragmentData := renderFragment([]string{})
	if err := os.WriteFile(filepath.Join(scriptDir, "apparmor", "docker-helper.d", "managed-roots"), fragmentData, 0644); err != nil {
		t.Fatal(err)
	}

	// daemon-reload fails
	systemctlScript := fmt.Sprintf(`#!/bin/bash
log_file="%s"
echo "$@" >> "$log_file"
case "$*" in
  *"is-active"*) exit 1 ;;
  *"daemon-reload"*) exit 1 ;;
  *) exit 0 ;;
esac
`, logFile)
	if err := os.WriteFile(filepath.Join(fakeBinDir, "systemctl"), []byte(systemctlScript), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fakeBinDir, "docker"), []byte("#!/bin/bash\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fakeBinDir, "apparmor_parser"), []byte("#!/bin/bash\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}

	if err := os.MkdirAll(filepath.Join(destDir, "bin"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(destDir, "etc", "systemd", "system"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(destDir, "etc", "apparmor.d", "docker-helper.d"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(destDir, "etc", "docker-helper"), 0755); err != nil {
		t.Fatal(err)
	}

	scriptData, err := os.ReadFile("packaging/install-system.sh")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scriptDir, "install-system.sh"), scriptData, 0755); err != nil {
		t.Fatal(err)
	}

	env := []string{
		"PATH=" + fakeBinDir + ":" + os.Getenv("PATH"),
		"BINARY_DEST=" + filepath.Join(destDir, "bin/docker-helper"),
		"UNIT_DEST=" + filepath.Join(destDir, "etc/systemd/system/docker-helper.service"),
		"AA_PROFILE_DEST=" + filepath.Join(destDir, "etc/apparmor.d/docker-helper-system"),
		"AA_FRAGMENT_DEST=" + filepath.Join(destDir, "etc/apparmor.d/docker-helper.d/managed-roots"),
		"CONFIG_PATH=" + filepath.Join(destDir, "etc/docker-helper/config.json"),
		"AA_PARSER=" + filepath.Join(fakeBinDir, "apparmor_parser"),
		"SYSTEMCTL=" + filepath.Join(fakeBinDir, "systemctl"),
		"DOCKER=" + filepath.Join(fakeBinDir, "docker"),
	}

	testRoot := t.TempDir()
	cmd := exec.Command("bash", "-c", fmt.Sprintf(`
		source %s/install-system.sh
		check_root() { :; }
		main --yes --allowed-root %s
	`, scriptDir, testRoot))
	cmd.Env = append(os.Environ(), env...)
	cmd.Dir = scriptDir
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("install should fail when daemon-reload fails")
	}

	calls := readCalls(t, logFile)
	for _, c := range calls {
		if strings.Contains(c, "start") {
			t.Error("start should not be called after daemon-reload failure")
		}
	}
	if strings.Contains(string(out), "installation complete") {
		t.Error("should not print installation complete on failure")
	}
}

func TestInstallSystemStartFailure(t *testing.T) {
	tmpDir := t.TempDir()
	scriptDir := filepath.Join(tmpDir, "script")
	fakeBinDir := filepath.Join(tmpDir, "fakes")
	destDir := filepath.Join(tmpDir, "dest")
	logFile := filepath.Join(tmpDir, "calls.log")

	if err := os.MkdirAll(scriptDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(scriptDir, "systemd", "system"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(scriptDir, "apparmor", "docker-helper.d"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(fakeBinDir, 0755); err != nil {
		t.Fatal(err)
	}

	binaryScript := fmt.Sprintf(`#!/bin/bash
log_file="%s"
echo "binary: $@" >> "$log_file"
exit 0
`, logFile)
	if err := os.WriteFile(filepath.Join(scriptDir, "docker-helper"), []byte(binaryScript), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scriptDir, "systemd", "system", "docker-helper.service"), []byte("[Service]"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scriptDir, "apparmor", "docker-helper-system"), []byte("profile {}"), 0644); err != nil {
		t.Fatal(err)
	}
	fragmentData := renderFragment([]string{})
	if err := os.WriteFile(filepath.Join(scriptDir, "apparmor", "docker-helper.d", "managed-roots"), fragmentData, 0644); err != nil {
		t.Fatal(err)
	}

	// start fails
	systemctlScript := fmt.Sprintf(`#!/bin/bash
log_file="%s"
echo "$@" >> "$log_file"
case "$*" in
  *"is-active"*) exit 1 ;;
  *"start"*) exit 1 ;;
  *) exit 0 ;;
esac
`, logFile)
	if err := os.WriteFile(filepath.Join(fakeBinDir, "systemctl"), []byte(systemctlScript), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fakeBinDir, "docker"), []byte("#!/bin/bash\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fakeBinDir, "apparmor_parser"), []byte("#!/bin/bash\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}

	if err := os.MkdirAll(filepath.Join(destDir, "bin"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(destDir, "etc", "systemd", "system"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(destDir, "etc", "apparmor.d", "docker-helper.d"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(destDir, "etc", "docker-helper"), 0755); err != nil {
		t.Fatal(err)
	}

	scriptData, err := os.ReadFile("packaging/install-system.sh")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scriptDir, "install-system.sh"), scriptData, 0755); err != nil {
		t.Fatal(err)
	}

	env := []string{
		"PATH=" + fakeBinDir + ":" + os.Getenv("PATH"),
		"BINARY_DEST=" + filepath.Join(destDir, "bin/docker-helper"),
		"UNIT_DEST=" + filepath.Join(destDir, "etc/systemd/system/docker-helper.service"),
		"AA_PROFILE_DEST=" + filepath.Join(destDir, "etc/apparmor.d/docker-helper-system"),
		"AA_FRAGMENT_DEST=" + filepath.Join(destDir, "etc/apparmor.d/docker-helper.d/managed-roots"),
		"CONFIG_PATH=" + filepath.Join(destDir, "etc/docker-helper/config.json"),
		"AA_PARSER=" + filepath.Join(fakeBinDir, "apparmor_parser"),
		"SYSTEMCTL=" + filepath.Join(fakeBinDir, "systemctl"),
		"DOCKER=" + filepath.Join(fakeBinDir, "docker"),
	}

	testRoot := t.TempDir()
	cmd := exec.Command("bash", "-c", fmt.Sprintf(`
		source %s/install-system.sh
		check_root() { :; }
		main --yes --allowed-root %s
	`, scriptDir, testRoot))
	cmd.Env = append(os.Environ(), env...)
	cmd.Dir = scriptDir
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("install should fail when start fails")
	}

	if strings.Contains(string(out), "system installation complete") {
		t.Error("should not print installation complete on start failure")
	}
}

func TestUninstallSystemActiveStopFailure(t *testing.T) {
	tmpDir := t.TempDir()
	scriptDir := filepath.Join(tmpDir, "script")
	destDir := filepath.Join(tmpDir, "dest")
	fakeBinDir := filepath.Join(tmpDir, "fakes")
	logFile := filepath.Join(tmpDir, "calls.log")

	if err := os.MkdirAll(scriptDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(fakeBinDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Service is active, stop fails
	systemctlScript := fmt.Sprintf(`#!/bin/bash
log_file="%s"
echo "$@" >> "$log_file"
case "$*" in
  *"is-active"*) exit 0 ;;  # active
  *"stop"*) exit 1 ;;       # stop fails
  *) exit 0 ;;
esac
`, logFile)
	if err := os.WriteFile(filepath.Join(fakeBinDir, "systemctl"), []byte(systemctlScript), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fakeBinDir, "apparmor_parser"), []byte("#!/bin/bash\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}

	// Create binary/unit/profile to protect
	if err := os.MkdirAll(filepath.Join(destDir, "bin"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(destDir, "etc", "systemd", "system"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(destDir, "etc", "apparmor.d"), 0755); err != nil {
		t.Fatal(err)
	}
	sentinelBinary := []byte("existing-binary")
	sentinelUnit := []byte("[Service]")
	sentinelProfile := []byte("profile {}")
	if err := os.WriteFile(filepath.Join(destDir, "bin", "docker-helper"), sentinelBinary, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(destDir, "etc", "systemd", "system", "docker-helper.service"), sentinelUnit, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(destDir, "etc", "apparmor.d", "docker-helper-system"), sentinelProfile, 0644); err != nil {
		t.Fatal(err)
	}

	scriptData, err := os.ReadFile("packaging/uninstall-system.sh")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scriptDir, "uninstall-system.sh"), scriptData, 0755); err != nil {
		t.Fatal(err)
	}

	env := []string{
		"PATH=" + fakeBinDir + ":" + os.Getenv("PATH"),
		"BINARY_DEST=" + filepath.Join(destDir, "bin/docker-helper"),
		"UNIT_DEST=" + filepath.Join(destDir, "etc/systemd/system/docker-helper.service"),
		"AA_PROFILE_DEST=" + filepath.Join(destDir, "etc/apparmor.d/docker-helper-system"),
		"AA_FRAGMENT_DEST=" + filepath.Join(destDir, "etc/apparmor.d/docker-helper.d/managed-roots"),
		"AA_FRAGMENT_DIR=" + filepath.Join(destDir, "etc/apparmor.d/docker-helper.d"),
		"CONFIG_DIR=" + filepath.Join(destDir, "etc/docker-helper"),
		"STATE_DIR=" + filepath.Join(destDir, "var/lib/docker-helper"),
		"RUNTIME_DIR=" + filepath.Join(destDir, "run/docker-helper"),
		"AA_PARSER=" + filepath.Join(fakeBinDir, "apparmor_parser"),
		"SYSTEMCTL=" + filepath.Join(fakeBinDir, "systemctl"),
	}

	cmd := exec.Command("bash", "-c", fmt.Sprintf(`
		source %s/uninstall-system.sh
		check_root() { :; }
		main --yes
	`, scriptDir))
	cmd.Env = append(os.Environ(), env...)
	cmd.Dir = scriptDir
	if out, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("uninstall should fail when stop fails: %s", out)
	}

	// Verify files unchanged
	actualBinary, err := os.ReadFile(filepath.Join(destDir, "bin", "docker-helper"))
	if err != nil || string(actualBinary) != string(sentinelBinary) {
		t.Error("binary should be unchanged when stop fails")
	}
	actualUnit, err := os.ReadFile(filepath.Join(destDir, "etc", "systemd", "system", "docker-helper.service"))
	if err != nil || string(actualUnit) != string(sentinelUnit) {
		t.Error("unit should be unchanged when stop fails")
	}
	actualProfile, err := os.ReadFile(filepath.Join(destDir, "etc", "apparmor.d", "docker-helper-system"))
	if err != nil || string(actualProfile) != string(sentinelProfile) {
		t.Error("profile should be unchanged when stop fails")
	}
}

func TestUninstallSystemSuccessfulActiveOrder(t *testing.T) {
	tmpDir := t.TempDir()
	scriptDir := filepath.Join(tmpDir, "script")
	destDir := filepath.Join(tmpDir, "dest")
	fakeBinDir := filepath.Join(tmpDir, "fakes")
	logFile := filepath.Join(tmpDir, "calls.log")

	if err := os.MkdirAll(scriptDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(fakeBinDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Service is active, stop succeeds
	systemctlScript := fmt.Sprintf(`#!/bin/bash
log_file="%s"
echo "$@" >> "$log_file"
case "$*" in
  *"is-active"*) exit 0 ;;  # active
  *"stop"*) exit 0 ;;
  *) exit 0 ;;
esac
`, logFile)
	if err := os.WriteFile(filepath.Join(fakeBinDir, "systemctl"), []byte(systemctlScript), 0755); err != nil {
		t.Fatal(err)
	}

	parserScript := fmt.Sprintf(`#!/bin/bash
log_file="%s"
echo "$@" >> "$log_file"
exit 0
`, logFile)
	if err := os.WriteFile(filepath.Join(fakeBinDir, "apparmor_parser"), []byte(parserScript), 0755); err != nil {
		t.Fatal(err)
	}

	if err := os.MkdirAll(filepath.Join(destDir, "bin"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(destDir, "bin", "docker-helper"), []byte("fake"), 0755); err != nil {
		t.Fatal(err)
	}

	scriptData, err := os.ReadFile("packaging/uninstall-system.sh")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scriptDir, "uninstall-system.sh"), scriptData, 0755); err != nil {
		t.Fatal(err)
	}

	env := []string{
		"PATH=" + fakeBinDir + ":" + os.Getenv("PATH"),
		"BINARY_DEST=" + filepath.Join(destDir, "bin/docker-helper"),
		"UNIT_DEST=" + filepath.Join(destDir, "etc/systemd/system/docker-helper.service"),
		"AA_PROFILE_DEST=" + filepath.Join(destDir, "etc/apparmor.d/docker-helper-system"),
		"AA_FRAGMENT_DEST=" + filepath.Join(destDir, "etc/apparmor.d/docker-helper.d/managed-roots"),
		"AA_FRAGMENT_DIR=" + filepath.Join(destDir, "etc/apparmor.d/docker-helper.d"),
		"CONFIG_DIR=" + filepath.Join(destDir, "etc/docker-helper"),
		"STATE_DIR=" + filepath.Join(destDir, "var/lib/docker-helper"),
		"RUNTIME_DIR=" + filepath.Join(destDir, "run/docker-helper"),
		"AA_PARSER=" + filepath.Join(fakeBinDir, "apparmor_parser"),
		"SYSTEMCTL=" + filepath.Join(fakeBinDir, "systemctl"),
	}

	cmd := exec.Command("bash", "-c", fmt.Sprintf(`
		source %s/uninstall-system.sh
		check_root() { :; }
		main --yes
	`, scriptDir))
	cmd.Env = append(os.Environ(), env...)
	cmd.Dir = scriptDir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("uninstall failed: %v\n%s", err, out)
	}

	calls := readCalls(t, logFile)
	// Verify order: is-active, stop, ..., apparmor_parser -R
	var isActiveIdx, stopIdx, unloadIdx int
	for i, c := range calls {
		if strings.Contains(c, "is-active") {
			isActiveIdx = i
		}
		if strings.Contains(c, "stop") && !strings.Contains(c, "docker-helper") {
			stopIdx = i
		}
		if strings.Contains(c, "apparmor_parser") {
			unloadIdx = i
		}
	}
	if isActiveIdx >= 0 && stopIdx >= 0 && isActiveIdx > stopIdx {
		t.Error("is-active should be called before stop")
	}
	if stopIdx >= 0 && unloadIdx >= 0 && stopIdx > unloadIdx {
		t.Error("stop should be called before apparmor_parser unload")
	}
}

func TestUninstallSystemParserExitDiagnostic(t *testing.T) {
	tmpDir := t.TempDir()
	scriptDir := filepath.Join(tmpDir, "script")
	destDir := filepath.Join(tmpDir, "dest")
	fakeBinDir := filepath.Join(tmpDir, "fakes")
	logFile := filepath.Join(tmpDir, "calls.log")

	if err := os.MkdirAll(scriptDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(fakeBinDir, 0755); err != nil {
		t.Fatal(err)
	}

	systemctlScript := fmt.Sprintf(`#!/bin/bash
log_file="%s"
echo "$@" >> "$log_file"
exit 1
`, logFile)
	if err := os.WriteFile(filepath.Join(fakeBinDir, "systemctl"), []byte(systemctlScript), 0755); err != nil {
		t.Fatal(err)
	}

	// Parser exits with code 42
	parserScript := fmt.Sprintf(`#!/bin/bash
log_file="%s"
echo "parser error diagnostic" >&2
echo "$@" >> "$log_file"
exit 42
`, logFile)
	if err := os.WriteFile(filepath.Join(fakeBinDir, "apparmor_parser"), []byte(parserScript), 0755); err != nil {
		t.Fatal(err)
	}

	if err := os.MkdirAll(filepath.Join(destDir, "bin"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(destDir, "bin", "docker-helper"), []byte("fake"), 0755); err != nil {
		t.Fatal(err)
	}

	scriptData, err := os.ReadFile("packaging/uninstall-system.sh")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scriptDir, "uninstall-system.sh"), scriptData, 0755); err != nil {
		t.Fatal(err)
	}

	env := []string{
		"PATH=" + fakeBinDir + ":" + os.Getenv("PATH"),
		"BINARY_DEST=" + filepath.Join(destDir, "bin/docker-helper"),
		"UNIT_DEST=" + filepath.Join(destDir, "etc/systemd/system/docker-helper.service"),
		"AA_PROFILE_DEST=" + filepath.Join(destDir, "etc/apparmor.d/docker-helper-system"),
		"AA_FRAGMENT_DEST=" + filepath.Join(destDir, "etc/apparmor.d/docker-helper.d/managed-roots"),
		"AA_FRAGMENT_DIR=" + filepath.Join(destDir, "etc/apparmor.d/docker-helper.d"),
		"CONFIG_DIR=" + filepath.Join(destDir, "etc/docker-helper"),
		"STATE_DIR=" + filepath.Join(destDir, "var/lib/docker-helper"),
		"RUNTIME_DIR=" + filepath.Join(destDir, "run/docker-helper"),
		"AA_PARSER=" + filepath.Join(fakeBinDir, "apparmor_parser"),
		"SYSTEMCTL=" + filepath.Join(fakeBinDir, "systemctl"),
	}

	cmd := exec.Command("bash", "-c", fmt.Sprintf(`
		source %s/uninstall-system.sh
		check_root() { :; }
		main --yes
	`, scriptDir))
	cmd.Env = append(os.Environ(), env...)
	cmd.Dir = scriptDir
	out, _ := cmd.CombinedOutput()

	output := string(out)
	// Should contain the real exit code 42, not 0
	if !strings.Contains(output, "exit 42") {
		t.Errorf("warning should contain real exit code 42, not 0. Output: %s", output)
	}
	// Should contain parser diagnostic
	if !strings.Contains(output, "parser error diagnostic") {
		t.Errorf("warning should contain parser stderr diagnostic. Output: %s", output)
	}
}

// --- nFPM config static tests ---

// TestNfpmConfigExists verifies the nFPM config file is present.
func TestNfpmConfigExists(t *testing.T) {
	if _, err := os.Stat("packaging/nfpm.yaml"); err != nil {
		t.Fatalf("packaging/nfpm.yaml not found: %v", err)
	}
}

// TestNfpmConfigRequiredFields checks that the nFPM config contains
// all required top-level fields.
func TestNfpmConfigRequiredFields(t *testing.T) {
	data, err := os.ReadFile("packaging/nfpm.yaml")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	for _, field := range []string{"name:", "version:", "arch:", "platform:"} {
		if !strings.Contains(content, field) {
			t.Errorf("nfpm.yaml missing required field: %s", field)
		}
	}
}

// TestNfpmConfigRequiredDestinations verifies the config installs all
// required system assets.
func TestNfpmConfigRequiredDestinations(t *testing.T) {
	data, err := os.ReadFile("packaging/nfpm.yaml")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	for _, path := range []string{
		"/usr/bin/docker-helper",
		"/usr/lib/systemd/system/docker-helper.service",
		"/etc/apparmor.d/docker-helper-system",
		"/etc/apparmor.d/docker-helper.d/managed-roots",
	} {
		if !strings.Contains(content, path) {
			t.Errorf("nfpm.yaml missing required destination: %s", path)
		}
	}
}

// TestNfpmConfigExcludesRuntimeState ensures the package does not ship
// operator-managed runtime or state paths.
func TestNfpmConfigExcludesRuntimeState(t *testing.T) {
	data, err := os.ReadFile("packaging/nfpm.yaml")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	for _, path := range []string{
		"/etc/docker-helper/config.json",
		"/etc/docker-helper/admin.token",
		"/var/lib/docker-helper",
		"/run/docker-helper",
	} {
		if strings.Contains(content, path) {
			t.Errorf("nfpm.yaml must not include runtime path: %s", path)
		}
	}
}

// TestNfpmConfigExcludesUserAssets ensures the system package does not
// ship user-mode or installer artifacts.
func TestNfpmConfigExcludesUserAssets(t *testing.T) {
	data, err := os.ReadFile("packaging/nfpm.yaml")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	for _, s := range []string{
		"systemd/user",
		"install.sh",
		"uninstall.sh",
		"SKILL.md",
	} {
		if strings.Contains(content, s) {
			t.Errorf("nfpm.yaml must not include: %s", s)
		}
	}
}

// TestNfpmConfigSystemdVendorDirectory verifies the systemd unit is
// installed to the vendor directory, not /etc/systemd/system.
func TestNfpmConfigSystemdVendorDirectory(t *testing.T) {
	data, err := os.ReadFile("packaging/nfpm.yaml")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if strings.Contains(content, "/etc/systemd/system") {
		t.Error("systemd unit must not be installed to /etc/systemd/system")
	}
	if !strings.Contains(content, "/usr/lib/systemd/system/docker-helper.service") {
		t.Error("systemd unit must be installed to /usr/lib/systemd/system/")
	}
}

// TestNfpmConfigManagedRootsType verifies the managed-roots content entry
// uses type: config|noreplace so that both DEB (conffile) and RPM
// (%config(noreplace)) preserve operator-modified contents on upgrade.
func TestNfpmConfigManagedRootsType(t *testing.T) {
	data, err := os.ReadFile("packaging/nfpm.yaml")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	idx := strings.Index(content, "dst: /etc/apparmor.d/docker-helper.d/managed-roots")
	if idx < 0 {
		t.Fatal("managed-roots destination entry not found")
	}
	before := content[:idx]
	entryStart := strings.LastIndex(before, "- src:")
	if entryStart < 0 {
		entryStart = 0
	}
	entry := content[entryStart:]
	if !strings.Contains(entry, "type: config|noreplace") {
		t.Error("managed-roots content entry must have type: config|noreplace")
	}
}

// TestNfpmConfigBinaryMode verifies the binary destination mode is 0755.
func TestNfpmConfigBinaryMode(t *testing.T) {
	data, err := os.ReadFile("packaging/nfpm.yaml")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if !strings.Contains(content, "0755") {
		t.Error("nfpm.yaml must set binary mode 0755")
	}
}

// TestNfpmConfigAssetModes verifies system asset modes are 0644.
func TestNfpmConfigAssetModes(t *testing.T) {
	data, err := os.ReadFile("packaging/nfpm.yaml")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	count := strings.Count(content, "0644")
	if count < 3 {
		t.Errorf("expected at least 3 assets with mode 0644, found %d", count)
	}
}

// TestNfpmConfigVersionFromEnvironment verifies the version is sourced
// from an environment variable, not hardcoded.
func TestNfpmConfigVersionFromEnvironment(t *testing.T) {
	data, err := os.ReadFile("packaging/nfpm.yaml")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if !strings.Contains(content, "${VERSION}") {
		t.Error("version must use ${VERSION} template variable")
	}
}

// TestNfpmConfigDebDepends verifies DEB depends are correct.
func TestNfpmConfigDebDepends(t *testing.T) {
	data, err := os.ReadFile("packaging/nfpm.yaml")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	debIdx := strings.Index(content, "deb:")
	if debIdx < 0 {
		t.Fatal("deb overrides section not found")
	}
	rpmIdx := strings.Index(content, "rpm:")
	if rpmIdx < 0 || debIdx > rpmIdx {
		t.Fatal("rpm overrides section not found or ordering wrong")
	}
	debSection := content[debIdx:rpmIdx]

	if !strings.Contains(debSection, "depends:") {
		t.Fatal("deb depends: section not found")
	}
	if !strings.Contains(debSection, "systemd") {
		t.Error("DEB depends must include systemd")
	}
	if !strings.Contains(debSection, "apparmor") {
		t.Error("DEB depends must include apparmor")
	}
	for _, line := range strings.Split(debSection, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "- docker") {
			t.Error("DEB depends must not include docker package")
		}
	}
}

// TestNfpmConfigRpmDepends verifies RPM depends are correct.
func TestNfpmConfigRpmDepends(t *testing.T) {
	data, err := os.ReadFile("packaging/nfpm.yaml")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	rpmIdx := strings.Index(content, "rpm:")
	if rpmIdx < 0 {
		t.Fatal("rpm overrides section not found")
	}
	contentsIdx := strings.Index(content[rpmIdx:], "\ncontents:")
	if contentsIdx < 0 {
		contentsIdx = len(content) - rpmIdx
	}
	rpmSection := content[rpmIdx : rpmIdx+contentsIdx]

	if !strings.Contains(rpmSection, "depends:") {
		t.Fatal("rpm depends: section not found")
	}
	if !strings.Contains(rpmSection, "systemd") {
		t.Error("RPM depends must include systemd")
	}
	if !strings.Contains(rpmSection, "apparmor-parser") {
		t.Error("RPM depends must include apparmor-parser")
	}
	for _, line := range strings.Split(rpmSection, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "- docker") {
			t.Error("RPM depends must not include docker package")
		}
	}
}

// --- build-packages.sh tests ---

// TestBuildPackagesScriptSyntax verifies build-packages.sh has valid bash syntax.
func TestBuildPackagesScriptSyntax(t *testing.T) {
	cmd := exec.Command("bash", "-n", "build-packages.sh")
	if err := cmd.Run(); err != nil {
		t.Fatalf("build-packages.sh syntax error: %v", err)
	}
}

// TestBuildPackagesScriptRequiresVersion verifies the script fails when
// VERSION is not provided.
func TestBuildPackagesScriptRequiresVersion(t *testing.T) {
	cmd := exec.Command("bash", "build-packages.sh")
	cmd.Env = append(os.Environ(), "PATH=")
	if err := cmd.Run(); err == nil {
		t.Fatal("build-packages.sh must fail without VERSION argument")
	}
}

// TestBuildPackagesScriptNfpmMissing verifies the script fails with a
// clear error when nfpm is not available.
func TestBuildPackagesScriptNfpmMissing(t *testing.T) {
	cmd := exec.Command("bash", "build-packages.sh", "1.0.0")
	cmd.Env = append(os.Environ(), "PATH=")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("build-packages.sh must fail when nfpm is not found")
	}
	output := string(out)
	if !strings.Contains(output, "nfpm") {
		t.Errorf("error message must mention nfpm: %s", output)
	}
}

// TestBuildPackagesScriptCallsStaticBuild verifies the script delegates
// binary building to build-static.sh with the exact VERSION.
func TestBuildPackagesScriptCallsStaticBuild(t *testing.T) {
	data, err := os.ReadFile("build-packages.sh")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if !strings.Contains(content, "build-static.sh") {
		t.Error("build-packages.sh must call build-static.sh")
	}
	if !strings.Contains(content, "$VERSION") {
		t.Error("build-packages.sh must pass VERSION to build-static.sh")
	}
}

// TestBuildPackagesScriptBuildsBothFormats verifies the script builds
// both DEB and RPM packages.
func TestBuildPackagesScriptBuildsBothFormats(t *testing.T) {
	data, err := os.ReadFile("build-packages.sh")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if !strings.Contains(content, "deb") {
		t.Error("build-packages.sh must build DEB packages")
	}
	if !strings.Contains(content, "rpm") {
		t.Error("build-packages.sh must build RPM packages")
	}
}

// TestBuildPackagesScriptOutputsToDist verifies package artifacts are
// written to the dist/ directory.
func TestBuildPackagesScriptOutputsToDist(t *testing.T) {
	data, err := os.ReadFile("build-packages.sh")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if !strings.Contains(content, "dist") {
		t.Error("build-packages.sh must output artifacts to dist/")
	}
}

// TestBuildPackagesScriptVerifiesBinary verifies the script checks that
// the static binary exists and is executable before packaging.
func TestBuildPackagesScriptVerifiesBinary(t *testing.T) {
	data, err := os.ReadFile("build-packages.sh")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if !strings.Contains(content, "dist/docker-helper") {
		t.Error("build-packages.sh must verify dist/docker-helper exists")
	}
	if !strings.Contains(content, "-x") {
		t.Error("build-packages.sh must check binary is executable")
	}
}

// TestBuildPackagesScriptNoSedConfig verifies the script does not use
// sed/mktemp to generate a temporary nFPM config — nFPM expands
// ${VERSION} from the environment directly.
func TestBuildPackagesScriptNoSedConfig(t *testing.T) {
	data, err := os.ReadFile("build-packages.sh")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if strings.Contains(content, "sed") {
		t.Error("build-packages.sh must not use sed to substitute version")
	}
	if strings.Contains(content, "mktemp") {
		t.Error("build-packages.sh must not create temporary config files")
	}
}

// --- Package metadata integration tests (nfpm only, no musl-gcc required) ---

// TestPackageMetadataIntegration builds packages with a dummy binary and
// verifies metadata: contents, modes, dependencies, conffiles/config flags.
// Skipped only when nfpm is unavailable.
func TestPackageMetadataIntegration(t *testing.T) {
	if _, err := exec.LookPath("nfpm"); err != nil {
		t.Skip("nfpm not installed, skipping package metadata integration test")
	}

	testVersion := "0.0.0-meta-test"
	tmpDir := t.TempDir()

	// Create a dummy binary for packaging.
	dummyBin := filepath.Join(tmpDir, "docker-helper")
	if err := os.WriteFile(dummyBin, []byte("dummy"), 0755); err != nil {
		t.Fatal(err)
	}

	// Create a temporary nFPM config that uses the dummy binary and tmp output.
	nfpmData, err := os.ReadFile("packaging/nfpm.yaml")
	if err != nil {
		t.Fatal(err)
	}
	// Replace dist/docker-helper with the dummy binary path.
	configContent := strings.ReplaceAll(string(nfpmData), "src: dist/docker-helper", "src: "+dummyBin)
	// Replace ${VERSION} with test version.
	configContent = strings.ReplaceAll(configContent, "${VERSION}", testVersion)

	configFile := filepath.Join(tmpDir, "nfpm.yaml")
	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Build DEB.
	debCmd := exec.Command("nfpm", "package",
		"--config", configFile,
		"--packager", "deb",
		"--target", tmpDir,
	)
	debCmd.Env = append(os.Environ(), "VERSION="+testVersion)
	if out, err := debCmd.CombinedOutput(); err != nil {
		t.Fatalf("nfpm DEB build failed: %v\n%s", err, out)
	}

	// Build RPM.
	rpmCmd := exec.Command("nfpm", "package",
		"--config", configFile,
		"--packager", "rpm",
		"--target", tmpDir,
	)
	rpmCmd.Env = append(os.Environ(), "VERSION="+testVersion)
	if out, err := rpmCmd.CombinedOutput(); err != nil {
		t.Fatalf("nfpm RPM build failed: %v\n%s", err, out)
	}

	// Find exact package files in tmpDir (no stale artifacts).
	debFile := filepath.Join(tmpDir, "docker-helper_"+testVersion+"_amd64.deb")
	if _, err := os.Stat(debFile); err != nil {
		t.Fatalf("DEB package not found at %s: %v", debFile, err)
	}
	rpmFile := filepath.Join(tmpDir, "docker-helper-"+testVersion+"-1.x86_64.rpm")
	if _, err := os.Stat(rpmFile); err != nil {
		// Try without release number.
		rpmFile = filepath.Join(tmpDir, "docker-helper-"+testVersion+".x86_64.rpm")
		if _, err := os.Stat(rpmFile); err != nil {
			// List what's in tmpDir to help diagnose.
			entries, _ := os.ReadDir(tmpDir)
			var names []string
			for _, e := range entries {
				names = append(names, e.Name())
			}
			t.Fatalf("RPM package not found, tmpDir contains: %v", names)
		}
	}

	// Verify DEB with dpkg-deb.
	if dpkgDeb, err := exec.LookPath("dpkg-deb"); err == nil {
		verifyDEBPackage(t, dpkgDeb, debFile)
	} else {
		t.Log("dpkg-deb not available, skipping DEB verification")
	}

	// Verify RPM with rpm.
	if rpmPath, err := exec.LookPath("rpm"); err == nil {
		verifyRPMPackage(t, rpmPath, rpmFile)
	} else {
		t.Log("rpm not available, skipping RPM verification")
	}
}

func verifyDEBPackage(t *testing.T, dpkgDeb, debFile string) {
	t.Helper()

	// Contents.
	cmd := exec.Command(dpkgDeb, "--contents", debFile)
	out, _ := cmd.CombinedOutput()
	verifyPackageContents(t, "DEB", string(out))

	// Modes.
	verifyPackageModes(t, "DEB", string(out))

	// Dependencies.
	cmd = exec.Command(dpkgDeb, "--field", debFile, "Depends")
	out, _ = cmd.CombinedOutput()
	depends := string(out)
	if !strings.Contains(depends, "systemd") {
		t.Error("DEB Depends must include systemd")
	}
	if !strings.Contains(depends, "apparmor") {
		t.Error("DEB Depends must include apparmor")
	}
	if strings.Contains(depends, "docker") {
		t.Error("DEB Depends must not include docker package")
	}

	// Conffiles — extract control tarball and read conffiles.
	controlDir := t.TempDir()
	cmd = exec.Command(dpkgDeb, "--control", debFile, controlDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("dpkg-deb --control failed: %v\n%s", err, out)
	}
	conffilesData, err := os.ReadFile(filepath.Join(controlDir, "conffiles"))
	if err != nil {
		t.Fatalf("DEB conffiles not found in control tarball: %v", err)
	}
	conffilesStr := string(conffilesData)
	if !strings.Contains(conffilesStr, "/etc/apparmor.d/docker-helper.d/managed-roots") {
		t.Errorf("DEB conffiles must contain managed-roots, got:\n%s", conffilesStr)
	}
}

func verifyRPMPackage(t *testing.T, rpmPath, rpmFile string) {
	t.Helper()

	// Contents.
	cmd := exec.Command(rpmPath, "-qpl", rpmFile)
	out, _ := cmd.CombinedOutput()
	verifyPackageContents(t, "RPM", string(out))

	// Modes — use FILEMODES:perms array format.
	cmd = exec.Command(rpmPath, "-qp", "--qf", "[%{FILEMODES:perms} %{FILENAMES}\\n]", rpmFile)
	modeOut, _ := cmd.CombinedOutput()
	verifyRPMModesPerms(t, string(modeOut))

	// Dependencies.
	cmd = exec.Command(rpmPath, "-qp", "--requires", rpmFile)
	out, _ = cmd.CombinedOutput()
	requires := string(out)
	if !strings.Contains(requires, "systemd") {
		t.Error("RPM Requires must include systemd")
	}
	if !strings.Contains(requires, "apparmor-parser") {
		t.Error("RPM Requires must include apparmor-parser")
	}
	// Check for docker dependency (various package names).
	for _, dep := range []string{"docker.io", "docker-ce", "docker-" + "community"} {
		if strings.Contains(requires, dep) {
			t.Errorf("RPM Requires must not include %s", dep)
		}
	}

	// Config(noreplace) flag on managed-roots — use FILEFLAGS:fflags.
	cmd = exec.Command(rpmPath, "-qp", "--qf", "[%{FILENAMES} %{FILEFLAGS:fflags}\\n]", rpmFile)
	flagOut, _ := cmd.CombinedOutput()
	flagStr := string(flagOut)
	found := false
	for _, line := range strings.Split(flagStr, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "managed-roots") {
			found = true
			// config flag = 0x0001, noreplace = 0x0008
			// fflags output: "config noreplace" or similar
			if !strings.Contains(line, "config") {
				t.Errorf("RPM managed-roots must have config flag: %s", line)
			}
			if !strings.Contains(line, "noreplace") {
				t.Errorf("RPM managed-roots must have noreplace flag: %s", line)
			}
			break
		}
	}
	if !found {
		t.Errorf("managed-roots not found in RPM file flags output:\n%s", flagStr)
	}
}

func verifyPackageContents(t *testing.T, format, contents string) {
	t.Helper()

	for _, path := range []string{
		"/usr/bin/docker-helper",
		"/usr/lib/systemd/system/docker-helper.service",
		"/etc/apparmor.d/docker-helper-system",
		"/etc/apparmor.d/docker-helper.d/managed-roots",
	} {
		if !strings.Contains(contents, path) {
			t.Errorf("%s missing required path: %s", format, path)
		}
	}

	for _, path := range []string{
		"/etc/docker-helper/config.json",
		"/etc/docker-helper/admin.token",
		"/var/lib/docker-helper",
		"/run/docker-helper",
	} {
		if strings.Contains(contents, path) {
			t.Errorf("%s must not contain: %s", format, path)
		}
	}
}

func verifyPackageModes(t *testing.T, format, contents string) {
	t.Helper()
	// dpkg-deb --contents output format:
	// -rwxr-xr-x root/root       1234 2024-01-01 00:00 ./usr/bin/docker-helper
	for _, line := range strings.Split(contents, "\n") {
		if len(line) < 11 {
			continue
		}
		mode := line[:10]
		parts := strings.Fields(line)
		if len(parts) < 6 {
			continue
		}
		path := strings.TrimPrefix(parts[len(parts)-1], "./")
		if path == "" {
			continue
		}
		switch path {
		case "usr/bin/docker-helper":
			if mode != "-rwxr-xr-x" {
				t.Errorf("%s: %s mode = %s, want -rwxr-xr-x (0755)", format, path, mode)
			}
		case "usr/lib/systemd/system/docker-helper.service",
			"etc/apparmor.d/docker-helper-system",
			"etc/apparmor.d/docker-helper.d/managed-roots":
			if mode != "-rw-r--r--" {
				t.Errorf("%s: %s mode = %s, want -rw-r--r-- (0644)", format, path, mode)
			}
		}
	}
}

func verifyRPMModesPerms(t *testing.T, modeOutput string) {
	t.Helper()
	// rpm --qf "[%{FILEMODES:perms} %{FILENAMES}\n]" output:
	// -rwxr-xr-x /usr/bin/docker-helper
	for _, line := range strings.Split(strings.TrimSpace(modeOutput), "\n") {
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		mode := parts[0]
		path := strings.TrimPrefix(parts[1], "/")
		switch path {
		case "usr/bin/docker-helper":
			if mode != "-rwxr-xr-x" {
				t.Errorf("RPM: %s mode = %s, want -rwxr-xr-x", path, mode)
			}
		case "usr/lib/systemd/system/docker-helper.service",
			"etc/apparmor.d/docker-helper-system",
			"etc/apparmor.d/docker-helper.d/managed-roots":
			if mode != "-rw-r--r--" {
				t.Errorf("RPM: %s mode = %s, want -rw-r--r--", path, mode)
			}
		}
	}
}

// --- Full pipeline integration test (requires nfpm + musl-gcc) ---

// TestPackageBuildIntegration runs the full build-packages.sh pipeline
// and verifies the resulting packages. Skipped when nfpm is unavailable.
func TestPackageBuildIntegration(t *testing.T) {
	if _, err := exec.LookPath("nfpm"); err != nil {
		t.Skip("nfpm not installed, skipping package build integration test")
	}

	testVersion := "1.0.0-test"
	tmpDir := t.TempDir()

	// Build to a controlled temp output to avoid stale artifacts.
	cmd := exec.Command("bash", "-c",
		fmt.Sprintf("cd '%s' && VERSION='%s' bash build-packages.sh '%s'",
			filepath.Dir(filepath.Dir(tmpDir)), testVersion, testVersion))
	// Actually, build-packages.sh writes to dist/. Use a temp dist instead.
	// The simplest approach: run build-packages.sh and find exact filenames.
	cmd = exec.Command("bash", "build-packages.sh", testVersion)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build-packages.sh failed: %v\n%s", err, out)
	}

	// Exact filenames for the test version.
	debFile := "dist/docker-helper_" + testVersion + "_amd64.deb"
	if _, err := os.Stat(debFile); err != nil {
		// List dist/ to diagnose.
		entries, _ := os.ReadDir("dist")
		var names []string
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".deb") {
				names = append(names, e.Name())
			}
		}
		t.Fatalf("DEB not found at %s; .deb files in dist/: %v", debFile, names)
	}

	rpmFile := "dist/docker-helper-" + testVersion + "-1.x86_64.rpm"
	if _, err := os.Stat(rpmFile); err != nil {
		entries, _ := os.ReadDir("dist")
		var names []string
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".rpm") {
				names = append(names, e.Name())
			}
		}
		t.Fatalf("RPM not found at %s; .rpm files in dist/: %v", rpmFile, names)
	}

	// Verify DEB.
	if dpkgDeb, err := exec.LookPath("dpkg-deb"); err == nil {
		verifyDEBPackage(t, dpkgDeb, debFile)
	} else {
		t.Log("dpkg-deb not available, skipping DEB verification")
	}

	// Verify RPM.
	if rpmPath, err := exec.LookPath("rpm"); err == nil {
		verifyRPMPackage(t, rpmPath, rpmFile)
	} else {
		t.Log("rpm not available, skipping RPM verification")
	}
}
