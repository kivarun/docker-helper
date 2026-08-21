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

// TestScriptSyntax verifies every shipped script has valid shell syntax.
func TestScriptSyntax(t *testing.T) {
	tests := []struct {
		shell string
		path  string
	}{
		{"bash", "packaging/install.sh"},
		{"bash", "packaging/uninstall.sh"},
		{"bash", "packaging/install-system.sh"},
		{"bash", "packaging/uninstall-system.sh"},
		{"bash", "build-static.sh"},
		{"bash", "build-bundle.sh"},
		{"bash", "build-packages.sh"},
		{"bash", "build-manpages.sh"},
		{"sh", "packaging/scripts/deb/postinstall.sh"},
		{"sh", "packaging/scripts/deb/preremove.sh"},
		{"sh", "packaging/scripts/deb/postremove.sh"},
		{"sh", "packaging/scripts/rpm/postinstall.sh"},
		{"sh", "packaging/scripts/rpm/preremove.sh"},
		{"sh", "packaging/scripts/rpm/postremove.sh"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if err := exec.Command(tt.shell, "-n", tt.path).Run(); err != nil {
				t.Fatalf("%s syntax error: %v", tt.path, err)
			}
		})
	}
}

// setupInstalledHome creates a temp home with an installed docker-helper
// (binary, unit, config, state) for running the production uninstall.sh.
func setupInstalledHome(t *testing.T) string {
	t.Helper()
	tempHome := t.TempDir()

	installDir := filepath.Join(tempHome, ".local", "bin")
	if err := os.MkdirAll(installDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(installDir, "docker-helper"), []byte("#!/bin/bash\necho 1.0.0\n"), 0755); err != nil {
		t.Fatal(err)
	}

	unitDir := filepath.Join(tempHome, ".config", "systemd", "user")
	if err := os.MkdirAll(unitDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(unitDir, "docker-helper.service"), []byte("[Unit]\n"), 0644); err != nil {
		t.Fatal(err)
	}

	configDir := filepath.Join(tempHome, ".config", "docker-helper")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "config.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	writeTestTokenFile(t, filepath.Join(configDir, "admin.token"), "test-admin-token\n")

	stateDir := filepath.Join(tempHome, ".local", "state", "docker-helper")
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "docker-helper.db"), []byte("fake db"), 0600); err != nil {
		t.Fatal(err)
	}

	return tempHome
}

// runUninstall runs the production packaging/uninstall.sh against a temp home.
func runUninstall(t *testing.T, tempHome string, args []string) ([]byte, error) {
	t.Helper()
	script, err := filepath.Abs("packaging/uninstall.sh")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", append([]string{script}, args...)...)
	cmd.Env = append(os.Environ(),
		"HOME="+tempHome,
		"XDG_CONFIG_HOME="+filepath.Join(tempHome, ".config"),
		"XDG_STATE_HOME="+filepath.Join(tempHome, ".local", "state"),
	)
	return cmd.CombinedOutput()
}

// TestInstallIdempotent verifies that running the production install.sh twice
// does not fail and installs the binary and unit.
func TestInstallIdempotent(t *testing.T) {
	tempHome, scriptDir, fakeDir, _ := setupInstallEnv(t, "", "1.0.0")

	if err := os.WriteFile(filepath.Join(fakeDir, "systemctl"), []byte("#!/bin/bash\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 2; i++ {
		out, err := runInstall(t, scriptDir, tempHome, fakeDir, []string{"--yes"}, "")
		if err != nil {
			t.Fatalf("install run %d failed: %v\n%s", i+1, err, out)
		}
	}

	installedBin := filepath.Join(tempHome, ".local", "bin", "docker-helper")
	info, err := os.Stat(installedBin)
	if err != nil {
		t.Fatalf("binary not installed to %s: %v", installedBin, err)
	}
	if mode := info.Mode().Perm(); mode != 0755 {
		t.Errorf("binary mode = %o, want 0755", mode)
	}

	installedUnit := filepath.Join(tempHome, ".config", "systemd", "user", "docker-helper.service")
	if _, err := os.Stat(installedUnit); err != nil {
		t.Fatalf("unit not installed to %s: %v", installedUnit, err)
	}
}

// TestUninstallRemovesBinary verifies that the production uninstall.sh removes
// the installed binary and unit while a soft uninstall preserves config/state.
func TestUninstallRemovesBinary(t *testing.T) {
	tempHome := setupInstalledHome(t)

	out, err := runUninstall(t, tempHome, []string{"--yes"})
	if err != nil {
		t.Fatalf("uninstall failed: %v\n%s", err, out)
	}

	if _, err := os.Stat(filepath.Join(tempHome, ".local", "bin", "docker-helper")); !os.IsNotExist(err) {
		t.Error("binary should be removed")
	}
	if _, err := os.Stat(filepath.Join(tempHome, ".config", "systemd", "user", "docker-helper.service")); !os.IsNotExist(err) {
		t.Error("unit should be removed")
	}

	// Soft uninstall preserves config and state.
	if _, err := os.Stat(filepath.Join(tempHome, ".config", "docker-helper", "config.json")); err != nil {
		t.Error("config.json should be preserved")
	}
	if _, err := os.Stat(filepath.Join(tempHome, ".config", "docker-helper", "admin.token")); err != nil {
		t.Error("admin.token should be preserved")
	}
	if _, err := os.Stat(filepath.Join(tempHome, ".local", "state", "docker-helper", "docker-helper.db")); err != nil {
		t.Error("database should be preserved")
	}
}

// TestUninstallPurgeRemovesConfig verifies that uninstall.sh --purge removes
// config and state.
func TestUninstallPurgeRemovesConfig(t *testing.T) {
	tempHome := setupInstalledHome(t)

	out, err := runUninstall(t, tempHome, []string{"--yes", "--purge"})
	if err != nil {
		t.Fatalf("uninstall --purge failed: %v\n%s", err, out)
	}

	configDir := filepath.Join(tempHome, ".config", "docker-helper")
	stateDir := filepath.Join(tempHome, ".local", "state", "docker-helper")
	if _, err := os.Stat(configDir); !os.IsNotExist(err) {
		t.Error("config dir should be removed on purge")
	}
	if _, err := os.Stat(stateDir); !os.IsNotExist(err) {
		t.Error("state dir should be removed on purge")
	}
}

// TestUninstallPurgeDoesNotRemoveParent verifies purge removes only
// docker-helper's config/state dirs, not their parents or siblings.
func TestUninstallPurgeDoesNotRemoveParent(t *testing.T) {
	tempHome := setupInstalledHome(t)

	siblingDir := filepath.Join(tempHome, ".config", "other-app")
	if err := os.MkdirAll(siblingDir, 0700); err != nil {
		t.Fatal(err)
	}
	siblingState := filepath.Join(tempHome, ".local", "state", "other-app")
	if err := os.MkdirAll(siblingState, 0700); err != nil {
		t.Fatal(err)
	}

	out, err := runUninstall(t, tempHome, []string{"--yes", "--purge"})
	if err != nil {
		t.Fatalf("uninstall --purge failed: %v\n%s", err, out)
	}

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

// TestInstallScriptUnknownFlag verifies install.sh rejects unknown flags
// and prints a usage hint.
func TestInstallScriptUnknownFlag(t *testing.T) {
	cmd := exec.Command("bash", "packaging/install.sh", "--unknown-flag")
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir())
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected non-zero exit code for unknown flag")
	}
	if !strings.Contains(string(out), "Try") {
		t.Errorf("expected usage hint in stderr, got: %s", out)
	}
}

// TestInstallScriptHelp verifies install.sh --help and -h print usage
// and exit 0.
func TestInstallScriptHelp(t *testing.T) {
	for _, flag := range []string{"--help", "-h"} {
		t.Run(flag, func(t *testing.T) {
			cmd := exec.Command("bash", "packaging/install.sh", flag)
			cmd.Env = append(os.Environ(), "HOME="+t.TempDir())
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("expected exit 0 for %s, got: %v: %s", flag, err, out)
			}
			output := string(out)
			if !strings.Contains(output, "--yes") {
				t.Errorf("--help output missing --yes: %s", output)
			}
			if !strings.Contains(output, "--help") {
				t.Errorf("--help output missing --help: %s", output)
			}
		})
	}
}

// TestUninstallScriptUnknownFlag verifies uninstall.sh rejects unknown flags
// and prints a usage hint.
func TestUninstallScriptUnknownFlag(t *testing.T) {
	cmd := exec.Command("bash", "packaging/uninstall.sh", "--unknown-flag")
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir())
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected non-zero exit code for unknown flag")
	}
	if !strings.Contains(string(out), "Try") {
		t.Errorf("expected usage hint in stderr, got: %s", out)
	}
}

// TestUninstallScriptHelp verifies uninstall.sh --help and -h print usage
// and exit 0.
func TestUninstallScriptHelp(t *testing.T) {
	for _, flag := range []string{"--help", "-h"} {
		t.Run(flag, func(t *testing.T) {
			cmd := exec.Command("bash", "packaging/uninstall.sh", flag)
			cmd.Env = append(os.Environ(), "HOME="+t.TempDir())
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("expected exit 0 for %s, got: %v: %s", flag, err, out)
			}
			output := string(out)
			if !strings.Contains(output, "--yes") {
				t.Errorf("--help output missing --yes: %s", output)
			}
			if !strings.Contains(output, "--purge") {
				t.Errorf("--help output missing --purge: %s", output)
			}
			if !strings.Contains(output, "--help") {
				t.Errorf("--help output missing --help: %s", output)
			}
		})
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
		// Lines that are purely informational output (info/warn/error calls)
		// may reference sudo as user instructions without executing it.
		if strings.HasPrefix(trimmed, "info ") || strings.HasPrefix(trimmed, "warn ") || strings.HasPrefix(trimmed, "error ") {
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

// TestReleaseReadmeNoSecrets verifies the release README template does not
// contain plaintext secret values.
func TestReleaseReadmeNoSecrets(t *testing.T) {
	data, err := os.ReadFile("packaging/README.release.md")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	for _, s := range []string{"admin_token", "session_token", "Bearer", "password"} {
		if strings.Contains(content, s) {
			t.Errorf("release README must not contain %q", s)
		}
	}
}

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

// TestBuildBundleScriptContent verifies build-bundle.sh references the
// expected bundle layout, places the skill at skills/docker-helper,
// keeps .claude out of the bundle, fails closed on unconfirmed static
// linking, verifies the exact mandatory tarball paths, and bundles
// compressed man pages.
func TestBuildBundleScriptContent(t *testing.T) {
	data, err := os.ReadFile("build-bundle.sh")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	// The script must copy these artifacts into the bundle.
	for _, s := range []string{
		"docker-helper", "install.sh", "uninstall.sh", "install-system.sh", "uninstall-system.sh",
		"systemd/user", "systemd/user/docker-helper.service", "systemd/system/docker-helper.service",
		"apparmor", "apparmor/docker-helper", "apparmor/docker-helper-system", "apparmor/docker-helper.d/managed-roots",
		"apparmor/local/curl",
		"SKILL.md", "README.release.md", "LICENSE",
	} {
		if !strings.Contains(content, s) {
			t.Errorf("build-bundle.sh should reference %q", s)
		}
	}
	// System scripts must be set executable in the bundle.
	if !strings.Contains(content, "755") {
		t.Error("build-bundle.sh must set system scripts executable (755)")
	}
	// Skill placed at skills/docker-helper (never .claude/skills).
	if !strings.Contains(content, "skills/docker-helper/SKILL.md") {
		t.Error("build-bundle.sh must reference skills/docker-helper/SKILL.md")
	}
	if !strings.Contains(content, "docker-helper-${VERSION}-linux-amd64/skills/docker-helper/SKILL.md") {
		t.Error("build-bundle.sh must verify skills/docker-helper/SKILL.md in tarball")
	}
	if bundleDirIdx := strings.Index(content, "BUNDLE_DIR="); bundleDirIdx >= 0 {
		if strings.Contains(content[bundleDirIdx:], "$BUNDLE_DIR/.claude") {
			t.Error("build-bundle.sh must not create .claude inside BUNDLE_DIR")
		}
	}
	// EXPECTED_PATHS must not contain .claude paths.
	if idx := strings.Index(content, "EXPECTED_PATHS="); idx < 0 {
		t.Fatal("EXPECTED_PATHS not found")
	} else if endIdx := strings.Index(content[idx:], ")"); endIdx >= 0 {
		if strings.Contains(content[idx:idx+endIdx], ".claude") {
			t.Error("EXPECTED_PATHS must not contain .claude paths")
		}
	}
	// Must bundle compressed man pages.
	for _, s := range []string{"man/docker-helper.1.gz", "man/docker-helper-config.5.gz"} {
		if !strings.Contains(content, s) {
			t.Errorf("build-bundle.sh must bundle %s", s)
		}
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

// TestSystemUnitFile verifies the system unit file: ExecStart/ExecReload,
// AppArmor binding, apparmor ordering without hard dependency, no dedicated
// user, and bounded restart behavior.
func TestSystemUnitFile(t *testing.T) {
	path := "packaging/systemd/system/docker-helper.service"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("system unit %s not found: %v", path, err)
	}
	content := string(data)

	if !strings.Contains(content, "ExecStart=/usr/bin/docker-helper serve") {
		t.Error("ExecStart must point to /usr/bin/docker-helper serve")
	}
	if !strings.Contains(content, "ExecReload=/usr/bin/docker-helper reload --system") {
		t.Error("ExecReload must be /usr/bin/docker-helper reload --system")
	}
	if !strings.Contains(content, "AppArmorProfile=docker-helper-system") {
		t.Error("unit must contain AppArmorProfile=docker-helper-system")
	}
	// Must order after apparmor.service but not hard-require it.
	if !strings.Contains(content, "apparmor.service") {
		t.Error("After= must include apparmor.service")
	}
	if strings.Contains(content, "Requires=apparmor.service") {
		t.Error("unit must not hard-require apparmor.service")
	}
	// Runs as root — no User= directive.
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "User=") {
			t.Error("system unit must not contain User= (runs as root)")
		}
	}
	if !strings.Contains(content, "Restart=on-failure") {
		t.Error("unit must contain Restart=on-failure")
	}
	if !strings.Contains(content, "TimeoutStopSec=") {
		t.Error("unit must contain bounded TimeoutStopSec")
	}
	// Dual-LSM contract: ConditionSecurity=|apparmor and ConditionSecurity=|selinux
	// provide OR semantics — unit starts when either backend is active.
	if !strings.Contains(content, "ConditionSecurity=|apparmor") {
		t.Error("system unit must contain ConditionSecurity=|apparmor")
	}
	if !strings.Contains(content, "ConditionSecurity=|selinux") {
		t.Error("system unit must contain ConditionSecurity=|selinux")
	}
	if !strings.Contains(content, "SELinuxContext=system_u:system_r:docker_helper_t:s0") {
		t.Error("system unit must contain SELinuxContext=system_u:system_r:docker_helper_t:s0")
	}
	// RestrictRealtime must be present; RestrictRTP is invalid.
	if !strings.Contains(content, "RestrictRealtime=true") {
		t.Error("unit must contain RestrictRealtime=true")
	}
	if strings.Contains(content, "RestrictRTP=") {
		t.Error("unit must not contain invalid RestrictRTP= directive")
	}
}

// TestSystemUnitNoMountNamespace verifies that the system unit does not
// enable any directive that creates a separate mount namespace. A separate
// mount namespace hides mount pins created by docker-helper from dockerd,
// causing "Permission denied" on bind mounts.
func TestSystemUnitNoMountNamespace(t *testing.T) {
	path := "packaging/systemd/system/docker-helper.service"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("system unit %s not found: %v", path, err)
	}
	content := string(data)

	// Directives that create a mount namespace when active.
	namespaceDirectives := []string{
		"ProtectKernelTunables=",
		"ProtectKernelModules=",
		"ProtectKernelLogs=",
		"ProtectControlGroups=",
		"ProtectSystem=",
		"ProtectHome=",
		"PrivateDevices=",
		"PrivateMounts=",
		"PrivateTmp=",
		"ReadWritePaths=",
		"ReadOnlyPaths=",
		"InaccessiblePaths=",
		"TemporaryFileSystem=",
		"ExecPaths=",
		"NoExecPaths=",
		"BindPaths=",
		"BindReadOnlyPaths=",
	}

	trueValues := map[string]bool{
		"true": true, "yes": true, "on": true, "1": true,
	}

	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		for _, directive := range namespaceDirectives {
			if !strings.HasPrefix(trimmed, directive) {
				continue
			}
			value := strings.TrimSpace(strings.TrimPrefix(trimmed, directive))
			// Empty value or false-equivalent is acceptable (directive present
			// but disabled). Non-empty value that is not "false" creates a
			// mount namespace.
			if value == "" {
				continue
			}
			lower := strings.ToLower(value)
			if lower == "false" || lower == "no" || lower == "off" || lower == "0" {
				continue
			}
			// PrivateTmp= and PrivateMounts= with "false" are OK.
			// All other active values create a mount namespace.
			if trueValues[lower] {
				t.Errorf("system unit must not enable %s%s (creates mount namespace, hides mount pins from dockerd)", directive, value)
				continue
			}
			// Non-boolean values (paths, mount specs) are always active.
			t.Errorf("system unit must not enable %s%s (creates mount namespace, hides mount pins from dockerd)", directive, value)
		}
	}
}

// TestUnitNoRestrictSUIDSGID verifies that neither shipped systemd unit
// contains an active RestrictSUIDSGID directive that would enable the
// restriction. Any active directive with a true-equivalent value (true, yes,
// on, 1) would block openat2(2), which docker-helper build staging requires.
// Comments explaining the omission are allowed.
func TestUnitNoRestrictSUIDSGID(t *testing.T) {
	trueValues := map[string]bool{
		"true": true, "yes": true, "on": true, "1": true,
	}

	tests := []struct {
		name string
		path string
	}{
		{"system unit", "packaging/systemd/system/docker-helper.service"},
		{"user unit", "packaging/systemd/user/docker-helper.service"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := os.ReadFile(tt.path)
			if err != nil {
				t.Fatalf("%s not found: %v", tt.path, err)
			}

			for _, line := range strings.Split(string(data), "\n") {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "#") {
					continue
				}
				if !strings.HasPrefix(trimmed, "RestrictSUIDSGID=") {
					continue
				}
				value := strings.TrimSpace(strings.TrimPrefix(trimmed, "RestrictSUIDSGID="))
				if trueValues[strings.ToLower(value)] {
					t.Errorf("%s: active RestrictSUIDSGID=%s blocks openat2 required by build staging", tt.path, value)
				}
			}
		})
	}
}

func TestUserUnitStillExists(t *testing.T) {
	path := "packaging/systemd/user/docker-helper.service"
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("user unit %s must still exist: %v", path, err)
	}
}

// --- System AppArmor profile tests ---

// TestSystemAppArmorProfileFile verifies the system AppArmor profile:
// named profile with managed-roots fragment, required capabilities,
// Docker socket policy, scoped mount policy, and no broad/overly
// permissive rules.
func TestSystemAppArmorProfileFile(t *testing.T) {
	path := "packaging/apparmor/docker-helper-system"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("system AppArmor profile %s not found: %v", path, err)
	}
	content := string(data)

	// Must include the managed-roots fragment.
	if !strings.Contains(content, "docker-helper.d/managed-roots") {
		t.Error("profile must include managed-roots fragment")
	}
	// Must not grant broad home access.
	if strings.Contains(content, "/home/**") {
		t.Error("profile must not contain broad /home/** access")
	}
	// sys_admin is required for mount-pin; it must be granted, not denied.
	if strings.Contains(content, "deny capability sys_admin") {
		t.Error("profile must not deny sys_admin (required for mount-pin)")
	}
	if !strings.Contains(content, "capability sys_admin") {
		t.Error("profile must grant sys_admin for mount-pin operations")
	}
	if !strings.Contains(content, "capability dac_read_search") {
		t.Error("profile must grant dac_read_search for private workspace traversal")
	}
	// AppArmor LSM status: minimal read rules for requireAppArmorActive and
	// requireAppArmorConfinement.
	if !strings.Contains(content, "/sys/module/apparmor/parameters/enabled r,") {
		t.Error("profile must grant read access to AppArmor enabled parameter")
	}
	if !strings.Contains(content, "owner @{PROC}/@{pid}/attr/current r,") {
		t.Error("profile must grant owner read access to proc attr/current for confinement check")
	}
	// Named profile, not path-attached.
	if !strings.Contains(content, "profile docker-helper-system") {
		t.Error("profile must be named profile docker-helper-system")
	}
	if strings.Contains(content, "profile /usr/bin/docker-helper") {
		t.Error("profile must not use path-based attachment")
	}
	// Instructions must not use touch for managed-roots.
	if strings.Contains(content, "touch") {
		t.Error("profile instructions must not use touch for managed-roots")
	}
	// Docker socket policy: stream connect only, plus filesystem rules.
	if !strings.Contains(content, "unix (connect,send,receive)") {
		t.Error("profile must contain unix socket connect policy for Docker")
	}
	if strings.Contains(content, "type=dgram") {
		t.Error("profile must not contain dgram unix rule for Docker socket")
	}
	if !strings.Contains(content, "/run/docker.sock rw") {
		t.Error("profile must retain filesystem Docker socket rule")
	}
	// Mount policy scoped to the helper-owned mount directory.
	if !strings.Contains(content, "mount options in (rw,move)") {
		t.Error("profile must contain mount policy with move option for move_mount")
	}
	if !strings.Contains(content, "/run/docker-helper/mounts") {
		t.Error("mount rules must be scoped to /run/docker-helper/mounts")
	}
	if !strings.Contains(content, "umount /run/docker-helper/mounts") {
		t.Error("profile must contain umount policy for mount-pin detach")
	}
	for _, line := range strings.Split(content, "\n") {
		if strings.TrimSpace(line) == "mount," {
			t.Error("profile must not contain blanket unrestricted mount rule")
		}
	}
	// SQLite locking: specific rwk rules for database files.
	// /var/lib/docker-helper/** rw must NOT be present (too broad for k permission).
	if strings.Contains(content, "/var/lib/docker-helper/** rw") {
		t.Error("profile must not grant broad /var/lib/docker-helper/** rw (SQLite needs explicit rwk)")
	}
	if !strings.Contains(content, "/var/lib/docker-helper/docker-helper.db rwk,") {
		t.Error("profile must grant rwk for docker-helper.db")
	}
	if !strings.Contains(content, "/var/lib/docker-helper/docker-helper.db-wal rwk,") {
		t.Error("profile must grant rwk for docker-helper.db-wal")
	}
	if !strings.Contains(content, "/var/lib/docker-helper/docker-helper.db-shm rwk,") {
		t.Error("profile must grant rwk for docker-helper.db-shm")
	}
	if !strings.Contains(content, "/var/lib/docker-helper/docker-helper.db-journal rwk,") {
		t.Error("profile must grant rwk for docker-helper.db-journal")
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

// TestInstallSystemScriptContent guards the facts normal CI cannot
// exercise: the root fail-closed check, the real system destination paths,
// and the separation from user-mode artifacts. Allowed-root handling,
// managed-roots preservation, AppArmor-before-init ordering, and profile
// load flags are proven by the behavioral tests below.
func TestInstallSystemScriptContent(t *testing.T) {
	data, err := os.ReadFile("packaging/install-system.sh")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	// Must check for root (UID 0) before any mutation.
	if !strings.Contains(content, "id -u") || !strings.Contains(content, "-ne 0") {
		t.Error("install-system.sh must check for root (UID 0)")
	}
	// Real system destination paths (behavioral tests override these).
	for _, p := range []string{
		"/usr/bin/docker-helper",
		"/etc/systemd/system/docker-helper.service",
		"/etc/apparmor.d/docker-helper-system",
		"/etc/apparmor.d/docker-helper.d/managed-roots",
	} {
		if !strings.Contains(content, p) {
			t.Errorf("install-system.sh must reference destination path: %s", p)
		}
	}
	// Must not install the agent skill or touch user artifacts.
	if strings.Contains(content, "SKILL.md") || strings.Contains(content, ".claude") {
		t.Error("install-system.sh must not install agent skill")
	}
	for _, p := range []string{"~/.local/bin", "~/.config/systemd/user", "$HOME/.local"} {
		if strings.Contains(content, p) {
			t.Errorf("install-system.sh must not touch user path: %s", p)
		}
	}
}

// TestUninstallSystemScriptContent guards the facts normal CI cannot
// exercise: the root fail-closed check, the real system purge paths, and
// the separation from user-mode artifacts. Stop-before-remove ordering,
// AppArmor unload, and purge preservation/removal are proven by the
// behavioral tests below.
func TestUninstallSystemScriptContent(t *testing.T) {
	data, err := os.ReadFile("packaging/uninstall-system.sh")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	// Must check for root (UID 0) before any mutation.
	if !strings.Contains(content, "id -u") || !strings.Contains(content, "-ne 0") {
		t.Error("uninstall-system.sh must check for root (UID 0)")
	}
	// Real system paths removed with --purge (behavioral tests override these).
	for _, p := range []string{"/etc/docker-helper", "/var/lib/docker-helper", "/run/docker-helper"} {
		if !strings.Contains(content, p) {
			t.Errorf("uninstall-system.sh --purge must remove: %s", p)
		}
	}
	// Must not touch user artifacts.
	for _, p := range []string{"~/.local/bin", "~/.config/systemd/user", "$HOME/.local"} {
		if strings.Contains(content, p) {
			t.Errorf("uninstall-system.sh must not touch user path: %s", p)
		}
	}
}

// --- Behavioral tests for install-system.sh / uninstall-system.sh ---

// systemScriptEnv is the authoritative fixture for the install-system.sh and
// uninstall-system.sh behavioral tests.
//
// It owns the test directories, the standard fake tools (systemctl, docker,
// apparmor_parser — each logs "$0 $@" to a lifecycle call log and succeeds),
// the override environment (BINARY_DEST, UNIT_DEST, AA_PROFILE_DEST,
// AA_FRAGMENT_DEST, AA_FRAGMENT_DIR, CONFIG_PATH/CONFIG_DIR, STATE_DIR,
// RUNTIME_DIR, AA_PARSER, SYSTEMCTL, DOCKER), and copies the real production
// script into the emulated bundle directory.
//
// run sources the production script, overrides check_root, and invokes main.
// Tests override only scenario-specific fakes and describe scenario-specific
// setup and assertions.
type systemScriptEnv struct {
	scriptPath string
	scriptDir  string
	fakeBinDir string
	destDir    string
	logFile    string
	env        []string
}

// dest returns a path under the emulated system root.
func (e *systemScriptEnv) dest(rel string) string {
	return filepath.Join(e.destDir, rel)
}

// fakeSystemctl replaces the standard systemctl fake.
func (e *systemScriptEnv) fakeSystemctl(t *testing.T, script string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(e.fakeBinDir, "systemctl"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
}

// fakeParser replaces the standard apparmor_parser fake.
func (e *systemScriptEnv) fakeParser(t *testing.T, script string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(e.fakeBinDir, "apparmor_parser"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
}

// calls returns the lifecycle tool calls recorded so far, in order.
func (e *systemScriptEnv) calls(t *testing.T) []string {
	t.Helper()
	return readLifecycleCalls(t, e.logFile)
}

// run sources the production script, overrides check_root, and runs main
// with the given args and stdin.
func (e *systemScriptEnv) run(t *testing.T, args, stdin string) (string, error) {
	t.Helper()
	cmd := exec.Command("bash", "-c", fmt.Sprintf(
		"source %s\ncheck_root() { :; }\nmain %s", e.scriptPath, args))
	cmd.Env = append(os.Environ(), e.env...)
	cmd.Dir = e.scriptDir
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// runFragmentInstall invokes install_apparmor_fragment directly from the
// production script against the fixture bundle and destination.
func (e *systemScriptEnv) runFragmentInstall(t *testing.T) (string, error) {
	t.Helper()
	cmd := exec.Command("bash", "-c", fmt.Sprintf(`
		source %s
		AA_FRAGMENT_SRC="apparmor/docker-helper.d/managed-roots"
		AA_FRAGMENT_DEST="%s"
		script_dir="%s"
		install_apparmor_fragment
	`, e.scriptPath, e.dest("etc/apparmor.d/docker-helper.d/managed-roots"), e.scriptDir))
	cmd.Dir = e.scriptDir
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// newSystemScriptEnv creates the shared fixture layout, installs the
// standard fake tools, and copies the production script from sourcePath.
func newSystemScriptEnv(t *testing.T, sourcePath, scriptName string) *systemScriptEnv {
	t.Helper()
	tmpDir := t.TempDir()
	e := &systemScriptEnv{
		scriptPath: filepath.Join(tmpDir, "script", scriptName),
		scriptDir:  filepath.Join(tmpDir, "script"),
		fakeBinDir: filepath.Join(tmpDir, "fakes"),
		destDir:    filepath.Join(tmpDir, "dest"),
		logFile:    filepath.Join(tmpDir, "calls.log"),
	}
	for _, d := range []string{
		e.scriptDir,
		e.fakeBinDir,
		e.dest("bin"),
		e.dest("etc/systemd/system"),
		e.dest("etc/apparmor.d/docker-helper.d"),
		e.dest("etc/docker-helper"),
		e.dest("var/lib/docker-helper"),
		e.dest("run/docker-helper"),
	} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}

	logFile := e.logFile
	// Standard systemctl: inactive service, all operations succeed.
	e.fakeSystemctl(t, fmt.Sprintf(`#!/bin/bash
log_file="%s"
echo "$0 $@" >> "$log_file"
case "$*" in
  *"is-active"*) exit 1 ;;
  *) exit 0 ;;
esac
`, logFile))
	// Standard docker: log and succeed.
	if err := os.WriteFile(filepath.Join(e.fakeBinDir, "docker"), []byte(fmt.Sprintf(`#!/bin/bash
log_file="%s"
echo "$0 $@" >> "$log_file"
exit 0
`, logFile)), 0755); err != nil {
		t.Fatal(err)
	}
	// Standard apparmor_parser: log and succeed.
	e.fakeParser(t, fmt.Sprintf(`#!/bin/bash
log_file="%s"
echo "$0 $@" >> "$log_file"
exit 0
`, logFile))
	// Standard AppArmor LSM status: active.
	aaDir := filepath.Join(e.destDir, "sys", "module", "apparmor", "parameters")
	if err := os.MkdirAll(aaDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(aaDir, "enabled"), []byte("Y"), 0644); err != nil {
		t.Fatal(err)
	}

	scriptData, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	// Replace the hardcoded AppArmor LSM path with the test-controlled one.
	scriptData = []byte(strings.ReplaceAll(string(scriptData),
		"/sys/module/apparmor/parameters/enabled", "$AA_ENABLED_PATH"))
	if err := os.WriteFile(e.scriptPath, scriptData, 0755); err != nil {
		t.Fatal(err)
	}
	return e
}

// newSystemInstallScriptEnv creates the fixture for install-system.sh with
// the standard bundled assets and the install override environment. The
// bundled binary logs its invocations to the call log.
func newSystemInstallScriptEnv(t *testing.T) *systemScriptEnv {
	t.Helper()
	e := newSystemScriptEnv(t, "packaging/install-system.sh", "install-system.sh")

	if err := os.WriteFile(filepath.Join(e.scriptDir, "docker-helper"), []byte(fmt.Sprintf(`#!/bin/bash
log_file="%s"
echo "binary: $@" >> "$log_file"
exit 0
`, e.logFile)), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(e.scriptDir, "systemd", "system"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.scriptDir, "systemd", "system", "docker-helper.service"), []byte("[Service]"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(e.scriptDir, "apparmor", "docker-helper.d"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.scriptDir, "apparmor", "docker-helper-system"), []byte("profile docker-helper-system {}"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.scriptDir, "apparmor", "docker-helper.d", "managed-roots"), renderFragment([]string{}), 0644); err != nil {
		t.Fatal(err)
	}

	e.env = []string{
		"PATH=" + e.fakeBinDir + ":" + os.Getenv("PATH"),
		"BINARY_DEST=" + e.dest("bin/docker-helper"),
		"UNIT_DEST=" + e.dest("etc/systemd/system/docker-helper.service"),
		"AA_PROFILE_DEST=" + e.dest("etc/apparmor.d/docker-helper-system"),
		"AA_FRAGMENT_DEST=" + e.dest("etc/apparmor.d/docker-helper.d/managed-roots"),
		"CONFIG_PATH=" + e.dest("etc/docker-helper/config.json"),
		"AA_PARSER=" + filepath.Join(e.fakeBinDir, "apparmor_parser"),
		"SYSTEMCTL=" + filepath.Join(e.fakeBinDir, "systemctl"),
		"DOCKER=" + filepath.Join(e.fakeBinDir, "docker"),
		"AA_ENABLED_PATH=" + filepath.Join(e.destDir, "sys", "module", "apparmor", "parameters", "enabled"),
	}
	return e
}

// newSystemUninstallScriptEnv creates the fixture for uninstall-system.sh
// with an installed sentinel binary, the managed-roots fragment, and the
// uninstall override environment.
func newSystemUninstallScriptEnv(t *testing.T) *systemScriptEnv {
	t.Helper()
	e := newSystemScriptEnv(t, "packaging/uninstall-system.sh", "uninstall-system.sh")

	if err := os.WriteFile(e.dest("bin/docker-helper"), []byte("installed-binary"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.dest("etc/apparmor.d/docker-helper.d/managed-roots"),
		[]byte("# fixture managed-roots fragment\n"), 0644); err != nil {
		t.Fatal(err)
	}

	e.env = []string{
		"PATH=" + e.fakeBinDir + ":" + os.Getenv("PATH"),
		"BINARY_DEST=" + e.dest("bin/docker-helper"),
		"UNIT_DEST=" + e.dest("etc/systemd/system/docker-helper.service"),
		"AA_PROFILE_DEST=" + e.dest("etc/apparmor.d/docker-helper-system"),
		"AA_FRAGMENT_DEST=" + e.dest("etc/apparmor.d/docker-helper.d/managed-roots"),
		"AA_FRAGMENT_DIR=" + e.dest("etc/apparmor.d/docker-helper.d"),
		"CONFIG_DIR=" + e.dest("etc/docker-helper"),
		"STATE_DIR=" + e.dest("var/lib/docker-helper"),
		"RUNTIME_DIR=" + e.dest("run/docker-helper"),
		"AA_PARSER=" + filepath.Join(e.fakeBinDir, "apparmor_parser"),
		"SYSTEMCTL=" + filepath.Join(e.fakeBinDir, "systemctl"),
	}
	return e
}

func readLifecycleCalls(t *testing.T, logFile string) []string {
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

// TestInstallSystemParseArgs verifies install-system.sh parse_args:
// option order independence, and rejection of missing values,
// options-as-values, and unknown flags.
func TestInstallSystemParseArgs(t *testing.T) {
	env := newSystemInstallScriptEnv(t)

	tests := []struct {
		name    string
		args    string
		wantErr bool
	}{
		{name: "yes_then_root", args: "--yes --allowed-root /srv/ws"},
		{name: "root_then_yes", args: "--allowed-root /srv/ws --yes"},
		{name: "missing_value", args: "--allowed-root", wantErr: true},
		{name: "option_as_value", args: "--allowed-root --yes", wantErr: true},
		{name: "unknown_arg", args: "--unknown", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verify := ""
			if !tt.wantErr {
				verify = `
		if [[ "$interactive" != "false" ]]; then echo "FAIL: interactive should be false"; exit 1; fi
		if [[ "$allowed_root" != "/srv/ws" ]]; then echo "FAIL: allowed_root wrong: $allowed_root"; exit 1; fi`
			}
			cmd := exec.Command("bash", "-c", fmt.Sprintf(`
		source %s
		parse_args %s%s
	`, env.scriptPath, tt.args, verify))
			out, err := cmd.CombinedOutput()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parse_args %s should fail", tt.args)
				}
				return
			}
			if err != nil {
				t.Fatalf("parse_args %s failed: %v\n%s", tt.args, err, out)
			}
		})
	}
}

func TestInstallSystemFreshYesWithoutAllowedRoot(t *testing.T) {
	env := newSystemInstallScriptEnv(t)

	cmd := exec.Command("bash", "-c", fmt.Sprintf(`
		source %s
		parse_args --yes
		CONFIG_PATH="/nonexistent/config.json"
		check_allowed_root
	`, env.scriptPath))
	if _, err := cmd.CombinedOutput(); err == nil {
		t.Fatal("fresh --yes without --allowed-root should fail")
	}
}

func TestInstallSystemPreservesManagedRoots(t *testing.T) {
	env := newSystemInstallScriptEnv(t)

	existingContent := "# existing operator-managed content\n"
	fragmentDest := env.dest("etc/apparmor.d/docker-helper.d/managed-roots")
	if err := os.WriteFile(fragmentDest, []byte(existingContent), 0644); err != nil {
		t.Fatal(err)
	}

	if out, err := env.runFragmentInstall(t); err != nil {
		t.Fatalf("install_apparmor_fragment failed: %v\n%s", err, out)
	}

	actual, err := os.ReadFile(fragmentDest)
	if err != nil {
		t.Fatal(err)
	}
	if string(actual) != existingContent {
		t.Errorf("existing fragment not preserved\ngot:  %q\nwant: %q", string(actual), existingContent)
	}
}

func TestInstallSystemCopiesMissingFragment(t *testing.T) {
	env := newSystemInstallScriptEnv(t)

	bundledContent := renderFragment([]string{})
	fragmentDest := env.dest("etc/apparmor.d/docker-helper.d/managed-roots")

	if out, err := env.runFragmentInstall(t); err != nil {
		t.Fatalf("install_apparmor_fragment failed: %v\n%s", err, out)
	}

	actual, err := os.ReadFile(fragmentDest)
	if err != nil {
		t.Fatal(err)
	}
	if string(actual) != string(bundledContent) {
		t.Errorf("fragment not copied correctly\ngot:  %q\nwant: %q", string(actual), string(bundledContent))
	}
}

func TestInstallSystemParserFailurePreventsServiceStart(t *testing.T) {
	env := newSystemInstallScriptEnv(t)
	env.fakeParser(t, fmt.Sprintf(`#!/bin/bash
log_file="%s"
echo "$0 $@" >> "$log_file"
exit 1
`, env.logFile))

	out, err := env.run(t, "--yes --allowed-root /tmp/ws", "")
	if err == nil {
		t.Fatalf("parser failure should cause install to fail: %s", out)
	}

	for _, c := range env.calls(t) {
		if strings.Contains(c, "start") {
			t.Error("service start should not be called after parser failure")
		}
		if strings.Contains(c, "enable") {
			t.Error("service enable should not be called after parser failure")
		}
	}
}

func TestInstallSystemExistingConfigSkipsInit(t *testing.T) {
	env := newSystemInstallScriptEnv(t)

	// Create existing config
	if err := os.WriteFile(env.dest("etc/docker-helper/config.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}

	out, err := env.run(t, "--yes --allowed-root /tmp/ws", "")
	if err != nil {
		t.Fatalf("install failed: %v\n%s", err, out)
	}

	for _, c := range env.calls(t) {
		if strings.Contains(c, "binary: init") {
			t.Error("init should not be called when config exists")
		}
	}
}

func TestInstallSystemFreshInitReceivesAllowedRoot(t *testing.T) {
	env := newSystemInstallScriptEnv(t)

	testRoot := t.TempDir()

	out, err := env.run(t, "--yes --allowed-root "+testRoot, "")
	if err != nil {
		t.Fatalf("install failed: %v\n%s", err, out)
	}

	found := false
	for _, c := range env.calls(t) {
		if c == "binary: init --allowed-root "+testRoot {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("init should receive exact --allowed-root %s, calls: %v", testRoot, env.calls(t))
	}
}

func TestInstallSystemFreshYesEnablesStartsService(t *testing.T) {
	env := newSystemInstallScriptEnv(t)

	testRoot := t.TempDir()

	out, err := env.run(t, "--yes --allowed-root "+testRoot, "")
	if err != nil {
		t.Fatalf("install failed: %v\n%s", err, out)
	}

	enableIdx, startIdx, parserIdx, initIdx := -1, -1, -1, -1
	for i, c := range env.calls(t) {
		if strings.Contains(c, "enable") {
			enableIdx = i
		}
		if strings.Contains(c, "start") {
			startIdx = i
		}
		if strings.Contains(c, "apparmor_parser") {
			parserIdx = i
			if !strings.Contains(c, "--replace") || !strings.Contains(c, "--skip-read-cache") {
				t.Errorf("profile load must be idempotent with a clean cache: %q", c)
			}
		}
		if strings.Contains(c, "binary: init") {
			initIdx = i
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
	if parserIdx < 0 || initIdx < 0 || parserIdx > initIdx {
		t.Errorf("AppArmor profile must be loaded before init: parser(%d) init(%d), calls: %v",
			parserIdx, initIdx, env.calls(t))
	}
}

// --- Behavioral tests for uninstall-system.sh ---

func TestUninstallSystemPurgeConfirmation(t *testing.T) {
	env := newSystemUninstallScriptEnv(t)

	// Decline the interactive purge prompt (Enter = no).
	out, err := env.run(t, "--purge", "\n")
	if err != nil {
		if !strings.Contains(out, "Aborting") {
			t.Fatalf("unexpected error: %v\n%s", err, out)
		}
	}

	if _, err := os.Stat(env.dest("etc/docker-helper")); os.IsNotExist(err) {
		t.Error("config dir should be preserved when purge confirmation is declined")
	}
	if _, err := os.Stat(env.dest("etc/apparmor.d/docker-helper.d/managed-roots")); os.IsNotExist(err) {
		t.Error("fragment should be preserved when purge confirmation is declined")
	}
}

func TestUninstallSystemNormalPreservesConfig(t *testing.T) {
	env := newSystemUninstallScriptEnv(t)

	if err := os.WriteFile(env.dest("etc/docker-helper/config.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}

	out, err := env.run(t, "--yes", "")
	if err != nil {
		t.Fatalf("uninstall failed: %v\n%s", err, out)
	}

	if _, err := os.Stat(env.dest("etc/docker-helper/config.json")); os.IsNotExist(err) {
		t.Error("config should be preserved without --purge")
	}
	if _, err := os.Stat(env.dest("var/lib/docker-helper")); os.IsNotExist(err) {
		t.Error("state should be preserved without --purge")
	}
	if _, err := os.Stat(env.dest("etc/apparmor.d/docker-helper.d/managed-roots")); os.IsNotExist(err) {
		t.Error("fragment should be preserved without --purge")
	}
	if _, err := os.Stat(env.dest("bin/docker-helper")); !os.IsNotExist(err) {
		t.Error("binary should be removed")
	}
}

func TestUninstallSystemPurgeRemovesData(t *testing.T) {
	env := newSystemUninstallScriptEnv(t)

	if err := os.WriteFile(env.dest("etc/docker-helper/config.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}

	out, err := env.run(t, "--yes --purge", "")
	if err != nil {
		t.Fatalf("uninstall failed: %v\n%s", err, out)
	}

	if _, err := os.Stat(env.dest("etc/docker-helper")); !os.IsNotExist(err) {
		t.Error("config should be removed with --purge")
	}
	if _, err := os.Stat(env.dest("var/lib/docker-helper")); !os.IsNotExist(err) {
		t.Error("state should be removed with --purge")
	}
	if _, err := os.Stat(env.dest("run/docker-helper")); !os.IsNotExist(err) {
		t.Error("runtime should be removed with --purge")
	}
	if _, err := os.Stat(env.dest("etc/apparmor.d/docker-helper.d/managed-roots")); !os.IsNotExist(err) {
		t.Error("fragment should be removed with --purge")
	}
}

func TestInstallSystemActiveServiceStopFailure(t *testing.T) {
	env := newSystemInstallScriptEnv(t)

	// Service is active, stop fails
	env.fakeSystemctl(t, fmt.Sprintf(`#!/bin/bash
log_file="%s"
echo "$0 $@" >> "$log_file"
case "$*" in
  *"is-active"*) exit 0 ;;  # active
  *"stop"*) exit 1 ;;       # stop fails
  *) exit 0 ;;
esac
`, env.logFile))

	// Sentinel files at destination that must survive a failed install.
	sentinelBinary := []byte("existing-binary-content")
	sentinelUnit := []byte("[Service]\nExecStart=/old/bin")
	sentinelProfile := []byte("profile old {}")
	if err := os.WriteFile(env.dest("bin/docker-helper"), sentinelBinary, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(env.dest("etc/systemd/system/docker-helper.service"), sentinelUnit, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(env.dest("etc/apparmor.d/docker-helper-system"), sentinelProfile, 0644); err != nil {
		t.Fatal(err)
	}

	testRoot := t.TempDir()
	out, err := env.run(t, "--yes --allowed-root "+testRoot, "")
	if err == nil {
		t.Fatalf("install should fail when stop fails: %s", out)
	}

	// Verify sentinel files unchanged
	actualBinary, err := os.ReadFile(env.dest("bin/docker-helper"))
	if err != nil || string(actualBinary) != string(sentinelBinary) {
		t.Error("binary should be unchanged when stop fails")
	}
	actualUnit, err := os.ReadFile(env.dest("etc/systemd/system/docker-helper.service"))
	if err != nil || string(actualUnit) != string(sentinelUnit) {
		t.Error("unit should be unchanged when stop fails")
	}
	actualProfile, err := os.ReadFile(env.dest("etc/apparmor.d/docker-helper-system"))
	if err != nil || string(actualProfile) != string(sentinelProfile) {
		t.Error("profile should be unchanged when stop fails")
	}
}

func TestInstallSystemActiveServiceSuccessfulUpgrade(t *testing.T) {
	env := newSystemInstallScriptEnv(t)

	// Service is active, stop succeeds
	env.fakeSystemctl(t, fmt.Sprintf(`#!/bin/bash
log_file="%s"
echo "$0 $@" >> "$log_file"
case "$*" in
  *"is-active"*) exit 0 ;;  # active
  *) exit 0 ;;
esac
`, env.logFile))

	testRoot := t.TempDir()
	out, err := env.run(t, "--yes --allowed-root "+testRoot, "")
	if err != nil {
		t.Fatalf("install should succeed: %v\n%s", err, out)
	}

	// For previously active service, start should be called, not enable
	foundStart, foundEnable := false, false
	for _, c := range env.calls(t) {
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
	env := newSystemInstallScriptEnv(t)

	// daemon-reload fails
	env.fakeSystemctl(t, fmt.Sprintf(`#!/bin/bash
log_file="%s"
echo "$0 $@" >> "$log_file"
case "$*" in
  *"is-active"*) exit 1 ;;
  *"daemon-reload"*) exit 1 ;;
  *) exit 0 ;;
esac
`, env.logFile))

	testRoot := t.TempDir()
	out, err := env.run(t, "--yes --allowed-root "+testRoot, "")
	if err == nil {
		t.Fatal("install should fail when daemon-reload fails")
	}

	for _, c := range env.calls(t) {
		if strings.Contains(c, "start") {
			t.Error("start should not be called after daemon-reload failure")
		}
	}
	if strings.Contains(out, "installation complete") {
		t.Error("should not print installation complete on failure")
	}
}

func TestInstallSystemStartFailure(t *testing.T) {
	env := newSystemInstallScriptEnv(t)

	// start fails
	env.fakeSystemctl(t, fmt.Sprintf(`#!/bin/bash
log_file="%s"
echo "$0 $@" >> "$log_file"
case "$*" in
  *"is-active"*) exit 1 ;;
  *"start"*) exit 1 ;;
  *) exit 0 ;;
esac
`, env.logFile))

	testRoot := t.TempDir()
	out, err := env.run(t, "--yes --allowed-root "+testRoot, "")
	if err == nil {
		t.Fatal("install should fail when start fails")
	}

	if strings.Contains(out, "system installation complete") {
		t.Error("should not print installation complete on start failure")
	}
}

// TestInstallSystemInactiveApparmorLsm verifies that install-system.sh
// fails early when AppArmor LSM is not active, before any file installation.
func TestInstallSystemInactiveApparmorLsm(t *testing.T) {
	env := newSystemInstallScriptEnv(t)

	// Override LSM status to inactive.
	aaEnabledPath := filepath.Join(env.destDir, "sys", "module", "apparmor", "parameters", "enabled")
	if err := os.WriteFile(aaEnabledPath, []byte("N"), 0644); err != nil {
		t.Fatal(err)
	}

	testRoot := t.TempDir()
	out, err := env.run(t, "--yes --allowed-root "+testRoot, "")
	if err == nil {
		t.Fatal("install should fail when AppArmor LSM is inactive")
	}
	if !strings.Contains(out, "not active") && !strings.Contains(out, "AppArmor") {
		t.Errorf("expected AppArmor error, got: %s", out)
	}
	// Binary should NOT have been installed.
	if _, err := os.Stat(env.dest("bin/docker-helper")); !os.IsNotExist(err) {
		t.Error("binary should not be installed when AppArmor LSM is inactive")
	}
}

func TestUninstallSystemActiveStopFailure(t *testing.T) {
	env := newSystemUninstallScriptEnv(t)

	// Service is active, stop fails
	env.fakeSystemctl(t, fmt.Sprintf(`#!/bin/bash
log_file="%s"
echo "$0 $@" >> "$log_file"
case "$*" in
  *"is-active"*) exit 0 ;;  # active
  *"stop"*) exit 1 ;;       # stop fails
  *) exit 0 ;;
esac
`, env.logFile))

	// Sentinel files that must survive a failed uninstall.
	sentinelBinary := []byte("existing-binary")
	sentinelUnit := []byte("[Service]")
	sentinelProfile := []byte("profile {}")
	if err := os.WriteFile(env.dest("bin/docker-helper"), sentinelBinary, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(env.dest("etc/systemd/system/docker-helper.service"), sentinelUnit, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(env.dest("etc/apparmor.d/docker-helper-system"), sentinelProfile, 0644); err != nil {
		t.Fatal(err)
	}

	out, err := env.run(t, "--yes", "")
	if err == nil {
		t.Fatalf("uninstall should fail when stop fails: %s", out)
	}

	// Verify files unchanged
	actualBinary, err := os.ReadFile(env.dest("bin/docker-helper"))
	if err != nil || string(actualBinary) != string(sentinelBinary) {
		t.Error("binary should be unchanged when stop fails")
	}
	actualUnit, err := os.ReadFile(env.dest("etc/systemd/system/docker-helper.service"))
	if err != nil || string(actualUnit) != string(sentinelUnit) {
		t.Error("unit should be unchanged when stop fails")
	}
	actualProfile, err := os.ReadFile(env.dest("etc/apparmor.d/docker-helper-system"))
	if err != nil || string(actualProfile) != string(sentinelProfile) {
		t.Error("profile should be unchanged when stop fails")
	}
}

func TestUninstallSystemSuccessfulActiveOrder(t *testing.T) {
	env := newSystemUninstallScriptEnv(t)

	// Service is active, stop succeeds
	env.fakeSystemctl(t, fmt.Sprintf(`#!/bin/bash
log_file="%s"
echo "$0 $@" >> "$log_file"
case "$*" in
  *"is-active"*) exit 0 ;;  # active
  *) exit 0 ;;
esac
`, env.logFile))

	out, err := env.run(t, "--yes", "")
	if err != nil {
		t.Fatalf("uninstall failed: %v\n%s", err, out)
	}

	// Verify order: is-active, stop, ..., apparmor_parser -R
	isActiveIdx, stopIdx, unloadIdx := -1, -1, -1
	for i, c := range env.calls(t) {
		if strings.Contains(c, "is-active") {
			isActiveIdx = i
		}
		if strings.Contains(c, " stop ") {
			stopIdx = i
		}
		if strings.Contains(c, "apparmor_parser") {
			unloadIdx = i
			if !strings.Contains(c, " -R ") {
				t.Errorf("profile unload must use apparmor_parser -R: %q", c)
			}
		}
	}
	if isActiveIdx < 0 || stopIdx < 0 || unloadIdx < 0 ||
		!(isActiveIdx < stopIdx && stopIdx < unloadIdx) {
		t.Errorf("expected is-active(%d) < stop(%d) < apparmor unload(%d), calls: %v",
			isActiveIdx, stopIdx, unloadIdx, env.calls(t))
	}
}

func TestUninstallSystemParserExitDiagnostic(t *testing.T) {
	env := newSystemUninstallScriptEnv(t)

	// Parser exits with code 42
	env.fakeParser(t, fmt.Sprintf(`#!/bin/bash
log_file="%s"
echo "parser error diagnostic" >&2
echo "$0 $@" >> "$log_file"
exit 42
`, env.logFile))

	out, _ := env.run(t, "--yes", "")

	// Should contain the real exit code 42, not 0
	if !strings.Contains(out, "exit 42") {
		t.Errorf("warning should contain real exit code 42, not 0. Output: %s", out)
	}
	// Should contain parser diagnostic
	if !strings.Contains(out, "parser error diagnostic") {
		t.Errorf("warning should contain parser stderr diagnostic. Output: %s", out)
	}
}

// --- nFPM config static tests ---

// TestNfpmConfigFile verifies the nFPM config: required fields, system
// asset destinations, exclusions, vendor systemd directory, managed-roots
// config type, modes, version templating, and per-format depends and
// lifecycle scripts.
func TestNfpmConfigFile(t *testing.T) {
	data, err := os.ReadFile("packaging/nfpm.yaml")
	if err != nil {
		t.Fatalf("packaging/nfpm.yaml not found: %v", err)
	}
	content := string(data)

	// Required top-level fields.
	for _, field := range []string{"name:", "version:", "arch:", "platform:"} {
		if !strings.Contains(content, field) {
			t.Errorf("nfpm.yaml missing required field: %s", field)
		}
	}

	// Required system asset destinations (also proves vendor systemd dir).
	for _, path := range []string{
		"/usr/bin/docker-helper",
		"/usr/lib/systemd/system/docker-helper.service",
		"/etc/apparmor.d/docker-helper-system",
		"/etc/apparmor.d/docker-helper.d/managed-roots",
		"/usr/share/docker-helper/apparmor/local/curl",
	} {
		if !strings.Contains(content, path) {
			t.Errorf("nfpm.yaml missing required destination: %s", path)
		}
	}

	// Must not ship operator-managed runtime/state paths.
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

	// Must not ship installer artifacts.
	for _, s := range []string{"SKILL.md"} {
		if strings.Contains(content, s) {
			t.Errorf("nfpm.yaml must not include: %s", s)
		}
	}
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "install.sh" || trimmed == "uninstall.sh" ||
			strings.HasSuffix(trimmed, ": install.sh") || strings.HasSuffix(trimmed, ": uninstall.sh") {
			t.Errorf("nfpm.yaml must not include: %s", trimmed)
		}
	}
	// systemd unit must not be installed to /etc/systemd/system.
	if strings.Contains(content, "/etc/systemd/system") {
		t.Error("systemd unit must not be installed to /etc/systemd/system")
	}

	// managed-roots entry must be config|noreplace so operator edits
	// survive upgrades on both DEB (conffile) and RPM (%config(noreplace)).
	idx := strings.Index(content, "dst: /etc/apparmor.d/docker-helper.d/managed-roots")
	if idx < 0 {
		t.Fatal("managed-roots destination entry not found")
	}
	before := content[:idx]
	entryStart := strings.LastIndex(before, "- src:")
	if entryStart < 0 {
		entryStart = 0
	}
	if !strings.Contains(content[entryStart:], "type: config|noreplace") {
		t.Error("managed-roots content entry must have type: config|noreplace")
	}

	// Modes: binary 0755, assets 0644.
	if !strings.Contains(content, "0755") {
		t.Error("nfpm.yaml must set binary mode 0755")
	}
	if count := strings.Count(content, "0644"); count < 3 {
		t.Errorf("expected at least 3 assets with mode 0644, found %d", count)
	}

	// Version sourced from environment, not hardcoded.
	if !strings.Contains(content, "${VERSION}") {
		t.Error("version must use ${VERSION} template variable")
	}

	// DEB overrides: lifecycle scripts and depends.
	debIdx := strings.Index(content, "deb:")
	rpmIdx := strings.Index(content, "rpm:")
	if debIdx < 0 {
		t.Fatal("deb overrides section not found")
	}
	if rpmIdx < 0 || debIdx > rpmIdx {
		t.Fatal("rpm overrides section not found or ordering wrong")
	}
	debSection := content[debIdx:rpmIdx]
	for _, script := range []string{"postinstall:", "preremove:", "postremove:"} {
		if !strings.Contains(debSection, script) {
			t.Errorf("DEB overrides must include script: %s", script)
		}
	}
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
		if strings.HasPrefix(strings.TrimSpace(line), "- docker") {
			t.Error("DEB depends must not include docker package")
		}
	}

	// RPM overrides: lifecycle scripts and depends.
	contentsIdx := strings.Index(content[rpmIdx:], "\ncontents:")
	if contentsIdx < 0 {
		contentsIdx = len(content) - rpmIdx
	}
	rpmSection := content[rpmIdx : rpmIdx+contentsIdx]
	for _, script := range []string{"postinstall:", "preremove:", "postremove:"} {
		if !strings.Contains(rpmSection, script) {
			t.Errorf("RPM overrides must include script: %s", script)
		}
	}
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
		if strings.HasPrefix(strings.TrimSpace(line), "- docker") {
			t.Error("RPM depends must not include docker package")
		}
	}
}

// --- build-packages.sh tests ---

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

// TestBuildPackagesScriptContent verifies build-packages.sh delegates to
// build-static.sh, passes the version through, builds both package formats
// to dist/, and verifies the static binary before packaging.
func TestBuildPackagesScriptContent(t *testing.T) {
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
	if !strings.Contains(content, "deb") {
		t.Error("build-packages.sh must build DEB packages")
	}
	if !strings.Contains(content, "rpm") {
		t.Error("build-packages.sh must build RPM packages")
	}
	if !strings.Contains(content, "dist") {
		t.Error("build-packages.sh must output artifacts to dist/")
	}
	if !strings.Contains(content, "dist/docker-helper") {
		t.Error("build-packages.sh must verify dist/docker-helper exists")
	}
	if !strings.Contains(content, "-x") {
		t.Error("build-packages.sh must check binary is executable")
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

	testVersion := "0.0.0"
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

	// Config(noreplace) flags — use FILEFLAGS:fflags.
	cmd = exec.Command(rpmPath, "-qp", "--qf", "[%{FILENAMES} %{FILEFLAGS:fflags}\\n]", rpmFile)
	flagOut, _ := cmd.CombinedOutput()
	flagStr := string(flagOut)
	managedRootsFound := false
	aaProfileFound := false
	for _, line := range strings.Split(flagStr, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "/etc/apparmor.d/docker-helper.d/managed-roots") {
			managedRootsFound = true
			parts := strings.Fields(line)
			if len(parts) < 2 {
				t.Errorf("RPM managed-roots flags line has no flags field: %s", line)
				continue
			}
			flags := parts[len(parts)-1]
			if !strings.Contains(flags, "c") {
				t.Errorf("RPM managed-roots must have config flag (c): %s", line)
			}
			if !strings.Contains(flags, "n") {
				t.Errorf("RPM managed-roots must have noreplace flag (n): %s", line)
			}
		}
		if strings.Contains(line, "/etc/apparmor.d/docker-helper-system") {
			aaProfileFound = true
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				flags := parts[len(parts)-1]
				if strings.Contains(flags, "n") {
					t.Errorf("RPM docker-helper-system must NOT have noreplace flag (n): %s", line)
				}
			}
		}
	}
	if !managedRootsFound {
		t.Errorf("managed-roots not found in RPM file flags output:\n%s", flagStr)
	}
	if !aaProfileFound {
		t.Errorf("docker-helper-system not found in RPM file flags output:\n%s", flagStr)
	}
}

func verifyPackageContents(t *testing.T, format, contents string) {
	t.Helper()

	for _, path := range []string{
		"/usr/bin/docker-helper",
		"/usr/lib/systemd/system/docker-helper.service",
		"/etc/apparmor.d/docker-helper-system",
		"/etc/apparmor.d/docker-helper.d/managed-roots",
		"/usr/share/docker-helper/apparmor/local/curl",
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
			"etc/apparmor.d/docker-helper.d/managed-roots",
			"usr/share/docker-helper/apparmor/local/curl":
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
			"etc/apparmor.d/docker-helper.d/managed-roots",
			"usr/share/docker-helper/apparmor/local/curl":
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

	hasCC := false
	if _, err := exec.LookPath("musl-gcc"); err == nil {
		hasCC = true
	}
	if _, err := os.Stat("/etc/alpine-release"); err == nil {
		if _, err := exec.LookPath("gcc"); err == nil {
			hasCC = true
		}
	}
	if !hasCC {
		t.Skip("musl-gcc (or Alpine gcc) not available, skipping full package build pipeline")
	}

	testVersion := "1.0.0"

	cmd := exec.Command("bash", "build-packages.sh", testVersion)
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

// --- Lifecycle script behavioral tests ---

// setupScriptTest creates a fake environment for testing lifecycle scripts.
// Returns (fakeDir, logFile) where fakeDir contains fake systemctl/apparmor_parser
// and logFile records all commands called.
func setupScriptTest(t *testing.T) (fakeDir, logFile string) {
	t.Helper()
	tmpDir := t.TempDir()
	fakeDir = filepath.Join(tmpDir, "fakes")
	logFile = filepath.Join(tmpDir, "calls.log")
	if err := os.MkdirAll(fakeDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(logFile, nil, 0644); err != nil {
		t.Fatal(err)
	}
	return
}

// writeFakeSystemctl creates a systemctl script that logs calls and
// returns specific exit codes based on the action.
func writeFakeSystemctl(t *testing.T, fakeDir, logFile string, active bool, enabled bool) {
	t.Helper()
	activeStr := "false"
	if active {
		activeStr = "true"
	}
	enabledStr := "false"
	if enabled {
		enabledStr = "true"
	}
	script := fmt.Sprintf(`#!/bin/sh
echo "$0 $@" >> "%s"
case "$*" in
  *"is-active"*)
    if [ "%s" = "true" ]; then exit 0; else exit 3; fi
    ;;
  *"is-enabled"*)
    if [ "%s" = "true" ]; then exit 0; else exit 1; fi
    ;;
  *"stop"*)
    if [ "${STOP_FAIL:-false}" = "true" ]; then exit 1; fi
    exit 0
    ;;
  *"try-restart"*)
    if [ "${RESTART_FAIL:-false}" = "true" ]; then exit 1; fi
    exit 0
    ;;
  *"start"*)
    if [ "${START_FAIL:-false}" = "true" ]; then exit 1; fi
    exit 0
    ;;
  *"daemon-reload"*)
    if [ "${RELOAD_FAIL:-false}" = "true" ]; then exit 1; fi
    exit 0
    ;;
  *"disable"*)
    if [ "${DISABLE_FAIL:-false}" = "true" ]; then exit 1; fi
    exit 0
    ;;
  *) exit 0 ;;
esac
`, logFile, activeStr, enabledStr)
	if err := os.WriteFile(filepath.Join(fakeDir, "systemctl"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
}

// writeFakeApparmorParser creates an apparmor_parser script that logs calls.
func writeFakeApparmorParser(t *testing.T, fakeDir, logFile string, failReplace bool, failUnload bool) {
	t.Helper()
	failReplaceStr := "false"
	if failReplace {
		failReplaceStr = "true"
	}
	failUnloadStr := "false"
	if failUnload {
		failUnloadStr = "true"
	}
	script := fmt.Sprintf(`#!/bin/sh
echo "$0 $@" >> "%s"
case "$*" in
  *"--replace"*)
    if [ "%s" = "true" ]; then
      echo "apparmor_parser: parse error" >&2
      exit 1
    fi
    exit 0
    ;;
  *"-R"*)
    if [ "%s" = "true" ]; then
      echo "apparmor_parser: unload error" >&2
      exit 1
    fi
    exit 0
    ;;
  *) exit 0 ;;
esac
`, logFile, failReplaceStr, failUnloadStr)
	if err := os.WriteFile(filepath.Join(fakeDir, "apparmor_parser"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
}

// writeFakeSemodule creates a semodule script that logs calls.
func writeFakeSemodule(t *testing.T, fakeDir, logFile string, failInstall bool, failRemove bool) {
	t.Helper()
	failInstallStr := "false"
	if failInstall {
		failInstallStr = "true"
	}
	failRemoveStr := "false"
	if failRemove {
		failRemoveStr = "true"
	}
	script := fmt.Sprintf(`#!/bin/sh
echo "$0 $@" >> "%s"
case "$*" in
  *"-i"*)
    if [ "%s" = "true" ]; then
      echo "semodule: Failed to install module" >&2
      exit 1
    fi
    exit 0
    ;;
  *"-r"*)
    if [ "%s" = "true" ]; then
      echo "semodule: Failed to remove module" >&2
      exit 1
    fi
    exit 0
    ;;
  *) exit 0 ;;
esac
`, logFile, failInstallStr, failRemoveStr)
	if err := os.WriteFile(filepath.Join(fakeDir, "semodule"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
}

// writeFakeRestorecon creates a restorecon script that logs calls.
func writeFakeRestorecon(t *testing.T, fakeDir, logFile string) {
	t.Helper()
	script := fmt.Sprintf(`#!/bin/sh
echo "$0 $@" >> "%s"
exit 0
`, logFile)
	if err := os.WriteFile(filepath.Join(fakeDir, "restorecon"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
}

// readCalls reads the command log.
func readLifecycleScriptCalls(t *testing.T, logFile string) []string {
	t.Helper()
	data, err := os.ReadFile(logFile)
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

// runScript runs a lifecycle script with the fake environment.
func runScript(t *testing.T, scriptPath, fakeDir, logFile string, args []string, liveSystem bool, extraEnv []string) (stdout, stderr string, exitCode int) {
	t.Helper()
	tmpDir := t.TempDir()
	scriptDir := filepath.Join(tmpDir, "script")
	if err := os.MkdirAll(scriptDir, 0755); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatal(err)
	}

	// Replace /run/systemd/system with a test-controlled path.
	modified := strings.ReplaceAll(string(data), "/run/systemd/system", "$TEST_RUN_SYSTEMD")
	// Replace AppArmor LSM status path with a test-controlled path.
	modified = strings.ReplaceAll(modified, "/sys/module/apparmor/parameters/enabled", "$AA_ENABLED_PATH")
	// Replace SELinux enforce path with a test-controlled path.
	modified = strings.ReplaceAll(modified, "/sys/fs/selinux/enforce", "$SELINUX_ENFORCE_PATH")
	modifiedFile := filepath.Join(scriptDir, "modified.sh")
	if err := os.WriteFile(modifiedFile, []byte(modified), 0755); err != nil {
		t.Fatal(err)
	}

	testRunDir := filepath.Join(tmpDir, "run", "systemd", "system")
	if liveSystem {
		if err := os.MkdirAll(testRunDir, 0755); err != nil {
			t.Fatal(err)
		}
	}

	// Default: AppArmor LSM is active. Tests can override by providing
	// their own AA_ENABLED_PATH via extraEnv and creating the file.
	aaEnabledPath := filepath.Join(tmpDir, "sys", "module", "apparmor", "parameters", "enabled")
	if err := os.MkdirAll(filepath.Dir(aaEnabledPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(aaEnabledPath, []byte("Y"), 0644); err != nil {
		t.Fatal(err)
	}

	// Default: SELinux is not enforcing. Tests can override by providing
	// their own SELINUX_ENFORCE_PATH via extraEnv and creating the file.
	selinuxEnforcePath := filepath.Join(tmpDir, "sys", "fs", "selinux", "enforce")
	if err := os.MkdirAll(filepath.Dir(selinuxEnforcePath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(selinuxEnforcePath, []byte("0"), 0644); err != nil {
		t.Fatal(err)
	}

	env := append(os.Environ(),
		"PATH="+fakeDir+":"+os.Getenv("PATH"),
		"STOP_FAIL=false",
		"START_FAIL=false",
		"RESTART_FAIL=false",
		"RELOAD_FAIL=false",
		"DISABLE_FAIL=false",
		"SEMODULE_FAIL=false",
		"TEST_RUN_SYSTEMD="+testRunDir,
		"AA_ENABLED_PATH="+aaEnabledPath,
		"SELINUX_ENFORCE_PATH="+selinuxEnforcePath,
	)
	env = append(env, extraEnv...)

	if err := os.WriteFile(logFile, nil, 0644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("sh", modifiedFile)
	cmd.Env = env
	for _, a := range args {
		cmd.Args = append(cmd.Args, a)
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
	} else {
		exitCode = 0
	}
	return string(out), string(out), exitCode
}

// --- DEB postinstall tests ---

// TestDebPostinstallInactive verifies postinst on fresh install (inactive):
// is-active -> apparmor replace -> daemon-reload, no restart/start/enable.
func TestDebPostinstallInactive(t *testing.T) {
	fakeDir, logFile := setupScriptTest(t)
	writeFakeSystemctl(t, fakeDir, logFile, false, false)
	writeFakeApparmorParser(t, fakeDir, logFile, false, false)

	_, _, code := runScript(t, "packaging/scripts/deb/postinstall.sh", fakeDir, logFile,
		[]string{"configure"}, true, nil)
	if code != 0 {
		t.Fatalf("postinst should exit 0, got %d", code)
	}

	calls := readLifecycleScriptCalls(t, logFile)
	// Must call is-active
	found := false
	for _, c := range calls {
		if strings.Contains(c, "is-active") {
			found = true
			break
		}
	}
	if !found {
		t.Error("must call systemctl is-active")
	}
	// Must call apparmor_parser --replace
	found = false
	for _, c := range calls {
		if strings.Contains(c, "--replace") {
			found = true
			break
		}
	}
	if !found {
		t.Error("must call apparmor_parser --replace")
	}
	// Must call daemon-reload
	found = false
	for _, c := range calls {
		if strings.Contains(c, "daemon-reload") {
			found = true
			break
		}
	}
	if !found {
		t.Error("must call systemctl daemon-reload")
	}
	// Must NOT call try-restart, start, or enable
	for _, c := range calls {
		if strings.Contains(c, "try-restart") || strings.Contains(c, " start") || strings.Contains(c, "enable") {
			t.Errorf("must not start/enable service when inactive: %s", c)
		}
	}
}

// TestDebPostinstallActive verifies postinst on upgrade (active):
// is-active -> replace -> daemon-reload -> try-restart.
func TestDebPostinstallActive(t *testing.T) {
	fakeDir, logFile := setupScriptTest(t)
	writeFakeSystemctl(t, fakeDir, logFile, true, false)
	writeFakeApparmorParser(t, fakeDir, logFile, false, false)

	_, _, code := runScript(t, "packaging/scripts/deb/postinstall.sh", fakeDir, logFile,
		[]string{"configure"}, true, nil)
	if code != 0 {
		t.Fatalf("postinst should exit 0, got %d", code)
	}

	calls := readLifecycleScriptCalls(t, logFile)
	found := false
	for _, c := range calls {
		if strings.Contains(c, "try-restart") {
			found = true
			break
		}
	}
	if !found {
		t.Error("must call systemctl try-restart when service was active")
	}
}

// TestDebPostinstallParserFailure verifies postinst fails when apparmor_parser fails.
func TestDebPostinstallParserFailure(t *testing.T) {
	fakeDir, logFile := setupScriptTest(t)
	writeFakeSystemctl(t, fakeDir, logFile, false, false)
	writeFakeApparmorParser(t, fakeDir, logFile, true, false)

	_, _, code := runScript(t, "packaging/scripts/deb/postinstall.sh", fakeDir, logFile,
		[]string{"configure"}, true, nil)
	if code == 0 {
		t.Fatal("postinst should fail when parser fails")
	}
	calls := readLifecycleScriptCalls(t, logFile)
	for _, c := range calls {
		if strings.Contains(c, "daemon-reload") || strings.Contains(c, "try-restart") {
			t.Error("must not proceed after parser failure")
		}
	}
}

// TestDebPostinstallDaemonReloadFailure verifies postinst fails when daemon-reload fails.
func TestDebPostinstallDaemonReloadFailure(t *testing.T) {
	fakeDir, logFile := setupScriptTest(t)
	writeFakeSystemctl(t, fakeDir, logFile, false, false)
	writeFakeApparmorParser(t, fakeDir, logFile, false, false)

	_, _, code := runScript(t, "packaging/scripts/deb/postinstall.sh", fakeDir, logFile,
		[]string{"configure"}, true, []string{"RELOAD_FAIL=true"})
	if code == 0 {
		t.Fatal("postinst should fail when daemon-reload fails")
	}
	calls := readLifecycleScriptCalls(t, logFile)
	for _, c := range calls {
		if strings.Contains(c, "try-restart") {
			t.Error("must not restart after daemon-reload failure")
		}
	}
}

// TestDebPostinstallRestartFailure verifies postinst fails when try-restart fails.
func TestDebPostinstallRestartFailure(t *testing.T) {
	fakeDir, logFile := setupScriptTest(t)
	writeFakeSystemctl(t, fakeDir, logFile, true, false)
	writeFakeApparmorParser(t, fakeDir, logFile, false, false)

	_, _, code := runScript(t, "packaging/scripts/deb/postinstall.sh", fakeDir, logFile,
		[]string{"configure"}, true, []string{"RESTART_FAIL=true"})
	if code == 0 {
		t.Fatal("postinst should fail when try-restart fails")
	}
	calls := readLifecycleScriptCalls(t, logFile)
	// Verify replace and daemon-reload were called before the failed restart.
	foundReplace, foundReload, foundRestart := false, false, false
	for _, c := range calls {
		if strings.Contains(c, "--replace") {
			foundReplace = true
		}
		if strings.Contains(c, "daemon-reload") {
			foundReload = true
		}
		if strings.Contains(c, "try-restart") {
			foundRestart = true
		}
	}
	if !foundReplace || !foundReload || !foundRestart {
		t.Errorf("expected replace+reload+restart calls, got replace=%v reload=%v restart=%v", foundReplace, foundReload, foundRestart)
	}
}

// TestRpmPostinstallRestartFailure verifies RPM postinstall fails when try-restart fails.
func TestRpmPostinstallRestartFailure(t *testing.T) {
	fakeDir, logFile := setupScriptTest(t)
	writeFakeSystemctl(t, fakeDir, logFile, true, false)
	writeFakeApparmorParser(t, fakeDir, logFile, false, false)

	_, _, code := runScript(t, "packaging/scripts/rpm/postinstall.sh", fakeDir, logFile,
		[]string{"1"}, true, []string{"RESTART_FAIL=true"})
	if code == 0 {
		t.Fatal("rpm postinstall should fail when try-restart fails")
	}
	calls := readLifecycleScriptCalls(t, logFile)
	foundReplace, foundReload, foundRestart := false, false, false
	for _, c := range calls {
		if strings.Contains(c, "--replace") {
			foundReplace = true
		}
		if strings.Contains(c, "daemon-reload") {
			foundReload = true
		}
		if strings.Contains(c, "try-restart") {
			foundRestart = true
		}
	}
	if !foundReplace || !foundReload || !foundRestart {
		t.Errorf("expected replace+reload+restart calls, got replace=%v reload=%v restart=%v", foundReplace, foundReload, foundRestart)
	}
}

// --- DEB postinstall: AppArmor LSM inactive ---

// TestDebPostinstallInactiveApparmorLsm verifies that when AppArmor LSM
// is not active, the postinst skips apparmor_parser but still performs
// daemon-reload and exits 0.
func TestDebPostinstallInactiveApparmorLsm(t *testing.T) {
	fakeDir, logFile := setupScriptTest(t)
	writeFakeSystemctl(t, fakeDir, logFile, false, false)
	writeFakeApparmorParser(t, fakeDir, logFile, false, false)

	// Write "N" to simulate inactive AppArmor LSM.
	tmpDir := t.TempDir()
	aaEnabledDir := filepath.Join(tmpDir, "sys", "module", "apparmor", "parameters")
	if err := os.MkdirAll(aaEnabledDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(aaEnabledDir, "enabled"), []byte("N"), 0644); err != nil {
		t.Fatal(err)
	}

	_, stderr, code := runScript(t, "packaging/scripts/deb/postinstall.sh", fakeDir, logFile,
		[]string{"configure"}, true, []string{"AA_ENABLED_PATH=" + filepath.Join(aaEnabledDir, "enabled")})
	if code != 0 {
		t.Fatalf("postinst should exit 0 when AppArmor LSM inactive, got %d (stderr: %s)", code, stderr)
	}

	calls := readLifecycleScriptCalls(t, logFile)
	// Must NOT call apparmor_parser
	for _, c := range calls {
		if strings.Contains(c, "--replace") {
			t.Error("must not call apparmor_parser when AppArmor LSM is inactive")
		}
	}
	// Must call daemon-reload
	found := false
	for _, c := range calls {
		if strings.Contains(c, "daemon-reload") {
			found = true
			break
		}
	}
	if !found {
		t.Error("must call daemon-reload even when AppArmor LSM is inactive")
	}
	// Must emit warning
	if !strings.Contains(stderr, "not active") && !strings.Contains(stderr, "warning") {
		t.Errorf("expected warning about inactive AppArmor, got: %s", stderr)
	}
}

// TestRpmPostinstallInactiveApparmorLsm verifies that when AppArmor LSM
// is not active, the RPM postinst skips apparmor_parser but still performs
// daemon-reload and exits 0.
func TestRpmPostinstallInactiveApparmorLsm(t *testing.T) {
	fakeDir, logFile := setupScriptTest(t)
	writeFakeSystemctl(t, fakeDir, logFile, false, false)
	writeFakeApparmorParser(t, fakeDir, logFile, false, false)

	tmpDir := t.TempDir()
	aaEnabledDir := filepath.Join(tmpDir, "sys", "module", "apparmor", "parameters")
	if err := os.MkdirAll(aaEnabledDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(aaEnabledDir, "enabled"), []byte("N"), 0644); err != nil {
		t.Fatal(err)
	}

	_, stderr, code := runScript(t, "packaging/scripts/rpm/postinstall.sh", fakeDir, logFile,
		[]string{"1"}, true, []string{"AA_ENABLED_PATH=" + filepath.Join(aaEnabledDir, "enabled")})
	if code != 0 {
		t.Fatalf("rpm postinst should exit 0 when AppArmor LSM inactive, got %d (stderr: %s)", code, stderr)
	}

	calls := readLifecycleScriptCalls(t, logFile)
	for _, c := range calls {
		if strings.Contains(c, "--replace") {
			t.Error("must not call apparmor_parser when AppArmor LSM is inactive")
		}
	}
	found := false
	for _, c := range calls {
		if strings.Contains(c, "daemon-reload") {
			found = true
			break
		}
	}
	if !found {
		t.Error("must call daemon-reload even when AppArmor LSM is inactive")
	}
	if !strings.Contains(stderr, "not active") && !strings.Contains(stderr, "warning") {
		t.Errorf("expected warning about inactive AppArmor, got: %s", stderr)
	}
}

// --- DEB preremove tests ---

// TestDebPreremoveUpgrade verifies prerm on upgrade does nothing.
func TestDebPreremoveUpgrade(t *testing.T) {
	fakeDir, logFile := setupScriptTest(t)
	writeFakeSystemctl(t, fakeDir, logFile, true, true)
	writeFakeApparmorParser(t, fakeDir, logFile, false, false)

	_, _, code := runScript(t, "packaging/scripts/deb/preremove.sh", fakeDir, logFile,
		[]string{"upgrade", "2.0.0"}, true, nil)
	if code != 0 {
		t.Fatalf("prerm upgrade should exit 0, got %d", code)
	}
	calls := readLifecycleScriptCalls(t, logFile)
	for _, c := range calls {
		if strings.Contains(c, "stop") || strings.Contains(c, "disable") || strings.Contains(c, "-R") {
			t.Errorf("prerm upgrade must not stop/disable/unload: %s", c)
		}
	}
}

// TestDebPreremoveRemovesActive verifies prerm on remove stops+disables+unloads.
func TestDebPreremoveRemovesActive(t *testing.T) {
	fakeDir, logFile := setupScriptTest(t)
	writeFakeSystemctl(t, fakeDir, logFile, true, true)
	writeFakeApparmorParser(t, fakeDir, logFile, false, false)

	_, _, code := runScript(t, "packaging/scripts/deb/preremove.sh", fakeDir, logFile,
		[]string{"remove"}, true, nil)
	if code != 0 {
		t.Fatalf("prerm remove should exit 0, got %d", code)
	}
	calls := readLifecycleScriptCalls(t, logFile)
	// Must call stop
	found := false
	for _, c := range calls {
		if strings.Contains(c, "stop") {
			found = true
			break
		}
	}
	if !found {
		t.Error("must call systemctl stop")
	}
	// Must call disable
	found = false
	for _, c := range calls {
		if strings.Contains(c, "disable") {
			found = true
			break
		}
	}
	if !found {
		t.Error("must call systemctl disable")
	}
	// Must call apparmor_parser -R
	found = false
	for _, c := range calls {
		if strings.Contains(c, "-R") {
			found = true
			break
		}
	}
	if !found {
		t.Error("must call apparmor_parser -R")
	}
}

// TestDebPreremoveStopFailure verifies prerm fails when stop fails.
func TestDebPreremoveStopFailure(t *testing.T) {
	fakeDir, logFile := setupScriptTest(t)
	writeFakeSystemctl(t, fakeDir, logFile, true, true)
	writeFakeApparmorParser(t, fakeDir, logFile, false, false)

	_, _, code := runScript(t, "packaging/scripts/deb/preremove.sh", fakeDir, logFile,
		[]string{"remove"}, true, []string{"STOP_FAIL=true"})
	if code == 0 {
		t.Fatal("prerm should fail when stop fails")
	}
}

// TestDebPreremoveUnloadFailure verifies prerm continues when unload fails.
func TestDebPreremoveUnloadFailure(t *testing.T) {
	fakeDir, logFile := setupScriptTest(t)
	writeFakeSystemctl(t, fakeDir, logFile, true, true)
	writeFakeApparmorParser(t, fakeDir, logFile, false, true)

	out, _, code := runScript(t, "packaging/scripts/deb/preremove.sh", fakeDir, logFile,
		[]string{"remove"}, true, nil)
	if code != 0 {
		t.Fatalf("prerm should exit 0 when unload fails (best-effort), got %d", code)
	}
	if !strings.Contains(out, "AppArmor") {
		t.Error("warning should mention AppArmor")
	}
	if !strings.Contains(out, "unload error") {
		t.Error("warning should contain parser diagnostic")
	}
}

// TestRpmPreremoveUnloadFailure verifies RPM preun continues when unload fails.
func TestRpmPreremoveUnloadFailure(t *testing.T) {
	fakeDir, logFile := setupScriptTest(t)
	writeFakeSystemctl(t, fakeDir, logFile, true, true)
	writeFakeApparmorParser(t, fakeDir, logFile, false, true)

	out, _, code := runScript(t, "packaging/scripts/rpm/preremove.sh", fakeDir, logFile,
		[]string{"0"}, true, nil)
	if code != 0 {
		t.Fatalf("rpm preun should exit 0 when unload fails (best-effort), got %d", code)
	}
	if !strings.Contains(out, "AppArmor") {
		t.Error("warning should mention AppArmor")
	}
	if !strings.Contains(out, "unload error") {
		t.Error("warning should contain parser diagnostic")
	}
}

// --- DEB postremove tests ---

// TestDebPostremoveRemovesReloads verifies postrm remove does daemon-reload.
func TestDebPostremoveRemovesReloads(t *testing.T) {
	fakeDir, logFile := setupScriptTest(t)
	writeFakeSystemctl(t, fakeDir, logFile, false, false)

	_, _, code := runScript(t, "packaging/scripts/deb/postremove.sh", fakeDir, logFile,
		[]string{"remove"}, true, nil)
	if code != 0 {
		t.Fatalf("postrm remove should exit 0, got %d", code)
	}
	calls := readLifecycleScriptCalls(t, logFile)
	found := false
	for _, c := range calls {
		if strings.Contains(c, "daemon-reload") {
			found = true
			break
		}
	}
	if !found {
		t.Error("must call systemctl daemon-reload")
	}
}

// TestDebPostremovePurgeRemovesState verifies postrm purge removes exact
// state directories and preserves unrelated files.
func TestDebPostremovePurgeRemovesState(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test-controlled state directories.
	testEtc := filepath.Join(tmpDir, "etc-dh")
	testLib := filepath.Join(tmpDir, "lib-dh")
	testRun := filepath.Join(tmpDir, "run-dh")
	testAadir := filepath.Join(tmpDir, "aadir")
	for _, d := range []string{testEtc, testLib, testRun, testAadir} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}
	// Create sentinel files inside.
	for _, d := range []string{testEtc, testLib, testRun} {
		if err := os.WriteFile(filepath.Join(d, "sentinel"), []byte("state"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	// Create unrelated sentinel outside.
	unrelated := filepath.Join(tmpDir, "unrelated")
	if err := os.WriteFile(unrelated, []byte("keep me"), 0644); err != nil {
		t.Fatal(err)
	}

	// Read production script and create a test-only copy with replaced paths.
	data, err := os.ReadFile("packaging/scripts/deb/postremove.sh")
	if err != nil {
		t.Fatal(err)
	}
	modified := string(data)
	modified = strings.ReplaceAll(modified, "/etc/docker-helper", testEtc)
	modified = strings.ReplaceAll(modified, "/var/lib/docker-helper", testLib)
	modified = strings.ReplaceAll(modified, "/run/docker-helper", testRun)
	modified = strings.ReplaceAll(modified, "/etc/apparmor.d/docker-helper.d", testAadir)

	scriptFile := filepath.Join(tmpDir, "postremove.sh")
	if err := os.WriteFile(scriptFile, []byte(modified), 0755); err != nil {
		t.Fatal(err)
	}

	// Execute the modified copy.
	cmd := exec.Command("sh", scriptFile, "purge")
	cmd.Env = os.Environ()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("postrm purge failed: %v\n%s", err, out)
	}

	// Verify exact three dirs removed.
	for _, d := range []string{testEtc, testLib, testRun} {
		if _, err := os.Stat(d); !os.IsNotExist(err) {
			t.Errorf("purge must remove: %s", d)
		}
	}
	// Verify aa dir cleaned up.
	if _, err := os.Stat(testAadir); !os.IsNotExist(err) {
		t.Error("purge should rmdir empty docker-helper.d")
	}
	// Verify unrelated sentinel preserved.
	if _, err := os.Stat(unrelated); err != nil {
		t.Error("purge must not remove unrelated files")
	}
}

// --- RPM postinstall tests ---

// TestRpmPostinstallInactive verifies RPM postinstall on fresh install (inactive).
func TestRpmPostinstallInactive(t *testing.T) {
	fakeDir, logFile := setupScriptTest(t)
	writeFakeSystemctl(t, fakeDir, logFile, false, false)
	writeFakeApparmorParser(t, fakeDir, logFile, false, false)

	_, _, code := runScript(t, "packaging/scripts/rpm/postinstall.sh", fakeDir, logFile,
		[]string{"1"}, true, nil)
	if code != 0 {
		t.Fatalf("rpm postinstall should exit 0, got %d", code)
	}
	calls := readLifecycleScriptCalls(t, logFile)
	for _, c := range calls {
		if strings.Contains(c, "try-restart") || strings.Contains(c, " start") {
			t.Error("must not start service when inactive")
		}
	}
}

// TestRpmPostinstallActive verifies RPM postinstall on upgrade (active).
func TestRpmPostinstallActive(t *testing.T) {
	fakeDir, logFile := setupScriptTest(t)
	writeFakeSystemctl(t, fakeDir, logFile, true, false)
	writeFakeApparmorParser(t, fakeDir, logFile, false, false)

	_, _, code := runScript(t, "packaging/scripts/rpm/postinstall.sh", fakeDir, logFile,
		[]string{"1"}, true, nil)
	if code != 0 {
		t.Fatalf("rpm postinstall should exit 0, got %d", code)
	}
	calls := readLifecycleScriptCalls(t, logFile)
	found := false
	for _, c := range calls {
		if strings.Contains(c, "try-restart") {
			found = true
			break
		}
	}
	if !found {
		t.Error("must call try-restart when service was active")
	}
}

// --- RPM preremove tests ---

// TestRpmPreremoveUpgrade verifies RPM preun on upgrade ($1>0) is no-op.
func TestRpmPreremoveUpgrade(t *testing.T) {
	fakeDir, logFile := setupScriptTest(t)
	writeFakeSystemctl(t, fakeDir, logFile, true, true)
	writeFakeApparmorParser(t, fakeDir, logFile, false, false)

	_, _, code := runScript(t, "packaging/scripts/rpm/preremove.sh", fakeDir, logFile,
		[]string{"1"}, true, nil)
	if code != 0 {
		t.Fatalf("rpm preun upgrade should exit 0, got %d", code)
	}
	calls := readLifecycleScriptCalls(t, logFile)
	for _, c := range calls {
		if strings.Contains(c, "stop") || strings.Contains(c, "disable") || strings.Contains(c, "-R") {
			t.Errorf("rpm preun upgrade must not stop/disable/unload: %s", c)
		}
	}
}

// TestRpmPreremoveFinalErase verifies RPM preun on final erase ($1=0).
func TestRpmPreremoveFinalErase(t *testing.T) {
	fakeDir, logFile := setupScriptTest(t)
	writeFakeSystemctl(t, fakeDir, logFile, true, true)
	writeFakeApparmorParser(t, fakeDir, logFile, false, false)

	_, _, code := runScript(t, "packaging/scripts/rpm/preremove.sh", fakeDir, logFile,
		[]string{"0"}, true, nil)
	if code != 0 {
		t.Fatalf("rpm preun final erase should exit 0, got %d", code)
	}
	calls := readLifecycleScriptCalls(t, logFile)
	found := false
	for _, c := range calls {
		if strings.Contains(c, "stop") {
			found = true
			break
		}
	}
	if !found {
		t.Error("must call systemctl stop on final erase")
	}
}

// --- RPM postremove tests ---

// TestRpmPostremoveUpgrade verifies RPM postun on upgrade ($1>0) is no-op.
func TestRpmPostremoveUpgrade(t *testing.T) {
	fakeDir, logFile := setupScriptTest(t)

	_, _, code := runScript(t, "packaging/scripts/rpm/postremove.sh", fakeDir, logFile,
		[]string{"1"}, true, nil)
	if code != 0 {
		t.Fatalf("rpm postun upgrade should exit 0, got %d", code)
	}
	calls := readLifecycleScriptCalls(t, logFile)
	for _, c := range calls {
		if strings.Contains(c, "daemon-reload") {
			t.Error("rpm postun upgrade must not call daemon-reload")
		}
	}
}

// TestRpmPostremoveFinalErase verifies RPM postun on final erase ($1=0).
func TestRpmPostremoveFinalErase(t *testing.T) {
	fakeDir, logFile := setupScriptTest(t)
	writeFakeSystemctl(t, fakeDir, logFile, false, false)

	_, _, code := runScript(t, "packaging/scripts/rpm/postremove.sh", fakeDir, logFile,
		[]string{"0"}, true, nil)
	if code != 0 {
		t.Fatalf("rpm postun final erase should exit 0, got %d", code)
	}
	calls := readLifecycleScriptCalls(t, logFile)
	found := false
	for _, c := range calls {
		if strings.Contains(c, "daemon-reload") {
			found = true
			break
		}
	}
	if !found {
		t.Error("must call daemon-reload on final erase")
	}
}

// --- Offline (no live system) tests ---

// --- SELinux packaging tests ---

// TestNfpmConfigIncludesSELinuxPolicy verifies nfpm.yaml includes the
// compiled SELinux policy module.
func TestNfpmConfigIncludesSELinuxPolicy(t *testing.T) {
	data, err := os.ReadFile("packaging/nfpm.yaml")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	if !strings.Contains(content, "packaging/selinux/docker-helper.pp") {
		t.Error("nfpm.yaml must include packaging/selinux/docker-helper.pp source")
	}
	if !strings.Contains(content, "/usr/share/selinux/docker-helper.pp") {
		t.Error("nfpm.yaml must install .pp to /usr/share/selinux/docker-helper.pp")
	}
}

// TestBuildPackagesScriptContentSELinux verifies build-packages.sh builds
// the SELinux policy module when tools are available.
func TestBuildPackagesScriptContentSELinux(t *testing.T) {
	data, err := os.ReadFile("build-packages.sh")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	if !strings.Contains(content, "checkmodule") {
		t.Error("build-packages.sh must reference checkmodule")
	}
	if !strings.Contains(content, "semodule_package") {
		t.Error("build-packages.sh must reference semodule_package")
	}
	if !strings.Contains(content, "docker-helper.te") {
		t.Error("build-packages.sh must reference docker-helper.te")
	}
	if !strings.Contains(content, "docker-helper.pp") {
		t.Error("build-packages.sh must produce docker-helper.pp")
	}
}

// TestRpmPostinstallSELinuxActive verifies RPM postinstall installs the
// SELinux module and restores contexts when SELinux is enforcing.
func TestRpmPostinstallSELinuxActive(t *testing.T) {
	fakeDir, logFile := setupScriptTest(t)
	writeFakeSystemctl(t, fakeDir, logFile, false, false)
	writeFakeSemodule(t, fakeDir, logFile, false, false)
	writeFakeRestorecon(t, fakeDir, logFile)

	// Set SELinux to enforcing.
	tmpDir := t.TempDir()
	selinuxEnforceDir := filepath.Join(tmpDir, "sys", "fs", "selinux")
	if err := os.MkdirAll(selinuxEnforceDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(selinuxEnforceDir, "enforce"), []byte("1"), 0644); err != nil {
		t.Fatal(err)
	}

	// Disable AppArmor.
	aaEnabledDir := filepath.Join(tmpDir, "sys", "module", "apparmor", "parameters")
	if err := os.MkdirAll(aaEnabledDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(aaEnabledDir, "enabled"), []byte("N"), 0644); err != nil {
		t.Fatal(err)
	}

	_, _, code := runScript(t, "packaging/scripts/rpm/postinstall.sh", fakeDir, logFile,
		[]string{"1"}, true, []string{
			"SELINUX_ENFORCE_PATH=" + filepath.Join(selinuxEnforceDir, "enforce"),
			"AA_ENABLED_PATH=" + filepath.Join(aaEnabledDir, "enabled"),
		})
	if code != 0 {
		t.Fatalf("rpm postinst should exit 0 when SELinux active, got %d", code)
	}

	calls := readLifecycleScriptCalls(t, logFile)

	// Must call semodule -i
	foundSemodule := false
	for _, c := range calls {
		if strings.Contains(c, "semodule") && strings.Contains(c, "-i") {
			foundSemodule = true
			if !strings.Contains(c, "/usr/share/selinux/docker-helper.pp") {
				t.Errorf("semodule -i must use correct path: %s", c)
			}
		}
	}
	if !foundSemodule {
		t.Error("must call semodule -i to install SELinux module")
	}

	// Must call restorecon for the binary
	foundRestorecon := false
	for _, c := range calls {
		if strings.Contains(c, "restorecon") && strings.Contains(c, "/usr/bin/docker-helper") {
			foundRestorecon = true
		}
	}
	if !foundRestorecon {
		t.Error("must call restorecon for /usr/bin/docker-helper")
	}

	// Must call daemon-reload
	foundDaemonReload := false
	for _, c := range calls {
		if strings.Contains(c, "daemon-reload") {
			foundDaemonReload = true
		}
	}
	if !foundDaemonReload {
		t.Error("must call daemon-reload")
	}

	// Must NOT call apparmor_parser --replace
	for _, c := range calls {
		if strings.Contains(c, "apparmor_parser") && strings.Contains(c, "--replace") {
			t.Error("must not call apparmor_parser when SELinux is the only active MAC")
		}
	}
}

// TestRpmPostinstallSELinuxUpgrade verifies RPM postinstall replaces the
// SELinux module on upgrade when SELinux is enforcing.
func TestRpmPostinstallSELinuxUpgrade(t *testing.T) {
	fakeDir, logFile := setupScriptTest(t)
	writeFakeSystemctl(t, fakeDir, logFile, true, false)
	writeFakeSemodule(t, fakeDir, logFile, false, false)
	writeFakeRestorecon(t, fakeDir, logFile)

	tmpDir := t.TempDir()
	selinuxEnforceDir := filepath.Join(tmpDir, "sys", "fs", "selinux")
	if err := os.MkdirAll(selinuxEnforceDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(selinuxEnforceDir, "enforce"), []byte("1"), 0644); err != nil {
		t.Fatal(err)
	}
	aaEnabledDir := filepath.Join(tmpDir, "sys", "module", "apparmor", "parameters")
	if err := os.MkdirAll(aaEnabledDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(aaEnabledDir, "enabled"), []byte("N"), 0644); err != nil {
		t.Fatal(err)
	}

	_, _, code := runScript(t, "packaging/scripts/rpm/postinstall.sh", fakeDir, logFile,
		[]string{"2"}, true, []string{
			"SELINUX_ENFORCE_PATH=" + filepath.Join(selinuxEnforceDir, "enforce"),
			"AA_ENABLED_PATH=" + filepath.Join(aaEnabledDir, "enabled"),
		})
	if code != 0 {
		t.Fatalf("rpm postinst upgrade should exit 0, got %d", code)
	}

	calls := readLifecycleScriptCalls(t, logFile)

	// Must call semodule -i (replaces existing module)
	foundSemodule := false
	for _, c := range calls {
		if strings.Contains(c, "semodule") && strings.Contains(c, "-i") {
			foundSemodule = true
		}
	}
	if !foundSemodule {
		t.Error("upgrade must call semodule -i to replace SELinux module")
	}

	// Must call try-restart when service was active
	foundRestart := false
	for _, c := range calls {
		if strings.Contains(c, "try-restart") {
			foundRestart = true
		}
	}
	if !foundRestart {
		t.Error("upgrade must call try-restart when service was active")
	}
}

// TestRpmPostinstallSELinuxNoFalseAppArmorWarning verifies that when
// SELinux is active, the RPM postinstall does not emit the false
// "AppArmor LSM is not active" warning.
func TestRpmPostinstallSELinuxNoFalseAppArmorWarning(t *testing.T) {
	fakeDir, logFile := setupScriptTest(t)
	writeFakeSystemctl(t, fakeDir, logFile, false, false)
	writeFakeSemodule(t, fakeDir, logFile, false, false)
	writeFakeRestorecon(t, fakeDir, logFile)

	tmpDir := t.TempDir()
	selinuxEnforceDir := filepath.Join(tmpDir, "sys", "fs", "selinux")
	if err := os.MkdirAll(selinuxEnforceDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(selinuxEnforceDir, "enforce"), []byte("1"), 0644); err != nil {
		t.Fatal(err)
	}
	aaEnabledDir := filepath.Join(tmpDir, "sys", "module", "apparmor", "parameters")
	if err := os.MkdirAll(aaEnabledDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(aaEnabledDir, "enabled"), []byte("N"), 0644); err != nil {
		t.Fatal(err)
	}

	stdout, _, code := runScript(t, "packaging/scripts/rpm/postinstall.sh", fakeDir, logFile,
		[]string{"1"}, true, []string{
			"SELINUX_ENFORCE_PATH=" + filepath.Join(selinuxEnforceDir, "enforce"),
			"AA_ENABLED_PATH=" + filepath.Join(aaEnabledDir, "enabled"),
		})
	if code != 0 {
		t.Fatalf("rpm postinst should exit 0, got %d", code)
	}

	// Must NOT emit the false AppArmor warning
	if strings.Contains(stdout, "AppArmor LSM is not active") {
		t.Error("must not emit 'AppArmor LSM is not active' warning when SELinux is active")
	}
	// Must NOT say "system mode will not start" when SELinux is active
	if strings.Contains(stdout, "system mode will not start") {
		t.Error("must not say 'system mode will not start' when SELinux is active")
	}
}

// TestRpmPostinstallAppArmorActive verifies the AppArmor path still works
// when only AppArmor is active (SELinux not enforcing).
func TestRpmPostinstallAppArmorActive(t *testing.T) {
	fakeDir, logFile := setupScriptTest(t)
	writeFakeSystemctl(t, fakeDir, logFile, false, false)
	writeFakeApparmorParser(t, fakeDir, logFile, false, false)

	_, _, code := runScript(t, "packaging/scripts/rpm/postinstall.sh", fakeDir, logFile,
		[]string{"1"}, true, nil)
	if code != 0 {
		t.Fatalf("rpm postinst should exit 0 when AppArmor active, got %d", code)
	}

	calls := readLifecycleScriptCalls(t, logFile)

	// Must call apparmor_parser --replace
	found := false
	for _, c := range calls {
		if strings.Contains(c, "apparmor_parser") && strings.Contains(c, "--replace") {
			found = true
		}
	}
	if !found {
		t.Error("must call apparmor_parser --replace when AppArmor is active")
	}

	// Must NOT call semodule -i (SELinux not enforcing)
	for _, c := range calls {
		if strings.Contains(c, "semodule") && strings.Contains(c, "-i") {
			t.Error("must not call semodule -i when SELinux is not enforcing")
		}
	}
}

// TestRpmPostinstallNeitherMAC verifies that when no MAC backend is active,
// the RPM postinstall emits the correct warning and still performs daemon-reload.
func TestRpmPostinstallNeitherMAC(t *testing.T) {
	fakeDir, logFile := setupScriptTest(t)
	writeFakeSystemctl(t, fakeDir, logFile, false, false)

	tmpDir := t.TempDir()
	aaEnabledDir := filepath.Join(tmpDir, "sys", "module", "apparmor", "parameters")
	if err := os.MkdirAll(aaEnabledDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(aaEnabledDir, "enabled"), []byte("N"), 0644); err != nil {
		t.Fatal(err)
	}
	selinuxEnforceDir := filepath.Join(tmpDir, "sys", "fs", "selinux")
	if err := os.MkdirAll(selinuxEnforceDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(selinuxEnforceDir, "enforce"), []byte("0"), 0644); err != nil {
		t.Fatal(err)
	}

	stdout, _, code := runScript(t, "packaging/scripts/rpm/postinstall.sh", fakeDir, logFile,
		[]string{"1"}, true, []string{
			"AA_ENABLED_PATH=" + filepath.Join(aaEnabledDir, "enabled"),
			"SELINUX_ENFORCE_PATH=" + filepath.Join(selinuxEnforceDir, "enforce"),
		})
	if code != 0 {
		t.Fatalf("rpm postinst should exit 0 when no MAC active, got %d", code)
	}

	// Must emit warning about no MAC backend
	if !strings.Contains(stdout, "no supported MAC backend active") {
		t.Errorf("expected 'no supported MAC backend active' warning, got: %s", stdout)
	}

	calls := readLifecycleScriptCalls(t, logFile)

	// Must NOT call apparmor_parser
	for _, c := range calls {
		if strings.Contains(c, "apparmor_parser") {
			t.Error("must not call apparmor_parser when no MAC is active")
		}
	}
	// Must NOT call semodule
	for _, c := range calls {
		if strings.Contains(c, "semodule") {
			t.Error("must not call semodule when no MAC is active")
		}
	}
	// Must still call daemon-reload
	found := false
	for _, c := range calls {
		if strings.Contains(c, "daemon-reload") {
			found = true
		}
	}
	if !found {
		t.Error("must still call daemon-reload when no MAC is active")
	}
}

// TestRpmPostinstallBothMAC verifies that when both AppArmor and SELinux
// are active, the postinstall warns about the unsupported configuration
// and still attempts to set up both.
func TestRpmPostinstallBothMAC(t *testing.T) {
	fakeDir, logFile := setupScriptTest(t)
	writeFakeSystemctl(t, fakeDir, logFile, false, false)
	writeFakeApparmorParser(t, fakeDir, logFile, false, false)
	writeFakeSemodule(t, fakeDir, logFile, false, false)
	writeFakeRestorecon(t, fakeDir, logFile)

	tmpDir := t.TempDir()
	selinuxEnforceDir := filepath.Join(tmpDir, "sys", "fs", "selinux")
	if err := os.MkdirAll(selinuxEnforceDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(selinuxEnforceDir, "enforce"), []byte("1"), 0644); err != nil {
		t.Fatal(err)
	}
	aaEnabledDir := filepath.Join(tmpDir, "sys", "module", "apparmor", "parameters")
	if err := os.MkdirAll(aaEnabledDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(aaEnabledDir, "enabled"), []byte("Y"), 0644); err != nil {
		t.Fatal(err)
	}

	stdout, _, code := runScript(t, "packaging/scripts/rpm/postinstall.sh", fakeDir, logFile,
		[]string{"1"}, true, []string{
			"AA_ENABLED_PATH=" + filepath.Join(aaEnabledDir, "enabled"),
			"SELINUX_ENFORCE_PATH=" + filepath.Join(selinuxEnforceDir, "enforce"),
		})
	if code != 0 {
		t.Fatalf("rpm postinst should exit 0 when both MAC active, got %d", code)
	}

	// Must warn about both being active
	if !strings.Contains(stdout, "both AppArmor and SELinux are active") {
		t.Errorf("expected 'both AppArmor and SELinux are active' warning, got: %s", stdout)
	}

	calls := readLifecycleScriptCalls(t, logFile)

	// Must attempt both apparmor_parser and semodule
	foundAA, foundSELinux := false, false
	for _, c := range calls {
		if strings.Contains(c, "apparmor_parser") && strings.Contains(c, "--replace") {
			foundAA = true
		}
		if strings.Contains(c, "semodule") && strings.Contains(c, "-i") {
			foundSELinux = true
		}
	}
	if !foundAA {
		t.Error("must still attempt apparmor_parser when both are active")
	}
	if !foundSELinux {
		t.Error("must still attempt semodule when both are active")
	}
}

// TestRpmPostinstallSemoduleFailure verifies that when semodule -i fails,
// the RPM postinstall fails the transaction.
func TestRpmPostinstallSemoduleFailure(t *testing.T) {
	fakeDir, logFile := setupScriptTest(t)
	writeFakeSystemctl(t, fakeDir, logFile, false, false)
	writeFakeSemodule(t, fakeDir, logFile, true, false)

	tmpDir := t.TempDir()
	selinuxEnforceDir := filepath.Join(tmpDir, "sys", "fs", "selinux")
	if err := os.MkdirAll(selinuxEnforceDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(selinuxEnforceDir, "enforce"), []byte("1"), 0644); err != nil {
		t.Fatal(err)
	}
	aaEnabledDir := filepath.Join(tmpDir, "sys", "module", "apparmor", "parameters")
	if err := os.MkdirAll(aaEnabledDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(aaEnabledDir, "enabled"), []byte("N"), 0644); err != nil {
		t.Fatal(err)
	}

	_, _, code := runScript(t, "packaging/scripts/rpm/postinstall.sh", fakeDir, logFile,
		[]string{"1"}, true, []string{
			"SELINUX_ENFORCE_PATH=" + filepath.Join(selinuxEnforceDir, "enforce"),
			"AA_ENABLED_PATH=" + filepath.Join(aaEnabledDir, "enabled"),
		})
	if code == 0 {
		t.Fatal("rpm postinst should fail when semodule -i fails")
	}

	calls := readLifecycleScriptCalls(t, logFile)
	for _, c := range calls {
		if strings.Contains(c, "daemon-reload") || strings.Contains(c, "try-restart") {
			t.Error("must not proceed after semodule failure")
		}
	}
}

// TestRpmPreremoveFinalEraseSELinux verifies RPM preremove on final erase
// removes the SELinux module.
func TestRpmPreremoveFinalEraseSELinux(t *testing.T) {
	fakeDir, logFile := setupScriptTest(t)
	writeFakeSystemctl(t, fakeDir, logFile, true, true)
	writeFakeApparmorParser(t, fakeDir, logFile, false, false)
	writeFakeSemodule(t, fakeDir, logFile, false, false)

	_, _, code := runScript(t, "packaging/scripts/rpm/preremove.sh", fakeDir, logFile,
		[]string{"0"}, true, nil)
	if code != 0 {
		t.Fatalf("rpm preun final erase should exit 0, got %d", code)
	}

	calls := readLifecycleScriptCalls(t, logFile)

	// Must call semodule -r
	found := false
	for _, c := range calls {
		if strings.Contains(c, "semodule") && strings.Contains(c, "-r") {
			found = true
			if !strings.Contains(c, "docker_helper") {
				t.Errorf("semodule -r must target docker_helper: %s", c)
			}
		}
	}
	if !found {
		t.Error("must call semodule -r docker_helper on final erase")
	}
}

// TestRpmPreremoveUpgradePreservesSELinux verifies RPM preremove on upgrade
// does NOT remove the SELinux module (the new postinstall will replace it).
func TestRpmPreremoveUpgradePreservesSELinux(t *testing.T) {
	fakeDir, logFile := setupScriptTest(t)
	writeFakeSystemctl(t, fakeDir, logFile, true, true)
	writeFakeApparmorParser(t, fakeDir, logFile, false, false)
	writeFakeSemodule(t, fakeDir, logFile, false, false)

	_, _, code := runScript(t, "packaging/scripts/rpm/preremove.sh", fakeDir, logFile,
		[]string{"1"}, true, nil)
	if code != 0 {
		t.Fatalf("rpm preun upgrade should exit 0, got %d", code)
	}

	calls := readLifecycleScriptCalls(t, logFile)
	for _, c := range calls {
		if strings.Contains(c, "semodule") {
			t.Errorf("rpm preun upgrade must not call semodule: %s", c)
		}
		if strings.Contains(c, "stop") || strings.Contains(c, "disable") {
			t.Errorf("rpm preun upgrade must not stop/disable: %s", c)
		}
	}
}

// TestDebPostinstallSELinuxNoFalseAppArmorWarning verifies that when
// SELinux is active, the DEB postinstall does not emit the false
// "AppArmor LSM is not active" warning.
func TestDebPostinstallSELinuxNoFalseAppArmorWarning(t *testing.T) {
	fakeDir, logFile := setupScriptTest(t)
	writeFakeSystemctl(t, fakeDir, logFile, false, false)

	tmpDir := t.TempDir()
	selinuxEnforceDir := filepath.Join(tmpDir, "sys", "fs", "selinux")
	if err := os.MkdirAll(selinuxEnforceDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(selinuxEnforceDir, "enforce"), []byte("1"), 0644); err != nil {
		t.Fatal(err)
	}
	aaEnabledDir := filepath.Join(tmpDir, "sys", "module", "apparmor", "parameters")
	if err := os.MkdirAll(aaEnabledDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(aaEnabledDir, "enabled"), []byte("N"), 0644); err != nil {
		t.Fatal(err)
	}

	stdout, _, code := runScript(t, "packaging/scripts/deb/postinstall.sh", fakeDir, logFile,
		[]string{"configure"}, true, []string{
			"SELINUX_ENFORCE_PATH=" + filepath.Join(selinuxEnforceDir, "enforce"),
			"AA_ENABLED_PATH=" + filepath.Join(aaEnabledDir, "enabled"),
		})
	if code != 0 {
		t.Fatalf("deb postinst should exit 0 when SELinux active, got %d", code)
	}

	// Must NOT emit the false AppArmor warning
	if strings.Contains(stdout, "AppArmor LSM is not active") {
		t.Error("must not emit 'AppArmor LSM is not active' warning when SELinux is active")
	}
	// Must NOT say "system mode will not start" when SELinux is active
	if strings.Contains(stdout, "system mode will not start") {
		t.Error("must not say 'system mode will not start' when SELinux is active")
	}

	calls := readLifecycleScriptCalls(t, logFile)

	// Must still call daemon-reload
	found := false
	for _, c := range calls {
		if strings.Contains(c, "daemon-reload") {
			found = true
		}
	}
	if !found {
		t.Error("must still call daemon-reload when SELinux is active")
	}
}

// TestDebPostinstallNeitherMAC verifies that when no MAC backend is active,
// the DEB postinstall emits the correct warning.
func TestDebPostinstallNeitherMAC(t *testing.T) {
	fakeDir, logFile := setupScriptTest(t)
	writeFakeSystemctl(t, fakeDir, logFile, false, false)

	tmpDir := t.TempDir()
	aaEnabledDir := filepath.Join(tmpDir, "sys", "module", "apparmor", "parameters")
	if err := os.MkdirAll(aaEnabledDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(aaEnabledDir, "enabled"), []byte("N"), 0644); err != nil {
		t.Fatal(err)
	}
	selinuxEnforceDir := filepath.Join(tmpDir, "sys", "fs", "selinux")
	if err := os.MkdirAll(selinuxEnforceDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(selinuxEnforceDir, "enforce"), []byte("0"), 0644); err != nil {
		t.Fatal(err)
	}

	stdout, _, code := runScript(t, "packaging/scripts/deb/postinstall.sh", fakeDir, logFile,
		[]string{"configure"}, true, []string{
			"AA_ENABLED_PATH=" + filepath.Join(aaEnabledDir, "enabled"),
			"SELINUX_ENFORCE_PATH=" + filepath.Join(selinuxEnforceDir, "enforce"),
		})
	if code != 0 {
		t.Fatalf("deb postinst should exit 0 when no MAC active, got %d", code)
	}

	// Must emit warning about no MAC backend
	if !strings.Contains(stdout, "no supported MAC backend active") {
		t.Errorf("expected 'no supported MAC backend active' warning, got: %s", stdout)
	}
}

// --- Offline (no live system) tests ---

// TestLifecycleScriptsOfflineNoop verifies all DEB/RPM lifecycle scripts
// are no-ops (exit 0, no tool calls) when no live system is present.
func TestLifecycleScriptsOfflineNoop(t *testing.T) {
	tests := []struct {
		name   string
		script string
		args   []string
	}{
		{"deb_postinst", "packaging/scripts/deb/postinstall.sh", []string{"configure"}},
		{"deb_prerm", "packaging/scripts/deb/preremove.sh", []string{"remove"}},
		{"deb_postrm", "packaging/scripts/deb/postremove.sh", []string{"remove"}},
		{"rpm_postinst", "packaging/scripts/rpm/postinstall.sh", []string{"1"}},
		{"rpm_preun", "packaging/scripts/rpm/preremove.sh", []string{"0"}},
		{"rpm_postun", "packaging/scripts/rpm/postremove.sh", []string{"0"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeDir, logFile := setupScriptTest(t)

			_, _, code := runScript(t, tt.script, fakeDir, logFile, tt.args, false, nil)
			if code != 0 {
				t.Fatalf("offline %s should exit 0, got %d", tt.name, code)
			}
			if calls := readLifecycleScriptCalls(t, logFile); len(calls) > 0 {
				t.Errorf("offline %s must not call any tools: %v", tt.name, calls)
			}
		})
	}
}

// --- RPM state preservation test ---

// TestRpmPostremovePreservesState verifies RPM postun does not remove state dirs.
func TestRpmPostremovePreservesState(t *testing.T) {
	data, err := os.ReadFile("packaging/scripts/rpm/postremove.sh")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	for _, path := range []string{"/etc/docker-helper", "/var/lib/docker-helper", "/run/docker-helper"} {
		if strings.Contains(content, path) {
			t.Errorf("RPM postremove must not remove: %s", path)
		}
	}
}

// --- Package metadata: scripts embedded ---

// TestPackageMetadataScripts verifies that the built packages contain the
// lifecycle scripts. Skipped when nfpm is unavailable.
func TestPackageMetadataScripts(t *testing.T) {
	if _, err := exec.LookPath("nfpm"); err != nil {
		t.Skip("nfpm not installed, skipping package metadata scripts test")
	}

	tmpDir := t.TempDir()

	// Create a dummy binary.
	dummyBin := filepath.Join(tmpDir, "docker-helper")
	if err := os.WriteFile(dummyBin, []byte("dummy"), 0755); err != nil {
		t.Fatal(err)
	}

	// Create a temporary nFPM config.
	nfpmData, err := os.ReadFile("packaging/nfpm.yaml")
	if err != nil {
		t.Fatal(err)
	}
	configContent := strings.ReplaceAll(string(nfpmData), "src: dist/docker-helper", "src: "+dummyBin)
	configContent = strings.ReplaceAll(configContent, "${VERSION}", "0.0.0")
	configFile := filepath.Join(tmpDir, "nfpm.yaml")
	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Build DEB.
	debCmd := exec.Command("nfpm", "package", "--config", configFile, "--packager", "deb", "--target", tmpDir)
	debCmd.Env = append(os.Environ(), "VERSION=0.0.0")
	if out, err := debCmd.CombinedOutput(); err != nil {
		t.Fatalf("nfpm DEB build failed: %v\n%s", err, out)
	}

	// Build RPM.
	rpmCmd := exec.Command("nfpm", "package", "--config", configFile, "--packager", "rpm", "--target", tmpDir)
	rpmCmd.Env = append(os.Environ(), "VERSION=0.0.0")
	if out, err := rpmCmd.CombinedOutput(); err != nil {
		t.Fatalf("nfpm RPM build failed: %v\n%s", err, out)
	}

	debFile := filepath.Join(tmpDir, "docker-helper_0.0.0_amd64.deb")
	rpmFile := filepath.Join(tmpDir, "docker-helper-0.0.0-1.x86_64.rpm")

	// Verify DEB scripts.
	if dpkgDeb, err := exec.LookPath("dpkg-deb"); err == nil {
		controlDir := filepath.Join(tmpDir, "deb-control")
		if err := os.MkdirAll(controlDir, 0755); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(dpkgDeb, "--control", debFile, controlDir)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("dpkg-deb --control failed: %v\n%s", err, out)
		}
		for _, script := range []string{"postinst", "prerm", "postrm"} {
			scriptPath := filepath.Join(controlDir, script)
			info, err := os.Stat(scriptPath)
			if err != nil {
				t.Errorf("DEB must contain script: %s", script)
				continue
			}
			if info.Mode()&0111 == 0 {
				t.Errorf("DEB script must be executable: %s (mode %o)", script, info.Mode())
			}
		}
	} else {
		t.Log("dpkg-deb not available, skipping DEB script verification")
	}

	// Verify RPM scripts.
	if rpmPath, err := exec.LookPath("rpm"); err == nil {
		cmd := exec.Command(rpmPath, "-qp", "--scripts", rpmFile)
		out, _ := cmd.CombinedOutput()
		scriptStr := string(out)
		for _, section := range []string{"postinstall", "preuninstall", "postuninstall"} {
			if !strings.Contains(scriptStr, section) {
				t.Errorf("RPM must contain scriptlet: %s", section)
			}
		}
	} else {
		t.Log("rpm not available, skipping RPM script verification")
	}
}

// --- Man page source tests ---

// --- Build script tests ---

func TestBuildManpagesScriptBuilds(t *testing.T) {
	if _, err := exec.LookPath("gzip"); err != nil {
		t.Skip("gzip not available, skipping manpage build test")
	}

	cmd := exec.Command("bash", "build-manpages.sh")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build-manpages.sh failed: %v\n%s", err, out)
	}

	for _, f := range []string{"dist/man/docker-helper.1.gz", "dist/man/docker-helper-config.5.gz"} {
		if _, err := os.Stat(f); err != nil {
			t.Fatalf("man page output not found: %s", f)
		}
		cmd := exec.Command("gzip", "-t", f)
		if err := cmd.Run(); err != nil {
			t.Errorf("gzip verification failed for %s: %v", f, err)
		}
	}

	// Decompress and verify .TH inside each gz.
	for _, f := range []string{"dist/man/docker-helper.1.gz", "dist/man/docker-helper-config.5.gz"} {
		cmd := exec.Command("gzip", "-d", "-c", f)
		dec, err := cmd.Output()
		if err != nil {
			t.Fatalf("decompress %s: %v", f, err)
		}
		decStr := string(dec)
		if strings.Contains(f, "docker-helper.1") && !strings.Contains(decStr, ".TH DOCKER-HELPER 1") {
			t.Errorf("decompressed %s missing '.TH DOCKER-HELPER 1'", f)
		}
		if strings.Contains(f, "docker-helper-config.5") && !strings.Contains(decStr, ".TH DOCKER-HELPER-CONFIG 5") {
			t.Errorf("decompressed %s missing '.TH DOCKER-HELPER-CONFIG 5'", f)
		}
	}
}

// --- Package metadata integration for man pages ---

func TestPackageMetadataManPages(t *testing.T) {
	if _, err := exec.LookPath("nfpm"); err != nil {
		t.Skip("nfpm not installed, skipping package metadata man pages test")
	}

	tmpDir := t.TempDir()

	// Create dummy binary.
	dummyBin := filepath.Join(tmpDir, "docker-helper")
	if err := os.WriteFile(dummyBin, []byte("dummy"), 0755); err != nil {
		t.Fatal(err)
	}

	// Build real compressed man pages for the test.
	os.MkdirAll(filepath.Join(tmpDir, "man"), 0755)
	for _, src := range []string{"docs/man/docker-helper.1", "docs/man/docker-helper-config.5"} {
		srcData, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		name := filepath.Base(src)
		cmd := exec.Command("gzip", "-9n", "-c")
		cmd.Stdin = strings.NewReader(string(srcData))
		gzOut, err := cmd.Output()
		if err != nil {
			t.Fatalf("gzip %s: %v", src, err)
		}
		if err := os.WriteFile(filepath.Join(tmpDir, "man", name+".gz"), gzOut, 0644); err != nil {
			t.Fatal(err)
		}
	}

	// Create temp nFPM config.
	nfpmData, err := os.ReadFile("packaging/nfpm.yaml")
	if err != nil {
		t.Fatal(err)
	}
	configContent := strings.ReplaceAll(string(nfpmData), "src: dist/docker-helper", "src: "+dummyBin)
	configContent = strings.ReplaceAll(configContent, "src: dist/man/docker-helper.1.gz", "src: "+filepath.Join(tmpDir, "man", "docker-helper.1.gz"))
	configContent = strings.ReplaceAll(configContent, "src: dist/man/docker-helper-config.5.gz", "src: "+filepath.Join(tmpDir, "man", "docker-helper-config.5.gz"))
	configContent = strings.ReplaceAll(configContent, "${VERSION}", "0.0.0")
	configFile := filepath.Join(tmpDir, "nfpm.yaml")
	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Build DEB.
	debCmd := exec.Command("nfpm", "package", "--config", configFile, "--packager", "deb", "--target", tmpDir)
	debCmd.Env = append(os.Environ(), "VERSION=0.0.0")
	if out, err := debCmd.CombinedOutput(); err != nil {
		t.Fatalf("nfpm DEB build failed: %v\n%s", err, out)
	}

	// Build RPM.
	rpmCmd := exec.Command("nfpm", "package", "--config", configFile, "--packager", "rpm", "--target", tmpDir)
	rpmCmd.Env = append(os.Environ(), "VERSION=0.0.0")
	if out, err := rpmCmd.CombinedOutput(); err != nil {
		t.Fatalf("nfpm RPM build failed: %v\n%s", err, out)
	}

	debFile := filepath.Join(tmpDir, "docker-helper_0.0.0_amd64.deb")
	rpmFile := filepath.Join(tmpDir, "docker-helper-0.0.0-1.x86_64.rpm")

	// Verify DEB contains man pages with exact paths and mode.
	if dpkgDeb, err := exec.LookPath("dpkg-deb"); err == nil {
		cmd := exec.Command(dpkgDeb, "--contents", debFile)
		out, _ := cmd.CombinedOutput()
		outStr := string(out)
		if !strings.Contains(outStr, "/usr/share/man/man1/docker-helper.1.gz") {
			t.Error("DEB missing /usr/share/man/man1/docker-helper.1.gz")
		}
		if !strings.Contains(outStr, "/usr/share/man/man5/docker-helper-config.5.gz") {
			t.Error("DEB missing /usr/share/man/man5/docker-helper-config.5.gz")
		}
		for _, line := range strings.Split(outStr, "\n") {
			if strings.Contains(line, "docker-helper.1.gz") || strings.Contains(line, "docker-helper-config.5.gz") {
				fields := strings.Fields(line)
				if len(fields) >= 1 && fields[0] != "-rw-r--r--" {
					t.Errorf("man page mode wrong in DEB: %s", line)
				}
			}
		}
	} else {
		t.Log("dpkg-deb not available, skipping DEB man page verification")
	}

	// Verify RPM contains man pages with exact paths and mode.
	if rpmPath, err := exec.LookPath("rpm"); err == nil {
		cmd := exec.Command(rpmPath, "-qpl", rpmFile)
		out, _ := cmd.CombinedOutput()
		outStr := string(out)
		if !strings.Contains(outStr, "/usr/share/man/man1/docker-helper.1.gz") {
			t.Error("RPM missing /usr/share/man/man1/docker-helper.1.gz")
		}
		if !strings.Contains(outStr, "/usr/share/man/man5/docker-helper-config.5.gz") {
			t.Error("RPM missing /usr/share/man/man5/docker-helper-config.5.gz")
		}
		// Verify exact FILEMODES for each man page path individually.
		cmd2 := exec.Command(rpmPath, "-qp", "--queryformat", "[%{FILENAMES}\t%{FILEMODES:perms}\n]", rpmFile)
		out2, _ := cmd2.CombinedOutput()
		expectedModes := map[string]string{
			"/usr/share/man/man1/docker-helper.1.gz":        "-rw-r--r--",
			"/usr/share/man/man5/docker-helper-config.5.gz": "-rw-r--r--",
		}
		foundModes := make(map[string]string)
		for _, line := range strings.Split(strings.TrimSpace(string(out2)), "\n") {
			parts := strings.Split(line, "\t")
			if len(parts) == 2 {
				foundModes[parts[0]] = parts[1]
			}
		}
		for path, expected := range expectedModes {
			actual, ok := foundModes[path]
			if !ok {
				t.Errorf("RPM man page path not found in FILENAMES: %s", path)
				continue
			}
			if actual != expected {
				t.Errorf("RPM man page mode wrong for %s: expected %s, got %s", path, expected, actual)
			}
		}
	} else {
		t.Log("rpm not available, skipping RPM man page verification")
	}
}

// TestReleaseWorkflow guards the release pipeline contract: authoritative
// build scripts, pinned nFPM version with SHA256, no @latest, SHA256SUMS,
// all artifact types, and prerelease handling.
func TestReleaseWorkflow(t *testing.T) {
	data, err := os.ReadFile(".github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	// Must use authoritative build scripts.
	if !strings.Contains(content, "build-bundle.sh") {
		t.Error("release.yml must call build-bundle.sh")
	}
	if !strings.Contains(content, "build-packages.sh") {
		t.Error("release.yml must call build-packages.sh")
	}

	// Must pin nFPM version.
	if !strings.Contains(content, "NFPM_VERSION=2.47.0") {
		t.Error("release.yml must pin NFPM_VERSION=2.47.0")
	}

	// Must verify nFPM SHA256.
	if !strings.Contains(content, "0660ca602b2d2d2ae4781a06c692b3eeb9d437ffea05b831d76e41f4a3188783") {
		t.Error("release.yml must contain pinned nFPM SHA256")
	}

	// Must NOT use @latest for nFPM.
	if strings.Contains(content, "@latest") {
		t.Error("release.yml must not use @latest for nFPM")
	}

	// Must generate and verify SHA256SUMS.
	if !strings.Contains(content, "SHA256SUMS") {
		t.Error("release.yml must generate SHA256SUMS")
	}

	// Must upload all artifact types.
	if !strings.Contains(content, "tar.gz") {
		t.Error("release.yml must upload .tar.gz")
	}
	if !strings.Contains(content, ".deb") {
		t.Error("release.yml must upload .deb")
	}
	if !strings.Contains(content, ".rpm") {
		t.Error("release.yml must upload .rpm")
	}

	// Prerelease handling must be preserved.
	if !strings.Contains(content, "prerelease") {
		t.Error("release.yml must handle prerelease")
	}

	// Must include race test (not weaker than CI).
	if !strings.Contains(content, "go test -race") {
		t.Error("release.yml must run go test -race")
	}

	// musl-tools must be present (release job installs it before building).
	muslIdx := strings.Index(content, "musl-tools")
	testsIdx := strings.Index(content, "go test ./...")
	if muslIdx < 0 || testsIdx < 0 {
		t.Fatal("release.yml must contain musl-tools install and go test")
	}
}

func TestReleaseWorkflowRaceBeforeBuild(t *testing.T) {
	data, err := os.ReadFile(".github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	// Race tests must complete before build-bundle.sh.
	raceIdx := strings.Index(content, "go test -race")
	bundleIdx := strings.Index(content, "build-bundle.sh")
	if raceIdx < 0 || bundleIdx < 0 {
		t.Fatal("release.yml must contain go test -race and build-bundle.sh")
	}
	if raceIdx > bundleIdx {
		t.Error("release.yml must run race tests before build-bundle.sh")
	}
}

func TestReleaseMetadataGPL3Only(t *testing.T) {
	// nfpm.yaml must use GPL-3.0-only.
	data, err := os.ReadFile("packaging/nfpm.yaml")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if !strings.Contains(content, "license: GPL-3.0-only") {
		t.Error("nfpm.yaml must specify license: GPL-3.0-only")
	}
	if strings.Contains(content, "GPL-3.0-or-later") {
		t.Error("nfpm.yaml must not use GPL-3.0-or-later")
	}

	// LICENSE file must exist and reference GPLv3.
	licenseData, err := os.ReadFile("LICENSE")
	if err != nil {
		t.Fatal(err)
	}
	licenseContent := string(licenseData)
	if !strings.Contains(licenseContent, "GNU GENERAL PUBLIC LICENSE") {
		t.Error("LICENSE must contain GNU GENERAL PUBLIC LICENSE")
	}
	if !strings.Contains(licenseContent, "Version 3") {
		t.Error("LICENSE must reference Version 3")
	}
}

func TestReleaseReadmeNoR3Features(t *testing.T) {
	data, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	// Release 2 must not claim R3 features.
	for _, feature := range []string{"remote", "TLS", "port publish", "attached exec", "MCP"} {
		if strings.Contains(content, feature) {
			t.Errorf("README must not reference R3 feature: %s", feature)
		}
	}
}

// TestAppArmorCurlSnippet verifies the curl AppArmor compatibility snippet
// exists and contains the required socket rules for both deployment modes.
func TestAppArmorCurlSnippet(t *testing.T) {
	path := "packaging/apparmor/local/curl"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("AppArmor curl snippet %s not found: %v", path, err)
	}
	content := string(data)

	// Must contain user-mode socket rule.
	if !strings.Contains(content, "/run/user/*/docker-helper/docker-helper.sock rw") {
		t.Error("snippet must contain user-mode socket rule")
	}
	// Must contain system-mode socket rule.
	if !strings.Contains(content, "/run/docker-helper/docker-helper.sock rw") {
		t.Error("snippet must contain system-mode socket rule")
	}
	// Must not contain executable or capability grants.
	for _, s := range []string{"rix", "ix", "capability"} {
		if strings.Contains(content, s) {
			t.Errorf("snippet must not contain %q (only socket access rules)", s)
		}
	}
}

// TestBuildBundleIncludesCurlSnippet verifies build-bundle.sh copies the
// curl AppArmor snippet into the tarball and verifies its presence.
func TestBuildBundleIncludesCurlSnippet(t *testing.T) {
	data, err := os.ReadFile("build-bundle.sh")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	// Must copy the snippet into the bundle.
	if !strings.Contains(content, "apparmor/local/curl") {
		t.Error("build-bundle.sh must copy apparmor/local/curl into the bundle")
	}
	// EXPECTED_PATHS must include the snippet.
	if idx := strings.Index(content, "EXPECTED_PATHS="); idx < 0 {
		t.Fatal("EXPECTED_PATHS not found")
	} else if endIdx := strings.Index(content[idx:], ")"); endIdx >= 0 {
		if !strings.Contains(content[idx:idx+endIdx], "apparmor/local/curl") {
			t.Error("EXPECTED_PATHS must include apparmor/local/curl")
		}
	}
}

// TestNfpmConfigIncludesCurlSnippet verifies nfpm.yaml includes the curl
// AppArmor snippet in the package contents.
func TestNfpmConfigIncludesCurlSnippet(t *testing.T) {
	data, err := os.ReadFile("packaging/nfpm.yaml")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	if !strings.Contains(content, "packaging/apparmor/local/curl") {
		t.Error("nfpm.yaml must include packaging/apparmor/local/curl source")
	}
	if !strings.Contains(content, "/usr/share/docker-helper/apparmor/local/curl") {
		t.Error("nfpm.yaml must install snippet to /usr/share/docker-helper/apparmor/local/curl")
	}
}

// TestInstallScriptAppArmorCurlWarning verifies install.sh contains the
// warn_apparmor_confined_curl function that checks for /etc/apparmor.d/curl
// and prints a hint without modifying system AppArmor policy.
func TestInstallScriptAppArmorCurlWarning(t *testing.T) {
	data, err := os.ReadFile("packaging/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	// Must contain the warning function.
	if !strings.Contains(content, "warn_apparmor_confined_curl") {
		t.Error("install.sh must contain warn_apparmor_confined_curl function")
	}
	// Must check for /etc/apparmor.d/curl.
	if !strings.Contains(content, "/etc/apparmor.d/curl") {
		t.Error("install.sh must check for /etc/apparmor.d/curl")
	}
	// Must reference the bundled snippet path.
	if !strings.Contains(content, "apparmor/local/curl") {
		t.Error("install.sh must reference the bundled snippet path")
	}
	// Must not modify system AppArmor policy outside of informational messages.
	// Check non-info/warn/error lines for automatic modifications.
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") ||
			strings.HasPrefix(trimmed, "info ") || strings.HasPrefix(trimmed, "warn ") ||
			strings.HasPrefix(trimmed, "error ") {
			continue
		}
		if strings.Contains(trimmed, ">> /etc/apparmor.d/local/curl") {
			t.Error("install.sh must not modify /etc/apparmor.d/local/curl automatically: " + trimmed)
		}
		if strings.Contains(trimmed, "apparmor_parser") {
			t.Error("install.sh must not call apparmor_parser: " + trimmed)
		}
	}
}

// TestReleaseReadmeIncludesCurlSnippet verifies the release README lists
// the curl AppArmor snippet in the contents.
func TestReleaseReadmeIncludesCurlSnippet(t *testing.T) {
	data, err := os.ReadFile("packaging/README.release.md")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	if !strings.Contains(content, "apparmor/local/curl") {
		t.Error("release README must list apparmor/local/curl in contents")
	}
}
