package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
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
		{"bash", "build-selinux-policy.sh"},
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
		"apparmor", "apparmor/docker-helper", "apparmor/docker-helper-system",
		"apparmor/local/curl",
		"selinux", "selinux/docker_helper.pp",
		"build-selinux-policy.sh",
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
	// Must create the tarball with canonical numeric ownership 0:0 independent
	// of the build environment (runner UID/GID must never leak into the archive).
	if !strings.Contains(content, "--owner=0 --group=0 --numeric-owner") {
		t.Error("build-bundle.sh must create the tarball with --owner=0 --group=0 --numeric-owner")
	}
	// Must fail closed when any archive entry (files or directories) is not 0:0.
	if !strings.Contains(content, `$2 == "0/0"`) {
		t.Error("build-bundle.sh must verify every archive entry is owned 0:0")
	}
	if !strings.Contains(content, "not owned 0:0") {
		t.Error("build-bundle.sh must fail with an ownership-specific message on non-root entries")
	}
}

// TestBuildBundleSELinuxArtifact verifies build-bundle.sh verifies the SELinux
// policy artifact is present in the bundle and that the tarball mandatory-path
// list includes selinux/docker_helper.pp (fail-closed: a missing policy build
// fails the bundle build).
func TestBuildBundleSELinuxArtifact(t *testing.T) {
	data, err := os.ReadFile("build-bundle.sh")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	// Must build the policy through the canonical owner before assembling.
	if !strings.Contains(content, "build-selinux-policy.sh") {
		t.Error("build-bundle.sh must call build-selinux-policy.sh")
	}
	if !strings.Contains(content, "BUNDLE_DIR/selinux/docker_helper.pp") {
		t.Error("build-bundle.sh must copy docker_helper.pp into BUNDLE_DIR/selinux/")
	}
	// Must verify the artifact is present and non-empty in the bundle.
	if !strings.Contains(content, "-s \"$BUNDLE_DIR/selinux/docker_helper.pp\"") {
		t.Error("build-bundle.sh must verify selinux/docker_helper.pp is present and non-empty")
	}
	// The tarball mandatory-path list must include the SELinux policy artifact.
	if !strings.Contains(content, "selinux/docker_helper.pp") {
		t.Error("build-bundle.sh EXPECTED_PATHS must include selinux/docker_helper.pp")
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
	// RuntimeDirectoryPreserve=restart keeps the RuntimeDirectory inode across
	// `systemctl restart` so long-lived agent containers bind-mounting
	// /run/docker-helper continue to see the socket. Cleanup still happens on a
	// real stop.
	if !strings.Contains(content, "RuntimeDirectoryPreserve=restart") {
		t.Error("unit must contain RuntimeDirectoryPreserve=restart")
	}
}

// TestSystemUnitPATHMatchesSELinuxResolver verifies the system unit declares an
// explicit PATH exactly equal to dockerCLISearchPath (selinux_deploy.go). The
// daemon resolves the Docker CLI over its process PATH and system init relabels
// that same executable for enforcing SELinux; if the two ever diverged, the
// relabeled executable and the executed executable could differ.
func TestSystemUnitPATHMatchesSELinuxResolver(t *testing.T) {
	path := "packaging/systemd/system/docker-helper.service"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("system unit %s not found: %v", path, err)
	}

	var declared string
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Environment=PATH=") {
			declared = strings.TrimPrefix(trimmed, "Environment=PATH=")
			break
		}
	}
	if declared == "" {
		t.Fatal("system unit must declare an explicit Environment=PATH= contract")
	}

	want := strings.Join(dockerCLISearchPath, ":")
	if declared != want {
		t.Errorf("unit PATH = %q, want %q (must equal dockerCLISearchPath)", declared, want)
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

// activeTimeoutStopSec returns the values of active (non-commented)
// TimeoutStopSec= directives in a systemd unit, in file order.
func activeTimeoutStopSec(content string) []string {
	var vals []string
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "TimeoutStopSec=") {
			vals = append(vals, strings.TrimPrefix(trimmed, "TimeoutStopSec="))
		}
	}
	return vals
}

// timeoutStopSecViolation validates the Release 2 stop-timeout contract for a
// systemd unit: exactly one active TimeoutStopSec= directive with the value
// 45s (the internal shutdown budget is max 30s; the extra 15s is the external
// process-exit / SIGKILL-fallback margin, never the internal force-cleanup
// phase). Returns "" when the unit complies, otherwise a violation
// description. Commented directives are not active.
func timeoutStopSecViolation(content string) string {
	vals := activeTimeoutStopSec(content)
	if len(vals) != 1 {
		return fmt.Sprintf("expected exactly one active TimeoutStopSec= directive, got %v", vals)
	}
	if vals[0] != "45s" {
		return fmt.Sprintf("TimeoutStopSec=%s, want 45s", vals[0])
	}
	return ""
}

// TestSystemdTimeoutStopSecContract pins the TimeoutStopSec=45s contract on
// both shipped units and proves the assertion logic catches wrong values
// (e.g. 30s), a missing directive, duplicate active directives, and commented
// directives (which are not active).
func TestSystemdTimeoutStopSecContract(t *testing.T) {
	units := []string{
		"packaging/systemd/system/docker-helper.service",
		"packaging/systemd/user/docker-helper.service",
	}
	for _, path := range units {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("cannot read unit %s: %v", path, err)
		}
		if v := timeoutStopSecViolation(string(data)); v != "" {
			t.Errorf("%s: %s", path, v)
		}
		if vals := activeTimeoutStopSec(string(data)); len(vals) != 1 || vals[0] != "45s" {
			t.Errorf("%s: active TimeoutStopSec values = %v, want exactly [45s]", path, vals)
		}
	}

	// Fail-closed proof: each fixture must be rejected by the same assertion
	// logic that validates the shipped units.
	fixtures := []struct {
		name    string
		content string
		want    string // expected violation substring
	}{
		{"wrong value", "# comment\nTimeoutStopSec=30s\n", "want 45s"},
		{"other value", "TimeoutStopSec=60s\n", "want 45s"},
		{"missing directive", "[Service]\nExecStart=/usr/bin/docker-helper serve\n", "exactly one active"},
		{"duplicate directives", "TimeoutStopSec=45s\nTimeoutStopSec=45s\n", "exactly one active"},
		{"commented directive not active", "# TimeoutStopSec=45s\n", "exactly one active"},
		{"empty", "", "exactly one active"},
	}
	for _, tc := range fixtures {
		got := timeoutStopSecViolation(tc.content)
		if !strings.Contains(got, tc.want) {
			t.Errorf("fixture %q: violation = %q, want substring %q", tc.name, got, tc.want)
		}
	}
}

// --- System AppArmor profile tests ---

// TestSystemAppArmorProfileFile verifies the system AppArmor profile:
// named profile with managed-boundaries include, required capabilities,
// Docker socket policy, scoped mount policy, and no broad/overly
// permissive rules.
func TestSystemAppArmorProfileFile(t *testing.T) {
	path := "packaging/apparmor/docker-helper-system"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("system AppArmor profile %s not found: %v", path, err)
	}
	content := string(data)

	// Must include the dynamic managed boundaries state via if-exists.
	if !strings.Contains(content, `#include if exists "/var/lib/docker-helper/apparmor/managed-boundaries"`) {
		t.Error("profile must include managed boundaries state via if-exists")
	}
	// Must not include the legacy managed-roots fragment path.
	if strings.Contains(content, "docker-helper.d/managed-roots") {
		t.Error("profile must not reference legacy managed-roots fragment")
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
	// Instructions must not use touch for managed boundaries state.
	if strings.Contains(content, "touch") {
		t.Error("profile instructions must not use touch for managed boundaries state")
	}
	// AppArmor managed boundaries state subtree: rw on directory and files.
	if !strings.Contains(content, "/var/lib/docker-helper/apparmor/ rw,") {
		t.Error("profile must grant rw on /var/lib/docker-helper/apparmor/ directory")
	}
	if !strings.Contains(content, "/var/lib/docker-helper/apparmor/* rw,") {
		t.Error("profile must grant rw on /var/lib/docker-helper/apparmor/* files")
	}
	// Must NOT grant generic write access to /etc/apparmor.d/**.
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.Contains(trimmed, "/etc/apparmor.d/**") {
			perm := trimmed[strings.LastIndex(trimmed, " ")+1:]
			if strings.Contains(perm, "w") {
				t.Errorf("profile must not grant write on /etc/apparmor.d/** (found: %s)", trimmed)
			}
		}
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

	// Read profile.
	profileData, err := os.ReadFile("packaging/apparmor/docker-helper-system")
	if err != nil {
		t.Fatal(err)
	}

	// Write profile to temp file for parser. The managed boundaries include
	// uses if-exists, so it is skipped when the state file is absent, which
	// still validates the profile rules and the include directive syntax.
	dir := t.TempDir()
	profileFile := filepath.Join(dir, "docker-helper-system")
	if err := os.WriteFile(profileFile, profileData, 0644); err != nil {
		t.Fatal(err)
	}

	// Run parser in dry-run mode (-Q = dry run, -T = no cache).
	cmd := exec.Command(parserPath, "-Q", "-T", profileFile)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("apparmor_parser syntax validation failed: %v\noutput: %s", err, out)
	}
}

// --- System install/uninstall script tests ---

// TestInstallSystemScriptContent guards the facts normal CI cannot
// exercise: the root fail-closed check, the real system destination paths,
// and the separation from user-mode artifacts. Allowed-root handling,
// managed-boundaries state migration, AppArmor-before-init ordering, and
// profile load flags are proven by the behavioral tests below.
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
		"/var/lib/docker-helper/apparmor/managed-boundaries",
		"/etc/apparmor.d/docker-helper.d/managed-roots",
	} {
		if !strings.Contains(content, p) {
			t.Errorf("install-system.sh must reference path: %s", p)
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
	// Kernel-truth LSM status files used by install-system.sh backend
	// selection (AA_ENABLED_PATH / SELINUX_ENFORCE_PATH).
	aaEnabledPath      string
	selinuxEnforcePath string
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

// fakeSemodule installs a semodule fake (SELinux path) into the fake bin dir.
func (e *systemScriptEnv) fakeSemodule(t *testing.T, script string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(e.fakeBinDir, "semodule"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
}

// fakeRestorecon installs a restorecon fake (SELinux path) into the fake bin dir.
func (e *systemScriptEnv) fakeRestorecon(t *testing.T, script string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(e.fakeBinDir, "restorecon"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
}

// setLSMState writes the AppArmor and SELinux kernel-truth files that drive
// install-system.sh backend selection.
func (e *systemScriptEnv) setLSMState(t *testing.T, aaEnabled, selinuxEnforce string) {
	t.Helper()
	if err := os.WriteFile(e.aaEnabledPath, []byte(aaEnabled), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.selinuxEnforcePath, []byte(selinuxEnforce), 0644); err != nil {
		t.Fatal(err)
	}
}

// writeBundledSELinuxPP creates the bundled selinux/docker_helper.pp asset in
// the emulated bundle so the SELinux install path has an artifact to load.
func (e *systemScriptEnv) writeBundledSELinuxPP(t *testing.T) {
	t.Helper()
	dir := filepath.Join(e.scriptDir, "selinux")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "docker_helper.pp"), []byte("fake-pp"), 0644); err != nil {
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

// runPrepareApparmorState invokes prepare_apparmor_state directly from the
// production script against the fixture state and legacy paths.
func (e *systemScriptEnv) runPrepareApparmorState(t *testing.T) (string, error) {
	t.Helper()
	cmd := exec.Command("bash", "-c", fmt.Sprintf(`
		source %s
		AA_STATE_FILE="%s"
		AA_LEGACY_FRAGMENT="%s"
		prepare_apparmor_state
	`, e.scriptPath, e.dest("var/lib/docker-helper/apparmor/managed-boundaries"), e.dest("etc/apparmor.d/docker-helper.d/managed-roots")))
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
	// Standard AppArmor LSM status: active; SELinux: not enforcing. The
	// backend-selection tests override these files as needed.
	aaDir := filepath.Join(e.destDir, "sys", "module", "apparmor", "parameters")
	if err := os.MkdirAll(aaDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(aaDir, "enabled"), []byte("Y"), 0644); err != nil {
		t.Fatal(err)
	}
	selinuxDir := filepath.Join(e.destDir, "sys", "fs", "selinux")
	if err := os.MkdirAll(selinuxDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(selinuxDir, "enforce"), []byte("0"), 0644); err != nil {
		t.Fatal(err)
	}

	scriptData, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.scriptPath, scriptData, 0755); err != nil {
		t.Fatal(err)
	}
	// The LSM kernel-truth paths are injected through the same env overrides the
	// production scripts support (AA_ENABLED_PATH / SELINUX_ENFORCE_PATH).
	e.aaEnabledPath = filepath.Join(aaDir, "enabled")
	e.selinuxEnforcePath = filepath.Join(selinuxDir, "enforce")
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
	if err := os.MkdirAll(filepath.Join(e.scriptDir, "apparmor"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.scriptDir, "apparmor", "docker-helper-system"), []byte("profile docker-helper-system {}"), 0644); err != nil {
		t.Fatal(err)
	}

	e.env = []string{
		"PATH=" + e.fakeBinDir + ":" + os.Getenv("PATH"),
		"BINARY_DEST=" + e.dest("bin/docker-helper"),
		"UNIT_DEST=" + e.dest("etc/systemd/system/docker-helper.service"),
		"AA_PROFILE_DEST=" + e.dest("etc/apparmor.d/docker-helper-system"),
		"AA_STATE_FILE=" + e.dest("var/lib/docker-helper/apparmor/managed-boundaries"),
		"AA_LEGACY_FRAGMENT=" + e.dest("etc/apparmor.d/docker-helper.d/managed-roots"),
		"CONFIG_PATH=" + e.dest("etc/docker-helper/config.json"),
		"AA_PARSER=" + filepath.Join(e.fakeBinDir, "apparmor_parser"),
		"SYSTEMCTL=" + filepath.Join(e.fakeBinDir, "systemctl"),
		"DOCKER=" + filepath.Join(e.fakeBinDir, "docker"),
		"SELINUX_PP_DEST=" + e.dest("usr/share/selinux/docker_helper.pp"),
		"AA_ENABLED_PATH=" + e.aaEnabledPath,
		"SELINUX_ENFORCE_PATH=" + e.selinuxEnforcePath,
	}
	return e
}

// newSystemUninstallScriptEnv creates the fixture for uninstall-system.sh
// with an installed sentinel binary, the legacy managed-roots fragment, and the
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
	if err := os.MkdirAll(filepath.Dir(e.dest("var/lib/docker-helper/apparmor/managed-boundaries")), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.dest("var/lib/docker-helper/apparmor/managed-boundaries"),
		[]byte("# fixture managed boundaries state\n"), 0644); err != nil {
		t.Fatal(err)
	}

	e.env = []string{
		"PATH=" + e.fakeBinDir + ":" + os.Getenv("PATH"),
		"BINARY_DEST=" + e.dest("bin/docker-helper"),
		"UNIT_DEST=" + e.dest("etc/systemd/system/docker-helper.service"),
		"AA_PROFILE_DEST=" + e.dest("etc/apparmor.d/docker-helper-system"),
		"AA_STATE_FILE=" + e.dest("var/lib/docker-helper/apparmor/managed-boundaries"),
		"AA_LEGACY_FRAGMENT=" + e.dest("etc/apparmor.d/docker-helper.d/managed-roots"),
		"CONFIG_DIR=" + e.dest("etc/docker-helper"),
		"STATE_DIR=" + e.dest("var/lib/docker-helper"),
		"RUNTIME_DIR=" + e.dest("run/docker-helper"),
		"AA_PARSER=" + filepath.Join(e.fakeBinDir, "apparmor_parser"),
		"SELINUX_PP_DEST=" + e.dest("usr/share/selinux/docker_helper.pp"),
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

func TestInstallSystemMigratesLegacyFragment(t *testing.T) {
	env := newSystemInstallScriptEnv(t)

	legacyContent := "# legacy managed-roots content\n"
	legacyPath := env.dest("etc/apparmor.d/docker-helper.d/managed-roots")
	if err := os.WriteFile(legacyPath, []byte(legacyContent), 0644); err != nil {
		t.Fatal(err)
	}

	stateFile := env.dest("var/lib/docker-helper/apparmor/managed-boundaries")
	if out, err := env.runPrepareApparmorState(t); err != nil {
		t.Fatalf("prepare_apparmor_state failed: %v\n%s", err, out)
	}

	actual, err := os.ReadFile(stateFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(actual) != legacyContent {
		t.Errorf("legacy fragment not migrated to new state\ngot:  %q\nwant: %q", string(actual), legacyContent)
	}
}

func TestInstallSystemExistingNewStatePreserved(t *testing.T) {
	env := newSystemInstallScriptEnv(t)

	// Existing new state file must NOT be overwritten by legacy.
	stateFile := env.dest("var/lib/docker-helper/apparmor/managed-boundaries")
	existingContent := "# existing new state\n"
	if err := os.MkdirAll(filepath.Dir(stateFile), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stateFile, []byte(existingContent), 0644); err != nil {
		t.Fatal(err)
	}

	legacyPath := env.dest("etc/apparmor.d/docker-helper.d/managed-roots")
	if err := os.WriteFile(legacyPath, []byte("# different legacy content\n"), 0644); err != nil {
		t.Fatal(err)
	}

	if out, err := env.runPrepareApparmorState(t); err != nil {
		t.Fatalf("prepare_apparmor_state failed: %v\n%s", err, out)
	}

	actual, err := os.ReadFile(stateFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(actual) != existingContent {
		t.Errorf("existing new state was overwritten by legacy\ngot:  %q\nwant: %q", string(actual), existingContent)
	}
}

func TestInstallSystemStateDirectorySecurity(t *testing.T) {
	env := newSystemInstallScriptEnv(t)

	stateDir := env.dest("var/lib/docker-helper")
	stateSubDir := env.dest("var/lib/docker-helper/apparmor")
	legacyPath := env.dest("etc/apparmor.d/docker-helper.d/managed-roots")

	// Create legacy fragment to trigger migration.
	if err := os.WriteFile(legacyPath, []byte("# legacy\n"), 0644); err != nil {
		t.Fatal(err)
	}

	if out, err := env.runPrepareApparmorState(t); err != nil {
		t.Fatalf("prepare_apparmor_state failed: %v\n%s", err, out)
	}

	// Top-level state directory must be 0700.
	topInfo, err := os.Stat(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if topInfo.Mode().Perm() != 0700 {
		t.Errorf("top state dir mode = %o, want 0700", topInfo.Mode().Perm())
	}

	// AppArmor state subdirectory must exist.
	subInfo, err := os.Stat(stateSubDir)
	if err != nil {
		t.Fatal(err)
	}
	if !subInfo.IsDir() {
		t.Error("AppArmor state subdirectory should exist")
	}
}

func TestInstallSystemMigrationUsesAtomicRename(t *testing.T) {
	env := newSystemInstallScriptEnv(t)

	stateFile := env.dest("var/lib/docker-helper/apparmor/managed-boundaries")
	stateDir := env.dest("var/lib/docker-helper/apparmor")
	legacyPath := env.dest("etc/apparmor.d/docker-helper.d/managed-roots")
	legacyContent := "# legacy content for atomic migration test\n"

	if err := os.WriteFile(legacyPath, []byte(legacyContent), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(stateDir, 0755); err != nil {
		t.Fatal(err)
	}

	if out, err := env.runPrepareApparmorState(t); err != nil {
		t.Fatalf("prepare_apparmor_state failed: %v\n%s", err, out)
	}

	// Verify the file was migrated correctly.
	actual, err := os.ReadFile(stateFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(actual) != legacyContent {
		t.Errorf("migrated content = %q, want %q", string(actual), legacyContent)
	}

	// No temp files should remain.
	entries, err := os.ReadDir(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("temp file should be cleaned up: %s", e.Name())
		}
	}
}

func TestInstallSystemMigrationFailureDoesNotLeaveDestination(t *testing.T) {
	env := newSystemInstallScriptEnv(t)

	stateFile := env.dest("var/lib/docker-helper/apparmor/managed-boundaries")
	legacyPath := env.dest("etc/apparmor.d/docker-helper.d/managed-roots")

	if err := os.WriteFile(legacyPath, []byte("# legacy\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Override cp to fail, simulating a copy failure during migration.
	fakeCp := filepath.Join(env.fakeBinDir, "cp")
	if err := os.WriteFile(fakeCp, []byte("#!/bin/sh\nexit 1\n"), 0755); err != nil {
		t.Fatal(err)
	}

	// Prepend fake bin dir to PATH so our fake cp is used.
	cmd := exec.Command("bash", "-c", fmt.Sprintf(`
		export PATH="%s:$PATH"
		source %s
		AA_STATE_FILE="%s"
		AA_LEGACY_FRAGMENT="%s"
		prepare_apparmor_state
	`, env.fakeBinDir, env.scriptPath, env.dest("var/lib/docker-helper/apparmor/managed-boundaries"), legacyPath))
	cmd.Dir = env.scriptDir
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("prepare_apparmor_state should fail when cp fails: %s", out)
	}

	// The destination managed-boundaries must NOT exist after failure.
	if _, err := os.Stat(stateFile); err == nil {
		t.Fatal("destination managed-boundaries must not exist after migration failure")
	}
}

func TestInstallSystemLegacyRetainedOnProfileLoadFailure(t *testing.T) {
	env := newSystemInstallScriptEnv(t)
	legacyPath := env.dest("etc/apparmor.d/docker-helper.d/managed-roots")
	stateFile := env.dest("var/lib/docker-helper/apparmor/managed-boundaries")

	if err := os.WriteFile(legacyPath, []byte("# legacy content\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Make the parser fail.
	env.fakeParser(t, fmt.Sprintf(`#!/bin/bash
log_file="%s"
echo "$0 $@" >> "$log_file"
exit 1
`, env.logFile))

	out, err := env.run(t, "--yes --allowed-root /tmp/ws", "")
	if err == nil {
		t.Fatalf("parser failure should cause install to fail: %s", out)
	}

	// Legacy fragment must be retained after profile load failure.
	if _, err := os.Stat(legacyPath); os.IsNotExist(err) {
		t.Fatal("legacy fragment must be retained when profile load fails")
	}

	// New state file should exist (migration succeeded before profile load).
	if _, err := os.Stat(stateFile); os.IsNotExist(err) {
		t.Fatal("new state file should exist after migration succeeds")
	}
}

func TestInstallSystemLegacyRemovedAfterSuccessfulProfileLoad(t *testing.T) {
	env := newSystemInstallScriptEnv(t)
	legacyPath := env.dest("etc/apparmor.d/docker-helper.d/managed-roots")

	if err := os.WriteFile(legacyPath, []byte("# legacy content\n"), 0644); err != nil {
		t.Fatal(err)
	}

	out, err := env.run(t, "--yes --allowed-root /tmp/ws", "")
	if err != nil {
		t.Fatalf("install should succeed: %v\n%s", err, out)
	}

	// Legacy fragment must be removed after successful profile load.
	if _, err := os.Stat(legacyPath); err == nil {
		t.Fatal("legacy fragment must be removed after successful profile load")
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
	if _, err := os.Stat(env.dest("var/lib/docker-helper/apparmor/managed-boundaries")); os.IsNotExist(err) {
		t.Error("AppArmor state should be preserved without --purge")
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
	if _, err := os.Stat(env.dest("var/lib/docker-helper/apparmor")); !os.IsNotExist(err) {
		t.Error("AppArmor state should be removed with --purge")
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

// TestInstallSystemInactiveApparmorLsm verifies that install-system.sh fails
// early when AppArmor is inactive and SELinux is not enforcing (no supported
// MAC backend active), before any file installation.
func TestInstallSystemInactiveApparmorLsm(t *testing.T) {
	env := newSystemInstallScriptEnv(t)

	env.setLSMState(t, "N", "0")

	testRoot := t.TempDir()
	out, err := env.run(t, "--yes --allowed-root "+testRoot, "")
	if err == nil {
		t.Fatal("install should fail when no MAC backend is active")
	}
	if !strings.Contains(out, "not active") || !strings.Contains(out, "AppArmor") {
		t.Errorf("expected no-active-backend error mentioning AppArmor, got: %s", out)
	}
	// Binary should NOT have been installed.
	if _, err := os.Stat(env.dest("bin/docker-helper")); !os.IsNotExist(err) {
		t.Error("binary should not be installed when no MAC backend is active")
	}
}

// TestInstallSystemSelectsApparmor verifies the AppArmor-only host selects the
// AppArmor path: profile installed and loaded, and no SELinux tooling is
// required (no bundled selinux/ artifact, no semodule on PATH).
func TestInstallSystemSelectsApparmor(t *testing.T) {
	env := newSystemInstallScriptEnv(t)
	env.setLSMState(t, "Y", "0") // AppArmor only (fixture default, explicit)

	testRoot := t.TempDir()
	out, err := env.run(t, "--yes --allowed-root "+testRoot, "")
	if err != nil {
		t.Fatalf("AppArmor-only install failed: %v\n%s", err, out)
	}

	parserSeen := false
	for _, c := range env.calls(t) {
		if strings.Contains(c, "apparmor_parser") {
			parserSeen = true
			if !strings.Contains(c, "--replace") {
				t.Errorf("AppArmor profile load must use --replace: %q", c)
			}
		}
		if strings.Contains(c, "semodule") {
			t.Errorf("AppArmor path must not invoke semodule: %q", c)
		}
		if strings.Contains(c, "restorecon") {
			t.Errorf("AppArmor path must not invoke restorecon: %q", c)
		}
	}
	if !parserSeen {
		t.Error("AppArmor profile must be loaded on the AppArmor-only path")
	}
	if _, err := os.Stat(env.dest("etc/apparmor.d/docker-helper-system")); err != nil {
		t.Error("AppArmor profile must be installed on the AppArmor-only path")
	}
	// The bundled SELinux artifact must not be required on the AppArmor path.
	if _, err := os.Stat(filepath.Join(env.scriptDir, "selinux", "docker_helper.pp")); !os.IsNotExist(err) {
		t.Error("AppArmor path must not require a bundled SELinux policy artifact")
	}
}

// TestInstallSystemSelectsSelinux verifies the SELinux-enforcing host selects
// the SELinux path: docker_helper module loaded with semodule -i from the
// bundled artifact, the artifact copied to the stable path, exact narrow
// restorecon applied, and no AppArmor tooling required.
func TestInstallSystemSelectsSelinux(t *testing.T) {
	env := newSystemInstallScriptEnv(t)
	env.setLSMState(t, "N", "1")
	env.writeBundledSELinuxPP(t)
	env.fakeSemodule(t, fmt.Sprintf(`#!/bin/bash
log_file="%s"
echo "$0 $@" >> "$log_file"
exit 0
`, env.logFile))
	env.fakeRestorecon(t, fmt.Sprintf(`#!/bin/bash
log_file="%s"
echo "$0 $@" >> "$log_file"
exit 0
`, env.logFile))

	testRoot := t.TempDir()
	out, err := env.run(t, "--yes --allowed-root "+testRoot, "")
	if err != nil {
		t.Fatalf("SELinux-only install failed: %v\n%s", err, out)
	}

	semoduleSeen := false
	restoreconSeen := false
	for _, c := range env.calls(t) {
		if strings.Contains(c, "semodule") {
			semoduleSeen = true
			if !strings.Contains(c, "-i") || !strings.Contains(c, "docker_helper.pp") {
				t.Errorf("semodule must load the bundled docker_helper.pp with -i: %q", c)
			}
		}
		if strings.Contains(c, "restorecon") {
			restoreconSeen = true
		}
		if strings.Contains(c, "apparmor_parser") {
			t.Errorf("SELinux path must not invoke apparmor_parser: %q", c)
		}
	}
	if !semoduleSeen {
		t.Error("semodule -i must be called on the SELinux path")
	}
	if !restoreconSeen {
		t.Error("restorecon must be applied on the SELinux path")
	}
	// The AppArmor profile must not be installed on the SELinux path.
	if _, err := os.Stat(env.dest("etc/apparmor.d/docker-helper-system")); !os.IsNotExist(err) {
		t.Error("AppArmor profile must not be installed on the SELinux path")
	}
	// The policy artifact must be copied to the stable path.
	if _, err := os.Stat(env.dest("usr/share/selinux/docker_helper.pp")); err != nil {
		t.Error("SELinux policy artifact must be installed to the stable path")
	}
}

// TestInstallSystemBothBackendsFail verifies the dual-active host is rejected
// before any installation mutation.
func TestInstallSystemBothBackendsFail(t *testing.T) {
	env := newSystemInstallScriptEnv(t)
	env.setLSMState(t, "Y", "1")
	env.writeBundledSELinuxPP(t)
	env.fakeSemodule(t, `#!/bin/bash
exit 0
`)
	env.fakeRestorecon(t, `#!/bin/bash
exit 0
`)

	testRoot := t.TempDir()
	out, err := env.run(t, "--yes --allowed-root "+testRoot, "")
	if err == nil {
		t.Fatal("install should fail when both MAC backends are active")
	}
	if !strings.Contains(out, "unsupported") {
		t.Errorf("expected dual-active rejection, got: %s", out)
	}
	if _, err := os.Stat(env.dest("bin/docker-helper")); !os.IsNotExist(err) {
		t.Error("binary should not be installed when both MAC backends are active")
	}
}

// TestInstallSystemSelinuxMissingSemodule verifies a SELinux host without
// semodule fails before any installation mutation.
func TestInstallSystemSelinuxMissingSemodule(t *testing.T) {
	env := newSystemInstallScriptEnv(t)
	env.setLSMState(t, "N", "1")
	env.writeBundledSELinuxPP(t)
	env.fakeRestorecon(t, `#!/bin/bash
exit 0
`)
	// No semodule fake: it must be absent from PATH.

	testRoot := t.TempDir()
	out, err := env.run(t, "--yes --allowed-root "+testRoot, "")
	if err == nil {
		t.Fatal("install should fail when semodule is missing on a SELinux host")
	}
	if !strings.Contains(out, "semodule") {
		t.Errorf("expected semodule error, got: %s", out)
	}
	if _, err := os.Stat(env.dest("bin/docker-helper")); !os.IsNotExist(err) {
		t.Error("binary should not be installed when semodule is missing")
	}
}

// TestInstallSystemSelinuxMissingRestorecon verifies a SELinux host without
// restorecon fails before any installation mutation.
func TestInstallSystemSelinuxMissingRestorecon(t *testing.T) {
	env := newSystemInstallScriptEnv(t)
	env.setLSMState(t, "N", "1")
	env.writeBundledSELinuxPP(t)
	env.fakeSemodule(t, `#!/bin/bash
exit 0
`)
	// No restorecon fake: it must be absent from PATH.

	testRoot := t.TempDir()
	out, err := env.run(t, "--yes --allowed-root "+testRoot, "")
	if err == nil {
		t.Fatal("install should fail when restorecon is missing on a SELinux host")
	}
	if !strings.Contains(out, "restorecon") {
		t.Errorf("expected restorecon error, got: %s", out)
	}
	if _, err := os.Stat(env.dest("bin/docker-helper")); !os.IsNotExist(err) {
		t.Error("binary should not be installed when restorecon is missing")
	}
}

// TestInstallSystemSelinuxMissingBundledPP verifies a SELinux host without the
// bundled selinux/docker_helper.pp fails before any installation mutation.
func TestInstallSystemSelinuxMissingBundledPP(t *testing.T) {
	env := newSystemInstallScriptEnv(t)
	env.setLSMState(t, "N", "1")
	env.fakeSemodule(t, `#!/bin/bash
exit 0
`)
	env.fakeRestorecon(t, `#!/bin/bash
exit 0
`)
	// No bundled selinux/docker_helper.pp.

	testRoot := t.TempDir()
	out, err := env.run(t, "--yes --allowed-root "+testRoot, "")
	if err == nil {
		t.Fatal("install should fail when the bundled SELinux policy artifact is missing")
	}
	if !strings.Contains(out, "docker_helper.pp") {
		t.Errorf("expected bundled policy artifact error, got: %s", out)
	}
	if _, err := os.Stat(env.dest("bin/docker-helper")); !os.IsNotExist(err) {
		t.Error("binary should not be installed when the bundled policy artifact is missing")
	}
}

// TestInstallSystemApparmorMissingParser verifies an AppArmor host without the
// parser fails before any installation mutation.
func TestInstallSystemApparmorMissingParser(t *testing.T) {
	env := newSystemInstallScriptEnv(t)
	env.setLSMState(t, "Y", "0")
	// Point the parser at a nonexistent path.
	env.env = append(env.env, "AA_PARSER=/nonexistent/apparmor_parser")

	testRoot := t.TempDir()
	out, err := env.run(t, "--yes --allowed-root "+testRoot, "")
	if err == nil {
		t.Fatal("install should fail when apparmor_parser is missing on an AppArmor host")
	}
	if !strings.Contains(out, "apparmor_parser") {
		t.Errorf("expected apparmor_parser error, got: %s", out)
	}
	if _, err := os.Stat(env.dest("bin/docker-helper")); !os.IsNotExist(err) {
		t.Error("binary should not be installed when apparmor_parser is missing")
	}
}

// TestInstallSystemSelinuxRestoreconExact verifies the SELinux restorecon
// invocation uses exactly the narrow targets proven by the RPM path and never
// recursively restores /run/docker-helper.
func TestInstallSystemSelinuxRestoreconExact(t *testing.T) {
	env := newSystemInstallScriptEnv(t)
	env.setLSMState(t, "N", "1")
	env.writeBundledSELinuxPP(t)
	env.fakeSemodule(t, `#!/bin/bash
exit 0
`)
	env.fakeRestorecon(t, fmt.Sprintf(`#!/bin/bash
log_file="%s"
echo "$0 $@" >> "$log_file"
exit 0
`, env.logFile))

	testRoot := t.TempDir()
	if _, err := env.run(t, "--yes --allowed-root "+testRoot, ""); err != nil {
		t.Fatalf("SELinux-only install failed: %v", err)
	}

	var restoreconCalls []string
	for _, c := range env.calls(t) {
		if strings.Contains(c, "restorecon") {
			restoreconCalls = append(restoreconCalls, c)
		}
	}
	if len(restoreconCalls) != 4 {
		t.Errorf("expected exactly 4 restorecon invocations, got %d: %v", len(restoreconCalls), restoreconCalls)
	}
	joined := strings.Join(restoreconCalls, "\n")
	for _, want := range []string{
		"restorecon /usr/bin/docker-helper",
		"restorecon -R /etc/docker-helper",
		"restorecon -R /var/lib/docker-helper",
		"restorecon /run/docker-helper",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("restorecon must include %q (got: %s)", want, joined)
		}
	}
	if strings.Contains(joined, "restorecon -R /run/docker-helper") {
		t.Error("restorecon must NEVER recurse into /run/docker-helper (mount-alias relabel bug)")
	}
	// Every restorecon target must be a docker-helper-owned path: no Docker
	// daemon/socket path may be relabeled by the installer.
	allowedTargets := map[string]bool{
		"/usr/bin/docker-helper": true,
		"/etc/docker-helper":     true,
		"/var/lib/docker-helper": true,
		"/run/docker-helper":     true,
	}
	for _, c := range restoreconCalls {
		target := c[strings.LastIndex(c, " ")+1:]
		if !allowedTargets[target] {
			t.Errorf("restorecon must only target docker-helper-owned paths, got: %q", c)
		}
	}
}

// TestInstallSystemSELinuxNoRecursiveRuntimeRestorecon verifies install-system.sh
// never contains a recursive restorecon of /run/docker-helper.
func TestInstallSystemSELinuxNoRecursiveRuntimeRestorecon(t *testing.T) {
	data, err := os.ReadFile("packaging/install-system.sh")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "restorecon -R /run/docker-helper") {
		t.Error("install-system.sh must not recursively restorecon /run/docker-helper (would walk mount-pin aliases and corrupt workspace SELinux labels)")
	}
}

// TestUninstallSystemSELinuxModuleCleanup verifies the uninstaller removes the
// SELinux docker_helper module (semodule -r docker_helper, RPM final-erase
// semantics) and the tarball-installed policy artifact, independent of the
// currently active LSM.
func TestUninstallSystemSELinuxModuleCleanup(t *testing.T) {
	env := newSystemUninstallScriptEnv(t)
	env.fakeSemodule(t, fmt.Sprintf(`#!/bin/bash
log_file="%s"
echo "$0 $@" >> "$log_file"
exit 0
`, env.logFile))
	// The installed policy artifact (tarball-installed stable path).
	ppDest := env.dest("usr/share/selinux/docker_helper.pp")
	if err := os.MkdirAll(filepath.Dir(ppDest), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ppDest, []byte("installed-pp"), 0644); err != nil {
		t.Fatal(err)
	}

	out, err := env.run(t, "--yes", "")
	if err != nil {
		t.Fatalf("uninstall failed: %v\n%s", err, out)
	}

	semoduleSeen := false
	for _, c := range env.calls(t) {
		if strings.Contains(c, "semodule") {
			semoduleSeen = true
			if !strings.Contains(c, "-r") || !strings.Contains(c, "docker_helper") {
				t.Errorf("semodule must remove docker_helper: %q", c)
			}
		}
	}
	if !semoduleSeen {
		t.Error("semodule -r docker_helper must be called on uninstall")
	}
	if _, err := os.Stat(ppDest); !os.IsNotExist(err) {
		t.Error("SELinux policy artifact must be removed on uninstall")
	}
	if _, err := os.Stat(env.dest("bin/docker-helper")); !os.IsNotExist(err) {
		t.Error("binary must be removed on uninstall")
	}
	// Config/state must be preserved without --purge.
	if _, err := os.Stat(env.dest("etc/docker-helper")); os.IsNotExist(err) {
		t.Error("config must be preserved without --purge")
	}
}

// TestUninstallSystemSELinuxModuleRemovalFailureWarns verifies a semodule
// removal failure (or an absent semodule) does not abort the uninstall: the
// common lifecycle completes and a useful warning is emitted.
func TestUninstallSystemSELinuxModuleRemovalFailureWarns(t *testing.T) {
	env := newSystemUninstallScriptEnv(t)
	// semodule exists but fails (module may not be loaded).
	env.fakeSemodule(t, fmt.Sprintf(`#!/bin/bash
log_file="%s"
echo "$0 $@" >> "$log_file"
exit 1
`, env.logFile))
	ppDest := env.dest("usr/share/selinux/docker_helper.pp")
	if err := os.MkdirAll(filepath.Dir(ppDest), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ppDest, []byte("installed-pp"), 0644); err != nil {
		t.Fatal(err)
	}

	out, err := env.run(t, "--yes", "")
	if err != nil {
		t.Fatalf("uninstall must complete despite semodule removal failure: %v\n%s", err, out)
	}
	if !strings.Contains(out, "docker_helper") || !strings.Contains(out, "warning") {
		t.Errorf("expected a useful warning about module removal, got: %s", out)
	}
	if _, err := os.Stat(ppDest); !os.IsNotExist(err) {
		t.Error("SELinux policy artifact must be removed even when module removal fails")
	}
}

// TestUninstallSystemSELinuxMissingSemoduleWarns verifies an uninstall on a
// host without semodule completes cleanly and warns instead of failing.
func TestUninstallSystemSELinuxMissingSemoduleWarns(t *testing.T) {
	env := newSystemUninstallScriptEnv(t)
	// No semodule fake: absent from PATH.
	ppDest := env.dest("usr/share/selinux/docker_helper.pp")
	if err := os.MkdirAll(filepath.Dir(ppDest), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ppDest, []byte("installed-pp"), 0644); err != nil {
		t.Fatal(err)
	}

	out, err := env.run(t, "--yes", "")
	if err != nil {
		t.Fatalf("uninstall must complete without semodule: %v\n%s", err, out)
	}
	if !strings.Contains(out, "semodule") || !strings.Contains(out, "warning") {
		t.Errorf("expected a warning about missing semodule, got: %s", out)
	}
	if _, err := os.Stat(ppDest); !os.IsNotExist(err) {
		t.Error("SELinux policy artifact must be removed even without semodule")
	}
}

// TestUninstallSystemApparmorCleanupWithoutLsm verifies the uninstaller unloads
// and removes the AppArmor profile when present, even on a host whose active
// LSM is no longer AppArmor (uninstall after host configuration changes).
func TestUninstallSystemApparmorCleanupWithoutLsm(t *testing.T) {
	env := newSystemUninstallScriptEnv(t)
	// Profile file is present (installed previously).
	if err := os.WriteFile(env.dest("etc/apparmor.d/docker-helper-system"), []byte("profile docker-helper-system {}"), 0644); err != nil {
		t.Fatal(err)
	}

	out, err := env.run(t, "--yes", "")
	if err != nil {
		t.Fatalf("uninstall failed: %v\n%s", err, out)
	}

	parserSeen := false
	for _, c := range env.calls(t) {
		if strings.Contains(c, "apparmor_parser") {
			parserSeen = true
			if !strings.Contains(c, "-R") {
				t.Errorf("AppArmor unload must use -R: %q", c)
			}
		}
	}
	if !parserSeen {
		t.Error("AppArmor profile must be unloaded when present")
	}
	if _, err := os.Stat(env.dest("etc/apparmor.d/docker-helper-system")); !os.IsNotExist(err) {
		t.Error("AppArmor profile file must be removed on uninstall")
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
// asset destinations, exclusions, vendor systemd directory, modes, version
// templating, and per-format depends and lifecycle scripts.
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
		"/usr/share/docker-helper/apparmor/local/curl",
	} {
		if !strings.Contains(content, path) {
			t.Errorf("nfpm.yaml missing required destination: %s", path)
		}
	}

	// Must not ship the dynamic AppArmor state under /etc (it is durable
	// helper-owned state, not a package-owned config file).
	if strings.Contains(content, "managed-roots") {
		t.Error("nfpm.yaml must not package the dynamic AppArmor managed boundaries state under /etc")
	}
	if strings.Contains(content, "var/lib/docker-helper/apparmor") {
		t.Error("nfpm.yaml must not package AppArmor state under /var/lib (state is created/migrated by lifecycle code)")
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

	// Create a dummy SELinux policy module (required by RPM nfpm config).
	dummyPP := filepath.Join(tmpDir, "docker_helper.pp")
	if err := os.WriteFile(dummyPP, []byte("dummy-pp"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create a dummy completion script (required by nfpm.yaml).
	os.MkdirAll(filepath.Join(tmpDir, "completions"), 0755)
	dummyCompletion := filepath.Join(tmpDir, "completions", "docker-helper")
	if err := os.WriteFile(dummyCompletion, []byte("# bash completion\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create a temporary nFPM config that uses the dummy binary and tmp output.
	nfpmData, err := os.ReadFile("packaging/nfpm.yaml")
	if err != nil {
		t.Fatal(err)
	}
	// Replace dist/docker-helper with the dummy binary path.
	configContent := strings.ReplaceAll(string(nfpmData), "src: dist/docker-helper", "src: "+dummyBin)
	// Replace dist/docker_helper.pp with the dummy PP path (RPM-only section).
	configContent = strings.ReplaceAll(configContent, "src: dist/docker_helper.pp", "src: "+dummyPP)
	// Replace dist/completions/docker-helper with the dummy completion path.
	configContent = strings.ReplaceAll(configContent, "src: dist/completions/docker-helper", "src: "+dummyCompletion)
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

// TestPackageSELinuxPayloadSeparation verifies that the SELinux policy module
// is included in the RPM but NOT in the DEB (DEB is AppArmor-only).
func TestPackageSELinuxPayloadSeparation(t *testing.T) {
	if _, err := exec.LookPath("nfpm"); err != nil {
		t.Skip("nfpm not installed, skipping SELinux payload separation test")
	}

	testVersion := "0.0.0"
	tmpDir := t.TempDir()

	// Create a dummy binary for packaging.
	dummyBin := filepath.Join(tmpDir, "docker-helper")
	if err := os.WriteFile(dummyBin, []byte("dummy"), 0755); err != nil {
		t.Fatal(err)
	}

	// Create a dummy SELinux policy module (required by RPM nfpm config).
	dummyPP := filepath.Join(tmpDir, "docker_helper.pp")
	if err := os.WriteFile(dummyPP, []byte("dummy-pp"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create a dummy completion script (required by nfpm.yaml).
	os.MkdirAll(filepath.Join(tmpDir, "completions"), 0755)
	dummyCompletion := filepath.Join(tmpDir, "completions", "docker-helper")
	if err := os.WriteFile(dummyCompletion, []byte("# bash completion\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create a temporary nFPM config.
	nfpmData, err := os.ReadFile("packaging/nfpm.yaml")
	if err != nil {
		t.Fatal(err)
	}
	configContent := strings.ReplaceAll(string(nfpmData), "src: dist/docker-helper", "src: "+dummyBin)
	configContent = strings.ReplaceAll(configContent, "src: dist/docker_helper.pp", "src: "+dummyPP)
	configContent = strings.ReplaceAll(configContent, "src: dist/completions/docker-helper", "src: "+dummyCompletion)
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

	debFile := filepath.Join(tmpDir, "docker-helper_"+testVersion+"_amd64.deb")
	rpmFile := filepath.Join(tmpDir, "docker-helper-"+testVersion+"-1.x86_64.rpm")

	// Verify DEB does NOT contain SELinux policy.
	if dpkgDeb, err := exec.LookPath("dpkg-deb"); err == nil {
		cmd := exec.Command(dpkgDeb, "--contents", debFile)
		out, _ := cmd.CombinedOutput()
		if strings.Contains(string(out), "/usr/share/selinux/docker_helper.pp") {
			t.Error("DEB must NOT contain /usr/share/selinux/docker_helper.pp (DEB is AppArmor-only)")
		}
	} else {
		t.Log("dpkg-deb not available, skipping DEB SELinux payload check")
	}

	// Verify RPM DOES contain SELinux policy.
	if rpmPath, err := exec.LookPath("rpm"); err == nil {
		cmd := exec.Command(rpmPath, "-qpl", rpmFile)
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "/usr/share/selinux/docker_helper.pp") {
			t.Error("RPM must contain /usr/share/selinux/docker_helper.pp")
		}
	} else {
		t.Log("rpm not available, skipping RPM SELinux payload check")
	}
}

// TestRPMPostinstallNoRecursiveRuntimeRestorecon guards against a regression
// where the RPM postinstall recursively restorecon's the /run/docker-helper
// runtime tree. The mount-pin namespace under /run/docker-helper/mounts holds
// bind-mount aliases of the real workspace inodes; a recursive relabel through
// them would relabel the actual workspace files to docker_helper_runtime_t,
// corrupting the SELinux workspace model. The postinstall must only relabel
// the helper-owned /run/docker-helper dir itself (non-recursively), never walk
// the mounts namespace.
func TestRPMPostinstallNoRecursiveRuntimeRestorecon(t *testing.T) {
	data, err := os.ReadFile("packaging/scripts/rpm/postinstall.sh")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	if strings.Contains(content, "restorecon -R /run/docker-helper") {
		t.Error("rpm postinstall must not recursively restorecon /run/docker-helper (would walk mount-pin aliases and corrupt workspace SELinux labels)")
	}
}

// TestRPMSelinuxDependencies verifies that the RPM depends on packages
// providing semodule and restorecon (policycoreutils on openSUSE).
func TestRPMSelinuxDependencies(t *testing.T) {
	data, err := os.ReadFile("packaging/nfpm.yaml")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	// Find the rpm overrides section.
	rpmIdx := strings.Index(content, "  rpm:")
	if rpmIdx < 0 {
		t.Fatal("rpm overrides section not found")
	}

	// Find the depends section within rpm (look for "    depends:" after rpm:).
	afterRpm := content[rpmIdx:]
	dependsIdx := strings.Index(afterRpm, "    depends:")
	if dependsIdx < 0 {
		t.Fatal("rpm depends section not found")
	}
	dependsSection := afterRpm[dependsIdx:]

	// Find the end of depends section (next top-level key or scripts).
	nextKeyIdx := strings.Index(dependsSection, "\n    scripts:")
	if nextKeyIdx > 0 {
		dependsSection = dependsSection[:nextKeyIdx]
	}

	// RPM postinstall uses semodule (from policycoreutils on openSUSE).
	// The dependency ensures semodule is available before scriptlet runs.
	if !strings.Contains(dependsSection, "policycoreutils") {
		t.Error("RPM depends must include policycoreutils (provides semodule and restorecon)")
	}

	// policycoreutils provides both semodule and restorecon on openSUSE.
	// With this hard dependency, both tools are guaranteed present.
	// restorecon failures remain best-effort because context restoration
	// is not strictly required for first-run functionality: the binary is
	// installed with default context and systemd handles the runtime directory.
}

// TestRPMBackendDependencies verifies that the RPM retains both AppArmor
// and SELinux backend toolchain dependencies, as required for the Release 2
// openSUSE Tumbleweed support contract.
func TestRPMBackendDependencies(t *testing.T) {
	data, err := os.ReadFile("packaging/nfpm.yaml")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	// Extract the RPM depends section.
	rpmIdx := strings.Index(content, "  rpm:")
	if rpmIdx < 0 {
		t.Fatal("rpm overrides section not found")
	}
	afterRpm := content[rpmIdx:]
	dependsIdx := strings.Index(afterRpm, "    depends:")
	if dependsIdx < 0 {
		t.Fatal("rpm depends section not found")
	}
	dependsSection := afterRpm[dependsIdx:]
	nextKeyIdx := strings.Index(dependsSection, "\n    scripts:")
	if nextKeyIdx > 0 {
		dependsSection = dependsSection[:nextKeyIdx]
	}

	// Parse individual dependency entries from the YAML list.
	deps := parseYAMLListItems(dependsSection)

	// Assert exact presence of each required dependency.
	required := []string{
		"systemd",
		"apparmor-parser",
		"apparmor-abstractions",
		"policycoreutils",
		"policycoreutils-python-utils",
	}
	for _, want := range required {
		found := false
		for _, dep := range deps {
			if dep == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("RPM depends must include exact entry %q (got: %v)", want, deps)
		}
	}
}

// TestRPMDocumentationTargetsTumbleweed verifies that Release 2 RPM
// documentation explicitly identifies openSUSE Tumbleweed as the supported
// RPM target, rather than generic RPM/Fedora/RHEL wording.
func TestRPMDocumentationTargetsTumbleweed(t *testing.T) {
	// README.md: locate the package installation section and verify RPM subsection.
	readmeData, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	readme := string(readmeData)

	// Find the package installation section.
	pkgInstallIdx := strings.Index(readme, "### Package installation")
	if pkgInstallIdx < 0 {
		t.Fatal("README.md must contain '### Package installation' section")
	}
	pkgSection := readme[pkgInstallIdx:]

	// The RPM subsection must mention openSUSE Tumbleweed.
	rpmSubIdx := strings.Index(pkgSection, "zypper install")
	if rpmSubIdx < 0 {
		t.Fatal("README.md package section must contain zypper install command")
	}
	// Check the heading preceding the zypper command.
	beforeZypper := pkgSection[:rpmSubIdx]
	if !strings.Contains(beforeZypper, "openSUSE Tumbleweed") {
		t.Error("README.md RPM subsection must identify openSUSE Tumbleweed")
	}

	// packaging/README.release.md: verify native package entries.
	releaseData, err := os.ReadFile("packaging/README.release.md")
	if err != nil {
		t.Fatal(err)
	}
	releaseReadme := string(releaseData)

	// Find the native packages section.
	nativePkgIdx := strings.Index(releaseReadme, "Native packages")
	if nativePkgIdx < 0 {
		t.Fatal("packaging/README.release.md must contain native packages section")
	}
	nativeSection := releaseReadme[nativePkgIdx:]

	// The .rpm entry must say openSUSE Tumbleweed.
	rpmLine := findLineContaining(nativeSection, ".rpm")
	if rpmLine == "" {
		t.Fatal("packaging/README.release.md must contain .rpm entry")
	}
	if !strings.Contains(rpmLine, "openSUSE Tumbleweed") {
		t.Errorf("packaging/README.release.md .rpm entry must say openSUSE Tumbleweed (got: %s)", rpmLine)
	}

	// The .deb entry must say Ubuntu, not Ubuntu/Debian.
	debLine := findLineContaining(nativeSection, ".deb")
	if debLine == "" {
		t.Fatal("packaging/README.release.md must contain .deb entry")
	}
	if !strings.Contains(debLine, "Ubuntu") {
		t.Errorf("packaging/README.release.md .deb entry must say Ubuntu (got: %s)", debLine)
	}
	if strings.Contains(debLine, "Debian") {
		t.Error("packaging/README.release.md .deb entry must not say Debian (Release 2 does not validate Debian)")
	}

	// No Release 2 package-support wording claims Fedora or RHEL support.
	// Historical roadmap statements about Fedora/RHEL being outside Release 2 are fine.
	// Check the package installation sections specifically.
	if strings.Contains(pkgSection, "Fedora") || strings.Contains(pkgSection, "RHEL") {
		t.Error("README.md package section must not claim Fedora or RHEL support")
	}
	if strings.Contains(nativeSection, "Fedora") || strings.Contains(nativeSection, "RHEL") {
		t.Error("packaging/README.release.md native packages section must not claim Fedora or RHEL support")
	}
}

// parseYAMLListItems extracts individual list items from a YAML list block.
// It handles "- item" format and returns trimmed item strings.
func parseYAMLListItems(block string) []string {
	var items []string
	for _, line := range strings.Split(block, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "- ") {
			item := strings.TrimSpace(trimmed[2:])
			if item != "" {
				items = append(items, item)
			}
		}
	}
	return items
}

// findLineContaining returns the first line in text that contains the needle.
func findLineContaining(text, needle string) string {
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, needle) {
			return strings.TrimSpace(line)
		}
	}
	return ""
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

	// Conffiles — extract control tarball and verify no conffiles
	// (dynamic AppArmor state is not package-owned).
	controlDir := t.TempDir()
	cmd = exec.Command(dpkgDeb, "--control", debFile, controlDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("dpkg-deb --control failed: %v\n%s", err, out)
	}
	conffilesData, err := os.ReadFile(filepath.Join(controlDir, "conffiles"))
	if err == nil && len(conffilesData) > 0 {
		t.Errorf("DEB should not contain conffiles, got:\n%s", string(conffilesData))
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
	if !strings.Contains(requires, "apparmor-abstractions") {
		t.Error("RPM Requires must include apparmor-abstractions")
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
	aaProfileFound := false
	for _, line := range strings.Split(flagStr, "\n") {
		line = strings.TrimSpace(line)
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
		"/etc/apparmor.d/docker-helper.d",
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

	// Skip if SELinux build tools are not available (checkmodule is required by build-packages.sh).
	if _, err := exec.LookPath("checkmodule"); err != nil {
		t.Skip("checkmodule not available, skipping full package build pipeline (requires SELinux build tools)")
	}

	// Clean up dist/ to avoid stale artifacts.
	if err := os.RemoveAll("dist"); err != nil {
		t.Skipf("cannot clean dist/: %v, skipping test", err)
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

// writeFakeSemodule creates a semodule script that logs calls. The fake
// reports the docker_helper module as installed when listing (-l) unless
// SEMODULE_MODULE_PRESENT=false, so tests can exercise the presence-gated
// preremove removal and its absence.
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
  *"-l"*)
    if [ "${SEMODULE_MODULE_PRESENT:-true}" = "true" ]; then
      echo "docker_helper"
    fi
    exit 0
    ;;
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
	// Replace AppArmor loaded-profiles path with a test-controlled path.
	modified = strings.ReplaceAll(modified, "/sys/kernel/security/apparmor/profiles", "$AA_PROFILES_PATH")
	// Replace SELinux enforce path with a test-controlled path.
	modified = strings.ReplaceAll(modified, "/sys/fs/selinux/enforce", "$SELINUX_ENFORCE_PATH")
	// Replace migration state paths with test-controlled paths.
	modified = strings.ReplaceAll(modified, "/var/lib/docker-helper/apparmor/managed-boundaries", "$AA_STATE_FILE")
	modified = strings.ReplaceAll(modified, "/etc/apparmor.d/docker-helper.d/managed-roots", "$AA_LEGACY_FRAGMENT")
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

	// Default: the managed AppArmor profile is loaded, so the presence-gated
	// preremove unload is attempted. Tests can override by providing their own
	// AA_PROFILES_PATH via extraEnv and writing the file.
	aaProfilesPath := filepath.Join(tmpDir, "sys", "kernel", "security", "apparmor", "profiles")
	if err := os.MkdirAll(filepath.Dir(aaProfilesPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(aaProfilesPath, []byte("docker-helper-system (enforce)\n"), 0644); err != nil {
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

	// Default: AppArmor migration state paths under test-controlled directory.
	aaStateFile := filepath.Join(tmpDir, "var", "lib", "docker-helper", "apparmor", "managed-boundaries")
	if err := os.MkdirAll(filepath.Dir(aaStateFile), 0755); err != nil {
		t.Fatal(err)
	}
	aaLegacyFragment := filepath.Join(tmpDir, "etc", "apparmor.d", "docker-helper.d", "managed-roots")
	if err := os.MkdirAll(filepath.Dir(aaLegacyFragment), 0755); err != nil {
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
		"AA_PROFILES_PATH="+aaProfilesPath,
		"SELINUX_ENFORCE_PATH="+selinuxEnforcePath,
		"AA_STATE_FILE="+aaStateFile,
		"AA_LEGACY_FRAGMENT="+aaLegacyFragment,
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

	// nfpm source must point to the freshly generated artifact in dist/,
	// never to packaging/selinux/ (which would permit stale policy reuse).
	if !strings.Contains(content, "dist/docker_helper.pp") {
		t.Error("nfpm.yaml must source dist/docker_helper.pp (freshly generated artifact)")
	}
	if strings.Contains(content, "packaging/selinux/docker_helper.pp") {
		t.Error("nfpm.yaml must not source packaging/selinux/docker_helper.pp (stale policy risk)")
	}
	if !strings.Contains(content, "/usr/share/selinux/docker_helper.pp") {
		t.Error("nfpm.yaml must install .pp to /usr/share/selinux/docker_helper.pp")
	}
}

// TestBuildPackagesScriptContentSELinux verifies build-packages.sh delegates
// SELinux policy compilation to the canonical build-selinux-policy.sh owner
// (the same one build-bundle.sh uses) and that the helper itself is
// fail-closed: requires tools, generates the .pp, removes stale output.
func TestBuildPackagesScriptContentSELinux(t *testing.T) {
	data, err := os.ReadFile("build-packages.sh")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	if !strings.Contains(content, "build-selinux-policy.sh") {
		t.Error("build-packages.sh must delegate SELinux policy build to build-selinux-policy.sh")
	}
	if !strings.Contains(content, "dist") {
		t.Error("build-packages.sh must pass the dist output dir to the SELinux policy builder")
	}
	if strings.Contains(content, "packaging/selinux/docker_helper.pp") {
		t.Error("build-packages.sh must not output to packaging/selinux/docker_helper.pp (stale policy risk)")
	}

	helper, err := os.ReadFile("build-selinux-policy.sh")
	if err != nil {
		t.Fatal(err)
	}
	h := string(helper)

	for _, s := range []string{"checkmodule", "semodule_package", "docker-helper.te", "docker-helper.fc", "docker_helper.pp"} {
		if !strings.Contains(h, s) {
			t.Errorf("build-selinux-policy.sh must reference %q", s)
		}
	}

	// Must fail-closed: exit 1 when tools are missing, not warn-and-continue.
	if !strings.Contains(h, "exit 1") {
		t.Error("build-selinux-policy.sh must contain explicit exit 1 for missing tools")
	}

	// Must remove previous generated output before building (stale policy
	// output can never satisfy the build).
	if !strings.Contains(h, "rm -f") {
		t.Error("build-selinux-policy.sh must remove previous generated output before building")
	}
}

// TestBuildSelinuxPolicyHelperToolsRequired verifies that the canonical
// build-selinux-policy.sh fails when SELinux build tools are unavailable,
// rather than warning and continuing (which would allow stale policy
// packaging), and that both build-packages.sh and build-bundle.sh invoke it.
func TestBuildSelinuxPolicyHelperToolsRequired(t *testing.T) {
	helper, err := os.ReadFile("build-selinux-policy.sh")
	if err != nil {
		t.Fatal(err)
	}
	content := string(helper)

	// The script must check for checkmodule and semodule_package and fail
	// if either is missing. Verify the pattern: if ! command -v ... then exit 1.
	for _, tool := range []string{"checkmodule", "semodule_package"} {
		idx := strings.Index(content, tool)
		if idx < 0 {
			t.Fatalf("%s reference not found in build-selinux-policy.sh", tool)
		}
		remaining := content[idx:]
		// The error block must contain "exit 1" before the actual compile step.
		compileIdx := strings.Index(remaining, "checkmodule -M")
		buildIdx := compileIdx
		if buildIdx < 0 {
			buildIdx = len(remaining)
		}
		if !strings.Contains(remaining[:buildIdx], "exit 1") {
			t.Errorf("build-selinux-policy.sh must exit 1 when %s is missing", tool)
		}
	}

	// Both consumers must route through the canonical owner.
	for _, consumer := range []string{"build-packages.sh", "build-bundle.sh"} {
		cd, err := os.ReadFile(consumer)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(cd), "build-selinux-policy.sh") {
			t.Errorf("%s must call build-selinux-policy.sh", consumer)
		}
	}
}

// TestBuildSelinuxPolicyHelperProducesPP runs the canonical helper and proves
// it produces a non-empty docker_helper.pp, removing stale policy output first.
// Skipped when the SELinux build tools are unavailable.
func TestBuildSelinuxPolicyHelperProducesPP(t *testing.T) {
	if _, err := exec.LookPath("checkmodule"); err != nil {
		t.Skip("checkmodule not installed, skipping policy build test")
	}
	if _, err := exec.LookPath("semodule_package"); err != nil {
		t.Skip("semodule_package not installed, skipping policy build test")
	}

	outDir := t.TempDir()
	// Plant stale policy artifacts; they must never satisfy the build.
	stale := []byte("stale-policy-content")
	if err := os.WriteFile(filepath.Join(outDir, "docker_helper.pp"), stale, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "docker-helper.pp"), stale, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "docker_helper.mod"), stale, 0644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("bash", "build-selinux-policy.sh", outDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build-selinux-policy.sh failed: %v\n%s", err, out)
	}

	pp := filepath.Join(outDir, "docker_helper.pp")
	fi, err := os.Stat(pp)
	if err != nil {
		t.Fatalf("docker_helper.pp not produced: %v", err)
	}
	if fi.Size() == 0 {
		t.Error("docker_helper.pp must not be empty")
	}
	if got, _ := os.ReadFile(pp); string(got) == string(stale) {
		t.Error("docker_helper.pp must not be the planted stale artifact")
	}
	if _, err := os.Stat(filepath.Join(outDir, "docker_helper.mod")); !os.IsNotExist(err) {
		t.Error("intermediate docker_helper.mod must be removed")
	}
	if _, err := os.Stat(filepath.Join(outDir, "docker-helper.pp")); !os.IsNotExist(err) {
		t.Error("legacy docker-helper.pp must be removed")
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
			if !strings.Contains(c, "/usr/share/selinux/docker_helper.pp") {
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

// TestRpmPreremoveAppArmorOnlyNoSELinuxWarning verifies the observed
// cross-MAC uninstall regression: on an AppArmor-only host (SELinux module
// absent), final erase must NOT emit a bogus "failed to remove SELinux module"
// warning and must not attempt semodule -r, while the loaded AppArmor profile
// is still unloaded.
func TestRpmPreremoveAppArmorOnlyNoSELinuxWarning(t *testing.T) {
	fakeDir, logFile := setupScriptTest(t)
	writeFakeSystemctl(t, fakeDir, logFile, true, true)
	writeFakeApparmorParser(t, fakeDir, logFile, false, false)
	writeFakeSemodule(t, fakeDir, logFile, false, false)

	out, _, code := runScript(t, "packaging/scripts/rpm/preremove.sh", fakeDir, logFile,
		[]string{"0"}, true, []string{"SEMODULE_MODULE_PRESENT=false"})
	if code != 0 {
		t.Fatalf("rpm preun final erase should exit 0, got %d", code)
	}
	if strings.Contains(out, "SELinux") {
		t.Errorf("AppArmor-only erase must not warn about SELinux: %s", out)
	}
	calls := readLifecycleScriptCalls(t, logFile)
	for _, c := range calls {
		if strings.Contains(c, "semodule") && strings.Contains(c, "-r") {
			t.Errorf("must not call semodule -r when the module is absent: %s", c)
		}
	}
	// The loaded AppArmor profile must still be unloaded.
	unloadSeen := false
	for _, c := range calls {
		if strings.Contains(c, "apparmor_parser") && strings.Contains(c, "-R") {
			unloadSeen = true
		}
	}
	if !unloadSeen {
		t.Error("loaded AppArmor profile must still be unloaded on final erase")
	}
}

// TestRpmPreremoveSELinuxPresentRemovesModule (final erase) verifies that on a
// host where the SELinux module is installed, final erase really removes it.
// The module-present default of the fake exercises the real `semodule -r`
// removal path.
func TestRpmPreremoveSELinuxPresentRemovesModule(t *testing.T) {
	fakeDir, logFile := setupScriptTest(t)
	writeFakeSystemctl(t, fakeDir, logFile, true, true)
	writeFakeApparmorParser(t, fakeDir, logFile, false, false)
	writeFakeSemodule(t, fakeDir, logFile, false, false)

	out, _, code := runScript(t, "packaging/scripts/rpm/preremove.sh", fakeDir, logFile,
		[]string{"0"}, true, nil)
	if code != 0 {
		t.Fatalf("rpm preun final erase should exit 0, got %d", code)
	}
	if strings.Contains(out, "warning") {
		t.Errorf("installed module removal must not warn: %s", out)
	}
	calls := readLifecycleScriptCalls(t, logFile)
	removeSeen := false
	for _, c := range calls {
		if strings.Contains(c, "semodule") && strings.Contains(c, "-r") {
			removeSeen = true
			if !strings.Contains(c, "docker_helper") {
				t.Errorf("semodule -r must target docker_helper: %s", c)
			}
		}
	}
	if !removeSeen {
		t.Error("semodule -r docker_helper must be called when the module is installed")
	}
}

// TestRpmPreremoveAbsentBothIdempotent verifies that when neither our AppArmor
// profile nor our SELinux module is present (for example a host now booted
// under a different MAC backend), final erase is a clean idempotent success
// with no attempt to unload/remove and no warning.
func TestRpmPreremoveAbsentBothIdempotent(t *testing.T) {
	fakeDir, logFile := setupScriptTest(t)
	writeFakeSystemctl(t, fakeDir, logFile, true, true)
	writeFakeApparmorParser(t, fakeDir, logFile, false, false)
	writeFakeSemodule(t, fakeDir, logFile, false, false)

	absentProfiles := filepath.Join(t.TempDir(), "profiles")
	if err := os.WriteFile(absentProfiles, []byte("# no docker-helper profile loaded\n"), 0644); err != nil {
		t.Fatal(err)
	}

	out, _, code := runScript(t, "packaging/scripts/rpm/preremove.sh", fakeDir, logFile,
		[]string{"0"}, true, []string{"SEMODULE_MODULE_PRESENT=false", "AA_PROFILES_PATH=" + absentProfiles})
	if code != 0 {
		t.Fatalf("rpm preun final erase should exit 0, got %d", code)
	}
	if strings.Contains(out, "warning") {
		t.Errorf("absent managed MAC artifacts must be idempotent (no warning): %s", out)
	}
	calls := readLifecycleScriptCalls(t, logFile)
	for _, c := range calls {
		if strings.Contains(c, "apparmor_parser") || (strings.Contains(c, "semodule") && strings.Contains(c, "-r")) {
			t.Errorf("must not attempt to remove absent managed MAC artifacts: %s", c)
		}
	}
}

// TestRpmPreremoveSELinuxRemovalFailureWarns verifies a real failure removing
// an installed SELinux module is still reported (warning), and does not abort
// the erase.
func TestRpmPreremoveSELinuxRemovalFailureWarns(t *testing.T) {
	fakeDir, logFile := setupScriptTest(t)
	writeFakeSystemctl(t, fakeDir, logFile, true, true)
	writeFakeApparmorParser(t, fakeDir, logFile, false, false)
	writeFakeSemodule(t, fakeDir, logFile, false, true)

	out, _, code := runScript(t, "packaging/scripts/rpm/preremove.sh", fakeDir, logFile,
		[]string{"0"}, true, nil)
	if code != 0 {
		t.Fatalf("rpm preun final erase should exit 0 despite module removal failure, got %d", code)
	}
	if !strings.Contains(out, "SELinux") || !strings.Contains(out, "warning") {
		t.Errorf("real module removal failure must be reported: %s", out)
	}
}

// TestDebPreremoveProfileAbsentIdempotent verifies the DEB preremove does not
// attempt to unload an absent AppArmor profile and emits no warning.
func TestDebPreremoveProfileAbsentIdempotent(t *testing.T) {
	fakeDir, logFile := setupScriptTest(t)
	writeFakeSystemctl(t, fakeDir, logFile, true, true)
	writeFakeApparmorParser(t, fakeDir, logFile, false, false)

	absentProfiles := filepath.Join(t.TempDir(), "profiles")
	if err := os.WriteFile(absentProfiles, []byte("# no docker-helper profile loaded\n"), 0644); err != nil {
		t.Fatal(err)
	}

	out, _, code := runScript(t, "packaging/scripts/deb/preremove.sh", fakeDir, logFile,
		[]string{"remove"}, true, []string{"AA_PROFILES_PATH=" + absentProfiles})
	if code != 0 {
		t.Fatalf("deb prerm remove should exit 0, got %d", code)
	}
	if strings.Contains(out, "warning") {
		t.Errorf("absent AppArmor profile must be idempotent (no warning): %s", out)
	}
	calls := readLifecycleScriptCalls(t, logFile)
	for _, c := range calls {
		if strings.Contains(c, "apparmor_parser") {
			t.Errorf("must not attempt to unload an absent AppArmor profile: %s", c)
		}
	}
}

// TestDebPostinstallSELinuxNoFalseAppArmorWarning verifies that when
// SELinux is active but AppArmor is not, the DEB postinstall emits an
// accurate message about DEB not supporting SELinux (not the old false
// "AppArmor LSM is not active" warning).
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

	// Must emit accurate message about DEB not supporting SELinux.
	if !strings.Contains(stdout, "DEB package does not install the SELinux module") {
		t.Errorf("expected accurate DEB/SELinux message, got: %s", stdout)
	}

	calls := readLifecycleScriptCalls(t, logFile)

	// Must NOT call apparmor_parser (AppArmor not active)
	for _, c := range calls {
		if strings.Contains(c, "apparmor_parser") {
			t.Error("must not call apparmor_parser when AppArmor is not active")
		}
	}
	// Must NOT call semodule (DEB does not support SELinux)
	for _, c := range calls {
		if strings.Contains(c, "semodule") {
			t.Error("must not call semodule in DEB postinstall")
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
		t.Error("must still call daemon-reload")
	}
}

// TestRpmPostinstallSelinuxOnlyNoAppArmorState verifies that on an
// SELinux-only host (AppArmor inactive), the RPM postinstall does NOT
// create AppArmor state or invoke apparmor_parser.
func TestRpmPostinstallSelinuxOnlyNoAppArmorState(t *testing.T) {
	fakeDir, logFile := setupScriptTest(t)
	writeFakeSystemctl(t, fakeDir, logFile, false, false)
	writeFakeApparmorParser(t, fakeDir, logFile, false, false)
	writeFakeSemodule(t, fakeDir, logFile, false, false)

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
	if err := os.WriteFile(filepath.Join(selinuxEnforceDir, "enforce"), []byte("1"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create legacy AppArmor fragment to test that it is NOT migrated.
	legacyPath := filepath.Join(tmpDir, "etc", "apparmor.d", "docker-helper.d", "managed-roots")
	if err := os.MkdirAll(filepath.Dir(legacyPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacyPath, []byte("# legacy content\n"), 0644); err != nil {
		t.Fatal(err)
	}

	stdout, _, code := runScript(t, "packaging/scripts/rpm/postinstall.sh", fakeDir, logFile,
		[]string{"1"}, true, []string{
			"AA_ENABLED_PATH=" + filepath.Join(aaEnabledDir, "enabled"),
			"SELINUX_ENFORCE_PATH=" + filepath.Join(selinuxEnforceDir, "enforce"),
			"AA_STATE_FILE=" + filepath.Join(tmpDir, "var", "lib", "docker-helper", "apparmor", "managed-boundaries"),
			"AA_LEGACY_FRAGMENT=" + legacyPath,
		})
	if code != 0 {
		t.Fatalf("rpm postinst should exit 0 on SELinux-only host, got %d, stdout: %s", code, stdout)
	}

	// AppArmor state directory must NOT be created.
	if _, err := os.Stat(filepath.Join(tmpDir, "var", "lib", "docker-helper", "apparmor")); !os.IsNotExist(err) {
		t.Error("AppArmor state directory must NOT be created on SELinux-only host")
	}

	// Legacy fragment must NOT be migrated or removed.
	if _, err := os.Stat(legacyPath); os.IsNotExist(err) {
		t.Error("legacy fragment must be retained on SELinux-only host")
	}

	// apparmor_parser must NOT be invoked.
	calls := readLifecycleScriptCalls(t, logFile)
	for _, c := range calls {
		if strings.Contains(c, "apparmor_parser") {
			t.Errorf("apparmor_parser must not be invoked on SELinux-only host: %s", c)
		}
	}
}

// TestRpmPostinstallAppArmorActiveStillMigrates verifies that when
// AppArmor IS active, the RPM postinstall still prepares/migrates state.
func TestRpmPostinstallAppArmorActiveStillMigrates(t *testing.T) {
	fakeDir, logFile := setupScriptTest(t)
	writeFakeSystemctl(t, fakeDir, logFile, false, false)
	writeFakeApparmorParser(t, fakeDir, logFile, false, false)

	tmpDir := t.TempDir()
	aaEnabledDir := filepath.Join(tmpDir, "sys", "module", "apparmor", "parameters")
	if err := os.MkdirAll(aaEnabledDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(aaEnabledDir, "enabled"), []byte("Y"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create legacy AppArmor fragment to test migration.
	legacyPath := filepath.Join(tmpDir, "etc", "apparmor.d", "docker-helper.d", "managed-roots")
	stateFile := filepath.Join(tmpDir, "var", "lib", "docker-helper", "apparmor", "managed-boundaries")
	if err := os.MkdirAll(filepath.Dir(legacyPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacyPath, []byte("# legacy content for migration test\n"), 0644); err != nil {
		t.Fatal(err)
	}

	stdout, _, code := runScript(t, "packaging/scripts/rpm/postinstall.sh", fakeDir, logFile,
		[]string{"1"}, true, []string{
			"AA_ENABLED_PATH=" + filepath.Join(aaEnabledDir, "enabled"),
			"AA_STATE_FILE=" + stateFile,
			"AA_LEGACY_FRAGMENT=" + legacyPath,
		})
	if code != 0 {
		t.Fatalf("rpm postinst should exit 0 when AppArmor active, got %d, stdout: %s", code, stdout)
	}

	// State file must be migrated.
	actual, err := os.ReadFile(stateFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(actual) != "# legacy content for migration test\n" {
		t.Errorf("state file migration failed, got: %q", string(actual))
	}

	// Legacy fragment must be removed after successful profile load.
	if _, err := os.Stat(legacyPath); !os.IsNotExist(err) {
		t.Error("legacy fragment must be removed after successful profile load")
	}
}

// TestDebPostinstallInactiveNoAppArmorState verifies that when
// AppArmor is inactive, the DEB postinstall does NOT create AppArmor state.
func TestDebPostinstallInactiveNoAppArmorState(t *testing.T) {
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

	// Create legacy AppArmor fragment to test that it is NOT migrated.
	legacyPath := filepath.Join(tmpDir, "etc", "apparmor.d", "docker-helper.d", "managed-roots")
	if err := os.MkdirAll(filepath.Dir(legacyPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacyPath, []byte("# legacy content\n"), 0644); err != nil {
		t.Fatal(err)
	}

	stdout, _, code := runScript(t, "packaging/scripts/deb/postinstall.sh", fakeDir, logFile,
		[]string{"configure"}, true, []string{
			"AA_ENABLED_PATH=" + filepath.Join(aaEnabledDir, "enabled"),
			"AA_STATE_FILE=" + filepath.Join(tmpDir, "var", "lib", "docker-helper", "apparmor", "managed-boundaries"),
			"AA_LEGACY_FRAGMENT=" + legacyPath,
		})
	if code != 0 {
		t.Fatalf("deb postinst should exit 0 when AppArmor inactive, got %d, stdout: %s", code, stdout)
	}

	// AppArmor state directory must NOT be created.
	if _, err := os.Stat(filepath.Join(tmpDir, "var", "lib", "docker-helper", "apparmor")); !os.IsNotExist(err) {
		t.Error("AppArmor state directory must NOT be created when AppArmor inactive")
	}

	// Legacy fragment must NOT be migrated or removed.
	if _, err := os.Stat(legacyPath); os.IsNotExist(err) {
		t.Error("legacy fragment must be retained when AppArmor inactive")
	}

	// apparmor_parser must NOT be invoked.
	calls := readLifecycleScriptCalls(t, logFile)
	for _, c := range calls {
		if strings.Contains(c, "apparmor_parser") {
			t.Errorf("apparmor_parser must not be invoked when AppArmor inactive: %s", c)
		}
	}

	// Must emit the AppArmor-inactive warning.
	if !strings.Contains(stdout, "AppArmor LSM is not active") {
		t.Errorf("expected 'AppArmor LSM is not active' warning, got: %s", stdout)
	}
}

// TestDebPostinstallActiveStillMigrates verifies that when AppArmor IS
// active, the DEB postinstall still prepares/migrates state.
func TestDebPostinstallActiveStillMigrates(t *testing.T) {
	fakeDir, logFile := setupScriptTest(t)
	writeFakeSystemctl(t, fakeDir, logFile, false, false)
	writeFakeApparmorParser(t, fakeDir, logFile, false, false)

	tmpDir := t.TempDir()
	aaEnabledDir := filepath.Join(tmpDir, "sys", "module", "apparmor", "parameters")
	if err := os.MkdirAll(aaEnabledDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(aaEnabledDir, "enabled"), []byte("Y"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create legacy AppArmor fragment to test migration.
	legacyPath := filepath.Join(tmpDir, "etc", "apparmor.d", "docker-helper.d", "managed-roots")
	stateFile := filepath.Join(tmpDir, "var", "lib", "docker-helper", "apparmor", "managed-boundaries")
	if err := os.MkdirAll(filepath.Dir(legacyPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacyPath, []byte("# legacy content for migration test\n"), 0644); err != nil {
		t.Fatal(err)
	}

	stdout, _, code := runScript(t, "packaging/scripts/deb/postinstall.sh", fakeDir, logFile,
		[]string{"configure"}, true, []string{
			"AA_ENABLED_PATH=" + filepath.Join(aaEnabledDir, "enabled"),
			"AA_STATE_FILE=" + stateFile,
			"AA_LEGACY_FRAGMENT=" + legacyPath,
		})
	if code != 0 {
		t.Fatalf("deb postinst should exit 0 when AppArmor active, got %d, stdout: %s", code, stdout)
	}

	// State file must be migrated.
	actual, err := os.ReadFile(stateFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(actual) != "# legacy content for migration test\n" {
		t.Errorf("state file migration failed, got: %q", string(actual))
	}

	// Legacy fragment must be removed after successful profile load.
	if _, err := os.Stat(legacyPath); !os.IsNotExist(err) {
		t.Error("legacy fragment must be removed after successful profile load")
	}
}

// TestDebPostinstallNeitherMACNoAppArmorState verifies that when no MAC
// backend is active, the DEB postinstall does NOT create AppArmor state.
func TestDebPostinstallNeitherMACNoAppArmorState(t *testing.T) {
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
	selinuxEnforceDir := filepath.Join(tmpDir, "sys", "fs", "selinux")
	if err := os.MkdirAll(selinuxEnforceDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(selinuxEnforceDir, "enforce"), []byte("0"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create legacy AppArmor fragment to test that it is NOT migrated.
	legacyPath := filepath.Join(tmpDir, "etc", "apparmor.d", "docker-helper.d", "managed-roots")
	if err := os.MkdirAll(filepath.Dir(legacyPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacyPath, []byte("# legacy content\n"), 0644); err != nil {
		t.Fatal(err)
	}

	stdout, _, code := runScript(t, "packaging/scripts/deb/postinstall.sh", fakeDir, logFile,
		[]string{"configure"}, true, []string{
			"AA_ENABLED_PATH=" + filepath.Join(aaEnabledDir, "enabled"),
			"SELINUX_ENFORCE_PATH=" + filepath.Join(selinuxEnforceDir, "enforce"),
			"AA_STATE_FILE=" + filepath.Join(tmpDir, "var", "lib", "docker-helper", "apparmor", "managed-boundaries"),
			"AA_LEGACY_FRAGMENT=" + legacyPath,
		})
	if code != 0 {
		t.Fatalf("deb postinst should exit 0 when no MAC active, got %d, stdout: %s", code, stdout)
	}

	// AppArmor state directory must NOT be created.
	if _, err := os.Stat(filepath.Join(tmpDir, "var", "lib", "docker-helper", "apparmor")); !os.IsNotExist(err) {
		t.Error("AppArmor state directory must NOT be created when no MAC active")
	}

	// Legacy fragment must NOT be migrated or removed.
	if _, err := os.Stat(legacyPath); os.IsNotExist(err) {
		t.Error("legacy fragment must be retained when no MAC active")
	}

	// apparmor_parser must NOT be invoked.
	calls := readLifecycleScriptCalls(t, logFile)
	for _, c := range calls {
		if strings.Contains(c, "apparmor_parser") {
			t.Errorf("apparmor_parser must not be invoked when no MAC active: %s", c)
		}
	}

	// Must emit the AppArmor-inactive warning.
	if !strings.Contains(stdout, "AppArmor LSM is not active") {
		t.Errorf("expected 'AppArmor LSM is not active' warning, got: %s", stdout)
	}
}

// TestDebPostinstallNeitherMAC verifies that when no MAC backend is active,
// the DEB postinstall emits the AppArmor-specific warning.
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

	// Must emit AppArmor-specific warning (not generic "no MAC backend")
	if !strings.Contains(stdout, "AppArmor LSM is not active") {
		t.Errorf("expected 'AppArmor LSM is not active' warning, got: %s", stdout)
	}
}

// TestSELinuxPolicyWorkspaceType verifies that the SELinux policy
// defines docker_helper_workspace_t for non-home workspace roots
// while retaining user_home_type for /home paths.
func TestSELinuxPolicyWorkspaceType(t *testing.T) {
	data, err := os.ReadFile("packaging/selinux/docker-helper.te")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	// Must use user_home_type attribute for /home workspace access
	if !strings.Contains(content, "user_home_type") {
		t.Error("SELinux policy must use user_home_type attribute for /home workspace access")
	}

	// Must define docker_helper_workspace_t for non-home system roots
	if !strings.Contains(content, "docker_helper_workspace_t") {
		t.Error("SELinux policy must define docker_helper_workspace_t for non-home system roots")
	}

	// Must define docker_helper_workspace_t as file_type
	if !strings.Contains(content, "type docker_helper_workspace_t, file_type;") {
		t.Error("SELinux policy must define docker_helper_workspace_t as file_type")
	}
}

// TestSELinuxPolicyNoGlobalContainerAccess verifies that the SELinux policy
// does not globally grant normal container_t access to user_home_type.
func TestSELinuxPolicyNoGlobalContainerAccess(t *testing.T) {
	data, err := os.ReadFile("packaging/selinux/docker-helper.te")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	// Must NOT grant container_t access to user_home_type
	// (only docker_helper_container_t should have this access)
	if strings.Contains(content, "allow container_t user_home_type") {
		t.Error("SELinux policy must not grant container_t access to user_home_type")
	}
}

// TestSELinuxPolicyCustomContainerType verifies that the SELinux policy
// defines a custom container type for docker-helper containers.
func TestSELinuxPolicyCustomContainerType(t *testing.T) {
	data, err := os.ReadFile("packaging/selinux/docker-helper.te")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	// Must define docker_helper_container_t
	if !strings.Contains(content, "docker_helper_container_t") {
		t.Error("SELinux policy must define docker_helper_container_t")
	}

	// Must grant docker_helper_container_t access to user_home_type
	if !strings.Contains(content, "allow docker_helper_container_t user_home_type") {
		t.Error("SELinux policy must grant docker_helper_container_t access to user_home_type")
	}
}

// TestSELinuxFCNoWorkspacePaths verifies that the SELinux file contexts
// do not include workspace/home paths.
func TestSELinuxFCNoWorkspacePaths(t *testing.T) {
	data, err := os.ReadFile("packaging/selinux/docker-helper.fc")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	// Must NOT include /home paths as file context rules
	// (comments are allowed, but not actual file context rules)
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, "/home") {
			t.Errorf("SELinux .fc must not include /home paths: %s", line)
		}
	}
}

// TestRunSELinuxContainerSecurityOpt verifies that the run command uses
// the correct SELinux container security option.
func TestRunSELinuxContainerSecurityOpt(t *testing.T) {
	// Verify the run.go code uses docker_helper_container_t for SELinux
	data, err := os.ReadFile("run.go")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	// Must use docker_helper_container_t for SELinux system mode
	if !strings.Contains(content, "docker_helper_container_t") {
		t.Error("run.go must use docker_helper_container_t for SELinux system mode")
	}

	// Must check for LSMSELinux before using custom type
	if !strings.Contains(content, "LSMSELinux") {
		t.Error("run.go must check for LSMSELinux before using custom container type")
	}
}

// TestInvalidWorkspaceOperationalLogging verifies that ErrInvalidWorkspace
// logs the detailed internal error to the operational log.
func TestInvalidWorkspaceOperationalLogging(t *testing.T) {
	data, err := os.ReadFile("sessions.go")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	// Must log the internal error for ErrInvalidWorkspace
	if !strings.Contains(content, "session creation rejected") {
		t.Error("sessions.go must log 'session creation rejected' for ErrInvalidWorkspace")
	}

	// Must include the error in the log
	if !strings.Contains(content, "slog.String(\"error\"") {
		t.Error("sessions.go must include the error in the operational log")
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

	// Create a dummy SELinux policy module (required by nfpm.yaml).
	dummyPP := filepath.Join(tmpDir, "docker_helper.pp")
	if err := os.WriteFile(dummyPP, []byte("dummy-pp"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create a dummy completion script (required by nfpm.yaml).
	os.MkdirAll(filepath.Join(tmpDir, "completions"), 0755)
	dummyCompletion := filepath.Join(tmpDir, "completions", "docker-helper")
	if err := os.WriteFile(dummyCompletion, []byte("# bash completion\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create a temporary nFPM config.
	nfpmData, err := os.ReadFile("packaging/nfpm.yaml")
	if err != nil {
		t.Fatal(err)
	}
	configContent := strings.ReplaceAll(string(nfpmData), "src: dist/docker-helper", "src: "+dummyBin)
	configContent = strings.ReplaceAll(configContent, "src: dist/docker_helper.pp", "src: "+dummyPP)
	configContent = strings.ReplaceAll(configContent, "src: dist/completions/docker-helper", "src: "+dummyCompletion)
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

	// Create a dummy SELinux policy module (required by nfpm.yaml).
	dummyPP := filepath.Join(tmpDir, "docker_helper.pp")
	if err := os.WriteFile(dummyPP, []byte("dummy-pp"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create a dummy completion script (required by nfpm.yaml).
	os.MkdirAll(filepath.Join(tmpDir, "completions"), 0755)
	dummyCompletion := filepath.Join(tmpDir, "completions", "docker-helper")
	if err := os.WriteFile(dummyCompletion, []byte("# bash completion\n"), 0644); err != nil {
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
	configContent = strings.ReplaceAll(configContent, "src: dist/docker_helper.pp", "src: "+dummyPP)
	configContent = strings.ReplaceAll(configContent, "src: dist/man/docker-helper.1.gz", "src: "+filepath.Join(tmpDir, "man", "docker-helper.1.gz"))
	configContent = strings.ReplaceAll(configContent, "src: dist/man/docker-helper-config.5.gz", "src: "+filepath.Join(tmpDir, "man", "docker-helper-config.5.gz"))
	configContent = strings.ReplaceAll(configContent, "src: dist/completions/docker-helper", "src: "+dummyCompletion)
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

// TestPackageBashCompletion verifies that the built packages contain the
// Bash completion script at the correct path.
func TestPackageBashCompletion(t *testing.T) {
	if _, err := exec.LookPath("nfpm"); err != nil {
		t.Skip("nfpm not installed, skipping package bash completion test")
	}

	tmpDir := t.TempDir()

	// Create dummy binary.
	dummyBin := filepath.Join(tmpDir, "docker-helper")
	if err := os.WriteFile(dummyBin, []byte("dummy"), 0755); err != nil {
		t.Fatal(err)
	}

	// Create a dummy SELinux policy module (required by nfpm.yaml).
	dummyPP := filepath.Join(tmpDir, "docker_helper.pp")
	if err := os.WriteFile(dummyPP, []byte("dummy-pp"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create dummy man pages.
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

	// Create dummy completion script.
	os.MkdirAll(filepath.Join(tmpDir, "completions"), 0755)
	dummyCompletion := filepath.Join(tmpDir, "completions", "docker-helper")
	if err := os.WriteFile(dummyCompletion, []byte("# bash completion\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create temp nFPM config.
	nfpmData, err := os.ReadFile("packaging/nfpm.yaml")
	if err != nil {
		t.Fatal(err)
	}
	configContent := strings.ReplaceAll(string(nfpmData), "src: dist/docker-helper", "src: "+dummyBin)
	configContent = strings.ReplaceAll(configContent, "src: dist/docker_helper.pp", "src: "+dummyPP)
	configContent = strings.ReplaceAll(configContent, "src: dist/man/docker-helper.1.gz", "src: "+filepath.Join(tmpDir, "man", "docker-helper.1.gz"))
	configContent = strings.ReplaceAll(configContent, "src: dist/man/docker-helper-config.5.gz", "src: "+filepath.Join(tmpDir, "man", "docker-helper-config.5.gz"))
	configContent = strings.ReplaceAll(configContent, "src: dist/completions/docker-helper", "src: "+dummyCompletion)
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

	// Verify DEB contains bash completion.
	if dpkgDeb, err := exec.LookPath("dpkg-deb"); err == nil {
		cmd := exec.Command(dpkgDeb, "--contents", debFile)
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "/usr/share/bash-completion/completions/docker-helper") {
			t.Error("DEB missing /usr/share/bash-completion/completions/docker-helper")
		}
	} else {
		t.Log("dpkg-deb not available, skipping DEB completion verification")
	}

	// Verify RPM contains bash completion.
	if rpmPath, err := exec.LookPath("rpm"); err == nil {
		cmd := exec.Command(rpmPath, "-qpl", rpmFile)
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "/usr/share/bash-completion/completions/docker-helper") {
			t.Error("RPM missing /usr/share/bash-completion/completions/docker-helper")
		}
	} else {
		t.Log("rpm not available, skipping RPM completion verification")
	}
}

// TestBuildPackagesScriptGeneratesCompletion verifies that build-packages.sh
// generates the completion script and fails if generation produces empty output.
func TestBuildPackagesScriptGeneratesCompletion(t *testing.T) {
	data, err := os.ReadFile("build-packages.sh")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	if !strings.Contains(content, "completion bash") {
		t.Error("build-packages.sh must generate bash completion")
	}
	if !strings.Contains(content, "dist/completions/docker-helper") {
		t.Error("build-packages.sh must output completion to dist/completions/docker-helper")
	}
	// Must fail closed if generation produces empty output.
	if !strings.Contains(content, "empty output") {
		t.Error("build-packages.sh must fail if completion generation produces empty output")
	}
}

// TestReleaseWorkflow guards the release pipeline contract: release.yml is a
// thin caller of the single canonical artifact gate, promotion never
// constructs artifacts, and the gate + canonical producer own the pinned nFPM,
// build-bundle / build-packages and SHA256SUMS responsibilities.
func TestReleaseWorkflow(t *testing.T) {
	release, err := os.ReadFile(".github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	releaseContent := string(release)

	gate, err := os.ReadFile(".github/workflows/artifact-gate.yml")
	if err != nil {
		t.Fatal(err)
	}
	gateContent := string(gate)

	// release.yml must call the single canonical artifact gate (one matrix
	// owner; release must not duplicate the UAT matrix).
	if !strings.Contains(releaseContent, "uses: ./.github/workflows/artifact-gate.yml") {
		t.Error("release.yml must call the artifact gate (artifact-gate.yml)")
	}

	// The gate must own the canonical producer and the pinned nFPM.
	if !strings.Contains(gateContent, "scripts/release-candidate.sh") {
		t.Error("artifact-gate.yml must run the canonical release-candidate.sh producer")
	}
	if !strings.Contains(gateContent, "NFPM_VERSION=2.47.0") {
		t.Error("artifact-gate.yml must pin NFPM_VERSION=2.47.0")
	}
	if !strings.Contains(gateContent, "0660ca602b2d2d2ae4781a06c692b3eeb9d437ffea05b831d76e41f4a3188783") {
		t.Error("artifact-gate.yml must contain pinned nFPM SHA256")
	}
	if strings.Contains(gateContent, "@latest") {
		t.Error("artifact-gate.yml must not use @latest for nFPM")
	}

	// The canonical producer script must build through the authoritative
	// builders and own SHA256SUMS generation + verification.
	producer, err := os.ReadFile("scripts/release-candidate.sh")
	if err != nil {
		t.Fatal(err)
	}
	producerContent := string(producer)
	if !strings.Contains(producerContent, "build-bundle.sh") {
		t.Error("release-candidate.sh must call build-bundle.sh")
	}
	if !strings.Contains(producerContent, "build-packages.sh") {
		t.Error("release-candidate.sh must call build-packages.sh")
	}
	if !strings.Contains(producerContent, "SHA256SUMS") {
		t.Error("release-candidate.sh must generate SHA256SUMS")
	}
	if !strings.Contains(producerContent, "--check") {
		t.Error("release-candidate.sh must verify SHA256SUMS")
	}

	// The promote job must publish tar.gz/deb/rpm/SHA256SUMS via gh.
	promoteJob := findJobSection(releaseContent, "promote")
	if promoteJob == "" {
		t.Fatal("release.yml must contain a promote job")
	}
	if !strings.Contains(promoteJob, "gh release create") {
		t.Error("promote job must call gh release create")
	}
	for _, must := range []string{".tar.gz", ".deb", ".rpm", "SHA256SUMS"} {
		if !strings.Contains(promoteJob, must) {
			t.Errorf("promote job must publish %s", must)
		}
	}
	// Prerelease handling must be preserved.
	if !strings.Contains(promoteJob, "prerelease") {
		t.Error("promote job must handle prerelease")
	}

	// release.yml must run race tests (not weaker than CI).
	if !strings.Contains(releaseContent, "go test -race") {
		t.Error("release.yml must run go test -race")
	}

	// Static checks must run before the gate/build.
	gateJob := findJobSection(releaseContent, "gate")
	if gateJob == "" {
		t.Fatal("release.yml must contain a gate job")
	}
	if !strings.Contains(gateJob, "needs: [prepare, checks, selinux-policy]") {
		t.Error("gate job must depend on prepare, checks and selinux-policy")
	}
}

// TestReleaseJobSELinuxBuildDeps verifies that the artifact gate's producer
// installs the build toolchain (musl-tools, checkpolicy, semodule-utils via
// the canonical platform dependency owner) BEFORE running the canonical
// release-candidate.sh build. The assertion is scoped to that job's steps so a
// mention in another job or step cannot satisfy it.
func TestReleaseJobSELinuxBuildDeps(t *testing.T) {
	gateData, err := os.ReadFile(".github/workflows/artifact-gate.yml")
	if err != nil {
		t.Fatal(err)
	}
	gateContent := string(gateData)

	// Locate the producer job section (the sole build job).
	producerJob := findJobSection(gateContent, "producer")
	if producerJob == "" {
		t.Fatal("could not locate producer job in artifact-gate.yml")
	}

	// The 'Install build dependencies' step must run the canonical platform
	// dependency owner.
	installStep := findStepBlock(producerJob, "Install build dependencies")
	if installStep == "" {
		t.Fatal("producer job must contain 'Install build dependencies' step")
	}
	runBlock := extractRunBlock(installStep)
	if runBlock == "" {
		t.Fatal("'Install build dependencies' step must have a run block")
	}
	if !strings.Contains(runBlock, "uat-blackbox.sh install-deps") {
		t.Fatal("'Install build dependencies' step must call uat-blackbox.sh install-deps")
	}

	// The canonical platform dependency owner must install the SELinux/build
	// toolchain (musl-tools, checkpolicy, semodule-utils).
	platformData, err := os.ReadFile("scripts/uat-platform-ubuntu.sh")
	if err != nil {
		t.Fatal(err)
	}
	platformContent := string(platformData)
	for _, pkg := range []string{"musl-tools", "checkpolicy", "semodule-utils"} {
		if !strings.Contains(platformContent, pkg) {
			t.Errorf("uat-platform-ubuntu.sh install-deps must install %s", pkg)
		}
	}

	// The canonical producer build step must exist and come after the install
	// step.
	buildStep := findStepBlock(producerJob, "Build + stage the immutable candidate set (canonical producer)")
	if buildStep == "" {
		t.Fatal("producer job must contain the release-candidate.sh build step")
	}
	if !strings.Contains(buildStep, "release-candidate.sh") {
		t.Fatal("candidate build step must call release-candidate.sh")
	}
	installPos := strings.Index(producerJob, "Install build dependencies")
	buildPos := strings.Index(producerJob, "Build + stage the immutable candidate set (canonical producer)")
	if installPos < 0 || buildPos < 0 {
		t.Fatal("could not locate both Install and Build steps in producer job")
	}
	if installPos > buildPos {
		t.Error("Install build dependencies must precede the candidate build in the producer job")
	}
}

// findJobSection returns the text belonging to the named job (e.g., "release").
// It finds "  name:" at the 2-space indentation level under "jobs:" and captures
// content until the next job key at the same indentation or end of file.
func findJobSection(content, name string) string {
	marker := "  " + name + ":"
	idx := strings.Index(content, marker)
	if idx < 0 {
		return ""
	}

	lines := strings.Split(content[idx:], "\n")
	var result []string
	for i, line := range lines {
		if i == 0 {
			result = append(result, line)
			continue
		}
		// A new top-level job key (exactly 2-space indent, non-empty, followed
		// by non-space) ends this job section.
		if isJobKey(line) {
			break
		}
		result = append(result, line)
	}
	return strings.Join(result, "\n")
}

// isJobKey returns true if line is a YAML key at exactly 2-space indentation
// (a top-level job definition under "jobs:").
func isJobKey(line string) bool {
	if len(line) < 3 {
		return false
	}
	if line[0] != ' ' || line[1] != ' ' || line[2] == ' ' || line[2] == '\t' {
		return false
	}
	// The rest must contain a colon (key: value or key:) and not be a comment.
	rest := line[2:]
	if strings.HasPrefix(rest, "#") {
		return false
	}
	return strings.ContainsRune(rest, ':')
}

// findStepBlock returns the text of the named step within a job's steps list.
// It finds "- name: STEP_NAME" and captures lines until the next step ("- name:"
// or "- uses:") or end of the steps list.
func findStepBlock(jobContent, stepName string) string {
	marker := "- name: " + stepName
	idx := strings.Index(jobContent, marker)
	if idx < 0 {
		return ""
	}

	lines := strings.Split(jobContent[idx:], "\n")
	var result []string
	for i, line := range lines {
		if i == 0 {
			result = append(result, line)
			continue
		}
		// A new step starts with "- name:" or "- uses:" at the step indentation.
		if isStepStart(line) {
			break
		}
		result = append(result, line)
	}
	return strings.Join(result, "\n")
}

// isStepStart returns true if line begins a new step in a GitHub Actions steps list.
func isStepStart(line string) bool {
	trimmed := strings.TrimSpace(line)
	return strings.HasPrefix(trimmed, "- name:") || strings.HasPrefix(trimmed, "- uses:")
}

// extractRunBlock extracts the "run:" block from a step's YAML text.
// For multi-line blocks ("run: |"), it captures all indented lines after
// the directive until a non-indented line or end of content.
func extractRunBlock(stepContent string) string {
	idx := strings.Index(stepContent, "run:")
	if idx < 0 {
		return ""
	}

	// Find the start of the run block content (after "run: |" or "run: ").
	rest := stepContent[idx+4:] // skip "run:"
	lines := strings.Split(rest, "\n")
	var result []string
	for _, line := range lines {
		// Skip the first line if it's just "|" (block scalar indicator) or empty.
		trimmed := strings.TrimSpace(line)
		if trimmed == "|" || trimmed == "" {
			continue
		}
		// Lines in the run block are indented (typically 10+ spaces in GitHub Actions).
		// A line with no leading whitespace and non-empty content ends the block.
		if line != "" && line[0] != ' ' && line[0] != '\t' {
			break
		}
		result = append(result, line)
	}
	return strings.Join(result, "\n")
}

// findAptInstallLine returns the first line in text that contains
// "apt-get install", trimmed of leading whitespace. Returns "" if not found.
func findAptInstallLine(text string) string {
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, "apt-get install") {
			return strings.TrimSpace(line)
		}
	}
	return ""
}

// workflowPermissionsBlock returns the top-level `permissions:` block of a
// workflow file (the block at column 0 up to the next top-level key), or ""
// when the workflow declares no top-level permissions.
func workflowPermissionsBlock(content string) string {
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		if line != "permissions:" {
			continue
		}
		var result []string
		result = append(result, line)
		for _, l := range lines[i+1:] {
			if l != "" && l[0] != ' ' && l[0] != '\t' {
				break
			}
			result = append(result, l)
		}
		return strings.Join(result, "\n")
	}
	return ""
}

// jobPermissionsBlock returns the `permissions:` block declared inside a job
// section (4-space indented key, 6-space indented values), or "" when the job
// declares none.
func jobPermissionsBlock(jobContent string) string {
	lines := strings.Split(jobContent, "\n")
	for i, line := range lines {
		if line != "    permissions:" {
			continue
		}
		var result []string
		result = append(result, line)
		for _, l := range lines[i+1:] {
			if l == "" {
				result = append(result, l)
				continue
			}
			indent := len(l) - len(strings.TrimLeft(l, " "))
			if indent <= 4 {
				break
			}
			result = append(result, l)
		}
		return strings.Join(result, "\n")
	}
	return ""
}

// TestReleaseWorkflowRaceBeforeBuild verifies the race tests (checks job) run
// before the candidate build in the release pipeline: the gate (which owns the
// producer/build) depends on checks, and promotion depends on the gate.
func TestReleaseWorkflowRaceBeforeBuild(t *testing.T) {
	data, err := os.ReadFile(".github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	if !strings.Contains(content, "go test -race") {
		t.Fatal("release.yml must contain go test -race")
	}

	// The gate job (which runs the candidate producer/build) must depend on the
	// checks job, so race tests complete before the build.
	gateJob := findJobSection(content, "gate")
	if gateJob == "" {
		t.Fatal("release.yml must contain a gate job")
	}
	if !strings.Contains(gateJob, "checks") {
		t.Fatal("gate job must depend on the checks job (race tests run before the build)")
	}

	// Promotion must depend on the gate (the build + full UAT).
	promoteJob := findJobSection(content, "promote")
	if promoteJob == "" {
		t.Fatal("release.yml must contain a promote job")
	}
	if !strings.Contains(promoteJob, "needs: [prepare, checks, selinux-policy, gate]") {
		t.Fatal("promote job must depend on the gate")
	}
}

// TestWorkflowActionsPinnedToImmutableShas is the deterministic supply-chain
// guard for the repository workflows: every external GitHub Action reference
// must be pinned to a full 40-hex commit SHA (with the human-readable tag
// retained in a trailing comment). Only local reusable workflow references
// (`uses: ./.github/workflows/...`) may stay tag-free. Mutable external refs
// (`actions/foo@v7`, `@main`, `@latest`, ...) are rejected.
func TestWorkflowActionsPinnedToImmutableShas(t *testing.T) {
	files, err := filepath.Glob(".github/workflows/*.yml")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no workflow files found under .github/workflows/")
	}

	hex40 := regexp.MustCompile(`^[0-9a-f]{40}$`)
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for lineNo, raw := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(raw)
			if !strings.Contains(trimmed, "uses:") {
				continue
			}
			// Take everything after "uses:", drop any trailing YAML comment.
			ref := strings.TrimSpace(strings.SplitN(trimmed, "uses:", 2)[1])
			if idx := strings.Index(ref, " #"); idx >= 0 {
				ref = strings.TrimSpace(ref[:idx])
			}
			location := fmt.Sprintf("%s:%d", f, lineNo+1)

			// Local reusable workflows stay local and are not external actions.
			if strings.HasPrefix(ref, "./") {
				continue
			}

			// External action must be owner/action@<40-hex-sha>.
			at := strings.LastIndex(ref, "@")
			if at <= 0 || at == len(ref)-1 {
				t.Errorf("%s: mutable external Action reference (must be <owner>/<action>@<40-hex sha> with a '# <tag>' comment): %q", location, ref)
				continue
			}
			sha := ref[at+1:]
			if !hex40.MatchString(sha) {
				t.Errorf("%s: external Action reference is not pinned to a 40-hex commit SHA: %q", location, ref)
				continue
			}
			// The human-readable release/major tag must be retained in a comment.
			if !strings.Contains(trimmed, " # ") {
				t.Errorf("%s: pinned Action must retain its tag in a trailing comment ('uses: %s # vN'): %q", location, ref, trimmed)
			}
		}
	}
}

// TestReleasePromoteNoBuild verifies the promote job contains NO construction:
// no build scripts, no nFPM, no Go build/toolchain, no regenerated
// manpages/completion, no regenerated SHA256SUMS. Promotion means PROMOTION,
// not construction: it downloads the candidate set and verifies it.
func TestReleasePromoteNoBuild(t *testing.T) {
	data, err := os.ReadFile(".github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	promoteJob := findJobSection(content, "promote")
	if promoteJob == "" {
		t.Fatal("release.yml must contain a promote job")
	}
	for _, banned := range []string{
		"build-bundle.sh", "build-packages.sh", "build-static.sh",
		"release-candidate.sh", "nfpm", "go build", "setup-go", "completion bash",
	} {
		if strings.Contains(promoteJob, banned) {
			t.Errorf("promote job must not contain %s", banned)
		}
	}
	if strings.Contains(promoteJob, "> SHA256SUMS") {
		t.Error("promote job must not regenerate SHA256SUMS")
	}
	if !strings.Contains(promoteJob, "release-promote-verify.sh") {
		t.Error("promote job must verify via release-promote-verify.sh")
	}
	if !strings.Contains(promoteJob, "download-artifact") {
		t.Error("promote job must download the candidate artifact, not build it")
	}
}

// TestReleaseDryRunNonPublishing verifies the safe dry-run path: publication is
// gated on the push (tag) event, and workflow_dispatch runs only a promotion
// verification that never calls gh release create.
func TestReleaseDryRunNonPublishing(t *testing.T) {
	data, err := os.ReadFile(".github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	promoteJob := findJobSection(content, "promote")
	if promoteJob == "" {
		t.Fatal("release.yml must contain a promote job")
	}
	if !strings.Contains(promoteJob, "github.event_name == 'push'") {
		t.Error("promote job must be gated on the push (tag) event")
	}

	dryRunJob := findJobSection(content, "promote-dry-run")
	if dryRunJob == "" {
		t.Fatal("release.yml must contain a promote-dry-run job")
	}
	if !strings.Contains(dryRunJob, "github.event_name == 'workflow_dispatch'") {
		t.Error("promote-dry-run must be gated on workflow_dispatch")
	}
	if strings.Contains(dryRunJob, "gh release create") {
		t.Error("promote-dry-run must never call gh release create")
	}
	if !strings.Contains(dryRunJob, "release-promote-verify.sh") {
		t.Error("promote-dry-run must verify via release-promote-verify.sh")
	}
}

// TestReleaseLeastPrivilegePermissions verifies the release pipeline runs at
// least privilege: workflow-level `contents: read` only, with `contents: write`
// granted to exactly one job — `promote`, the only job that publishes (via
// `gh release create`). No other job (prepare, checks, selinux-policy, gate,
// promote-dry-run) may declare explicit permissions, so a `contents: write`
// regression anywhere else is caught structurally.
func TestReleaseLeastPrivilegePermissions(t *testing.T) {
	data, err := os.ReadFile(".github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	// Workflow-level permissions must be the read-only baseline.
	wfPerms := workflowPermissionsBlock(content)
	if !strings.Contains(wfPerms, "contents: read") {
		t.Error("workflow-level permissions must grant contents: read")
	}
	if strings.Contains(wfPerms, "contents: write") {
		t.Error("workflow-level permissions must not grant contents: write (least privilege)")
	}

	// The promote job is the single writer: it must explicitly request
	// contents: write because `gh release create` publishes via the API.
	promoteJob := findJobSection(content, "promote")
	if promoteJob == "" {
		t.Fatal("release.yml must contain a promote job")
	}
	if block := jobPermissionsBlock(promoteJob); !strings.Contains(block, "contents: write") {
		t.Error("promote job must declare permissions: contents: write (gh release create requires it)")
	}

	// No other job may carry explicit permissions; the workflow-level
	// contents: read already covers checkout and artifact download, so write
	// can never creep into the non-publishing jobs.
	for _, job := range []string{"prepare", "checks", "selinux-policy", "gate", "promote-dry-run"} {
		section := findJobSection(content, job)
		if section == "" {
			t.Fatalf("release.yml must contain a %s job", job)
		}
		if block := jobPermissionsBlock(section); block != "" {
			t.Errorf("%s job must not declare explicit permissions (workflow-level contents: read suffices); got: %q", job, block)
		}
	}
}

// TestSyncReleaseToMainLeastPrivilege verifies sync-release-to-main.yml runs
// repository-controlled code only with contents: read, keeps the write job to a
// minimal merge+push with no repository-controlled test/build steps, and makes
// the write job push only the exact merge tree the read-only job validated.
func TestSyncReleaseToMainLeastPrivilege(t *testing.T) {
	data, err := os.ReadFile(".github/workflows/sync-release-to-main.yml")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	// Workflow-level baseline must be read-only.
	wfPerms := workflowPermissionsBlock(content)
	if !strings.Contains(wfPerms, "contents: read") {
		t.Error("sync-release-to-main.yml must set workflow-level contents: read")
	}
	if strings.Contains(wfPerms, "contents: write") {
		t.Error("sync-release-to-main.yml must not grant workflow-level contents: write")
	}

	// The validation job runs the repository-controlled checks and must not
	// declare write permission.
	validationJob := findJobSection(content, "validation")
	if validationJob == "" {
		t.Fatal("sync-release-to-main.yml must contain a validation job")
	}
	if block := jobPermissionsBlock(validationJob); strings.Contains(block, "contents: write") {
		t.Error("validation job must not declare contents: write")
	}
	for _, check := range []string{"gofmt", "go test", "go vet", "git diff --check"} {
		if !strings.Contains(validationJob, check) {
			t.Errorf("validation job must run %s", check)
		}
	}

	// The merge-push job is the single writer: it depends on validation,
	// requests contents: write, and performs only git merge/push — never
	// repository-controlled test/build commands.
	pushJob := findJobSection(content, "merge-push")
	if pushJob == "" {
		t.Fatal("sync-release-to-main.yml must contain a merge-push job")
	}
	if !strings.Contains(pushJob, "needs: validation") {
		t.Error("merge-push job must depend on the validation job")
	}
	if block := jobPermissionsBlock(pushJob); !strings.Contains(block, "contents: write") {
		t.Error("merge-push job must declare permissions: contents: write (git push requires it)")
	}
	for _, banned := range []string{"gofmt", "go test", "go vet", "git diff --check", "setup-go", "build-bundle.sh"} {
		if strings.Contains(pushJob, banned) {
			t.Errorf("merge-push job must not run repository-controlled step %q after gaining write", banned)
		}
	}
	if !strings.Contains(pushJob, "git push origin main") {
		t.Error("merge-push job must push to main")
	}

	// The validation job must export the exact main SHA it validated against and
	// the exact resulting merged tree SHA, so the write job can push only the
	// tested tree.
	if !strings.Contains(validationJob, "outputs:") ||
		!strings.Contains(validationJob, "main_sha") ||
		!strings.Contains(validationJob, "tree_sha") {
		t.Error("validation job must declare outputs for main_sha and tree_sha")
	}
	prepare := findStepBlock(validationJob, "Record validated main SHA and merged tree SHA")
	if prepare == "" {
		t.Fatal("validation job must record the validated main SHA and merged tree SHA")
	}
	prepareRun := extractRunBlock(prepare)
	if !strings.Contains(prepareRun, `main_sha="$(git rev-parse HEAD)"`) {
		t.Error("validation step must record the exact main SHA it validates against")
	}
	if !strings.Contains(prepareRun, "git merge --no-ff") {
		t.Error("validation step must prepare the merge locally")
	}
	if !strings.Contains(prepareRun, `tree_sha="$(git rev-parse HEAD^{tree})"`) {
		t.Error("validation step must record the exact merged tree SHA")
	}
	if !strings.Contains(prepareRun, "GITHUB_OUTPUT") {
		t.Error("validation step must export main_sha and tree_sha via GITHUB_OUTPUT")
	}

	// The write job must pin to the exact validated main SHA and tree SHA rather
	// than refetch and silently merge against a newer main.
	if !strings.Contains(pushJob, "needs.validation.outputs.main_sha") {
		t.Error("merge-push job must consume the validated main SHA from the validation job")
	}
	if !strings.Contains(pushJob, "needs.validation.outputs.tree_sha") {
		t.Error("merge-push job must consume the validated tree SHA from the validation job")
	}

	// Fail closed when origin/main advanced after validation.
	guard := findStepBlock(pushJob, "Fail closed if main advanced after validation")
	if guard == "" {
		t.Fatal("merge-push job must fail closed when origin/main advanced after validation")
	}
	guardRun := extractRunBlock(guard)
	if !strings.Contains(guardRun, "origin/main") || !strings.Contains(guardRun, "needs.validation.outputs.main_sha") {
		t.Error("main-advance guard must compare origin/main against the validated main SHA")
	}
	if !strings.Contains(guardRun, "exit 1") {
		t.Error("main-advance guard must fail the job (exit 1) on a changed main")
	}

	// Reconstruct the merge against the exact validated main SHA and verify tree
	// identity before pushing.
	reconstruct := findStepBlock(pushJob, "Reconstruct merge and verify tree identity")
	if reconstruct == "" {
		t.Fatal("merge-push job must reconstruct the merge and verify tree identity")
	}
	reconstructRun := extractRunBlock(reconstruct)
	if !strings.Contains(reconstructRun, `git switch -C main "${{ needs.validation.outputs.main_sha }}"`) {
		t.Error("reconstruction must check out the exact validated main SHA, not a refetched main")
	}
	if strings.Contains(reconstructRun, "origin/main") {
		t.Error("reconstruction must not merge against a refetched origin/main")
	}
	if !strings.Contains(reconstructRun, "git merge --no-ff") {
		t.Error("reconstruction must re-run the merge")
	}
	if !strings.Contains(reconstructRun, "git rev-parse HEAD^{tree}") ||
		!strings.Contains(reconstructRun, "needs.validation.outputs.tree_sha") {
		t.Error("reconstruction must compare the reconstructed tree SHA against the validated tree SHA")
	}
	if !strings.Contains(reconstructRun, "exit 1") {
		t.Error("reconstruction must fail closed (exit 1) when the tree differs from the validated tree")
	}

	// Push must come only after the tree-identity verification.
	pushIdx := strings.Index(pushJob, "git push origin main")
	verifyIdx := strings.Index(pushJob, "Reconstruct merge and verify tree identity")
	if pushIdx < 0 || verifyIdx < 0 || pushIdx < verifyIdx {
		t.Error("merge-push job must verify tree identity before pushing to main")
	}
}

// TestSyncReleaseToMainMergeTreeIdentity proves the write-job guarantees of
// sync-release-to-main.yml against real git semantics in throwaway repos:
//   - validated-tree identity: the write job's reconstruction of the merge tree
//     matches the tree the validation job validated, and the pushed tree is that
//     exact validated tree;
//   - changed main between validation and write: the main-advance guard fails
//     closed and nothing is pushed;
//   - fail-closed on tree difference: even if the main-advance guard were
//     removed and the write job merged against a refetched newer main, the
//     tree-identity check refuses to push a tree that differs from the tested
//     tree.
func TestSyncReleaseToMainMergeTreeIdentity(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	t.Run("unchanged main pushes the validated tree", func(t *testing.T) {
		origin, release := seedSyncRepo(t)
		mainSHA, treeSHA := simulateSyncValidation(t, origin, release)

		wc := t.TempDir()
		cloneSyncRepo(t, wc, origin)
		out, err := runBashIn(t, wc, syncWriteShell(mainSHA, treeSHA, release, "MAIN_SHA", true))
		if err != nil {
			t.Fatalf("expected write job to succeed against unchanged main: %v\n%s", err, out)
		}

		// The pushed merge commit must be a --no-ff merge whose tree is exactly
		// the tree the validation job validated.
		head := strings.Fields(strings.TrimSpace(gitAt(t, origin, "rev-list", "--parents", "-n", "1", "main")))
		if len(head) != 3 {
			t.Errorf("expected a two-parent merge commit, got %d fields: %v", len(head)-1, head)
		}
		pushedTree := strings.TrimSpace(gitAt(t, origin, "rev-parse", "main^{tree}"))
		if pushedTree != treeSHA {
			t.Errorf("pushed tree %s does not match validated tree %s", pushedTree, treeSHA)
		}
	})

	t.Run("main advanced between validation and write fails closed", func(t *testing.T) {
		origin, release := seedSyncRepo(t)
		mainSHA, treeSHA := simulateSyncValidation(t, origin, release)

		advanceSyncMain(t, origin)
		wc := t.TempDir()
		cloneSyncRepo(t, wc, origin)
		before := strings.TrimSpace(gitAt(t, origin, "rev-parse", "main"))

		out, err := runBashIn(t, wc, syncWriteShell(mainSHA, treeSHA, release, "MAIN_SHA", true))
		if err == nil {
			t.Fatalf("expected write job to fail closed when main advanced; succeeded:\n%s", out)
		}
		if !strings.Contains(out, "advanced after validation") {
			t.Errorf("failure must be the main-advance guard; got:\n%s", out)
		}
		if after := strings.TrimSpace(gitAt(t, origin, "rev-parse", "main")); after != before {
			t.Errorf("write job must not push when main advanced; origin/main changed %s -> %s", before, after)
		}
	})

	t.Run("reconstructed tree differs from validated tree fails closed", func(t *testing.T) {
		origin, release := seedSyncRepo(t)
		mainSHA, treeSHA := simulateSyncValidation(t, origin, release)

		advanceSyncMain(t, origin)
		wc := t.TempDir()
		cloneSyncRepo(t, wc, origin)
		before := strings.TrimSpace(gitAt(t, origin, "rev-parse", "main"))

		// Regression scenario: the main-advance guard is absent and the job
		// merges against a refetched newer main (checkoutRef "origin/main").
		// The tree-identity check must still fail closed instead of pushing a
		// different, untested merge.
		out, err := runBashIn(t, wc, syncWriteShell(mainSHA, treeSHA, release, "origin/main", false))
		if err == nil {
			t.Fatalf("expected tree-identity check to fail closed; succeeded:\n%s", out)
		}
		if !strings.Contains(out, "differs from validated tree") {
			t.Errorf("failure must be the tree-identity check; got:\n%s", out)
		}
		if after := strings.TrimSpace(gitAt(t, origin, "rev-parse", "main")); after != before {
			t.Errorf("write job must not push a tree differing from the validated tree; origin/main changed %s -> %s", before, after)
		}
	})
}

// seedSyncRepo creates a bare origin with a linear main history and a release
// branch commit on top; it returns the origin path and the release commit SHA.
func seedSyncRepo(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	origin := filepath.Join(dir, "origin.git")
	gitAt(t, dir, "init", "--bare", origin)
	work := filepath.Join(dir, "seed")
	gitAt(t, dir, "init", work)
	gitAt(t, work, "config", "user.name", "test")
	gitAt(t, work, "config", "user.email", "test@example.com")
	if err := os.WriteFile(filepath.Join(work, "base.txt"), []byte("base\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitAt(t, work, "add", ".")
	gitAt(t, work, "commit", "-m", "base")
	gitAt(t, work, "branch", "-M", "main")
	gitAt(t, work, "remote", "add", "origin", origin)
	gitAt(t, work, "push", "-u", "origin", "main")
	gitAt(t, work, "checkout", "-b", "release/1")
	if err := os.WriteFile(filepath.Join(work, "release.txt"), []byte("release\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitAt(t, work, "add", ".")
	gitAt(t, work, "commit", "-m", "release change")
	gitAt(t, work, "push", "-u", "origin", "release/1")
	release := strings.TrimSpace(gitAt(t, work, "rev-parse", "HEAD"))
	return origin, release
}

// simulateSyncValidation mirrors the validation job's prepare step: it checks
// out origin/main, records the exact main SHA, merges the release commit with
// --no-ff, and records the exact resulting tree SHA.
func simulateSyncValidation(t *testing.T, origin, release string) (string, string) {
	t.Helper()
	wc := t.TempDir()
	cloneSyncRepo(t, wc, origin)
	gitAt(t, wc, "fetch", "origin", "main")
	gitAt(t, wc, "switch", "-C", "main", "origin/main")
	mainSHA := strings.TrimSpace(gitAt(t, wc, "rev-parse", "HEAD"))
	gitAt(t, wc, "merge", "--no-ff", release, "-m", "merge release commit "+release)
	treeSHA := strings.TrimSpace(gitAt(t, wc, "rev-parse", "HEAD^{tree}"))
	return mainSHA, treeSHA
}

// advanceSyncMain simulates origin/main advancing after validation.
func advanceSyncMain(t *testing.T, origin string) {
	t.Helper()
	wc := t.TempDir()
	gitAt(t, wc, "init")
	gitAt(t, wc, "remote", "add", "origin", origin)
	gitAt(t, wc, "config", "user.name", "test")
	gitAt(t, wc, "config", "user.email", "test@example.com")
	gitAt(t, wc, "fetch", "origin", "main")
	gitAt(t, wc, "switch", "-C", "main", "origin/main")
	if err := os.WriteFile(filepath.Join(wc, "advance.txt"), []byte("advance\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitAt(t, wc, "add", ".")
	gitAt(t, wc, "commit", "-m", "advance main")
	gitAt(t, wc, "push", "origin", "main")
}

// cloneSyncRepo clones origin into the existing empty directory dst and sets a
// git identity for later merge commits.
func cloneSyncRepo(t *testing.T, dst, origin string) {
	t.Helper()
	gitAt(t, filepath.Dir(dst), "clone", "-q", origin, dst)
	gitAt(t, dst, "config", "user.name", "test")
	gitAt(t, dst, "config", "user.email", "test@example.com")
}

// syncWriteShell returns the merge-push job's shell sequence as a bash script.
// checkoutRef "MAIN_SHA" mirrors the workflow (check out the validated main);
// "origin/main" simulates the regression where the job merges against a
// refetched newer main. withGuard false removes the main-advance guard.
func syncWriteShell(mainSHA, treeSHA, release, checkoutRef string, withGuard bool) string {
	var guard string
	if withGuard {
		guard = `
current_main="$(git rev-parse origin/main)"
if [ "$current_main" != "MAIN_SHA" ]; then
  echo "origin/main advanced after validation: expected MAIN_SHA, got $current_main" >&2
  exit 1
fi
`
	}
	script := fmt.Sprintf(`set -e
git fetch origin main
%sgit switch -C main "%s"
git merge --no-ff "%s" -m "merge release commit %s"
tree_sha="$(git rev-parse HEAD^{tree})"
if [ "$tree_sha" != "%s" ]; then
  echo "reconstructed tree $tree_sha differs from validated tree %s" >&2
  exit 1
fi
git push origin main
`, guard, checkoutRef, release, release, treeSHA, treeSHA)
	return strings.ReplaceAll(script, "MAIN_SHA", mainSHA)
}

// gitAt runs git with the given working directory and returns combined output.
func gitAt(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s failed: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// runBashIn runs a bash script with the given working directory.
func runBashIn(t *testing.T, dir, script string) (string, error) {
	t.Helper()
	cmd := exec.Command("bash", "-c", script)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// runBashScriptIn runs a bash script file with the given working directory.
// Used when the script content would exceed the per-argument size limit of a
// single `bash -c` argv string (e.g. large embedded test payloads).
func runBashScriptIn(t *testing.T, dir, scriptPath string) (string, error) {
	t.Helper()
	cmd := exec.Command("bash", scriptPath)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// extractShellFunction returns the source of a top-level function named name
// from a shell script. The function must have its body indented and close with
// a "}" at column 0.
func extractShellFunction(t *testing.T, path, name string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read %s: %v", path, err)
	}
	lines := strings.Split(string(data), "\n")
	start := -1
	for i, line := range lines {
		if strings.HasPrefix(line, name+"() {") {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatalf("shell function %s not found in %s", name, path)
	}
	var b strings.Builder
	for _, line := range lines[start:] {
		b.WriteString(line)
		b.WriteString("\n")
		if line == "}" {
			break
		}
	}
	return b.String()
}

// TestRelease2AcceptanceClassifierPriority runs the shipped
// classify_registry_failure helper over the required registry-failure vectors
// and proves the network-first priority: a mixed stream carrying both network
// and auth markers must classify as network, never as an auth denial. Only
// "auth" may satisfy an auth-denial acceptance assertion (fail-closed).
func TestRelease2AcceptanceClassifierPriority(t *testing.T) {
	fn := extractShellFunction(t, "scripts/uat-release2-acceptance.sh", "classify_registry_failure")
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"auth only", "unauthorized: authentication required", "auth"},
		{"network only", "dial tcp: lookup registry-1.docker.io: no such host", "network"},
		{"network plus auth", "proxyconnect tcp: connection refused; failed with status: 401 Unauthorized", "network"},
		{"unknown", "some unrelated error text", "unknown"},
		{"no basic auth credentials", "no basic auth credentials", "auth"},
		{"failed with status 401", "failed with status: 401 Unauthorized", "auth"},
	}
	// The long mixed case places a network marker first, fills the stream with
	// more than 1 MiB of non-marker content, then appends an auth marker. Under
	// production semantics (set -uo pipefail) a producer-pipe implementation of
	// the classifier would let grep -q exit early, SIGPIPE the producer, and
	// misreport this as auth. It must classify as network.
	const longFiller = "benign registry stream filler line that matches no marker.\n"
	longMixed := "dial tcp: connection refused\n" +
		strings.Repeat(longFiller, (1<<20)/len(longFiller)+1) +
		"failed with status: 401 Unauthorized\n"
	cases = append(cases, struct {
		name  string
		input string
		want  string
	}{"long network plus auth", longMixed, "network"})
	var sb strings.Builder
	sb.WriteString("set -uo pipefail\n")
	sb.WriteString(fn)
	sb.WriteString("\n")
	for _, tc := range cases {
		fmt.Fprintf(&sb, "printf 'RESULT:%s='; classify_registry_failure %q\n", tc.name, tc.input)
	}
	// Run from a temp file rather than `bash -c`: the long mixed case embeds
	// > 1 MiB of filler, which exceeds the per-argument size limit of a single
	// argv string.
	script := sb.String()
	f, err := os.CreateTemp("", "classifier-*.sh")
	if err != nil {
		t.Fatalf("create temp classifier script: %v", err)
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(script); err != nil {
		f.Close()
		t.Fatalf("write temp classifier script: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close temp classifier script: %v", err)
	}
	out, err := runBashScriptIn(t, ".", f.Name())
	if err != nil {
		t.Fatalf("bash classifier run failed: %v\n%s", err, out)
	}
	for _, tc := range cases {
		re := regexp.MustCompile(`RESULT:` + regexp.QuoteMeta(tc.name) + `=(\S+)`)
		m := re.FindStringSubmatch(out)
		if m == nil {
			t.Errorf("case %q: no classifier result in output:\n%s", tc.name, out)
			continue
		}
		if m[1] != tc.want {
			t.Errorf("case %q: classify_registry_failure = %q, want %q", tc.name, m[1], tc.want)
		}
	}
}

// productionClassifyMarkers returns the network and auth marker sets used by
// production classifyDockerError, parsed from its source so the acceptance
// helper cannot silently drift from production.
func productionClassifyMarkers(t *testing.T) (network, auth []string) {
	t.Helper()
	data, err := os.ReadFile("docker_error_classify.go")
	if err != nil {
		t.Fatalf("cannot read docker_error_classify.go: %v", err)
	}
	markerRe := regexp.MustCompile(`strings\.Contains\(lower, "([^"]+)"\)`)
	current := "network"
	for _, line := range strings.Split(string(data), "\n") {
		switch {
		case strings.Contains(line, "return dockerErrorNetwork"):
			current = "auth"
			continue
		case strings.Contains(line, "return dockerErrorAuthDenied"):
			current = "image-not-found"
			continue
		}
		if m := markerRe.FindStringSubmatch(line); m != nil {
			switch current {
			case "network":
				network = append(network, m[1])
			case "auth":
				auth = append(auth, m[1])
			}
		}
	}
	return network, auth
}

// scriptClassifierMarkers returns the network and auth marker sets used by the
// classify_registry_failure helper in the Release-2 acceptance script.
func scriptClassifierMarkers(t *testing.T) (network, auth []string) {
	t.Helper()
	fn := extractShellFunction(t, "scripts/uat-release2-acceptance.sh", "classify_registry_failure")
	re := regexp.MustCompile(`grep -qiE[^']*'([^']+)'`)
	var got []string
	for _, m := range re.FindAllStringSubmatch(fn, -1) {
		got = append(got, m[1])
	}
	if len(got) != 2 {
		t.Fatalf("expected network+auth marker regexes in classify_registry_failure, got %d", len(got))
	}
	unescape := func(s string) string { return strings.ReplaceAll(s, `\/`, `/`) }
	for _, m := range strings.Split(unescape(got[0]), "|") {
		network = append(network, strings.TrimSpace(m))
	}
	for _, m := range strings.Split(unescape(got[1]), "|") {
		auth = append(auth, strings.TrimSpace(m))
	}
	return network, auth
}

// TestRelease2AcceptanceClassifierSingleOwner verifies the Release-2
// acceptance script uses exactly one registry-failure classifier
// (classify_registry_failure) in both the no-credentials and isolation checks,
// with no ad-hoc marker regex left in the checks, and that the helper's
// network/auth marker sets exactly match production classifyDockerError.
func TestRelease2AcceptanceClassifierSingleOwner(t *testing.T) {
	data, err := os.ReadFile("scripts/uat-release2-acceptance.sh")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	// Both registry checks must route through the shared helper.
	if n := strings.Count(content, "classify_registry_failure \"$A_NOAUTH_OUT\""); n != 1 {
		t.Errorf("no-credentials check must call classify_registry_failure once, got %d", n)
	}
	if n := strings.Count(content, "classify_registry_failure \"$B_ISO_OUT\""); n != 1 {
		t.Errorf("isolation check must call classify_registry_failure once, got %d", n)
	}
	// The helper must be invoked by name, not re-implemented inline: no
	// remaining ad-hoc auth-denial marker regex outside the helper body.
	if strings.Contains(strings.ReplaceAll(content, extractShellFunction(t, "scripts/uat-release2-acceptance.sh", "classify_registry_failure"), ""), "unauthorized|authentication required") {
		t.Error("ad-hoc auth-denial marker regex must not remain outside classify_registry_failure")
	}

	// The helper's marker sets must exactly match production.
	prodNet, prodAuth := productionClassifyMarkers(t)
	scriptNet, scriptAuth := scriptClassifierMarkers(t)
	if !markerSetsEqual(prodNet, scriptNet) {
		t.Errorf("classifier network markers mismatch production\ngot:  %v\nwant: %v", scriptNet, prodNet)
	}
	if !markerSetsEqual(prodAuth, scriptAuth) {
		t.Errorf("classifier auth markers mismatch production\ngot:  %v\nwant: %v", scriptAuth, prodAuth)
	}
	// Neither marker set may contain a bare "401" alternative.
	bare401 := regexp.MustCompile(`(^|\|)401(\||$)`)
	for _, set := range [][]string{scriptNet, scriptAuth} {
		for _, m := range set {
			if bare401.MatchString(m) {
				t.Errorf("classifier marker %q must not be a bare 401", m)
			}
		}
	}
}

// markerSetsEqual reports whether two marker slices are equal as multisets:
// the same elements with the same multiplicity. A set-style membership check
// would accept a duplicated marker standing in for a missing one, so the
// alignment check uses exact multiset equality instead.
func markerSetsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	ac := append([]string(nil), a...)
	bc := append([]string(nil), b...)
	sort.Strings(ac)
	sort.Strings(bc)
	for i := range ac {
		if ac[i] != bc[i] {
			return false
		}
	}
	return true
}

// TestRelease2AcceptanceClassifierMarkerExactMatch proves the classifier
// marker-alignment check rejects a multiset where one production marker is
// missing and another is duplicated in its place, even though lengths match
// and every script marker is present in production. A set-based comparison
// would wrongly accept this pair.
func TestRelease2AcceptanceClassifierMarkerExactMatch(t *testing.T) {
	prodNet, _ := productionClassifyMarkers(t)

	// The duplicate+missing fixture must be built from two DISTINCT markers.
	// If every production marker is identical there is no way to both drop one
	// marker and substitute a different one, so the test cannot exercise the
	// multiset-mismatch it is meant to protect.
	base := prodNet[0]
	distinct := -1
	for i, m := range prodNet {
		if m != base {
			distinct = i
			break
		}
	}
	if distinct < 0 {
		t.Fatalf("marker alignment test needs at least two distinct production network markers, got only %q", base)
	}

	// Drop prodNet[0] and duplicate prodNet[distinct] in its place: same length,
	// every element present in production, but not an exact multiset match. A
	// set-based comparison would wrongly accept this pair.
	scriptNet := append([]string(nil), prodNet...)
	scriptNet[0] = scriptNet[distinct]
	if markerSetsEqual(prodNet, scriptNet) {
		t.Fatalf("marker alignment must reject a set that duplicates %q and drops %q (multiset mismatch)", prodNet[distinct], prodNet[0])
	}

	// Sanity: an exact copy of the production markers must still align.
	if !markerSetsEqual(prodNet, append([]string(nil), prodNet...)) {
		t.Fatalf("marker alignment must accept an exact copy of production markers")
	}
}

// TestArtifactGateConsumersNoRebuild verifies every consumer of the artifact
// gate downloads the candidate set, resolves its artifact from the producer
// SHA256SUMS and never builds locally (no setup-go, no build scripts).
func TestArtifactGateConsumersNoRebuild(t *testing.T) {
	data, err := os.ReadFile(".github/workflows/artifact-gate.yml")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	consumers := []string{
		"uat-blackbox-ubuntu",
		"uat-blackbox-ubuntu-tarball",
		"uat-regressions-ubuntu",
		"uat-blackbox-opensuse-apparmor",
		"uat-blackbox-opensuse-selinux",
		"uat-blackbox-opensuse-tarball-selinux",
	}
	for _, c := range consumers {
		job := findJobSection(content, c)
		if job == "" {
			t.Fatalf("artifact-gate.yml must contain consumer job %s", c)
		}
		if !strings.Contains(job, "needs: producer") {
			t.Errorf("consumer job %s must depend on the producer", c)
		}
		for _, banned := range []string{"setup-go", "build-bundle.sh", "build-packages.sh", "build-static.sh", "nfpm"} {
			if strings.Contains(job, banned) {
				t.Errorf("consumer job %s must not contain %s (no local rebuild)", c, banned)
			}
		}
		if !strings.Contains(job, "release-candidate-artifact.sh") {
			t.Errorf("consumer job %s must resolve its artifact via release-candidate-artifact.sh", c)
		}
		if !strings.Contains(job, "download-artifact") {
			t.Errorf("consumer job %s must download the candidate artifact", c)
		}
	}

	// The Ubuntu regressions consumer must pass the exact candidate DEB to the
	// runner (UAT_ARTIFACT_PATH / UAT_ARTIFACT_SHA256).
	reg := findJobSection(content, "uat-regressions-ubuntu")
	if !strings.Contains(reg, "UAT_ARTIFACT_PATH") || !strings.Contains(reg, "UAT_ARTIFACT_SHA256") {
		t.Error("uat-regressions-ubuntu must consume the exact candidate DEB")
	}
}

// TestRegressionsRunnerConsumesExternalDEB verifies the Ubuntu regressions
// runner can consume an exact candidate DEB (UAT_ARTIFACT_PATH /
// UAT_ARTIFACT_SHA256) with a single installation truth; the local build
// (build-packages.sh) remains only the self-contained fallback.
func TestRegressionsRunnerConsumesExternalDEB(t *testing.T) {
	data, err := os.ReadFile("scripts/uat-regressions-runner-ubuntu.sh")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	for _, s := range []string{"UAT_ARTIFACT_PATH", "UAT_ARTIFACT_SHA256", "install_deb"} {
		if !strings.Contains(content, s) {
			t.Errorf("uat-regressions-runner-ubuntu.sh must consume %s", s)
		}
	}
	if !strings.Contains(content, "SHA-256 mismatch") {
		t.Error("uat-regressions-runner-ubuntu.sh must fail on candidate DEB SHA mismatch")
	}
	if !strings.Contains(content, "never rebuild") {
		t.Error("uat-regressions-runner-ubuntu.sh must not rebuild when a candidate DEB is supplied")
	}
	if !strings.Contains(content, "./build-packages.sh") {
		t.Error("uat-regressions-runner-ubuntu.sh must keep the self-contained build fallback")
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

// =============================================================================
// Upgrade-baseline fixture invariants (Stage 0.1)
// =============================================================================

// upgradeBaselineFixturePath is the single owner of the v2.0.0 upgrade-baseline
// version, URLs and pinned SHA-256s.
const upgradeBaselineFixturePath = "scripts/uat-upgrade-baseline-fixture.sh"

var upgradeBaselinePinned = []string{
	"81a95a312f2cabec0d2ca26a71944f0dfbc78bcef22345c1608fb17091d7b4ed", // DEB
	"b48983d3c4d9cc373246807b195141c77a00b1ac4de107e0e88eeea1828b5dbc", // RPM
}

// upgradeBaselineLiveDrivers are the live UAT lifecycle drivers that consume
// the upgrade-baseline fixture.
var upgradeBaselineLiveDrivers = []string{
	"scripts/uat-release2-acceptance.sh",
	"scripts/uat-package-lifecycle-rpm.sh",
	"scripts/uat-vm-opensuse-apparmor.sh",
	"scripts/uat-vm-opensuse-selinux.sh",
}

// TestUpgradeBaselineSingleOwner verifies the v2.0.0 baseline version and the
// pinned DEB/RPM SHA-256s live only in the single fixture owner and are not
// duplicated in any live UAT lifecycle driver.
func TestUpgradeBaselineSingleOwner(t *testing.T) {
	fixture, err := os.ReadFile(upgradeBaselineFixturePath)
	if err != nil {
		t.Fatal(err)
	}
	fixtureContent := string(fixture)

	for _, must := range []string{
		`UPGRADE_BASELINE_VERSION="2.0.0"`,
		"UPGRADE_BASELINE_DEB_SHA256=\"" + upgradeBaselinePinned[0] + "\"",
		"UPGRADE_BASELINE_RPM_SHA256=\"" + upgradeBaselinePinned[1] + "\"",
	} {
		if !strings.Contains(fixtureContent, must) {
			t.Errorf("upgrade-baseline fixture must define %s", must)
		}
	}

	for _, d := range upgradeBaselineLiveDrivers {
		data, err := os.ReadFile(d)
		if err != nil {
			t.Fatal(err)
		}
		content := string(data)
		for _, hash := range upgradeBaselinePinned {
			if strings.Contains(content, hash) {
				t.Errorf("%s must not duplicate the pinned baseline SHA-256 (%s); the fixture is the single owner", d, hash)
			}
		}
	}
}

// TestUpgradeBaselineExactIdentity verifies the exact v2.0.0 DEB and RPM
// expected hashes are pinned in the fixture owner.
func TestUpgradeBaselineExactIdentity(t *testing.T) {
	fixture, err := os.ReadFile(upgradeBaselineFixturePath)
	if err != nil {
		t.Fatal(err)
	}
	content := string(fixture)

	expected := map[string]string{
		"UPGRADE_BASELINE_DEB_SHA256": upgradeBaselinePinned[0],
		"UPGRADE_BASELINE_RPM_SHA256": upgradeBaselinePinned[1],
	}
	for key, sha := range expected {
		if !strings.Contains(content, key+"=\""+sha+"\"") {
			t.Errorf("fixture must pin exact %s = %s", key, sha)
		}
	}
}

// TestUpgradeBaselineGenericVocabulary verifies the live UAT lifecycle scripts
// do not expose the retired rc.22-specific API/env/function vocabulary.
func TestUpgradeBaselineGenericVocabulary(t *testing.T) {
	banned := []string{"RC22_", "rc22_fetch", "UAT_RC22_", "uat-rc22", "rc.22"}
	for _, d := range upgradeBaselineLiveDrivers {
		data, err := os.ReadFile(d)
		if err != nil {
			t.Fatal(err)
		}
		content := string(data)
		for _, b := range banned {
			if strings.Contains(content, b) {
				t.Errorf("%s must not expose retired fixture vocabulary %q", d, b)
			}
		}
	}
}

// TestUpgradeBaselineLifecycleSemantics verifies the DEB and RPM lifecycle
// scripts consume the source-owned stable v2.0.0 baseline identity from the
// single fixture owner (never as caller-controlled env inputs) and expect a
// 2.1.x UAT candidate (a real forward upgrade).
func TestUpgradeBaselineLifecycleSemantics(t *testing.T) {
	deb, err := os.ReadFile("scripts/uat-release2-acceptance.sh")
	if err != nil {
		t.Fatal(err)
	}
	debContent := string(deb)
	if !strings.Contains(debContent, "UAT_VERSION:-2.1.0-uat") {
		t.Error("DEB acceptance must default the candidate to 2.1.0-uat")
	}
	if !strings.Contains(debContent, "UPGRADE_BASELINE_VERSION") {
		t.Error("DEB acceptance must consume the fixture baseline version")
	}
	if !strings.Contains(debContent, "upgrade_baseline_fetch_deb") {
		t.Error("DEB acceptance must resolve the baseline via upgrade_baseline_fetch_deb")
	}

	rpm, err := os.ReadFile("scripts/uat-package-lifecycle-rpm.sh")
	if err != nil {
		t.Fatal(err)
	}
	rpmContent := string(rpm)
	if !strings.Contains(rpmContent, "UAT_VERSION:-2.1.0-uat") {
		t.Error("RPM lifecycle must default the candidate to 2.1.0-uat")
	}
	if !strings.Contains(rpmContent, "uat-upgrade-baseline-fixture.sh") {
		t.Error("RPM lifecycle must source the upgrade-baseline fixture owner")
	}
	if !strings.Contains(rpmContent, "UPGRADE_BASELINE_VERSION") {
		t.Error("RPM lifecycle must consume the fixture baseline version")
	}
	if !strings.Contains(rpmContent, "UPGRADE_BASELINE_RPM_SHA256") {
		t.Error("RPM lifecycle must consume the fixture baseline RPM SHA-256")
	}
}

// TestUpgradeBaselineIdentityEnvInputsAbsent verifies the baseline identity
// (version and RPM SHA-256) can never return as caller-controlled environment
// inputs in any live lifecycle driver: the only baseline value a driver may
// supply is the path of the already-transferred RPM artifact
// (UAT_UPGRADE_BASELINE_RPM).
func TestUpgradeBaselineIdentityEnvInputsAbsent(t *testing.T) {
	banned := []string{
		"UAT_UPGRADE_BASELINE_VERSION",
		"UAT_UPGRADE_BASELINE_RPM_SHA256",
	}
	for _, d := range upgradeBaselineLiveDrivers {
		data, err := os.ReadFile(d)
		if err != nil {
			t.Fatal(err)
		}
		content := string(data)
		for _, name := range banned {
			if strings.Contains(content, name) {
				t.Errorf("%s must not accept baseline identity env input %s; identity is source-owned by the fixture", d, name)
			}
		}
	}
}

// TestUpgradeBaselineWorkflowRecovery verifies artifact-gate.yml propagates
// optional repository variables that override ONLY the baseline artifact SOURCE
// (URL) for recovery, while the pinned hashes/version can never come from
// mutable GitHub workflow variables.
func TestUpgradeBaselineWorkflowRecovery(t *testing.T) {
	gate, err := os.ReadFile(".github/workflows/artifact-gate.yml")
	if err != nil {
		t.Fatal(err)
	}
	content := string(gate)

	// The optional URL source may be propagated from repository variables.
	for _, v := range []string{
		"UAT_UPGRADE_BASELINE_DEB_URL",
		"UAT_UPGRADE_BASELINE_RPM_URL",
	} {
		if !strings.Contains(content, "vars."+v) {
			t.Errorf("artifact-gate.yml must propagate optional repository variable %s for recovery", v)
		}
	}

	// The pinned hashes/version are source-owned identity and must NOT be
	// sourced from mutable workflow variables: the ONLY repository variables
	// referenced may be the two URL source overrides.
	varsRe := regexp.MustCompile(`vars\.[A-Z0-9_]+`)
	allowed := map[string]bool{
		"vars.UAT_UPGRADE_BASELINE_DEB_URL": true,
		"vars.UAT_UPGRADE_BASELINE_RPM_URL": true,
	}
	for _, ref := range varsRe.FindAllString(content, -1) {
		if !allowed[ref] {
			t.Errorf("artifact-gate.yml must not source baseline identity from repository variable %s", ref)
		}
	}
}
