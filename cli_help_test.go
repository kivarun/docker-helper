package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestServeHelpExitCode(t *testing.T) {
	exitCode := runCommand([]string{"serve", "--help"})
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}
}

func TestServeHelpShortFlag(t *testing.T) {
	exitCode := runCommand([]string{"serve", "-h"})
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}
}

func TestInitHelpExitCode(t *testing.T) {
	exitCode := runCommand([]string{"init", "--help"})
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}
}

func TestInitHelpShortFlag(t *testing.T) {
	exitCode := runCommand([]string{"init", "-h"})
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}
}

func TestInitHelpDoesNotCreateFiles(t *testing.T) {
	dir := t.TempDir()

	oldConfig := os.Getenv("XDG_CONFIG_HOME")
	oldState := os.Getenv("XDG_STATE_HOME")
	os.Setenv("XDG_CONFIG_HOME", dir)
	os.Setenv("XDG_STATE_HOME", dir)
	defer func() {
		os.Setenv("XDG_CONFIG_HOME", oldConfig)
		os.Setenv("XDG_STATE_HOME", oldState)
	}()

	_ = runCommand([]string{"init", "--help"})

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("cannot read dir: %v", err)
	}
	if len(entries) > 0 {
		t.Errorf("expected no files created, got %d entries", len(entries))
	}
}

func TestVersionHelpExitCode(t *testing.T) {
	exitCode := runCommand([]string{"version", "--help"})
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}
}

func TestVersionHelpShortFlag(t *testing.T) {
	exitCode := runCommand([]string{"version", "-h"})
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}
}

func TestSessionMissingSubcommandIncludesDelete(t *testing.T) {
	var stdout, stderr bytes.Buffer
	exitCode := runSessionCommandWithWriters([]string{}, &stdout, &stderr)
	if exitCode != 2 {
		t.Errorf("expected exit code 2, got %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "session subcommand required (create, list, delete)") {
		t.Errorf("expected 'session subcommand required (create, list, delete)' in stderr, got: %s", stderr.String())
	}
}

func TestServeHelpDoesNotAccessRuntimeDir(t *testing.T) {
	oldRuntime := os.Getenv("XDG_RUNTIME_DIR")
	os.Unsetenv("XDG_RUNTIME_DIR")
	defer os.Setenv("XDG_RUNTIME_DIR", oldRuntime)

	exitCode := runCommand([]string{"serve", "--help"})
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d (serve --help should not need XDG_RUNTIME_DIR)", exitCode)
	}
}

func TestInitHelpDoesNotCreateDirs(t *testing.T) {
	dir := t.TempDir()
	configHome := filepath.Join(dir, "nonexistent_config_home")
	stateHome := filepath.Join(dir, "nonexistent_state_home")

	oldConfig := os.Getenv("XDG_CONFIG_HOME")
	oldState := os.Getenv("XDG_STATE_HOME")
	os.Setenv("XDG_CONFIG_HOME", configHome)
	os.Setenv("XDG_STATE_HOME", stateHome)
	defer func() {
		os.Setenv("XDG_CONFIG_HOME", oldConfig)
		os.Setenv("XDG_STATE_HOME", oldState)
	}()

	exitCode := runCommand([]string{"init", "--help"})
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d (init --help should not create directories)", exitCode)
	}

	if _, err := os.Stat(configHome); !os.IsNotExist(err) {
		t.Error("init --help should not create config directory")
	}
	if _, err := os.Stat(stateHome); !os.IsNotExist(err) {
		t.Error("init --help should not create state directory")
	}
}
