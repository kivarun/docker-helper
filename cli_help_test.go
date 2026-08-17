package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- Framework unit tests (isolated, no global tree modification) ---

func makeTestLeaf(runCount *int) *Command {
	return &Command{
		Name:    "testleaf",
		Summary: "Test leaf command",
		Usage:   "docker-helper testleaf [--flag]",
		NewInvocation: func(fs *flag.FlagSet) Invocation {
			fs.Bool("flag", false, "Test flag")
			return Invocation{
				Validate: func() error { return nil },
				Run: func(stdout, stderr io.Writer) int {
					*runCount++
					fmt.Fprintln(stdout, "testleaf ran")
					return 0
				},
			}
		},
	}
}

func makeTestValidate(runCount *int) *Command {
	return &Command{
		Name:    "testvalidate",
		Summary: "Test validate command",
		Usage:   "docker-helper testvalidate --required",
		NewInvocation: func(fs *flag.FlagSet) Invocation {
			fs.String("required", "", "Required flag")
			return Invocation{
				Validate: func() error { return fmt.Errorf("--required is required") },
				Run: func(stdout, stderr io.Writer) int {
					*runCount++
					return 0
				},
			}
		},
	}
}

func TestFrameworkEmptyArgsCallsRun(t *testing.T) {
	runCount := 0
	cmd := makeTestLeaf(&runCount)
	inv := cmd.dispatch([]string{}, []string{}, &bytes.Buffer{}, &bytes.Buffer{})
	_ = inv
	if runCount != 1 {
		t.Errorf("expected Run called exactly once, got %d", runCount)
	}
}

func TestFrameworkHelpDoesNotCallRun(t *testing.T) {
	runCount := 0
	cmd := makeTestLeaf(&runCount)
	var stdout, stderr bytes.Buffer
	code := cmd.dispatch([]string{"--help"}, []string{}, &stdout, &stderr)
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
	if runCount != 0 {
		t.Errorf("expected Run NOT called for --help, got %d", runCount)
	}
	if !strings.Contains(stdout.String(), "Usage: docker-helper testleaf") {
		t.Errorf("expected help output, got: %s", stdout.String())
	}
}

func TestFrameworkHelpShortDoesNotCallRun(t *testing.T) {
	runCount := 0
	cmd := makeTestLeaf(&runCount)
	var stdout, stderr bytes.Buffer
	code := cmd.dispatch([]string{"-h"}, []string{}, &stdout, &stderr)
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
	if runCount != 0 {
		t.Errorf("expected Run NOT called for -h, got %d", runCount)
	}
}

func TestFrameworkParseErrorDoesNotCallRun(t *testing.T) {
	runCount := 0
	cmd := makeTestLeaf(&runCount)
	var stdout, stderr bytes.Buffer
	code := cmd.dispatch([]string{"--unknown"}, []string{}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit code 2, got %d", code)
	}
	if runCount != 0 {
		t.Errorf("expected Run NOT called for parse error, got %d", runCount)
	}
}

func TestFrameworkValidateErrorDoesNotCallRun(t *testing.T) {
	runCount := 0
	cmd := makeTestValidate(&runCount)
	var stdout, stderr bytes.Buffer
	code := cmd.dispatch([]string{}, []string{}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit code 2, got %d", code)
	}
	if runCount != 0 {
		t.Errorf("expected Run NOT called for validate error, got %d", runCount)
	}
	if !strings.Contains(stderr.String(), "--required is required") {
		t.Errorf("expected validate error in stderr, got: %s", stderr.String())
	}
}

// --- Black-box tests ---

func TestBlackBoxEmptyArgsRootHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{}, &stdout, &stderr)
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
	if !strings.Contains(stdout.String(), "docker-helper") {
		t.Errorf("expected root help output, got: %s", stdout.String())
	}
}

func TestBlackBoxBogusCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"bogus"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit code 2, got %d", code)
	}
	if !strings.Contains(stderr.String(), "unknown command") {
		t.Errorf("expected unknown command error, got: %s", stderr.String())
	}
}

func TestBlackBoxSessionUnknownSubcommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"session", "unknown"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit code 2, got %d", code)
	}
	if !strings.Contains(stderr.String(), "unknown") {
		t.Errorf("expected unknown subcommand error, got: %s", stderr.String())
	}
}

func TestBlackBoxServeServeUnexpected(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"serve", "serve"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit code 2, got %d", code)
	}
	if !strings.Contains(stderr.String(), "unexpected argument") {
		t.Errorf("expected unexpected argument error, got: %s", stderr.String())
	}
}

func TestBlackBoxVersionExact(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"version"}, &stdout, &stderr)
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
	expected := version + "\n"
	if stdout.String() != expected {
		t.Errorf("expected stdout %q, got %q", expected, stdout.String())
	}
	if stderr.Len() > 0 {
		t.Errorf("expected empty stderr, got: %s", stderr.String())
	}
}

func TestBlackBoxCreateHelpNoRun(t *testing.T) {
	t.Setenv("DOCKER_HELPER_CONFIG", "/nonexistent/config.json")
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"session", "create", "--workspace", "/tmp", "--help"}, &stdout, &stderr)
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
	if stderr.Len() > 0 {
		t.Errorf("expected empty stderr, got: %s", stderr.String())
	}
	if !strings.Contains(stdout.String(), "Usage: docker-helper session create") {
		t.Errorf("expected help output, got: %s", stdout.String())
	}
}

func TestBlackBoxSessionMissingSubcommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"session"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit code 2, got %d", code)
	}
	if !strings.Contains(stderr.String(), "session subcommand required") {
		t.Errorf("expected 'session subcommand required', got: %s", stderr.String())
	}
}

func TestHelpNoSideEffects(t *testing.T) {
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

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("cannot read dir: %v", err)
	}
	for _, e := range entries {
		if e.Name() == "docker-helper" {
			t.Error("expected no docker-helper dir created")
			break
		}
	}

	oldRuntime := os.Getenv("XDG_RUNTIME_DIR")
	os.Unsetenv("XDG_RUNTIME_DIR")
	defer os.Setenv("XDG_RUNTIME_DIR", oldRuntime)

	exitCode = runCommand([]string{"serve", "--help"})
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d (serve --help should not need XDG_RUNTIME_DIR)", exitCode)
	}
}

// --- Help subcommand tests ---

func TestHelpCommandEquivalence(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"help build", []string{"help", "build"}},
		{"help pull", []string{"help", "pull"}},
		{"help run", []string{"help", "run"}},
		{"help registry", []string{"help", "registry"}},
		{"help registry login", []string{"help", "registry", "login"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var helpOut, helpErr bytes.Buffer
			helpCode := runCommandWithWriters(tt.args, &helpOut, &helpErr)

			equivalentArgs := append(tt.args[1:], "--help")
			var flagOut, flagErr bytes.Buffer
			flagCode := runCommandWithWriters(equivalentArgs, &flagOut, &flagErr)

			if helpCode != 0 {
				t.Errorf("help %s: expected exit 0, got %d", strings.Join(tt.args, " "), helpCode)
			}
			if flagCode != 0 {
				t.Errorf("%s --help: expected exit 0, got %d", strings.Join(equivalentArgs, " "), flagCode)
			}
			if helpOut.String() != flagOut.String() {
				t.Errorf("help output mismatch\nhelp: %s\nflag: %s", helpOut.String(), flagOut.String())
			}
		})
	}
}

func TestHelpUnknownNestedCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"help", "registry", "wat"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit 2, got %d", code)
	}
	if !strings.Contains(stderr.String(), "unknown command") {
		t.Errorf("expected unknown command error, got: %s", stderr.String())
	}
}

// --- reload operator flags tests ---

func TestReloadSystemFlagAccepted(t *testing.T) {
	// --system should be accepted by the flag parser.
	// It will fail at connection time because there's no daemon,
	// but the flag itself should not be "unknown".
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"reload", "--system"}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected non-zero exit (no daemon running)")
	}
	if strings.Contains(stderr.String(), "unknown flag") {
		t.Fatalf("--system should not be unknown: %s", stderr.String())
	}
}

func TestReloadEndpointTokenFileAccepted(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	writeTestTokenFile(t, tokenPath, "test-token")

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"reload", "--endpoint", "http://127.0.0.1:52375", "--token-file", tokenPath}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected non-zero exit (no daemon running)")
	}
	if strings.Contains(stderr.String(), "unknown flag") {
		t.Fatalf("flags should not be unknown: %s", stderr.String())
	}
}

func TestReloadSystemEndpointMutuallyExclusive(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	writeTestTokenFile(t, tokenPath, "test-token")

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"reload", "--system", "--endpoint", "http://127.0.0.1:52375", "--token-file", tokenPath}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected non-zero exit")
	}
	if !strings.Contains(stderr.String(), "mutually exclusive") {
		t.Fatalf("expected mutual exclusion error: %s", stderr.String())
	}
}
