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

func TestFrameworkParseErrorUsageDoubleDash(t *testing.T) {
	runCount := 0
	cmd := makeTestLeaf(&runCount)
	var stdout, stderr bytes.Buffer
	cmd.dispatch([]string{"--bogus-flag"}, []string{}, &stdout, &stderr)

	stderrStr := stderr.String()

	// The usage output must use double-dash for long options.
	if strings.Contains(stderrStr, "-flag") && !strings.Contains(stderrStr, "--flag") {
		t.Errorf("parse error usage must use -- for long options, got: %s", stderrStr)
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

func TestBlackBoxUnknownFlagDoubleDashUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"run", "--bogus-flag"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit code 2, got %d", code)
	}

	stderrStr := stderr.String()

	// Verify usage shows --image, not -image
	if strings.Contains(stderrStr, "-image") && !strings.Contains(stderrStr, "--image") {
		t.Errorf("parse error usage must use -- for long options, got: %s", stderrStr)
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

// TestBlackBoxMissingPositionalArg verifies a missing required positional
// argument yields a semantic error plus the specific command's Usage, exit 2.
func TestBlackBoxMissingPositionalArg(t *testing.T) {
	for _, cmd := range [][]string{
		{"credential", "list"},
		{"principal", "show"},
		{"pull"},
	} {
		var stdout, stderr bytes.Buffer
		code := runCommandWithWriters(cmd, &stdout, &stderr)
		if code != 2 {
			t.Errorf("%v: expected exit code 2, got %d", cmd, code)
		}
		out := stderr.String()
		if !strings.Contains(out, "missing required argument") {
			t.Errorf("%v: expected missing-argument error, got: %s", cmd, out)
		}
		if !strings.Contains(out, "Usage:") {
			t.Errorf("%v: expected Usage line, got: %s", cmd, out)
		}
	}
}

// TestBlackBoxTooManyPositionalArgs verifies exceeding MaxPosArgs yields a
// semantic error plus the specific command's Usage, exit 2.
func TestBlackBoxTooManyPositionalArgs(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"principal", "show", "alice", "field", "extra"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit code 2, got %d", code)
	}
	out := stderr.String()
	if !strings.Contains(out, "too many arguments") {
		t.Errorf("expected too-many-arguments error, got: %s", out)
	}
	if !strings.Contains(out, "Usage:") {
		t.Errorf("expected Usage line, got: %s", out)
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

// --- Release 2 help regression tests ---

func TestHelpNoWorkspaceRoot(t *testing.T) {
	// Root help must NOT expose workspace-root.
	var stdout, stderr bytes.Buffer
	rootCommand.dispatch([]string{"--help"}, []string{}, &stdout, &stderr)
	if strings.Contains(stdout.String(), "workspace-root") {
		t.Error("root help must NOT expose workspace-root")
	}
}

func TestHelpInitMACLifecycleContract(t *testing.T) {
	// init help must describe the correct MAC lifecycle contract:
	// system mode has authorization ceiling + session-creation MAC preparation;
	// user mode requires no MAC preparation; init never prepares MAC state.
	var stdout, stderr bytes.Buffer
	initCommand.dispatch([]string{"--help"}, []string{}, &stdout, &stderr)
	helpText := stdout.String()

	// Must describe system mode and user mode.
	if !strings.Contains(helpText, "System mode") {
		t.Error("init help must describe system mode")
	}
	if !strings.Contains(helpText, "User mode") {
		t.Error("init help must describe user mode")
	}

	// Must describe the allowed root as the authorization ceiling.
	if !strings.Contains(helpText, "authorization ceiling") {
		t.Error("init help must describe the allowed root as the authorization ceiling")
	}

	// Must state that system-mode MAC preparation happens at session creation.
	if !strings.Contains(helpText, "session") {
		t.Error("init help must mention session lifecycle for MAC preparation")
	}

	// Must state that user mode requires no MAC preparation.
	if !strings.Contains(helpText, "No MAC preparation") {
		t.Error("init help must state that user mode requires no MAC preparation")
	}

	// Must NOT claim that init prepares MAC state.
	if strings.Contains(helpText, "prepared for the active MAC backend") {
		t.Error("init help must not claim that init prepares the active MAC backend")
	}
	// Must NOT direct users to config allowed-root add for MAC preparation.
	if strings.Contains(helpText, "config allowed-root add PATH") {
		t.Error("init help must not direct users to config allowed-root add for MAC preparation")
	}
}

func TestHelpReloadUsesAllowedRoots(t *testing.T) {
	// reload help must use allowed_roots, not scalar allowed_root.
	var stdout, stderr bytes.Buffer
	reloadCommand.dispatch([]string{"--help"}, []string{}, &stdout, &stderr)
	if !strings.Contains(stdout.String(), "allowed_roots") {
		t.Error("reload help must use allowed_roots")
	}
	if strings.Contains(stdout.String(), "allowed_root") && !strings.Contains(stdout.String(), "allowed_roots") {
		t.Error("reload help must not use stale allowed_root")
	}
}

func TestHelpConfigAllowedRootGlobalCeiling(t *testing.T) {
	// config allowed-root help must describe the authorization ceiling
	// and must not claim that changing allowed_roots prepares MAC state.
	var stdout, stderr bytes.Buffer
	configAllowedRootCommand.dispatch([]string{"--help"}, []string{}, &stdout, &stderr)
	helpText := stdout.String()

	// Must describe the authorization ceiling.
	if !strings.Contains(helpText, "authorization") {
		t.Error("config allowed-root help must mention authorization")
	}

	// Must state that changing allowed_roots never prepares MAC state.
	if !strings.Contains(helpText, "never prepares MAC state") {
		t.Error("config allowed-root help must state that changing allowed_roots never prepares MAC state")
	}

	// Must describe system mode MAC at session creation.
	if !strings.Contains(helpText, "session creation") {
		t.Error("config allowed-root help must mention session creation for system-mode MAC")
	}

	// Must describe user mode.
	if !strings.Contains(helpText, "user mode") {
		t.Error("config allowed-root help must describe user mode")
	}

	// Must NOT mention workspace-root add.
	if strings.Contains(helpText, "workspace-root add") {
		t.Error("config allowed-root help must not mention workspace-root add")
	}
	// Must NOT claim that allowed-root add prepares MAC state.
	if strings.Contains(helpText, "prepares the active MAC backend") {
		t.Error("config allowed-root help must not claim that allowed-root add prepares MAC state")
	}
}
