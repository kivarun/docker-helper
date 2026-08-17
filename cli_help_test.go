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

func TestBlackBoxRootHelpFlags(t *testing.T) {
	for _, args := range [][]string{{"-h"}, {"--help"}, {"help"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := runCommandWithWriters(args, &stdout, &stderr)
			if code != 0 {
				t.Errorf("expected exit code 0, got %d", code)
			}
			if !strings.Contains(stdout.String(), "docker-helper") {
				t.Errorf("expected root help output, got: %s", stdout.String())
			}
		})
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

func TestBlackBoxCreateWorkspaceFlagNoValue(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"session", "create", "--workspace", "--json"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit code 2, got %d", code)
	}
	if !strings.Contains(stderr.String(), "--workspace is required") {
		t.Errorf("expected --workspace error, got: %s", stderr.String())
	}
}

func TestBlackBoxDeleteIDFlagNoValue(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"session", "delete", "--id", "--json"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit code 2, got %d", code)
	}
	if !strings.Contains(stderr.String(), "--id is required") {
		t.Errorf("expected --id error, got: %s", stderr.String())
	}
}

func TestBlackBoxExactUsageStrings(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		expected string
	}{
		{"serve help", []string{"serve", "--help"}, "Usage: docker-helper serve"},
		{"init help", []string{"init", "--help"}, "Usage: docker-helper init [--allowed-root PATH]"},
		{"version help", []string{"version", "--help"}, "Usage: docker-helper version"},
		{"session list help", []string{"session", "list", "--help"}, "Usage: docker-helper session list [--system] [--endpoint ENDPOINT] [--token-file PATH] [--json]"},
		{"session create help", []string{"session", "create", "--help"}, "Usage: docker-helper session create [--system] [--endpoint ENDPOINT] [--token-file PATH] --workspace PATH [--json]"},
		{"session delete help", []string{"session", "delete", "--help"}, "Usage: docker-helper session delete [--system] [--endpoint ENDPOINT] [--token-file PATH] --id SESSION_ID [--json]"},
		{"session cleanup help", []string{"session", "cleanup", "--help"}, "Usage: docker-helper session cleanup"},
		{"principal list help", []string{"principal", "list", "--help"}, "Usage: docker-helper principal list [--system] [--endpoint ENDPOINT] [--token-file PATH] [--json]"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := runCommandWithWriters(tt.args, &stdout, &stderr)
			if code != 0 {
				t.Errorf("expected exit code 0, got %d", code)
			}
			firstLine := strings.Split(stdout.String(), "\n")[0]
			if firstLine != tt.expected {
				t.Errorf("expected first line %q, got %q", tt.expected, firstLine)
			}
		})
	}
}

func TestBlackBoxHelpContainsFlags(t *testing.T) {
	tests := []struct {
		name string
		args []string
		flag string
	}{
		{"session list help", []string{"session", "list", "--help"}, "--json"},
		{"session create help", []string{"session", "create", "--help"}, "--workspace"},
		{"session delete help", []string{"session", "delete", "--help"}, "--id"},
		{"principal list help", []string{"principal", "list", "--help"}, "--json"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := runCommandWithWriters(tt.args, &stdout, &stderr)
			if code != 0 {
				t.Errorf("expected exit code 0, got %d", code)
			}
			if !strings.Contains(stdout.String(), tt.flag) {
				t.Errorf("expected flag %q in output, got: %s", tt.flag, stdout.String())
			}
		})
	}
}

func TestBlackBoxExactlyOneFlagsSection(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"root help", []string{}},
		{"root --help", []string{"--help"}},
		{"session help", []string{"session", "--help"}},
		{"serve help", []string{"serve", "--help"}},
		{"init help", []string{"init", "--help"}},
		{"version help", []string{"version", "--help"}},
		{"session list help", []string{"session", "list", "--help"}},
		{"session create help", []string{"session", "create", "--help"}},
		{"session delete help", []string{"session", "delete", "--help"}},
		{"session cleanup help", []string{"session", "cleanup", "--help"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := runCommandWithWriters(tt.args, &stdout, &stderr)
			if code != 0 {
				t.Errorf("expected exit code 0, got %d", code)
			}
			count := strings.Count(stdout.String(), "Flags:")
			if count != 1 {
				t.Errorf("expected exactly one 'Flags:' section, got %d in: %s", count, stdout.String())
			}
		})
	}
}

func TestBlackBoxHelpWithUnknownFlag(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"root --help --unknown", []string{"--help", "--unknown"}},
		{"session --help --unknown", []string{"session", "--help", "--unknown"}},
		{"session --help unexpected", []string{"session", "--help", "unexpected"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := runCommandWithWriters(tt.args, &stdout, &stderr)
			if code != 2 {
				t.Errorf("expected exit code 2, got %d", code)
			}
		})
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

func TestBlackBoxSessionHelpHint(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"session"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit code 2, got %d", code)
	}
	if !strings.Contains(stderr.String(), "docker-helper session --help") {
		t.Errorf("expected 'docker-helper session --help' hint, got: %s", stderr.String())
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

func TestHelpUnknownCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"help", "wat"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit 2, got %d", code)
	}
	if !strings.Contains(stderr.String(), "unknown command") {
		t.Errorf("expected unknown command error, got: %s", stderr.String())
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

func TestRootHelpContainsHint(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{}, &stdout, &stderr)
	if code != 0 {
		t.Errorf("expected exit 0, got %d", code)
	}
	if !strings.Contains(stdout.String(), "docker-helper help <command>") {
		t.Errorf("expected help hint in root output, got: %s", stdout.String())
	}
}

func TestRootHelpGroupsAgentAndOperator(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{}, &stdout, &stderr)
	if code != 0 {
		t.Errorf("expected exit 0, got %d", code)
	}
	output := stdout.String()
	for _, section := range []string{"Agent commands:", "Operator commands:", "General commands:"} {
		if !strings.Contains(output, section) {
			t.Errorf("expected '%s' section in root help, got: %s", section, output)
		}
	}
	// Verify agent commands appear under Agent commands
	agentSection := output[strings.Index(output, "Agent commands:"):]
	nextIdx := minOfNonZero(strings.Index(agentSection, "Operator commands:"),
		strings.Index(agentSection, "General commands:"))
	if nextIdx > 0 {
		agentSection = agentSection[:nextIdx]
	}
	for _, cmd := range []string{"pull", "build", "run", "registry"} {
		if !strings.Contains(agentSection, cmd) {
			t.Errorf("expected %s under Agent commands, got: %s", cmd, agentSection)
		}
	}
	// Verify operator commands appear under Operator commands
	operatorSection := output[strings.Index(output, "Operator commands:"):]
	nextIdx2 := strings.Index(operatorSection, "General commands:")
	if nextIdx2 > 0 {
		operatorSection = operatorSection[:nextIdx2]
	}
	for _, cmd := range []string{"serve", "init", "reload", "session", "config"} {
		if !strings.Contains(operatorSection, cmd) {
			t.Errorf("expected %s under Operator commands, got: %s", cmd, operatorSection)
		}
	}
	// Verify general commands appear under General commands
	generalSection := output[strings.Index(output, "General commands:"):]
	for _, cmd := range []string{"version", "help"} {
		if !strings.Contains(generalSection, cmd) {
			t.Errorf("expected %s under General commands, got: %s", cmd, generalSection)
		}
	}
}

func minOfNonZero(a, b int) int {
	switch {
	case a <= 0:
		return b
	case b <= 0:
		return a
	default:
		if a < b {
			return a
		}
		return b
	}
}

// --- reload operator flags tests ---

func TestReloadHelpShowsOperatorFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"reload", "--help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("reload --help exited %d", code)
	}
	out := stdout.String()
	for _, flag := range []string{"--system", "--endpoint", "--token-file"} {
		if !strings.Contains(out, flag) {
			t.Errorf("reload --help should contain %q", flag)
		}
	}
}

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
	os.WriteFile(tokenPath, []byte("test-token"), 0600)

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
	os.WriteFile(tokenPath, []byte("test-token"), 0600)

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"reload", "--system", "--endpoint", "http://127.0.0.1:52375", "--token-file", tokenPath}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected non-zero exit")
	}
	if !strings.Contains(stderr.String(), "mutually exclusive") {
		t.Fatalf("expected mutual exclusion error: %s", stderr.String())
	}
}
