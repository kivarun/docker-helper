package main

import (
	"bytes"
	"flag"
	"strings"
	"testing"
)

// cliRemovedFlagSpellings is the grammar-removal matrix: command paths
// whose legacy flag spelling for the primary operand was removed. The
// structural sweep below proves none of these flags is registered anymore
// and the usage line carries the positional operand instead.
var cliRemovedFlagSpellings = []struct {
	commandPath []string
	removedFlag string
	operand     string
}{
	{[]string{"launcher", "create"}, "name", "NAME"},
	{[]string{"session", "create"}, "workspace", "WORKSPACE"},
	{[]string{"session", "delete"}, "id", "SESSION_ID"},
	{[]string{"registry", "login"}, "registry", "REGISTRY"},
	{[]string{"run"}, "image", "IMAGE"},
	{[]string{"build"}, "context", "CONTEXT"},
}

// cliCommandByPath resolves a command path in the real command tree.
func cliCommandByPath(t *testing.T, path []string) *Command {
	t.Helper()
	cmd := completionCommandPath(path)
	if cmd == nil {
		t.Fatalf("command %v missing from the command tree", path)
	}
	return cmd
}

// TestCLIPrimaryOperandIsPositional is the structural grammar invariant:
// every command whose primary operand was positionalized by the grammar
// normalization registers
// no legacy flag spelling for it, requires exactly one positional operand
// (or one plus the workload words), and documents the positional operand in
// the usage line. A regression reintroducing a flag+positional duplicate or
// dropping the positional requirement fails here, not only in a usage string.
func TestCLIPrimaryOperandIsPositional(t *testing.T) {
	for _, tc := range cliRemovedFlagSpellings {
		t.Run(strings.Join(tc.commandPath, " "), func(t *testing.T) {
			cmd := cliCommandByPath(t, tc.commandPath)

			fs := flag.NewFlagSet(strings.Join(tc.commandPath, "-"), flag.ContinueOnError)
			cmd.NewInvocation(fs)
			if fs.Lookup(tc.removedFlag) != nil {
				t.Errorf("removed flag --%s is still registered on %v", tc.removedFlag, tc.commandPath)
			}

			if cmd.MinPosArgs != 1 {
				t.Errorf("%v MinPosArgs = %d, want 1 (one required primary operand)", tc.commandPath, cmd.MinPosArgs)
			}
			// run is the workload-command grammar: IMAGE plus unlimited
			// workload words. Every other normalized command takes exactly
			// one positional.
			isRun := strings.Join(tc.commandPath, " ") == "run"
			if isRun {
				if cmd.MaxPosArgs != -1 {
					t.Errorf("run MaxPosArgs = %d, want -1 (IMAGE plus workload words)", cmd.MaxPosArgs)
				}
				if !cmd.FlagsStopAtPositional {
					t.Error("run must own the flags-stop-at-positional workload grammar")
				}
			} else if cmd.MaxPosArgs != 1 {
				t.Errorf("%v MaxPosArgs = %d, want 1", tc.commandPath, cmd.MaxPosArgs)
			}

			if cmd.Usage == "" {
				t.Fatalf("%v has no usage line", tc.commandPath)
			}
			if !strings.Contains(cmd.Usage, tc.operand) {
				t.Errorf("usage %q does not document the positional operand %s", cmd.Usage, tc.operand)
			}
		})
	}
}

// TestCLIWorkloadGrammarPassesPostImageArgsVerbatim proves the run grammar:
// docker-helper flags are parsed only before IMAGE; every following token —
// including workload option-looking words such as `sh -c` or `python -m` —
// is workload command data, and the documented `--` separator after IMAGE is
// consumed as the separator, never forwarded to the workload.
func TestCLIWorkloadGrammarPassesPostImageArgsVerbatim(t *testing.T) {
	decompose := func(t *testing.T, args []string) (image string, command []string) {
		t.Helper()
		fs := flag.NewFlagSet("run", flag.ContinueOnError)
		runContainerCommand.NewInvocation(fs)
		if err := fs.Parse(args); err != nil {
			t.Fatalf("parse %v: %v", args, err)
		}
		rest := fs.Args()
		if len(rest) == 0 {
			t.Fatalf("no IMAGE in %v", args)
		}
		image = rest[0]
		command = append([]string{}, rest[1:]...)
		if len(command) > 0 && command[0] == "--" {
			command = command[1:]
		}
		return image, command
	}

	image, command := decompose(t, []string{"alpine:3.24", "sh", "-c", "echo \"$FOO\""})
	if image != "alpine:3.24" || strings.Join(command, " ") != `sh -c echo "$FOO"` {
		t.Errorf("workload flags are workload data: image=%q command=%v", image, command)
	}

	image, command = decompose(t, []string{"--env", "FOO=bar", "alpine:3.24", "python", "-m", "http.server"})
	if image != "alpine:3.24" || strings.Join(command, " ") != "python -m http.server" {
		t.Errorf("post-IMAGE tokens must never be docker-helper flags: image=%q command=%v", image, command)
	}

	// The documented -- separator after IMAGE is consumed; a post-separator
	// option-looking word stays workload data verbatim.
	image, command = decompose(t, []string{"alpine:3.24", "--", "make", "test"})
	if image != "alpine:3.24" || strings.Join(command, " ") != "make test" {
		t.Errorf("-- separator handling: image=%q command=%v", image, command)
	}
	image, command = decompose(t, []string{"alpine:3.24", "--", "--verbose", "make"})
	if image != "alpine:3.24" || strings.Join(command, " ") != "--verbose make" {
		t.Errorf("post-separator workload words must stay verbatim: image=%q command=%v", image, command)
	}

	// No workload command: run still parses with IMAGE alone.
	image, command = decompose(t, []string{"--endpoint", "/run/dh.sock", "alpine:3.24"})
	if image != "alpine:3.24" || len(command) != 0 {
		t.Errorf("bare run: image=%q command=%v", image, command)
	}
}

// TestCLIRemovedSpellingsRejectedLocally proves the removed spellings fail
// with CLI syntax semantics (exit 2) before any run/validate logic, and no
// alias keeps the old spelling alive.
func TestCLIRemovedSpellingsRejectedLocally(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"launcher create --name", []string{"launcher", "create", "--name", "x"}},
		{"session create --workspace", []string{"session", "create", "--workspace", "/tmp"}},
		{"session delete --id", []string{"session", "delete", "--id", "dhs_x"}},
		{"registry login --registry", []string{"registry", "login", "--registry", "reg.example.com"}},
		{"run --image", []string{"run", "--image", "alpine:3.24"}},
		{"build --context", []string{"build", "--context", "."}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := runCommandWithWriters(tc.args, &stdout, &stderr)
			if code != 2 {
				t.Fatalf("exit = %d, want 2 (stderr=%s)", code, stderr.String())
			}
			if !strings.Contains(stderr.String(), "flag provided but not defined") {
				t.Errorf("stderr = %q, want the flag-parse rejection", stderr.String())
			}
		})
	}
}

// TestCLIPositionalCountSemantics proves the canonical positional forms work
// and the too-few/too-many positionals fail with CLI syntax exit semantics
// (exit 2, no daemon contact, usage line printed).
func TestCLIPositionalCountSemantics(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{"launcher create missing name", []string{"launcher", "create", "--no-credential"}, "missing required argument(s): expected at least 1, got 0"},
		{"launcher create too many", []string{"launcher", "create", "--no-credential", "a", "b"}, "too many arguments: expected at most 1, got 2"},
		{"session create missing workspace", []string{"session", "create"}, "missing required argument(s): expected at least 1, got 0"},
		{"session create too many", []string{"session", "create", "/a", "/b"}, "too many arguments: expected at most 1, got 2"},
		{"session delete missing id", []string{"session", "delete"}, "missing required argument(s): expected at least 1, got 0"},
		{"session delete too many", []string{"session", "delete", "a", "b"}, "too many arguments: expected at most 1, got 2"},
		{"registry login missing registry", []string{"registry", "login", "--username", "u"}, "missing required argument(s): expected at least 1, got 0"},
		{"registry login too many", []string{"registry", "login", "--username", "u", "a", "b"}, "too many arguments: expected at most 1, got 2"},
		{"build missing context", []string{"build", "--dockerfile", "Dockerfile", "--image", "app"}, "missing required argument(s): expected at least 1, got 0"},
		{"build too many", []string{"build", "--dockerfile", "D", "--image", "i", ".", "src"}, "too many arguments: expected at most 1, got 2"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("DOCKER_HELPER_SESSION_TOKEN", "")
			var stdout, stderr bytes.Buffer
			code := runCommandWithWriters(tc.args, &stdout, &stderr)
			if code != 2 {
				t.Fatalf("exit = %d, want 2 (stderr=%s)", code, stderr.String())
			}
			if !strings.Contains(stderr.String(), tc.wantErr) {
				t.Errorf("stderr = %q, want containing %q", stderr.String(), tc.wantErr)
			}
		})
	}
}

// TestCLILauncherAllowedRootTargetFirstUsage pins the target-first usage
// grammar of the launcher allowed-root family: the optional LAUNCHER
// selector leads and the operation operands follow. The --principal
// ownership selector and the --access modifier remain flags.
func TestCLILauncherAllowedRootTargetFirstUsage(t *testing.T) {
	tests := []struct {
		cmd  *Command
		want string
	}{
		{launcherAllowedRootAddCommand, "[LAUNCHER] PATH"},
		{launcherAllowedRootRemoveCommand, "[LAUNCHER] PATH"},
		{launcherAllowedRootSetAccessCommand, "[LAUNCHER] PATH read_only|read_write"},
		{launcherAllowedRootListCommand, "[LAUNCHER]"},
		{launcherAllowedRootInheritCommand, "[LAUNCHER]"},
	}
	for _, tc := range tests {
		if !strings.Contains(tc.cmd.Usage, tc.want) {
			t.Errorf("%s usage %q missing %q", tc.cmd.Name, tc.cmd.Usage, tc.want)
		}
	}
	for _, flagName := range []string{"principal", "access", "json"} {
		fs := flag.NewFlagSet("add", flag.ContinueOnError)
		launcherAllowedRootAddCommand.NewInvocation(fs)
		if fs.Lookup(flagName) == nil {
			t.Errorf("launcher allowed-root add lost its --%s flag", flagName)
		}
	}
}
