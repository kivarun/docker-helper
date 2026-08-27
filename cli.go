package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

type Invocation struct {
	Validate func() error
	Run      func(stdout, stderr io.Writer) int
}

type Command struct {
	Name          string
	Summary       string
	Usage         string
	Help          string
	MinPosArgs    int
	MaxPosArgs    int
	Subcommands   []*Command
	NewInvocation func(*flag.FlagSet) Invocation
}

// resolveSubcommand finds a direct subcommand by name.
// Returns nil if no matching subcommand exists.
func (c *Command) resolveSubcommand(name string) *Command {
	for _, sub := range c.Subcommands {
		if sub.Name == name {
			return sub
		}
	}
	return nil
}

// resolveCommandPath walks the command tree to resolve a full command path.
// Returns the resolved command and the path prefix (ancestors before the target).
// Returns (nil, nil) if any component in the path is not found or is a leaf.
func (c *Command) resolveCommandPath(names []string) (*Command, []string) {
	current := c
	for i, name := range names {
		sub := current.resolveSubcommand(name)
		if sub == nil {
			return nil, nil
		}
		// If we reached the last component, return it
		if i == len(names)-1 {
			return sub, names[:i]
		}
		// Otherwise, the intermediate must be a branch (not a leaf)
		if sub.NewInvocation != nil {
			return nil, nil
		}
		current = sub
	}
	return c, nil
}

// dispatch recursively routes args through the command tree.
// For branch commands: selects subcommand, requires it (except root).
// For leaf commands: parses flags, validates, runs.
func (c *Command) dispatch(args []string, path []string, stdout, stderr io.Writer) int {
	if c.NewInvocation != nil {
		return c.dispatchLeaf(args, path, stdout, stderr)
	}
	return c.dispatchBranch(args, path, stdout, stderr)
}

func (c *Command) dispatchBranch(args []string, path []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		// Root with no args: show help, exit 0.
		// Other branch commands: missing subcommand, exit 2.
		if c == rootCommand {
			c.printHelp(stdout, path)
			return 0
		}
		c.printSubcommandRequired(stderr, path)
		return 2
	}

	// Validate help args: --help with unknown flags or positional args is an error
	if args[0] == "-h" || args[0] == "--help" {
		if len(args) > 1 {
			// Check for unknown flags or positional args after --help
			for _, arg := range args[1:] {
				if arg == "-h" || arg == "--help" {
					continue
				}
				if strings.HasPrefix(arg, "-") {
					fmt.Fprintf(stderr, "flag provided but not defined: %s\n", arg)
					return 2
				}
				fmt.Fprintf(stderr, "error: unexpected argument %q\n", arg)
				return 2
			}
		}
		c.printHelp(stdout, path)
		return 0
	}

	// Root-level version aliases: docker-helper --version / -v behave like
	// the version subcommand. Handled before subcommand resolution.
	if c == rootCommand && (args[0] == "--version" || args[0] == "-v") {
		if len(args) > 1 {
			fmt.Fprintf(stderr, "error: unexpected argument %q\n", args[1])
			return 2
		}
		fmt.Fprintln(stdout, version)
		return 0
	}

	// Find matching subcommand
	sub := c.resolveSubcommand(args[0])
	if sub != nil {
		newPath := path
		// Don't include root command name in path
		if c != rootCommand {
			newPath = appendPath(path, c.Name)
		}
		return sub.dispatch(args[1:], newPath, stdout, stderr)
	}

	// Unknown subcommand
	if c == rootCommand {
		fmt.Fprintf(stderr, "error: unknown command %q\n", args[0])
		fmt.Fprintln(stderr)
		fmt.Fprintln(stderr, "Run the following for usage information:")
		fmt.Fprintln(stderr, "  docker-helper help")
	} else {
		fmt.Fprintf(stderr, "error: unknown %s subcommand %q\n", c.Name, args[0])
		fmt.Fprintln(stderr)
		prefix := buildPrefix(path)
		fmt.Fprintf(stderr, "Run the following for usage information:\n")
		fmt.Fprintf(stderr, "  %s %s --help\n", prefix, c.Name)
	}
	return 2
}

func (c *Command) dispatchLeaf(args []string, path []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(c.Name, flag.ContinueOnError)
	fs.SetOutput(stderr)

	// Override flag.FlagSet's default Usage so that parse errors render
	// through our own formatter (double-dash long options) instead of
	// Go's default single-dash format.
	fs.Usage = func() {
		prefix := buildPrefix(path)
		fmt.Fprintln(stderr, c.usageLine(prefix))
		fmt.Fprintln(stderr)
		fmt.Fprintln(stderr, "Flags:")
		fs.VisitAll(func(f *flag.Flag) {
			fmt.Fprintln(stderr, usageLine(f))
		})
	}

	// Register help flags
	helpShort := fs.Bool("h", false, "Show help for this command")
	helpLong := fs.Bool("help", false, "Show help for this command")

	// Register command-specific flags
	inv := c.NewInvocation(fs)

	// Parse flags
	if err := fs.Parse(args); err != nil {
		// flag.FlagSet already printed the error via SetOutput(stderr)
		return 2
	}

	// Handle help after successful parsing, before arg count/Validate/Run
	if *helpShort || *helpLong {
		c.printHelp(stdout, path)
		return 0
	}

	// Check positional argument count
	nArgs := fs.NArg()
	if c.MinPosArgs > 0 || c.MaxPosArgs > 0 || c.MaxPosArgs == -1 {
		if c.MaxPosArgs == -1 {
			// Unlimited
			if nArgs < c.MinPosArgs {
				c.printArgError(stderr, path, fmt.Sprintf("missing required argument(s): expected at least %d, got %d", c.MinPosArgs, nArgs))
				return 2
			}
		} else if c.MaxPosArgs == 0 {
			// No positional args allowed (zero-value default behavior)
			if nArgs > 0 {
				c.printArgError(stderr, path, fmt.Sprintf("unexpected argument %q", fs.Arg(0)))
				return 2
			}
		} else {
			// Bounded range
			if nArgs < c.MinPosArgs {
				c.printArgError(stderr, path, fmt.Sprintf("missing required argument(s): expected at least %d, got %d", c.MinPosArgs, nArgs))
				return 2
			}
			if nArgs > c.MaxPosArgs {
				c.printArgError(stderr, path, fmt.Sprintf("too many arguments: expected at most %d, got %d", c.MaxPosArgs, nArgs))
				return 2
			}
		}
	} else {
		// Default: reject all positional args
		if nArgs > 0 {
			c.printArgError(stderr, path, fmt.Sprintf("unexpected argument %q", fs.Arg(0)))
			return 2
		}
	}

	// Validate required options
	if inv.Validate != nil {
		if err := inv.Validate(); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
	}

	// Run the command
	return inv.Run(stdout, stderr)
}

// printArgError writes a semantic argument error followed by the specific
// command's Usage line, so users get actionable guidance instead of internal
// positional-count arithmetic.
func (c *Command) printArgError(stderr io.Writer, path []string, msg string) {
	fmt.Fprintf(stderr, "error: %s\n", msg)
	fmt.Fprintln(stderr)
	fmt.Fprintln(stderr, c.usageLine(buildPrefix(path)))
}

func (c *Command) printSubcommandRequired(stderr io.Writer, path []string) {
	subNames := make([]string, len(c.Subcommands))
	for i, sub := range c.Subcommands {
		subNames[i] = sub.Name
	}
	fmt.Fprintf(stderr, "error: %s subcommand required (%s)\n", c.Name, strings.Join(subNames, ", "))
	fmt.Fprintln(stderr)
	prefix := buildPrefix(path)
	fmt.Fprintf(stderr, "Run the following for usage information:\n")
	fmt.Fprintf(stderr, "  %s %s --help\n", prefix, c.Name)
}

func (c *Command) printHelp(w io.Writer, path []string) {
	prefix := buildPrefix(path)

	// Print Usage line
	usage := c.usageLine(prefix)
	fmt.Fprintln(w, usage)
	fmt.Fprintln(w)

	if c.Summary != "" {
		fmt.Fprintf(w, "%s\n", c.Summary)
		fmt.Fprintln(w)
	}

	if len(c.Subcommands) > 0 {
		// Root command: group commands by category.
		if c == rootCommand {
			c.printGroupedSubcommands(w)
		} else {
			fmt.Fprintln(w, "Subcommands:")
			for _, sub := range c.Subcommands {
				fmt.Fprintf(w, "  %-10s %s\n", sub.Name, sub.Summary)
			}
			fmt.Fprintln(w)
		}
	}

	// Print Help text if present
	if c.Help != "" {
		fmt.Fprintln(w, c.Help)
		fmt.Fprintln(w)
	}

	// Print Flags section
	fmt.Fprintln(w, "Flags:")
	if c.NewInvocation != nil {
		fs := flag.NewFlagSet("", flag.ContinueOnError)
		c.NewInvocation(fs)
		// Print command-specific flags first
		fs.VisitAll(func(f *flag.Flag) {
			if f.Name != "h" && f.Name != "help" {
				fmt.Fprintln(w, usageLine(f))
			}
		})
	}
	// Always print -h/--help
	fmt.Fprintln(w, "  -h, --help  Show help for this command")
	// Root-level version alias.
	if c == rootCommand {
		fmt.Fprintln(w, "  -v, --version  Print version information")
	}
	fmt.Fprintln(w)

	// Root command: add hint about help <command>
	if c == rootCommand {
		fmt.Fprintln(w, "Run 'docker-helper help <command>' or 'docker-helper <command> --help'")
		fmt.Fprintln(w, "for command-specific help.")
		fmt.Fprintln(w)
	}
}

// agentCommandNames lists commands intended for agent containers.
var agentCommandNames = map[string]struct{}{
	"pull":     {},
	"build":    {},
	"run":      {},
	"registry": {},
}

// generalCommandNames lists commands useful in any context.
var generalCommandNames = map[string]struct{}{
	"version": {},
	"help":    {},
}

func (c *Command) printGroupedSubcommands(w io.Writer) {
	var agentCmds, operatorCmds, generalCmds []*Command
	for _, sub := range c.Subcommands {
		if _, ok := agentCommandNames[sub.Name]; ok {
			agentCmds = append(agentCmds, sub)
		} else if _, ok := generalCommandNames[sub.Name]; ok {
			generalCmds = append(generalCmds, sub)
		} else {
			operatorCmds = append(operatorCmds, sub)
		}
	}

	if len(agentCmds) > 0 {
		fmt.Fprintln(w, "Agent commands:")
		for _, sub := range agentCmds {
			fmt.Fprintf(w, "  %-10s %s\n", sub.Name, sub.Summary)
		}
		fmt.Fprintln(w)
	}

	if len(operatorCmds) > 0 {
		fmt.Fprintln(w, "Operator commands:")
		for _, sub := range operatorCmds {
			fmt.Fprintf(w, "  %-10s %s\n", sub.Name, sub.Summary)
		}
		fmt.Fprintln(w)
	}

	if len(generalCmds) > 0 {
		fmt.Fprintln(w, "General commands:")
		for _, sub := range generalCmds {
			fmt.Fprintf(w, "  %-10s %s\n", sub.Name, sub.Summary)
		}
		fmt.Fprintln(w)
	}
}

func (c *Command) usageLine(prefix string) string {
	if c.Usage != "" {
		return "Usage: " + c.Usage
	}
	if c.NewInvocation != nil {
		return fmt.Sprintf("Usage: %s %s [flags]", prefix, c.Name)
	}
	if c == rootCommand {
		return fmt.Sprintf("Usage: %s <subcommand> [flags]", prefix)
	}
	return fmt.Sprintf("Usage: %s %s <subcommand> [flags]", prefix, c.Name)
}

func usageLine(f *flag.Flag) string {
	name := f.Name
	if len(name) == 1 {
		return fmt.Sprintf("  -%s    %s", name, f.Usage)
	}
	return fmt.Sprintf("  --%s    %s", name, f.Usage)
}

func buildPrefix(path []string) string {
	if len(path) == 0 {
		return "docker-helper"
	}
	return "docker-helper " + strings.Join(path, " ")
}

func appendPath(path []string, name string) []string {
	result := make([]string, len(path)+1)
	copy(result, path)
	result[len(path)] = name
	return result
}

var rootCommand = &Command{
	Name: "docker-helper",
}

var serveCommand = &Command{
	Name:    "serve",
	Summary: "Start the docker-helper daemon",
	Usage:   "docker-helper serve",
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				if err := runDaemon(stdout, stderr); err != nil {
					return 1
				}
				return 0
			},
		}
	},
}

var initCommand = &Command{
	Name:    "init",
	Summary: "Initialize configuration and admin token",
	Usage:   "docker-helper init [--allowed-root PATH]",
	Help: `Initialize docker-helper configuration and admin token.

If --allowed-root is provided, it is used directly.

Without --allowed-root and when running interactively (stdin is a
terminal), you will be prompted for the allowed root directory.
The user's home directory is used as the default.
For root, /home is used as the default.

In non-interactive mode (stdin is not a terminal), --allowed-root
is required.

System mode (effective UID 0):
  The allowed root is the system-wide authorization ceiling.
  init does not prepare MAC state.
  MAC coverage for a concrete workspace is prepared by the session
  lifecycle at session creation.

User mode (non-root):
  No MAC preparation is required.`,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		allowedRoot := fs.String("allowed-root", "", "Allowed root directory for agent workspaces")

		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				isTerminal := term.IsTerminal(int(os.Stdin.Fd()))
				resolved, err := resolveAllowedRootForInit(*allowedRoot, os.Stdin, stderr, isTerminal)
				if err != nil {
					fmt.Fprintln(stderr, err)
					return 2
				}

				if err := runInit(resolved, stdout, stderr); err != nil {
					fmt.Fprintln(stderr, err)
					var ie *inputError
					if errors.As(err, &ie) {
						return 2
					}
					return 1
				}
				return 0
			},
		}
	},
}

// resolveAllowedRootForInit resolves the allowed root for the init command.
// If flagValue is provided, it is validated and returned.
// If not provided and isTerminal is true, the user is prompted interactively.
// If not provided and isTerminal is false, an error is returned.
// The prompt default is /home for root, or the user's home directory otherwise.
func resolveAllowedRootForInit(flagValue string, stdin io.Reader, stderr io.Writer, isTerminal bool) (string, error) {
	if flagValue != "" {
		return resolveAllowedRoot(flagValue)
	}

	if !isTerminal {
		return "", errors.New("--allowed-root is required in non-interactive mode")
	}

	defaultPath := getInitDefaultRoot()

	input, err := promptAllowedRoot(defaultPath, stdin, stderr)
	if err != nil {
		return "", err
	}

	return resolveAllowedRoot(input)
}

// getInitDefaultRoot returns the default path for the init prompt.
// Root gets /home; non-root gets the user's home directory.
func getInitDefaultRoot() string {
	if EffectiveUID() == 0 {
		return "/home"
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home
}

var versionCommand = &Command{
	Name:    "version",
	Summary: "Print version",
	Usage:   "docker-helper version",
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				fmt.Fprintln(stdout, version)
				return 0
			},
		}
	},
}

var reloadCommand = &Command{
	Name:    "reload",
	Summary: "Reload configuration from disk",
	Usage:   "docker-helper reload [--system] [--endpoint ENDPOINT] [--token-file PATH]",
	Help: `Ask the running daemon to re-read config.json and apply changes without restarting.

The following configurable fields are applied at runtime:
  allowed_roots             root directories for agent workspaces
  session_ttl               session lifetime
  log_level                 operational log verbosity
  audit_enabled             audit output enablement
  shutdown_timeout          graceful shutdown budget
  operation_retention_ttl   completed operation retention period
  operation_max_completed   max completed operations in memory
  operation_log_max_bytes   max bytes per operation log
  trusted_ca_path           CA certificate file path
  trusted_ca_injection      CA injection mode ("disabled" or "auto")

Startup-only fields (require daemon restart):
  http_address              loopback TCP listen address

Runtime paths (socket, database, state) are not changed.

If the daemon is not running, this command fails with a non-zero exit code.
If the new configuration is invalid, the daemon keeps its current
configuration and this command returns an error.`,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		system, endpoint, tokenFile := registerOperatorFlags(fs)
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				return runReload(stdout, stderr, operatorClientOptions{
					System:    *system,
					Endpoint:  *endpoint,
					TokenFile: *tokenFile,
				})
			},
		}
	},
}

var helpCommand = &Command{
	Name:       "help",
	Summary:    "Show help",
	Usage:      "docker-helper help [command]",
	MaxPosArgs: -1, // Allow unlimited positional args for nested commands
	Help: `Show help for docker-helper or a specific command.

Run 'docker-helper help <command>' or 'docker-helper <command> --help'
for command-specific help.`,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				args := fs.Args()
				if len(args) == 0 {
					rootCommand.printHelp(stdout, []string{})
					return 0
				}

				// Resolve the command using the shared lookup primitive
				cmd, path := rootCommand.resolveCommandPath(args)
				if cmd == nil {
					fmt.Fprintf(stderr, "error: unknown command %q\n", strings.Join(args, " "))
					return 2
				}

				cmd.printHelp(stdout, path)
				return 0
			},
		}
	},
}

func init() {
	rootCommand.Subcommands = []*Command{
		serveCommand,
		initCommand,
		reloadCommand,
		sessionCommand,
		configCommand,
		principalCommand,
		credentialCommand,
		adminCommand,
		appArmorCommand,
		versionCommand,
		helpCommand,
		pullCommand,
		buildCommand,
		runContainerCommand,
	}
}

func runCommandWithWriters(args []string, stdout, stderr io.Writer) int {
	return rootCommand.dispatch(args, []string{}, stdout, stderr)
}

func runCommand(args []string) int {
	return runCommandWithWriters(args, os.Stdout, os.Stderr)
}
