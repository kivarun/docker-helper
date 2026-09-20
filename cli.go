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

// explicitStringFlag is the shared presence-aware string-flag primitive for
// CLI grammar that must distinguish omission from an explicitly supplied
// value, including the empty string. Command-family validation owns whether
// the explicit value is legal.
type explicitStringFlag struct {
	set   bool
	value string
}

func (f *explicitStringFlag) String() string { return f.value }

func (f *explicitStringFlag) Set(v string) error {
	f.set = true
	f.value = v
	return nil
}

// commandPresentation is declarative metadata owned by each leaf command.
// Finite-result commands declare the canonical human-default + explicit
// --json contract. True exceptions declare their reason next to the command;
// an unspecified leaf is a contract error caught by the command-tree test.
type commandPresentationMode uint8

const (
	presentationUnspecified commandPresentationMode = iota
	presentationHumanDefaultJSON
	presentationException
)

type commandPresentation struct {
	Mode   commandPresentationMode
	Reason string
}

func humanJSONPresentation() commandPresentation {
	return commandPresentation{Mode: presentationHumanDefaultJSON}
}

func exceptionPresentation(reason string) commandPresentation {
	return commandPresentation{Mode: presentationException, Reason: reason}
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
	Presentation  commandPresentation

	// FlagsStopAtPositional selects Go's native flag.FlagSet grammar for
	// the leaf: option parsing stops at the first positional token, and
	// every following token is positional data even when it looks like an
	// option. The workload-command grammar (run IMAGE [COMMAND...]) owns
	// this mode: post-IMAGE tokens belong to the workload command and must
	// never be reinterpreted as docker-helper flags. Every other command
	// keeps the interspersed grammar (parseCommandFlags).
	FlagsStopAtPositional bool
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

	// Parse flags. The default grammar is interspersed: flags may appear
	// before, between, or after positional arguments. A leaf that owns the
	// workload-command grammar parses with Go's native FlagSet instead:
	// option parsing stops at the first positional, so everything after it
	// is workload data verbatim.
	if c.FlagsStopAtPositional {
		if err := fs.Parse(args); err != nil {
			// flag.FlagSet already printed the error via SetOutput(stderr)
			return 2
		}
	} else if err := parseCommandFlags(fs, args); err != nil {
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

// parseCommandFlags parses flags with an interspersed grammar: flags may
// appear before, between, or after positional arguments. Go's flag package
// stops at the first positional token, so parsing runs in rounds: each round
// consumes the flag run at the front of the remaining tokens, and a positional
// token is set aside while parsing resumes after it. The collected positionals
// are re-presented to the flag set behind a bare "--" terminator as a final
// round, so fs.Args() ends up holding every positional in order and callers
// can keep reading positionals from the flag set as before.
//
// A bare "--" always terminates flag parsing: it is never consumed as a flag
// value, and tokens after it are positionals verbatim, even when they look
// like options. "--flag=--" still parses with the value "--".
func parseCommandFlags(fs *flag.FlagSet, args []string) error {
	head, sentinelTail := splitAtBareDoubleDash(args)

	var positionals []string
	for len(head) > 0 {
		if head[0] == "-" || !strings.HasPrefix(head[0], "-") {
			positionals = append(positionals, head[0])
			head = head[1:]
			continue
		}
		if err := fs.Parse(head); err != nil {
			return err
		}
		rest := fs.Args()
		if len(rest) == len(head) {
			// Defensive: parse consumed nothing; treat the token as a
			// positional to guarantee progress.
			positionals = append(positionals, rest[0])
			head = head[1:]
			continue
		}
		head = rest
	}

	// Tokens after the bare "--" sentinel are positionals verbatim, even
	// when they look like options.
	positionals = append(positionals, sentinelTail...)

	// One final round behind the bare "--" terminator makes fs.Args() hold
	// the complete positional list; flag values parsed above are already
	// recorded on the flag set. This round cannot fail, but keep the error
	// contract uniform.
	if err := fs.Parse(append([]string{"--"}, positionals...)); err != nil {
		return err
	}
	return nil
}

// splitAtBareDoubleDash splits args at the first bare "--". Everything after
// the sentinel is returned verbatim as trailing positionals.
func splitAtBareDoubleDash(args []string) (head, tail []string) {
	for i, a := range args {
		if a == "--" {
			return args[:i], args[i+1:]
		}
	}
	return args, nil
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
		fmt.Fprintln(w, "Run 'docker-helper help [<command> [<subcommand> ...]]' or")
		fmt.Fprintln(w, "'docker-helper <command> --help' for command-specific help.")
		fmt.Fprintln(w)
	}
}

// agentCommandNames lists commands intended for agent containers.
var agentCommandNames = map[string]struct{}{
	"pull":     {},
	"build":    {},
	"run":      {},
	"registry": {},
	"self":     {},
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

	Presentation: exceptionPresentation("process: long-running daemon, not a finite command result"),

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

System mode (effective UID 0, the only daemon deployment):
  The allowed root is the system-wide authorization ceiling.
  init does not prepare MAC state.
  MAC coverage for a concrete workspace is prepared by the session
  lifecycle at session creation.`,

	Presentation: exceptionPresentation("interactive setup workflow with one-time admin-token disclosure"),

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

// accessFlag is the presence-aware --access flag value shared by the
// allowed-root add commands: an explicitly supplied value must parse to the
// canonical vocabulary (an empty or unknown spelling is rejected at parse
// time, never reinterpreted as omission); an unsupplied flag selects the
// canonical read_write grant at the call site.
type accessFlag struct {
	set    bool
	access AllowedRootAccess
}

func (f *accessFlag) String() string {
	return string(f.access)
}

func (f *accessFlag) Set(value string) error {
	parsed, err := parseAllowedRootAccess(value)
	if err != nil {
		return err
	}
	f.set = true
	f.access = parsed
	return nil
}

// optionalAccessFromFlag projects the parsed --access flag to the wire form:
// an unsupplied flag is nil (the 2.1 path-only request), a supplied flag is
// always sent explicitly.
func optionalAccessFromFlag(f *accessFlag) *AllowedRootAccess {
	if !f.set {
		return nil
	}
	return &f.access
}

// printAllowedRootList prints the human allowed-root listing shared by the
// config, Principal, and Launcher allowed-root list commands. The default
// output is the 2.1-compatible one canonical root per line in stored-entry
// order; --json prints the canonical rich entries ([{"path","access"}, ...])
// in the same order for access-aware tooling.
func printAllowedRootList(w io.Writer, entries []AllowedRootEntry, jsonOut bool) error {
	if jsonOut {
		return encodeJSONOut(w, entries)
	}
	for _, e := range entries {
		fmt.Fprintln(w, e.Path)
	}
	return nil
}

// allowedRootAccessResult is the one shared --json shape of the three
// allowed-root set-access commands (config, Principal, Launcher): the stored
// path identity, the resulting access, whether this call changed it, and —
// config transaction only — whether this successful write also carried the
// legacy-schema migration. The two facts are independent: a legacy
// migration may accompany a changed or an unchanged access. Unchanged
// remains success (changed=false); a missing target is never routed here,
// it stays the command's failure.
type allowedRootAccessResult struct {
	Path     string            `json:"path"`
	Access   AllowedRootAccess `json:"access"`
	Changed  bool              `json:"changed"`
	Migrated bool              `json:"migrated,omitempty"`
}

// printAllowedRootAccessResult renders the one shared presentation of a
// successful allowed-root set-access result: human text by default (the
// subject names the targeted resource and is empty for the global config
// tree) or the shared JSON shape under the command's --json flag. The
// legacy-schema migration fact is reported in both modes, consistently
// with the unchanged wording.
func printAllowedRootAccessResult(w io.Writer, subject, path string, access AllowedRootAccess, changed, migrated bool, jsonOut bool) error {
	if jsonOut {
		return encodeJSONOut(w, allowedRootAccessResult{
			Path:     path,
			Access:   access,
			Changed:  changed,
			Migrated: migrated,
		})
	}
	target := ""
	if subject != "" {
		target = " on " + subject
	}
	if changed {
		migratedNote := ""
		if migrated {
			migratedNote = " (legacy schema migrated)"
		}
		fmt.Fprintf(w, "changed %s to access %s%s%s\n", path, access, migratedNote, target)
		return nil
	}
	if migrated {
		fmt.Fprintf(w, "unchanged %s (access %s; legacy schema migrated)%s\n", path, access, target)
		return nil
	}
	fmt.Fprintf(w, "unchanged %s (access %s)%s\n", path, access, target)
	return nil
}

// allowedRootAccessHumanMessage renders the shared set-access human form as
// one string, for transaction results that carry their success message.
func allowedRootAccessHumanMessage(subject, path string, access AllowedRootAccess, changed, migrated bool) string {
	var b strings.Builder
	_ = printAllowedRootAccessResult(&b, subject, path, access, changed, migrated, false)
	return b.String()
}

// configFieldResult is the CLI-owned --json shape of the local config
// set/unset acknowledgements: the addressed canonical field, whether this
// successful operation changed the stored document, and — config
// transaction only — whether the write also carried the legacy-schema
// migration. A set carries the applied value; an unset does not.
type configFieldResult struct {
	Field    string `json:"field"`
	Value    string `json:"value,omitempty"`
	Changed  bool   `json:"changed"`
	Migrated bool   `json:"migrated,omitempty"`
}

// allowedRootMutationResult is the CLI-owned --json shape of the global
// config allowed-root add/remove acknowledgements: the addressed canonical
// path identity, whether this successful operation changed the stored
// document, and whether the write also carried the legacy-schema
// migration. An add carries the access of the stored entry; a remove does
// not. The same {path, changed, migrated} facts as the set-access result,
// without the set-access-only unconditional access field.
type allowedRootMutationResult struct {
	Path     string            `json:"path"`
	Access   AllowedRootAccess `json:"access,omitempty"`
	Changed  bool              `json:"changed"`
	Migrated bool              `json:"migrated,omitempty"`
}

// deletedResourceResult is the CLI-owned --json shape of the delete
// acknowledgements whose daemon route returns no document (principal
// delete, launcher delete, launcher credential delete): the addressed
// resource subject and the deleted fact. The exit code carries success;
// the result names what was deleted.
type deletedResourceResult struct {
	Principal string `json:"principal,omitempty"`
	Launcher  string `json:"launcher,omitempty"`
	Deleted   bool   `json:"deleted"`
}

var versionCommand = &Command{
	Name:    "version",
	Summary: "Print version",
	Usage:   "docker-helper version [--json]",

	Presentation: humanJSONPresentation(),

	NewInvocation: func(fs *flag.FlagSet) Invocation {
		jsonOut := fs.Bool("json", false, "Output in JSON format")
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				if *jsonOut {
					if err := encodeJSONOut(stdout, versionResult{Version: version}); err != nil {
						fmt.Fprintf(stderr, "error: cannot encode output: %v\n", err)
						return 1
					}
					return 0
				}
				fmt.Fprintln(stdout, version)
				return 0
			},
		}
	},
}

// versionResult is the CLI-owned --json shape of the version scalar: the
// same version string the human line prints.
type versionResult struct {
	Version string `json:"version"`
}

var reloadCommand = &Command{
	Name:    "reload",
	Summary: "Reload configuration from disk",
	Usage:   "docker-helper reload [--endpoint ENDPOINT] [--token-file PATH] [--json]",
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

When allowed_roots is narrowed, reload reconciles persisted policy before
publishing the new runtime ceiling: stored Principal roots outside the new
global ceiling are pruned, then restricted-Launcher descendants outside the
surviving per-Principal ceilings are pruned. Already-issued Session snapshots
are immutable and are not rewritten. If reconciliation fails, no descendant
deletion is committed and the current runtime configuration remains active.

If the daemon is not running, this command fails with a non-zero exit code.
If the new configuration is invalid, the daemon keeps its current
configuration and this command returns an error.`,

	Presentation: humanJSONPresentation(),

	NewInvocation: func(fs *flag.FlagSet) Invocation {
		endpoint, tokenFile := registerOperatorFlags(fs)
		jsonOut := fs.Bool("json", false, "Output in JSON format")
		return Invocation{
			Validate: func() error {
				return validateOperatorEndpointOptions(operatorClientOptions{

					Endpoint:    endpoint.value,
					EndpointSet: endpoint.set,
					TokenFile:   *tokenFile,
				})
			},
			Run: func(stdout, stderr io.Writer) int {
				return runReload(stdout, stderr, operatorClientOptions{

					Endpoint:  endpoint.value,
					TokenFile: *tokenFile,
				}, *jsonOut)
			},
		}
	},
}

var helpCommand = &Command{
	Name:       "help",
	Summary:    "Show help",
	Usage:      "docker-helper help [command [subcommand ...]]",
	MaxPosArgs: -1, // Allow unlimited positional args for nested commands
	Help: `Show help for docker-helper or any command path.

Run 'docker-helper help <command> [<subcommand> ...]' to navigate the
command tree, or 'docker-helper <command> --help' for command-specific
help.`,

	Presentation: exceptionPresentation("navigation: help text, not a command result"),

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
		launcherCommand,
		selfCommand,
		credentialCommand,
		adminTokenCommand,
		appArmorCommand,
		selinuxCommand,
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
