package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// stringListFlag collects a repeatable string flag value.
type stringListFlag struct {
	values []string
}

func (f *stringListFlag) String() string {
	return strings.Join(f.values, ",")
}

func (f *stringListFlag) Set(v string) error {
	f.values = append(f.values, v)
	return nil
}

// launcherNameFlag collects the optional --name value of the Launcher create
// and set commands with explicit flag presence: an explicitly supplied empty
// value is an invalid Launcher name submitted as-is, not omission, and is
// never silently dropped or defaulted. The daemon remains the name-grammar
// authority.
type launcherNameFlag struct {
	set   bool
	value string
}

func (f *launcherNameFlag) String() string { return f.value }

func (f *launcherNameFlag) Set(v string) error {
	f.set = true
	f.value = v
	return nil
}

// resolveIssueCredential resolves whether a creation operation should issue a
// credential. The mutually exclusive --issue-credential/--no-credential flags
// suppress the prompt; with neither supplied it prompts when stdin is a
// terminal and fails locally when it is not, before any mutating HTTP request.
func resolveIssueCredential(issueFlag, noCredentialFlag bool, promptText string, stdin io.Reader, stderr io.Writer, isTerminal bool) (bool, error) {
	if issueFlag && noCredentialFlag {
		return false, errors.New("--issue-credential and --no-credential are mutually exclusive")
	}
	if issueFlag {
		return true, nil
	}
	if noCredentialFlag {
		return false, nil
	}
	if !isTerminal {
		return false, errors.New("non-interactive creation requires --issue-credential or --no-credential")
	}
	return promptCredentialYesNo(promptText, stdin, stderr)
}

// promptCredentialYesNo asks a yes/no credential question (default yes) and
// re-prompts on invalid input. Accepted yes: empty/y/Y/yes/YES; no: n/N/no/NO.
func promptCredentialYesNo(question string, stdin io.Reader, stderr io.Writer) (bool, error) {
	reader := bufio.NewReader(stdin)
	for {
		fmt.Fprintf(stderr, "%s ", question)
		line, err := reader.ReadString('\n')
		if err != nil && line == "" {
			return false, fmt.Errorf("failed to read input: %w", err)
		}
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "", "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		default:
			fmt.Fprintln(stderr, "Please answer yes or no.")
		}
	}
}

// resolveLauncherPrincipalForCLI returns the username to target on the canonical
// nested /principals/{username}/launchers endpoint. When --principal is omitted
// it infers the Principal from GET /auth; explicit --principal targets the
// endpoint directly with no local pre-authorization (the daemon remains the
// authorization authority).
func resolveLauncherPrincipalForCLI(client *apiClient, explicitPrincipal string) (string, error) {
	if explicitPrincipal != "" {
		return explicitPrincipal, nil
	}
	auth, err := client.auth()
	if err != nil {
		return "", err
	}
	switch auth.Authority {
	case "principal":
		if auth.Principal == "" {
			return "", errors.New("auth introspection returned no principal")
		}
		return auth.Principal, nil
	case "admin":
		return "", errors.New("--principal is required for admin authentication")
	case "launcher":
		return "", errors.New("Launcher credentials do not manage Launchers")
	default:
		return "", fmt.Errorf("unknown authority %q", auth.Authority)
	}
}

// launcherSelectorTarget resolves the CLI target for an individual Launcher
// command: the Principal from --principal or auth introspection (target
// construction only — the daemon remains the authorization authority) and the
// Launcher selector (name or ID), 'default' when the positional selector is
// omitted. Admin authentication must name the Principal explicitly; it is
// never inferred and never searched globally.
func launcherSelectorTarget(client *apiClient, explicitPrincipal string, fs *flag.FlagSet) (username, selector string, err error) {
	username, err = resolveLauncherPrincipalForCLI(client, explicitPrincipal)
	if err != nil {
		return "", "", err
	}
	selector = defaultLauncherName
	if fs.NArg() > 0 {
		selector = fs.Arg(0)
	}
	return username, selector, nil
}

func encodeJSONOut(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func launcherOpClient(system bool, endpoint, tokenFile string) (*apiClient, error) {
	return resolveOperatorClient(operatorClientOptions{
		System:    system,
		Endpoint:  endpoint,
		TokenFile: tokenFile,
	})
}

var launcherCommand = &Command{
	Name:    "launcher",
	Summary: "Manage launchers",
	Subcommands: []*Command{
		launcherCreateCommand,
		launcherListCommand,
		launcherShowCommand,
		launcherSetCommand,
		launcherDeleteCommand,
		launcherScopeCommand,
		launcherCredentialCommand,
	},
}

var launcherCreateCommand = &Command{
	Name:       "create",
	Summary:    "Create a launcher",
	Usage:      "docker-helper launcher create [--principal USER] [--name NAME] [--allowed-root PATH]... [--issue-credential | --no-credential]",
	MinPosArgs: 0,
	MaxPosArgs: 0,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		system, endpoint, tokenFile := registerOperatorFlags(fs)
		principal := fs.String("principal", "", "Principal username (inferred from credential when omitted)")
		name := &launcherNameFlag{}
		fs.Var(name, "name", "Launcher name (default: \"default\"; provisioned automatically at principal creation)")
		allowedRoots := &stringListFlag{}
		fs.Var(allowedRoots, "allowed-root", "Allowed root path (restricted scope)")
		issueCredential := fs.Bool("issue-credential", false, "Issue a launcher credential")
		noCredential := fs.Bool("no-credential", false, "Do not issue a launcher credential")
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				client, err := launcherOpClient(*system, *endpoint, *tokenFile)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				issue, err := resolveIssueCredential(*issueCredential, *noCredential,
					"Create launcher credential now? [Y/n]", os.Stdin, stderr, term.IsTerminal(int(os.Stdin.Fd())))
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 2
				}
				username, err := resolveLauncherPrincipalForCLI(client, *principal)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				req := createLauncherClientRequest{IssueCredential: issue}
				req.Name = defaultLauncherName
				if name.set {
					req.Name = name.value
				}
				if len(allowedRoots.values) == 0 {
					req.Scope = "inherit"
					req.AllowedRoots = []string{}
				} else {
					req.Scope = "restricted"
					req.AllowedRoots = append([]string{}, allowedRoots.values...)
				}

				result, err := client.createLauncher(username, req)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				if err := encodeJSONOut(stdout, result); err != nil {
					fmt.Fprintf(stderr, "error: cannot encode output: %v\n", err)
					return 1
				}
				return 0
			},
		}
	},
}

var launcherListCommand = &Command{
	Name:       "list",
	Summary:    "List launchers",
	Usage:      "docker-helper launcher list [--principal USER] [--json]",
	MinPosArgs: 0,
	MaxPosArgs: 0,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		system, endpoint, tokenFile := registerOperatorFlags(fs)
		principal := fs.String("principal", "", "Principal username (inferred from credential when omitted)")
		jsonOut := fs.Bool("json", false, "Output in JSON format")
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				client, err := launcherOpClient(*system, *endpoint, *tokenFile)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				username, err := resolveLauncherPrincipalForCLI(client, *principal)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				result, err := client.listLaunchers(username)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				if *jsonOut {
					if err := encodeJSONOut(stdout, result); err != nil {
						fmt.Fprintf(stderr, "error: cannot encode output: %v\n", err)
						return 1
					}
					return 0
				}
				fmt.Fprintf(stdout, "%-40s %-10s %-30s %-10s %s\n", "ID", "NAME", "SCOPE", "ENABLED", "PRINCIPAL")
				for _, l := range result.Launchers {
					enabled := "no"
					if l.Enabled {
						enabled = "yes"
					}
					fmt.Fprintf(stdout, "%-40s %-10s %-30s %-10s %s\n", l.ID, l.Name, l.Scope, enabled, l.Principal)
				}
				return 0
			},
		}
	},
}

var launcherShowCommand = &Command{
	Name:       "show",
	Summary:    "Show launcher details",
	Usage:      "docker-helper launcher show [--principal USER] [LAUNCHER]",
	MinPosArgs: 0,
	MaxPosArgs: 1,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		system, endpoint, tokenFile := registerOperatorFlags(fs)
		principal := fs.String("principal", "", "Principal username (inferred from credential when omitted)")
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				client, err := launcherOpClient(*system, *endpoint, *tokenFile)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				username, selector, err := launcherSelectorTarget(client, *principal, fs)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				l, err := client.showLauncher(username, selector)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				if err := encodeJSONOut(stdout, l); err != nil {
					fmt.Fprintf(stderr, "error: cannot encode output: %v\n", err)
					return 1
				}
				return 0
			},
		}
	},
}

var launcherSetCommand = &Command{
	Name:       "set",
	Summary:    "Modify a launcher name or enabled state",
	Usage:      "docker-helper launcher set [--principal USER] [--name NAME] [--enabled true|false] [LAUNCHER]",
	MinPosArgs: 0,
	MaxPosArgs: 1,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		system, endpoint, tokenFile := registerOperatorFlags(fs)
		principal := fs.String("principal", "", "Principal username (inferred from credential when omitted)")
		name := &launcherNameFlag{}
		fs.Var(name, "name", "New launcher name")
		enabled := fs.String("enabled", "", "Enable or disable the launcher (true|false)")
		return Invocation{
			Validate: func() error {
				if !name.set && *enabled == "" {
					return errors.New("at least one of --name or --enabled is required")
				}
				if *enabled != "" && *enabled != "true" && *enabled != "false" {
					return fmt.Errorf("--enabled must be true or false, got %q", *enabled)
				}
				return nil
			},
			Run: func(stdout, stderr io.Writer) int {
				client, err := launcherOpClient(*system, *endpoint, *tokenFile)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				username, selector, err := launcherSelectorTarget(client, *principal, fs)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				req := patchLauncherRequest{}
				if name.set {
					n := name.value
					req.Name = &n
				}
				if *enabled != "" {
					e := *enabled == "true"
					req.Enabled = &e
				}
				l, err := client.patchLauncher(username, selector, req)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				if err := encodeJSONOut(stdout, l); err != nil {
					fmt.Fprintf(stderr, "error: cannot encode output: %v\n", err)
					return 1
				}
				return 0
			},
		}
	},
}

var launcherDeleteCommand = &Command{
	Name:       "delete",
	Summary:    "Delete a launcher",
	Usage:      "docker-helper launcher delete [--principal USER] [LAUNCHER]",
	MinPosArgs: 0,
	MaxPosArgs: 1,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		system, endpoint, tokenFile := registerOperatorFlags(fs)
		principal := fs.String("principal", "", "Principal username (inferred from credential when omitted)")
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				client, err := launcherOpClient(*system, *endpoint, *tokenFile)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				username, selector, err := launcherSelectorTarget(client, *principal, fs)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				if err := client.deleteLauncher(username, selector); err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				fmt.Fprintf(stdout, "deleted launcher %s\n", selector)
				return 0
			},
		}
	},
}

var launcherScopeCommand = &Command{
	Name:    "scope",
	Summary: "Manage launcher scope",
	Subcommands: []*Command{
		launcherScopeSetCommand,
	},
}

var launcherScopeSetCommand = &Command{
	Name:       "set",
	Summary:    "Replace launcher scope",
	Usage:      "docker-helper launcher scope set [--principal USER] [--inherit | --allowed-root PATH [--allowed-root PATH]...] [LAUNCHER]",
	MinPosArgs: 0,
	MaxPosArgs: 1,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		system, endpoint, tokenFile := registerOperatorFlags(fs)
		principal := fs.String("principal", "", "Principal username (inferred from credential when omitted)")
		inherit := fs.Bool("inherit", false, "Inherit the principal's scope")
		allowedRoots := &stringListFlag{}
		fs.Var(allowedRoots, "allowed-root", "Allowed root path (restricted scope)")
		return Invocation{
			Validate: func() error {
				if *inherit && len(allowedRoots.values) > 0 {
					return errors.New("--inherit and --allowed-root are mutually exclusive")
				}
				if !*inherit && len(allowedRoots.values) == 0 {
					return errors.New("restricted scope requires at least one --allowed-root (or use --inherit)")
				}
				return nil
			},
			Run: func(stdout, stderr io.Writer) int {
				client, err := launcherOpClient(*system, *endpoint, *tokenFile)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				username, selector, err := launcherSelectorTarget(client, *principal, fs)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				req := allowedRootsReplaceRequest{}
				if *inherit {
					req.Scope = "inherit"
					req.AllowedRoots = []string{}
				} else {
					req.Scope = "restricted"
					req.AllowedRoots = append([]string{}, allowedRoots.values...)
				}
				l, err := client.replaceLauncherScope(username, selector, req)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				if err := encodeJSONOut(stdout, l); err != nil {
					fmt.Fprintf(stderr, "error: cannot encode output: %v\n", err)
					return 1
				}
				return 0
			},
		}
	},
}

var launcherCredentialCommand = &Command{
	Name:    "credential",
	Summary: "Manage launcher credentials",
	Subcommands: []*Command{
		launcherCredentialIssueCommand,
		launcherCredentialRotateCommand,
		launcherCredentialDeleteCommand,
	},
}

var launcherCredentialIssueCommand = &Command{
	Name:       "issue",
	Summary:    "Issue a launcher credential",
	Usage:      "docker-helper launcher credential issue [--principal USER] [LAUNCHER]",
	MinPosArgs: 0,
	MaxPosArgs: 1,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		system, endpoint, tokenFile := registerOperatorFlags(fs)
		principal := fs.String("principal", "", "Principal username (inferred from credential when omitted)")
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				client, err := launcherOpClient(*system, *endpoint, *tokenFile)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				username, selector, err := launcherSelectorTarget(client, *principal, fs)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				result, err := client.issueLauncherCredential(username, selector)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				if err := encodeJSONOut(stdout, result); err != nil {
					fmt.Fprintf(stderr, "error: cannot encode output: %v\n", err)
					return 1
				}
				return 0
			},
		}
	},
}

var launcherCredentialRotateCommand = &Command{
	Name:       "rotate",
	Summary:    "Rotate a launcher credential",
	Usage:      "docker-helper launcher credential rotate [--principal USER] [LAUNCHER]",
	MinPosArgs: 0,
	MaxPosArgs: 1,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		system, endpoint, tokenFile := registerOperatorFlags(fs)
		principal := fs.String("principal", "", "Principal username (inferred from credential when omitted)")
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				client, err := launcherOpClient(*system, *endpoint, *tokenFile)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				username, selector, err := launcherSelectorTarget(client, *principal, fs)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				result, err := client.rotateLauncherCredential(username, selector)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				if err := encodeJSONOut(stdout, result); err != nil {
					fmt.Fprintf(stderr, "error: cannot encode output: %v\n", err)
					return 1
				}
				return 0
			},
		}
	},
}

var launcherCredentialDeleteCommand = &Command{
	Name:       "delete",
	Summary:    "Delete a launcher credential",
	Usage:      "docker-helper launcher credential delete [--principal USER] [LAUNCHER]",
	MinPosArgs: 0,
	MaxPosArgs: 1,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		system, endpoint, tokenFile := registerOperatorFlags(fs)
		principal := fs.String("principal", "", "Principal username (inferred from credential when omitted)")
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				client, err := launcherOpClient(*system, *endpoint, *tokenFile)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				username, selector, err := launcherSelectorTarget(client, *principal, fs)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				if err := client.deleteLauncherCredential(username, selector); err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				fmt.Fprintf(stdout, "deleted launcher credential for %s\n", selector)
				return 0
			},
		}
	},
}
