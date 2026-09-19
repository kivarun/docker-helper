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

// explicitStringFlag is a presence-aware string flag. It distinguishes an
// omitted flag from an explicitly supplied value, including the empty string.
// Command-specific validation decides whether the explicit value is valid.
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

// resolveTargetPrincipalForCLI is the shared scope-aware Principal selector
// for ownership-scoped CLI commands: an explicit Principal selector wins;
// otherwise the Principal is inferred from GET /auth for a Principal-credential
// caller (the authenticated credential defines the effective visibility
// scope). Admin authentication must name the target explicitly (it is never
// inferred and never searched globally); a Launcher credential has no
// control-plane authority. adminErr and launcherErr carry the calling command
// family's rejection messages. adminResolver, when non-nil, gives admin
// authentication one selector-driven way to name the target (the Launcher
// selector rule: an ID-shaped selector resolves the owning Principal through
// the daemon); returning handled=false falls back to adminErr.
func resolveTargetPrincipalForCLI(client *apiClient, explicitPrincipal string, adminErr, launcherErr error, adminResolver func() (username string, handled bool, err error)) (string, error) {
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
		if adminResolver != nil {
			username, handled, err := adminResolver()
			if err != nil {
				return "", err
			}
			if handled {
				return username, nil
			}
		}
		return "", adminErr
	case "launcher":
		return "", launcherErr
	default:
		return "", fmt.Errorf("unknown authority %q", auth.Authority)
	}
}

// resolveLauncherPrincipalForCLI returns the username to target on the canonical
// nested /principals/{username}/launchers endpoint. When --principal is omitted
// it infers the Principal from GET /auth; explicit --principal targets the
// endpoint directly with no local pre-authorization (the daemon remains the
// authorization authority).
func resolveLauncherPrincipalForCLI(client *apiClient, explicitPrincipal string) (string, error) {
	return resolveTargetPrincipalForCLI(client, explicitPrincipal,
		errors.New("--principal is required for admin authentication"),
		errLauncherCredentialNoManagement, nil)
}

// resolvePrincipalTargetForCLI returns the Principal targeted by a Principal
// credential command (list/rotate): the optional explicit selector, or the
// authenticated Principal-credential owner. The same scope-aware rule as the
// Launcher command family applies; only the rejection messages differ.
func resolvePrincipalTargetForCLI(client *apiClient, explicitPrincipal string) (string, error) {
	return resolveTargetPrincipalForCLI(client, explicitPrincipal,
		errors.New("PRINCIPAL is required for admin authentication"),
		errors.New("Launcher credentials do not manage Principal credentials"), nil)
}

// resolveLauncherPrincipalByID resolves the owning Principal of an ID-shaped
// Launcher selector through the daemon's scope-first launcher list query.
// The daemon remains the authorization authority: the query narrows by the
// exact Launcher ID server-side and never searches Launcher names globally.
func resolveLauncherPrincipalByID(client *apiClient, selector string) (string, error) {
	result, err := client.listLaunchersFiltered("", selector)
	if err != nil {
		return "", err
	}
	if len(result.Launchers) != 1 {
		return "", ErrLauncherNotFound
	}
	return result.Launchers[0].Principal, nil
}

// launcherSelectorTargetSelector resolves the CLI target for one Launcher
// selector: the Principal from --principal or auth introspection (target
// construction only — the daemon remains the authorization authority) and the
// given Launcher selector (name or ID). Admin authentication must name the
// Principal explicitly for a Launcher name; an ID-shaped selector (dhl_...)
// resolves the owning Principal through the daemon's scope-first list query
// and never searches Launcher names globally.
// errLauncherCredentialNoManagement is the local targeting refusal of
// commands whose target construction has no Launcher-credential capability:
// a Launcher credential does not manage Launchers. The rotate command
// catches exactly this sentinel for its narrow self-rotation exception.
var errLauncherCredentialNoManagement = errors.New("Launcher credentials do not manage Launchers")

func launcherSelectorTargetSelector(client *apiClient, explicitPrincipal, selector string) (string, error) {
	adminResolver := func() (string, bool, error) {
		if !isLauncherIDSelector(selector) {
			return "", false, nil
		}
		owner, err := resolveLauncherPrincipalByID(client, selector)
		if err != nil {
			return "", true, err
		}
		return owner, true, nil
	}
	return resolveTargetPrincipalForCLI(client, explicitPrincipal,
		errors.New("--principal is required for admin authentication"),
		errLauncherCredentialNoManagement, adminResolver)
}

// launcherSelectorTarget resolves the CLI target for an individual Launcher
// command: the Principal from --principal or auth introspection (target
// construction only — the daemon remains the authorization authority) and the
// Launcher selector (name or ID), 'default' when the positional selector is
// omitted.
func launcherSelectorTarget(client *apiClient, explicitPrincipal string, fs *flag.FlagSet) (username, selector string, err error) {
	selector = defaultLauncherName
	if fs.NArg() > 0 {
		selector = fs.Arg(0)
	}
	username, err = launcherSelectorTargetSelector(client, explicitPrincipal, selector)
	return username, selector, err
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
		launcherAllowedRootCommand,
		launcherCredentialCommand,
	},
}

var launcherCreateCommand = &Command{
	Name:       "create",
	Summary:    "Create a launcher",
	Usage:      "docker-helper launcher create [--system] [--endpoint ENDPOINT] [--token-file PATH] [--principal USER] [--allowed-root PATH]... [--issue-credential | --no-credential] [--json] NAME",
	MinPosArgs: 1,
	MaxPosArgs: 1,

	Presentation: humanJSONPresentation(),

	NewInvocation: func(fs *flag.FlagSet) Invocation {
		system, endpoint, tokenFile := registerOperatorFlags(fs)
		principal := fs.String("principal", "", "Principal username (inferred from credential when omitted)")
		allowedRoots := &stringListFlag{}
		fs.Var(allowedRoots, "allowed-root", "Allowed root path (restricted scope)")
		issueCredential := fs.Bool("issue-credential", false, "Issue a launcher credential")
		noCredential := fs.Bool("no-credential", false, "Do not issue a launcher credential")
		jsonOut := fs.Bool("json", false, "Output in JSON format")
		return Invocation{
			Validate: func() error {
				if err := validateOperatorEndpointOptions(operatorClientOptions{
					System:      *system,
					Endpoint:    endpoint.value,
					EndpointSet: endpoint.set,
					TokenFile:   *tokenFile,
				}); err != nil {
					return err
				}
				return nil
			},
			Run: func(stdout, stderr io.Writer) int {
				client, err := launcherOpClient(*system, endpoint.value, *tokenFile)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				username, err := resolveLauncherPrincipalForCLI(client, *principal)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				// The Launcher name is the primary resource identity and is
				// positional, like the other resource create commands. An
				// attempt to create the auto-provisioned 'default' Launcher
				// is an ordinary create: the daemon's conflict response names
				// the colliding Launcher and Principal.
				targetName := fs.Arg(0)
				issue, err := resolveIssueCredential(*issueCredential, *noCredential,
					"Create launcher credential now? [Y/n]", os.Stdin, stderr, term.IsTerminal(int(os.Stdin.Fd())))
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 2
				}

				req := createLauncherClientRequest{IssueCredential: issue}
				req.Name = targetName
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

				if *jsonOut {
					if err := encodeJSONOut(stdout, result); err != nil {
						fmt.Fprintf(stderr, "error: cannot encode output: %v\n", err)
						return 1
					}
					if result.Token != "" {
						printCredentialInstallHint(stderr, "launcher")
					}
					return 0
				}

				printLauncherShow(stdout, &result.Launcher)
				if result.Token != "" {
					fmt.Fprintf(stdout, "TOKEN:     %s\n", result.Token)
					printCredentialInstallHint(stdout, "launcher")
				}
				return 0
			},
		}
	},
}

var launcherListCommand = &Command{
	Name:       "list",
	Summary:    "List launchers",
	Usage:      "docker-helper launcher list [--system] [--endpoint ENDPOINT] [--token-file PATH] [--principal USER] [--launcher LAUNCHER] [--json]",
	MinPosArgs: 0,
	MaxPosArgs: 0,

	Presentation: humanJSONPresentation(),

	NewInvocation: func(fs *flag.FlagSet) Invocation {
		system, endpoint, tokenFile := registerOperatorFlags(fs)
		principal := fs.String("principal", "", "Principal username filter (narrowing only; the daemon authorizes visibility)")
		launcher := fs.String("launcher", "", "Launcher name or ID filter (admin without --principal must use an ID)")
		jsonOut := fs.Bool("json", false, "Output in JSON format")
		return Invocation{
			Validate: func() error {
				if err := validateOperatorEndpointOptions(operatorClientOptions{
					System:      *system,
					Endpoint:    endpoint.value,
					EndpointSet: endpoint.set,
					TokenFile:   *tokenFile,
				}); err != nil {
					return err
				}
				return nil
			},
			Run: func(stdout, stderr io.Writer) int {
				client, err := launcherOpClient(*system, endpoint.value, *tokenFile)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				// Scope-first list: the daemon authorizes the query against the
				// authenticated bearer and performs the narrowing server-side;
				// both selectors are sent as-is and the CLI never filters a
				// broader collection locally.
				result, err := client.listLaunchersFiltered(*principal, *launcher)
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
	Usage:      "docker-helper launcher show [--system] [--endpoint ENDPOINT] [--token-file PATH] [--principal USER] [--json] [LAUNCHER]",
	MinPosArgs: 0,
	MaxPosArgs: 1,

	Presentation: humanJSONPresentation(),

	NewInvocation: func(fs *flag.FlagSet) Invocation {
		system, endpoint, tokenFile := registerOperatorFlags(fs)
		principal := fs.String("principal", "", "Principal username (inferred from credential when omitted)")
		jsonOut := fs.Bool("json", false, "Output the canonical JSON document")
		return Invocation{
			Validate: func() error {
				if err := validateOperatorEndpointOptions(operatorClientOptions{
					System:      *system,
					Endpoint:    endpoint.value,
					EndpointSet: endpoint.set,
					TokenFile:   *tokenFile,
				}); err != nil {
					return err
				}
				return nil
			},
			Run: func(stdout, stderr io.Writer) int {
				client, err := launcherOpClient(*system, endpoint.value, *tokenFile)
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
				if *jsonOut {
					if err := encodeJSONOut(stdout, l); err != nil {
						fmt.Fprintf(stderr, "error: cannot encode output: %v\n", err)
						return 1
					}
					return 0
				}
				printLauncherShow(stdout, l)
				return 0
			},
		}
	},
}

// printLauncherCredentialBlock renders the human launcher-credential
// metadata block shared by the launcher credential commands whose default
// output is the human block. No secret is part of the block; the one-time
// token is rendered separately by the issuing commands.
func printLauncherCredentialBlock(w io.Writer, c *launcherCredentialJSON) {
	if c == nil {
		fmt.Fprintln(w, "CREDENTIAL: -")
		return
	}
	fmt.Fprintf(w, "ID:        %s\n", c.ID)
	fmt.Fprintf(w, "CREATED:   %s\n", c.CreatedAt)
	revoked := "-"
	if c.RevokedAt != nil {
		revoked = *c.RevokedAt
	}
	fmt.Fprintf(w, "REVOKED:   %s\n", revoked)
}

// printLauncherShow renders the human launcher-show block: the identity
// fields and the stored allowed roots through the shared PATH/ACCESS table
// renderer. The canonical JSON document remains the explicit --json form.
func printLauncherShow(w io.Writer, l *launcherJSON) {
	fmt.Fprintf(w, "ID:        %s\n", l.ID)
	fmt.Fprintf(w, "NAME:      %s\n", l.Name)
	fmt.Fprintf(w, "PRINCIPAL: %s\n", l.Principal)
	fmt.Fprintf(w, "ENABLED:   %t\n", l.Enabled)
	fmt.Fprintf(w, "SCOPE:     %s\n", l.Scope)
	fmt.Fprintf(w, "CREATED:   %s\n", l.CreatedAt)
	printRootEntriesTable(w, "ALLOWED ROOTS", l.AllowedRoots)
}

var launcherSetCommand = &Command{
	Name:       "set",
	Summary:    "Modify a launcher name or enabled state",
	Usage:      "docker-helper launcher set [--system] [--endpoint ENDPOINT] [--token-file PATH] [--principal USER] [--name NAME] [--enabled true|false] [--json] [LAUNCHER]",
	MinPosArgs: 0,
	MaxPosArgs: 1,

	Presentation: humanJSONPresentation(),

	NewInvocation: func(fs *flag.FlagSet) Invocation {
		system, endpoint, tokenFile := registerOperatorFlags(fs)
		principal := fs.String("principal", "", "Principal username (inferred from credential when omitted)")
		name := &explicitStringFlag{}
		fs.Var(name, "name", "New launcher name")
		enabled := fs.String("enabled", "", "Enable or disable the launcher (true|false)")
		jsonOut := fs.Bool("json", false, "Output in JSON format")
		return Invocation{
			Validate: func() error {
				if err := validateOperatorEndpointOptions(operatorClientOptions{
					System:      *system,
					Endpoint:    endpoint.value,
					EndpointSet: endpoint.set,
					TokenFile:   *tokenFile,
				}); err != nil {
					return err
				}
				if !name.set && *enabled == "" {
					return errors.New("at least one of --name or --enabled is required")
				}
				if *enabled != "" && *enabled != "true" && *enabled != "false" {
					return fmt.Errorf("--enabled must be true or false, got %q", *enabled)
				}
				return nil
			},
			Run: func(stdout, stderr io.Writer) int {
				client, err := launcherOpClient(*system, endpoint.value, *tokenFile)
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

				if *jsonOut {
					if err := encodeJSONOut(stdout, l); err != nil {
						fmt.Fprintf(stderr, "error: cannot encode output: %v\n", err)
						return 1
					}
					return 0
				}

				printLauncherShow(stdout, l)
				return 0
			},
		}
	},
}

var launcherDeleteCommand = &Command{
	Name:       "delete",
	Summary:    "Delete a launcher",
	Usage:      "docker-helper launcher delete [--system] [--endpoint ENDPOINT] [--token-file PATH] [--principal USER] [--json] [LAUNCHER]",
	MinPosArgs: 0,
	MaxPosArgs: 1,

	Presentation: humanJSONPresentation(),

	NewInvocation: func(fs *flag.FlagSet) Invocation {
		system, endpoint, tokenFile := registerOperatorFlags(fs)
		principal := fs.String("principal", "", "Principal username (inferred from credential when omitted)")
		jsonOut := fs.Bool("json", false, "Output in JSON format")
		return Invocation{
			Validate: func() error {
				if err := validateOperatorEndpointOptions(operatorClientOptions{
					System:      *system,
					Endpoint:    endpoint.value,
					EndpointSet: endpoint.set,
					TokenFile:   *tokenFile,
				}); err != nil {
					return err
				}
				return nil
			},
			Run: func(stdout, stderr io.Writer) int {
				client, err := launcherOpClient(*system, endpoint.value, *tokenFile)
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

				if *jsonOut {
					if err := encodeJSONOut(stdout, deletedResourceResult{Launcher: selector, Deleted: true}); err != nil {
						fmt.Fprintf(stderr, "error: cannot encode output: %v\n", err)
						return 1
					}
					return 0
				}

				fmt.Fprintf(stdout, "deleted launcher %s\n", selector)
				return 0
			},
		}
	},
}

// launcherAllowedRootTarget resolves the CLI target for the target-first
// positional launcher allowed-root add/remove forms: [LAUNCHER] PATH. One
// positional is the PATH under the Principal's 'default' Launcher; two
// positionals are the LAUNCHER selector (name or dhl_ ID) and the PATH. The
// Principal resolves once through the shared selector owner
// (launcherSelectorTargetSelector): the daemon remains the authorization
// authority.
func launcherAllowedRootTarget(client *apiClient, explicitPrincipal string, fs *flag.FlagSet) (username, selector, path string, err error) {
	args := fs.Args()
	selector = defaultLauncherName
	operands := args
	if len(args) == 2 {
		selector = args[0]
		operands = args[1:]
	}
	path = operands[0]
	username, err = launcherSelectorTargetSelector(client, explicitPrincipal, selector)
	if err != nil {
		return "", "", "", err
	}
	return username, selector, path, nil
}

// launcherAllowedRootSetAccessTarget decomposes the target-first positional
// operands of the launcher allowed-root set-access command: an optional
// leading LAUNCHER selector (name or dhl_ ID) followed by PATH ACCESS. Two
// positionals are the PATH and the access value under the Principal's
// 'default' Launcher; three positionals are the LAUNCHER selector, the PATH,
// and the access value. The daemon performs the conditional mutation, so the
// CLI never reads and re-sends the root list.
func launcherAllowedRootSetAccessTarget(fs *flag.FlagSet) (selector, path, access string) {
	args := fs.Args()
	selector = defaultLauncherName
	operands := args
	if len(args) == 3 {
		selector = args[0]
		operands = args[1:]
	}
	path = operands[0]
	access = operands[1]
	return selector, path, access
}

var launcherAllowedRootCommand = &Command{
	Name:    "allowed-root",
	Summary: "Manage launcher allowed roots",
	Subcommands: []*Command{
		launcherAllowedRootAddCommand,
		launcherAllowedRootListCommand,
		launcherAllowedRootSetAccessCommand,
		launcherAllowedRootRemoveCommand,
		launcherAllowedRootInheritCommand,
	},
}

var launcherAllowedRootAddCommand = &Command{
	Name:       "add",
	Summary:    "Add an allowed root to a launcher",
	Usage:      "docker-helper launcher allowed-root add [--system] [--endpoint ENDPOINT] [--token-file PATH] [--principal USER] [--access ACCESS] [--json] [LAUNCHER] PATH",
	MinPosArgs: 1,
	MaxPosArgs: 2,

	Presentation: humanJSONPresentation(),

	NewInvocation: func(fs *flag.FlagSet) Invocation {
		system, endpoint, tokenFile := registerOperatorFlags(fs)
		principal := fs.String("principal", "", "Principal username (inferred from credential when omitted)")
		access := &accessFlag{}
		fs.Var(access, "access", "Access mode: read_write (default) or read_only")
		jsonOut := fs.Bool("json", false, "Output in JSON format")
		return Invocation{
			Validate: func() error {
				if err := validateOperatorEndpointOptions(operatorClientOptions{
					System:      *system,
					Endpoint:    endpoint.value,
					EndpointSet: endpoint.set,
					TokenFile:   *tokenFile,
				}); err != nil {
					return err
				}
				return nil
			},
			Run: func(stdout, stderr io.Writer) int {
				client, err := launcherOpClient(*system, endpoint.value, *tokenFile)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				username, selector, path, err := launcherAllowedRootTarget(client, *principal, fs)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				result, err := client.addLauncherAllowedRoot(username, selector, path, optionalAccessFromFlag(access))
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

				fmt.Fprintf(stdout, "added %q to launcher %s\n", path, selector)
				if result.Message == "unchanged" {
					fmt.Fprintf(stdout, "(already present with access %s)\n", result.Access)
				}
				return 0
			},
		}
	},
}

var launcherAllowedRootListCommand = &Command{
	Name:       "list",
	Summary:    "List a launcher's allowed roots",
	Usage:      "docker-helper launcher allowed-root list [--system] [--endpoint ENDPOINT] [--token-file PATH] [--principal USER] [--json] [LAUNCHER]",
	MinPosArgs: 0,
	MaxPosArgs: 1,

	Presentation: humanJSONPresentation(),

	NewInvocation: func(fs *flag.FlagSet) Invocation {
		system, endpoint, tokenFile := registerOperatorFlags(fs)
		principal := fs.String("principal", "", "Principal username (inferred from credential when omitted)")
		jsonOut := fs.Bool("json", false, "Output in JSON format")
		return Invocation{
			Validate: func() error {
				if err := validateOperatorEndpointOptions(operatorClientOptions{
					System:      *system,
					Endpoint:    endpoint.value,
					EndpointSet: endpoint.set,
					TokenFile:   *tokenFile,
				}); err != nil {
					return err
				}
				return nil
			},
			Run: func(stdout, stderr io.Writer) int {
				client, err := launcherOpClient(*system, endpoint.value, *tokenFile)
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
				if err := printAllowedRootList(stdout, l.AllowedRoots, *jsonOut); err != nil {
					fmt.Fprintf(stderr, "error: cannot encode output: %v\n", err)
					return 1
				}
				return 0
			},
		}
	},
}

var launcherAllowedRootSetAccessCommand = &Command{
	Name:       "set-access",
	Summary:    "Change the access mode of a launcher allowed root",
	Usage:      "docker-helper launcher allowed-root set-access [--system] [--endpoint ENDPOINT] [--token-file PATH] [--principal USER] [--json] [LAUNCHER] PATH read_only|read_write",
	MinPosArgs: 2,
	MaxPosArgs: 3,

	Presentation: humanJSONPresentation(),

	NewInvocation: func(fs *flag.FlagSet) Invocation {
		system, endpoint, tokenFile := registerOperatorFlags(fs)
		principal := fs.String("principal", "", "Principal username (inferred from credential when omitted)")
		jsonOut := fs.Bool("json", false, "Output the shared structured set-access result")
		return Invocation{
			Validate: func() error {
				if err := validateOperatorEndpointOptions(operatorClientOptions{
					System:      *system,
					Endpoint:    endpoint.value,
					EndpointSet: endpoint.set,
					TokenFile:   *tokenFile,
				}); err != nil {
					return err
				}
				return nil
			},
			Run: func(stdout, stderr io.Writer) int {
				client, err := launcherOpClient(*system, endpoint.value, *tokenFile)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				selector, path, accessArg := launcherAllowedRootSetAccessTarget(fs)
				access, aerr := parseAllowedRootAccess(accessArg)
				if aerr != nil {
					fmt.Fprintf(stderr, "error: %v\n", aerr)
					return 2
				}
				username, err := launcherSelectorTargetSelector(client, *principal, selector)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				result, err := client.setLauncherAllowedRootAccess(username, selector, path, access)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				if err := printAllowedRootAccessResult(stdout, "launcher "+selector, result.Path,
					AllowedRootAccess(result.Access), result.Changed, false, *jsonOut); err != nil {
					fmt.Fprintf(stderr, "error: cannot encode output: %v\n", err)
					return 1
				}
				return 0
			},
		}
	},
}

var launcherAllowedRootRemoveCommand = &Command{
	Name:       "remove",
	Summary:    "Remove an allowed root from a launcher",
	Usage:      "docker-helper launcher allowed-root remove [--system] [--endpoint ENDPOINT] [--token-file PATH] [--principal USER] [--json] [LAUNCHER] PATH",
	MinPosArgs: 1,
	MaxPosArgs: 2,

	Presentation: humanJSONPresentation(),

	NewInvocation: func(fs *flag.FlagSet) Invocation {
		system, endpoint, tokenFile := registerOperatorFlags(fs)
		principal := fs.String("principal", "", "Principal username (inferred from credential when omitted)")
		jsonOut := fs.Bool("json", false, "Output in JSON format")
		return Invocation{
			Validate: func() error {
				if err := validateOperatorEndpointOptions(operatorClientOptions{
					System:      *system,
					Endpoint:    endpoint.value,
					EndpointSet: endpoint.set,
					TokenFile:   *tokenFile,
				}); err != nil {
					return err
				}
				return nil
			},
			Run: func(stdout, stderr io.Writer) int {
				client, err := launcherOpClient(*system, endpoint.value, *tokenFile)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				username, selector, path, err := launcherAllowedRootTarget(client, *principal, fs)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				result, err := client.removeLauncherAllowedRoot(username, selector, path)
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

				fmt.Fprintf(stdout, "removed %q from launcher %s\n", path, selector)
				if result.Message == "unchanged" {
					fmt.Fprintln(stdout, "(was not present)")
				}
				return 0
			},
		}
	},
}

var launcherAllowedRootInheritCommand = &Command{
	Name:       "inherit",
	Summary:    "Return a launcher to inherited allowed roots",
	Usage:      "docker-helper launcher allowed-root inherit [--system] [--endpoint ENDPOINT] [--token-file PATH] [--principal USER] [--json] [LAUNCHER]",
	MinPosArgs: 0,
	MaxPosArgs: 1,

	Presentation: humanJSONPresentation(),

	NewInvocation: func(fs *flag.FlagSet) Invocation {
		system, endpoint, tokenFile := registerOperatorFlags(fs)
		principal := fs.String("principal", "", "Principal username (inferred from credential when omitted)")
		jsonOut := fs.Bool("json", false, "Output in JSON format")
		return Invocation{
			Validate: func() error {
				if err := validateOperatorEndpointOptions(operatorClientOptions{
					System:      *system,
					Endpoint:    endpoint.value,
					EndpointSet: endpoint.set,
					TokenFile:   *tokenFile,
				}); err != nil {
					return err
				}
				return nil
			},
			Run: func(stdout, stderr io.Writer) int {
				client, err := launcherOpClient(*system, endpoint.value, *tokenFile)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				username, selector, err := launcherSelectorTarget(client, *principal, fs)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				// Returning to inherited roots is the explicit atomic
				// replacement: the complete inherit body is sent in one
				// request — never a read-modify-write.
				l, err := client.replaceLauncherScope(username, selector, LauncherScopeInherit, nil)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				if *jsonOut {
					if err := encodeJSONOut(stdout, l); err != nil {
						fmt.Fprintf(stderr, "error: cannot encode output: %v\n", err)
						return 1
					}
					return 0
				}

				printLauncherShow(stdout, l)
				return 0
			},
		}
	},
}

var launcherCredentialCommand = &Command{
	Name:    "credential",
	Summary: "Manage launcher credentials",
	Subcommands: []*Command{
		launcherCredentialCreateCommand,
		launcherCredentialShowCommand,
		launcherCredentialRotateCommand,
		launcherCredentialDeleteCommand,
	},
}

// launcherCredentialCreateCommand targets the canonical Launcher-credential
// create endpoint (PUT .../credential). The public verb is create for both
// credential kinds; the Launcher's 0..1 credential cardinality needs no
// separate verb, and an existing credential is a normal conflict error.
var launcherCredentialCreateCommand = &Command{
	Name:       "create",
	Summary:    "Create a launcher credential",
	Usage:      "docker-helper launcher credential create [--system] [--endpoint ENDPOINT] [--token-file PATH] [--principal USER] [--json] [LAUNCHER]",
	MinPosArgs: 0,
	MaxPosArgs: 1,

	Presentation: humanJSONPresentation(),

	NewInvocation: func(fs *flag.FlagSet) Invocation {
		system, endpoint, tokenFile := registerOperatorFlags(fs)
		principal := fs.String("principal", "", "Principal username (inferred from credential when omitted)")
		jsonOut := fs.Bool("json", false, "Output in JSON format")
		return Invocation{
			Validate: func() error {
				if err := validateOperatorEndpointOptions(operatorClientOptions{
					System:      *system,
					Endpoint:    endpoint.value,
					EndpointSet: endpoint.set,
					TokenFile:   *tokenFile,
				}); err != nil {
					return err
				}
				return nil
			},
			Run: func(stdout, stderr io.Writer) int {
				client, err := launcherOpClient(*system, endpoint.value, *tokenFile)
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

				if *jsonOut {
					if err := encodeJSONOut(stdout, result); err != nil {
						fmt.Fprintf(stderr, "error: cannot encode output: %v\n", err)
						return 1
					}
					if result.Token != "" {
						printCredentialInstallHint(stderr, "launcher")
					}
					return 0
				}

				printLauncherCredentialBlock(stdout, result.Credential)
				if result.Token != "" {
					fmt.Fprintf(stdout, "TOKEN:     %s\n", result.Token)
					printCredentialInstallHint(stdout, "launcher")
				}
				return 0
			},
		}
	},
}

var launcherCredentialShowCommand = &Command{
	Name:       "show",
	Summary:    "Show a launcher credential",
	Usage:      "docker-helper launcher credential show [--system] [--endpoint ENDPOINT] [--token-file PATH] [--principal USER] [--json] [LAUNCHER]",
	MinPosArgs: 0,
	MaxPosArgs: 1,

	Presentation: humanJSONPresentation(),

	NewInvocation: func(fs *flag.FlagSet) Invocation {
		system, endpoint, tokenFile := registerOperatorFlags(fs)
		principal := fs.String("principal", "", "Principal username (inferred from credential when omitted)")
		jsonOut := fs.Bool("json", false, "Output in JSON format")
		return Invocation{
			Validate: func() error {
				if err := validateOperatorEndpointOptions(operatorClientOptions{
					System:      *system,
					Endpoint:    endpoint.value,
					EndpointSet: endpoint.set,
					TokenFile:   *tokenFile,
				}); err != nil {
					return err
				}
				return nil
			},
			Run: func(stdout, stderr io.Writer) int {
				client, err := launcherOpClient(*system, endpoint.value, *tokenFile)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				username, selector, err := launcherSelectorTarget(client, *principal, fs)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				result, err := client.getLauncherCredential(username, selector)
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

				printLauncherCredentialBlock(stdout, result.Credential)
				return 0
			},
		}
	},
}

// launcherCredentialRotateTarget resolves the target of the rotate command.
// Under a Launcher credential the sole credential-management capability is
// atomic self-rotation: the exact-own request is constructed from the
// authenticated GET /auth projection, while the daemon remains the
// authorization authority. Omitted selector rotates self; the own stable
// dhl_... ID is accepted as explicit self-selection; a foreign dhl_ ID is
// forwarded unchanged for the daemon's non-disclosing refusal (the CLI
// performs no foreign lookup); a name-shaped selector gains no
// name-resolution authority; --principal must not widen scope. Admin and
// Principal targeting semantics are unchanged.
func launcherCredentialRotateTarget(client *apiClient, explicitPrincipal string, fs *flag.FlagSet) (string, string, error) {
	username, selector, targetErr := launcherSelectorTarget(client, explicitPrincipal, fs)
	if targetErr == nil {
		// Admin/Principal targeting semantics are unchanged. An explicitly
		// named Principal under a Launcher credential (the shared targeting
		// accepts it without introspection) is forwarded unchanged: the
		// daemon's self-admission compares the path against the
		// authenticated owner projection and answers the same non-disclosing
		// refusal, so --principal cannot select scope or widen it.
		return username, selector, nil
	}
	if !errors.Is(targetErr, errLauncherCredentialNoManagement) {
		return "", "", targetErr
	}
	// The Launcher-credential self-rotation exception: the exact-own request
	// is constructed from the authenticated GET /auth projection, while the
	// daemon remains the authorization authority. With Launcher
	// authentication, omission selects the authenticated Launcher (its own
	// stable ID is the exact-own spelling sent on the wire; publicly the
	// meaning is simply "own Launcher"). An explicit selector — own name,
	// own stable ID, or anything else — is forwarded unchanged: the daemon's
	// dedicated self-admission accepts the projection-matching spellings and
	// refuses every other one non-disclosing, so the CLI performs no foreign
	// lookup and gains no name-resolution authority.
	auth, err := client.auth()
	if err != nil || auth.Authority != "launcher" {
		return "", "", targetErr
	}
	if fs.NArg() == 0 {
		return auth.Principal, auth.LauncherID, nil
	}
	return auth.Principal, fs.Arg(0), nil
}

var launcherCredentialRotateCommand = &Command{
	Name:       "rotate",
	Summary:    "Rotate a launcher credential",
	Usage:      "docker-helper launcher credential rotate [--system] [--endpoint ENDPOINT] [--token-file PATH] [--principal USER] [--json] [LAUNCHER]",
	MinPosArgs: 0,
	MaxPosArgs: 1,

	Help: `Rotate a Launcher credential atomically: the same credential row keeps
its ID, ownership, and Launcher policy, only the bearer secret changes,
and the old bearer is immediately invalid. The new bearer is returned
exactly once; the caller is responsible for atomically installing it
through the supported credential-install mechanism — this command never
rewrites a credential store.

Admin and Principal-credential targeting is unchanged (--principal USER
and the optional positional LAUNCHER selector). With Launcher
authentication, omission selects the authenticated Launcher. An explicit
selector may be that Launcher's own name or stable ID; any other selector
is refused non-disclosing and grants no name-resolution authority. This
is the one credential-management capability of a Launcher credential — it
grants no other Launcher/Principal control-plane authority.`,

	Presentation: humanJSONPresentation(),

	NewInvocation: func(fs *flag.FlagSet) Invocation {
		system, endpoint, tokenFile := registerOperatorFlags(fs)
		principal := fs.String("principal", "", "Principal username (inferred from credential when omitted)")
		jsonOut := fs.Bool("json", false, "Output in JSON format")
		return Invocation{
			Validate: func() error {
				if err := validateOperatorEndpointOptions(operatorClientOptions{
					System:      *system,
					Endpoint:    endpoint.value,
					EndpointSet: endpoint.set,
					TokenFile:   *tokenFile,
				}); err != nil {
					return err
				}
				return nil
			},
			Run: func(stdout, stderr io.Writer) int {
				client, err := launcherOpClient(*system, endpoint.value, *tokenFile)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				username, selector, err := launcherCredentialRotateTarget(client, *principal, fs)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				result, err := client.rotateLauncherCredential(username, selector)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				if *jsonOut {
					if err := encodeJSONOut(stdout, result); err != nil {
						fmt.Fprintf(stderr, "error: cannot encode output: %v\n", err)
						return 1
					}
					if result.Token != "" {
						printCredentialInstallHint(stderr, "launcher")
					}
					return 0
				}

				printLauncherCredentialBlock(stdout, result.Credential)
				if result.Token != "" {
					fmt.Fprintf(stdout, "TOKEN:     %s\n", result.Token)
					printCredentialInstallHint(stdout, "launcher")
				}
				return 0
			},
		}
	},
}

var launcherCredentialDeleteCommand = &Command{
	Name:       "delete",
	Summary:    "Delete a launcher credential",
	Usage:      "docker-helper launcher credential delete [--system] [--endpoint ENDPOINT] [--token-file PATH] [--principal USER] [--json] [LAUNCHER]",
	MinPosArgs: 0,
	MaxPosArgs: 1,

	Presentation: humanJSONPresentation(),

	NewInvocation: func(fs *flag.FlagSet) Invocation {
		system, endpoint, tokenFile := registerOperatorFlags(fs)
		principal := fs.String("principal", "", "Principal username (inferred from credential when omitted)")
		jsonOut := fs.Bool("json", false, "Output in JSON format")
		return Invocation{
			Validate: func() error {
				if err := validateOperatorEndpointOptions(operatorClientOptions{
					System:      *system,
					Endpoint:    endpoint.value,
					EndpointSet: endpoint.set,
					TokenFile:   *tokenFile,
				}); err != nil {
					return err
				}
				return nil
			},
			Run: func(stdout, stderr io.Writer) int {
				client, err := launcherOpClient(*system, endpoint.value, *tokenFile)
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

				if *jsonOut {
					if err := encodeJSONOut(stdout, deletedResourceResult{Launcher: selector, Deleted: true}); err != nil {
						fmt.Fprintf(stderr, "error: cannot encode output: %v\n", err)
						return 1
					}
					return 0
				}

				fmt.Fprintf(stdout, "deleted launcher credential for %s\n", selector)
				return 0
			},
		}
	},
}
