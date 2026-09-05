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
		errors.New("Launcher credentials do not manage Launchers"), nil)
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

// launcherSelectorTarget resolves the CLI target for an individual Launcher
// command: the Principal from --principal or auth introspection (target
// construction only — the daemon remains the authorization authority) and the
// Launcher selector (name or ID), 'default' when the positional selector is
// omitted. Admin authentication must name the Principal explicitly for a
// Launcher name or the omitted default; an ID-shaped selector (dhl_...)
// resolves the owning Principal through the daemon's scope-first list query
// and never searches Launcher names globally.
func launcherSelectorTarget(client *apiClient, explicitPrincipal string, fs *flag.FlagSet) (username, selector string, err error) {
	selector = defaultLauncherName
	if fs.NArg() > 0 {
		selector = fs.Arg(0)
	}
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
	username, err = resolveTargetPrincipalForCLI(client, explicitPrincipal,
		errors.New("--principal is required for admin authentication"),
		errors.New("Launcher credentials do not manage Launchers"), adminResolver)
	if err != nil {
		return "", "", err
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

// launcherDefaultConflictHint is the CLI's pre-flight rejection for the
// guaranteed conflict of creating the auto-provisioned 'default' Launcher:
// every Principal gets a 'default' Launcher at creation, so a create without
// --name can only collide. The check is a read-only show of the Launcher the
// caller could fetch anyway; the create itself stays atomic on the daemon.
const launcherDefaultConflictHint = "; use --name NAME to create a differently named launcher"

// launcherDefaultExists reports whether the target Principal's 'default'
// Launcher already exists. The check is advisory pre-flight: any query
// failure, including a transient server error, reports false so the create
// request remains the authoritative conflict boundary.
func launcherDefaultExists(client *apiClient, username string) bool {
	_, err := client.showLauncher(username, defaultLauncherName)
	return err == nil
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
				username, err := resolveLauncherPrincipalForCLI(client, *principal)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				targetName := defaultLauncherName
				if name.set {
					targetName = name.value
				}
				// Without --name the request targets the auto-provisioned
				// 'default' Launcher, which every Principal already has:
				// reject before the credential prompt instead of walking
				// into the daemon's guaranteed conflict. With --name the
				// create stays atomic and the daemon's conflict response
				// names the colliding Launcher and Principal.
				if !name.set && launcherDefaultExists(client, username) {
					fmt.Fprintf(stderr, "error: launcher %q already exists for principal %q%s\n",
						defaultLauncherName, username, launcherDefaultConflictHint)
					return 1
				}
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
	Usage:      "docker-helper launcher list [--system] [--endpoint ENDPOINT] [--token-file PATH] [--principal USER] [--launcher LAUNCHER] [--json]",
	MinPosArgs: 0,
	MaxPosArgs: 0,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		system, endpoint, tokenFile := registerOperatorFlags(fs)
		principal := fs.String("principal", "", "Principal username filter (narrowing only; the daemon authorizes visibility)")
		launcher := fs.String("launcher", "", "Launcher name or ID filter (admin without --principal must use an ID)")
		jsonOut := fs.Bool("json", false, "Output in JSON format")
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				client, err := launcherOpClient(*system, *endpoint, *tokenFile)
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
	Usage:      "docker-helper launcher credential create [--principal USER] [LAUNCHER]",
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

var launcherCredentialShowCommand = &Command{
	Name:       "show",
	Summary:    "Show a launcher credential",
	Usage:      "docker-helper launcher credential show [--principal USER] [LAUNCHER]",
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
				result, err := client.getLauncherCredential(username, selector)
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
