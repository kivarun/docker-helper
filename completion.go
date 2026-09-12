package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// pathValuedFlags are flags whose value is a filesystem path (or endpoint
// socket path); Bash completion completes them with filesystem paths.
//
// Selected path-valued flags additionally receive daemon-backed
// effective-root completion through policyValueCompletions (below): the
// daemon is the authorization and policy authority and the local config is
// never interpreted as policy. When the query fails, completion degrades
// silently to the generic filesystem completion for the flag value.
var pathValuedFlags = []string{
	"endpoint",
	"token-file",
	"workspace",
	"filesystem-root",
	"context",
	"dockerfile",
	"allowed-root",
}

var completionCommand = &Command{Name: "completion",
	Summary:    "Generate shell completion script",
	Usage:      "docker-helper completion <shell>",
	MaxPosArgs: 1,
	Help: `Generate shell completion script for docker-helper.

Supported shells:
  bash    Bash completion script

Install for Bash:
  source <(docker-helper completion bash)

Or install persistently:
  docker-helper completion bash > ~/.local/share/bash-completion/completions/docker-helper`,
	Subcommands: []*Command{completionBashCommand, completionRootsCommand, completionSelectorsCommand},
}

// completionBashCommand generates the canonical capability-aware Bash
// completion script: one generator produces the whole script, so the
// emitted definitions and the single `complete` registration are the
// final behavior at declaration time.
var completionBashCommand = &Command{
	Name:    "bash",
	Summary: "Generate Bash completion script",
	Usage:   "docker-helper completion bash",
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				generateBashCompletion(stdout)
				return 0
			},
		}
	},
}

// completionRootsCommand is the machine-facing policy introspection surface
// used by generated Bash completion: the queried paths come from the daemon
// (which remains the authorization and policy authority), never from the
// local config interpreted as policy.
//
// completionQueryTimeout bounds the whole daemon exchange (dial, request,
// response) for these queries: an unavailable, unresponsive, or overloaded
// daemon must make the helper exit non-zero within a bounded sub-second
// interval so the generated Bash degrades silently to generic filesystem
// completion instead of stalling the interactive shell. Ordinary operator
// commands keep the unbounded operator client.
const completionQueryTimeout = 750 * time.Millisecond

// completionAuthorityQueryTimeout bounds the --authority-only exchange: the
// short timeout of the shell-completion authority probe.
const completionAuthorityQueryTimeout = 250 * time.Millisecond

var completionRootsCommand = &Command{
	Name:        "roots",
	Summary:     "Query effective policy roots for shell completion",
	Usage:       "docker-helper completion roots <principal|session> [...]",
	Subcommands: []*Command{completionRootsPrincipalCommand, completionRootsSessionCommand},
}

// completionRootsPrincipalCommand prints the effective allowed roots of the
// targeted Principal, one path per line. The target Principal is --principal
// when given; otherwise it is inferred from the authenticated credential with
// the same scope-aware rule the launcher command family uses. The daemon
// authorizes the query; this command performs no local policy computation.
//
// With --authority-only it instead prints exactly one of admin, principal,
// launcher — the authenticated operator authority for shell-completion
// introspection — under the short authority probe timeout; an unknown
// authority or a query failure exits non-zero. The declared invocation is the
// final behavior: no later rewrite patches this command.
var completionRootsPrincipalCommand = &Command{
	Name:       "principal",
	Summary:    "Print a Principal's effective allowed roots",
	Usage:      "docker-helper completion roots principal [--principal USER] [--authority-only] [--system] [--endpoint ENDPOINT] [--token-file PATH]",
	MinPosArgs: 0,
	MaxPosArgs: 0,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		system, endpoint, tokenFile := registerOperatorFlags(fs)
		principal := fs.String("principal", "", "Principal username (inferred from credential when omitted)")
		authorityOnly := fs.Bool("authority-only", false, "Print authenticated operator authority for shell completion")
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				timeout := completionQueryTimeout
				if *authorityOnly {
					timeout = completionAuthorityQueryTimeout
				}
				client, err := resolveOperatorClient(operatorClientOptions{
					System:    *system,
					Endpoint:  *endpoint,
					TokenFile: *tokenFile,
					Timeout:   timeout,
				})
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				if *authorityOnly {
					auth, err := client.auth()
					if err != nil {
						fmt.Fprintf(stderr, "error: %v\n", err)
						return 1
					}
					switch auth.Authority {
					case "admin", "principal", "launcher":
						fmt.Fprintln(stdout, auth.Authority)
						return 0
					default:
						fmt.Fprintf(stderr, "error: unknown authority %q\n", auth.Authority)
						return 1
					}
				}
				username, err := resolveTargetPrincipalForCLI(client, *principal,
					errors.New("--principal is required for admin authentication"),
					errors.New("Launcher credentials cannot query Principal policy"), nil)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				result, err := client.principalEffectiveRoots(username)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				for _, root := range result.AllowedRoots {
					fmt.Fprintln(stdout, root)
				}
				return 0
			},
		}
	},
}

// completionRootsSessionCommand prints the effective allowed roots of the
// Launcher that a Session created right now with this authority would use,
// one path per line. The typed --principal/--launcher selectors are
// forwarded to the daemon untouched; the daemon resolves them through the
// same canonical owners real Session creation uses, so the printed roots
// are exactly the roots a real create with the typed selectors would use. A
// rejected selector makes the query unavailable so completion falls back
// silently.
var completionRootsSessionCommand = &Command{
	Name:       "session",
	Summary:    "Print the Session-create effective allowed roots",
	Usage:      "docker-helper completion roots session [--principal USER] [--launcher LAUNCHER] [--system] [--endpoint ENDPOINT] [--token-file PATH]",
	MinPosArgs: 0,
	MaxPosArgs: 0,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		system, endpoint, tokenFile := registerOperatorFlags(fs)
		principal := &explicitStringFlag{}
		fs.Var(principal, "principal", "Principal username (admin authentication; targets the Principal's default Launcher)")
		launcher := &explicitStringFlag{}
		fs.Var(launcher, "launcher", "Launcher name or ID (dhl_...) to target instead of the default Launcher")
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				client, err := resolveOperatorClient(operatorClientOptions{
					System:    *system,
					Endpoint:  *endpoint,
					TokenFile: *tokenFile,
					Timeout:   completionQueryTimeout,
				})
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				result, err := client.sessionCreatePolicy(principal.value, launcher.value)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				for _, root := range result.AllowedRoots {
					fmt.Fprintln(stdout, root)
				}
				return 0
			},
		}
	},
}

// completionSelectorsCommand is the machine-facing selector introspection
// surface used by generated Bash completion to complete the values of the
// --principal/--launcher selector flags. The daemon remains the ownership
// and authorization authority: this command only formats the scope-applicable
// selectors the daemon returns for the authenticated authority, and a query
// failure or an unauthorized scope degrades silently (no suggestions, no
// local policy).
var completionSelectorsCommand = &Command{
	Name:        "selectors",
	Summary:     "Query scope-applicable selector values for shell completion",
	Usage:       "docker-helper completion selectors <principal|launcher> [...]",
	Subcommands: []*Command{completionSelectorsPrincipalCommand, completionSelectorsLauncherCommand},
}

// completionSelectorsPrincipalCommand prints the Principal names the
// authenticated authority may target with a --principal selector on the
// typed command path (--command), one per line. The command context comes
// from the generated completion walk; the daemon remains the ownership and
// authorization authority.
//
// An admin authority may target any Principal on every command that carries
// the selector, so it receives the daemon's Principal list. A Principal
// credential may explicitly target exactly its own Principal on the Launcher
// command families; the selector is illegal on both Session command paths —
// session create rejects every --principal under a Principal credential and
// session list rejects every Principal selector, even the credential's own
// Principal — so it receives its own username for every other command path
// and nothing on the illegal ones. A Launcher credential receives nothing:
// the selector is not applicable to it. With no command context nothing is
// offered, and a query failure degrades silently.
var completionSelectorsPrincipalCommand = &Command{
	Name:       "principal",
	Summary:    "Print the Principal names selectable with --principal",
	Usage:      "docker-helper completion selectors principal [--command PATH] [--system] [--endpoint ENDPOINT] [--token-file PATH]",
	MinPosArgs: 0,
	MaxPosArgs: 0,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		system, endpoint, tokenFile := registerOperatorFlags(fs)
		command := &explicitStringFlag{}
		fs.Var(command, "command", "Completed command path (context for the selector's applicability)")
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				client, err := resolveOperatorClient(operatorClientOptions{
					System:    *system,
					Endpoint:  *endpoint,
					TokenFile: *tokenFile,
					Timeout:   completionQueryTimeout,
				})
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				auth, err := client.auth()
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				switch auth.Authority {
				case "launcher":
					return 0
				case "principal":
					// The selector is illegal on both Session command
					// paths: session create rejects every --principal
					// under a Principal credential (conflicting
					// selectors) and session list rejects every
					// Principal selector, even the credential's own
					// Principal — a narrowing selector may only narrow,
					// never redefine authority. Unknown without a
					// command context; everywhere else the Principal
					// credential may explicitly target exactly its own
					// Principal.
					switch command.value {
					case "", "session create", "session list":
						return 0
					}
					fmt.Fprintln(stdout, auth.Principal)
					return 0
				case "admin":
					result, err := client.listPrincipals()
					if err != nil {
						fmt.Fprintf(stderr, "error: %v\n", err)
						return 1
					}
					for _, p := range result.Principals {
						fmt.Fprintln(stdout, p.Username)
					}
					return 0
				default:
					fmt.Fprintf(stderr, "error: unknown authority %q\n", auth.Authority)
					return 1
				}
			},
		}
	},
}

// completionSelectorsLauncherCommand prints the Launcher selectors the
// authenticated authority may target with a --launcher selector, one per
// line, honoring the typed --principal context: an admin with a Principal
// context receives that Principal's Launcher names; an admin without one
// receives only globally resolvable Launcher IDs (a name is never searched
// globally); a Principal credential receives its own Launchers' names —
// including when it types its own --principal context, which the daemon
// authorizes as an in-scope narrowing — and a Launcher credential receives
// nothing because explicit selectors are contractually inapplicable to it.
// A foreign or missing context fails with the daemon's non-disclosing
// contract and the command degrades silently.
var completionSelectorsLauncherCommand = &Command{
	Name:       "launcher",
	Summary:    "Print the Launcher selectors selectable with --launcher",
	Usage:      "docker-helper completion selectors launcher [--principal USER] [--system] [--endpoint ENDPOINT] [--token-file PATH]",
	MinPosArgs: 0,
	MaxPosArgs: 0,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		system, endpoint, tokenFile := registerOperatorFlags(fs)
		principal := &explicitStringFlag{}
		fs.Var(principal, "principal", "Principal context (admin authority; its Launcher names become selectable)")
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				client, err := resolveOperatorClient(operatorClientOptions{
					System:    *system,
					Endpoint:  *endpoint,
					TokenFile: *tokenFile,
					Timeout:   completionQueryTimeout,
				})
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				auth, err := client.auth()
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				var print func(l launcherJSON) string
				switch auth.Authority {
				case "launcher":
					return 0
				case "principal":
					// The daemon is the selector authority: no local
					// explicit-self rule. The own Principal context is an
					// in-scope narrowing the daemon authorizes and the
					// authorized result is printed; a foreign context is
					// rejected non-disclosing and degrades silently.
					print = func(l launcherJSON) string { return l.Name }
				case "admin":
					if principal.value == "" {
						// Without a Principal context only a globally unique
						// Launcher ID resolves; a name is never searched
						// globally.
						print = func(l launcherJSON) string { return l.ID }
					} else {
						print = func(l launcherJSON) string { return l.Name }
					}
				default:
					fmt.Fprintf(stderr, "error: unknown authority %q\n", auth.Authority)
					return 1
				}
				result, err := client.listLaunchersFiltered(principal.value, "")
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				for _, l := range result.Launchers {
					fmt.Fprintln(stdout, print(l))
				}
				return 0
			},
		}
	},
}

// completionCommandPath walks the Command tree to find the command at the given path.
// Returns nil if any component is not found.
func completionCommandPath(path []string) *Command {
	current := rootCommand
	for _, name := range path {
		found := false
		for _, sub := range current.Subcommands {
			if sub.Name == name {
				current = sub
				found = true
				break
			}
		}
		if !found {
			return nil
		}
	}
	return current
}

// collectAllCommandPaths recursively collects all command paths in the tree.
func collectAllCommandPaths(cmd *Command, prefix []string) []string {
	var paths []string
	for _, sub := range cmd.Subcommands {
		path := append([]string{}, prefix...)
		path = append(path, sub.Name)
		paths = append(paths, strings.Join(path, " "))
		paths = append(paths, collectAllCommandPaths(sub, path)...)
	}
	return paths
}

// flagInfo holds flag metadata derived from the FlagSet.
type flagInfo struct {
	name   string
	isBool bool
}

// collectFlagInfos collects all flag metadata from a command's flag set.
func collectFlagInfos(cmd *Command) []flagInfo {
	if cmd.NewInvocation == nil {
		return nil
	}
	fs := flag.NewFlagSet("", flag.ContinueOnError)
	cmd.NewInvocation(fs)
	var infos []flagInfo
	fs.VisitAll(func(f *flag.Flag) {
		info := flagInfo{name: f.Name}
		// Check if the flag implements IsBoolFlag
		if bf, ok := any(f.Value).(interface{ IsBoolFlag() bool }); ok {
			info.isBool = bf.IsBoolFlag()
		}
		infos = append(infos, info)
	})
	return infos
}

// collectFlagsForCommand collects all flag names from a command's flag set.
func collectFlagsForCommand(cmd *Command) []string {
	infos := collectFlagInfos(cmd)
	var flags []string
	for _, info := range infos {
		flags = append(flags, "--"+info.name)
		if len(info.name) == 1 {
			flags = append(flags, "-"+info.name)
		}
	}
	// Always include -h and --help for all commands (leaf and branch)
	flags = append(flags, "-h", "--help")
	return flags
}

// collectBoolFlagNames collects boolean flag names from a command's flag set.
func collectBoolFlagNames(cmd *Command) []string {
	infos := collectFlagInfos(cmd)
	var names []string
	for _, info := range infos {
		if info.isBool {
			names = append(names, info.name)
		}
	}
	// -h and --help are always boolean
	names = append(names, "h", "help")
	return names
}

// policyValueCompletion associates one (command path, flag) pair with the
// daemon-backed completion query serving its values. The generated Bash
// script re-invokes docker-helper itself for the query; the daemon remains
// the authorization and policy authority and the local config is never
// interpreted as policy. When the query fails, completion degrades silently
// to the generic filesystem completion for the flag value.
type policyValueCompletion struct {
	commandPath string
	flag        string
	query       string
}

var policyValueCompletions = []policyValueCompletion{
	{commandPath: "launcher create", flag: "allowed-root", query: "principal"},
	{commandPath: "session create", flag: "workspace", query: "session"},
	{commandPath: "session create", flag: "filesystem-root", query: "session"},
}

// generateBashCompletion generates the canonical Bash completion script for
// the docker-helper CLI: one generator emits the whole script — the
// tree-driven helpers, the availability-driven tables and evaluation helpers
// (completion_availability.go), the single capability-aware
// _docker_helper_complete_subcommands, and the single `complete`
// registration. No emitted function is redefined later in the script.
func generateBashCompletion(w io.Writer) {
	// Collect all command paths.
	allPaths := collectAllCommandPaths(rootCommand, nil)
	sort.Strings(allPaths)

	// Flag-only leaves are derived structurally from the Command tree:
	// leaf commands (NewInvocation set, no subcommands) that accept no
	// positional arguments (MaxPosArgs == 0). For these commands no
	// positional or subcommand completion applies, so an ordinary current
	// word completes the command's own flags. This is never a
	// hand-maintained command-name list: new flag-only leaf commands are
	// picked up automatically.
	var flagOnlyLeaves []string
	for _, path := range allPaths {
		cmd := completionCommandPath(strings.Split(path, " "))
		if cmd != nil && cmd.NewInvocation != nil && len(cmd.Subcommands) == 0 && cmd.MaxPosArgs == 0 {
			flagOnlyLeaves = append(flagOnlyLeaves, path)
		}
	}
	sort.Strings(flagOnlyLeaves)

	// Collect flags for each command path (leaf commands with NewInvocation).
	commandFlags := make(map[string][]string)
	collectAllFlags(rootCommand, []string{}, commandFlags)

	// Collect boolean flags for each command path.
	commandBoolFlags := make(map[string][]string)
	collectAllBoolFlags(rootCommand, []string{}, commandBoolFlags)

	// Sort command paths for deterministic output.
	sortedPaths := make([]string, 0, len(commandFlags))
	for path := range commandFlags {
		sortedPaths = append(sortedPaths, path)
	}
	sort.Strings(sortedPaths)

	// Sort bool flag paths too.
	sortedBoolPaths := make([]string, 0, len(commandBoolFlags))
	for path := range commandBoolFlags {
		sortedBoolPaths = append(sortedBoolPaths, path)
	}
	sort.Strings(sortedBoolPaths)

	fmt.Fprintln(w, "# Bash completion for docker-helper")
	fmt.Fprintln(w, "# Generated automatically - do not edit")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "# Report whether a flag takes a filesystem path value, so the")
	fmt.Fprintln(w, "# completion entry can enable Readline filename semantics for it.")
	fmt.Fprintln(w, "_docker_helper_completion_path_flag() {")
	fmt.Fprintln(w, "    case \"$1\" in")
	for _, flagName := range pathValuedFlags {
		fmt.Fprintf(w, "        --%s) return 0 ;;\n", flagName)
	}
	fmt.Fprintln(w, "        *) return 1 ;;")
	fmt.Fprintln(w, "    esac")
	fmt.Fprintln(w, "}")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "# Build the canonical logical word view of the completion input.")
	fmt.Fprintln(w, "#")
	fmt.Fprintln(w, "# Readline breaks words at COMP_WORDBREAKS characters, so a typed")
	fmt.Fprintln(w, "# argument reaches completion as several physical COMP_WORDS pieces:")
	fmt.Fprintln(w, "# the inline --flag=VALUE form arrives as --flag, =, VALUE and an")
	fmt.Fprintln(w, "# http://HOST:PORT endpoint value arrives as http, :, //HOST, :,")
	fmt.Fprintln(w, "# PORT. Every consumer of the word list — the command-path walk, the")
	fmt.Fprintln(w, "# current flag/value recognition, the typed selector extraction, the")
	fmt.Fprintln(w, "# operator-argument forwarding, the positional counting, and the")
	fmt.Fprintln(w, "# policy-root query forwarding — shares ONE normalized view built")
	fmt.Fprintln(w, "# here: the real CLI arguments of the completion line, each")
	fmt.Fprintln(w, "# represented whole. The view is reconstructed from COMP_LINE up to")
	fmt.Fprintln(w, "# COMP_POINT with the line's own lexical rules — unquoted whitespace")
	fmt.Fprintln(w, "# separates arguments, backslash escapes the next character, single")
	fmt.Fprintln(w, "# quotes are literal, double quotes honor backslash escapes; no")
	fmt.Fprintln(w, "# expansion and no multi-command operator handling — so")
	fmt.Fprintln(w, "# every physically broken argument keeps its full logical content")
	fmt.Fprintln(w, "# and no consumer needs break-character special cases. The cursor")
	fmt.Fprintln(w, "# argument is the text from its start to the cursor (an empty")
	fmt.Fprintln(w, "# argument when the cursor sits after whitespace); arguments beyond")
	fmt.Fprintln(w, "# the cursor are not part of the view. A synthetic caller that")
	fmt.Fprintln(w, "# presents argument-level COMP_WORDS without COMP_LINE gets that")
	fmt.Fprintln(w, "# array verbatim.")
	fmt.Fprintln(w, "_docker_helper_normalize_line() {")
	fmt.Fprintln(w, "    _docker_helper_WORDS=()")
	fmt.Fprintln(w, "    if [ -z \"${COMP_LINE:-}\" ]; then")
	fmt.Fprintln(w, "        _docker_helper_WORDS=(\"${COMP_WORDS[@]}\")")
	fmt.Fprintln(w, "        _docker_helper_CWORD=$COMP_CWORD")
	fmt.Fprintln(w, "        return")
	fmt.Fprintln(w, "    fi")
	fmt.Fprintln(w, "    local line=\"${COMP_LINE:0:COMP_POINT}\"")
	fmt.Fprintln(w, "    local len=${#line}")
	fmt.Fprintln(w, "    local tab=$'\\t'")
	fmt.Fprintln(w, "    local i=0")
	fmt.Fprintln(w, "    local arg=\"\"")
	fmt.Fprintln(w, "    local pending=0")
	fmt.Fprintln(w, "    local rest upto j rlen d")
	fmt.Fprintln(w, "    while [ \"$i\" -lt \"$len\" ]; do")
	fmt.Fprintln(w, "        local c=\"${line:i:1}\"")
	fmt.Fprintln(w, "        if [ \"$c\" = \"'\" ]; then")
	fmt.Fprintln(w, "            # Single quotes: every character is literal.")
	fmt.Fprintln(w, "            rest=\"${line:i+1}\"")
	fmt.Fprintln(w, "            upto=\"${rest%%\\'*}\"")
	fmt.Fprintln(w, "            if [ \"${#upto}\" -eq \"${#rest}\" ]; then")
	fmt.Fprintln(w, "                arg=\"$arg$rest\"")
	fmt.Fprintln(w, "                i=$len")
	fmt.Fprintln(w, "            else")
	fmt.Fprintln(w, "                arg=\"$arg$upto\"")
	fmt.Fprintln(w, "                i=$(( i + 1 + ${#upto} + 1 ))")
	fmt.Fprintln(w, "            fi")
	fmt.Fprintln(w, "        elif [ \"$c\" = '\"' ]; then")
	fmt.Fprintln(w, "            # Double quotes: backslash escapes the next character.")
	fmt.Fprintln(w, "            rest=\"${line:i+1}\"")
	fmt.Fprintln(w, "            rlen=${#rest}")
	fmt.Fprintln(w, "            j=0")
	fmt.Fprintln(w, "            upto=\"\"")
	fmt.Fprintln(w, "            while [ \"$j\" -lt \"$rlen\" ]; do")
	fmt.Fprintln(w, "                d=\"${rest:j:1}\"")
	fmt.Fprintln(w, "                if [ \"$d\" = \"\\\\\" ]; then")
	fmt.Fprintln(w, "                    if [ \"$j\" -lt \"$rlen\" ]; then")
	fmt.Fprintln(w, "                        upto=\"$upto${rest:j+1:1}\"")
	fmt.Fprintln(w, "                        j=$(( j + 2 ))")
	fmt.Fprintln(w, "                    fi")
	fmt.Fprintln(w, "                elif [ \"$d\" = '\"' ]; then")
	fmt.Fprintln(w, "                    j=$(( j + 1 ))")
	fmt.Fprintln(w, "                    break")
	fmt.Fprintln(w, "                else")
	fmt.Fprintln(w, "                    upto=\"$upto$d\"")
	fmt.Fprintln(w, "                    j=$(( j + 1 ))")
	fmt.Fprintln(w, "                fi")
	fmt.Fprintln(w, "            done")
	fmt.Fprintln(w, "            arg=\"$arg$upto\"")
	fmt.Fprintln(w, "            i=$(( i + 1 + j ))")
	fmt.Fprintln(w, "        elif [ \"$c\" = \"\\\\\" ]; then")
	fmt.Fprintln(w, "            # Backslash escape outside quotes.")
	fmt.Fprintln(w, "            if [ \"$i\" -lt \"$(( len - 1 ))\" ]; then")
	fmt.Fprintln(w, "                arg=\"$arg${line:i+1:1}\"")
	fmt.Fprintln(w, "                i=$(( i + 2 ))")
	fmt.Fprintln(w, "            else")
	fmt.Fprintln(w, "                i=$(( i + 1 ))")
	fmt.Fprintln(w, "            fi")
	fmt.Fprintln(w, "        elif [ \"$c\" = \" \" ] || [ \"$c\" = \"$tab\" ]; then")
	fmt.Fprintln(w, "            # Unquoted whitespace separates arguments.")
	fmt.Fprintln(w, "            if [ -n \"$arg\" ]; then")
	fmt.Fprintln(w, "                _docker_helper_WORDS+=(\"$arg\")")
	fmt.Fprintln(w, "                arg=\"\"")
	fmt.Fprintln(w, "            fi")
	fmt.Fprintln(w, "            pending=1")
	fmt.Fprintln(w, "            i=$(( i + 1 ))")
	fmt.Fprintln(w, "        else")
	fmt.Fprintln(w, "            arg=\"$arg$c\"")
	fmt.Fprintln(w, "            i=$(( i + 1 ))")
	fmt.Fprintln(w, "        fi")
	fmt.Fprintln(w, "    done")
	fmt.Fprintln(w, "    if [ -n \"$arg\" ]; then")
	fmt.Fprintln(w, "        _docker_helper_WORDS+=(\"$arg\")")
	fmt.Fprintln(w, "    elif [ \"$pending\" -eq 1 ]; then")
	fmt.Fprintln(w, "        # The cursor sits after whitespace: the empty current argument.")
	fmt.Fprintln(w, "        _docker_helper_WORDS+=(\"\")")
	fmt.Fprintln(w, "    fi")
	fmt.Fprintln(w, "    _docker_helper_CWORD=$(( ${#_docker_helper_WORDS[@]} - 1 ))")
	fmt.Fprintln(w, "}")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "_docker_helper_completion() {")
	fmt.Fprintln(w, "    _docker_helper_normalize_line")
	fmt.Fprintln(w, "    local cur=\"${_docker_helper_WORDS[_docker_helper_CWORD]:-}\"")
	fmt.Fprintln(w, "    local prev=\"${_docker_helper_WORDS[_docker_helper_CWORD-1]:-}\"")
	fmt.Fprintln(w, "    local words=(\"${_docker_helper_WORDS[@]}\")")
	fmt.Fprintln(w, "    local cword=${_docker_helper_CWORD}")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "    # Enable filename semantics up front when the value being completed")
	fmt.Fprintln(w, "    # belongs to a path-valued flag — the previous word is the flag, or")
	fmt.Fprintln(w, "    # the current word is --flag=VALUE — so a daemon-backed directory")
	fmt.Fprintln(w, "    # anchor keeps its trailing slash open for continued completion")
	fmt.Fprintln(w, "    # instead of appending a space.")
	fmt.Fprintln(w, "    local inline_flag=\"\"")
	fmt.Fprintln(w, "    if [[ \"$cur\" == --*=* ]]; then inline_flag=\"${cur%%=*}\"; fi")
	fmt.Fprintln(w, "    if _docker_helper_completion_path_flag \"$prev\" || { [ -n \"$inline_flag\" ] && _docker_helper_completion_path_flag \"$inline_flag\"; }; then")
	fmt.Fprintln(w, "        compopt -o filenames 2>/dev/null || true")
	fmt.Fprintln(w, "    fi")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "    # Build the command path by walking the Command tree")
	fmt.Fprintln(w, "    local cmds=()")
	fmt.Fprintln(w, "    local i=1")
	fmt.Fprintln(w, "    local seen_double_dash=0")
	fmt.Fprintln(w, "    local seen_positional=0")
	fmt.Fprintln(w, "    # `help` is navigation: words after it walk the same command tree.")
	fmt.Fprintln(w, "    local in_help=0")
	fmt.Fprintln(w, "    while [ \"$i\" -lt \"$cword\" ]; do")
	fmt.Fprintln(w, "        local word=\"${words[$i]}\"")
	fmt.Fprintln(w, "        case \"$word\" in")
	fmt.Fprintln(w, "            --)")
	fmt.Fprintln(w, "                # End of options: no more flags or subcommands")
	fmt.Fprintln(w, "                seen_double_dash=1")
	fmt.Fprintln(w, "                ;;")
	fmt.Fprintln(w, "            -*)")
	fmt.Fprintln(w, "                # Skip flags")
	fmt.Fprintln(w, "                # Check if this flag takes a value; if so, skip the next word too")
	fmt.Fprintln(w, "                # But --flag=value is self-contained; do not skip next word.")
	fmt.Fprintln(w, "                # While the command path is still unknown the value-taking")
	fmt.Fprintln(w, "                # rule is not decidable (bool flags are per-command), so the")
	fmt.Fprintln(w, "                # next word stays in the walk instead of being swallowed.")
	fmt.Fprintln(w, "                local test_path=\"${cmds[*]}\"")
	fmt.Fprintln(w, "                if [[ \"$word\" != *=* ]] && [ -n \"$test_path\" ] && _docker_helper_flag_takes_value \"$test_path\" \"$word\"; then")
	fmt.Fprintln(w, "                    i=$((i + 2))")
	fmt.Fprintln(w, "                    continue")
	fmt.Fprintln(w, "                fi")
	fmt.Fprintln(w, "                ;;")
	fmt.Fprintln(w, "            *)")
	fmt.Fprintln(w, "                # Enter help navigation on the literal help command")
	fmt.Fprintln(w, "                if [ $in_help -eq 0 ] && [ \"$word\" = \"help\" ]; then")
	fmt.Fprintln(w, "                    in_help=1")
	fmt.Fprintln(w, "                else")
	fmt.Fprintln(w, "                    # Check if this is a valid subcommand")
	fmt.Fprintln(w, "                    local test_path")
	fmt.Fprintln(w, "                    if [ ${#cmds[@]} -eq 0 ]; then")
	fmt.Fprintln(w, "                        test_path=\"$word\"")
	fmt.Fprintln(w, "                    else")
	fmt.Fprintln(w, "                        test_path=\"${cmds[*]} $word\"")
	fmt.Fprintln(w, "                    fi")
	fmt.Fprintln(w, "                    if _docker_helper_is_command \"$test_path\"; then")
	fmt.Fprintln(w, "                        cmds+=(\"$word\")")
	fmt.Fprintln(w, "                    else")
	fmt.Fprintln(w, "                        # Not a valid subcommand; this is a positional argument")
	fmt.Fprintln(w, "                        seen_positional=1")
	fmt.Fprintln(w, "                    fi")
	fmt.Fprintln(w, "                fi")
	fmt.Fprintln(w, "                ;;")
	fmt.Fprintln(w, "        esac")
	fmt.Fprintln(w, "        i=$((i + 1))")
	fmt.Fprintln(w, "    done")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "    local cmd_path=\"${cmds[*]}\"")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "    # Under help navigation, subcommands complete from the navigated path")
	fmt.Fprintln(w, "    # while flags complete from the help command itself.")
	fmt.Fprintln(w, "    local flag_path=\"$cmd_path\"")
	fmt.Fprintln(w, "    if [ $in_help -eq 1 ]; then flag_path=\"help\"; fi")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "    # After -- (option terminator) or after a positional argument, do")
	fmt.Fprintln(w, "    # not suggest flags. A literal -- as the CURRENT word is an unfinished")
	fmt.Fprintln(w, "    # long-flag word and completes below like any other dash word.")
	fmt.Fprintln(w, "    if [ $seen_double_dash -eq 1 ] || [ $seen_positional -eq 1 ]; then")
	fmt.Fprintln(w, "        # No flag completion after -- or positional")
	fmt.Fprintln(w, "        case \"$cur\" in")
	fmt.Fprintln(w, "            -*) return ;;")
	fmt.Fprintln(w, "        esac")
	fmt.Fprintln(w, "    fi")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "    # If current word starts with -, complete flags. A partially typed")
	fmt.Fprintln(w, "    # --flag=VALUE word completes the flag's VALUE with the typed")
	fmt.Fprintln(w, "    # prefix, exactly like the separated --flag VALUE form.")
	fmt.Fprintln(w, "    if [[ \"$cur\" == --*=* ]]; then")
	fmt.Fprintln(w, "        local inline_name=\"${cur%%=*}\"")
	fmt.Fprintln(w, "        local clean_inline=\"${inline_name#-}\"")
	fmt.Fprintln(w, "        clean_inline=\"${clean_inline#-}\"")
	fmt.Fprintln(w, "        if _docker_helper_flag_takes_value \"$flag_path\" \"$clean_inline\"; then")
	fmt.Fprintln(w, "            _docker_helper_complete_flag_value \"$flag_path\" \"$clean_inline\" \"${cur#*=}\"")
	fmt.Fprintln(w, "            return")
	fmt.Fprintln(w, "        fi")
	fmt.Fprintln(w, "    fi")
	fmt.Fprintln(w, "    case \"$cur\" in")
	fmt.Fprintln(w, "        -*)")
	fmt.Fprintln(w, "            local flags=($(_docker_helper_flags \"$flag_path\"))")
	fmt.Fprintln(w, "            local comp_flags=()")
	fmt.Fprintln(w, "            for f in \"${flags[@]}\"; do")
	fmt.Fprintln(w, "                case \"$f\" in")
	fmt.Fprintln(w, "                    \"$cur\"*) comp_flags+=(\"$f\") ;;")
	fmt.Fprintln(w, "                esac")
	fmt.Fprintln(w, "            done")
	fmt.Fprintln(w, "            COMPREPLY=(\"${comp_flags[@]}\")")
	fmt.Fprintln(w, "            return")
	fmt.Fprintln(w, "            ;;")
	fmt.Fprintln(w, "    esac")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "    # If previous word was a flag that takes a value, complete the value.")
	fmt.Fprintln(w, "    # The typed value prefix (the current word for the separated form,")
	fmt.Fprintln(w, "    # the part after --flag= for the inline form) is passed explicitly.")
	fmt.Fprintln(w, "    if [ -n \"$prev\" ] && [[ \"$prev\" == -* ]]; then")
	fmt.Fprintln(w, "        local clean_prev=\"${prev#-}\"")
	fmt.Fprintln(w, "        clean_prev=\"${clean_prev#-}\"")
	fmt.Fprintln(w, "        _docker_helper_complete_flag_value \"$flag_path\" \"$clean_prev\" \"$cur\"")
	fmt.Fprintln(w, "        return")
	fmt.Fprintln(w, "    fi")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "    # Complete positional args or subcommands. Flag-only leaves fall back")
	fmt.Fprintln(w, "    # to their own flags only while flags are still applicable (not after")
	fmt.Fprintln(w, "    # -- or a positional argument, and not under help navigation).")
	fmt.Fprintln(w, "    local nofallback=0")
	fmt.Fprintln(w, "    if [ $seen_double_dash -eq 1 ] || [ $seen_positional -eq 1 ]; then nofallback=1; fi")
	fmt.Fprintln(w, "    _docker_helper_complete_positional \"$cmd_path\" \"$in_help\" \"$nofallback\"")
	fmt.Fprintln(w, "}")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "# Count the positional arguments already typed before the current")
	fmt.Fprintln(w, "# word for a command path: command-path words are skipped and the")
	fmt.Fprintln(w, "# values of value-taking flags (for example --principal USER) are")
	fmt.Fprintln(w, "# consumed with their flag, so a typed flag never shifts the PATH")
	fmt.Fprintln(w, "# position. Reads the canonical normalized word view, so an inline")
	fmt.Fprintln(w, "# --flag=VALUE counts like the separated --flag VALUE form.")
	fmt.Fprintln(w, "_docker_helper_positional_count() {")
	fmt.Fprintln(w, "    local cmd_path=\"$1\"")
	fmt.Fprintln(w, "    local count=0")
	fmt.Fprintln(w, "    local i=1")
	fmt.Fprintln(w, "    while [ \"$i\" -lt \"$_docker_helper_CWORD\" ]; do")
	fmt.Fprintln(w, "        local w=\"${_docker_helper_WORDS[$i]}\"")
	fmt.Fprintln(w, "        case \"$w\" in")
	fmt.Fprintln(w, "            -*)")
	fmt.Fprintln(w, "                if [[ \"$w\" != *=* ]] && _docker_helper_flag_takes_value \"$cmd_path\" \"$w\"; then")
	fmt.Fprintln(w, "                    i=$((i + 2))")
	fmt.Fprintln(w, "                    continue")
	fmt.Fprintln(w, "                fi")
	fmt.Fprintln(w, "                ;;")
	fmt.Fprintln(w, "            *)")
	fmt.Fprintln(w, "                case \" $cmd_path \" in")
	fmt.Fprintln(w, "                    *\" $w \"*) ;;")
	fmt.Fprintln(w, "                    *) count=$((count + 1)) ;;")
	fmt.Fprintln(w, "                esac")
	fmt.Fprintln(w, "                ;;")
	fmt.Fprintln(w, "        esac")
	fmt.Fprintln(w, "        i=$((i + 1))")
	fmt.Fprintln(w, "    done")
	io.WriteString(w, "    printf '%s\\n' \"$count\"\n")
	fmt.Fprintln(w, "}")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "# _docker_helper_positional_value prints the value of the nth positional")
	fmt.Fprintln(w, "# (0-based) before the cursor, using the same canonical normalized word")
	fmt.Fprintln(w, "# view as _docker_helper_positional_count. It prints nothing when that")
	fmt.Fprintln(w, "# positional has not been typed yet.")
	fmt.Fprintln(w, "_docker_helper_positional_value() {")
	fmt.Fprintln(w, "    local cmd_path=\"$1\"")
	fmt.Fprintln(w, "    local want=\"$2\"")
	fmt.Fprintln(w, "    local count=0")
	fmt.Fprintln(w, "    local i=1")
	fmt.Fprintln(w, "    while [ \"$i\" -lt \"$_docker_helper_CWORD\" ]; do")
	fmt.Fprintln(w, "        local w=\"${_docker_helper_WORDS[$i]}\"")
	fmt.Fprintln(w, "        case \"$w\" in")
	fmt.Fprintln(w, "            -*)")
	fmt.Fprintln(w, "                if [[ \"$w\" != *=* ]] && _docker_helper_flag_takes_value \"$cmd_path\" \"$w\"; then")
	fmt.Fprintln(w, "                    i=$((i + 2))")
	fmt.Fprintln(w, "                    continue")
	fmt.Fprintln(w, "                fi")
	fmt.Fprintln(w, "                ;;")
	fmt.Fprintln(w, "            *)")
	fmt.Fprintln(w, "                case \" $cmd_path \" in")
	fmt.Fprintln(w, "                    *\" $w \"*) ;;")
	fmt.Fprintln(w, "                    *) count=$((count + 1))")
	fmt.Fprintln(w, "                       if [ \"$((count - 1))\" -eq \"$want\" ]; then")
	io.WriteString(w, "                           printf '%s\\n' \"$w\"\n")
	fmt.Fprintln(w, "                           return")
	fmt.Fprintln(w, "                       fi ;;")
	fmt.Fprintln(w, "                esac")
	fmt.Fprintln(w, "                ;;")
	fmt.Fprintln(w, "        esac")
	fmt.Fprintln(w, "        i=$((i + 1))")
	fmt.Fprintln(w, "    done")
	fmt.Fprintln(w, "}")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "# Complete positional arguments or subcommands")
	fmt.Fprintln(w, "_docker_helper_complete_positional() {")
	fmt.Fprintln(w, "    local cmd_path=\"$1\"")
	fmt.Fprintln(w, "    local in_help=\"$2\"")
	fmt.Fprintln(w, "    local nofallback=\"$3\"")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "    # Positional-value completion is keyed on real command paths; under")
	fmt.Fprintln(w, "    # help navigation only tree navigation applies.")
	fmt.Fprintln(w, "    if [ \"$in_help\" -eq 1 ]; then")
	fmt.Fprintln(w, "        _docker_helper_complete_subcommands \"$cmd_path\"")
	fmt.Fprintln(w, "        return")
	fmt.Fprintln(w, "    fi")
	fmt.Fprintln(w, "    # Check for config subcommand positional completion")
	fmt.Fprintln(w, "    case \"$cmd_path\" in")
	fmt.Fprintln(w, "        \"config show\")")
	fmt.Fprintf(w, "            COMPREPLY=( $(compgen -W %q -- \"$cur\") )\n", strings.Join(configShowFields(), " "))
	fmt.Fprintln(w, "            return")
	fmt.Fprintln(w, "            ;;")
	fmt.Fprintln(w, "        \"config set\")")
	fmt.Fprintln(w, "            # Determine if we need FIELD or VALUE")
	fmt.Fprintln(w, "            local pos_count=0")
	fmt.Fprintln(w, "            local j=1")
	fmt.Fprintln(w, "            while [ \"$j\" -lt \"$_docker_helper_CWORD\" ]; do")
	fmt.Fprintln(w, "                local w=\"${_docker_helper_WORDS[$j]}\"")
	fmt.Fprintln(w, "                case \"$w\" in")
	fmt.Fprintln(w, "                    docker-helper|config|set) ;;")
	fmt.Fprintln(w, "                    -*)")
	fmt.Fprintln(w, "                        if _docker_helper_flag_takes_value \"config set\" \"$w\"; then")
	fmt.Fprintln(w, "                            j=$((j + 2))")
	fmt.Fprintln(w, "                            continue")
	fmt.Fprintln(w, "                        fi")
	fmt.Fprintln(w, "                        ;;")
	fmt.Fprintln(w, "                    *) pos_count=$((pos_count + 1)) ;;")
	fmt.Fprintln(w, "                esac")
	fmt.Fprintln(w, "                j=$((j + 1))")
	fmt.Fprintln(w, "            done")
	fmt.Fprintln(w, "            if [ $pos_count -eq 0 ]; then")
	fmt.Fprintln(w, "                # Complete FIELD")
	fmt.Fprintf(w, "                COMPREPLY=( $(compgen -W %q -- \"$cur\") )\n", strings.Join(configSetFields(), " "))
	fmt.Fprintln(w, "            else")
	fmt.Fprintln(w, "                # Complete VALUE based on FIELD")
	fmt.Fprintln(w, "                local field=\"\"")
	fmt.Fprintln(w, "                pos_count=0")
	fmt.Fprintln(w, "                j=1")
	fmt.Fprintln(w, "                while [ \"$j\" -lt \"$_docker_helper_CWORD\" ]; do")
	fmt.Fprintln(w, "                    local w=\"${_docker_helper_WORDS[$j]}\"")
	fmt.Fprintln(w, "                    case \"$w\" in")
	fmt.Fprintln(w, "                        docker-helper|config|set) ;;")
	fmt.Fprintln(w, "                        -*)")
	fmt.Fprintln(w, "                            if _docker_helper_flag_takes_value \"config set\" \"$w\"; then")
	fmt.Fprintln(w, "                                j=$((j + 2))")
	fmt.Fprintln(w, "                                continue")
	fmt.Fprintln(w, "                            fi")
	fmt.Fprintln(w, "                            ;;")
	fmt.Fprintln(w, "                        *)")
	fmt.Fprintln(w, "                            if [ $pos_count -eq 0 ]; then field=\"$w\"; fi")
	fmt.Fprintln(w, "                            pos_count=$((pos_count + 1))")
	fmt.Fprintln(w, "                            ;;")
	fmt.Fprintln(w, "                    esac")
	fmt.Fprintln(w, "                    j=$((j + 1))")
	fmt.Fprintln(w, "                done")
	fmt.Fprintln(w, "                case \"$field\" in")
	fmt.Fprintln(w, "                    log_level) COMPREPLY=( $(compgen -W \"debug info warn error\" -- \"$cur\") ) ;;")
	fmt.Fprintln(w, "                    audit_enabled) COMPREPLY=( $(compgen -W \"true false\" -- \"$cur\") ) ;;")
	fmt.Fprintln(w, "                    trusted_ca_injection) COMPREPLY=( $(compgen -W \"disabled auto\" -- \"$cur\") ) ;;")
	fmt.Fprintln(w, "                    trusted_ca_path) compopt -o filenames 2>/dev/null || true; COMPREPLY=( $(compgen -f -- \"$cur\") ); _docker_helper_normalize_path_candidates ;;")
	fmt.Fprintln(w, "                esac")
	fmt.Fprintln(w, "            fi")
	fmt.Fprintln(w, "            return")
	fmt.Fprintln(w, "            ;;")
	fmt.Fprintln(w, "        \"config allowed-root add\")")
	fmt.Fprintln(w, "            # Count positional args to check if PATH was provided")
	fmt.Fprintln(w, "            local pos_count=0")
	fmt.Fprintln(w, "            local j=1")
	fmt.Fprintln(w, "            while [ \"$j\" -lt \"$_docker_helper_CWORD\" ]; do")
	fmt.Fprintln(w, "                local w=\"${_docker_helper_WORDS[$j]}\"")
	fmt.Fprintln(w, "                case \"$w\" in")
	fmt.Fprintln(w, "                    docker-helper|config|allowed-root|add) ;;")
	fmt.Fprintln(w, "                    -*) ;;")
	fmt.Fprintln(w, "                    *) pos_count=$((pos_count + 1)) ;;")
	fmt.Fprintln(w, "                esac")
	fmt.Fprintln(w, "                j=$((j + 1))")
	fmt.Fprintln(w, "            done")
	fmt.Fprintln(w, "            if [ $pos_count -ge 1 ]; then")
	fmt.Fprintln(w, "                # PATH already provided, no further suggestions")
	fmt.Fprintln(w, "                return")
	fmt.Fprintln(w, "            fi")
	fmt.Fprintln(w, "            # Directory completion only")
	fmt.Fprintln(w, "            compopt -o filenames 2>/dev/null || true")
	fmt.Fprintln(w, "            COMPREPLY=( $(compgen -d -- \"$cur\") )")
	fmt.Fprintln(w, "            _docker_helper_normalize_path_candidates")
	fmt.Fprintln(w, "            return")
	fmt.Fprintln(w, "            ;;")
	fmt.Fprintln(w, "        \"config allowed-root remove\")")
	fmt.Fprintln(w, "            # Count positional args to check if PATH was provided")
	fmt.Fprintln(w, "            local pos_count=0")
	fmt.Fprintln(w, "            local j=1")
	fmt.Fprintln(w, "            while [ \"$j\" -lt \"$_docker_helper_CWORD\" ]; do")
	fmt.Fprintln(w, "                local w=\"${_docker_helper_WORDS[$j]}\"")
	fmt.Fprintln(w, "                case \"$w\" in")
	fmt.Fprintln(w, "                    docker-helper|config|allowed-root|remove) ;;")
	fmt.Fprintln(w, "                    -*) ;;")
	fmt.Fprintln(w, "                    *) pos_count=$((pos_count + 1)) ;;")
	fmt.Fprintln(w, "                esac")
	fmt.Fprintln(w, "                j=$((j + 1))")
	fmt.Fprintln(w, "            done")
	fmt.Fprintln(w, "            if [ $pos_count -ge 1 ]; then")
	fmt.Fprintln(w, "                # PATH already provided, no further suggestions")
	fmt.Fprintln(w, "                return")
	fmt.Fprintln(w, "            fi")
	fmt.Fprintln(w, "            # Filesystem/directory completion acceptable")
	fmt.Fprintln(w, "            compopt -o filenames 2>/dev/null || true")
	fmt.Fprintln(w, "            COMPREPLY=( $(compgen -f -- \"$cur\") )")
	fmt.Fprintln(w, "            _docker_helper_normalize_path_candidates")
	fmt.Fprintln(w, "            return")
	fmt.Fprintln(w, "            ;;")
	fmt.Fprintln(w, "        \"config unset\")")
	fmt.Fprintf(w, "            COMPREPLY=( $(compgen -W %q -- \"$cur\") )\n", strings.Join(configUnsetFields(), " "))
	fmt.Fprintln(w, "            return")
	fmt.Fprintln(w, "            ;;")
	fmt.Fprintln(w, "        \"apparmor root add\")")
	fmt.Fprintln(w, "            # Count positional args to check if PATH was provided")
	fmt.Fprintln(w, "            local pos_count=0")
	fmt.Fprintln(w, "            local j=1")
	fmt.Fprintln(w, "            while [ \"$j\" -lt \"$_docker_helper_CWORD\" ]; do")
	fmt.Fprintln(w, "                local w=\"${_docker_helper_WORDS[$j]}\"")
	fmt.Fprintln(w, "                case \"$w\" in")
	fmt.Fprintln(w, "                    docker-helper|apparmor|root|add) ;;")
	fmt.Fprintln(w, "                    -*) ;;")
	fmt.Fprintln(w, "                    *) pos_count=$((pos_count + 1)) ;;")
	fmt.Fprintln(w, "                esac")
	fmt.Fprintln(w, "                j=$((j + 1))")
	fmt.Fprintln(w, "            done")
	fmt.Fprintln(w, "            if [ $pos_count -ge 1 ]; then")
	fmt.Fprintln(w, "                # PATH already provided, no further suggestions")
	fmt.Fprintln(w, "                return")
	fmt.Fprintln(w, "            fi")
	fmt.Fprintln(w, "            # Directory completion only (managed root must be a directory)")
	fmt.Fprintln(w, "            compopt -o filenames 2>/dev/null || true")
	fmt.Fprintln(w, "            COMPREPLY=( $(compgen -d -- \"$cur\") )")
	fmt.Fprintln(w, "            _docker_helper_normalize_path_candidates")
	fmt.Fprintln(w, "            return")
	fmt.Fprintln(w, "            ;;")
	fmt.Fprintln(w, "        \"apparmor root remove\")")
	fmt.Fprintln(w, "            # Count positional args to check if PATH was provided")
	fmt.Fprintln(w, "            local pos_count=0")
	fmt.Fprintln(w, "            local j=1")
	fmt.Fprintln(w, "            while [ \"$j\" -lt \"$_docker_helper_CWORD\" ]; do")
	fmt.Fprintln(w, "                local w=\"${_docker_helper_WORDS[$j]}\"")
	fmt.Fprintln(w, "                case \"$w\" in")
	fmt.Fprintln(w, "                    docker-helper|apparmor|root|remove) ;;")
	fmt.Fprintln(w, "                    -*) ;;")
	fmt.Fprintln(w, "                    *) pos_count=$((pos_count + 1)) ;;")
	fmt.Fprintln(w, "                esac")
	fmt.Fprintln(w, "                j=$((j + 1))")
	fmt.Fprintln(w, "            done")
	fmt.Fprintln(w, "            if [ $pos_count -ge 1 ]; then")
	fmt.Fprintln(w, "                # PATH already provided, no further suggestions")
	fmt.Fprintln(w, "                return")
	fmt.Fprintln(w, "            fi")
	fmt.Fprintln(w, "            # Filesystem/directory completion acceptable")
	fmt.Fprintln(w, "            compopt -o filenames 2>/dev/null || true")
	fmt.Fprintln(w, "            COMPREPLY=( $(compgen -f -- \"$cur\") )")
	fmt.Fprintln(w, "            _docker_helper_normalize_path_candidates")
	fmt.Fprintln(w, "            return")
	fmt.Fprintln(w, "            ;;")
	fmt.Fprintln(w, `        "launcher show"|"launcher set"|"launcher delete"|"launcher credential create"|"launcher credential show"|"launcher credential rotate"|"launcher credential delete"|"launcher allowed-root list"|"launcher allowed-root inherit")`)
	fmt.Fprintln(w, "            # [LAUNCHER] positional: the same daemon-backed selector")
	fmt.Fprintln(w, "            # introspection the --launcher flag uses (one owner for")
	fmt.Fprintln(w, "            # Launcher selector semantics: an admin with a typed")
	fmt.Fprintln(w, "            # --principal sees that Principal's Launcher names, an admin")
	fmt.Fprintln(w, "            # without one sees only globally resolvable Launcher IDs, a")
	fmt.Fprintln(w, "            # Principal credential sees its own Launchers, and a Launcher")
	fmt.Fprintln(w, "            # credential sees no control-plane targets).")
	fmt.Fprintln(w, "            local lpos")
	fmt.Fprintln(w, "            lpos=\"$(_docker_helper_positional_count \"$cmd_path\")\"")
	fmt.Fprintln(w, "            if [ \"$lpos\" -eq 0 ]; then")
	fmt.Fprintln(w, "                _docker_helper_complete_selector_value launcher \"$cur\"")
	fmt.Fprintln(w, "            fi")
	fmt.Fprintln(w, "            return")
	fmt.Fprintln(w, "            ;;")
	fmt.Fprintln(w, `        "principal show")`)
	fmt.Fprintln(w, "            # USER completes from the daemon's scope-aware")
	fmt.Fprintln(w, "            # Principal selector introspection (the same owner")
	fmt.Fprintln(w, "            # the --principal selector uses, so admin sees the")
	fmt.Fprintln(w, "            # daemon-visible Principal names, a Principal")
	fmt.Fprintln(w, "            # credential sees exactly its own Principal, and a")
	fmt.Fprintln(w, "            # Launcher credential sees nothing); after USER the")
	fmt.Fprintln(w, "            # FIELD word completes from the canonical")
	fmt.Fprintln(w, "            # extractPrincipalField vocabulary; a full USER+FIELD")
	fmt.Fprintln(w, "            # pair offers nothing further.")
	fmt.Fprintln(w, "            local ppos")
	fmt.Fprintln(w, "            ppos=\"$(_docker_helper_positional_count \"$cmd_path\")\"")
	fmt.Fprintln(w, "            if [ \"$ppos\" -eq 0 ]; then")
	fmt.Fprintln(w, "                _docker_helper_complete_selector_value principal \"$cur\"")
	fmt.Fprintln(w, "            elif [ \"$ppos\" -eq 1 ]; then")
	fmt.Fprintf(w, "                COMPREPLY=( $(compgen -W %q -- \"$cur\") )\n", strings.Join(principalShowFieldNames(), " "))
	fmt.Fprintln(w, "            fi")
	fmt.Fprintln(w, "            return")
	fmt.Fprintln(w, "            ;;")
	fmt.Fprintln(w, `        "principal allowed-root add"|"principal allowed-root remove"|"launcher allowed-root add"|"launcher allowed-root remove")`)
	fmt.Fprintln(w, "            # USER (principal) positionals take no suggestions; the")
	fmt.Fprintln(w, "            # next position is the PATH. add suggests directories")
	fmt.Fprintln(w, "            # only (a managed root must be a directory); remove")
	fmt.Fprintln(w, "            # accepts any filesystem entry.")
	fmt.Fprintln(w, "            local pos")
	fmt.Fprintln(w, "            pos=\"$(_docker_helper_positional_count \"$cmd_path\")\"")
	fmt.Fprintln(w, "            if [ \"$pos\" -eq 1 ]; then")
	fmt.Fprintln(w, "                compopt -o filenames 2>/dev/null || true")
	fmt.Fprintln(w, "                case \"$cmd_path\" in")
	fmt.Fprintln(w, `                    *add) COMPREPLY=( $(compgen -d -- "$cur") ) ;;`)
	fmt.Fprintln(w, `                    *remove) COMPREPLY=( $(compgen -f -- "$cur") ) ;;`)
	fmt.Fprintln(w, "                esac")
	fmt.Fprintln(w, "                _docker_helper_normalize_path_candidates")
	fmt.Fprintln(w, "            elif [ \"$pos\" -eq 0 ]; then")
	fmt.Fprintln(w, "                case \"$cmd_path\" in")
	fmt.Fprintln(w, `                "launcher allowed-root add"|"launcher allowed-root remove")`)
	fmt.Fprintln(w, "                    # The first positional is grammar-ambiguous: with")
	fmt.Fprintln(w, "                    # one positional the word is the PATH for the")
	fmt.Fprintln(w, "                    # default Launcher, so a relative PATH without a")
	fmt.Fprintln(w, "                    # slash is legal. A word containing a slash can")
	fmt.Fprintln(w, "                    # only be the PATH (Launcher names never contain")
	fmt.Fprintln(w, "                    # one): complete filesystem candidates without a")
	fmt.Fprintln(w, "                    # selector query. A slash-free word stays")
	fmt.Fprintln(w, "                    # ambiguous: offer the union of the daemon-backed")
	fmt.Fprintln(w, "                    # Launcher selectors and the PATH candidates")
	fmt.Fprintln(w, "                    # (directories for add, any filesystem entry for")
	fmt.Fprintln(w, "                    # remove). The union is deterministic and unique;")
	fmt.Fprintln(w, "                    # resolving the ambiguity stays a matter for the")
	fmt.Fprintln(w, "                    # daemon, and a failed selector query never")
	fmt.Fprintln(w, "                    # removes the PATH candidates.")
	fmt.Fprintln(w, `                    case "$cur" in`)
	fmt.Fprintln(w, "                    */*)")
	fmt.Fprintln(w, "                        COMPREPLY=()")
	fmt.Fprintln(w, "                        compopt -o filenames 2>/dev/null || true")
	fmt.Fprintln(w, `                        case "$cmd_path" in`)
	fmt.Fprintln(w, `                            "launcher allowed-root add") COMPREPLY=( $(compgen -d -- "$cur") ) ;;`)
	fmt.Fprintln(w, `                            "launcher allowed-root remove") COMPREPLY=( $(compgen -f -- "$cur") ) ;;`)
	fmt.Fprintln(w, "                        esac")
	fmt.Fprintln(w, "                        _docker_helper_normalize_path_candidates")
	fmt.Fprintln(w, "                        ;;")
	fmt.Fprintln(w, "                    *)")
	fmt.Fprintln(w, "                        local -a sel=()")
	fmt.Fprintln(w, "                        if _docker_helper_complete_selector_value launcher \"$cur\"; then")
	fmt.Fprintln(w, "                            sel=(\"${COMPREPLY[@]}\")")
	fmt.Fprintln(w, "                        fi")
	fmt.Fprintln(w, "                        COMPREPLY=()")
	fmt.Fprintln(w, "                        compopt -o filenames 2>/dev/null || true")
	fmt.Fprintln(w, `                        case "$cmd_path" in`)
	fmt.Fprintln(w, `                            "launcher allowed-root add") COMPREPLY=( $(compgen -d -- "$cur") ) ;;`)
	fmt.Fprintln(w, `                            "launcher allowed-root remove") COMPREPLY=( $(compgen -f -- "$cur") ) ;;`)
	fmt.Fprintln(w, "                        esac")
	fmt.Fprintln(w, "                        _docker_helper_normalize_path_candidates")
	fmt.Fprintln(w, "                        COMPREPLY=( \"${sel[@]}\" \"${COMPREPLY[@]}\" )")
	fmt.Fprintln(w, "                        if [ ${#COMPREPLY[@]} -gt 0 ]; then")
	io.WriteString(w, "                            mapfile -t COMPREPLY < <(printf '%s\\n' \"${COMPREPLY[@]}\" | LC_ALL=C sort -u)\n")
	fmt.Fprintln(w, "                        fi")
	fmt.Fprintln(w, "                        ;;")
	fmt.Fprintln(w, "                    esac")
	fmt.Fprintln(w, "                    ;;")
	fmt.Fprintln(w, "                esac")
	fmt.Fprintln(w, "            fi")
	fmt.Fprintln(w, "            return")
	fmt.Fprintln(w, "            ;;")
	fmt.Fprintln(w, `        "config allowed-root set-access")`)
	fmt.Fprintln(w, "            # pos 0 is the PATH (any filesystem entry, matched by the")
	fmt.Fprintln(w, "            # stored canonical identity); pos 1 is the static access")
	fmt.Fprintln(w, "            # vocabulary.")
	fmt.Fprintln(w, "            local spos")
	fmt.Fprintln(w, "            spos=\"$(_docker_helper_positional_count \"$cmd_path\")\"")
	fmt.Fprintln(w, "            if [ \"$spos\" -eq 0 ]; then")
	fmt.Fprintln(w, "                compopt -o filenames 2>/dev/null || true")
	fmt.Fprintln(w, "                COMPREPLY=( $(compgen -f -- \"$cur\") )")
	fmt.Fprintln(w, "                _docker_helper_normalize_path_candidates")
	fmt.Fprintln(w, "            elif [ \"$spos\" -eq 1 ]; then")
	fmt.Fprintf(w, "                COMPREPLY=( $(compgen -W %q -- \"$cur\") )\n", strings.Join(allowedRootAccessVocabulary(), " "))
	fmt.Fprintln(w, "            fi")
	fmt.Fprintln(w, "            return")
	fmt.Fprintln(w, "            ;;")
	fmt.Fprintln(w, `        "principal allowed-root set-access")`)
	fmt.Fprintln(w, "            # USER (pos 0) takes no suggestions; pos 1 is the PATH (any")
	fmt.Fprintln(w, "            # filesystem entry, matched by the stored canonical")
	fmt.Fprintln(w, "            # identity); pos 2 is the static access vocabulary.")
	fmt.Fprintln(w, "            local spos")
	fmt.Fprintln(w, "            spos=\"$(_docker_helper_positional_count \"$cmd_path\")\"")
	fmt.Fprintln(w, "            if [ \"$spos\" -eq 1 ]; then")
	fmt.Fprintln(w, "                compopt -o filenames 2>/dev/null || true")
	fmt.Fprintln(w, "                COMPREPLY=( $(compgen -f -- \"$cur\") )")
	fmt.Fprintln(w, "                _docker_helper_normalize_path_candidates")
	fmt.Fprintln(w, "            elif [ \"$spos\" -eq 2 ]; then")
	fmt.Fprintf(w, "                COMPREPLY=( $(compgen -W %q -- \"$cur\") )\n", strings.Join(allowedRootAccessVocabulary(), " "))
	fmt.Fprintln(w, "            fi")
	fmt.Fprintln(w, "            return")
	fmt.Fprintln(w, "            ;;")
	fmt.Fprintln(w, `        "launcher allowed-root set-access")`)
	fmt.Fprintln(w, "            # The first positional is grammar-ambiguous ([LAUNCHER]")
	fmt.Fprintln(w, "            # PATH ACCESS, same union contract as add/remove); pos 1 is")
	fmt.Fprintln(w, "            # the PATH (any filesystem entry); pos 2 is the static")
	fmt.Fprintln(w, "            # access vocabulary.")
	fmt.Fprintln(w, "            local spos")
	fmt.Fprintln(w, "            spos=\"$(_docker_helper_positional_count \"$cmd_path\")\"")
	fmt.Fprintln(w, "            if [ \"$spos\" -eq 0 ]; then")
	fmt.Fprintln(w, "                local -a sel=()")
	fmt.Fprintln(w, "                if _docker_helper_complete_selector_value launcher \"$cur\"; then")
	fmt.Fprintln(w, "                    sel=(\"${COMPREPLY[@]}\")")
	fmt.Fprintln(w, "                fi")
	fmt.Fprintln(w, "                COMPREPLY=()")
	fmt.Fprintln(w, "                compopt -o filenames 2>/dev/null || true")
	fmt.Fprintln(w, "                COMPREPLY=( $(compgen -f -- \"$cur\") )")
	fmt.Fprintln(w, "                _docker_helper_normalize_path_candidates")
	fmt.Fprintln(w, "                COMPREPLY=( \"${sel[@]}\" \"${COMPREPLY[@]}\" )")
	fmt.Fprintln(w, "                if [ ${#COMPREPLY[@]} -gt 0 ]; then")
	io.WriteString(w, "                    mapfile -t COMPREPLY < <(printf '%s\\n' \"${COMPREPLY[@]}\" | LC_ALL=C sort -u)\n")
	fmt.Fprintln(w, "                fi")
	fmt.Fprintln(w, "            elif [ \"$spos\" -eq 1 ]; then")
	fmt.Fprintln(w, "                # Grammar-ambiguous first positional ([LAUNCHER] PATH")
	fmt.Fprintln(w, "                # ACCESS union): a first positional containing a slash")
	fmt.Fprintln(w, "                # can only be the PATH, so the current word is the")
	fmt.Fprintln(w, "                # ACCESS vocabulary. A slash-free first positional may")
	fmt.Fprintln(w, "                # be the [LAUNCHER] selector, making the current word")
	fmt.Fprintln(w, "                # the PATH.")
	fmt.Fprintln(w, "                local first_pos")
	fmt.Fprintln(w, "                first_pos=\"$(_docker_helper_positional_value \"$cmd_path\" 0)\"")
	fmt.Fprintln(w, "                case \"$first_pos\" in")
	fmt.Fprintln(w, "                    */*)")
	fmt.Fprintf(w, "                        COMPREPLY=( $(compgen -W %q -- \"$cur\") )\n", strings.Join(allowedRootAccessVocabulary(), " "))
	fmt.Fprintln(w, "                        ;;")
	fmt.Fprintln(w, "                    *)")
	fmt.Fprintln(w, "                        compopt -o filenames 2>/dev/null || true")
	fmt.Fprintln(w, "                        COMPREPLY=( $(compgen -f -- \"$cur\") )")
	fmt.Fprintln(w, "                        _docker_helper_normalize_path_candidates")
	fmt.Fprintln(w, "                        ;;")
	fmt.Fprintln(w, "                esac")
	fmt.Fprintln(w, "            elif [ \"$spos\" -eq 2 ]; then")
	fmt.Fprintf(w, "                COMPREPLY=( $(compgen -W %q -- \"$cur\") )\n", strings.Join(allowedRootAccessVocabulary(), " "))
	fmt.Fprintln(w, "            fi")
	fmt.Fprintln(w, "            return")
	fmt.Fprintln(w, "            ;;")
	fmt.Fprintln(w, "    esac")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "    # Flag-only leaf fallback (parser tree == completion tree): a leaf")
	fmt.Fprintln(w, "    # command that accepts no positional arguments has no applicable")
	fmt.Fprintln(w, "    # positional or subcommand completion, so the current word completes")
	fmt.Fprintln(w, "    # the command's own flags from the same table used for dash words.")
	fmt.Fprintln(w, "    if [ \"$nofallback\" -eq 0 ] && [ \"$in_help\" -eq 0 ]; then")
	fmt.Fprintln(w, "        case \"$cmd_path\" in")
	fmt.Fprintf(w, "            %s)\n", strings.Join(quoteWords(flagOnlyLeaves), "|"))
	fmt.Fprintln(w, "                COMPREPLY=( $(compgen -W \"$(_docker_helper_flags \"$cmd_path\")\" -- \"$cur\") )")
	fmt.Fprintln(w, "                return")
	fmt.Fprintln(w, "                ;;")
	fmt.Fprintln(w, "        esac")
	fmt.Fprintln(w, "    fi")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "    _docker_helper_complete_subcommands \"$cmd_path\"")
	fmt.Fprintln(w, "}")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "# Return subcommands for a given command path")
	fmt.Fprintln(w, "_docker_helper_subcommands() {")
	fmt.Fprintln(w, "    local cmd_path=\"$1\"")
	fmt.Fprintln(w, "    case \"$cmd_path\" in")
	for _, path := range allPaths {
		cmd := completionCommandPath(strings.Split(path, " "))
		if cmd != nil && len(cmd.Subcommands) > 0 {
			var subNames []string
			for _, sub := range cmd.Subcommands {
				subNames = append(subNames, sub.Name)
			}
			fmt.Fprintf(w, "        \"%s\") echo \"%s\" ;;\n", path, strings.Join(subNames, " "))
		}
	}
	// Root command subcommands.
	var rootSubNames []string
	for _, sub := range rootCommand.Subcommands {
		rootSubNames = append(rootSubNames, sub.Name)
	}
	fmt.Fprintf(w, "        \"\") echo \"%s\" ;;\n", strings.Join(rootSubNames, " "))
	fmt.Fprintln(w, "    esac")
	fmt.Fprintln(w, "}")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "# Check if a path is a valid command")
	fmt.Fprintln(w, "_docker_helper_is_command() {")
	fmt.Fprintln(w, "    local cmd_path=\"$1\"")
	fmt.Fprintln(w, "    case \"$cmd_path\" in")
	for _, path := range allPaths {
		fmt.Fprintf(w, "        \"%s\") return 0 ;;\n", path)
	}
	fmt.Fprintf(w, "        \"\") return 0 ;;\n")
	fmt.Fprintln(w, "        *) return 1 ;;")
	fmt.Fprintln(w, "    esac")
	fmt.Fprintln(w, "}")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "# Return flags for a given command path (includes branch commands)")
	fmt.Fprintln(w, "_docker_helper_flags() {")
	fmt.Fprintln(w, "    local cmd_path=\"$1\"")
	fmt.Fprintln(w, "    case \"$cmd_path\" in")
	for _, path := range sortedPaths {
		flags := commandFlags[path]
		if len(flags) > 0 {
			fmt.Fprintf(w, "        \"%s\") echo \"%s\" ;;\n", path, strings.Join(flags, " "))
		}
	}
	// Branch commands (no NewInvocation) still get -h/--help
	for _, path := range allPaths {
		cmd := completionCommandPath(strings.Split(path, " "))
		if cmd != nil && cmd.NewInvocation == nil && len(cmd.Subcommands) > 0 {
			fmt.Fprintf(w, "        \"%s\") echo \"-h --help\" ;;\n", path)
		}
	}
	// Root command also gets -h/--help and the -v/--version aliases
	fmt.Fprintf(w, "        \"\") echo \"-h --help -v --version\" ;;\n")
	fmt.Fprintln(w, "    esac")
	fmt.Fprintln(w, "}")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "# Check if a flag takes a value (non-boolean)")
	fmt.Fprintln(w, "_docker_helper_flag_takes_value() {")
	fmt.Fprintln(w, "    local cmd_path=\"$1\"")
	fmt.Fprintln(w, "    local flag=\"$2\"")
	fmt.Fprintln(w, "    local clean_flag=\"${flag#-}\"")
	fmt.Fprintln(w, "    clean_flag=\"${clean_flag#-}\"")
	fmt.Fprintln(w, "    # Check if this is a known boolean flag for this command")
	fmt.Fprintln(w, "    local bool_flags=($(_docker_helper_bool_flags \"$cmd_path\"))")
	fmt.Fprintln(w, "    for bf in \"${bool_flags[@]}\"; do")
	fmt.Fprintln(w, "        if [ \"$bf\" = \"$clean_flag\" ]; then")
	fmt.Fprintln(w, "            return 1")
	fmt.Fprintln(w, "        fi")
	fmt.Fprintln(w, "    done")
	fmt.Fprintln(w, "    # Non-boolean flags take values")
	fmt.Fprintln(w, "    return 0")
	fmt.Fprintln(w, "}")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "# Return boolean flag names for a given command path")
	fmt.Fprintln(w, "_docker_helper_bool_flags() {")
	fmt.Fprintln(w, "    local cmd_path=\"$1\"")
	fmt.Fprintln(w, "    case \"$cmd_path\" in")
	for _, path := range sortedBoolPaths {
		flags := commandBoolFlags[path]
		if len(flags) > 0 {
			fmt.Fprintf(w, "        \"%s\") echo \"%s\" ;;\n", path, strings.Join(flags, " "))
		}
	}
	fmt.Fprintln(w, "    esac")
	fmt.Fprintln(w, "}")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "# Complete flag values (for flags that take values). The third argument")
	fmt.Fprintln(w, "# is the typed value prefix: the current word for the separated")
	fmt.Fprintln(w, "# --flag VALUE form, the part after --flag= for the inline form.")
	fmt.Fprintln(w, "_docker_helper_complete_flag_value() {")
	fmt.Fprintln(w, "    local cmd_path=\"$1\"")
	fmt.Fprintln(w, "    local flag=\"$2\"")
	fmt.Fprintln(w, "    local prefix=\"$3\"")
	fmt.Fprintln(w, "    # Selector-value flags complete from the daemon's scope-aware")
	fmt.Fprintln(w, "    # selector introspection; the daemon remains the ownership and")
	fmt.Fprintln(w, "    # authorization authority and an unauthorized or unavailable query")
	fmt.Fprintln(w, "    # degrades silently.")
	fmt.Fprintln(w, "    case \"$flag\" in")
	fmt.Fprintln(w, "        principal|launcher)")
	fmt.Fprintln(w, "            if _docker_helper_complete_selector_value \"$flag\" \"$prefix\"; then")
	fmt.Fprintln(w, "                return")
	fmt.Fprintln(w, "            fi")
	fmt.Fprintln(w, "            ;;")
	fmt.Fprintln(w, "    esac")
	fmt.Fprintln(w, "    # The ACCESS side of the repeatable --filesystem-root PATH=ACCESS")
	fmt.Fprintln(w, "    # flag: the split is on the LAST '=' (\"${prefix%=*}\"), exactly like")
	fmt.Fprintln(w, "    # the CLI parser. The suffix is an ACCESS decision only when it is")
	fmt.Fprintln(w, "    # unambiguous: a trailing '=' (empty suffix) or a prefix/exact")
	fmt.Fprintln(w, "    # member of the canonical access vocabulary. Any other suffix —")
	fmt.Fprintln(w, "    # for example the bar of a real path foo=bar — keeps the whole")
	fmt.Fprintln(w, "    # current value on the PATH side, so a path containing '='")
	fmt.Fprintln(w, "    # completes as a path until the caller types the final access")
	fmt.Fprintln(w, "    # delimiter. One deterministic ambiguity rule, one canonical")
	fmt.Fprintln(w, "    # access vocabulary owner.")
	fmt.Fprintln(w, "    case \"$flag\" in")
	fmt.Fprintln(w, "        filesystem-root)")
	fmt.Fprintln(w, "            if [[ \"$prefix\" == *=* ]]; then")
	fmt.Fprintln(w, "                local _fsr_head=\"${prefix%=*}=\"")
	fmt.Fprintln(w, "                local _fsr_acc=\"${prefix##*=}\"")
	fmt.Fprintln(w, "                local _fsr_w _fsr_acc_side=0")
	fmt.Fprintln(w, "                for _fsr_w in "+strings.Join(allowedRootAccessVocabulary(), " ")+"; do")
	fmt.Fprintln(w, "                    case \"$_fsr_w\" in \"$_fsr_acc\"*) _fsr_acc_side=1 ;; esac")
	fmt.Fprintln(w, "                done")
	fmt.Fprintln(w, "                if [ \"$_fsr_acc_side\" -eq 1 ]; then")
	fmt.Fprintln(w, "                    local _fsr_i")
	fmt.Fprintf(w, "                    COMPREPLY=( $(compgen -W %q -- \"$_fsr_acc\") )\n", strings.Join(allowedRootAccessVocabulary(), " "))
	fmt.Fprintln(w, "                    for _fsr_i in \"${!COMPREPLY[@]}\"; do")
	fmt.Fprintln(w, "                        COMPREPLY[$_fsr_i]=\"$_fsr_head${COMPREPLY[$_fsr_i]}\"")
	fmt.Fprintln(w, "                    done")
	fmt.Fprintln(w, "                    return")
	fmt.Fprintln(w, "                fi")
	fmt.Fprintln(w, "                # Not an access decision: the value stays the PATH side")
	fmt.Fprintln(w, "                # and falls through to the daemon-backed policy-roots")
	fmt.Fprintln(w, "                # machinery with the full typed value.")
	fmt.Fprintln(w, "            fi")
	fmt.Fprintln(w, "            ;;")
	fmt.Fprintln(w, "    esac")
	fmt.Fprintln(w, "    # Daemon-backed policy roots take precedence for their registered")
	fmt.Fprintln(w, "    # (command, flag) pairs. Convenience only: on any query failure")
	fmt.Fprintln(w, "    # completion degrades silently to the generic filesystem completion.")
	fmt.Fprintln(w, "    local mode")
	fmt.Fprintln(w, "    if mode=\"$(_docker_helper_policy_value_mode \"$cmd_path\" \"$flag\")\"; then")
	fmt.Fprintln(w, "        if _docker_helper_complete_policy_roots \"$mode\" \"$prefix\"; then")
	fmt.Fprintln(w, "            return")
	fmt.Fprintln(w, "        fi")
	fmt.Fprintln(w, "    fi")
	fmt.Fprintln(w, "    # The allowed-root access vocabulary is a static two-value domain")
	fmt.Fprintln(w, "    # shared by every --access flag.")
	fmt.Fprintln(w, "    case \"$flag\" in")
	fmt.Fprintln(w, "        access)")
	fmt.Fprintf(w, "            COMPREPLY=( $(compgen -W %q -- \"$prefix\") )\n", strings.Join(allowedRootAccessVocabulary(), " "))
	fmt.Fprintln(w, "            ;;")
	fmt.Fprintln(w, "    esac")
	fmt.Fprintln(w, "    # Path-valued flags complete with filesystem paths.")
	fmt.Fprintln(w, "    case \"$flag\" in")
	for _, f := range pathValuedFlags {
		fmt.Fprintf(w, "        %q)\n", f)
		fmt.Fprintln(w, "            compopt -o filenames 2>/dev/null || true")
		fmt.Fprintln(w, "            COMPREPLY=( $(compgen -f -- \"$prefix\") )")
		fmt.Fprintln(w, "            _docker_helper_normalize_path_candidates")
		fmt.Fprintln(w, "            ;;")
	}
	fmt.Fprintln(w, "    esac")
	fmt.Fprintln(w, "}")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "# Report the policy completion query serving a (command, flag) pair,")
	fmt.Fprintln(w, "# or fail when the pair has no daemon-backed completion.")
	fmt.Fprintln(w, "_docker_helper_policy_value_mode() {")
	fmt.Fprintln(w, "    local cmd_path=\"$1\"")
	fmt.Fprintln(w, "    local flag=\"$2\"")
	fmt.Fprintln(w, "    case \"$cmd_path/$flag\" in")
	for _, p := range policyValueCompletions {
		fmt.Fprintf(w, "        %q/%q) echo %q ;;\n", p.commandPath, p.flag, p.query)
	}
	fmt.Fprintln(w, "        *) return 1 ;;")
	fmt.Fprintln(w, "    esac")
	fmt.Fprintln(w, "}")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "# Forward the operator overrides already typed on the current command")
	fmt.Fprintln(w, "# line (--system, --endpoint, --token-file) so the completion query")
	fmt.Fprintln(w, "# targets the same daemon and token as the command being completed.")
	fmt.Fprintln(w, "# Emits one argument per NUL so the caller can read them into a Bash")
	fmt.Fprintln(w, "# array verbatim: no string round-trip, no word splitting, no glob")
	fmt.Fprintln(w, "# expansion, and values with spaces survive intact.")
	fmt.Fprintln(w, "_docker_helper_operator_args() {")
	fmt.Fprintln(w, "    local cmd_path=\"$1\"")
	fmt.Fprintln(w, "    local out=()")
	fmt.Fprintln(w, "    local i=1")
	fmt.Fprintln(w, "    while [ \"$i\" -lt \"$_docker_helper_CWORD\" ]; do")
	fmt.Fprintln(w, "        local w=\"${_docker_helper_WORDS[$i]}\"")
	fmt.Fprintln(w, "        case \"$w\" in")
	fmt.Fprintln(w, "            --system) out+=(\"--system\") ;;")
	fmt.Fprintln(w, "            --endpoint|--token-file)")
	fmt.Fprintln(w, "                out+=(\"$w\" \"${_docker_helper_WORDS[$((i+1))]:-}\")")
	fmt.Fprintln(w, "                i=$((i + 2))")
	fmt.Fprintln(w, "                continue")
	fmt.Fprintln(w, "                ;;")
	fmt.Fprintln(w, "            --endpoint=*|--token-file=*) out+=(\"$w\") ;;")
	fmt.Fprintln(w, "            -*)")
	fmt.Fprintln(w, "                # Skip values of other value-taking flags so they are")
	fmt.Fprintln(w, "                # never mistaken for operator overrides.")
	fmt.Fprintln(w, "                if [[ \"$w\" != *=* ]] && _docker_helper_flag_takes_value \"$cmd_path\" \"$w\"; then")
	fmt.Fprintln(w, "                    i=$((i + 2))")
	fmt.Fprintln(w, "                    continue")
	fmt.Fprintln(w, "                fi")
	fmt.Fprintln(w, "                ;;")
	fmt.Fprintln(w, "        esac")
	fmt.Fprintln(w, "        i=$((i + 1))")
	fmt.Fprintln(w, "    done")
	fmt.Fprintln(w, "    if [ ${#out[@]} -gt 0 ]; then")
	io.WriteString(w, "        printf '%s\\0' \"${out[@]}\"\n")
	fmt.Fprintln(w, "    fi")
	fmt.Fprintln(w, "}")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "# Print the value already typed for a flag on the current command line")
	fmt.Fprintln(w, "# (--flag VALUE or --flag=VALUE); last occurrence wins, mirroring flag")
	fmt.Fprintln(w, "# parsing. Empty output when the flag has no typed value yet. Reads")
	fmt.Fprintln(w, "# the canonical normalized word view, so the physical inline")
	fmt.Fprintln(w, "# tokenization (--flag = VALUE) yields the same value as the one-word")
	fmt.Fprintln(w, "# and separated forms.")
	fmt.Fprintln(w, "_docker_helper_typed_flag_value() {")
	fmt.Fprintln(w, "    local name=\"$1\"")
	fmt.Fprintln(w, "    local value=\"\"")
	fmt.Fprintln(w, "    local i=1")
	fmt.Fprintln(w, "    while [ \"$i\" -lt \"$_docker_helper_CWORD\" ]; do")
	fmt.Fprintln(w, "        local w=\"${_docker_helper_WORDS[$i]}\"")
	fmt.Fprintln(w, "        case \"$w\" in")
	fmt.Fprintln(w, "            \"--$name=\"*) value=\"${w#--$name=}\" ;;")
	fmt.Fprintln(w, "            \"--$name\")")
	fmt.Fprintln(w, "                i=$((i + 1))")
	fmt.Fprintln(w, "                if [ \"$i\" -lt \"$_docker_helper_CWORD\" ]; then value=\"${_docker_helper_WORDS[$i]}\"; fi")
	fmt.Fprintln(w, "                ;;")
	fmt.Fprintln(w, "        esac")
	fmt.Fprintln(w, "        i=$((i + 1))")
	fmt.Fprintln(w, "    done")
	io.WriteString(w, "    printf '%s\\n' \"$value\"\n")
	fmt.Fprintln(w, "}")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "# Complete the values of the --principal/--launcher selector flags from")
	fmt.Fprintln(w, "# the daemon's scope-aware selector introspection (docker-helper")
	fmt.Fprintln(w, "# completion selectors): an admin sees Principal names for --principal")
	fmt.Fprintln(w, "# and, for --launcher, the typed --principal context's Launcher names")
	fmt.Fprintln(w, "# (both forms) or, without one, only globally resolvable Launcher IDs;")
	fmt.Fprintln(w, "# a Principal credential sees its own Launchers; a Launcher credential")
	fmt.Fprintln(w, "# and any unauthorized or foreign scope offer nothing. The word list is")
	fmt.Fprintln(w, "# filtered by the typed prefix, so --launcher=ki completes like")
	fmt.Fprintln(w, "# --launcher ki. Prints nothing and fails silently when the query is")
	fmt.Fprintln(w, "# unavailable.")
	fmt.Fprintln(w, "_docker_helper_complete_selector_value() {")
	fmt.Fprintln(w, "    local flag=\"$1\"")
	fmt.Fprintln(w, "    local prefix=\"$2\"")
	fmt.Fprintln(w, "    local -a opargs=() selargs=()")
	fmt.Fprintln(w, "    mapfile -d '' -t opargs < <(_docker_helper_operator_args \"$cmd_path\")")
	fmt.Fprintln(w, "    if [ \"$flag\" = launcher ]; then")
	fmt.Fprintln(w, "        local p")
	fmt.Fprintln(w, "        p=\"$(_docker_helper_typed_flag_value principal)\"")
	fmt.Fprintln(w, "        if [ -n \"$p\" ]; then")
	fmt.Fprintln(w, "            selargs+=(--principal \"$p\")")
	fmt.Fprintln(w, "        fi")
	fmt.Fprintln(w, "    fi")
	fmt.Fprintln(w, "    if [ \"$flag\" = principal ] && [ -n \"$cmd_path\" ]; then")
	fmt.Fprintln(w, "        selargs+=(--command \"$cmd_path\")")
	fmt.Fprintln(w, "    fi")
	fmt.Fprintln(w, "    local vals")
	fmt.Fprintln(w, "    if ! vals=\"$(${_docker_helper_WORDS[0]} completion selectors \"$flag\" \"${opargs[@]}\" \"${selargs[@]}\" 2>/dev/null)\"; then")
	fmt.Fprintln(w, "        return 1")
	fmt.Fprintln(w, "    fi")
	fmt.Fprintln(w, "    [ -n \"$vals\" ] || return 1")
	fmt.Fprintln(w, "    mapfile -t COMPREPLY < <(compgen -W \"$vals\" -- \"$prefix\")")
	fmt.Fprintln(w, "    [ ${#COMPREPLY[@]} -gt 0 ]")
	fmt.Fprintln(w, "}")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "# Run the daemon-backed roots query through docker-helper itself and")
	fmt.Fprintln(w, "# complete from the returned policy anchors. The forwarded operator")
	fmt.Fprintln(w, "# overrides and the typed selector values stay Bash arrays end to")
	fmt.Fprintln(w, "# end, so values with spaces reach the helper as single arguments.")
	fmt.Fprintln(w, "# For a Session-create query the typed --principal/--launcher")
	fmt.Fprintln(w, "# selectors (either --flag VALUE or --flag=VALUE) are forwarded to")
	fmt.Fprintln(w, "# docker-helper, which normalizes them exactly like a real Session")
	fmt.Fprintln(w, "# create; the daemon resolves the same target the real command")
	fmt.Fprintln(w, "# would. Prints nothing and fails silently when the query is")
	fmt.Fprintln(w, "# unavailable.")
	fmt.Fprintln(w, "_docker_helper_complete_policy_roots() {")
	fmt.Fprintln(w, "    local mode=\"$1\"")
	fmt.Fprintln(w, "    local prefix=\"$2\"")
	fmt.Fprintln(w, "    local -a opargs=() selargs=()")
	fmt.Fprintln(w, "    mapfile -d '' -t opargs < <(_docker_helper_operator_args \"$cmd_path\")")
	fmt.Fprintln(w, "    local arg")
	fmt.Fprintln(w, "    for arg in principal launcher; do")
	fmt.Fprintln(w, "        if [ \"$mode\" = \"$arg\" ] || [ \"$mode\" = session ]; then")
	fmt.Fprintln(w, "            local sel")
	fmt.Fprintln(w, "            sel=\"$(_docker_helper_typed_flag_value \"$arg\")\"")
	fmt.Fprintln(w, "            if [ -n \"$sel\" ]; then")
	fmt.Fprintln(w, "                selargs+=(--\"$arg\" \"$sel\")")
	fmt.Fprintln(w, "            fi")
	fmt.Fprintln(w, "        fi")
	fmt.Fprintln(w, "    done")
	fmt.Fprintln(w, "    local roots")
	fmt.Fprintln(w, "    if ! roots=\"$(\"${_docker_helper_WORDS[0]}\" completion roots \"$mode\" \"${opargs[@]}\" \"${selargs[@]}\" 2>/dev/null)\"; then")
	fmt.Fprintln(w, "        return 1")
	fmt.Fprintln(w, "    fi")
	fmt.Fprintln(w, "    # An empty answer is no usable policy projection (for example an")
	fmt.Fprintln(w, "    # authority with no effective roots): it degrades like a failed")
	fmt.Fprintln(w, "    # query, so the caller falls back to the generic filesystem")
	fmt.Fprintln(w, "    # completion instead of silently offering nothing. A query that")
	fmt.Fprintln(w, "    # returned roots but no candidate matches the typed prefix keeps")
	fmt.Fprintln(w, "    # the empty result: the policy-backed branch exists to keep")
	fmt.Fprintln(w, "    # unauthorized paths out of the suggestions.")
	fmt.Fprintln(w, "    [ -n \"$roots\" ] || return 1")
	fmt.Fprintln(w, "    _docker_helper_complete_within_roots \"$flag\" \"$roots\" \"$prefix\"")
	fmt.Fprintln(w, "}")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "# Collapse doubled separators in the current filesystem candidates.")
	fmt.Fprintln(w, "# Bash joins a directory prefix ending in a separator with directory")
	fmt.Fprintln(w, "# entries verbatim, so a word that already carries \"//\" (typed or")
	fmt.Fprintln(w, "# produced by an earlier completion) would otherwise persist into the")
	fmt.Fprintln(w, "# completed word, for example /home/michael/work//git. On Linux a")
	fmt.Fprintln(w, "# doubled separator is equivalent to a single one, so normalizing the")
	fmt.Fprintln(w, "# candidate fixes the completed word and keeps continued completion")
	fmt.Fprintln(w, "# clean. The rewrite happens in place: no subshell per candidate.")
	fmt.Fprintln(w, "_docker_helper_normalize_path_candidates() {")
	fmt.Fprintln(w, "    local c n=0")
	fmt.Fprintln(w, "    for c in \"${COMPREPLY[@]}\"; do")
	fmt.Fprintln(w, "        while [[ \"$c\" == *//* ]]; do")
	fmt.Fprintln(w, "            c=\"${c/'//'/'/'}\"")
	fmt.Fprintln(w, "        done")
	fmt.Fprintln(w, "        COMPREPLY[n++]=\"$c\"")
	fmt.Fprintln(w, "    done")
	fmt.Fprintln(w, "}")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "# Complete a path-valued flag constrained to the effective policy roots.")
	fmt.Fprintln(w, "# The roots are tree boundaries, not terminal candidates: from the typed")
	fmt.Fprintln(w, "# prefix the next path segment toward each root is offered, so sibling")
	fmt.Fprintln(w, "# roots (/home/michael and /opt/michael) render as distinguishable")
	fmt.Fprintln(w, "# boundary segments (home/ and opt/) instead of two identical terminal")
	fmt.Fprintln(w, "# basenames, and once the cursor has reached or entered an authorized")
	fmt.Fprintln(w, "# root, ordinary directory navigation continues inside it.")
	fmt.Fprintln(w, "#")
	fmt.Fprintln(w, "# Filesystem candidates are confined symlink-safely: a candidate is")
	fmt.Fprintln(w, "# accepted only when its canonicalized path (realpath) lies strictly")
	fmt.Fprintln(w, "# inside the canonicalized root, so a link escaping the root is never")
	fmt.Fprintln(w, "# suggested and a link pointing inside is treated as its target. The")
	fmt.Fprintln(w, "# workspace flag suggests directories only (the workspace must be a")
	fmt.Fprintln(w, "# directory); the filesystem-root flag suggests directories and regular")
	fmt.Fprintln(w, "# files. The daemon remains the security boundary; this only keeps")
	fmt.Fprintln(w, "# obviously invalid paths out of the suggestions.")
	fmt.Fprintln(w, "_docker_helper_complete_within_roots() {")
	fmt.Fprintln(w, "    local flag=\"$1\"")
	fmt.Fprintln(w, "    local roots=\"$2\"")
	fmt.Fprintln(w, "    local prefix=\"$3\"")
	fmt.Fprintln(w, "    # Pattern matching strips the trailing separator: a typed")
	fmt.Fprintln(w, "    # \"/home/\" prefix must match a root \"/home/michael\" — the")
	fmt.Fprintln(w, "    # literal pattern would otherwise double the separator.")
	fmt.Fprintln(w, "    local match_prefix=\"$prefix\"")
	fmt.Fprintln(w, "    match_prefix=\"${match_prefix%/}\"")
	fmt.Fprintln(w, "    local -a anchors=() roots_can=()")
	fmt.Fprintln(w, "    local r")
	fmt.Fprintln(w, "    while IFS= read -r r; do")
	fmt.Fprintln(w, "        [ -n \"$r\" ] || continue")
	fmt.Fprintln(w, "        anchors+=(\"$r\")")
	fmt.Fprintln(w, "        roots_can+=(\"$(realpath -m -- \"$r\" 2>/dev/null)\")")
	fmt.Fprintln(w, "    done <<< \"$roots\"")
	fmt.Fprintln(w, "    local comp=()")
	fmt.Fprintln(w, "    local a rem i root_can d d_can accept root_entered")
	fmt.Fprintln(w, "    # Tree-boundary segments: the next segment toward each root from the")
	fmt.Fprintln(w, "    # typed prefix; the root itself when it is the next segment or is")
	fmt.Fprintln(w, "    # already exactly typed. A partially typed next component continues")
	fmt.Fprintln(w, "    # toward the root (/h offers /home), keeping the boundary navigable")
	fmt.Fprintln(w, "    # instead of returning nothing.")
	fmt.Fprintln(w, "    for i in \"${!anchors[@]}\"; do")
	fmt.Fprintln(w, "        a=\"${anchors[$i]}\"")
	fmt.Fprintln(w, "        root_can=\"${roots_can[$i]}\"")
	fmt.Fprintln(w, "        [ -n \"$root_can\" ] || continue")
	fmt.Fprintln(w, "        case \"$root_can\" in")
	fmt.Fprintln(w, "            \"$match_prefix\")")
	fmt.Fprintln(w, "                # Offer the already exactly typed root only when no")
	fmt.Fprintln(w, "                # separator was typed behind it: with the separator")
	fmt.Fprintln(w, "                # the cursor is inside the root and the ordinary")
	fmt.Fprintln(w, "                # navigation below continues.")
	fmt.Fprintln(w, "                [ \"$prefix\" = \"$match_prefix\" ] && comp+=(\"$root_can\")")
	fmt.Fprintln(w, "                ;;")
	fmt.Fprintln(w, "            \"$match_prefix\"/*)")
	fmt.Fprintln(w, "                rem=\"${root_can#\"$match_prefix\"/}\"")
	fmt.Fprintln(w, "                case \"$rem\" in")
	fmt.Fprintln(w, "                    */*) comp+=(\"$prefix/${rem%%/*}\") ;;")
	fmt.Fprintln(w, "                    *)   [ -n \"$rem\" ] && comp+=(\"$root_can\") ;;")
	fmt.Fprintln(w, "                esac")
	fmt.Fprintln(w, "                ;;")
	fmt.Fprintln(w, "            \"$match_prefix\"?*)")
	fmt.Fprintln(w, "                # The typed prefix is a proper prefix of the next")
	fmt.Fprintln(w, "                # component: offer the prefix completed through the")
	fmt.Fprintln(w, "                # next component boundary (or the root itself when the")
	fmt.Fprintln(w, "                # prefix reaches into its last component). The rendered")
	fmt.Fprintln(w, "                # candidate is a real parent directory, so a unique")
	fmt.Fprintln(w, "                # boundary keeps its filename semantics under Readline")
	fmt.Fprintln(w, "                # and a second TAB continues inside it.")
	fmt.Fprintln(w, "                rem=\"${root_can#\"$match_prefix\"}\"")
	fmt.Fprintln(w, "                case \"$rem\" in")
	fmt.Fprintln(w, "                    */*) comp+=(\"$prefix${rem%%/*}\") ;;")
	fmt.Fprintln(w, "                    *)   comp+=(\"$root_can\") ;;")
	fmt.Fprintln(w, "                esac")
	fmt.Fprintln(w, "                ;;")
	fmt.Fprintln(w, "        esac")
	fmt.Fprintln(w, "    done")
	fmt.Fprintln(w, "    # Ordinary navigation inside an entered root: when the typed prefix")
	fmt.Fprintln(w, "    # reaches or enters an authorized root, the root's own filesystem")
	fmt.Fprintln(w, "    # entries continue the navigation, confined symlink-safely to the")
	fmt.Fprintln(w, "    # roots. The workspace flag suggests directories only (the workspace")
	fmt.Fprintln(w, "    # must be a directory); the filesystem-root flag also suggests")
	fmt.Fprintln(w, "    # regular files.")
	fmt.Fprintln(w, "    root_entered=0")
	fmt.Fprintln(w, "    for i in \"${!roots_can[@]}\"; do")
	fmt.Fprintln(w, "        root_can=\"${roots_can[$i]}\"")
	fmt.Fprintln(w, "        [ -n \"$root_can\" ] || continue")
	fmt.Fprintln(w, "        case \"$prefix\" in")
	fmt.Fprintln(w, "            \"$root_can\"|\"$root_can\"/*) root_entered=1; break ;;")
	fmt.Fprintln(w, "        esac")
	fmt.Fprintln(w, "    done")
	fmt.Fprintln(w, "    if [ \"$root_entered\" -eq 1 ]; then")
	fmt.Fprintln(w, "        while IFS= read -r d; do")
	fmt.Fprintln(w, "            [ -n \"$d\" ] || continue")
	fmt.Fprintln(w, "            [ -e \"$d\" ] || continue")
	fmt.Fprintln(w, "            accept=0")
	fmt.Fprintln(w, "            if [ \"$flag\" = filesystem-root ]; then")
	fmt.Fprintln(w, "                if [ -d \"$d\" ] || [ -f \"$d\" ]; then accept=1; fi")
	fmt.Fprintln(w, "            else")
	fmt.Fprintln(w, "                if [ -d \"$d\" ]; then accept=1; fi")
	fmt.Fprintln(w, "            fi")
	fmt.Fprintln(w, "            [ \"$accept\" -eq 1 ] || continue")
	fmt.Fprintln(w, "            d_can=\"$(realpath -m -- \"$d\" 2>/dev/null)\"")
	fmt.Fprintln(w, "            [ -n \"$d_can\" ] || continue")
	fmt.Fprintln(w, "            for i in \"${!roots_can[@]}\"; do")
	fmt.Fprintln(w, "                root_can=\"${roots_can[$i]}\"")
	fmt.Fprintln(w, "                [ -n \"$root_can\" ] || continue")
	fmt.Fprintln(w, "                if [ \"$d_can\" != \"$root_can\" ] && [[ \"$d_can\" == \"$root_can/\"* ]]; then")
	fmt.Fprintln(w, "                    comp+=(\"$d\")")
	fmt.Fprintln(w, "                    break")
	fmt.Fprintln(w, "                fi")
	fmt.Fprintln(w, "            done")
	fmt.Fprintln(w, "        done < <(compgen -f -- \"$prefix\" 2>/dev/null)")
	fmt.Fprintln(w, "    fi")
	fmt.Fprintln(w, "# The rendered candidates are made deterministic and unique. Path")
	fmt.Fprintln(w, "# candidates are normalized BEFORE the final deduplication, so doubled")
	fmt.Fprintln(w, "# separators can never survive as two rendered results, and nested roots")
	fmt.Fprintln(w, "# never produce duplicate display entries.")
	fmt.Fprintln(w, "    if [ ${#comp[@]} -gt 0 ]; then")
	fmt.Fprintln(w, "        local c n=0")
	fmt.Fprintln(w, "        for c in \"${comp[@]}\"; do")
	fmt.Fprintln(w, "            while [[ \"$c\" == *//* ]]; do")
	fmt.Fprintln(w, "                c=\"${c/'//'/'/'}\"")
	fmt.Fprintln(w, "            done")
	fmt.Fprintln(w, "            comp[n++]=\"$c\"")
	fmt.Fprintln(w, "        done")
	io.WriteString(w, "        mapfile -t comp < <(printf '%s\\n' \"${comp[@]}\" | LC_ALL=C sort -u)\n")
	fmt.Fprintln(w, "    fi")
	fmt.Fprintln(w, "    COMPREPLY=(\"${comp[@]}\")")
	fmt.Fprintln(w, "    _docker_helper_normalize_path_candidates")
	fmt.Fprintln(w, "}")
	fmt.Fprintln(w)

	// The availability-driven tables, evaluation helpers, and the single
	// capability-aware subcommand-completion implementation (no redefinition
	// of any earlier emission).
	generateCompletionAvailabilityBash(w)

	fmt.Fprintln(w, "complete -F _docker_helper_completion docker-helper")
}

// quoteWords quotes each word for use as a Bash case pattern.
func quoteWords(words []string) []string {
	quoted := make([]string, len(words))
	for i, word := range words {
		quoted[i] = fmt.Sprintf("%q", word)
	}
	return quoted
}

// collectAllFlags recursively collects flags for each command path.
func collectAllFlags(cmd *Command, path []string, flags map[string][]string) {
	if cmd.NewInvocation != nil {
		cmdPath := strings.Join(path, " ")
		flags[cmdPath] = collectFlagsForCommand(cmd)
	}
	for _, sub := range cmd.Subcommands {
		newPath := append([]string{}, path...)
		newPath = append(newPath, sub.Name)
		collectAllFlags(sub, newPath, flags)
	}
}

// collectAllBoolFlags recursively collects boolean flag names for each command path.
func collectAllBoolFlags(cmd *Command, path []string, flags map[string][]string) {
	if cmd.NewInvocation != nil {
		cmdPath := strings.Join(path, " ")
		flags[cmdPath] = collectBoolFlagNames(cmd)
	}
	for _, sub := range cmd.Subcommands {
		newPath := append([]string{}, path...)
		newPath = append(newPath, sub.Name)
		collectAllBoolFlags(sub, newPath, flags)
	}
}

func init() {
	rootCommand.Subcommands = append(rootCommand.Subcommands, completionCommand)
}
