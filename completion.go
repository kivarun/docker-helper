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
// Daemon-backed effective-root completion for --allowed-root/--workspace is
// a separate follow-up UX story: it must respect the real authority model
// (Principal credential -> default Launcher -> effective roots; Launcher
// credential -> authenticated Launcher), and the local config is not a
// substitute for daemon policy. Until that exists, path-valued flags keep
// generic filesystem completion.
var pathValuedFlags = []string{
	"endpoint",
	"token-file",
	"workspace",
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
	Subcommands: []*Command{completionBashCommand, completionRootsCommand},
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
// one path per line, resolved by the same daemon-side owner as real Session
// creation.
var completionRootsSessionCommand = &Command{
	Name:       "session",
	Summary:    "Print the Session-create effective allowed roots",
	Usage:      "docker-helper completion roots session [--system] [--endpoint ENDPOINT] [--token-file PATH]",
	MinPosArgs: 0,
	MaxPosArgs: 0,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		system, endpoint, tokenFile := registerOperatorFlags(fs)
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
				result, err := client.sessionCreatePolicy()
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
	{commandPath: "launcher scope set", flag: "allowed-root", query: "principal"},
	{commandPath: "session create", flag: "workspace", query: "session"},
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
	fmt.Fprintln(w, "_docker_helper_completion() {")
	fmt.Fprintln(w, "    local cur=\"${COMP_WORDS[COMP_CWORD]}\"")
	fmt.Fprintln(w, "    local prev=\"${COMP_WORDS[COMP_CWORD-1]:-}\"")
	fmt.Fprintln(w, "    local words=(\"${COMP_WORDS[@]}\")")
	fmt.Fprintln(w, "    local cword=${COMP_CWORD}")
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
	fmt.Fprintln(w, "    while [ $i -lt $cword ]; do")
	fmt.Fprintln(w, "        local word=\"${words[$i]}\"")
	fmt.Fprintln(w, "        case \"$word\" in")
	fmt.Fprintln(w, "            --)")
	fmt.Fprintln(w, "                # End of options: no more flags or subcommands")
	fmt.Fprintln(w, "                seen_double_dash=1")
	fmt.Fprintln(w, "                ;;")
	fmt.Fprintln(w, "            -*)")
	fmt.Fprintln(w, "                # Skip flags")
	fmt.Fprintln(w, "                # Check if this flag takes a value; if so, skip the next word too")
	fmt.Fprintln(w, "                # But --flag=value is self-contained; do not skip next word")
	fmt.Fprintln(w, "                local test_path=\"${cmds[*]}\"")
	fmt.Fprintln(w, "                if [[ \"$word\" != *=* ]] && _docker_helper_flag_takes_value \"$test_path\" \"$word\"; then")
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
	fmt.Fprintln(w, "    # If current word starts with -, complete flags")
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
	fmt.Fprintln(w, "    # If previous word was a flag that takes a value, complete the value")
	fmt.Fprintln(w, "    if [ -n \"$prev\" ] && [[ \"$prev\" == -* ]]; then")
	fmt.Fprintln(w, "        local clean_prev=\"${prev#-}\"")
	fmt.Fprintln(w, "        clean_prev=\"${clean_prev#-}\"")
	fmt.Fprintln(w, "        _docker_helper_complete_flag_value \"$flag_path\" \"$clean_prev\"")
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
	fmt.Fprintln(w, "            while [ $j -lt $COMP_CWORD ]; do")
	fmt.Fprintln(w, "                local w=\"${COMP_WORDS[$j]}\"")
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
	fmt.Fprintln(w, "                while [ $j -lt $COMP_CWORD ]; do")
	fmt.Fprintln(w, "                    local w=\"${COMP_WORDS[$j]}\"")
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
	fmt.Fprintln(w, "            while [ $j -lt $COMP_CWORD ]; do")
	fmt.Fprintln(w, "                local w=\"${COMP_WORDS[$j]}\"")
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
	fmt.Fprintln(w, "            while [ $j -lt $COMP_CWORD ]; do")
	fmt.Fprintln(w, "                local w=\"${COMP_WORDS[$j]}\"")
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
	fmt.Fprintln(w, "            while [ $j -lt $COMP_CWORD ]; do")
	fmt.Fprintln(w, "                local w=\"${COMP_WORDS[$j]}\"")
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
	fmt.Fprintln(w, "            while [ $j -lt $COMP_CWORD ]; do")
	fmt.Fprintln(w, "                local w=\"${COMP_WORDS[$j]}\"")
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
	fmt.Fprintln(w, "# Complete flag values (for flags that take values)")
	fmt.Fprintln(w, "_docker_helper_complete_flag_value() {")
	fmt.Fprintln(w, "    local cmd_path=\"$1\"")
	fmt.Fprintln(w, "    local flag=\"$2\"")
	fmt.Fprintln(w, "    # Daemon-backed policy roots take precedence for their registered")
	fmt.Fprintln(w, "    # (command, flag) pairs. Convenience only: on any query failure")
	fmt.Fprintln(w, "    # completion degrades silently to the generic filesystem completion.")
	fmt.Fprintln(w, "    local mode")
	fmt.Fprintln(w, "    if mode=\"$(_docker_helper_policy_value_mode \"$cmd_path\" \"$flag\")\"; then")
	fmt.Fprintln(w, "        if _docker_helper_complete_policy_roots \"$mode\"; then")
	fmt.Fprintln(w, "            return")
	fmt.Fprintln(w, "        fi")
	fmt.Fprintln(w, "    fi")
	fmt.Fprintln(w, "    # Path-valued flags complete with filesystem paths.")
	fmt.Fprintln(w, "    case \"$flag\" in")
	for _, f := range pathValuedFlags {
		fmt.Fprintf(w, "        %q)\n", f)
		fmt.Fprintln(w, "            compopt -o filenames 2>/dev/null || true")
		fmt.Fprintln(w, "            COMPREPLY=( $(compgen -f -- \"$cur\") )")
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
	fmt.Fprintln(w, "    while [ $i -lt $COMP_CWORD ]; do")
	fmt.Fprintln(w, "        local w=\"${COMP_WORDS[$i]}\"")
	fmt.Fprintln(w, "        case \"$w\" in")
	fmt.Fprintln(w, "            --system) out+=(\"--system\") ;;")
	fmt.Fprintln(w, "            --endpoint|--token-file)")
	fmt.Fprintln(w, "                out+=(\"$w\" \"${COMP_WORDS[$((i+1))]:-}\")")
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
	fmt.Fprintln(w, "# parsing. Empty output when the flag has no typed value yet.")
	fmt.Fprintln(w, "_docker_helper_typed_flag_value() {")
	fmt.Fprintln(w, "    local name=\"$1\"")
	fmt.Fprintln(w, "    local value=\"\"")
	fmt.Fprintln(w, "    local i=1")
	fmt.Fprintln(w, "    while [ $i -lt $COMP_CWORD ]; do")
	fmt.Fprintln(w, "        local w=\"${COMP_WORDS[$i]}\"")
	fmt.Fprintln(w, "        case \"$w\" in")
	fmt.Fprintln(w, "            \"--$name=\"*) value=\"${w#--$name=}\" ;;")
	fmt.Fprintln(w, "            \"--$name\")")
	fmt.Fprintln(w, "                i=$((i + 1))")
	fmt.Fprintln(w, "                if [ $i -lt $COMP_CWORD ]; then value=\"${COMP_WORDS[$i]}\"; fi")
	fmt.Fprintln(w, "                ;;")
	fmt.Fprintln(w, "        esac")
	fmt.Fprintln(w, "        i=$((i + 1))")
	fmt.Fprintln(w, "    done")
	io.WriteString(w, "    printf '%s\\n' \"$value\"\n")
	fmt.Fprintln(w, "}")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "# Run the daemon-backed roots query through docker-helper itself and")
	fmt.Fprintln(w, "# complete from the returned policy anchors. The forwarded operator")
	fmt.Fprintln(w, "# overrides and the typed --principal value stay Bash arrays end to")
	fmt.Fprintln(w, "# end, so values with spaces reach the helper as single arguments.")
	fmt.Fprintln(w, "# Prints nothing and fails silently when the query is unavailable.")
	fmt.Fprintln(w, "_docker_helper_complete_policy_roots() {")
	fmt.Fprintln(w, "    local mode=\"$1\"")
	fmt.Fprintln(w, "    local -a opargs=()")
	fmt.Fprintln(w, "    mapfile -d '' -t opargs < <(_docker_helper_operator_args \"$cmd_path\")")
	fmt.Fprintln(w, "    local -a principal_qargs=()")
	fmt.Fprintln(w, "    if [ \"$mode\" = principal ]; then")
	fmt.Fprintln(w, "        local principal_arg")
	fmt.Fprintln(w, "        principal_arg=\"$(_docker_helper_typed_flag_value principal)\"")
	fmt.Fprintln(w, "        if [ -n \"$principal_arg\" ]; then")
	fmt.Fprintln(w, "            principal_qargs=(--principal \"$principal_arg\")")
	fmt.Fprintln(w, "        fi")
	fmt.Fprintln(w, "    fi")
	fmt.Fprintln(w, "    local roots")
	fmt.Fprintln(w, "    if ! roots=\"$(\"${COMP_WORDS[0]}\" completion roots \"$mode\" \"${opargs[@]}\" \"${principal_qargs[@]}\" 2>/dev/null)\"; then")
	fmt.Fprintln(w, "        return 1")
	fmt.Fprintln(w, "    fi")
	fmt.Fprintln(w, "    _docker_helper_complete_within_roots \"$flag\" \"$roots\"")
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
	fmt.Fprintln(w, "# Complete a path-valued flag constrained to the effective policy roots:")
	fmt.Fprintln(w, "# the roots are the entry anchors, and directory completion inside a")
	fmt.Fprintln(w, "# root is confined to that root. Regular files and paths outside the")
	fmt.Fprintln(w, "# roots are never suggested. Directory continuation is left to Bash's")
	fmt.Fprintln(w, "# filename semantics: the roots are offered bare and Bash appends the")
	fmt.Fprintln(w, "# separator for a directory, so no candidate is ever pre-slash-")
	fmt.Fprintln(w, "# terminated (Bash marks directories itself and a pre-terminated")
	fmt.Fprintln(w, "# candidate could receive a second separator on some Bash versions).")
	fmt.Fprintln(w, "#")
	fmt.Fprintln(w, "# Filesystem candidates are confined symlink-safely: a candidate is")
	fmt.Fprintln(w, "# accepted only when its canonicalized path (realpath) lies strictly")
	fmt.Fprintln(w, "# inside the canonicalized root, so a link escaping the root is never")
	fmt.Fprintln(w, "# suggested and a link pointing inside is treated as its target. The")
	fmt.Fprintln(w, "# daemon remains the security boundary; this only keeps obviously")
	fmt.Fprintln(w, "# invalid paths out of the suggestions.")
	fmt.Fprintln(w, "_docker_helper_complete_within_roots() {")
	fmt.Fprintln(w, "    local flag=\"$1\"")
	fmt.Fprintln(w, "    local roots=\"$2\"")
	fmt.Fprintln(w, "    local -a anchors=() roots_can=()")
	fmt.Fprintln(w, "    local r")
	fmt.Fprintln(w, "    while IFS= read -r r; do")
	fmt.Fprintln(w, "        [ -n \"$r\" ] || continue")
	fmt.Fprintln(w, "        anchors+=(\"$r\")")
	fmt.Fprintln(w, "        roots_can+=(\"$(realpath -m -- \"$r\" 2>/dev/null)\")")
	fmt.Fprintln(w, "    done <<< \"$roots\"")
	fmt.Fprintln(w, "    local comp=()")
	fmt.Fprintln(w, "    local a d d_can i root_can")
	fmt.Fprintln(w, "    for a in \"${anchors[@]}\"; do")
	fmt.Fprintln(w, "        case \"$a\" in")
	fmt.Fprintln(w, "            \"$cur\"*) comp+=(\"$a\") ;;")
	fmt.Fprintln(w, "        esac")
	fmt.Fprintln(w, "    done")
	fmt.Fprintln(w, "    if [[ \"$cur\" == */* ]]; then")
	fmt.Fprintln(w, "        while IFS= read -r d; do")
	fmt.Fprintln(w, "            [ -n \"$d\" ] || continue")
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
	fmt.Fprintln(w, "        done < <(compgen -d -- \"$cur\" 2>/dev/null)")
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
