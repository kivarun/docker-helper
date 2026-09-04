package main

import (
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// completionLocalPrivilege is local execution-identity metadata used only to
// suppress completion suggestions that cannot run under the current EUID.
// It is not an authorization layer; explicit invocation keeps the command's
// existing runtime checks and help remains fully navigable.
type completionLocalPrivilege uint8

const (
	completionPrivilegeAny completionLocalPrivilege = iota
	completionPrivilegeRoot
	completionPrivilegeNonRoot
)

// completionAuthorityMask describes which operator bearer authorities can use
// a command. A zero mask means completion does not filter that command by
// operator authority (for example local commands and Session-token data-plane
// commands). The daemon remains the authorization authority.
type completionAuthorityMask uint8

const (
	completionAuthorityAdmin completionAuthorityMask = 1 << iota
	completionAuthorityPrincipal
	completionAuthorityLauncher
)

type completionAvailability struct {
	Local       completionLocalPrivilege
	Authorities completionAuthorityMask
}

// completionAvailabilityByCommand is keyed by command nodes, not command-name
// strings, so availability metadata follows the parser tree structurally.
var completionAvailabilityByCommand = map[*Command]completionAvailability{}

const completionAuthorityQueryTimeout = 250 * time.Millisecond

// completionAuthorityCommand is the narrow machine-facing helper used by the
// generated shell completion to learn the current operator bearer authority.
// GET /auth remains the single authority source; failures are silent to Bash,
// which falls back to the unfiltered static command tree.
var completionAuthorityCommand = &Command{
	Name:       "authority",
	Summary:    "Query operator authority for shell completion",
	Usage:      "docker-helper completion authority [--system] [--endpoint ENDPOINT] [--token-file PATH]",
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
					Timeout:   completionAuthorityQueryTimeout,
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
				case "admin", "principal", "launcher":
					fmt.Fprintln(stdout, auth.Authority)
					return 0
				default:
					fmt.Fprintf(stderr, "error: unknown authority %q\n", auth.Authority)
					return 1
				}
			},
		}
	},
}

func setCompletionLocal(local completionLocalPrivilege, commands ...*Command) {
	for _, cmd := range commands {
		if cmd == nil {
			panic("completion availability: nil command")
		}
		v := completionAvailabilityByCommand[cmd]
		v.Local = local
		completionAvailabilityByCommand[cmd] = v
	}
}

func setCompletionAuthorities(authorities completionAuthorityMask, commands ...*Command) {
	for _, cmd := range commands {
		if cmd == nil {
			panic("completion availability: nil command")
		}
		v := completionAvailabilityByCommand[cmd]
		v.Authorities = authorities
		completionAvailabilityByCommand[cmd] = v
	}
}

func mustCompletionSubcommand(parent *Command, name string) *Command {
	cmd := parent.resolveSubcommand(name)
	if cmd == nil {
		panic(fmt.Sprintf("completion availability: %s has no %s subcommand", parent.Name, name))
	}
	return cmd
}

func configureCompletionAvailability() {
	setCompletionLocal(completionPrivilegeRoot,
		appArmorRootListCommand,
		appArmorRootAddCommand,
		appArmorRootRemoveCommand,
		appArmorCheckCommand,
		selinuxCheckCommand,
	)
	setCompletionLocal(completionPrivilegeNonRoot, credentialInstallCommand)

	admin := completionAuthorityAdmin
	adminPrincipal := completionAuthorityAdmin | completionAuthorityPrincipal
	control := adminPrincipal | completionAuthorityLauncher

	setCompletionAuthorities(admin,
		reloadCommand,
		adminTokenRotateCommand,
		principalCreateCommand,
		principalListCommand,
		principalShowCommand,
		principalSetCommand,
		principalDeleteCommand,
		principalAllowedRootAddCommand,
		principalAllowedRootRemoveCommand,
		principalCredentialCreateCommand,
		principalCredentialRevokeCommand,
		mustCompletionSubcommand(credentialCommand, "create"),
		mustCompletionSubcommand(credentialCommand, "revoke"),
	)

	setCompletionAuthorities(adminPrincipal,
		principalCredentialListCommand,
		principalCredentialRotateCommand,
		mustCompletionSubcommand(credentialCommand, "list"),
		launcherCreateCommand,
		launcherListCommand,
		launcherShowCommand,
		launcherSetCommand,
		launcherDeleteCommand,
		launcherScopeSetCommand,
		launcherCredentialCreateCommand,
		launcherCredentialShowCommand,
		launcherCredentialRotateCommand,
		launcherCredentialDeleteCommand,
		completionRootsPrincipalCommand,
	)

	setCompletionAuthorities(control,
		sessionCreateCommand,
		sessionListCommand,
		sessionDeleteCommand,
		completionRootsSessionCommand,
	)
}

func completionAuthorityForName(name string) completionAuthorityMask {
	switch name {
	case "admin":
		return completionAuthorityAdmin
	case "principal":
		return completionAuthorityPrincipal
	case "launcher":
		return completionAuthorityLauncher
	default:
		return 0
	}
}

// completionCommandAvailable mirrors the generated Bash pruning rule and is
// intentionally advisory only. Branches remain visible when at least one
// descendant command is available in the supplied local/authority context.
func completionCommandAvailable(cmd *Command, euid int, authority string) bool {
	availability := completionAvailabilityByCommand[cmd]
	switch availability.Local {
	case completionPrivilegeRoot:
		if euid != 0 {
			return false
		}
	case completionPrivilegeNonRoot:
		if euid == 0 {
			return false
		}
	}
	if availability.Authorities != 0 {
		authorityMask := completionAuthorityForName(authority)
		if authorityMask == 0 || availability.Authorities&authorityMask == 0 {
			return false
		}
	}
	if len(cmd.Subcommands) == 0 {
		return true
	}
	for _, sub := range cmd.Subcommands {
		if completionCommandAvailable(sub, euid, authority) {
			return true
		}
	}
	return false
}

func completionAvailabilityPaths() map[string]completionAvailability {
	result := make(map[string]completionAvailability)
	var walk func(*Command, []string)
	walk = func(cmd *Command, path []string) {
		for _, sub := range cmd.Subcommands {
			subPath := append(append([]string{}, path...), sub.Name)
			if availability, ok := completionAvailabilityByCommand[sub]; ok {
				result[strings.Join(subPath, " ")] = availability
			}
			walk(sub, subPath)
		}
	}
	walk(rootCommand, nil)
	return result
}

func completionAuthorityWords(mask completionAuthorityMask) string {
	var words []string
	if mask&completionAuthorityAdmin != 0 {
		words = append(words, "admin")
	}
	if mask&completionAuthorityPrincipal != 0 {
		words = append(words, "principal")
	}
	if mask&completionAuthorityLauncher != 0 {
		words = append(words, "launcher")
	}
	return strings.Join(words, " ")
}

func generateCapabilityAwareBashCompletion(w io.Writer) {
	generateBashCompletion(w)
	generateCompletionAvailabilityBash(w)
}

func generateCompletionAvailabilityBash(w io.Writer) {
	paths := completionAvailabilityPaths()
	var sortedPaths []string
	for path := range paths {
		sortedPaths = append(sortedPaths, path)
	}
	sort.Strings(sortedPaths)

	fmt.Fprintln(w)
	fmt.Fprintln(w, "# Capability-aware availability overlay. Explicit command paths and help")
	fmt.Fprintln(w, "# keep the full parser tree; only ordinary subcommand suggestions are pruned.")
	fmt.Fprintln(w, "_docker_helper_completion_local_requirement() {")
	fmt.Fprintln(w, "    case \"$1\" in")
	for _, path := range sortedPaths {
		switch paths[path].Local {
		case completionPrivilegeRoot:
			fmt.Fprintf(w, "        %q) echo root ;;\n", path)
		case completionPrivilegeNonRoot:
			fmt.Fprintf(w, "        %q) echo non-root ;;\n", path)
		}
	}
	fmt.Fprintln(w, "    esac")
	fmt.Fprintln(w, "}")
	fmt.Fprintln(w)

	fmt.Fprintln(w, "_docker_helper_completion_authorities() {")
	fmt.Fprintln(w, "    case \"$1\" in")
	for _, path := range sortedPaths {
		if words := completionAuthorityWords(paths[path].Authorities); words != "" {
			fmt.Fprintf(w, "        %q) echo %q ;;\n", path, words)
		}
	}
	fmt.Fprintln(w, "    esac")
	fmt.Fprintln(w, "}")
	fmt.Fprintln(w)

	fmt.Fprintln(w, "_docker_helper_completion_euid() {")
	fmt.Fprint(w, "    if [ -n \"${EUID+x}\" ]; then printf '%s\\n' \"$EUID\"; else id -u; fi\n")
	fmt.Fprintln(w, "}")
	fmt.Fprintln(w)

	fmt.Fprintln(w, "_docker_helper_completion_authority() {")
	fmt.Fprintln(w, "    local cmd_path=\"$1\"")
	fmt.Fprintln(w, "    local -a opargs=()")
	fmt.Fprintln(w, "    mapfile -d '' -t opargs < <(_docker_helper_operator_args \"$cmd_path\")")
	fmt.Fprintln(w, "    \"${COMP_WORDS[0]}\" completion authority \"${opargs[@]}\" 2>/dev/null")
	fmt.Fprintln(w, "}")
	fmt.Fprintln(w)

	fmt.Fprintln(w, "_docker_helper_completion_path_available() {")
	fmt.Fprintln(w, "    local path=\"$1\" euid=\"$2\" authority=\"$3\"")
	fmt.Fprintln(w, "    local local_req auths child")
	fmt.Fprintln(w, "    local_req=\"$(_docker_helper_completion_local_requirement \"$path\")\"")
	fmt.Fprintln(w, "    case \"$local_req\" in")
	fmt.Fprintln(w, "        root) [ \"$euid\" -eq 0 ] || return 1 ;;\n        non-root) [ \"$euid\" -ne 0 ] || return 1 ;;\n    esac")
	fmt.Fprintln(w, "    auths=\"$(_docker_helper_completion_authorities \"$path\")\"")
	fmt.Fprintln(w, "    if [ -n \"$auths\" ]; then")
	fmt.Fprintln(w, "        case \" $auths \" in *\" $authority \"*) ;; *) return 1 ;; esac")
	fmt.Fprintln(w, "    fi")
	fmt.Fprintln(w, "    local children=($(_docker_helper_subcommands \"$path\"))")
	fmt.Fprintln(w, "    if [ ${#children[@]} -eq 0 ]; then return 0; fi")
	fmt.Fprintln(w, "    for child in \"${children[@]}\"; do")
	fmt.Fprintln(w, "        local child_path=\"$child\"")
	fmt.Fprintln(w, "        if [ -n \"$path\" ]; then child_path=\"$path $child\"; fi")
	fmt.Fprintln(w, "        if _docker_helper_completion_path_available \"$child_path\" \"$euid\" \"$authority\"; then return 0; fi")
	fmt.Fprintln(w, "    done")
	fmt.Fprintln(w, "    return 1")
	fmt.Fprintln(w, "}")
	fmt.Fprintln(w)

	fmt.Fprintln(w, "# Override only the suggestion layer. _docker_helper_is_command remains the")
	fmt.Fprintln(w, "# complete parser tree so manually typed commands continue to parse normally.")
	fmt.Fprintln(w, "_docker_helper_complete_subcommands() {")
	fmt.Fprintln(w, "    local cmd_path=\"$1\"")
	fmt.Fprintln(w, "    local subcmds=($(_docker_helper_subcommands \"$cmd_path\"))")
	fmt.Fprintln(w, "    local comp_cmds=() c child_path")
	fmt.Fprintln(w, "    if [ \"${in_help:-0}\" -eq 1 ]; then")
	fmt.Fprintln(w, "        for c in \"${subcmds[@]}\"; do case \"$c\" in \"$cur\"*) comp_cmds+=(\"$c\") ;; esac; done")
	fmt.Fprintln(w, "        COMPREPLY=(\"${comp_cmds[@]}\")")
	fmt.Fprintln(w, "        return")
	fmt.Fprintln(w, "    fi")
	fmt.Fprintln(w, "    local authority")
	fmt.Fprintln(w, "    if ! authority=\"$(_docker_helper_completion_authority \"$cmd_path\")\"; then")
	fmt.Fprintln(w, "        for c in \"${subcmds[@]}\"; do case \"$c\" in \"$cur\"*) comp_cmds+=(\"$c\") ;; esac; done")
	fmt.Fprintln(w, "        COMPREPLY=(\"${comp_cmds[@]}\")")
	fmt.Fprintln(w, "        return")
	fmt.Fprintln(w, "    fi")
	fmt.Fprintln(w, "    local euid")
	fmt.Fprintln(w, "    euid=\"$(_docker_helper_completion_euid)\"")
	fmt.Fprintln(w, "    for c in \"${subcmds[@]}\"; do")
	fmt.Fprintln(w, "        child_path=\"$c\"")
	fmt.Fprintln(w, "        if [ -n \"$cmd_path\" ]; then child_path=\"$cmd_path $c\"; fi")
	fmt.Fprintln(w, "        if _docker_helper_completion_path_available \"$child_path\" \"$euid\" \"$authority\"; then")
	fmt.Fprintln(w, "            case \"$c\" in \"$cur\"*) comp_cmds+=(\"$c\") ;; esac")
	fmt.Fprintln(w, "        fi")
	fmt.Fprintln(w, "    done")
	fmt.Fprintln(w, "    COMPREPLY=(\"${comp_cmds[@]}\")")
	fmt.Fprintln(w, "}")
}

func init() {
	configureCompletionAvailability()
	completionCommand.Subcommands = append(completionCommand.Subcommands, completionAuthorityCommand)
	completionBashCommand.NewInvocation = func(fs *flag.FlagSet) Invocation {
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				generateCapabilityAwareBashCompletion(stdout)
				return 0
			},
		}
	}
}
