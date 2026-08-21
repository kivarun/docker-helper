package main

import (
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"
)

var completionCommand = &Command{
	Name:       "completion",
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
	Subcommands: []*Command{completionBashCommand},
}

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

// collectFlagsForCommand collects all flag names from a command's flag set.
func collectFlagsForCommand(cmd *Command) []string {
	if cmd.NewInvocation == nil {
		return nil
	}
	fs := flag.NewFlagSet("", flag.ContinueOnError)
	cmd.NewInvocation(fs)
	var flags []string
	fs.VisitAll(func(f *flag.Flag) {
		flags = append(flags, "--"+f.Name)
		if len(f.Name) == 1 {
			flags = append(flags, "-"+f.Name)
		}
	})
	// Always include -h and --help for commands with NewInvocation
	flags = append(flags, "-h", "--help")
	return flags
}

// isBoolFlag checks if a flag is a boolean flag.
func isBoolFlag(cmd *Command, flagName string) bool {
	if cmd.NewInvocation == nil {
		return false
	}
	fs := flag.NewFlagSet("", flag.ContinueOnError)
	cmd.NewInvocation(fs)
	fs.VisitAll(func(f *flag.Flag) {
		if f.Name == flagName {
			// Boolean flags have a default value of "true" or "false"
			// and are of type *bool
			_ = f.Value
		}
	})
	// Check if the flag value is a boolean by checking the default
	fs.VisitAll(func(f *flag.Flag) {
		if f.Name == flagName {
			// We can't easily check the type, so we check known bool flags
			// For now, we check if the usage contains common bool patterns
			// or if the flag name matches known bool flags
		}
	})
	// Use a heuristic: check if the flag name matches known bool flags
	boolFlags := map[string]bool{
		"system": true,
		"json":   true,
		"help":   true,
		"h":      true,
	}
	return boolFlags[flagName]
}

// generateBashCompletion generates a Bash completion script for the docker-helper CLI.
func generateBashCompletion(w io.Writer) {
	// Collect all command paths.
	allPaths := collectAllCommandPaths(rootCommand, nil)
	sort.Strings(allPaths)

	// Collect flags for each command path.
	commandFlags := make(map[string][]string)
	collectAllFlags(rootCommand, []string{}, commandFlags)

	// Sort command paths for deterministic output.
	sortedPaths := make([]string, 0, len(commandFlags))
	for path := range commandFlags {
		sortedPaths = append(sortedPaths, path)
	}
	sort.Strings(sortedPaths)

	fmt.Fprintln(w, "# Bash completion for docker-helper")
	fmt.Fprintln(w, "# Generated automatically - do not edit")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "_docker_helper_completion() {")
	fmt.Fprintln(w, "    local cur=\"${COMP_WORDS[COMP_CWORD]}\"")
	fmt.Fprintln(w, "    local prev=\"${COMP_WORDS[COMP_CWORD-1]:-}\"")
	fmt.Fprintln(w, "    local words=(\"${COMP_WORDS[@]}\")")
	fmt.Fprintln(w, "    local cword=${COMP_CWORD}")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "    # Build the command path by walking the Command tree")
	fmt.Fprintln(w, "    local cmds=()")
	fmt.Fprintln(w, "    local i=1")
	fmt.Fprintln(w, "    while [ $i -lt $cword ]; do")
	fmt.Fprintln(w, "        local word=\"${words[$i]}\"")
	fmt.Fprintln(w, "        case \"$word\" in")
	fmt.Fprintln(w, "            -*)")
	fmt.Fprintln(w, "                # Skip flags")
	fmt.Fprintln(w, "                # Check if this flag takes a value; if so, skip the next word too")
	fmt.Fprintln(w, "                local cmd_path=\"${cmds[*]}\"")
	fmt.Fprintln(w, "                if _docker_helper_flag_takes_value \"$cmd_path\" \"$word\"; then")
	fmt.Fprintln(w, "                    i=$((i + 2))")
	fmt.Fprintln(w, "                    continue")
	fmt.Fprintln(w, "                fi")
	fmt.Fprintln(w, "                ;;")
	fmt.Fprintln(w, "            *)")
	fmt.Fprintln(w, "                cmds+=(\"$word\")")
	fmt.Fprintln(w, "                ;;")
	fmt.Fprintln(w, "        esac")
	fmt.Fprintln(w, "        i=$((i + 1))")
	fmt.Fprintln(w, "    done")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "    local cmd_path=\"${cmds[*]}\"")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "    # If current word starts with -, complete flags")
	fmt.Fprintln(w, "    case \"$cur\" in")
	fmt.Fprintln(w, "        -*)")
	fmt.Fprintln(w, "            local flags=($(_docker_helper_flags \"$cmd_path\"))")
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
	fmt.Fprintln(w, "        _docker_helper_complete_value \"$cmd_path\" \"$clean_prev\"")
	fmt.Fprintln(w, "        return")
	fmt.Fprintln(w, "    fi")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "    # Complete subcommands")
	fmt.Fprintln(w, "    local subcmds=($(_docker_helper_subcommands \"$cmd_path\"))")
	fmt.Fprintln(w, "    local comp_cmds=()")
	fmt.Fprintln(w, "    for c in \"${subcmds[@]}\"; do")
	fmt.Fprintln(w, "        case \"$c\" in")
	fmt.Fprintln(w, "            \"$cur\"*) comp_cmds+=(\"$c\") ;;")
	fmt.Fprintln(w, "        esac")
	fmt.Fprintln(w, "    done")
	fmt.Fprintln(w, "    COMPREPLY=(\"${comp_cmds[@]}\")")
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
	fmt.Fprintln(w, "# Return flags for a given command path")
	fmt.Fprintln(w, "_docker_helper_flags() {")
	fmt.Fprintln(w, "    local cmd_path=\"$1\"")
	fmt.Fprintln(w, "    case \"$cmd_path\" in")
	for _, path := range sortedPaths {
		flags := commandFlags[path]
		if len(flags) > 0 {
			fmt.Fprintf(w, "        \"%s\") echo \"%s\" ;;\n", path, strings.Join(flags, " "))
		}
	}
	fmt.Fprintln(w, "    esac")
	fmt.Fprintln(w, "}")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "# Check if a flag takes a value (non-boolean)")
	fmt.Fprintln(w, "_docker_helper_flag_takes_value() {")
	fmt.Fprintln(w, "    local cmd_path=\"$1\"")
	fmt.Fprintln(w, "    local flag=\"$2\"")
	fmt.Fprintln(w, "    local clean_flag=\"${flag#-}\"")
	fmt.Fprintln(w, "    clean_flag=\"${clean_flag#-}\"")
	fmt.Fprintln(w, "    # Boolean flags do not take values")
	fmt.Fprintln(w, "    case \"$clean_flag\" in")
	fmt.Fprintln(w, "        system|json|h|help) return 1 ;;")
	fmt.Fprintln(w, "    esac")
	fmt.Fprintln(w, "    # String flags take values")
	fmt.Fprintln(w, "    case \"$clean_flag\" in")
	fmt.Fprintln(w, "        allowed-root|endpoint|token-file|registry|username|config|value) return 0 ;;")
	fmt.Fprintln(w, "    esac")
	fmt.Fprintln(w, "    # Default: assume it takes a value")
	fmt.Fprintln(w, "    return 0")
	fmt.Fprintln(w, "}")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "# Complete flag values")
	fmt.Fprintln(w, "_docker_helper_complete_value() {")
	fmt.Fprintln(w, "    local cmd_path=\"$1\"")
	fmt.Fprintln(w, "    local flag=\"$2\"")
	fmt.Fprintln(w, "    case \"$flag\" in")
	fmt.Fprintln(w, "        config)")
	fmt.Fprintln(w, "            COMPREPLY=( $(compgen -W \"allowed_root session_ttl log_level audit_enabled shutdown_timeout operation_retention_ttl operation_max_completed operation_log_max_bytes trusted_ca_path trusted_ca_injection http_address\" -- \"${COMP_WORDS[COMP_CWORD]}\") )")
	fmt.Fprintln(w, "            ;;")
	fmt.Fprintln(w, "        log-level)")
	fmt.Fprintln(w, "            COMPREPLY=( $(compgen -W \"DEBUG INFO WARN ERROR\" -- \"${COMP_WORDS[COMP_CWORD]}\") )")
	fmt.Fprintln(w, "            ;;")
	fmt.Fprintln(w, "        trusted-ca-injection)")
	fmt.Fprintln(w, "            COMPREPLY=( $(compgen -W \"disabled auto\" -- \"${COMP_WORDS[COMP_CWORD]}\") )")
	fmt.Fprintln(w, "            ;;")
	fmt.Fprintln(w, "    esac")
	fmt.Fprintln(w, "}")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "complete -F _docker_helper_completion docker-helper")
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

func init() {
	rootCommand.Subcommands = append(rootCommand.Subcommands, completionCommand)
}
