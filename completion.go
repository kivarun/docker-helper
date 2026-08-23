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

// generateBashCompletion generates a Bash completion script for the docker-helper CLI.
func generateBashCompletion(w io.Writer) {
	// Collect all command paths.
	allPaths := collectAllCommandPaths(rootCommand, nil)
	sort.Strings(allPaths)

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
	fmt.Fprintln(w, "                local test_path=\"${cmds[*]}\"")
	fmt.Fprintln(w, "                if _docker_helper_flag_takes_value \"$test_path\" \"$word\"; then")
	fmt.Fprintln(w, "                    i=$((i + 2))")
	fmt.Fprintln(w, "                    continue")
	fmt.Fprintln(w, "                fi")
	fmt.Fprintln(w, "                ;;")
	fmt.Fprintln(w, "            *)")
	fmt.Fprintln(w, "                # Only add to cmds if this is a valid subcommand")
	fmt.Fprintln(w, "                local test_path")
	fmt.Fprintln(w, "                if [ ${#cmds[@]} -eq 0 ]; then")
	fmt.Fprintln(w, "                    test_path=\"$word\"")
	fmt.Fprintln(w, "                else")
	fmt.Fprintln(w, "                    test_path=\"${cmds[*]} $word\"")
	fmt.Fprintln(w, "                fi")
	fmt.Fprintln(w, "                if _docker_helper_is_command \"$test_path\"; then")
	fmt.Fprintln(w, "                    cmds+=(\"$word\")")
	fmt.Fprintln(w, "                fi")
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
	fmt.Fprintln(w, "        _docker_helper_complete_flag_value \"$cmd_path\" \"$clean_prev\"")
	fmt.Fprintln(w, "        return")
	fmt.Fprintln(w, "    fi")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "    # Complete positional args or subcommands")
	fmt.Fprintln(w, "    _docker_helper_complete_positional \"$cmd_path\"")
	fmt.Fprintln(w, "}")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "# Complete positional arguments or subcommands")
	fmt.Fprintln(w, "_docker_helper_complete_positional() {")
	fmt.Fprintln(w, "    local cmd_path=\"$1\"")
	fmt.Fprintln(w)
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
	fmt.Fprintln(w, "            return")
	fmt.Fprintln(w, "            ;;")
	fmt.Fprintln(w, "        \"config unset\")")
	fmt.Fprintf(w, "            COMPREPLY=( $(compgen -W %q -- \"$cur\") )\n", strings.Join(configUnsetFields(), " "))
	fmt.Fprintln(w, "            return")
	fmt.Fprintln(w, "            ;;")
	fmt.Fprintln(w, "    esac")
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
	// Root command also gets -h/--help
	fmt.Fprintf(w, "        \"\") echo \"-h --help\" ;;\n")
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
	fmt.Fprintln(w, "    # No flag-based value completion needed; positional handles config")
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
