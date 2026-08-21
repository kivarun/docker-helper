package main

import (
	"flag"
	"fmt"
	"io"
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

// collectCommandNames collects all command and subcommand names from the command tree.
func collectCommandNames(cmd *Command, path []string) []string {
	var names []string
	for _, sub := range cmd.Subcommands {
		fullPath := append(path, sub.Name)
		names = append(names, strings.Join(fullPath, " "))
	}
	return names
}

// collectFlags collects all flag names from a command's flag set.
func collectFlags(cmd *Command) []string {
	if cmd.NewInvocation == nil {
		return nil
	}
	fs := flag.NewFlagSet("", flag.ContinueOnError)
	cmd.NewInvocation(fs)
	var flags []string
	fs.VisitAll(func(f *flag.Flag) {
		if f.Name == "h" || f.Name == "help" {
			return
		}
		flags = append(flags, "--"+f.Name)
		if len(f.Name) == 1 {
			flags = append(flags, "-"+f.Name)
		}
	})
	return flags
}

// generateBashCompletion generates a Bash completion script for the docker-helper CLI.
func generateBashCompletion(w io.Writer) {
	// Collect all commands and their subcommands.
	allCommands := collectCommandNames(rootCommand, []string{})

	// Collect all flags for each command.
	commandFlags := make(map[string][]string)
	collectCommandFlags(rootCommand, []string{}, commandFlags)

	// Generate the Bash completion script.
	fmt.Fprintln(w, "# Bash completion for docker-helper")
	fmt.Fprintln(w, "# Generated automatically - do not edit")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "_docker_helper_completion() {")
	fmt.Fprintln(w, "    local cur prev words cword")
	fmt.Fprintln(w, "    _init_completion")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "    # Get the command path so far")
	fmt.Fprintln(w, "    local cmds=()")
	fmt.Fprintln(w, "    local i")
	fmt.Fprintln(w, "    for ((i=1; i < ${COMP_WORDS[@]}; i++)); do")
	fmt.Fprintln(w, "        local word=${COMP_WORDS[$i]}")
	fmt.Fprintln(w, "        case $word in")
	fmt.Fprintln(w, "            -*)")
	fmt.Fprintln(w, "                continue")
	fmt.Fprintln(w, "                ;;")
	fmt.Fprintln(w, "            *)")
	fmt.Fprintln(w, "                cmds+=(\"$word\")")
	fmt.Fprintln(w, "                ;;")
	fmt.Fprintln(w, "        esac")
	fmt.Fprintln(w, "    done")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "    local cmd_path=\"${cmds[*]}\"")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "    # Check if the current word is a flag value")
	fmt.Fprintln(w, "    if [[ \"$prev\" == -* ]]; then")
	fmt.Fprintln(w, "        _docker_helper_complete_flag_value \"$cmd_path\" \"$prev\"")
	fmt.Fprintln(w, "        return")
	fmt.Fprintln(w, "    fi")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "    # Check if we're completing a flag")
	fmt.Fprintln(w, "    if [[ \"$cur\" == -* ]]; then")
	fmt.Fprintln(w, "        local flags=($(_docker_helper_flags_for \"$cmd_path\"))")
	fmt.Fprintln(w, "        COMPREPLY=( $(compgen -W \"${flags[*]}\" -- \"$cur\") )")
	fmt.Fprintln(w, "        return")
	fmt.Fprintln(w, "    fi")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "    # Complete subcommands")
	fmt.Fprintln(w, "    local subcmds=($(_docker_helper_subcommands_for \"$cmd_path\"))")
	fmt.Fprintln(w, "    COMPREPLY=( $(compgen -W \"${subcmds[*]}\" -- \"$cur\") )")
	fmt.Fprintln(w, "}")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "# Return subcommands for a given command path")
	fmt.Fprintln(w, "_docker_helper_subcommands_for() {")
	fmt.Fprintln(w, "    local cmd_path=\"$1\"")
	fmt.Fprintln(w)
	// Generate case statements for each command path.
	for _, cmd := range allCommands {
		subcmds := getSubcommandsForPath(cmd)
		if len(subcmds) > 0 {
			fmt.Fprintln(w, "    case \"$cmd_path\" in")
			fmt.Fprintf(w, "        \"%s\")\n", cmd)
			fmt.Fprintf(w, "            echo \"%s\"\n", strings.Join(subcmds, " "))
			fmt.Fprintln(w, "            ;;")
			fmt.Fprintln(w, "    esac")
			fmt.Fprintln(w)
		}
	}
	// Root command subcommands.
	rootSubcmds := getSubcommandsForPath("")
	fmt.Fprintln(w, "    case \"$cmd_path\" in")
	fmt.Fprintln(w, "        \"\")")
	fmt.Fprintf(w, "            echo \"%s\"\n", strings.Join(rootSubcmds, " "))
	fmt.Fprintf(w, "            ;;")
	fmt.Fprintf(w, "    esac")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "}")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "# Return flags for a given command path")
	fmt.Fprintln(w, "_docker_helper_flags_for() {")
	fmt.Fprintln(w, "    local cmd_path=\"$1\"")
	fmt.Fprintln(w)
	// Generate case statements for each command path.
	for cmd, flags := range commandFlags {
		fmt.Fprintln(w, "    case \"$cmd_path\" in")
		fmt.Fprintf(w, "        \"%s\")\n", cmd)
		fmt.Fprintf(w, "            echo \"%s\"\n", strings.Join(flags, " "))
		fmt.Fprintln(w, "            ;;")
		fmt.Fprintln(w, "    esac")
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w, "}")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "# Complete flag values")
	fmt.Fprintln(w, "_docker_helper_complete_flag_value() {")
	fmt.Fprintln(w, "    local cmd_path=\"$1\"")
	fmt.Fprintln(w, "    local flag=\"$2\"")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "    # No dynamic completion for flag values yet")
	fmt.Fprintln(w, "    # Future: complete enum values, config keys, etc.")
	fmt.Fprintln(w, "}")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "complete -F _docker_helper_completion docker-helper")
}

// collectCommandFlags recursively collects flags for each command path.
func collectCommandFlags(cmd *Command, path []string, flags map[string][]string) {
	if cmd.NewInvocation != nil {
		cmdPath := strings.Join(path, " ")
		flags[cmdPath] = collectFlags(cmd)
	}
	for _, sub := range cmd.Subcommands {
		newPath := append(path, sub.Name)
		collectCommandFlags(sub, newPath, flags)
	}
}

// getSubcommandsForPath returns the subcommand names for a given command path.
func getSubcommandsForPath(path string) []string {
	var cmd *Command
	if path == "" {
		cmd = rootCommand
	} else {
		parts := strings.Split(path, " ")
		cmd = rootCommand
		for _, part := range parts {
			found := false
			for _, sub := range cmd.Subcommands {
				if sub.Name == part {
					cmd = sub
					found = true
					break
				}
			}
			if !found {
				return nil
			}
		}
	}
	var subcmds []string
	for _, sub := range cmd.Subcommands {
		subcmds = append(subcmds, sub.Name)
	}
	return subcmds
}

func init() {
	rootCommand.Subcommands = append(rootCommand.Subcommands, completionCommand)
}
