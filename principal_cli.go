package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"

	"golang.org/x/term"
)

var principalCommand = &Command{
	Name:    "principal",
	Summary: "Manage principals",
	Subcommands: []*Command{
		principalCreateCommand,
		principalListCommand,
		principalShowCommand,
		principalSetCommand,
		principalDeleteCommand,
		principalAllowedRootCommand,
		principalCredentialCommand,
	},
}

var principalCreateCommand = &Command{
	Name:       "create",
	Summary:    "Create a new principal",
	Usage:      "docker-helper principal create [--system] [--endpoint ENDPOINT] [--token-file PATH] [--issue-credential | --no-credential] USER",
	MinPosArgs: 1,
	MaxPosArgs: 1,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		system, endpoint, tokenFile := registerOperatorFlags(fs)
		issueCredential := fs.Bool("issue-credential", false, "Issue an initial principal credential")
		noCredential := fs.Bool("no-credential", false, "Do not issue an initial principal credential")
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				args := fs.Args()
				username := args[0]

				issue, err := resolveIssueCredential(*issueCredential, *noCredential,
					"Create principal credential now? [Y/n]", os.Stdin, stderr, term.IsTerminal(int(os.Stdin.Fd())))
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 2
				}

				client, err := resolveOperatorClient(operatorClientOptions{
					System:    *system,
					Endpoint:  *endpoint,
					TokenFile: *tokenFile,
				})
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				result, err := client.createPrincipal(username, issue)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				if err := encodeJSONOut(stdout, result); err != nil {
					fmt.Fprintf(stderr, "error: cannot encode output: %v\n", err)
					return 1
				}
				if result.Token != "" {
					printCredentialInstallHint(stderr, "principal")
				}
				return 0
			},
		}
	},
}

var principalShowCommand = &Command{
	Name:       "show",
	Summary:    "Show principal details",
	Usage:      "docker-helper principal show [--system] [--endpoint ENDPOINT] [--token-file PATH] USER [FIELD]",
	MinPosArgs: 1,
	MaxPosArgs: 2,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		system, endpoint, tokenFile := registerOperatorFlags(fs)
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				args := fs.Args()
				username := args[0]

				client, err := resolveOperatorClient(operatorClientOptions{
					System:    *system,
					Endpoint:  *endpoint,
					TokenFile: *tokenFile,
				})
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				result, err := client.showPrincipal(username)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				if len(args) == 2 {
					field := args[1]
					val, ok := extractPrincipalField(result, field)
					if !ok {
						fmt.Fprintf(stderr, "error: unknown field %q\n", field)
						return 1
					}
					fmt.Fprintln(stdout, val)
					return 0
				}

				enc := json.NewEncoder(stdout)
				enc.SetIndent("", "  ")
				if err := enc.Encode(result); err != nil {
					fmt.Fprintf(stderr, "error: cannot encode output: %v\n", err)
					return 1
				}
				return 0
			},
		}
	},
}

var principalListCommand = &Command{
	Name:       "list",
	Summary:    "List all principals",
	Usage:      "docker-helper principal list [--system] [--endpoint ENDPOINT] [--token-file PATH] [--json]",
	MinPosArgs: 0,
	MaxPosArgs: 0,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		system, endpoint, tokenFile := registerOperatorFlags(fs)
		jsonOut := fs.Bool("json", false, "Output in JSON format")
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				client, err := resolveOperatorClient(operatorClientOptions{
					System:    *system,
					Endpoint:  *endpoint,
					TokenFile: *tokenFile,
				})
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				result, err := client.listPrincipals()
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				if *jsonOut {
					enc := json.NewEncoder(stdout)
					enc.SetIndent("", "  ")
					if err := enc.Encode(result); err != nil {
						fmt.Fprintf(stderr, "error: cannot encode JSON: %v\n", err)
						return 1
					}
					return 0
				}

				// Print as a table
				fmt.Fprintf(stdout, "%-20s %8s %8s %-30s %s\n", "USER", "UID", "GID", "HOME", "ENABLED")
				for _, p := range result.Principals {
					enabled := "no"
					if p.Enabled {
						enabled = "yes"
					}
					fmt.Fprintf(stdout, "%-20s %8d %8d %-30s %s\n", p.Username, p.UID, p.GID, p.Home, enabled)
				}
				return 0
			},
		}
	},
}

// principalField is one readable FIELD of `principal show USER FIELD`. The
// slice below is the single canonical owner of the FIELD vocabulary:
// `principal show` extraction and completion generation both derive from it,
// so the offered completion can never drift from the fields the command
// actually accepts. Field order is the canonical completion order.
type principalField struct {
	name    string
	extract func(*principalResponse) (string, bool)
}

var principalFields = []principalField{
	{name: "username", extract: func(p *principalResponse) (string, bool) { return p.Username, true }},
	{name: "uid", extract: func(p *principalResponse) (string, bool) { return strconv.Itoa(p.UID), true }},
	{name: "gid", extract: func(p *principalResponse) (string, bool) { return strconv.Itoa(p.GID), true }},
	{name: "home", extract: func(p *principalResponse) (string, bool) { return p.Home, true }},
	{name: "enabled", extract: func(p *principalResponse) (string, bool) { return strconv.FormatBool(p.Enabled), true }},
	{
		name: "allowed_roots",
		extract: func(p *principalResponse) (string, bool) {
			data, err := json.Marshal(p.AllowedRoots)
			if err != nil {
				return "", false
			}
			return string(data), true
		},
	},
	{
		name: "allowed_root_entries",
		extract: func(p *principalResponse) (string, bool) {
			data, err := json.Marshal(p.AllowedRootEntries)
			if err != nil {
				return "", false
			}
			return string(data), true
		},
	},
}

// principalShowFieldNames returns the canonical FIELD vocabulary in
// canonical order (the completion generation reads the same owner).
func principalShowFieldNames() []string {
	names := make([]string, 0, len(principalFields))
	for _, f := range principalFields {
		names = append(names, f.name)
	}
	return names
}

func extractPrincipalField(p *principalResponse, field string) (string, bool) {
	for _, f := range principalFields {
		if f.name == field {
			return f.extract(p)
		}
	}
	return "", false
}

var principalSetCommand = &Command{
	Name:       "set",
	Summary:    "Modify principal settings",
	Usage:      "docker-helper principal set [--system] [--endpoint ENDPOINT] [--token-file PATH] USER FIELD VALUE",
	MinPosArgs: 3,
	MaxPosArgs: 3,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		system, endpoint, tokenFile := registerOperatorFlags(fs)
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				args := fs.Args()
				username := args[0]
				field := args[1]
				value := args[2]

				if field != "enabled" {
					fmt.Fprintf(stderr, "error: unsupported field %q\n", field)
					return 1
				}

				var enabled bool
				switch value {
				case "true":
					enabled = true
				case "false":
					enabled = false
				default:
					fmt.Fprintf(stderr, "error: invalid value %q for enabled; must be true or false\n", value)
					return 1
				}

				client, err := resolveOperatorClient(operatorClientOptions{
					System:    *system,
					Endpoint:  *endpoint,
					TokenFile: *tokenFile,
				})
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				result, err := client.setPrincipalEnabled(username, enabled)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				fmt.Fprintf(stdout, "%s %s = %v\n", username, field, enabled)
				if result.Message == "unchanged" {
					fmt.Fprintln(stdout, "(unchanged)")
				}
				return 0
			},
		}
	},
}

var principalDeleteCommand = &Command{
	Name:       "delete",
	Summary:    "Delete a principal",
	Usage:      "docker-helper principal delete [--system] [--endpoint ENDPOINT] [--token-file PATH] USER",
	MinPosArgs: 1,
	MaxPosArgs: 1,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		system, endpoint, tokenFile := registerOperatorFlags(fs)
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				args := fs.Args()
				username := args[0]

				client, err := resolveOperatorClient(operatorClientOptions{
					System:    *system,
					Endpoint:  *endpoint,
					TokenFile: *tokenFile,
				})
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				if err := client.deletePrincipal(username); err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				fmt.Fprintf(stdout, "deleted principal %s\n", username)
				return 0
			},
		}
	},
}

var principalAllowedRootCommand = &Command{
	Name:    "allowed-root",
	Summary: "Manage principal allowed roots",
	Subcommands: []*Command{
		principalAllowedRootAddCommand,
		principalAllowedRootListCommand,
		principalAllowedRootSetAccessCommand,
		principalAllowedRootRemoveCommand,
	},
}

var principalAllowedRootListCommand = &Command{
	Name:       "list",
	Summary:    "List a principal's allowed roots",
	Usage:      "docker-helper principal allowed-root list [--system] [--endpoint ENDPOINT] [--token-file PATH] USER",
	MinPosArgs: 1,
	MaxPosArgs: 1,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		system, endpoint, tokenFile := registerOperatorFlags(fs)
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				username := fs.Args()[0]

				client, err := resolveOperatorClient(operatorClientOptions{
					System:    *system,
					Endpoint:  *endpoint,
					TokenFile: *tokenFile,
				})
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				result, err := client.showPrincipal(username)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				printAllowedRootAccessTable(stdout, result.AllowedRootEntries)
				return 0
			},
		}
	},
}

var principalAllowedRootAddCommand = &Command{
	Name:       "add",
	Summary:    "Add an allowed root for a principal",
	Usage:      "docker-helper principal allowed-root add [--system] [--endpoint ENDPOINT] [--token-file PATH] [--access ACCESS] USER PATH",
	MinPosArgs: 2,
	MaxPosArgs: 2,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		system, endpoint, tokenFile := registerOperatorFlags(fs)
		access := &accessFlag{}
		fs.Var(access, "access", "Access mode: read_write (default) or read_only")
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				args := fs.Args()
				username := args[0]
				path := args[1]

				client, err := resolveOperatorClient(operatorClientOptions{
					System:    *system,
					Endpoint:  *endpoint,
					TokenFile: *tokenFile,
				})
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				result, err := client.addPrincipalAllowedRoot(username, path, optionalAccessFromFlag(access))
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				fmt.Fprintf(stdout, "added %q to %s\n", path, username)
				if result.Message == "unchanged" {
					fmt.Fprintf(stdout, "(already present with access %s)\n", result.Access)
				}
				return 0
			},
		}
	},
}

// principalAllowedRootSetAccessCommand changes the access mode of exactly one
// stored root: USER PATH ACCESS. The daemon performs the conditional
// mutation, so the CLI never reads and re-sends the root list.
var principalAllowedRootSetAccessCommand = &Command{
	Name:       "set-access",
	Summary:    "Change the access mode of a principal allowed root",
	Usage:      "docker-helper principal allowed-root set-access [--system] [--endpoint ENDPOINT] [--token-file PATH] USER PATH read_only|read_write",
	MinPosArgs: 3,
	MaxPosArgs: 3,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		system, endpoint, tokenFile := registerOperatorFlags(fs)
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				args := fs.Args()
				username := args[0]
				path := args[1]

				access, err := parseAllowedRootAccess(args[2])
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 2
				}

				client, err := resolveOperatorClient(operatorClientOptions{
					System:    *system,
					Endpoint:  *endpoint,
					TokenFile: *tokenFile,
				})
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				result, err := client.setPrincipalAllowedRootAccess(username, path, access)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				fmt.Fprintf(stdout, "access of %q on %s is %s\n", result.Path, username, result.Access)
				if result.Message == "unchanged" {
					fmt.Fprintln(stdout, "(unchanged)")
				}
				return 0
			},
		}
	},
}

var principalAllowedRootRemoveCommand = &Command{
	Name:       "remove",
	Summary:    "Remove an allowed root for a principal",
	Usage:      "docker-helper principal allowed-root remove [--system] [--endpoint ENDPOINT] [--token-file PATH] USER PATH",
	MinPosArgs: 2,
	MaxPosArgs: 2,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		system, endpoint, tokenFile := registerOperatorFlags(fs)
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				args := fs.Args()
				username := args[0]
				path := args[1]

				client, err := resolveOperatorClient(operatorClientOptions{
					System:    *system,
					Endpoint:  *endpoint,
					TokenFile: *tokenFile,
				})
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				result, err := client.removePrincipalAllowedRoot(username, path)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				fmt.Fprintf(stdout, "removed %q from %s\n", path, username)
				if result.Message == "unchanged" {
					fmt.Fprintln(stdout, "(was not present)")
				}
				return 0
			},
		}
	},
}
