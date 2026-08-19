package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

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
	},
}

var credentialCommand = &Command{
	Name:    "credential",
	Summary: "Manage principal credentials",
	Subcommands: []*Command{
		credentialCreateCommand,
		credentialListCommand,
		credentialRevokeCommand,
		credentialInstallCommand,
	},
}

var principalCreateCommand = &Command{
	Name:       "create",
	Summary:    "Create a new principal",
	Usage:      "docker-helper principal create [--system] [--endpoint ENDPOINT] [--token-file PATH] USER",
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

				result, err := client.createPrincipal(username)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
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

func extractPrincipalField(p *principalResponse, field string) (string, bool) {
	switch field {
	case "username":
		return p.Username, true
	case "uid":
		return fmt.Sprintf("%d", p.UID), true
	case "gid":
		return fmt.Sprintf("%d", p.GID), true
	case "home":
		return p.Home, true
	case "enabled":
		return fmt.Sprintf("%t", p.Enabled), true
	case "allowed_roots":
		data, err := json.Marshal(p.AllowedRoots)
		if err != nil {
			return "", false
		}
		return string(data), true
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
		principalAllowedRootRemoveCommand,
	},
}

var principalAllowedRootAddCommand = &Command{
	Name:       "add",
	Summary:    "Add an allowed root for a principal",
	Usage:      "docker-helper principal allowed-root add [--system] [--endpoint ENDPOINT] [--token-file PATH] USER PATH",
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

				result, err := client.addPrincipalAllowedRoot(username, path)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				fmt.Fprintf(stdout, "added %q to %s\n", path, username)
				if result.Message == "unchanged" {
					fmt.Fprintln(stdout, "(already present)")
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

var credentialCreateCommand = &Command{
	Name:       "create",
	Summary:    "Create a new credential for a principal",
	Usage:      "docker-helper credential create [--system] [--endpoint ENDPOINT] [--token-file PATH] --name NAME USER",
	MinPosArgs: 1,
	MaxPosArgs: 1,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		system, endpoint, tokenFile := registerOperatorFlags(fs)
		name := fs.String("name", "", "Credential name")

		return Invocation{
			Validate: func() error {
				if *name == "" {
					return fmt.Errorf("--name is required")
				}
				return nil
			},
			Run: func(stdout, stderr io.Writer) int {
				args := fs.Args()
				if len(args) == 0 || args[0] == "" {
					fmt.Fprintf(stderr, "error: principal username is required\n")
					return 1
				}
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

				result, err := client.createPrincipalCredential(username, *name)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				fmt.Fprintf(stdout, "Credential created for %s\n", username)
				fmt.Fprintf(stdout, "  ID:    %s\n", result.Credential.ID)
				fmt.Fprintf(stdout, "  Name:  %s\n", result.Credential.Name)
				fmt.Fprintf(stdout, "  Token: %s\n", result.Token)
				fmt.Fprintln(stdout, "")
				fmt.Fprintln(stdout, "IMPORTANT: Save the token now. It will not be shown again.")
				fmt.Fprintln(stdout, "")
				fmt.Fprintln(stdout, "Give this token securely to the principal.")
				fmt.Fprintln(stdout, "The principal installs it with:")
				fmt.Fprintln(stdout, "  docker-helper credential install")
				return 0
			},
		}
	},
}

var credentialListCommand = &Command{
	Name:       "list",
	Summary:    "List credentials for a principal",
	Usage:      "docker-helper credential list [--system] [--endpoint ENDPOINT] [--token-file PATH] USER",
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

				result, err := client.listPrincipalCredentials(username)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				if len(result.Credentials) == 0 {
					fmt.Fprintln(stdout, "No credentials for", username)
					return 0
				}

				for _, c := range result.Credentials {
					revoked := "no"
					if c.RevokedAt != nil {
						revoked = *c.RevokedAt
					}
					fmt.Fprintf(stdout, "  %-16s %-12s created=%s revoked=%s\n", c.ID, c.Name, c.CreatedAt, revoked)
				}
				return 0
			},
		}
	},
}

var credentialRevokeCommand = &Command{
	Name:       "revoke",
	Summary:    "Revoke a credential",
	Usage:      "docker-helper credential revoke [--system] [--endpoint ENDPOINT] [--token-file PATH] CREDENTIAL_ID",
	MinPosArgs: 1,
	MaxPosArgs: 1,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		system, endpoint, tokenFile := registerOperatorFlags(fs)
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				args := fs.Args()
				id := args[0]

				client, err := resolveOperatorClient(operatorClientOptions{
					System:    *system,
					Endpoint:  *endpoint,
					TokenFile: *tokenFile,
				})
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				result, err := client.revokeCredential(id)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				fmt.Fprintf(stdout, "revoked %s\n", id)
				if result.Message == "unchanged" {
					fmt.Fprintln(stdout, "(was already revoked)")
				}
				return 0
			},
		}
	},
}

var credentialInstallCommand = &Command{
	Name:       "install",
	Summary:    "Install a principal credential token",
	Usage:      "docker-helper credential install [--force]",
	MinPosArgs: 0,
	MaxPosArgs: 0,
	Help: `Install a credential token for use with docker-helper --system.

Reads the token from stdin (hidden input when connected to a terminal).
Stores the token at:
  ${XDG_CONFIG_HOME:-$HOME/.config}/docker-helper/credential.token

This command must NOT be run as root. It is intended for principal users
who received a token from the operator.

The token is validated for format before storage. It is written atomically
with mode 0600. The directory is created with mode 0700 if it does not exist.

With --force, an existing credential is replaced atomically.`,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		force := fs.Bool("force", false, "Replace existing credential")

		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				credPath, err := installCredential(credentialInstallConfig{
					reader:     os.Stdin,
					writer:     safeWriteCredential,
					uid:        EffectiveUID,
					isTerminal: func() bool { return term.IsTerminal(int(os.Stdin.Fd())) },
					readPassword: func() (string, error) {
						return readTokenHidden("Credential token: ", stderr)
					},
					force: *force,
				})
				if err != nil {
					if errors.Is(err, ErrCredentialInstallAsRoot) {
						fmt.Fprintln(stderr, "error: credential install must not be run as root")
						fmt.Fprintln(stderr, "This command is for principal users, not the operator.")
						return 1
					}
					if errors.Is(err, ErrCredentialAlreadyExists) {
						fmt.Fprintf(stderr, "error: credential already installed\n")
						fmt.Fprintln(stderr, "Use --force to replace it.")
						return 1
					}
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				fmt.Fprintf(stdout, "installed credential at %s\n", credPath)
				return 0
			},
		}
	},
}
