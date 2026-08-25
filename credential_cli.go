package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"golang.org/x/term"
)

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

var credentialCreateCommand = &Command{
	Name:       "create",
	Summary:    "Create a new credential for a principal",
	Usage:      "docker-helper credential create [--system] [--endpoint ENDPOINT] [--token-file PATH] [--name NAME] USER",
	MinPosArgs: 1,
	MaxPosArgs: 1,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		system, endpoint, tokenFile := registerOperatorFlags(fs)
		name := fs.String("name", "default", "Credential name")

		return Invocation{
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
