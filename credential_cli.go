package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"golang.org/x/term"
)

// principalCredentialCommand is the canonical ownership-based credential tree
// for named Principal credentials (0..N per Principal): create, list, revoke,
// rotate. The top-level `credential` command keeps `install` as the canonical
// local install command and mirrors create/list/revoke as Release 2.0
// compatibility aliases that share these implementations.
var principalCredentialCommand = &Command{
	Name:    "credential",
	Summary: "Manage principal credentials",
	Subcommands: []*Command{
		principalCredentialCreateCommand,
		principalCredentialListCommand,
		principalCredentialRevokeCommand,
		principalCredentialRotateCommand,
	},
}

var principalCredentialCreateCommand = &Command{
	Name:       "create",
	Summary:    "Create a new credential for a principal",
	Usage:      "docker-helper principal credential create [--system] [--endpoint ENDPOINT] [--token-file PATH] [--name NAME] USER",
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

// principalCredentialListCommand lists a Principal's named credentials. The
// Principal selector is optional: a Principal-credential caller's own
// Principal is inferred from the authenticated credential, while an explicit
// selector is only available to callers with broader visibility (admin).
var principalCredentialListCommand = &Command{
	Name:       "list",
	Summary:    "List a principal's credentials",
	Usage:      "docker-helper principal credential list [--system] [--endpoint ENDPOINT] [--token-file PATH] [PRINCIPAL]",
	MinPosArgs: 0,
	MaxPosArgs: 1,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		system, endpoint, tokenFile := registerOperatorFlags(fs)
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				args := fs.Args()
				explicit := ""
				if len(args) > 0 {
					explicit = args[0]
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

				username, err := resolvePrincipalTargetForCLI(client, explicit)
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

				tw := tabwriter.NewWriter(stdout, 0, 0, 1, ' ', 0)
				fmt.Fprintln(tw, "ID\tNAME\tCREATED\tREVOKED")
				for _, c := range result.Credentials {
					revoked := "-"
					if c.RevokedAt != nil {
						revoked = *c.RevokedAt
					}
					fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n",
						c.ID, c.Name, c.CreatedAt, revoked)
				}
				tw.Flush()
				return 0
			},
		}
	},
}

var principalCredentialRevokeCommand = &Command{
	Name:       "revoke",
	Summary:    "Revoke a principal credential",
	Usage:      "docker-helper principal credential revoke [--system] [--endpoint ENDPOINT] [--token-file PATH] CREDENTIAL_ID",
	MinPosArgs: 1,
	MaxPosArgs: 1,
	Help: `Revoke a principal credential by its credential ID.

CREDENTIAL_ID is the credential's unique identifier, prefixed with "dhcr_".
It is printed by 'docker-helper principal credential create' and can be
listed with:

    docker-helper principal credential list PRINCIPAL

Revoking a credential permanently invalidates its token. The credential
record remains in the database as history, and its name becomes available
for reuse by a new credential.`,
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

var principalCredentialRotateCommand = &Command{
	Name:       "rotate",
	Summary:    "Rotate a principal credential",
	Usage:      "docker-helper principal credential rotate [--system] [--endpoint ENDPOINT] [--token-file PATH] [--name NAME] [PRINCIPAL]",
	MinPosArgs: 0,
	MaxPosArgs: 1,
	Help: `Rotate a principal credential in one atomic server-side operation.

The old bearer token is invalidated immediately and the new one is
returned exactly once on stdout. The credential ID, name, and ownership
are unchanged; the name is reused according to principal credential
semantics.

The credential name defaults to "default"; --name selects another named
credential. The Principal defaults to the owner of the authenticated
Principal credential; an explicit PRINCIPAL is required for admin
authentication.`,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		system, endpoint, tokenFile := registerOperatorFlags(fs)
		name := fs.String("name", "default", "Credential name")

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

				args := fs.Args()
				explicit := ""
				if len(args) > 0 {
					explicit = args[0]
				}
				username, err := resolvePrincipalTargetForCLI(client, explicit)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				result, err := client.rotatePrincipalCredential(username, *name)
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

// credentialCommand is the top-level credential entry point: `install` is the
// canonical local install command, and create/list/revoke are Release 2.0
// compatibility aliases for the canonical principal credential commands. The
// aliases share the canonical implementations (no separate business logic).
var credentialCommand = &Command{
	Name:    "credential",
	Summary: "Install a credential; Release 2.0 principal credential aliases",
	Help: `Local credential install plus Release 2.0 compatibility aliases.

docker-helper credential install is the canonical install command for a
non-admin credential token.

create, list, and revoke are compatibility aliases for the canonical
principal credential commands. New scripts should use:

  docker-helper principal credential create|list|revoke`,
	Subcommands: []*Command{
		{
			Name:          "create",
			Summary:       principalCredentialCreateCommand.Summary,
			Usage:         "docker-helper credential create [--system] [--endpoint ENDPOINT] [--token-file PATH] [--name NAME] USER",
			MinPosArgs:    principalCredentialCreateCommand.MinPosArgs,
			MaxPosArgs:    principalCredentialCreateCommand.MaxPosArgs,
			Help:          "Compatibility alias for docker-helper principal credential create.",
			NewInvocation: principalCredentialCreateCommand.NewInvocation,
		},
		{
			Name:          "list",
			Summary:       principalCredentialListCommand.Summary,
			Usage:         "docker-helper credential list [--system] [--endpoint ENDPOINT] [--token-file PATH] [PRINCIPAL]",
			MinPosArgs:    principalCredentialListCommand.MinPosArgs,
			MaxPosArgs:    principalCredentialListCommand.MaxPosArgs,
			Help:          "Compatibility alias for docker-helper principal credential list.",
			NewInvocation: principalCredentialListCommand.NewInvocation,
		},
		{
			Name:          "revoke",
			Summary:       principalCredentialRevokeCommand.Summary,
			Usage:         "docker-helper credential revoke [--system] [--endpoint ENDPOINT] [--token-file PATH] CREDENTIAL_ID",
			MinPosArgs:    principalCredentialRevokeCommand.MinPosArgs,
			MaxPosArgs:    principalCredentialRevokeCommand.MaxPosArgs,
			Help:          "Compatibility alias for docker-helper principal credential revoke.",
			NewInvocation: principalCredentialRevokeCommand.NewInvocation,
		},
		credentialInstallCommand,
	},
}

var credentialInstallCommand = &Command{
	Name:       "install",
	Summary:    "Install a non-admin credential token",
	Usage:      "docker-helper credential install [--force]",
	MinPosArgs: 0,
	MaxPosArgs: 0,
	Help: `Install a non-admin credential token for docker-helper --system.
The credential may belong to a Principal or a Launcher.
The daemon resolves its owner and authorization scope when the token is used.

Reads the token from stdin (hidden input when connected to a terminal).
Stores the token at:
  ${XDG_CONFIG_HOME:-$HOME/.config}/docker-helper/credential.token

This command must NOT be run as root. The token is installed by the owning
user who received it.

The token is validated for format before storage. It is written atomically
with mode 0600. The directory is created with mode 0700 if it does not exist.

With --force, an existing credential is replaced atomically. An alternative
credential source can be selected per invocation with --token-file PATH on
the operator command.`,
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
						fmt.Fprintln(stderr, "Non-admin credential tokens are installed by the owning user, not by root.")
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
