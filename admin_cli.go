package main

import (
	"flag"
	"fmt"
	"io"
)

var adminCommand = &Command{
	Name:    "admin",
	Summary: "Administrative operations",
	Subcommands: []*Command{
		adminTokenCommand,
	},
}

var adminTokenCommand = &Command{
	Name:    "token",
	Summary: "Manage the admin token",
	Subcommands: []*Command{
		adminTokenRotateCommand,
	},
}

var adminTokenRotateCommand = &Command{
	Name:       "rotate",
	Summary:    "Rotate the admin token",
	Usage:      "docker-helper admin token rotate [--system] [--endpoint ENDPOINT] [--token-file PATH]",
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
				})
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				result, err := client.rotateAdminToken()
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				// Print the new token to stdout (only place it appears).
				fmt.Fprintln(stdout, result.Token)
				return 0
			},
		}
	},
}
