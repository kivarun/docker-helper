package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
)

var adminTokenCommand = &Command{
	Name:    "admin-token",
	Summary: "Manage the admin token",
	Subcommands: []*Command{
		adminTokenRotateCommand,
	},
}

var adminTokenRotateCommand = &Command{
	Name:       "rotate",
	Summary:    "Rotate the admin token",
	Usage:      "docker-helper admin-token rotate [--system] [--endpoint ENDPOINT] [--token-file PATH] [--json]",
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

				result, err := client.rotateAdminToken()
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

				// Print the new token to stdout (only place it appears).
				fmt.Fprintln(stdout, result.Token)
				return 0
			},
		}
	},
}
