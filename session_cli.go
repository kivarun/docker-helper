package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"text/tabwriter"
)

var sessionCommand = &Command{
	Name:    "session",
	Summary: "Manage sessions",
	Subcommands: []*Command{
		sessionCreateCommand,
		sessionListCommand,
		sessionDeleteCommand,
		sessionCleanupCommand,
	},
}

var sessionCreateCommand = &Command{
	Name:    "create",
	Summary: "Create a new session",
	Usage:   "docker-helper session create --workspace PATH [--json]",
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		workspace := fs.String("workspace", "", "Workspace directory")
		jsonOut := fs.Bool("json", false, "Output in JSON format")

		return Invocation{
			Validate: func() error {
				if *workspace == "" || strings.HasPrefix(*workspace, "-") {
					return fmt.Errorf("--workspace is required")
				}
				return nil
			},
			Run: func(stdout, stderr io.Writer) int {
				socketPath, adminTokenPath, err := adminAPIPaths()
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				tokenSource, err := adminAPITokenSource(adminTokenPath)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				client := newUnixAPIClient(socketPath, tokenSource, nil)

				result, err := client.createSession(*workspace)
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

				var buf strings.Builder
				fmt.Fprintf(&buf, "ID:        %s\n", result.Session.ID)
				fmt.Fprintf(&buf, "TOKEN:     %s\n", result.Token)
				fmt.Fprintf(&buf, "WORKSPACE: %s\n", result.Session.Workspace)
				fmt.Fprintf(&buf, "CREATED:   %s\n", result.Session.CreatedAt)
				fmt.Fprintf(&buf, "EXPIRES:   %s\n", result.Session.ExpiresAt)

				if _, err := stdout.Write([]byte(buf.String())); err != nil {
					fmt.Fprintln(stderr, "error: cannot write output")
					return 1
				}

				return 0
			},
		}
	},
}

var sessionListCommand = &Command{
	Name:    "list",
	Summary: "List active sessions",
	Usage:   "docker-helper session list [--json]",
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		jsonOut := fs.Bool("json", false, "Output in JSON format")

		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				socketPath, adminTokenPath, err := adminAPIPaths()
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				tokenSource, err := adminAPITokenSource(adminTokenPath)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				client := newUnixAPIClient(socketPath, tokenSource, nil)

				result, err := client.listSessions()
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

				printSessionsTable(stdout, result.Sessions)
				return 0
			},
		}
	},
}

var sessionDeleteCommand = &Command{
	Name:    "delete",
	Summary: "Delete a session",
	Usage:   "docker-helper session delete --id SESSION_ID [--json]",
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		id := fs.String("id", "", "Session ID to delete")
		jsonOut := fs.Bool("json", false, "Output in JSON format")

		return Invocation{
			Validate: func() error {
				if *id == "" || strings.HasPrefix(*id, "-") {
					return fmt.Errorf("--id is required")
				}
				return nil
			},
			Run: func(stdout, stderr io.Writer) int {
				socketPath, adminTokenPath, err := adminAPIPaths()
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				tokenSource, err := adminAPITokenSource(adminTokenPath)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				client := newUnixAPIClient(socketPath, tokenSource, nil)

				if err := client.deleteSession(*id); err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

				if *jsonOut {
					enc := json.NewEncoder(stdout)
					enc.SetIndent("", "  ")
					if err := enc.Encode(map[string]any{"ok": true, "id": *id, "deleted": true}); err != nil {
						fmt.Fprintf(stderr, "error: cannot encode JSON: %v\n", err)
						return 1
					}
					return 0
				}

				var buf strings.Builder
				fmt.Fprintf(&buf, "ID: %s\n", *id)
				fmt.Fprintf(&buf, "DELETED: true\n")

				if _, err := stdout.Write([]byte(buf.String())); err != nil {
					fmt.Fprintln(stderr, "error: cannot write output")
					return 1
				}

				return 0
			},
		}
	},
}

func printSessionsTable(w io.Writer, sessions []sessionJSON) {
	tw := tabwriter.NewWriter(w, 0, 0, 1, ' ', 0)

	fmt.Fprintln(tw, "ID\tWORKSPACE\tCREATED\tEXPIRES")

	for _, s := range sessions {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n",
			s.ID, s.Workspace, s.CreatedAt, s.ExpiresAt)
	}

	tw.Flush()
}

var sessionCleanupCommand = &Command{
	Name:    "cleanup",
	Summary: "Remove expired sessions from the database",
	Usage:   "docker-helper session cleanup",
	Help: `Remove expired sessions from the local state database.

Only sessions whose expires_at has passed are removed.
Active sessions are untouched.

This operates directly on the local SQLite database; no running
daemon or API connection is required. No admin or session token is needed.

Expired sessions are already rejected for authentication and excluded
from session lists by their expires_at value. This command is useful
for explicitly reclaiming storage during long daemon uptimes.

The daemon also removes expired sessions automatically at startup.`,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				return runSessionCleanup(stdout, stderr)
			},
		}
	},
}

func runSessionCleanup(stdout, stderr io.Writer) int {
	dbPath := filepath.Join(getStateDir(), "docker-helper.db")

	db, err := openDatabase(dbPath)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	defer db.Close()

	n, err := cleanupExpiredSessions(db)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "removed %d expired sessions\n", n)
	return 0
}
