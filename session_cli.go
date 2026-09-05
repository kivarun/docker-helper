package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
)

// resolveSessionCreateSelectors maps the session-create --principal/--launcher
// selectors onto the daemon's mutually exclusive create selectors for the
// authenticated authority. Authorities with Launcher control-plane access
// resolve name-shaped selectors to the global ID through the daemon's
// scope-first launcher list query (an admin only under an explicitly named
// Principal, a Principal credential within its own scope), so a name only
// ever resolves within the caller's visible scope and a foreign or missing
// Launcher is the daemon's non-disclosing not-found. A Launcher credential has
// no Launcher control-plane authority: its ID-shaped selector is forwarded
// as-is and the daemon's create admission stays the authority (own -> self,
// foreign -> non-disclosing launcher-not-found), and a name-shaped selector is
// rejected locally because no resolvable representation exists. The daemon
// remains the selector-resolution and authorization authority.
func resolveSessionCreateSelectors(client *apiClient, principal, launcher string, req *createSessionClientRequest) error {
	auth, err := client.auth()
	if err != nil {
		return err
	}
	switch auth.Authority {
	case "admin":
		switch {
		case launcher != "" && principal != "":
			id, err := resolveLauncherIDBySelector(client, principal, launcher)
			if err != nil {
				return err
			}
			req.LauncherID = id
		case launcher != "":
			if isLauncherIDSelector(launcher) {
				req.LauncherID = launcher
				return nil
			}
			return errors.New("admin authentication requires --principal USER when --launcher is a Launcher name; use the Launcher's dhl_ ID to target it globally")
		default:
			req.Principal = principal
		}
	case "principal":
		if principal != "" {
			return errors.New("--principal is only valid with admin authentication")
		}
		if launcher != "" {
			id, err := resolveLauncherIDBySelector(client, "", launcher)
			if err != nil {
				return err
			}
			req.LauncherID = id
		}
	case "launcher":
		if principal != "" {
			return errors.New("--principal is only valid with admin authentication")
		}
		if launcher != "" {
			// A Launcher credential has no Launcher control-plane authority,
			// so a selector must not be resolved through the launcher list.
			// The ID-shaped selector is forwarded as-is and the daemon's
			// create admission stays the authority (own -> self, foreign ->
			// non-disclosing launcher-not-found); a name has no resolvable
			// representation for this authority and is rejected locally.
			if isLauncherIDSelector(launcher) {
				req.LauncherID = launcher
				return nil
			}
			return errors.New("Launcher authentication requires the Launcher's dhl_ ID for --launcher; Launcher names cannot be resolved without Launcher control-plane authority (GET /auth reports your Launcher's dhl_ ID)")
		}
	default:
		return fmt.Errorf("unknown authority %q", auth.Authority)
	}
	return nil
}

// resolveLauncherIDBySelector resolves one Launcher selector to its global ID
// through the daemon's scope-first launcher list query. The same rule backs
// the individual-Launcher admin selector: the query never searches Launcher
// names globally, and fewer than one visible match is the non-disclosing
// launcher-not-found.
func resolveLauncherIDBySelector(client *apiClient, principal, launcher string) (string, error) {
	result, err := client.listLaunchersFiltered(principal, launcher)
	if err != nil {
		return "", err
	}
	if len(result.Launchers) != 1 {
		return "", ErrLauncherNotFound
	}
	return result.Launchers[0].ID, nil
}

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
	Usage:   "docker-helper session create [--system] [--endpoint ENDPOINT] [--token-file PATH] --workspace PATH [--principal USER] [--launcher LAUNCHER] [--json]",
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		system, endpoint, tokenFile := registerOperatorFlags(fs)
		workspace := fs.String("workspace", "", "Workspace directory")
		principal := &launcherNameFlag{}
		fs.Var(principal, "principal", "Principal username (admin authentication; targets the Principal's default Launcher)")
		launcher := &launcherNameFlag{}
		fs.Var(launcher, "launcher", "Launcher name or ID (dhl_...) to target instead of the default Launcher")
		jsonOut := fs.Bool("json", false, "Output in JSON format")

		return Invocation{
			Validate: func() error {
				if *workspace == "" || strings.HasPrefix(*workspace, "-") {
					return fmt.Errorf("--workspace is required")
				}
				if principal.set && principal.value == "" {
					return fmt.Errorf("--principal value must not be empty")
				}
				if launcher.set && launcher.value == "" {
					return fmt.Errorf("--launcher value must not be empty")
				}
				return nil
			},
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

				absWorkspace, err := filepath.Abs(*workspace)
				if err != nil {
					fmt.Fprintf(stderr, "error: cannot resolve workspace path: %v\n", err)
					return 1
				}

				req := createSessionClientRequest{Workspace: absWorkspace}
				if launcher.set || principal.set {
					if err := resolveSessionCreateSelectors(client, principal.value, launcher.value, &req); err != nil {
						fmt.Fprintf(stderr, "error: %v\n", err)
						return 1
					}
				}

				result, err := client.createSession(req)
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
	Usage:   "docker-helper session list [--system] [--endpoint ENDPOINT] [--token-file PATH] [--json]",
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
	Usage:   "docker-helper session delete [--system] [--endpoint ENDPOINT] [--token-file PATH] --id SESSION_ID [--json]",
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		system, endpoint, tokenFile := registerOperatorFlags(fs)
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
				client, err := resolveOperatorClient(operatorClientOptions{
					System:    *system,
					Endpoint:  *endpoint,
					TokenFile: *tokenFile,
				})
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}

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

	fmt.Fprintln(tw, "ID\tPRINCIPAL\tLAUNCHER\tWORKSPACE\tCREATED\tEXPIRES")

	for _, s := range sessions {
		principal := "-"
		if s.Principal != nil {
			principal = *s.Principal
		}
		launcher := "-"
		if s.Launcher != nil {
			launcher = *s.Launcher
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			s.ID, principal, launcher, s.Workspace, s.CreatedAt, s.ExpiresAt)
	}

	tw.Flush()
}

var sessionCleanupCommand = &Command{
	Name:    "cleanup",
	Summary: "Remove expired sessions from the database",
	Usage:   "docker-helper session cleanup",
	Help: `Remove expired sessions from the local state database.

This is an OFFLINE maintenance command. The daemon must not be running.
The command fails if another docker-helper instance holds the daemon lock.

Only sessions whose expires_at has passed are removed.
Active sessions are untouched.

This operates directly on the local SQLite database. No API connection is
needed. No admin or session token is required.

Stale session runtime directories are also cleaned up. These directories
may contain session-scoped Docker registry credentials.

Daemon startup already removes expired sessions automatically.`,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				return runSessionCleanup(stdout, stderr)
			},
		}
	},
}

func runSessionCleanup(stdout, stderr io.Writer) int {
	// Resolve runtime directory before any database mutation.
	runtimeDir := getRuntimeDirSafe()
	if runtimeDir == "" {
		fmt.Fprintf(stderr, "error: cannot determine runtime directory\n")
		return 1
	}

	// Ensure runtime directory exists with mode-appropriate permissions.
	dirMode := os.FileMode(0700)
	if resolveDeploymentMode() == ModeSystem {
		dirMode = 0755
	}
	if err := os.MkdirAll(runtimeDir, dirMode); err != nil {
		fmt.Fprintf(stderr, "error: cannot create runtime directory: %v\n", err)
		return 1
	}

	// Acquire the same daemon instance lock used by serve.
	// If the daemon owns the lock, fail cleanly without mutating anything.
	lockPath := filepath.Join(runtimeDir, "docker-helper.sock.lock")
	lockFile, err := acquireDaemonInstanceLock(lockPath)
	if err != nil {
		fmt.Fprintf(stderr, "error: another docker-helper instance is already running; session cleanup must be offline\n")
		return 1
	}
	defer lockFile.Close()

	// Lock acquired: safe to open the database and clean up.
	dbPath := filepath.Join(getStateDirFunc(), "docker-helper.db")

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

	if err := cleanupStaleSessionRuntimeDirs(db, runtimeDir); err != nil {
		fmt.Fprintf(stdout, "removed %d expired sessions\n", n)
		fmt.Fprintf(stderr, "error: failed to clean stale runtime dirs: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "removed %d expired sessions\n", n)
	return 0
}
