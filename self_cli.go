package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"text/tabwriter"
)

var selfCommand = &Command{
	Name:    "self",
	Summary: "Introspect the authenticated credential's own identity",
	Usage:   "docker-helper self [--system] [--endpoint ENDPOINT] [--token-file PATH] [--json]",
	Help: `Introspect the authenticated credential's own identity on the daemon.

docker-helper self answers one question: who am I to this daemon? The
daemon classifies the bearer credential itself and answers with the
matching self resource; the CLI performs no local classification and
never resolves your identity from configuration.

  Principal credential -> your Principal: username, uid/gid, home,
                          enabled state, stored allowed-root entries,
                          and effective allowed-root entries.
  Launcher credential  -> your Launcher: id, name, owning principal,
                          enabled state, scope, stored allowed-root
                          entries (empty for inherit scope), and the
                          effective three-level allowed-root entries.
  Session bearer       -> your Session: id, workspace, ownership,
                          creation/expiry, and the persisted immutable
                          filesystem snapshot (same body as
                          'session show --id' of your own session).

The admin token has no self resource and is answered with the stable
404 self_not_available contract. Unknown, revoked, disabled, or
expired credentials receive the non-disclosing authentication
failure. The endpoint is read-only: it grants no authority the
credential does not already have and never mutates state.

--json prints the raw response envelope (ok, type, resource).
`,
	MinPosArgs: 0,
	MaxPosArgs: 0,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		system, endpoint, tokenFile := registerOperatorFlags(fs)
		jsonOut := fs.Bool("json", false, "Output raw JSON response")
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				// Credential resolution for self: the explicit --token-file
				// stays the operator-style bearer path (the same owner as
				// `session show`). Without it, the agent environment's
				// DOCKER_HELPER_SESSION_TOKEN is the session bearer's own
				// credential — the agent-context self introspection path —
				// resolved through the agent client owner (default user-mode
				// socket, --system system socket, or the explicit endpoint).
				// With neither, the operator resolution (system/default
				// endpoint token files) answers.
				var client *apiClient
				if *tokenFile == "" && os.Getenv("DOCKER_HELPER_SESSION_TOKEN") != "" {
					opts := agentClientOptions{System: *system, Endpoint: *endpoint}
					if err := validateAgentEndpointOptions(opts); err != nil {
						fmt.Fprintf(stderr, "error: %v\n", err)
						return 1
					}
					agentClient, cerr := resolveAgentClient(opts)
					if cerr != nil {
						fmt.Fprintf(stderr, "error: %v\n", cerr)
						return 1
					}
					client = agentClient
				} else {
					operatorClient, cerr := resolveOperatorClient(operatorClientOptions{
						System:    *system,
						Endpoint:  *endpoint,
						TokenFile: *tokenFile,
					})
					if cerr != nil {
						fmt.Fprintf(stderr, "error: %v\n", cerr)
						return 1
					}
					client = operatorClient
				}

				// The daemon classifies the bearer and answers with the
				// matching self resource; the CLI performs no client-side
				// ownership check and never recomputes policy.
				result, err := client.self()
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

				printSelf(stdout, result)
				return 0
			},
		}
	},
}

// printSelf renders the compact human self output for the authenticated
// credential class: the identity block, the stored and effective
// allowed-root tables where the class carries them, and — for a Session —
// the persisted immutable filesystem snapshot table in its exact persisted
// canonical ordering.
func printSelf(w io.Writer, result *selfResponse) {
	fmt.Fprintf(w, "TYPE: %s\n", result.Type)
	switch result.Type {
	case string(selfTypePrincipal):
		var r principalSelfResource
		if decodeSelfResource(w, result.Resource, &r) {
			printPrincipalSelf(w, &r)
		}
	case string(selfTypeLauncher):
		var r launcherSelfResource
		if decodeSelfResource(w, result.Resource, &r) {
			printLauncherSelf(w, &r)
		}
	case string(selfTypeSession):
		var r sessionShowJSON
		if decodeSelfResource(w, result.Resource, &r) {
			fmt.Fprintln(w)
			printSessionShow(w, &r)
		}
	}
}

// decodeSelfResource decodes the raw envelope resource into one class shape.
func decodeSelfResource(w io.Writer, raw json.RawMessage, target any) bool {
	if err := json.Unmarshal(raw, target); err != nil {
		fmt.Fprintf(w, "error: cannot decode self resource: %v\n", err)
		return false
	}
	return true
}

// printRootEntriesTable renders one allowed-root entries table.
func printRootEntriesTable(w io.Writer, header string, entries []AllowedRootEntry) {
	fmt.Fprintf(w, "\n%s\n", header)
	tw := tabwriter.NewWriter(w, 0, 0, 1, ' ', 0)
	fmt.Fprintln(tw, "PATH\tACCESS")
	for _, entry := range entries {
		fmt.Fprintf(tw, "%s\t%s\n", entry.Path, entry.Access)
	}
	tw.Flush()
}

func printPrincipalSelf(w io.Writer, r *principalSelfResource) {
	fmt.Fprintf(w, "USERNAME: %s\n", r.Username)
	fmt.Fprintf(w, "UID:      %d\n", r.UID)
	fmt.Fprintf(w, "GID:      %d\n", r.GID)
	fmt.Fprintf(w, "HOME:     %s\n", r.Home)
	fmt.Fprintf(w, "ENABLED:  %t\n", r.Enabled)
	printRootEntriesTable(w, "ALLOWED ROOTS (STORED)", r.AllowedRootEntries)
	printRootEntriesTable(w, "ALLOWED ROOTS (EFFECTIVE)", r.EffectiveAllowedRootEntries)
}

func printLauncherSelf(w io.Writer, r *launcherSelfResource) {
	fmt.Fprintf(w, "ID:        %s\n", r.ID)
	fmt.Fprintf(w, "NAME:      %s\n", r.Name)
	fmt.Fprintf(w, "PRINCIPAL: %s\n", r.Principal)
	fmt.Fprintf(w, "ENABLED:   %t\n", r.Enabled)
	fmt.Fprintf(w, "SCOPE:     %s\n", r.Scope)
	printRootEntriesTable(w, "ALLOWED ROOTS (STORED)", r.AllowedRootEntries)
	printRootEntriesTable(w, "ALLOWED ROOTS (EFFECTIVE)", r.EffectiveAllowedRootEntries)
}
