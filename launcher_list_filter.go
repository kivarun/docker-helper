package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"
)

// handleListLaunchersQuery is the production GET /launchers dispatcher. The
// established scope-first list remains unchanged when no Launcher selector is
// supplied. A ?launcher= selector adds one more narrowing predicate:
//
//   - inside a resolved Principal scope, Launcher name or ID is accepted;
//   - for an unfiltered admin scope, only a globally-unique Launcher ID is
//     accepted (Launcher names are Principal-scoped and are never searched
//     globally).
//
// The daemon remains the authorization and filtering authority. The CLI never
// downloads a broader collection and filters it locally.
func (a *App) handleListLaunchersQuery(w http.ResponseWriter, r *http.Request) {
	launcherFilter := r.URL.Query().Get("launcher")
	if launcherFilter == "" {
		a.handleListLaunchersForAuthority(w, r)
		return
	}

	auth, err := a.authenticateControlRequest(w, r, "launcher")
	if err != nil || auth == nil {
		return
	}
	a.serveLauncherFilteredList(w, r, auth, r.URL.Query().Get("principal"), launcherFilter)
}

func (a *App) serveLauncherFilteredList(w http.ResponseWriter, r *http.Request, auth *controlAuthority, principalFilter, launcherFilter string) {
	started := time.Now()
	ctx := r.Context()

	scope, ok := a.resolveListScope(w, r, auth, principalFilter)
	if !ok {
		return
	}

	var (
		launcher      *LauncherWithPrincipal
		err           error
		principalName string
	)

	if scope.allPrincipals {
		// Only an admin can have an all-Principals scope. Launcher names are
		// unique only under one Principal, so a global name query is
		// intentionally rejected instead of scanning names across Principals.
		if !isLauncherIDSelector(launcherFilter) {
			duration := time.Since(started).Round(time.Millisecond).String()
			writeLauncherControlAudit(ctx, auditRecord{
				Event:    "launcher.list",
				Result:   "launcher_name_requires_principal",
				Duration: duration,
			}, auth, nil)
			writeError(ctx, w, http.StatusBadRequest,
				"launcher_name_requires_principal",
				"launcher name filter requires --principal; without a Principal use a Launcher ID")
			return
		}
		launcher, err = findLauncherByID(a.DB, launcherFilter)
	} else {
		principalName = scope.principal.Username
		launcher, err = findLauncherForPrincipal(a.DB, int64(scope.principal.ID), launcherFilter)
	}

	duration := time.Since(started).Round(time.Millisecond).String()
	if err != nil {
		if errors.Is(err, ErrLauncherNotFound) {
			writeLauncherControlAudit(ctx, auditRecord{
				Event:         "launcher.list",
				PrincipalName: principalName,
				Result:        "launcher_not_found",
				Duration:      duration,
			}, auth, nil)
			writeError(ctx, w, http.StatusNotFound, "launcher_not_found", "launcher not found")
			return
		}
		writeLauncherControlAudit(ctx, auditRecord{
			Event:         "launcher.list",
			PrincipalName: principalName,
			Result:        "error",
			Duration:      duration,
		}, auth, nil)
		opLog(ctx).Error("launcher list filter failed",
			slog.String("operation", "launcher_list"),
			slog.String("error", err.Error()),
		)
		writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}

	resp := listLaunchersResponse{
		OK:        true,
		Launchers: []launcherJSON{launcherToJSON(*launcher)},
	}
	writeLauncherControlAudit(ctx, auditRecord{
		Event:    "launcher.list",
		Result:   "success",
		Duration: duration,
	}, auth, launcher)
	writeJSONRaw(ctx, w, http.StatusOK, resp)
}

// listLaunchersFiltered is the scope-first Launcher collection client. Both
// selectors are sent to the daemon; an empty selector is omitted. Filtering is
// never performed client-side.
func (c *apiClient) listLaunchersFiltered(principalFilter, launcherFilter string) (*listLaunchersResponse, error) {
	values := url.Values{}
	if principalFilter != "" {
		values.Set("principal", principalFilter)
	}
	if launcherFilter != "" {
		values.Set("launcher", launcherFilter)
	}
	path := "/launchers"
	if encoded := values.Encode(); encoded != "" {
		path += "?" + encoded
	}

	resp, err := c.doAuthenticatedRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := c.readResponseBody(resp)
	if err != nil {
		return nil, err
	}
	var result listLaunchersResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("cannot decode response: %w", err)
	}
	return &result, nil
}

// configureLauncherListFilter extends the existing command node in place so
// every structural consumer (parser, help and completion) keeps the same
// *Command identity while gaining the Launcher narrowing selector.
func configureLauncherListFilter() {
	launcherListCommand.Usage = "docker-helper launcher list [--system] [--endpoint ENDPOINT] [--token-file PATH] [--principal USER] [--launcher LAUNCHER] [--json]"
	launcherListCommand.NewInvocation = func(fs *flag.FlagSet) Invocation {
		system, endpoint, tokenFile := registerOperatorFlags(fs)
		principal := fs.String("principal", "", "Principal username filter (narrowing only; the daemon authorizes visibility)")
		launcher := fs.String("launcher", "", "Launcher name or ID filter (admin without --principal must use an ID)")
		jsonOut := fs.Bool("json", false, "Output in JSON format")
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				client, err := launcherOpClient(*system, *endpoint, *tokenFile)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				result, err := client.listLaunchersFiltered(*principal, *launcher)
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				if *jsonOut {
					if err := encodeJSONOut(stdout, result); err != nil {
						fmt.Fprintf(stderr, "error: cannot encode output: %v\n", err)
						return 1
					}
					return 0
				}
				fmt.Fprintf(stdout, "%-40s %-10s %-30s %-10s %s\n", "ID", "NAME", "SCOPE", "ENABLED", "PRINCIPAL")
				for _, l := range result.Launchers {
					enabled := "no"
					if l.Enabled {
						enabled = "yes"
					}
					fmt.Fprintf(stdout, "%-40s %-10s %-30s %-10s %s\n", l.ID, l.Name, l.Scope, enabled, l.Principal)
				}
				return 0
			},
		}
	}
}

func init() {
	configureLauncherListFilter()
}
