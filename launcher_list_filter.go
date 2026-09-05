package main

import (
	"errors"
	"log/slog"
	"net/http"
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

	auth, err := a.authenticatePrincipalControlRequest(w, r, "launcher")
	if err != nil || auth == nil {
		return
	}
	a.serveLauncherFilteredList(w, r, auth, r.URL.Query().Get("principal"), launcherFilter)
}

func (a *App) serveLauncherFilteredList(w http.ResponseWriter, r *http.Request, auth *operatorAuthority, principalFilter, launcherFilter string) {
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
