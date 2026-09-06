package main

import (
	"errors"
	"log/slog"
	"net/http"
	"time"
)

type createPrincipalRequest struct {
	Username        string `json:"username"`
	IssueCredential bool   `json:"issue_credential,omitempty"`
}

type setPrincipalRequest struct {
	Enabled *bool `json:"enabled,omitempty"`
}

type allowedRootRequest struct {
	Path string `json:"path"`
}

type principalResponse struct {
	OK           bool                     `json:"ok"`
	Username     string                   `json:"username"`
	UID          int                      `json:"uid"`
	GID          int                      `json:"gid"`
	Home         string                   `json:"home"`
	Enabled      bool                     `json:"enabled"`
	AllowedRoots []string                 `json:"allowed_roots"`
	Credential   *principalCredentialJSON `json:"credential,omitempty"`
	Token        string                   `json:"token,omitempty"`
}

type principalChangedResponse struct {
	OK       bool   `json:"ok"`
	Username string `json:"username"`
	Field    string `json:"field"`
	Changed  bool   `json:"changed"`
	Message  string `json:"message,omitempty"`
}

// principalToResponse is the single projection owner for the public
// Principal resource document (create and show). allowed_roots is always
// serialized as a JSON array: zero stored roots project the empty array,
// never null. Internal nil slices are not mutated.
func principalToResponse(p *PrincipalWithRoots) principalResponse {
	roots := p.AllowedRoots
	if roots == nil {
		roots = []string{}
	}
	return principalResponse{
		OK:           true,
		Username:     p.Username,
		UID:          p.UID,
		GID:          p.GID,
		Home:         p.Home,
		Enabled:      p.Enabled,
		AllowedRoots: roots,
	}
}

func (a *App) handleCreatePrincipal(w http.ResponseWriter, r *http.Request) {
	started := time.Now()

	if !a.requireAdmin(w, r) {
		return
	}

	ctx := r.Context()

	var req createPrincipalRequest
	if err := decodeJSONRequest(w, r, &req); err != nil {
		duration := time.Since(started).Round(time.Millisecond).String()
		writeRequestContextAudit(ctx, auditRecord{
			Event:    "principal.create",
			Result:   "invalid_json",
			Duration: duration,
		})
		writeError(ctx, w, http.StatusBadRequest, "invalid_json", "invalid JSON request")
		return
	}

	if req.Username == "" {
		duration := time.Since(started).Round(time.Millisecond).String()
		writeRequestContextAudit(ctx, auditRecord{
			Event:         "principal.create",
			PrincipalName: req.Username,
			Result:        "missing_username",
			Duration:      duration,
		})
		writeError(ctx, w, http.StatusBadRequest, "missing_username", "username is required")
		return
	}

	// The Principal creation is a policy-authority mutation: it shares the
	// lifecycle serialization with Session creation so a concurrent create
	// observes either the pre-creation or post-creation ownership, never a
	// mix. createPrincipalWithLifecycle owns that boundary and resolves the
	// current global ceiling inside it (the current global policy snapshot is
	// read inside the boundary, the same lifecycleMu -> a.mu ordering as
	// config reload), so a Principal home outside a ceiling committed by a
	// reload that linearized first is rejected before any durable change.
	result, cred, token, err := a.createPrincipalWithLifecycle(req.Username, req.IssueCredential)
	duration := time.Since(started).Round(time.Millisecond).String()

	if err != nil {
		writeRequestContextAudit(ctx, auditRecord{
			Event:         "principal.create",
			PrincipalName: req.Username,
			Result:        "error",
			Duration:      duration,
		})

		switch {
		case isErrOSUserNotFound(err):
			writeError(ctx, w, http.StatusBadRequest, "os_user_not_found", "OS user not found")
		case isErrPrincipalExists(err):
			writeError(ctx, w, http.StatusConflict, "principal_exists", "principal already exists")
		case errors.Is(err, ErrPrincipalRootOutsideGlobal):
			writeError(ctx, w, http.StatusBadRequest, "outside_global_root", "principal home is not under any global allowed root")
		default:
			opLog(ctx).Error("principal create failed",
				slog.String("operation", "principal_create"),
				slog.String("error", err.Error()),
			)
			writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		}
		return
	}

	writeRequestContextAudit(ctx, auditRecord{
		Event:         "principal.create",
		PrincipalName: result.Username,
		Result:        "success",
		Duration:      duration,
	})

	resp := principalToResponse(result)
	if cred != nil {
		cj := principalCredentialToJSON(*cred)
		resp.Credential = &cj
		resp.Token = token
	}

	writeJSONRaw(ctx, w, http.StatusCreated, resp)
}

// handleShowPrincipal answers GET /principals/{username}: the public
// Principal resource document (create and show share principalToResponse).
// Read authority is scope-first through the stable Principal-control target
// owner (resolvePrincipalControlTarget): an admin authority may read any
// Principal, a Principal credential may read exactly the Principal it
// authenticated as, and a foreign selector is the established non-disclosing
// not-found; a Launcher credential has no Principal-read authority and gets
// the family's non-disclosing unauthorized contract. The CLI performs no
// local self-check: it always sends the request and the daemon authorizes
// the target, so principal show and its FIELD extraction consume the same
// response for an own-Principal read as for an admin read.
func (a *App) handleShowPrincipal(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	authCtx, err := a.authenticatePrincipalControlRequest(w, r, "principal")
	if err != nil || authCtx == nil {
		return
	}

	username := r.PathValue("username")
	if username == "" {
		writeError(ctx, w, http.StatusBadRequest, "missing_username", "username is required")
		return
	}

	target, err := resolvePrincipalControlTarget(a.DB, authCtx, username)
	if err != nil {
		writePrincipalControlLookupError(ctx, w, err)
		return
	}

	result, err := findPrincipalByID(a.DB, int(target.ID))
	if err != nil {
		if isErrPrincipalNotFound(err) {
			writeError(ctx, w, http.StatusNotFound, "principal_not_found", "principal not found")
			return
		}
		opLog(ctx).Error("principal show failed",
			slog.String("operation", "principal_show"),
			slog.String("error", err.Error()),
		)
		writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	roots, err := readPrincipalAllowedRoots(a.DB, target.ID)
	if err != nil {
		opLog(ctx).Error("principal show failed",
			slog.String("operation", "principal_show"),
			slog.String("error", err.Error()),
		)
		writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}

	writeJSONRaw(ctx, w, http.StatusOK, principalToResponse(&PrincipalWithRoots{Principal: *result, AllowedRoots: roots}))
}

func (a *App) handleListPrincipals(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdmin(w, r) {
		return
	}

	ctx := r.Context()

	summaries, err := listPrincipalSummaries(a.DB)
	if err != nil {
		opLog(ctx).Error("principal list failed",
			slog.String("operation", "principal_list"),
			slog.String("error", err.Error()),
		)
		writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}

	writeJSONRaw(ctx, w, http.StatusOK, listPrincipalsResponse{
		OK:         true,
		Principals: summaries,
	})
}

func (a *App) handleSetPrincipal(w http.ResponseWriter, r *http.Request) {
	started := time.Now()

	if !a.requireAdmin(w, r) {
		return
	}

	ctx := r.Context()

	username := r.PathValue("username")
	if username == "" {
		duration := time.Since(started).Round(time.Millisecond).String()
		writeRequestContextAudit(ctx, auditRecord{
			Event:    "principal.enabled_change",
			Result:   "missing_username",
			Duration: duration,
		})
		writeError(ctx, w, http.StatusBadRequest, "missing_username", "username is required")
		return
	}

	var req setPrincipalRequest
	if err := decodeJSONRequest(w, r, &req); err != nil {
		duration := time.Since(started).Round(time.Millisecond).String()
		writeRequestContextAudit(ctx, auditRecord{
			Event:         "principal.enabled_change",
			PrincipalName: username,
			Result:        "invalid_json",
			Duration:      duration,
		})
		writeError(ctx, w, http.StatusBadRequest, "invalid_json", "invalid JSON request")
		return
	}

	if req.Enabled == nil {
		duration := time.Since(started).Round(time.Millisecond).String()
		writeRequestContextAudit(ctx, auditRecord{
			Event:         "principal.enabled_change",
			PrincipalName: username,
			Result:        "missing_enabled",
			Duration:      duration,
		})
		writeError(ctx, w, http.StatusBadRequest, "missing_enabled", "enabled field is required")
		return
	}

	var result principalEnabledChangeResult
	var changeErr error
	if *req.Enabled {
		// Re-enabling commits enabled=true first; only after that success does
		// the Principal reopen Operation admission across its Launchers (quiesce
		// is the runtime companion of durable disabled state).
		result, changeErr = a.enablePrincipalLaunchers(username)
	} else {
		// Disabling quiesces every Launcher beneath the Principal before the
		// disable commits and keeps them quiesced on success.
		result, changeErr = a.disablePrincipalLaunchers(username)
	}
	duration := time.Since(started).Round(time.Millisecond).String()
	changed := result.Changed

	if changeErr != nil {
		result := "error"
		if isErrUserModeOwnerReserved(changeErr) {
			result = "user_mode_owner_reserved"
		}
		writeRequestContextAudit(ctx, auditRecord{
			Event:         "principal.enabled_change",
			PrincipalName: username,
			Result:        result,
			Duration:      duration,
		})

		switch {
		case isErrPrincipalNotFound(changeErr):
			writeError(ctx, w, http.StatusNotFound, "principal_not_found", "principal not found")
		case isErrUserModeOwnerReserved(changeErr):
			writeError(ctx, w, http.StatusConflict, "user_mode_owner_reserved",
				"this principal is managed by transparent user mode and cannot be mutated in this way")
		default:
			opLog(ctx).Error("principal set failed",
				slog.String("operation", "principal_set"),
				slog.String("error", changeErr.Error()),
			)
			writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		}
		return
	}

	if !*req.Enabled && len(result.RevokedSessionIDs) > 0 {
		cfg := a.getConfig()
		for _, sessionID := range result.RevokedSessionIDs {
			if err := cleanupSessionRuntimeDir(cfg.RuntimeDir, sessionID); err != nil {
				opLog(ctx).Warn("failed to clean up session runtime directory",
					slog.String("operation", "principal_disable"),
					slog.String("session_id", sessionID),
					slog.String("error", err.Error()),
				)
			}
		}
	}

	writeRequestContextAudit(ctx, auditRecord{
		Event:            "principal.enabled_change",
		PrincipalName:    username,
		PrincipalEnabled: req.Enabled,
		Result:           "success",
		Duration:         duration,
	})

	writeJSONRaw(ctx, w, http.StatusOK, principalChangedResponse{
		OK:       true,
		Username: username,
		Field:    "enabled",
		Changed:  changed,
		Message: func() string {
			if !changed {
				return "unchanged"
			}
			return ""
		}(),
	})
}

func (a *App) handleAddPrincipalAllowedRoot(w http.ResponseWriter, r *http.Request) {
	started := time.Now()

	if !a.requireAdmin(w, r) {
		return
	}

	ctx := r.Context()

	username := r.PathValue("username")
	if username == "" {
		duration := time.Since(started).Round(time.Millisecond).String()
		writeRequestContextAudit(ctx, auditRecord{
			Event:    "principal.allowed_root_add",
			Result:   "missing_username",
			Duration: duration,
		})
		writeError(ctx, w, http.StatusBadRequest, "missing_username", "username is required")
		return
	}

	var req allowedRootRequest
	if err := decodeJSONRequest(w, r, &req); err != nil {
		duration := time.Since(started).Round(time.Millisecond).String()
		writeRequestContextAudit(ctx, auditRecord{
			Event:         "principal.allowed_root_add",
			PrincipalName: username,
			Result:        "invalid_json",
			Duration:      duration,
		})
		writeError(ctx, w, http.StatusBadRequest, "invalid_json", "invalid JSON request")
		return
	}

	if req.Path == "" {
		duration := time.Since(started).Round(time.Millisecond).String()
		writeRequestContextAudit(ctx, auditRecord{
			Event:         "principal.allowed_root_add",
			PrincipalName: username,
			Result:        "missing_path",
			Duration:      duration,
		})
		writeError(ctx, w, http.StatusBadRequest, "missing_path", "path is required")
		return
	}

	// The Principal allowed-root mutation is a policy-authority mutation: it
	// shares the lifecycle serialization with Session creation so a concurrent
	// create either linearizes before the mutation (and observed the old
	// policy) or after it (and observes the narrowed/widened one).
	// addPrincipalAllowedRootWithLifecycle owns that boundary and the current
	// policy snapshot inside it, and refuses the reserved user-mode
	// daemon-owner Principal before any change.
	changed, canonicalPath, err := a.addPrincipalAllowedRootWithLifecycle(username, req.Path)
	duration := time.Since(started).Round(time.Millisecond).String()

	if err != nil {
		result := "error"
		if isErrUserModeOwnerReserved(err) {
			result = "user_mode_owner_reserved"
		}
		writeRequestContextAudit(ctx, auditRecord{
			Event:         "principal.allowed_root_add",
			PrincipalName: username,
			Result:        result,
			Duration:      duration,
		})

		switch {
		case isErrPrincipalNotFound(err):
			writeError(ctx, w, http.StatusNotFound, "principal_not_found", "principal not found")
		case isErrUserModeOwnerReserved(err):
			writeError(ctx, w, http.StatusConflict, "user_mode_owner_reserved",
				"this principal is managed by transparent user mode and cannot be mutated in this way")
		case isErrInvalidAllowedRoot(err):
			writeError(ctx, w, http.StatusBadRequest, "invalid_allowed_root", "invalid allowed root")
		case errors.Is(err, ErrPrincipalRootOutsideGlobal):
			writeError(ctx, w, http.StatusBadRequest, "outside_global_root", "path is not under any global allowed root")
		default:
			opLog(ctx).Error("principal allowed_root_add failed",
				slog.String("operation", "principal_allowed_root_add"),
				slog.String("error", err.Error()),
			)
			writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		}
		return
	}

	resp := principalChangedResponse{
		OK:       true,
		Username: username,
		Field:    "allowed_roots",
		Changed:  changed,
	}
	if !changed {
		resp.Message = "unchanged"
	}

	writeRequestContextAudit(ctx, auditRecord{
		Event:                "principal.allowed_root_add",
		PrincipalName:        username,
		PrincipalAllowedRoot: canonicalPath,
		Result:               "success",
		Duration:             duration,
	})

	writeJSONRaw(ctx, w, http.StatusOK, resp)
}

func (a *App) handleRemovePrincipalAllowedRoot(w http.ResponseWriter, r *http.Request) {
	started := time.Now()

	if !a.requireAdmin(w, r) {
		return
	}

	ctx := r.Context()

	username := r.PathValue("username")
	if username == "" {
		duration := time.Since(started).Round(time.Millisecond).String()
		writeRequestContextAudit(ctx, auditRecord{
			Event:    "principal.allowed_root_remove",
			Result:   "missing_username",
			Duration: duration,
		})
		writeError(ctx, w, http.StatusBadRequest, "missing_username", "username is required")
		return
	}

	var req allowedRootRequest
	if err := decodeJSONRequest(w, r, &req); err != nil {
		duration := time.Since(started).Round(time.Millisecond).String()
		writeRequestContextAudit(ctx, auditRecord{
			Event:         "principal.allowed_root_remove",
			PrincipalName: username,
			Result:        "invalid_json",
			Duration:      duration,
		})
		writeError(ctx, w, http.StatusBadRequest, "invalid_json", "invalid JSON request")
		return
	}

	if req.Path == "" {
		duration := time.Since(started).Round(time.Millisecond).String()
		writeRequestContextAudit(ctx, auditRecord{
			Event:         "principal.allowed_root_remove",
			PrincipalName: username,
			Result:        "missing_path",
			Duration:      duration,
		})
		writeError(ctx, w, http.StatusBadRequest, "missing_path", "path is required")
		return
	}

	// Same lifecycle serialization boundary as Session creation and the
	// Principal allowed-root add (see handleAddPrincipalAllowedRoot);
	// removePrincipalAllowedRootWithLifecycle owns it and refuses the reserved
	// user-mode daemon-owner Principal before any change.
	changed, canonicalPath, err := a.removePrincipalAllowedRootWithLifecycle(username, req.Path)
	duration := time.Since(started).Round(time.Millisecond).String()

	if err != nil {
		result := "error"
		if isErrUserModeOwnerReserved(err) {
			result = "user_mode_owner_reserved"
		}
		writeRequestContextAudit(ctx, auditRecord{
			Event:         "principal.allowed_root_remove",
			PrincipalName: username,
			Result:        result,
			Duration:      duration,
		})

		switch {
		case isErrPrincipalNotFound(err):
			writeError(ctx, w, http.StatusNotFound, "principal_not_found", "principal not found")
		case isErrUserModeOwnerReserved(err):
			writeError(ctx, w, http.StatusConflict, "user_mode_owner_reserved",
				"this principal is managed by transparent user mode and cannot be mutated in this way")
		case isErrInvalidAllowedRoot(err):
			writeError(ctx, w, http.StatusBadRequest, "invalid_allowed_root", "invalid allowed root")
		default:
			opLog(ctx).Error("principal allowed_root_remove failed",
				slog.String("operation", "principal_allowed_root_remove"),
				slog.String("error", err.Error()),
			)
			writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		}
		return
	}

	resp := principalChangedResponse{
		OK:       true,
		Username: username,
		Field:    "allowed_roots",
		Changed:  changed,
	}
	if !changed {
		resp.Message = "unchanged"
	}

	writeRequestContextAudit(ctx, auditRecord{
		Event:                "principal.allowed_root_remove",
		PrincipalName:        username,
		PrincipalAllowedRoot: canonicalPath,
		Result:               "success",
		Duration:             duration,
	})

	writeJSONRaw(ctx, w, http.StatusOK, resp)
}

func isErrPrincipalNotFound(err error) bool {
	return errors.Is(err, ErrPrincipalNotFound)
}

func isErrPrincipalExists(err error) bool {
	return errors.Is(err, ErrPrincipalExists)
}

func isErrOSUserNotFound(err error) bool {
	return errors.Is(err, ErrOSUserNotFound)
}

func isErrInvalidAllowedRoot(err error) bool {
	return errors.Is(err, ErrInvalidAllowedRoot)
}

func (a *App) handleDeletePrincipal(w http.ResponseWriter, r *http.Request) {
	started := time.Now()

	if !a.requireAdmin(w, r) {
		return
	}

	ctx := r.Context()

	username := r.PathValue("username")
	if username == "" {
		duration := time.Since(started).Round(time.Millisecond).String()
		writeRequestContextAudit(ctx, auditRecord{
			Event:    "principal.delete",
			Result:   "missing_username",
			Duration: duration,
		})
		writeError(ctx, w, http.StatusBadRequest, "missing_username", "username is required")
		return
	}

	sessionIDs, err := a.deletePrincipalChecked(ctx, username)
	duration := time.Since(started).Round(time.Millisecond).String()

	// Best-effort cleanup of runtime directories for invalidated sessions. It
	// runs regardless of the outcome: a durable child disable that committed
	// before a later teardown failure has already invalidated those sessions,
	// and their IDs are returned with the error so the cleanup is not lost
	// until daemon restart.
	cfg := a.getConfig()
	cleanupSessionRuntimeDirsBestEffort(ctx, "principal_delete", cfg.RuntimeDir, sessionIDs)

	if err != nil {
		switch {
		case isErrPrincipalNotFound(err):
			writeRequestContextAudit(ctx, auditRecord{
				Event:         "principal.delete",
				PrincipalName: username,
				Result:        "not_found",
				Duration:      duration,
			})
			writeError(ctx, w, http.StatusNotFound, "principal_not_found", "principal not found")
		case isErrLauncherRuntimeActive(err):
			writeRequestContextAudit(ctx, auditRecord{
				Event:         "principal.delete",
				PrincipalName: username,
				Result:        "launcher_runtime_active",
				Duration:      duration,
			})
			writeError(ctx, w, http.StatusConflict, "launcher_runtime_active", "principal has active launcher runtime")
		case isErrUserModeOwnerReserved(err):
			writeRequestContextAudit(ctx, auditRecord{
				Event:         "principal.delete",
				PrincipalName: username,
				Result:        "user_mode_owner_reserved",
				Duration:      duration,
			})
			writeError(ctx, w, http.StatusConflict, "user_mode_owner_reserved",
				"this principal is managed by transparent user mode and cannot be mutated in this way")
		default:
			writeRequestContextAudit(ctx, auditRecord{
				Event:         "principal.delete",
				PrincipalName: username,
				Result:        "database_error",
				Duration:      duration,
			})
			opLog(ctx).Error("principal delete failed",
				slog.String("operation", "principal_delete"),
				slog.String("error", err.Error()),
			)
			writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		}
		return
	}

	writeRequestContextAudit(ctx, auditRecord{
		Event:         "principal.delete",
		PrincipalName: username,
		Result:        "success",
		Duration:      duration,
	})

	w.WriteHeader(http.StatusNoContent)
}
