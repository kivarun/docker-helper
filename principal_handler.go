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
	OK           bool            `json:"ok"`
	Username     string          `json:"username"`
	UID          int             `json:"uid"`
	GID          int             `json:"gid"`
	Home         string          `json:"home"`
	Enabled      bool            `json:"enabled"`
	AllowedRoots []string        `json:"allowed_roots"`
	Credential   *credentialJSON `json:"credential,omitempty"`
	Token        string          `json:"token,omitempty"`
}

type principalChangedResponse struct {
	OK       bool   `json:"ok"`
	Username string `json:"username"`
	Field    string `json:"field"`
	Changed  bool   `json:"changed"`
	Message  string `json:"message,omitempty"`
}

func principalToResponse(p *PrincipalWithRoots) principalResponse {
	return principalResponse{
		OK:           true,
		Username:     p.Username,
		UID:          p.UID,
		GID:          p.GID,
		Home:         p.Home,
		Enabled:      p.Enabled,
		AllowedRoots: p.AllowedRoots,
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

	result, cred, token, err := createPrincipalWithOptionalCredential(a.DB, req.Username, a.getConfig().AllowedRoots, req.IssueCredential)
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
		cj := credentialToJSON(*cred)
		resp.Credential = &cj
		resp.Token = token
	}

	writeJSONRaw(ctx, w, http.StatusCreated, resp)
}

func (a *App) handleShowPrincipal(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdmin(w, r) {
		return
	}

	ctx := r.Context()

	username := r.PathValue("username")
	if username == "" {
		writeError(ctx, w, http.StatusBadRequest, "missing_username", "username is required")
		return
	}

	result, err := findPrincipalByUsername(a.DB, username)
	if err != nil {
		if isErrPrincipalNotFound(err) {
			writeError(ctx, w, http.StatusNotFound, "principal_not_found", "principal not found")
		} else {
			opLog(ctx).Error("principal show failed",
				slog.String("operation", "principal_show"),
				slog.String("error", err.Error()),
			)
			writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		}
		return
	}

	writeJSONRaw(ctx, w, http.StatusOK, principalToResponse(result))
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
		writeRequestContextAudit(ctx, auditRecord{
			Event:         "principal.enabled_change",
			PrincipalName: username,
			Result:        "error",
			Duration:      duration,
		})

		if isErrPrincipalNotFound(changeErr) {
			writeError(ctx, w, http.StatusNotFound, "principal_not_found", "principal not found")
		} else {
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

	changed, canonicalPath, err := addPrincipalAllowedRoot(a.DB, username, req.Path, a.getConfig().AllowedRoots)
	duration := time.Since(started).Round(time.Millisecond).String()

	if err != nil {
		writeRequestContextAudit(ctx, auditRecord{
			Event:         "principal.allowed_root_add",
			PrincipalName: username,
			Result:        "error",
			Duration:      duration,
		})

		switch {
		case isErrPrincipalNotFound(err):
			writeError(ctx, w, http.StatusNotFound, "principal_not_found", "principal not found")
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

	changed, canonicalPath, err := removePrincipalAllowedRoot(a.DB, username, req.Path)
	duration := time.Since(started).Round(time.Millisecond).String()

	if err != nil {
		writeRequestContextAudit(ctx, auditRecord{
			Event:         "principal.allowed_root_remove",
			PrincipalName: username,
			Result:        "error",
			Duration:      duration,
		})

		switch {
		case isErrPrincipalNotFound(err):
			writeError(ctx, w, http.StatusNotFound, "principal_not_found", "principal not found")
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

	if err != nil {
		if isErrPrincipalNotFound(err) {
			writeRequestContextAudit(ctx, auditRecord{
				Event:         "principal.delete",
				PrincipalName: username,
				Result:        "not_found",
				Duration:      duration,
			})
			writeError(ctx, w, http.StatusNotFound, "principal_not_found", "principal not found")
		} else if isErrLauncherRuntimeActive(err) {
			writeRequestContextAudit(ctx, auditRecord{
				Event:         "principal.delete",
				PrincipalName: username,
				Result:        "launcher_runtime_active",
				Duration:      duration,
			})
			writeError(ctx, w, http.StatusConflict, "launcher_runtime_active", "principal has active launcher runtime")
		} else {
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

	// Best-effort cleanup of runtime directories for deleted sessions.
	cfg := a.getConfig()
	for _, sessionID := range sessionIDs {
		if err := cleanupSessionRuntimeDir(cfg.RuntimeDir, sessionID); err != nil {
			opLog(ctx).Warn("failed to clean up session runtime directory",
				slog.String("operation", "principal_delete"),
				slog.String("session_id", sessionID),
				slog.String("error", err.Error()),
			)
		}
	}

	writeRequestContextAudit(ctx, auditRecord{
		Event:         "principal.delete",
		PrincipalName: username,
		Result:        "success",
		Duration:      duration,
	})

	w.WriteHeader(http.StatusNoContent)
}
