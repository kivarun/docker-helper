package main

import (
	"errors"
	"net/http"
	"time"
)

type createPrincipalRequest struct {
	Username string `json:"username"`
}

type setPrincipalRequest struct {
	Enabled *bool `json:"enabled,omitempty"`
}

type allowedRootRequest struct {
	Path string `json:"path"`
}

type principalResponse struct {
	OK           bool     `json:"ok"`
	Username     string   `json:"username"`
	UID          int      `json:"uid"`
	GID          int      `json:"gid"`
	Home         string   `json:"home"`
	Enabled      bool     `json:"enabled"`
	AllowedRoots []string `json:"allowed_roots"`
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
		writeAuditWithRequestID(ctx, auditRecord{
			Event:    "principal.create",
			Result:   "invalid_json",
			Duration: duration,
		})
		writeError(ctx, w, http.StatusBadRequest, "invalid_json", "invalid JSON request")
		return
	}

	if req.Username == "" {
		duration := time.Since(started).Round(time.Millisecond).String()
		writeAuditWithRequestID(ctx, auditRecord{
			Event:         "principal.create",
			PrincipalName: req.Username,
			Result:        "missing_username",
			Duration:      duration,
		})
		writeError(ctx, w, http.StatusBadRequest, "missing_username", "username is required")
		return
	}

	result, err := createPrincipal(a.DB, req.Username)
	duration := time.Since(started).Round(time.Millisecond).String()

	if err != nil {
		writeAuditWithRequestID(ctx, auditRecord{
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
		default:
			writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		}
		return
	}

	writeAuditWithRequestID(ctx, auditRecord{
		Event:         "principal.create",
		PrincipalName: result.Username,
		Result:        "success",
		Duration:      duration,
	})

	writeJSONRaw(ctx, w, http.StatusCreated, principalToResponse(result))
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

	result, err := findPrincipalByUserName(a.DB, username)
	if err != nil {
		if isErrPrincipalNotFound(err) {
			writeError(ctx, w, http.StatusNotFound, "principal_not_found", "principal not found")
		} else {
			writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		}
		return
	}

	writeJSONRaw(ctx, w, http.StatusOK, principalToResponse(result))
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
		writeAuditWithRequestID(ctx, auditRecord{
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
		writeAuditWithRequestID(ctx, auditRecord{
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
		writeAuditWithRequestID(ctx, auditRecord{
			Event:         "principal.enabled_change",
			PrincipalName: username,
			Result:        "missing_enabled",
			Duration:      duration,
		})
		writeError(ctx, w, http.StatusBadRequest, "missing_enabled", "enabled field is required")
		return
	}

	changed, err := updatePrincipalEnabled(a.DB, username, *req.Enabled)
	duration := time.Since(started).Round(time.Millisecond).String()

	if err != nil {
		writeAuditWithRequestID(ctx, auditRecord{
			Event:         "principal.enabled_change",
			PrincipalName: username,
			Result:        "error",
			Duration:      duration,
		})

		if isErrPrincipalNotFound(err) {
			writeError(ctx, w, http.StatusNotFound, "principal_not_found", "principal not found")
		} else {
			writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		}
		return
	}

	resp := principalChangedResponse{
		OK:       true,
		Username: username,
		Field:    "enabled",
		Changed:  changed,
	}
	if !changed {
		resp.Message = "unchanged"
	}

	writeAuditWithRequestID(ctx, auditRecord{
		Event:            "principal.enabled_change",
		PrincipalName:    username,
		PrincipalEnabled: req.Enabled,
		Result:           "success",
		Duration:         duration,
	})

	writeJSONRaw(ctx, w, http.StatusOK, resp)
}

func (a *App) handleAddAllowedRoot(w http.ResponseWriter, r *http.Request) {
	started := time.Now()

	if !a.requireAdmin(w, r) {
		return
	}

	ctx := r.Context()

	username := r.PathValue("username")
	if username == "" {
		duration := time.Since(started).Round(time.Millisecond).String()
		writeAuditWithRequestID(ctx, auditRecord{
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
		writeAuditWithRequestID(ctx, auditRecord{
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
		writeAuditWithRequestID(ctx, auditRecord{
			Event:         "principal.allowed_root_add",
			PrincipalName: username,
			Result:        "missing_path",
			Duration:      duration,
		})
		writeError(ctx, w, http.StatusBadRequest, "missing_path", "path is required")
		return
	}

	changed, canonicalPath, err := addAllowedRoot(a.DB, username, req.Path)
	duration := time.Since(started).Round(time.Millisecond).String()

	if err != nil {
		writeAuditWithRequestID(ctx, auditRecord{
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
		default:
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

	writeAuditWithRequestID(ctx, auditRecord{
		Event:         "principal.allowed_root_add",
		PrincipalName: username,
		PrincipalPath: canonicalPath,
		Result:        "success",
		Duration:      duration,
	})

	writeJSONRaw(ctx, w, http.StatusOK, resp)
}

func (a *App) handleRemoveAllowedRoot(w http.ResponseWriter, r *http.Request) {
	started := time.Now()

	if !a.requireAdmin(w, r) {
		return
	}

	ctx := r.Context()

	username := r.PathValue("username")
	if username == "" {
		duration := time.Since(started).Round(time.Millisecond).String()
		writeAuditWithRequestID(ctx, auditRecord{
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
		writeAuditWithRequestID(ctx, auditRecord{
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
		writeAuditWithRequestID(ctx, auditRecord{
			Event:         "principal.allowed_root_remove",
			PrincipalName: username,
			Result:        "missing_path",
			Duration:      duration,
		})
		writeError(ctx, w, http.StatusBadRequest, "missing_path", "path is required")
		return
	}

	changed, canonicalPath, err := removeAllowedRoot(a.DB, username, req.Path)
	duration := time.Since(started).Round(time.Millisecond).String()

	if err != nil {
		writeAuditWithRequestID(ctx, auditRecord{
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

	writeAuditWithRequestID(ctx, auditRecord{
		Event:         "principal.allowed_root_remove",
		PrincipalName: username,
		PrincipalPath: canonicalPath,
		Result:        "success",
		Duration:      duration,
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

func isErrCredentialNotFound(err error) bool {
	return errors.Is(err, ErrCredentialNotFound)
}

func isErrCredentialExists(err error) bool {
	return errors.Is(err, ErrCredentialExists)
}

type createCredentialRequest struct {
	Name string `json:"name"`
}

type credentialJSON struct {
	ID        string  `json:"id"`
	Principal string  `json:"principal"`
	Name      string  `json:"name"`
	CreatedAt string  `json:"created_at"`
	RevokedAt *string `json:"revoked_at"`
}

type createCredentialResponse struct {
	OK         bool           `json:"ok"`
	Credential credentialJSON `json:"credential"`
	Token      string         `json:"token"`
}

type listCredentialsResponse struct {
	OK          bool             `json:"ok"`
	Credentials []credentialJSON `json:"credentials"`
}

type revokeCredentialResponse struct {
	OK      bool   `json:"ok"`
	ID      string `json:"id"`
	Changed bool   `json:"changed"`
	Message string `json:"message,omitempty"`
}

func credentialToJSON(c CredentialWithPrincipal) credentialJSON {
	revokedAt := (*string)(nil)
	if c.RevokedAt != nil {
		s := c.RevokedAt.Format(time.RFC3339)
		revokedAt = &s
	}
	return credentialJSON{
		ID:        c.ID,
		Principal: c.Principal,
		Name:      c.Name,
		CreatedAt: c.CreatedAt.Format(time.RFC3339),
		RevokedAt: revokedAt,
	}
}

func (a *App) handleCreateCredential(w http.ResponseWriter, r *http.Request) {
	started := time.Now()

	if !a.requireAdmin(w, r) {
		return
	}

	ctx := r.Context()

	username := r.PathValue("username")
	if username == "" {
		duration := time.Since(started).Round(time.Millisecond).String()
		writeAuditWithRequestID(ctx, auditRecord{
			Event:    "principal.credential_create",
			Result:   "missing_username",
			Duration: duration,
		})
		writeError(ctx, w, http.StatusBadRequest, "missing_username", "username is required")
		return
	}

	var req createCredentialRequest
	if err := decodeJSONRequest(w, r, &req); err != nil {
		duration := time.Since(started).Round(time.Millisecond).String()
		writeAuditWithRequestID(ctx, auditRecord{
			Event:         "principal.credential_create",
			PrincipalName: username,
			Result:        "invalid_json",
			Duration:      duration,
		})
		writeError(ctx, w, http.StatusBadRequest, "invalid_json", "invalid JSON request")
		return
	}

	if req.Name == "" {
		duration := time.Since(started).Round(time.Millisecond).String()
		writeAuditWithRequestID(ctx, auditRecord{
			Event:         "principal.credential_create",
			PrincipalName: username,
			Result:        "missing_name",
			Duration:      duration,
		})
		writeError(ctx, w, http.StatusBadRequest, "missing_name", "credential name is required")
		return
	}

	result, token, err := createCredential(a.DB, username, req.Name)
	duration := time.Since(started).Round(time.Millisecond).String()

	if err != nil {
		writeAuditWithRequestID(ctx, auditRecord{
			Event:          "principal.credential_create",
			PrincipalName:  username,
			CredentialName: req.Name,
			Result:         "error",
			Duration:       duration,
		})

		switch {
		case isErrPrincipalNotFound(err):
			writeError(ctx, w, http.StatusNotFound, "principal_not_found", "principal not found")
		case isErrCredentialExists(err):
			writeError(ctx, w, http.StatusConflict, "credential_exists", "credential already exists")
		default:
			writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		}
		return
	}

	writeAuditWithRequestID(ctx, auditRecord{
		Event:          "principal.credential_create",
		PrincipalName:  result.Principal,
		CredentialID:   result.ID,
		CredentialName: result.Name,
		Result:         "success",
		Duration:       duration,
	})

	writeJSONRaw(ctx, w, http.StatusCreated, createCredentialResponse{
		OK:         true,
		Credential: credentialToJSON(*result),
		Token:      token,
	})
}

func (a *App) handleListCredentials(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdmin(w, r) {
		return
	}

	ctx := r.Context()

	username := r.PathValue("username")
	if username == "" {
		writeError(ctx, w, http.StatusBadRequest, "missing_username", "username is required")
		return
	}

	creds, err := listCredentials(a.DB, username)
	if err != nil {
		if isErrPrincipalNotFound(err) {
			writeError(ctx, w, http.StatusNotFound, "principal_not_found", "principal not found")
		} else {
			writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		}
		return
	}

	resp := listCredentialsResponse{
		OK:          true,
		Credentials: make([]credentialJSON, 0, len(creds)),
	}
	for _, c := range creds {
		resp.Credentials = append(resp.Credentials, credentialToJSON(c))
	}

	writeJSONRaw(ctx, w, http.StatusOK, resp)
}

func (a *App) handleRevokeCredential(w http.ResponseWriter, r *http.Request) {
	started := time.Now()

	if !a.requireAdmin(w, r) {
		return
	}

	ctx := r.Context()

	id := r.PathValue("id")
	if id == "" {
		duration := time.Since(started).Round(time.Millisecond).String()
		writeAuditWithRequestID(ctx, auditRecord{
			Event:    "principal.credential_revoke",
			Result:   "missing_id",
			Duration: duration,
		})
		writeError(ctx, w, http.StatusBadRequest, "missing_id", "credential id is required")
		return
	}

	cred, err := findCredentialByID(a.DB, id)
	duration := time.Since(started).Round(time.Millisecond).String()

	if err != nil {
		writeAuditWithRequestID(ctx, auditRecord{
			Event:    "principal.credential_revoke",
			Result:   "credential_not_found",
			Duration: duration,
		})
		writeError(ctx, w, http.StatusNotFound, "credential_not_found", "credential not found")
		return
	}

	changed, err := revokeCredential(a.DB, id)
	duration = time.Since(started).Round(time.Millisecond).String()

	if err != nil {
		writeAuditWithRequestID(ctx, auditRecord{
			Event:          "principal.credential_revoke",
			PrincipalName:  cred.Principal,
			CredentialID:   cred.ID,
			CredentialName: cred.Name,
			Result:         "error",
			Duration:       duration,
		})
		writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}

	resp := revokeCredentialResponse{
		OK:      true,
		ID:      id,
		Changed: changed,
	}
	if !changed {
		resp.Message = "unchanged"
	}

	writeAuditWithRequestID(ctx, auditRecord{
		Event:             "principal.credential_revoke",
		PrincipalName:     cred.Principal,
		CredentialID:      cred.ID,
		CredentialName:    cred.Name,
		CredentialChanged: &changed,
		Result:            "success",
		Duration:          duration,
	})

	writeJSONRaw(ctx, w, http.StatusOK, resp)
}
