package main

import (
	"errors"
	"log/slog"
	"net/http"
	"time"
)

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
		Principal: c.PrincipalName,
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
		writeRequestContextAudit(ctx, auditRecord{
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
		writeRequestContextAudit(ctx, auditRecord{
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
		writeRequestContextAudit(ctx, auditRecord{
			Event:         "principal.credential_create",
			PrincipalName: username,
			Result:        "invalid_credential_name",
			Duration:      duration,
		})
		writeError(ctx, w, http.StatusBadRequest, "invalid_credential_name", "credential name is required")
		return
	}

	result, token, err := createCredential(a.DB, username, req.Name)
	duration := time.Since(started).Round(time.Millisecond).String()

	if err != nil {
		writeRequestContextAudit(ctx, auditRecord{
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
		case isErrInvalidAllowedRoot(err):
			writeError(ctx, w, http.StatusBadRequest, "invalid_allowed_root", "invalid allowed root")
		default:
			opLog(ctx).Error("credential create failed",
				slog.String("operation", "credential_create"),
				slog.String("error", err.Error()),
			)
			writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		}
		return
	}

	writeRequestContextAudit(ctx, auditRecord{
		Event:          "principal.credential_create",
		PrincipalName:  result.PrincipalName,
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
			opLog(ctx).Error("credential list failed",
				slog.String("operation", "credential_list"),
				slog.String("error", err.Error()),
			)
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
		writeRequestContextAudit(ctx, auditRecord{
			Event:    "principal.credential_revoke",
			Result:   "missing_id",
			Duration: duration,
		})
		writeError(ctx, w, http.StatusBadRequest, "missing_id", "credential id is required")
		return
	}

	// Pre-read credential metadata before any mutation so that audit
	// always has full context even if the mutation fails.
	cred, preReadErr := findCredentialByID(a.DB, id)
	if preReadErr != nil {
		duration := time.Since(started).Round(time.Millisecond).String()
		if isErrCredentialNotFound(preReadErr) {
			writeRequestContextAudit(ctx, auditRecord{
				Event:    "principal.credential_revoke",
				Result:   "credential_not_found",
				Duration: duration,
			})
			writeError(ctx, w, http.StatusNotFound, "credential_not_found", "credential not found")
		} else {
			writeRequestContextAudit(ctx, auditRecord{
				Event:    "principal.credential_revoke",
				Result:   "error",
				Duration: duration,
			})
			opLog(ctx).Error("credential revoke pre-read failed",
				slog.String("operation", "credential_revoke"),
				slog.String("error", preReadErr.Error()),
			)
			writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		}
		return
	}

	changed, err := revokeCredential(a.DB, id)
	duration := time.Since(started).Round(time.Millisecond).String()

	if err != nil {
		writeRequestContextAudit(ctx, auditRecord{
			Event:          "principal.credential_revoke",
			PrincipalName:  cred.PrincipalName,
			CredentialID:   cred.ID,
			CredentialName: cred.Name,
			Result:         "error",
			Duration:       duration,
		})
		opLog(ctx).Error("credential revoke mutation failed",
			slog.String("operation", "credential_revoke"),
			slog.String("error", err.Error()),
		)
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

	writeRequestContextAudit(ctx, auditRecord{
		Event:             "principal.credential_revoke",
		PrincipalName:     cred.PrincipalName,
		CredentialID:      cred.ID,
		CredentialName:    cred.Name,
		CredentialChanged: &changed,
		Result:            "success",
		Duration:          duration,
	})

	writeJSONRaw(ctx, w, http.StatusOK, resp)
}
