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

func isErrPrincipalCredentialExists(err error) bool {
	return errors.Is(err, ErrPrincipalCredentialExists)
}

type createPrincipalCredentialRequest struct {
	Name string `json:"name"`
}

type principalCredentialJSON struct {
	ID        string  `json:"id"`
	Principal string  `json:"principal"`
	Name      string  `json:"name"`
	CreatedAt string  `json:"created_at"`
	RevokedAt *string `json:"revoked_at"`
}

type principalCredentialTokenResponse struct {
	OK         bool                    `json:"ok"`
	Credential principalCredentialJSON `json:"credential"`
	Token      string                  `json:"token"`
}

type listPrincipalCredentialsResponse struct {
	OK          bool                      `json:"ok"`
	Credentials []principalCredentialJSON `json:"credentials"`
}

type revokePrincipalCredentialResponse struct {
	OK      bool   `json:"ok"`
	ID      string `json:"id"`
	Changed bool   `json:"changed"`
	Message string `json:"message,omitempty"`
}

func principalCredentialToJSON(c PrincipalCredential) principalCredentialJSON {
	revokedAt := (*string)(nil)
	if c.RevokedAt != nil {
		s := c.RevokedAt.Format(time.RFC3339)
		revokedAt = &s
	}
	return principalCredentialJSON{
		ID:        c.ID,
		Principal: c.PrincipalName,
		Name:      c.Name,
		CreatedAt: c.CreatedAt.Format(time.RFC3339),
		RevokedAt: revokedAt,
	}
}

func (a *App) handleCreatePrincipalCredential(w http.ResponseWriter, r *http.Request) {
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

	var req createPrincipalCredentialRequest
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

	result, token, err := createPrincipalCredential(a.DB, username, req.Name)
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
		case isErrPrincipalCredentialExists(err):
			writeError(ctx, w, http.StatusConflict, "credential_exists", "credential already exists")
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

	writeJSONRaw(ctx, w, http.StatusCreated, principalCredentialTokenResponse{
		OK:         true,
		Credential: principalCredentialToJSON(*result),
		Token:      token,
	})
}

// handleListPrincipalCredentials serves GET /principals/{username}/credentials: the
// list of one Principal's credentials. The path Principal is a required
// single-Principal filter of the shared scope-first list rule.
func (a *App) handleListPrincipalCredentials(w http.ResponseWriter, r *http.Request) {
	auth, err := a.authenticateControlRequest(w, r, "credential")
	if err != nil || auth == nil {
		return
	}
	username := r.PathValue("username")
	if username == "" {
		writeError(r.Context(), w, http.StatusBadRequest, "missing_username", "username is required")
		return
	}
	a.servePrincipalCredentialList(w, r, auth, username)
}

// handleListPrincipalCredentialsForAuthority serves GET /credentials: the scope-first
// principal credential list. The authenticated authority establishes the
// maximum visibility and the optional ?principal= filter can only narrow it;
// the daemon remains the authorization authority.
func (a *App) handleListPrincipalCredentialsForAuthority(w http.ResponseWriter, r *http.Request) {
	auth, err := a.authenticateControlRequest(w, r, "credential")
	if err != nil || auth == nil {
		return
	}
	a.servePrincipalCredentialList(w, r, auth, r.URL.Query().Get("principal"))
}

// servePrincipalCredentialList answers a principal credential list Query
// under the scope-first list rule: the authority scope plus the optional
// Principal filter resolve into one authorized query predicate. A filtered or
// single-Principal list audits the target Principal; the unfiltered admin
// list covers every Principal.
func (a *App) servePrincipalCredentialList(w http.ResponseWriter, r *http.Request, auth *controlAuthority, principalFilter string) {
	started := time.Now()

	ctx := r.Context()

	// The list is scope-first: the authenticated authority defines the
	// effective visibility and the optional Principal filter can only narrow
	// it — never expand it (a foreign Principal filter is a non-disclosing
	// 404). A Launcher credential is rejected by authentication.
	scope, ok := a.resolveListScope(w, r, auth, principalFilter)
	if !ok {
		return
	}
	var principalID *int64
	principalName := ""
	if !scope.allPrincipals {
		id := int64(scope.principal.ID)
		principalID = &id
		principalName = scope.principal.Username
	}

	creds, err := listPrincipalCredentialsForScope(a.DB, principalID)
	duration := time.Since(started).Round(time.Millisecond).String()
	if err != nil {
		writeControlAudit(ctx, auditRecord{
			Event:         "principal.credential_list",
			PrincipalName: principalName,
			Result:        "error",
			Duration:      duration,
		}, auth)
		opLog(ctx).Error("credential list failed",
			slog.String("operation", "credential_list"),
			slog.String("error", err.Error()),
		)
		writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}

	resp := listPrincipalCredentialsResponse{
		OK:          true,
		Credentials: make([]principalCredentialJSON, 0, len(creds)),
	}
	for _, c := range creds {
		resp.Credentials = append(resp.Credentials, principalCredentialToJSON(c))
	}

	writeControlAudit(ctx, auditRecord{
		Event:         "principal.credential_list",
		PrincipalName: principalName,
		Result:        "success",
		Duration:      duration,
	}, auth)

	writeJSONRaw(ctx, w, http.StatusOK, resp)
}

// handleRotatePrincipalCredential rotates the named Principal credential in
// one atomic server-side operation: the old bearer token is invalidated and
// the new one is returned exactly once. The credential ID, name, and ownership
// are unchanged. Scope-aware: an admin token may rotate any principal's
// credential; a Principal credential may rotate only its own principal's.
func (a *App) handleRotatePrincipalCredential(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	auth, err := a.authenticateControlRequest(w, r, "credential")
	if err != nil || auth == nil {
		return
	}

	ctx := r.Context()

	username := r.PathValue("username")
	if username == "" {
		writeControlAudit(ctx, auditRecord{
			Event:    "principal.credential_rotate",
			Result:   "missing_username",
			Duration: time.Since(started).Round(time.Millisecond).String(),
		}, auth)
		writeError(ctx, w, http.StatusBadRequest, "missing_username", "username is required")
		return
	}
	name := r.PathValue("name")
	if name == "" {
		writeControlAudit(ctx, auditRecord{
			Event:         "principal.credential_rotate",
			PrincipalName: username,
			Result:        "missing_credential_name",
			Duration:      time.Since(started).Round(time.Millisecond).String(),
		}, auth)
		writeError(ctx, w, http.StatusBadRequest, "missing_credential_name", "credential name is required")
		return
	}

	// The target Principal is resolved under the request authority before any
	// mutation: a Principal credential can only target its own Principal and
	// any other username is a non-disclosing 404.
	p, ok := a.resolveControlPrincipal(w, r, auth, username)
	if !ok {
		return
	}

	cred, token, err := rotatePrincipalCredential(a.DB, p.Username, name)
	duration := time.Since(started).Round(time.Millisecond).String()

	if err != nil {
		writeControlAudit(ctx, auditRecord{
			Event:          "principal.credential_rotate",
			PrincipalName:  p.Username,
			CredentialName: name,
			Result:         "error",
			Duration:       duration,
		}, auth)
		switch {
		case isErrCredentialNotFound(err):
			writeError(ctx, w, http.StatusNotFound, "credential_not_found", "credential not found")
		case errors.Is(err, ErrCredentialRevoked):
			writeError(ctx, w, http.StatusConflict, "credential_revoked", "credential is revoked")
		default:
			opLog(ctx).Error("credential rotate failed",
				slog.String("operation", "credential_rotate"),
				slog.String("error", err.Error()),
			)
			writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		}
		return
	}

	writeControlAudit(ctx, auditRecord{
		Event:          "principal.credential_rotate",
		PrincipalName:  cred.PrincipalName,
		CredentialID:   cred.ID,
		CredentialName: cred.Name,
		Result:         "success",
		Duration:       duration,
	}, auth)

	writeJSONRaw(ctx, w, http.StatusOK, principalCredentialTokenResponse{
		OK:         true,
		Credential: principalCredentialToJSON(*cred),
		Token:      token,
	})
}

func (a *App) handleRevokePrincipalCredential(w http.ResponseWriter, r *http.Request) {
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
	cred, preReadErr := findPrincipalCredentialByID(a.DB, id)
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

	changed, err := revokePrincipalCredential(a.DB, id)
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

	resp := revokePrincipalCredentialResponse{
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
