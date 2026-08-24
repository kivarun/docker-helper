package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"
	"time"
)

type sessionRequest struct {
	Workspace string `json:"workspace"`
}

type sessionJSON struct {
	ID            string  `json:"id"`
	Workspace     string  `json:"workspace"`
	CreatedAt     string  `json:"created_at"`
	ExpiresAt     string  `json:"expires_at"`
	PrincipalName *string `json:"principal,omitempty"`
}

type createSessionResponse struct {
	OK      bool        `json:"ok"`
	Session sessionJSON `json:"session"`
	Token   string      `json:"token"`
}

type listSessionsResponse struct {
	OK       bool          `json:"ok"`
	Sessions []sessionJSON `json:"sessions"`
}

func sessionToJSON(s Session) sessionJSON {
	principalName := (*string)(nil)
	if s.PrincipalName != "" {
		principalName = &s.PrincipalName
	}
	return sessionJSON{
		ID:            s.ID,
		Workspace:     s.Workspace,
		CreatedAt:     s.CreatedAt.Format(time.RFC3339),
		ExpiresAt:     s.ExpiresAt.Format(time.RFC3339),
		PrincipalName: principalName,
	}
}

// sessionControlAuthority represents the authenticated authority for session
// control operations: create, list, and delete sessions.
type sessionControlAuthority struct {
	isAdmin             bool
	principalCredential *CredentialAuthResult
}

// authenticateSessionControlRequest tries admin token first, then Principal
// credential. It returns the authority context on success.
func (a *App) authenticateSessionControlRequest(w http.ResponseWriter, r *http.Request) (*sessionControlAuthority, error) {
	ctx := r.Context()

	// Parse the Authorization header.
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		writeAuthFailure(ctx, r, "parse_failed")
		writeUnauthorizedSessionControl(ctx, w)
		return nil, nil
	}

	token, ok := parseBearerToken(r)
	if !ok {
		writeAuthFailure(ctx, r, "parse_failed")
		writeUnauthorizedSessionControl(ctx, w)
		return nil, nil
	}

	if token == "" {
		writeAuthFailure(ctx, r, "parse_failed")
		writeUnauthorizedSessionControl(ctx, w)
		return nil, nil
	}

	// Check admin token.
	tokenHash := sha256.Sum256([]byte(token))
	currentHash := a.getAdminTokenHash()
	if subtle.ConstantTimeCompare(tokenHash[:], currentHash[:]) == 1 {
		return &sessionControlAuthority{isAdmin: true}, nil
	}

	// Try Principal credential.
	authResult, err := authenticateCredential(a.DB, token)
	if err == nil {
		return &sessionControlAuthority{principalCredential: authResult}, nil
	}

	// Credential auth failed. Check if it's a database error.
	if !errors.Is(err, ErrCredentialNotFound) &&
		!errors.Is(err, ErrCredentialRevoked) &&
		!errors.Is(err, ErrCredentialDisabled) {
		writeAuditWithRequestID(ctx, auditRecord{
			Event:  "auth.session",
			Result: "database_error",
		})
		opLog(ctx).Error("session control auth database error",
			slog.String("operation", "session_auth"),
			slog.String("error", err.Error()),
		)
		writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		return nil, err
	}

	// Single auth failure for any credential reason.
	resultCode := "credential.not_found"
	if errors.Is(err, ErrCredentialRevoked) {
		resultCode = "credential.revoked"
	} else if errors.Is(err, ErrCredentialDisabled) {
		resultCode = "credential.disabled"
	}
	writeAuthFailure(ctx, r, resultCode)
	writeUnauthorizedSessionControl(ctx, w)
	return nil, err
}

func (a *App) handleCreateSession(w http.ResponseWriter, r *http.Request) {
	started := time.Now()

	authCtx, err := a.authenticateSessionControlRequest(w, r)
	if err != nil || authCtx == nil {
		return
	}

	ctx := r.Context()

	var req sessionRequest

	if err := decodeJSONRequest(w, r, &req); err != nil {
		duration := time.Since(started).Round(time.Millisecond).String()
		writeAuditWithRequestID(ctx, auditRecord{
			Event:    "session.create",
			Result:   "invalid_json",
			Duration: duration,
		})
		writeError(ctx, w, http.StatusBadRequest, "invalid_json", "invalid JSON request")
		return
	}

	var result *CreatedSession

	if authCtx.isAdmin {
		result, err = a.createSession(req.Workspace)
	} else {
		auth := authCtx.principalCredential
		globalRoots := a.getConfig().AllowedRoots
		result, err = a.createSessionWithPolicy(&sessionCreatePolicy{
			Workspace:    req.Workspace,
			AllowedRoots: intersectRoots(globalRoots, auth.AllowedRoots),
			PrincipalID:  &auth.PrincipalID,
		})
	}

	duration := time.Since(started).Round(time.Millisecond).String()

	if err != nil {
		resultCode := classifyCreateSessionError(err)
		auditRec := auditRecord{
			Event:     "session.create",
			Workspace: req.Workspace,
			Result:    resultCode,
			Duration:  duration,
		}
		if !authCtx.isAdmin && authCtx.principalCredential != nil {
			auditRec.PrincipalName = authCtx.principalCredential.PrincipalName
			auditRec.CredentialID = authCtx.principalCredential.CredentialID
		}
		writeAuditWithRequestID(ctx, auditRec)

		if errors.Is(err, ErrInvalidWorkspace) {
			// Log the internal cause to the operational log.
			// The client receives the generic invalid_workspace response.
			opLog(ctx).Warn("session creation rejected",
				slog.String("operation", "session_create"),
				slog.String("error", err.Error()),
			)
			writeError(ctx, w, http.StatusBadRequest, "invalid_workspace", "invalid workspace")
		} else {
			opLog(ctx).Error("session creation error",
				slog.String("operation", "session_create"),
				slog.String("error", err.Error()),
			)
			writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		}
		return
	}

	auditRec := auditRecord{
		Event:     "session.create",
		SessionID: result.Session.ID,
		Workspace: result.Session.Workspace,
		Result:    "success",
		Duration:  duration,
	}
	if !authCtx.isAdmin && authCtx.principalCredential != nil {
		auditRec.PrincipalName = authCtx.principalCredential.PrincipalName
		auditRec.CredentialID = authCtx.principalCredential.CredentialID
		// Populate principal name in the session for the response.
		result.Session.PrincipalName = authCtx.principalCredential.PrincipalName
	}
	writeAuditWithRequestID(ctx, auditRec)

	writeJSONRaw(ctx, w, http.StatusCreated, createSessionResponse{
		OK:      true,
		Session: sessionToJSON(result.Session),
		Token:   result.Token,
	})
}

func (a *App) handleListSessions(w http.ResponseWriter, r *http.Request) {
	started := time.Now()

	authCtx, err := a.authenticateSessionControlRequest(w, r)
	if err != nil || authCtx == nil {
		return
	}

	ctx := r.Context()

	var sessions []Session

	if authCtx.isAdmin {
		sessions, err = a.listSessions()
	} else {
		auth := authCtx.principalCredential
		sessions, err = a.listSessionsForPrincipal(auth.PrincipalID)
	}

	duration := time.Since(started).Round(time.Millisecond).String()

	if err != nil {
		auditRec := auditRecord{
			Event:    "session.list",
			Result:   "database_error",
			Duration: duration,
		}
		if !authCtx.isAdmin && authCtx.principalCredential != nil {
			auditRec.PrincipalName = authCtx.principalCredential.PrincipalName
			auditRec.CredentialID = authCtx.principalCredential.CredentialID
		}
		writeAuditWithRequestID(ctx, auditRec)
		opLog(ctx).Error("list sessions error",
			slog.String("operation", "session_list"),
			slog.String("error", err.Error()),
		)
		writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}

	resp := listSessionsResponse{
		OK:       true,
		Sessions: make([]sessionJSON, 0, len(sessions)),
	}

	for _, s := range sessions {
		resp.Sessions = append(resp.Sessions, sessionToJSON(s))
	}

	auditRec := auditRecord{
		Event:    "session.list",
		Result:   "success",
		Duration: duration,
	}
	if !authCtx.isAdmin && authCtx.principalCredential != nil {
		auditRec.PrincipalName = authCtx.principalCredential.PrincipalName
		auditRec.CredentialID = authCtx.principalCredential.CredentialID
	}
	writeAuditWithRequestID(ctx, auditRec)

	writeJSONRaw(ctx, w, http.StatusOK, resp)
}

func (a *App) handleDeleteSession(w http.ResponseWriter, r *http.Request) {
	started := time.Now()

	authCtx, err := a.authenticateSessionControlRequest(w, r)
	if err != nil || authCtx == nil {
		return
	}

	ctx := r.Context()

	id := r.PathValue("id")
	if id == "" {
		duration := time.Since(started).Round(time.Millisecond).String()
		writeAuditWithRequestID(ctx, auditRecord{
			Event:    "session.delete",
			Result:   "invalid_session_id",
			Duration: duration,
		})
		writeError(ctx, w, http.StatusBadRequest, "invalid_session_id", "session id is required")
		return
	}

	var session *Session

	if authCtx.isAdmin {
		session, err = a.deleteSession(id)
	} else {
		auth := authCtx.principalCredential
		session, err = a.deleteSessionForPrincipal(id, auth.PrincipalID)
	}

	duration := time.Since(started).Round(time.Millisecond).String()

	if err != nil {
		var resultCode string
		var workspace string

		switch {
		case errors.Is(err, ErrSessionNotFound):
			resultCode = "not_found"
		case errors.Is(err, ErrDatabase):
			resultCode = "database_error"
			if session != nil {
				workspace = session.Workspace
			}
		default:
			resultCode = "unknown_error"
		}

		auditRec := auditRecord{
			Event:     "session.delete",
			SessionID: id,
			Result:    resultCode,
			Duration:  duration,
		}
		if workspace != "" {
			auditRec.Workspace = workspace
		}
		if !authCtx.isAdmin && authCtx.principalCredential != nil {
			auditRec.PrincipalName = authCtx.principalCredential.PrincipalName
			auditRec.CredentialID = authCtx.principalCredential.CredentialID
		}
		writeAuditWithRequestID(ctx, auditRec)

		if errors.Is(err, ErrSessionNotFound) {
			writeError(ctx, w, http.StatusNotFound, "session_not_found", "session not found")
		} else {
			opLog(ctx).Error("delete session error",
				slog.String("operation", "session_delete"),
				slog.String("error", err.Error()),
			)
			writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		}
		return
	}

	auditRec := auditRecord{
		Event:     "session.delete",
		SessionID: id,
		Result:    "success",
		Duration:  duration,
	}
	if session != nil {
		auditRec.Workspace = session.Workspace
	}
	if !authCtx.isAdmin && authCtx.principalCredential != nil {
		auditRec.PrincipalName = authCtx.principalCredential.PrincipalName
		auditRec.CredentialID = authCtx.principalCredential.CredentialID
	}
	writeAuditWithRequestID(ctx, auditRec)

	// Clean up session runtime directory (Docker config, etc.) best-effort.
	// Cleanup failure must not fail the already-deleted session.
	cfg := a.getConfig()
	if err := cleanupSessionRuntimeDir(cfg.RuntimeDir, id); err != nil {
		opLog(ctx).Warn("cannot remove session runtime directory",
			slog.String("operation", "session_delete"),
			slog.String("session_id", id),
			slog.String("error", err.Error()),
		)
	}

	w.WriteHeader(http.StatusNoContent)
}
