package main

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

type sessionRequest struct {
	Workspace string `json:"workspace"`
}

type sessionJSON struct {
	ID        string `json:"id"`
	Workspace string `json:"workspace"`
	CreatedAt string `json:"created_at"`
	ExpiresAt string `json:"expires_at"`
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
	return sessionJSON{
		ID:        s.ID,
		Workspace: s.Workspace,
		CreatedAt: s.CreatedAt.Format(time.RFC3339),
		ExpiresAt: s.ExpiresAt.Format(time.RFC3339),
	}
}

func (a *App) handleCreateSession(w http.ResponseWriter, r *http.Request) {
	started := time.Now()

	if !a.requireAdmin(w, r) {
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

	result, err := a.createSession(req.Workspace)
	duration := time.Since(started).Round(time.Millisecond).String()

	if err != nil {
		resultCode := classifyCreateSessionError(err)
		writeAuditWithRequestID(ctx, auditRecord{
			Event:     "session.create",
			Workspace: req.Workspace,
			Result:    resultCode,
			Duration:  duration,
		})

		if errors.Is(err, ErrInvalidWorkspace) {
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

	writeAuditWithRequestID(ctx, auditRecord{
		Event:     "session.create",
		SessionID: result.Session.ID,
		Workspace: result.Session.Workspace,
		Result:    "success",
		Duration:  duration,
	})

	writeJSONRaw(ctx, w, http.StatusCreated, createSessionResponse{
		OK:      true,
		Session: sessionToJSON(result.Session),
		Token:   result.Token,
	})
}

func (a *App) handleListSessions(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdmin(w, r) {
		return
	}

	ctx := r.Context()

	sessions, err := a.listSessions()
	if err != nil {
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

	writeJSONRaw(ctx, w, http.StatusOK, resp)
}

func (a *App) handleDeleteSession(w http.ResponseWriter, r *http.Request) {
	started := time.Now()

	if !a.requireAdmin(w, r) {
		return
	}

	ctx := r.Context()

	id := strings.TrimPrefix(r.URL.Path, "/sessions/")
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

	session, err := a.deleteSession(id)
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

	writeAuditWithRequestID(ctx, auditRecord{
		Event:     "session.delete",
		SessionID: session.ID,
		Workspace: session.Workspace,
		Result:    "success",
		Duration:  duration,
	})

	w.WriteHeader(http.StatusNoContent)
}
