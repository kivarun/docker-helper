package main

import (
	"encoding/json"
	"errors"
	"log"
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

	var req sessionRequest

	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&req); err != nil {
		duration := time.Since(started).Round(time.Millisecond).String()
		writeAudit(auditRecord{
			Event:    "session.create",
			Result:   "invalid_json",
			Duration: duration,
		})
		writeError(w, http.StatusBadRequest, "invalid_json", "invalid JSON request")
		return
	}

	result, err := a.createSession(req.Workspace)
	duration := time.Since(started).Round(time.Millisecond).String()

	if err != nil {
		resultCode := classifyCreateSessionError(err)
		writeAudit(auditRecord{
			Event:     "session.create",
			Workspace: req.Workspace,
			Result:    resultCode,
			Duration:  duration,
		})

		if errors.Is(err, ErrInvalidWorkspace) {
			writeError(w, http.StatusBadRequest, "invalid_workspace", "invalid workspace")
		} else {
			log.Printf("session creation error: %v", err)
			writeError(w, http.StatusInternalServerError, "internal_error", "internal server error")
		}
		return
	}

	writeAudit(auditRecord{
		Event:     "session.create",
		SessionID: result.Session.ID,
		Workspace: result.Session.Workspace,
		Result:    "success",
		Duration:  duration,
	})

	writeJSONRaw(w, http.StatusCreated, createSessionResponse{
		OK:      true,
		Session: sessionToJSON(result.Session),
		Token:   result.Token,
	})
}

func (a *App) handleListSessions(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdmin(w, r) {
		return
	}

	sessions, err := a.listSessions()
	if err != nil {
		log.Printf("list sessions error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}

	resp := listSessionsResponse{
		OK:       true,
		Sessions: make([]sessionJSON, 0, len(sessions)),
	}

	for _, s := range sessions {
		resp.Sessions = append(resp.Sessions, sessionToJSON(s))
	}

	writeJSONRaw(w, http.StatusOK, resp)
}

func (a *App) handleDeleteSession(w http.ResponseWriter, r *http.Request) {
	started := time.Now()

	if !a.requireAdmin(w, r) {
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/sessions/")
	if id == "" {
		duration := time.Since(started).Round(time.Millisecond).String()
		writeAudit(auditRecord{
			Event:    "session.delete",
			Result:   "invalid_session_id",
			Duration: duration,
		})
		writeError(w, http.StatusBadRequest, "invalid_session_id", "session id is required")
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
		writeAudit(auditRec)

		if errors.Is(err, ErrSessionNotFound) {
			writeError(w, http.StatusNotFound, "session_not_found", "session not found")
		} else {
			log.Printf("delete session error: %v", err)
			writeError(w, http.StatusInternalServerError, "internal_error", "internal server error")
		}
		return
	}

	writeAudit(auditRecord{
		Event:     "session.delete",
		SessionID: session.ID,
		Workspace: session.Workspace,
		Result:    "success",
		Duration:  duration,
	})

	w.WriteHeader(http.StatusNoContent)
}
