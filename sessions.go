package main

import (
	"encoding/json"
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
	var req sessionRequest

	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	result, err := a.createSession(req.Workspace)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSONRaw(w, http.StatusCreated, createSessionResponse{
		OK:      true,
		Session: sessionToJSON(result.Session),
		Token:   result.Token,
	})
}

func (a *App) handleListSessions(w http.ResponseWriter, r *http.Request) {
	sessions, err := a.listSessions()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
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
	id := strings.TrimPrefix(r.URL.Path, "/sessions/")
	if id == "" {
		writeError(w, http.StatusBadRequest, "session id is required")
		return
	}

	deleted, err := a.deleteSession(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if !deleted {
		writeError(w, http.StatusNotFound, "session not found")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
