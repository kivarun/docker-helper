package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

type response struct {
	OK       bool   `json:"ok"`
	Code     string `json:"code,omitempty"`
	Message  string `json:"message,omitempty"`
	Output   string `json:"output,omitempty"`
	Duration string `json:"duration,omitempty"`
	ExitCode *int   `json:"exit_code,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, value response) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(value); err != nil {
		opLogger.Error("failed to encode response", slog.String("error", err.Error()))
	}
}

func writeJSONRaw(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(value); err != nil {
		opLogger.Error("failed to encode response", slog.String("error", err.Error()))
	}
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, response{
		OK:      false,
		Code:    code,
		Message: message,
	})
}

func parseBearerToken(r *http.Request) (string, bool) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return "", false
	}

	if len(auth) < 8 || auth[:7] != "Bearer " {
		return "", false
	}

	token := auth[7:]
	if token == "" || strings.ContainsRune(token, ' ') || strings.ContainsRune(token, '\t') {
		return "", false
	}

	return token, true
}

func writeUnauthorizedAdmin(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	writeJSON(w, http.StatusUnauthorized, response{
		OK:      false,
		Code:    "unauthorized",
		Message: "Administrative authentication required.",
	})
}

func writeUnauthorizedSession(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	writeJSON(w, http.StatusUnauthorized, response{
		OK:      false,
		Code:    "unauthorized",
		Message: "Valid session authentication required.",
	})
}

func (a *App) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	ctx := r.Context()
	token, ok := parseBearerToken(r)
	if !ok {
		writeAuditWithRequestID(ctx, auditRecord{
			Time:      time.Now().UTC().Format(time.RFC3339),
			Stream:    "audit",
			Event:     "auth.failure",
			Method:    r.Method,
			Path:      r.URL.Path,
			RequestID: requestIDFromContext(ctx),
			Result:    "admin.parse_failed",
		})
		writeUnauthorizedAdmin(w)
		return false
	}

	tokenHash := sha256.Sum256([]byte(token))
	if subtle.ConstantTimeCompare(tokenHash[:], a.AdminTokenHash[:]) != 1 {
		writeAuditWithRequestID(ctx, auditRecord{
			Time:      time.Now().UTC().Format(time.RFC3339),
			Stream:    "audit",
			Event:     "auth.failure",
			Method:    r.Method,
			Path:      r.URL.Path,
			RequestID: requestIDFromContext(ctx),
			Result:    "admin.wrong_token",
		})
		writeUnauthorizedAdmin(w)
		return false
	}

	return true
}

func (a *App) requireSession(w http.ResponseWriter, r *http.Request) (*Session, bool) {
	ctx := r.Context()
	token, ok := parseBearerToken(r)
	if !ok {
		writeAuditWithRequestID(ctx, auditRecord{
			Time:      time.Now().UTC().Format(time.RFC3339),
			Stream:    "audit",
			Event:     "auth.failure",
			Method:    r.Method,
			Path:      r.URL.Path,
			RequestID: requestIDFromContext(ctx),
			Result:    "session.parse_failed",
		})
		writeUnauthorizedSession(w)
		return nil, false
	}

	session, err := a.findSessionByToken(token)
	if err != nil {
		resultCode := "session.not_found"
		if !errors.Is(err, ErrSessionNotFound) {
			resultCode = "session.database_error"
		}
		writeAuditWithRequestID(ctx, auditRecord{
			Time:      time.Now().UTC().Format(time.RFC3339),
			Stream:    "audit",
			Event:     "auth.failure",
			Method:    r.Method,
			Path:      r.URL.Path,
			RequestID: requestIDFromContext(ctx),
			Result:    resultCode,
		})

		if !errors.Is(err, ErrSessionNotFound) {
			opLog(ctx).Error("session lookup error",
				slog.String("operation", "session_lookup"),
				slog.String("error", err.Error()),
			)
			writeError(w, http.StatusInternalServerError, "internal_error", "internal server error")
		} else {
			writeUnauthorizedSession(w)
		}
		return nil, false
	}

	return session, true
}

func (a *App) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, response{
		OK:      true,
		Message: "docker-helper is running",
	})
}
