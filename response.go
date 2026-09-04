package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
)

const maxRequestBody = 16 * 1024

// decodeJSONRequest decodes exactly one JSON value from the request body
// into target.  It enforces a body size limit, rejects unknown fields,
// and requires EOF (after optional whitespace) following the first value.
func decodeJSONRequest(w http.ResponseWriter, r *http.Request, target any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBody))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(target); err != nil {
		return err
	}

	// Verify no trailing content after the first JSON value.
	// A successful decode means another JSON value follows.
	// io.EOF means only whitespace remained (acceptable).
	// Any other error means non-JSON garbage follows.
	var dummy struct{}
	if err := decoder.Decode(&dummy); err != nil {
		if err == io.EOF {
			return nil
		}
		return errors.New("trailing data after JSON value")
	}
	return errors.New("trailing data after JSON value")
}

type response struct {
	OK       bool   `json:"ok"`
	Code     string `json:"code,omitempty"`
	Message  string `json:"message,omitempty"`
	Output   string `json:"output,omitempty"`
	Duration string `json:"duration,omitempty"`
	ExitCode *int   `json:"exit_code,omitempty"`
}

func writeJSON(ctx context.Context, w http.ResponseWriter, status int, value response) {
	writeJSONRaw(ctx, w, status, value)
}

func writeJSONRaw(ctx context.Context, w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(value); err != nil {
		writeJSONError(ctx, err)
	}
}

func writeOperationCreated(ctx context.Context, w http.ResponseWriter, operationID string, status operationState) {
	writeJSONRaw(ctx, w, http.StatusCreated, operationCreatedResponse{
		OK:          true,
		OperationID: operationID,
		Status:      status,
	})
}

func writeError(ctx context.Context, w http.ResponseWriter, status int, code, message string) {
	writeJSON(ctx, w, status, response{
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

func writeUnauthorizedAdmin(ctx context.Context, w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	writeJSON(ctx, w, http.StatusUnauthorized, response{
		OK:      false,
		Code:    "unauthorized",
		Message: "Administrative authentication required.",
	})
}

func writeUnauthorizedSessionCapability(ctx context.Context, w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	writeJSON(ctx, w, http.StatusUnauthorized, response{
		OK:      false,
		Code:    "unauthorized",
		Message: "Session authentication required.",
	})
}

func writeUnauthorizedSessionControl(ctx context.Context, w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	writeJSON(ctx, w, http.StatusUnauthorized, response{
		OK:      false,
		Code:    "unauthorized",
		Message: "Authentication required for session management.",
	})
}

// writeUnauthorizedControl writes the non-disclosing unauthorized response
// for a Principal-owned resource control plane. Each family keeps its own
// established message contract (launcher management, credential management).
func writeUnauthorizedControl(ctx context.Context, w http.ResponseWriter, message string) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	writeJSON(ctx, w, http.StatusUnauthorized, response{
		OK:      false,
		Code:    "unauthorized",
		Message: message,
	})
}

// writeUnauthorizedAuth writes the non-disclosing unauthorized response for
// GET /auth operator auth introspection.
func writeUnauthorizedAuth(ctx context.Context, w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	writeJSON(ctx, w, http.StatusUnauthorized, response{
		OK:      false,
		Code:    "unauthorized",
		Message: "Authentication required.",
	})
}

func writeAuthFailure(ctx context.Context, r *http.Request, result string) {
	writeRequestContextAudit(ctx, auditRecord{
		Event:  "auth.failure",
		Method: r.Method,
		Path:   r.URL.Path,
		Result: result,
	})
}

func (a *App) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	_, ok := a.requireAdminWithHash(w, r)
	return ok
}

// requireAdminWithHash authenticates the request and returns the hash of the
// authorizing token on success. The caller can use this hash to verify the
// token is still current at a later commit point (e.g., rotation).
func (a *App) requireAdminWithHash(w http.ResponseWriter, r *http.Request) ([sha256.Size]byte, bool) {
	ctx := r.Context()
	token, ok := parseBearerToken(r)
	if !ok {
		writeAuthFailure(ctx, r, "admin.parse_failed")
		writeUnauthorizedAdmin(ctx, w)
		return [sha256.Size]byte{}, false
	}

	tokenHash := sha256.Sum256([]byte(token))
	currentHash := a.getAdminTokenHash()
	if subtle.ConstantTimeCompare(tokenHash[:], currentHash[:]) != 1 {
		writeAuthFailure(ctx, r, "admin.wrong_token")
		writeUnauthorizedAdmin(ctx, w)
		return [sha256.Size]byte{}, false
	}

	return tokenHash, true
}

// requireSessionCapability authenticates a Session bearer token for data-plane
// actions such as run, build, pull, registry login, and operation access.
func (a *App) requireSessionCapability(w http.ResponseWriter, r *http.Request) (*Session, bool) {
	ctx := r.Context()
	token, ok := parseBearerToken(r)
	if !ok {
		writeAuthFailure(ctx, r, "session.parse_failed")
		writeUnauthorizedSessionCapability(ctx, w)
		return nil, false
	}

	session, err := a.findSessionByToken(token)
	if err != nil {
		resultCode := "session.not_found"
		if !errors.Is(err, ErrSessionNotFound) {
			resultCode = "session.database_error"
		}
		writeAuthFailure(ctx, r, resultCode)

		if !errors.Is(err, ErrSessionNotFound) {
			opLog(ctx).Error("session lookup error",
				slog.String("operation", "session_lookup"),
				slog.String("error", err.Error()),
			)
			writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		} else {
			writeUnauthorizedSessionCapability(ctx, w)
		}
		return nil, false
	}

	return session, true
}

func (a *App) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(r.Context(), w, http.StatusOK, response{
		OK:      true,
		Message: "docker-helper is running",
	})
}
