package main

import (
	"context"
	"crypto/sha256"
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

// writeInvalidOperatorAuthority reports an authenticated operator authority
// that is structurally invalid: an internal authentication anomaly, never an
// unauthorized credential. It is audited as <auditScope>.database_error and
// answered with the HTTP 500 internal_error contract, and the returned error
// stops the handler before any endpoint scope resolution. The operator
// authenticator emits only structurally valid authorities, so this is the
// fail-closed gate for an authority that reaches a request wrapper invalid
// anyway.
func writeInvalidOperatorAuthority(ctx context.Context, r *http.Request, w http.ResponseWriter, auditScope, operation string, authority *operatorAuthority) error {
	err := authority.validate()
	writeAuthFailure(ctx, r, auditScope+".database_error")
	opLog(ctx).Error("invalid operator authority",
		slog.String("operation", operation),
		slog.String("error", err.Error()),
	)
	writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
	return err
}

func (a *App) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	_, ok := a.requireAdminWithHash(w, r)
	return ok
}

// requireAdminWithHash authenticates the request and returns the hash of the
// authorizing token on success. The caller can use this hash to verify the
// token is still current at a later commit point (e.g., rotation). It is the
// dedicated admin-only request wrapper over the shared matchAdminToken
// primitive: a non-admin bearer is answered from the token comparison alone
// and never causes a credential database lookup.
func (a *App) requireAdminWithHash(w http.ResponseWriter, r *http.Request) ([sha256.Size]byte, bool) {
	ctx := r.Context()
	token, ok := parseBearerToken(r)
	if !ok {
		writeAuthFailure(ctx, r, "admin.parse_failed")
		writeUnauthorizedAdmin(ctx, w)
		return [sha256.Size]byte{}, false
	}

	tokenHash, matched := a.matchAdminToken(token)
	if !matched {
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

// sessionFilesystemAuthority is the immutable coherent data-plane filesystem
// authority for one filesystem-consuming request: the authenticated live
// Session plus its persisted immutable filesystem snapshot, captured together
// in one short read transaction. A concurrent Session deletion linearizing
// after the read transaction does not invalidate the captured authority.
type sessionFilesystemAuthority struct {
	Session  *Session
	Snapshot *sessionFilesystemSnapshot
}

// sessionAuthorityCaptureClass distinguishes the outcomes of the
// transactional Session filesystem-authority capture so every caller keeps
// its own established audit and wire contract. The classes mirror the
// capture's three failure points (begin, live-Session lookup, snapshot load,
// commit) plus the non-disclosing live-lookup miss: not_found routes a
// non-Session bearer onward instead of failing the request, while the other
// classes fail closed.
type sessionAuthorityCaptureClass int

const (
	// sessionAuthorityCaptureNotFound means the bearer is not a live
	// Session credential: unknown, expired, revoked-by-ownership, or
	// structurally not a Session token at all. It is an expected
	// non-disclosing outcome, never a database failure.
	sessionAuthorityCaptureNotFound sessionAuthorityCaptureClass = iota
	// sessionAuthorityCaptureLookupDB is a database failure of the live
	// Session lookup itself (the audited database-error case).
	sessionAuthorityCaptureLookupDB
	// sessionAuthorityCaptureIntegrity is a snapshot load failure after a
	// successful live lookup: the corrupted-issued-snapshot integrity
	// failure with the Session provenance attached.
	sessionAuthorityCaptureIntegrity
	// sessionAuthorityCaptureBegin is a transaction begin failure (not an
	// authentication outcome; not audited as auth.failure).
	sessionAuthorityCaptureBegin
	// sessionAuthorityCaptureCommit is a commit failure of the captured
	// authority (not an authentication outcome; not audited as
	// auth.failure).
	sessionAuthorityCaptureCommit
)

// sessionAuthorityCaptureError carries one failed filesystem-authority
// capture: the failure class, the underlying cause, the operational log
// message the caller logs for a database failure, and the captured Session
// provenance where the capture had it (integrity rejections, commit
// failures). A nil error from the capture owner means success.
type sessionAuthorityCaptureError struct {
	class   sessionAuthorityCaptureClass
	cause   error
	logMsg  string
	session *Session
}

// captureSessionFilesystemAuthority is the transactional owner of the
// Session filesystem-authority read: one short read transaction carrying the
// Session bearer authentication (findSessionByTokenQuerier) and the persisted
// immutable filesystem snapshot (loadSessionFilesystemSnapshot), so the two
// reads cannot observe different database generations. A concurrent Session
// deletion linearizing after the read transaction does not invalidate the
// captured authority. The transaction ends when the authority is captured;
// it is never held across filesystem I/O, pinning, staging, or Docker
// execution. The caller owns its own wire and audit contracts and maps the
// capture error classes onto them.
func (a *App) captureSessionFilesystemAuthority(token string) (*sessionFilesystemAuthority, *sessionAuthorityCaptureError) {
	tx, err := a.DB.Begin()
	if err != nil {
		return nil, &sessionAuthorityCaptureError{
			class:  sessionAuthorityCaptureBegin,
			cause:  err,
			logMsg: "cannot begin session filesystem authority read",
		}
	}

	session, err := findSessionByTokenQuerier(tx, token)
	if err != nil {
		tx.Rollback()
		if errors.Is(err, ErrSessionNotFound) {
			return nil, &sessionAuthorityCaptureError{
				class: sessionAuthorityCaptureNotFound,
				cause: err,
			}
		}
		return nil, &sessionAuthorityCaptureError{
			class:  sessionAuthorityCaptureLookupDB,
			cause:  err,
			logMsg: "session lookup error",
		}
	}

	snapshot, err := loadSessionFilesystemSnapshot(tx, session.ID, session.Workspace)
	if err != nil {
		tx.Rollback()
		return nil, &sessionAuthorityCaptureError{
			class:   sessionAuthorityCaptureIntegrity,
			cause:   err,
			session: session,
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, &sessionAuthorityCaptureError{
			class:   sessionAuthorityCaptureCommit,
			cause:   err,
			logMsg:  "cannot commit session filesystem authority read",
			session: session,
		}
	}

	return &sessionFilesystemAuthority{Session: session, Snapshot: snapshot}, nil
}

// requireSessionFilesystemCapability is the filesystem-capability variant of
// requireSessionCapability for the data-plane requests that consume a
// Session-controlled host filesystem source. kind names the consuming
// operation family ("run" or "build") for the symmetric rejection/audit
// contract below. It reads the Session bearer authentication and the
// persisted filesystem snapshot in one short read transaction through the
// transactional capture owner (captureSessionFilesystemAuthority), so the
// two reads cannot observe different database generations: a Session
// deletion or invalidation that commits concurrently either linearizes
// before the read transaction (the lookup fails closed with 401) or after
// the captured authority (the already-started request continues). A split
// read — an authenticated Session whose snapshot vanished through the
// deletion cascade — is structurally impossible.
//
// Snapshot load failure after a successful auth query is a state/integrity
// failure, not an authentication outcome: it fails closed with 500
// internal_error and never with 401 or a mount-policy code. The pathless
// data-plane actions (pull, registry login, operation status/logs/cancel)
// keep using requireSessionCapability because they consume no
// Session-controlled host filesystem source.
func (a *App) requireSessionFilesystemCapability(w http.ResponseWriter, r *http.Request, kind string) (*sessionFilesystemAuthority, bool) {
	ctx := r.Context()
	token, ok := parseBearerToken(r)
	if !ok {
		writeAuthFailure(ctx, r, "session.parse_failed")
		writeUnauthorizedSessionCapability(ctx, w)
		return nil, false
	}

	authority, cerr := a.captureSessionFilesystemAuthority(token)
	if cerr != nil {
		switch cerr.class {
		case sessionAuthorityCaptureNotFound:
			writeAuthFailure(ctx, r, "session.not_found")
			writeUnauthorizedSessionCapability(ctx, w)
		case sessionAuthorityCaptureIntegrity:
			// A corrupted issued snapshot is an internal integrity
			// failure, not an authentication or mount-policy outcome,
			// and is never repaired at request time. The audit keeps
			// exactly one <kind>.rejected record with the session
			// provenance so the failure does not vanish.
			writeSessionFilesystemAuthorityRejected(ctx, w, kind, cerr.session, cerr.cause)
		default:
			writeAuthFailure(ctx, r, "session.database_error")
			logArgs := []any{
				slog.String("operation", "session_lookup"),
				slog.String("error", cerr.cause.Error()),
			}
			if cerr.session != nil {
				logArgs = append(logArgs, slog.String("session_id", cerr.session.ID))
			}
			opLog(ctx).Error(cerr.logMsg, logArgs...)
			writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		}
		return nil, false
	}

	return authority, true
}

func (a *App) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(r.Context(), w, http.StatusOK, response{
		OK:      true,
		Message: "docker-helper is running",
	})
}
