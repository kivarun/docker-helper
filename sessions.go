package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// sessionSelectorField is a Session-request-specific optional string selector
// field that tracks true field presence. It distinguishes a field that is
// omitted (present false) from one supplied as "" (present true, value "").
// JSON null or any non-string value is recorded as present but invalid rather
// than silently treated as omitted. Value validity is interpreted only by
// validateCreateSelector, so structural conflict (both selector fields present)
// takes precedence over an individually invalid value. This is deliberately a
// narrow Session-request mechanism, not a generic Optional[T].
type sessionSelectorField struct {
	present bool
	invalid bool
	value   string
}

func (s *sessionSelectorField) UnmarshalJSON(b []byte) error {
	s.present = true
	s.invalid = false
	trimmed := bytes.TrimSpace(b)
	if bytes.Equal(trimmed, []byte("null")) {
		s.invalid = true
		return nil
	}
	var v string
	if err := json.Unmarshal(b, &v); err != nil {
		s.invalid = true
		return nil
	}
	s.value = v
	return nil
}

// isPresent reports whether the selector field was present in the request.
func (s *sessionSelectorField) isPresent() bool { return s.present }

// isInvalid reports whether the present selector value was malformed (null or
// non-string), distinct from an explicitly-empty string.
func (s *sessionSelectorField) isInvalid() bool { return s.invalid }

// selectorOrEmpty returns the selector value, or "" if it was omitted.
func (s *sessionSelectorField) selectorOrEmpty() string { return s.value }

type sessionRequest struct {
	Workspace       string                        `json:"workspace"`
	LauncherID      sessionSelectorField          `json:"launcher_id"`
	Principal       sessionSelectorField          `json:"principal"`
	FilesystemRoots sessionFilesystemRootsRequest `json:"filesystem_roots"`
}

// validateCreateSelector applies the Session create-selector contract to the
// presence-aware request fields and returns a normalized createSelector with
// only non-empty, explicitly-supplied values. Structural conflict has
// precedence over value validation: both fields explicitly present is always a
// conflicting_selectors error before any value/lookup check. An explicitly
// present but empty selector is an invalid_selector error.
func (req sessionRequest) validateCreateSelector() (createSelector, *createTargetError) {
	launcherPresent := req.LauncherID.isPresent()
	principalPresent := req.Principal.isPresent()

	if launcherPresent && principalPresent {
		return createSelector{}, &createTargetError{status: http.StatusBadRequest, code: "conflicting_selectors", msg: "launcher_id and principal selectors cannot both be provided"}
	}
	if launcherPresent && (req.LauncherID.isInvalid() || req.LauncherID.selectorOrEmpty() == "") {
		return createSelector{}, &createTargetError{status: http.StatusBadRequest, code: "invalid_selector", msg: "invalid session selector"}
	}
	if principalPresent && (req.Principal.isInvalid() || req.Principal.selectorOrEmpty() == "") {
		return createSelector{}, &createTargetError{status: http.StatusBadRequest, code: "invalid_selector", msg: "invalid session selector"}
	}
	return createSelector{launcherID: req.LauncherID.selectorOrEmpty(), principal: req.Principal.selectorOrEmpty()}, nil
}

// sessionFilesystemRootEntry is one caller-supplied issuance-time filesystem
// root of a Session create request: an absolute host path and the canonical
// access value. Path is resolved and converted to the canonical policy
// identity by the Session lifecycle; this type is the caller-supplied wire
// value only.
type sessionFilesystemRootEntry struct {
	Path   string `json:"path"`
	Access string `json:"access"`
}

// sessionFilesystemRootsRequest is the presence-aware optional
// filesystem_roots field of the Session create request. Occurrence and
// validity are distinct facts: omitted and the empty array preserve the
// inherited create behavior, while null and every malformed shape are an
// explicit refused request. Structural defects (JSON null, a non-array
// value, an unknown nested field, a malformed entry type, trailing data
// inside the array) are recorded as request state rather than decode
// errors, so every malformed Session filesystem request is refused with
// the one issuance-time invalid_filesystem_policy contract instead of the
// generic invalid_json shape.
type sessionFilesystemRootsRequest struct {
	present   bool
	malformed bool
	roots     []sessionFilesystemRootEntry
}

// UnmarshalJSON marks the field present on any occurrence and captures the
// request state leniently: JSON null and structurally invalid arrays become
// request state refused later by the handler, never a decode failure. Each
// array element is decoded strictly with unknown fields rejected; a
// structurally invalid element marks the whole request malformed, because one
// refusal code governs every malformed Session filesystem request. Trailing
// JSON after the field value cannot reach this decoder as reachable state:
// the outer request body is parsed as one JSON value first, and trailing
// outer data keeps the existing invalid_json contract, matching the Launcher
// rich-entries field.
func (r *sessionFilesystemRootsRequest) UnmarshalJSON(data []byte) error {
	r.present = true
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		r.malformed = true
		return nil
	}
	var raw []json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		r.malformed = true
		return nil
	}
	for _, rawRoot := range raw {
		dec := json.NewDecoder(bytes.NewReader(rawRoot))
		dec.DisallowUnknownFields()
		var root sessionFilesystemRootEntry
		if err := dec.Decode(&root); err != nil {
			r.malformed = true
			return nil
		}
		r.roots = append(r.roots, root)
	}
	return nil
}

// isPresent reports whether filesystem_roots occurred in the request.
func (r *sessionFilesystemRootsRequest) isPresent() bool { return r.present }

// suppliedRoots returns the explicitly supplied filesystem roots, or nil
// when the request was omitted or carried the empty array (both preserve
// the inherited workspace-only create behavior).
func (r *sessionFilesystemRootsRequest) suppliedRoots() []sessionFilesystemRootEntry {
	if !r.isPresent() {
		return nil
	}
	return r.roots
}

type sessionJSON struct {
	ID         string  `json:"id"`
	Workspace  string  `json:"workspace"`
	CreatedAt  string  `json:"created_at"`
	ExpiresAt  string  `json:"expires_at"`
	LauncherID string  `json:"launcher_id"`
	Launcher   *string `json:"launcher,omitempty"`
	Principal  *string `json:"principal,omitempty"`
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

// sessionFilesystemSnapshotJSON is the canonical public projection of the
// persisted immutable Session filesystem snapshot. The workspace is not
// repeated here: the top-level Session workspace is its canonical public
// owner, and the snapshot's first entry carries the root access mode.
type sessionFilesystemSnapshotJSON struct {
	Entries []AllowedRootEntry `json:"entries"`
}

// sessionShowJSON is the flat GET /sessions/{id} response body: the Session's
// usual public metadata plus the persisted immutable filesystem snapshot in
// its exact canonical persisted ordering. It never includes the token, the
// token hash, parent live policy, or MAC internals.
type sessionShowJSON struct {
	sessionJSON

	FilesystemSnapshot sessionFilesystemSnapshotJSON `json:"filesystem_snapshot"`
}

// sessionShowToJSON projects one Session and its persisted snapshot to the
// canonical public show body. entries is always an array, never null.
func sessionShowToJSON(s Session, snapshot *sessionFilesystemSnapshot) sessionShowJSON {
	entries := make([]AllowedRootEntry, 0, len(snapshot.Entries))
	entries = append(entries, snapshot.Entries...)
	return sessionShowJSON{
		sessionJSON:        sessionToJSON(s),
		FilesystemSnapshot: sessionFilesystemSnapshotJSON{Entries: entries},
	}
}

func sessionToJSON(s Session) sessionJSON {
	launcherName := (*string)(nil)
	if s.LauncherName != "" {
		launcherName = &s.LauncherName
	}
	principalName := (*string)(nil)
	if s.PrincipalName != "" {
		principalName = &s.PrincipalName
	}
	return sessionJSON{
		ID:         s.ID,
		Workspace:  s.Workspace,
		CreatedAt:  s.CreatedAt.Format(time.RFC3339),
		ExpiresAt:  s.ExpiresAt.Format(time.RFC3339),
		LauncherID: s.LauncherID,
		Launcher:   launcherName,
		Principal:  principalName,
	}
}

// authenticateSessionControlRequest authenticates the Session-control request
// authority (Session create/list/delete): an admin token, a Principal
// credential, or a Launcher credential — the explicit Session-control
// authority allow-list. It returns the common authenticated operator
// authority on success; expected credential-authentication failures are
// audited with the canonical Session-control classification and answered
// with the non-disclosing 401 contract, and a structurally invalid authority
// (an internal authentication anomaly, never an authorized credential) and a
// database failure stay an internal error.
func (a *App) authenticateSessionControlRequest(w http.ResponseWriter, r *http.Request) (*operatorAuthority, error) {
	ctx := r.Context()

	token, ok := parseBearerToken(r)
	if !ok {
		writeAuthFailure(ctx, r, "parse_failed")
		writeUnauthorizedSessionControl(ctx, w)
		return nil, nil
	}

	// A valid credential is Principal-owned or Launcher-owned; both are
	// authorized for Session control within their ownership scope.
	authority, err := a.authenticateOperatorToken(token)
	if err == nil {
		switch authority.class {
		case operatorAuthorityAdmin, operatorAuthorityPrincipal, operatorAuthorityLauncher:
			return authority, nil
		default:
			return nil, writeInvalidOperatorAuthority(ctx, r, w, "credential", "session_auth", authority)
		}
	}

	outcome := classifyCredentialAuthFailure(err)
	if !outcome.isExpectedAuthFailure() {
		writeAuthFailure(ctx, r, "credential.database_error")
		opLog(ctx).Error("session control auth database error",
			slog.String("operation", "session_auth"),
			slog.String("error", err.Error()),
		)
		writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		return nil, err
	}

	// Canonical Session-control audit classification for expected failures.
	var result string
	switch outcome {
	case credentialAuthRevoked:
		result = "credential.revoked"
	case credentialAuthPrincipalDisabled:
		result = "principal.disabled"
	case credentialAuthLauncherDisabled:
		result = "launcher.disabled"
	default:
		result = "credential.not_found"
	}
	writeAuthFailure(ctx, r, result)
	writeUnauthorizedSessionControl(ctx, w)
	return nil, err
}

// workspaceErrorMessage extracts a user-actionable message for a session
// creation failure. The internal ErrInvalidWorkspace wrapping suffix is
// removed so the client sees the specific actionable cause (for example a
// missing or non-directory workspace, or a workspace outside the allowed
// roots) while preserving the invalid_workspace error code.
func workspaceErrorMessage(err error) string {
	msg := err.Error()
	suffix := ": " + ErrInvalidWorkspace.Error()
	if strings.HasSuffix(msg, suffix) {
		return strings.TrimSuffix(msg, suffix)
	}
	return "invalid workspace"
}

// sessionFilesystemPolicyMessage is the bounded HTTP message of an
// issuance-time Session filesystem refusal: the refusal names no policy
// detail at all, because the domain refusal's internal diagnostic (which
// carries the canonical requested path) may disclose a resolved symlink
// target or upstream policy shape and stays in the operational log only.
// The stable code `invalid_filesystem_policy` carries the meaning; the
// client learns only that its request was refused before the Session
// existed.
const sessionFilesystemPolicyMessage = "invalid session filesystem policy"

// classifier for a create target relates a create error to its HTTP contract.
type createTargetError struct {
	status int
	code   string
	msg    string
}

func (e *createTargetError) Error() string { return e.msg }

// classifyCreateTargetError maps create-state errors to their HTTP contract.
func classifyCreateTargetError(err error) *createTargetError {
	switch {
	case errors.Is(err, ErrConflictingSelectors):
		return &createTargetError{status: http.StatusBadRequest, code: "conflicting_selectors", msg: "launcher_id and principal selectors cannot both be provided"}
	case errors.Is(err, ErrInvalidSelector):
		return &createTargetError{status: http.StatusBadRequest, code: "invalid_selector", msg: "invalid session selector"}
	case errors.Is(err, ErrMissingLauncherSelector):
		return &createTargetError{status: http.StatusBadRequest, code: "missing_launcher_selector", msg: "a launcher selector is required"}
	case errors.Is(err, ErrLauncherNotFound):
		return &createTargetError{status: http.StatusNotFound, code: "launcher_not_found", msg: "launcher not found"}
	case errors.Is(err, ErrLauncherUnavailable):
		return &createTargetError{status: http.StatusUnprocessableEntity, code: "launcher_unavailable", msg: "launcher is not available"}
	default:
		return nil
	}
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
		writeRequestContextAudit(ctx, auditRecord{
			Event:    "session.create",
			Result:   "invalid_json",
			Duration: duration,
		})
		writeError(ctx, w, http.StatusBadRequest, "invalid_json", "invalid JSON request")
		return
	}

	duration := time.Since(started).Round(time.Millisecond).String()

	sel, selErr := req.validateCreateSelector()
	if selErr != nil {
		auditRec := auditRecord{
			Event:     "session.create",
			Workspace: req.Workspace,
			Result:    selErr.code,
			Duration:  duration,
		}
		a.populateSessionAudit(&auditRec, authCtx)
		writeRequestContextAudit(ctx, auditRec)
		writeError(ctx, w, selErr.status, selErr.code, selErr.msg)
		return
	}

	// Issuance-time Session filesystem roots: presence semantics are
	// checked before any Session state exists. Omitted and the empty array
	// preserve the inherited create behavior; null and every malformed
	// shape are the one invalid_filesystem_policy refusal (not the generic
	// invalid_json code), because one code governs malformed/unauthorized
	// Session filesystem requests.
	if req.FilesystemRoots.isPresent() && req.FilesystemRoots.malformed {
		auditRec := auditRecord{
			Event:     "session.create",
			Workspace: req.Workspace,
			Result:    "invalid_filesystem_policy",
			Duration:  duration,
		}
		a.populateSessionAudit(&auditRec, authCtx)
		writeRequestContextAudit(ctx, auditRec)
		writeError(ctx, w, http.StatusBadRequest, "invalid_filesystem_policy",
			"filesystem_roots must be omitted, an empty array, or a well-formed array of {path, access} objects")
		return
	}

	result, cerr := a.createSessionAuthorized(authCtx, sel, req.Workspace, req.FilesystemRoots.suppliedRoots())
	if cerr != nil {
		// Stale-owner/enabled rejection at final persistence carries the same
		// deterministic typed contract as resolution-time rejection
		// (422 launcher_unavailable); the underlying cause is preserved in the
		// operational log. 400 invalid_workspace remains the workspace-shape
		// contract.
		if te := classifyCreateTargetError(cerr); te != nil {
			auditRec := auditRecord{
				Event:     "session.create",
				Workspace: req.Workspace,
				Result:    te.code,
				Duration:  duration,
			}
			a.populateSessionAudit(&auditRec, authCtx)
			writeRequestContextAudit(ctx, auditRec)
			if errors.Is(cerr, ErrLauncherUnavailable) {
				opLog(ctx).Warn("session creation rejected",
					slog.String("operation", "session_create"),
					slog.String("error", cerr.Error()),
				)
			}
			writeError(ctx, w, te.status, te.code, te.msg)
			return
		}
		resultCode := classifyCreateSessionError(cerr)
		auditRec := auditRecord{
			Event:     "session.create",
			Workspace: req.Workspace,
			Result:    resultCode,
			Duration:  duration,
		}
		a.populateSessionAudit(&auditRec, authCtx)
		writeRequestContextAudit(ctx, auditRec)

		if errors.Is(cerr, ErrInvalidWorkspace) {
			// Log the internal cause to the operational log.
			// The client receives the specific actionable cause (missing
			// directory, not a directory, outside an allowed root, no allowed
			// roots) with the same invalid_workspace code, without exposing
			// internal implementation detail.
			opLog(ctx).Warn("session creation rejected",
				slog.String("operation", "session_create"),
				slog.String("error", cerr.Error()),
			)
			writeError(ctx, w, http.StatusBadRequest, "invalid_workspace", workspaceErrorMessage(cerr))
		} else if errors.Is(cerr, ErrInvalidSessionFilesystemPolicy) {
			// Issuance-time filesystem refusal: the request is malformed or
			// is not a narrowing of the effective Launcher ceiling. The HTTP
			// message is the bounded non-disclosing contract — the internal
			// diagnostic (canonical requested path, which may name a resolved
			// symlink target or upstream policy shape) stays in the
			// operational log and never reaches the client.
			opLog(ctx).Warn("session creation rejected",
				slog.String("operation", "session_create"),
				slog.String("error", cerr.Error()),
			)
			writeError(ctx, w, http.StatusBadRequest, "invalid_filesystem_policy", sessionFilesystemPolicyMessage)
		} else {
			opLog(ctx).Error("session creation error",
				slog.String("operation", "session_create"),
				slog.String("error", cerr.Error()),
			)
			writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		}
		return
	}

	auditRec := auditRecord{
		Event:         "session.create",
		SessionID:     result.Session.ID,
		Workspace:     result.Session.Workspace,
		LauncherID:    result.Session.LauncherID,
		LauncherName:  result.Session.LauncherName,
		PrincipalName: result.Session.PrincipalName,
		Result:        "success",
		Duration:      duration,
	}
	a.populateSessionAudit(&auditRec, authCtx)
	writeRequestContextAudit(ctx, auditRec)

	writeJSONRaw(ctx, w, http.StatusCreated, createSessionResponse{
		OK:      true,
		Session: sessionToJSON(result.Session),
		Token:   result.Token,
	})
}

// populateSessionAudit adds credential provenance fields to a session-control
// audit record from a non-admin operator authority: a Principal credential
// names its Principal and credential, a Launcher credential additionally
// names its Launcher. Admin carries no credential provenance, and a
// structurally invalid authority fabricates none: only the three valid
// classes contribute provenance.
func (a *App) populateSessionAudit(rec *auditRecord, auth *operatorAuthority) {
	switch {
	case auth == nil || auth.class == operatorAuthorityAdmin:
		return
	case auth.class == operatorAuthorityLauncher:
		rec.PrincipalName = auth.launcher.PrincipalName
		rec.LauncherID = auth.launcher.LauncherID
		rec.LauncherName = auth.launcher.LauncherName
		rec.CredentialID = auth.launcher.CredentialID
	case auth.class == operatorAuthorityPrincipal:
		rec.PrincipalName = auth.principal.PrincipalName
		rec.CredentialID = auth.principal.CredentialID
	}
}

func (a *App) handleListSessions(w http.ResponseWriter, r *http.Request) {
	started := time.Now()

	authCtx, err := a.authenticateSessionControlRequest(w, r)
	if err != nil || authCtx == nil {
		return
	}

	ctx := r.Context()

	// Optional list narrowing selectors: an empty query value is absent,
	// matching the launcher-list selector contract. The daemon remains the
	// selector-resolution and authorization authority: the selectors are
	// resolved only inside the authority-visible ownership and composed into
	// the final sessionControlScope, which is then served by the single
	// Session ownership query.
	principalSel := r.URL.Query().Get("principal")
	launcherSel := r.URL.Query().Get("launcher")

	scope, err := a.resolveSessionListScope(authCtx, principalSel, launcherSel)

	duration := time.Since(started).Round(time.Millisecond).String()

	if err != nil {
		// Selector and lookup failures keep their classified, non-disclosing
		// contracts; a database/system failure stays the internal-error
		// contract and is never collapsed into not-found.
		auditRec := auditRecord{
			Event:    "session.list",
			Result:   "database_error",
			Duration: duration,
		}
		a.populateSessionAudit(&auditRec, authCtx)
		switch {
		case errors.Is(err, ErrPrincipalNotFound):
			auditRec.Result = "principal_not_found"
			writeRequestContextAudit(ctx, auditRec)
			writeError(ctx, w, http.StatusNotFound, "principal_not_found", "principal not found")
		case errors.Is(err, ErrLauncherNotFound):
			auditRec.Result = "launcher_not_found"
			writeRequestContextAudit(ctx, auditRec)
			writeError(ctx, w, http.StatusNotFound, "launcher_not_found", "launcher not found")
		case errors.Is(err, ErrLauncherNameRequiresPrincipal):
			auditRec.Result = "launcher_name_requires_principal"
			writeRequestContextAudit(ctx, auditRec)
			writeError(ctx, w, http.StatusBadRequest,
				"launcher_name_requires_principal",
				"launcher name filter requires --principal; without a Principal use a Launcher ID")
		case errors.Is(err, ErrInvalidSelector):
			auditRec.Result = "invalid_selector"
			writeRequestContextAudit(ctx, auditRec)
			writeError(ctx, w, http.StatusBadRequest, "invalid_selector", "invalid session selector")
		default:
			writeRequestContextAudit(ctx, auditRec)
			opLog(ctx).Error("list sessions error",
				slog.String("operation", "session_list"),
				slog.String("error", err.Error()),
			)
			writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		}
		return
	}

	sessions, err := a.listSessionsInScope(scope)

	duration = time.Since(started).Round(time.Millisecond).String()

	if err != nil {
		auditRec := auditRecord{
			Event:    "session.list",
			Result:   "database_error",
			Duration: duration,
		}
		a.populateSessionAudit(&auditRec, authCtx)
		writeRequestContextAudit(ctx, auditRec)
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
	a.populateSessionAudit(&auditRec, authCtx)
	writeRequestContextAudit(ctx, auditRec)

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
		writeRequestContextAudit(ctx, auditRecord{
			Event:    "session.delete",
			Result:   "invalid_session_id",
			Duration: duration,
		})
		writeError(ctx, w, http.StatusBadRequest, "invalid_session_id", "session id is required")
		return
	}

	scope, err := a.resolveSessionControlScope(authCtx)
	if err != nil {
		duration := time.Since(started).Round(time.Millisecond).String()
		writeRequestContextAudit(ctx, auditRecord{
			Event:     "session.delete",
			SessionID: id,
			Result:    "database_error",
			Duration:  duration,
		})
		opLog(ctx).Error("delete session error",
			slog.String("operation", "session_delete"),
			slog.String("error", err.Error()),
		)
		writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}

	var session *Session
	session, err = a.deleteSessionScoped(id, scope)

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
		if session != nil {
			auditRec.LauncherID = session.LauncherID
			auditRec.LauncherName = session.LauncherName
			auditRec.PrincipalName = session.PrincipalName
		}
		a.populateSessionAudit(&auditRec, authCtx)
		writeRequestContextAudit(ctx, auditRec)

		if errors.Is(err, ErrSessionNotFound) {
			// Non-disclosing: a Session outside the authority's scope (or a
			// nonexistent Session) is never revealed with a 403.
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
		auditRec.LauncherID = session.LauncherID
		auditRec.LauncherName = session.LauncherName
		auditRec.PrincipalName = session.PrincipalName
	}
	a.populateSessionAudit(&auditRec, authCtx)
	writeRequestContextAudit(ctx, auditRec)

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

// handleGetSession serves the read-only Session introspection surface
// (GET /sessions/{id}): the Session's usual public metadata plus its persisted
// immutable filesystem snapshot loaded through the single canonical snapshot
// loader. It shares the Session-control authority allow-list (an admin token,
// a Principal credential, or a Launcher credential — a Session bearer has no
// control-plane introspection authority) and the same ownership scope as
// Session list/delete: a missing or foreign Session is the same non-disclosing
// 404 session_not_found. A snapshot corruption discovered after startup is an
// internal error with an operational log (never silently hidden as not-found).
func (a *App) handleGetSession(w http.ResponseWriter, r *http.Request) {
	started := time.Now()

	authCtx, err := a.authenticateSessionControlRequest(w, r)
	if err != nil || authCtx == nil {
		return
	}

	ctx := r.Context()

	id := r.PathValue("id")
	if id == "" {
		duration := time.Since(started).Round(time.Millisecond).String()
		writeRequestContextAudit(ctx, auditRecord{
			Event:    "session.show",
			Result:   "invalid_session_id",
			Duration: duration,
		})
		writeError(ctx, w, http.StatusBadRequest, "invalid_session_id", "session id is required")
		return
	}

	scope, err := a.resolveSessionControlScope(authCtx)
	if err != nil {
		duration := time.Since(started).Round(time.Millisecond).String()
		writeRequestContextAudit(ctx, auditRecord{
			Event:     "session.show",
			SessionID: id,
			Result:    "database_error",
			Duration:  duration,
		})
		opLog(ctx).Error("session show error",
			slog.String("operation", "session_show"),
			slog.String("error", err.Error()),
		)
		writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}

	s, err := a.findSessionInScope(id, scope)

	duration := time.Since(started).Round(time.Millisecond).String()

	if err != nil {
		resultCode := "database_error"
		var workspace string
		switch {
		case errors.Is(err, ErrSessionNotFound):
			resultCode = "not_found"
		case errors.Is(err, ErrDatabase):
			if s != nil {
				workspace = s.Workspace
			}
		default:
			resultCode = "unknown_error"
		}
		auditRec := auditRecord{
			Event:     "session.show",
			SessionID: id,
			Result:    resultCode,
			Duration:  duration,
		}
		if workspace != "" {
			auditRec.Workspace = workspace
		}
		if s != nil {
			auditRec.LauncherID = s.LauncherID
			auditRec.LauncherName = s.LauncherName
			auditRec.PrincipalName = s.PrincipalName
		}
		a.populateSessionAudit(&auditRec, authCtx)
		writeRequestContextAudit(ctx, auditRec)

		if errors.Is(err, ErrSessionNotFound) {
			// Non-disclosing: a Session outside the authority's scope (or a
			// nonexistent Session) is never revealed with a 403.
			writeError(ctx, w, http.StatusNotFound, "session_not_found", "session not found")
		} else {
			opLog(ctx).Error("session show error",
				slog.String("operation", "session_show"),
				slog.String("error", err.Error()),
			)
			writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		}
		return
	}

	// The persisted snapshot is loaded through the single canonical loader,
	// the same owner the future data-plane consumers use. A post-startup
	// corruption is an internal integrity failure, not a policy refusal, and
	// is never hidden as not-found.
	snapshot, err := loadSessionFilesystemSnapshot(a.DB, s.ID, s.Workspace)
	if err != nil {
		auditRec := auditRecord{
			Event:         "session.show",
			SessionID:     s.ID,
			Workspace:     s.Workspace,
			LauncherID:    s.LauncherID,
			LauncherName:  s.LauncherName,
			PrincipalName: s.PrincipalName,
			Result:        "database_error",
			Duration:      time.Since(started).Round(time.Millisecond).String(),
		}
		a.populateSessionAudit(&auditRec, authCtx)
		writeRequestContextAudit(ctx, auditRec)
		opLog(ctx).Error("session show error",
			slog.String("operation", "session_show"),
			slog.String("session_id", s.ID),
			slog.String("error", err.Error()),
		)
		writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}

	auditRec := auditRecord{
		Event:         "session.show",
		SessionID:     s.ID,
		Workspace:     s.Workspace,
		LauncherID:    s.LauncherID,
		LauncherName:  s.LauncherName,
		PrincipalName: s.PrincipalName,
		Result:        "success",
		Duration:      time.Since(started).Round(time.Millisecond).String(),
	}
	a.populateSessionAudit(&auditRec, authCtx)
	writeRequestContextAudit(ctx, auditRec)

	writeJSONRaw(ctx, w, http.StatusOK, sessionShowToJSON(*s, snapshot))
}
