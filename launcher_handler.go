package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"
)

// applyLauncherControlAuditProvenance records the creator provenance of a
// launcher-control event performed with a Principal credential: the acting
// principal and its credential ID. Fields already present on the record (for
// example the issued or rotated launcher credential's ID on credential events)
// are preserved. Admin callers carry no credential provenance, and Launcher
// credentials cannot perform launcher control.
func applyLauncherControlAuditProvenance(rec *auditRecord, auth *launcherControlAuthority) {
	if auth == nil || auth.principalCredential == nil {
		return
	}
	if rec.PrincipalName == "" {
		rec.PrincipalName = auth.principalCredential.PrincipalName
	}
	if rec.CredentialID == "" {
		rec.CredentialID = auth.principalCredential.CredentialID
	}
}

// writeLauncherControlAudit writes a launcher-control audit record with the
// creator provenance of the authenticated launcher-control authority applied.
func writeLauncherControlAudit(ctx context.Context, rec auditRecord, auth *launcherControlAuthority) {
	applyLauncherControlAuditProvenance(&rec, auth)
	writeRequestContextAudit(ctx, rec)
}

// Launcher JSON contract uses "scope" as the public term and "allowed_roots"
// for the canonical stored roots (restricted scope only). principal_id is never
// exposed as public authorization state.
type launcherJSON struct {
	ID           string   `json:"id"`
	Principal    string   `json:"principal"`
	Name         string   `json:"name"`
	Enabled      bool     `json:"enabled"`
	Scope        string   `json:"scope"`
	AllowedRoots []string `json:"allowed_roots"`
	CreatedAt    string   `json:"created_at"`
}

// launcherCreateName is the presence-aware "name" field of the Launcher-create
// request. A field absent from the JSON object selects defaultLauncherName.
// An explicitly supplied value — including the empty string and JSON null — is
// the exact name to validate; it is never reinterpreted as omission.
type launcherCreateName struct {
	present bool
	value   string
}

// UnmarshalJSON marks the field present on any occurrence, including JSON
// null, which decodes as an explicitly supplied empty value and therefore
// fails the Launcher-name grammar instead of defaulting.
func (n *launcherCreateName) UnmarshalJSON(data []byte) error {
	n.present = true
	return json.Unmarshal(data, &n.value)
}

type createLauncherRequest struct {
	Name            launcherCreateName `json:"name"`
	Scope           string             `json:"scope"`
	AllowedRoots    []string           `json:"allowed_roots"`
	IssueCredential bool               `json:"issue_credential"`
}

type patchLauncherRequest struct {
	Name    *string `json:"name,omitempty"`
	Enabled *bool   `json:"enabled,omitempty"`
}

type allowedRootsReplaceRequest struct {
	Scope        string   `json:"scope"`
	AllowedRoots []string `json:"allowed_roots"`
}

type createLauncherResponse struct {
	OK         bool                    `json:"ok"`
	Launcher   launcherJSON            `json:"launcher"`
	Credential *launcherCredentialJSON `json:"credential,omitempty"`
	Token      string                  `json:"token,omitempty"`
}

type listLaunchersResponse struct {
	OK        bool           `json:"ok"`
	Launchers []launcherJSON `json:"launchers"`
}

type launcherCredentialJSON struct {
	ID        string  `json:"id"`
	CreatedAt string  `json:"created_at"`
	RevokedAt *string `json:"revoked_at"`
}

type launcherCredentialResponse struct {
	OK         bool                    `json:"ok"`
	Credential *launcherCredentialJSON `json:"credential"`
	Token      string                  `json:"token,omitempty"`
}

func launcherToJSON(l LauncherWithPrincipal) launcherJSON {
	allowedRoots := l.AllowedRoots
	if allowedRoots == nil {
		allowedRoots = []string{}
	}
	return launcherJSON{
		ID:           l.ID,
		Principal:    l.PrincipalName,
		Name:         l.Name,
		Enabled:      l.Enabled,
		Scope:        string(l.ScopeMode),
		AllowedRoots: allowedRoots,
		CreatedAt:    l.CreatedAt.Format(time.RFC3339),
	}
}

func launcherCredentialToJSON(c launcherCredential) launcherCredentialJSON {
	revokedAt := (*string)(nil)
	if c.RevokedAt != nil {
		s := c.RevokedAt.Format(time.RFC3339)
		revokedAt = &s
	}
	return launcherCredentialJSON{
		ID:        c.ID,
		CreatedAt: c.CreatedAt.Format(time.RFC3339),
		RevokedAt: revokedAt,
	}
}

func isErrLauncherNotFound(err error) bool { return errors.Is(err, ErrLauncherNotFound) }
func isErrLauncherExists(err error) bool   { return errors.Is(err, ErrLauncherExists) }
func isErrInvalidLauncherName(err error) bool {
	return errors.Is(err, ErrInvalidLauncherName)
}
func isErrInvalidScope(err error) bool { return errors.Is(err, ErrInvalidScope) }
func isErrInvalidAllowedRoots(err error) bool {
	return errors.Is(err, ErrInvalidAllowedRoots) || isErrInvalidAllowedRoot(err)
}
func isErrLauncherRootOutsidePrincipal(err error) bool {
	return errors.Is(err, ErrLauncherRootOutsidePrincipal)
}
func isErrLauncherCredentialNotFound(err error) bool {
	return errors.Is(err, ErrLauncherCredentialNotFound)
}
func isErrLauncherCredentialExists(err error) bool {
	return errors.Is(err, ErrLauncherCredentialExists)
}

// resolveLauncherPrincipal resolves the target Principal for a nested
// /principals/{username}/launchers route under the given authority. For a
// Principal credential only its own Principal is reachable; any other username
// returns a non-disclosing 404.
func (a *App) resolveLauncherPrincipal(w http.ResponseWriter, r *http.Request, auth *launcherControlAuthority, username string) (*PrincipalWithRoots, bool) {
	ctx := r.Context()
	if !auth.isAdmin {
		if username != auth.principalCredential.PrincipalName {
			writeError(ctx, w, http.StatusNotFound, "principal_not_found", "principal not found")
			return nil, false
		}
	}
	p, err := findPrincipalByUsername(a.DB, username)
	if err != nil {
		if isErrPrincipalNotFound(err) {
			writeError(ctx, w, http.StatusNotFound, "principal_not_found", "principal not found")
		} else {
			opLog(ctx).Error("launcher principal lookup failed",
				slog.String("operation", "launcher_principal_lookup"),
				slog.String("error", err.Error()),
			)
			writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		}
		return nil, false
	}
	return p, true
}

// requireScopedLauncher resolves the target Launcher for a Principal-scoped
// Launcher route (/principals/{username}/launchers/{launcher}): the Principal
// is resolved under the request authority, then the Launcher selector (name or
// ID) is resolved under that Principal. Malformed, missing, foreign, and
// nonexistent selectors are the same non-disclosing 404 launcher_not_found.
func (a *App) requireScopedLauncher(w http.ResponseWriter, r *http.Request, auth *launcherControlAuthority) (*LauncherWithPrincipal, bool) {
	ctx := r.Context()
	p, ok := a.resolveLauncherPrincipal(w, r, auth, r.PathValue("username"))
	if !ok {
		return nil, false
	}
	l, err := findLauncherForPrincipal(a.DB, int64(p.ID), r.PathValue("launcher"))
	if err != nil {
		if isErrLauncherNotFound(err) {
			writeError(ctx, w, http.StatusNotFound, "launcher_not_found", "launcher not found")
		} else {
			opLog(ctx).Error("launcher lookup failed",
				slog.String("operation", "launcher_lookup"),
				slog.String("error", err.Error()),
			)
			writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		}
		return nil, false
	}
	return l, true
}

func (a *App) handleCreateLauncher(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	auth, err := a.authenticateLauncherControlRequest(w, r)
	if err != nil || auth == nil {
		return
	}
	ctx := r.Context()

	username := r.PathValue("username")
	if username == "" {
		writeLauncherControlAudit(ctx, auditRecord{
			Event:    "launcher.create",
			Result:   "missing_username",
			Duration: time.Since(started).Round(time.Millisecond).String(),
		}, auth)
		writeError(ctx, w, http.StatusBadRequest, "missing_username", "username is required")
		return
	}

	var req createLauncherRequest
	if err := decodeJSONRequest(w, r, &req); err != nil {
		writeLauncherControlAudit(ctx, auditRecord{
			Event:    "launcher.create",
			Result:   "invalid_json",
			Duration: time.Since(started).Round(time.Millisecond).String(),
		}, auth)
		writeError(ctx, w, http.StatusBadRequest, "invalid_json", "invalid JSON request")
		return
	}

	p, ok := a.resolveLauncherPrincipal(w, r, auth, username)
	if !ok {
		return
	}

	name := defaultLauncherName
	if req.Name.present {
		name = req.Name.value
	}
	scopeMode := LauncherScopeMode(req.Scope)
	if scopeMode == "" {
		scopeMode = LauncherScopeInherit
	}
	if scopeMode != LauncherScopeInherit && scopeMode != LauncherScopeRestricted {
		writeLauncherControlAudit(ctx, auditRecord{
			Event:         "launcher.create",
			PrincipalName: username,
			Result:        "invalid_scope",
			Duration:      time.Since(started).Round(time.Millisecond).String(),
		}, auth)
		writeError(ctx, w, http.StatusBadRequest, "invalid_scope", "invalid scope")
		return
	}
	if scopeMode == LauncherScopeInherit && len(req.AllowedRoots) > 0 {
		writeLauncherControlAudit(ctx, auditRecord{
			Event:         "launcher.create",
			PrincipalName: username,
			Result:        "invalid_allowed_roots",
			Duration:      time.Since(started).Round(time.Millisecond).String(),
		}, auth)
		writeError(ctx, w, http.StatusBadRequest, "invalid_allowed_roots", "inherit scope cannot carry allowed roots")
		return
	}

	a.lifecycleMu.Lock()
	l, cred, token, err := createLauncher(a.DB, int64(p.ID), name, scopeMode, req.AllowedRoots, a.getConfig().AllowedRoots, req.IssueCredential)
	a.lifecycleMu.Unlock()
	duration := time.Since(started).Round(time.Millisecond).String()

	if err != nil {
		writeLauncherControlAudit(ctx, auditRecord{
			Event:         "launcher.create",
			PrincipalName: username,
			Result:        "error",
			Duration:      duration,
		}, auth)
		switch {
		case isErrPrincipalNotFound(err):
			writeError(ctx, w, http.StatusNotFound, "principal_not_found", "principal not found")
		case isErrLauncherExists(err):
			writeError(ctx, w, http.StatusConflict, "launcher_exists", "launcher already exists")
		case isErrInvalidLauncherName(err):
			writeError(ctx, w, http.StatusBadRequest, "invalid_launcher_name", "invalid launcher name")
		case isErrInvalidScope(err):
			writeError(ctx, w, http.StatusBadRequest, "invalid_scope", "invalid scope")
		case isErrInvalidAllowedRoots(err):
			writeError(ctx, w, http.StatusBadRequest, "invalid_allowed_roots", "invalid allowed roots")
		case isErrLauncherRootOutsidePrincipal(err):
			writeError(ctx, w, http.StatusBadRequest, "outside_principal_root", "launcher root is not under the effective principal roots")
		case isErrLauncherCredentialExists(err):
			writeError(ctx, w, http.StatusConflict, "launcher_credential_exists", "launcher already has a credential")
		default:
			opLog(ctx).Error("launcher create failed",
				slog.String("operation", "launcher_create"),
				slog.String("error", err.Error()),
			)
			writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		}
		return
	}

	resp := createLauncherResponse{OK: true, Launcher: launcherToJSON(*l)}
	if cred != nil {
		credJSON := launcherCredentialToJSON(*cred)
		resp.Credential = &credJSON
		resp.Token = token
	}

	writeLauncherControlAudit(ctx, auditRecord{
		Event:         "launcher.create",
		PrincipalName: l.PrincipalName,
		LauncherID:    l.ID,
		LauncherName:  l.Name,
		LauncherScope: string(l.ScopeMode),
		Result:        "success",
		Duration:      duration,
	}, auth)

	writeJSONRaw(ctx, w, http.StatusCreated, resp)
}

func (a *App) handleListLaunchers(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	auth, err := a.authenticateLauncherControlRequest(w, r)
	if err != nil || auth == nil {
		return
	}
	ctx := r.Context()

	username := r.PathValue("username")
	if username == "" {
		writeError(ctx, w, http.StatusBadRequest, "missing_username", "username is required")
		return
	}

	p, ok := a.resolveLauncherPrincipal(w, r, auth, username)
	if !ok {
		return
	}

	launchers, err := listLaunchersForPrincipal(a.DB, int64(p.ID))
	duration := time.Since(started).Round(time.Millisecond).String()
	if err != nil {
		writeLauncherControlAudit(ctx, auditRecord{
			Event:         "launcher.list",
			PrincipalName: username,
			Result:        "error",
			Duration:      duration,
		}, auth)
		opLog(ctx).Error("launcher list failed",
			slog.String("operation", "launcher_list"),
			slog.String("error", err.Error()),
		)
		writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}

	resp := listLaunchersResponse{OK: true, Launchers: make([]launcherJSON, 0, len(launchers))}
	for _, l := range launchers {
		resp.Launchers = append(resp.Launchers, launcherToJSON(l))
	}

	writeLauncherControlAudit(ctx, auditRecord{
		Event:         "launcher.list",
		PrincipalName: username,
		Result:        "success",
		Duration:      duration,
	}, auth)

	writeJSONRaw(ctx, w, http.StatusOK, resp)
}

func (a *App) handleShowLauncher(w http.ResponseWriter, r *http.Request) {
	auth, err := a.authenticateLauncherControlRequest(w, r)
	if err != nil || auth == nil {
		return
	}
	l, ok := a.requireScopedLauncher(w, r, auth)
	if !ok {
		return
	}
	writeJSONRaw(r.Context(), w, http.StatusOK, launcherToJSON(*l))
}

func (a *App) handlePatchLauncher(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	auth, err := a.authenticateLauncherControlRequest(w, r)
	if err != nil || auth == nil {
		return
	}
	ctx := r.Context()

	l, ok := a.requireScopedLauncher(w, r, auth)
	if !ok {
		return
	}

	var req patchLauncherRequest
	if err := decodeJSONRequest(w, r, &req); err != nil {
		writeLauncherControlAudit(ctx, auditRecord{
			Event:      "launcher.update",
			LauncherID: l.ID,
			Result:     "invalid_json",
			Duration:   time.Since(started).Round(time.Millisecond).String(),
		}, auth)
		writeError(ctx, w, http.StatusBadRequest, "invalid_json", "invalid JSON request")
		return
	}
	if req.Name == nil && req.Enabled == nil {
		writeLauncherControlAudit(ctx, auditRecord{
			Event:      "launcher.update",
			LauncherID: l.ID,
			Result:     "missing_field",
			Duration:   time.Since(started).Round(time.Millisecond).String(),
		}, auth)
		writeError(ctx, w, http.StatusBadRequest, "missing_field", "name or enabled is required")
		return
	}

	duration := time.Since(started).Round(time.Millisecond).String()

	// The PATCH is a lifecycle mutation owned by updateLauncherWithLifecycle:
	// rename and enable/disable commit atomically, so a failed disable leaves
	// no partial rename behind, and the owner holds lifecycleMu so the whole
	// PATCH cannot interleave with another Launcher/Principal lifecycle
	// mutation on the same ownership.
	updated, revoked, err := a.updateLauncherWithLifecycle(l.ID, req.Name, req.Enabled)
	if err != nil {
		writeLauncherControlAudit(ctx, auditRecord{
			Event:      "launcher.update",
			LauncherID: l.ID,
			Result:     "error",
			Duration:   duration,
		}, auth)
		switch {
		case isErrLauncherNotFound(err):
			writeError(ctx, w, http.StatusNotFound, "launcher_not_found", "launcher not found")
		case isErrLauncherExists(err):
			writeError(ctx, w, http.StatusConflict, "launcher_exists", "launcher already exists")
		case isErrInvalidLauncherName(err):
			writeError(ctx, w, http.StatusBadRequest, "invalid_launcher_name", "invalid launcher name")
		default:
			opLog(ctx).Error("launcher update failed",
				slog.String("operation", "launcher_update"),
				slog.String("error", err.Error()),
			)
			writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		}
		return
	}

	// Best-effort cleanup of Session runtime directories after the DB disable
	// and MAC release committed.
	cfg := a.getConfig()
	for _, sessionID := range revoked {
		if err := cleanupSessionRuntimeDir(cfg.RuntimeDir, sessionID); err != nil {
			opLog(ctx).Warn("failed to clean up session runtime directory",
				slog.String("operation", "launcher_update"),
				slog.String("launcher_id", updated.ID),
				slog.String("session_id", sessionID),
				slog.String("error", err.Error()),
			)
		}
	}

	writeLauncherControlAudit(ctx, auditRecord{
		Event:           "launcher.update",
		LauncherID:      updated.ID,
		LauncherName:    updated.Name,
		LauncherEnabled: &updated.Enabled,
		Result:          "success",
		Duration:        duration,
	}, auth)
	writeJSONRaw(ctx, w, http.StatusOK, launcherToJSON(*updated))
}

func (a *App) handleReplaceLauncherAllowedRoots(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	auth, err := a.authenticateLauncherControlRequest(w, r)
	if err != nil || auth == nil {
		return
	}
	ctx := r.Context()

	l, ok := a.requireScopedLauncher(w, r, auth)
	if !ok {
		return
	}

	var req allowedRootsReplaceRequest
	if err := decodeJSONRequest(w, r, &req); err != nil {
		writeLauncherControlAudit(ctx, auditRecord{
			Event:      "launcher.scope_replace",
			LauncherID: l.ID,
			Result:     "invalid_json",
			Duration:   time.Since(started).Round(time.Millisecond).String(),
		}, auth)
		writeError(ctx, w, http.StatusBadRequest, "invalid_json", "invalid JSON request")
		return
	}

	scopeMode := LauncherScopeMode(req.Scope)
	if scopeMode != LauncherScopeInherit && scopeMode != LauncherScopeRestricted {
		writeLauncherControlAudit(ctx, auditRecord{
			Event:      "launcher.scope_replace",
			LauncherID: l.ID,
			Result:     "invalid_scope",
			Duration:   time.Since(started).Round(time.Millisecond).String(),
		}, auth)
		writeError(ctx, w, http.StatusBadRequest, "invalid_scope", "invalid scope")
		return
	}
	if scopeMode == LauncherScopeRestricted && len(req.AllowedRoots) == 0 {
		writeLauncherControlAudit(ctx, auditRecord{
			Event:      "launcher.scope_replace",
			LauncherID: l.ID,
			Result:     "invalid_allowed_roots",
			Duration:   time.Since(started).Round(time.Millisecond).String(),
		}, auth)
		writeError(ctx, w, http.StatusBadRequest, "invalid_allowed_roots", "restricted scope requires at least one allowed root")
		return
	}
	if scopeMode == LauncherScopeInherit && len(req.AllowedRoots) > 0 {
		writeLauncherControlAudit(ctx, auditRecord{
			Event:      "launcher.scope_replace",
			LauncherID: l.ID,
			Result:     "invalid_allowed_roots",
			Duration:   time.Since(started).Round(time.Millisecond).String(),
		}, auth)
		writeError(ctx, w, http.StatusBadRequest, "invalid_allowed_roots", "inherit scope cannot carry allowed roots")
		return
	}

	// The Launcher scope replacement is a policy-authority mutation: it shares
	// the lifecycle serialization with Session creation so a concurrent create
	// observes either the pre-replacement or post-replacement scope, never a
	// mix, and a narrowing that linearizes first prevents the Session.
	a.lifecycleMu.Lock()
	updated, err := replaceLauncherScope(a.DB, l.ID, scopeMode, req.AllowedRoots, a.getConfig().AllowedRoots)
	a.lifecycleMu.Unlock()
	duration := time.Since(started).Round(time.Millisecond).String()
	if err != nil {
		writeLauncherControlAudit(ctx, auditRecord{
			Event:      "launcher.scope_replace",
			LauncherID: l.ID,
			Result:     "error",
			Duration:   duration,
		}, auth)
		switch {
		case isErrLauncherNotFound(err):
			writeError(ctx, w, http.StatusNotFound, "launcher_not_found", "launcher not found")
		case isErrInvalidScope(err):
			writeError(ctx, w, http.StatusBadRequest, "invalid_scope", "invalid scope")
		case isErrInvalidAllowedRoots(err):
			writeError(ctx, w, http.StatusBadRequest, "invalid_allowed_roots", "invalid allowed roots")
		case isErrLauncherRootOutsidePrincipal(err):
			writeError(ctx, w, http.StatusBadRequest, "outside_principal_root", "launcher root is not under the effective principal roots")
		default:
			opLog(ctx).Error("launcher scope replace failed",
				slog.String("operation", "launcher_scope_replace"),
				slog.String("error", err.Error()),
			)
			writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		}
		return
	}

	writeLauncherControlAudit(ctx, auditRecord{
		Event:         "launcher.scope_replace",
		LauncherID:    updated.ID,
		LauncherName:  updated.Name,
		LauncherScope: string(updated.ScopeMode),
		Result:        "success",
		Duration:      duration,
	}, auth)

	writeJSONRaw(ctx, w, http.StatusOK, launcherToJSON(*updated))
}

func (a *App) handleDeleteLauncher(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	auth, err := a.authenticateLauncherControlRequest(w, r)
	if err != nil || auth == nil {
		return
	}
	ctx := r.Context()

	l, ok := a.requireScopedLauncher(w, r, auth)
	if !ok {
		return
	}

	sessionIDs, err := a.deleteLauncherChecked(ctx, l.ID)
	duration := time.Since(started).Round(time.Millisecond).String()
	if err != nil {
		writeLauncherControlAudit(ctx, auditRecord{
			Event:      "launcher.delete",
			LauncherID: l.ID,
			Result:     "error",
			Duration:   duration,
		}, auth)
		switch {
		case isErrLauncherNotFound(err):
			writeError(ctx, w, http.StatusNotFound, "launcher_not_found", "launcher not found")
		case isErrLauncherRuntimeActive(err):
			writeError(ctx, w, http.StatusConflict, "launcher_runtime_active", "launcher has active runtime")
		default:
			opLog(ctx).Error("launcher delete failed",
				slog.String("operation", "launcher_delete"),
				slog.String("error", err.Error()),
			)
			writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		}
		return
	}

	// Best-effort cleanup of runtime directories for deleted sessions.
	cfg := a.getConfig()
	for _, sessionID := range sessionIDs {
		if err := cleanupSessionRuntimeDir(cfg.RuntimeDir, sessionID); err != nil {
			opLog(ctx).Warn("failed to clean up session runtime directory",
				slog.String("operation", "launcher_delete"),
				slog.String("session_id", sessionID),
				slog.String("error", err.Error()),
			)
		}
	}

	writeLauncherControlAudit(ctx, auditRecord{
		Event:        "launcher.delete",
		LauncherID:   l.ID,
		LauncherName: l.Name,
		Result:       "success",
		Duration:     duration,
	}, auth)

	w.WriteHeader(http.StatusNoContent)
}

func (a *App) handleIssueLauncherCredential(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	auth, err := a.authenticateLauncherControlRequest(w, r)
	if err != nil || auth == nil {
		return
	}
	ctx := r.Context()

	l, ok := a.requireScopedLauncher(w, r, auth)
	if !ok {
		return
	}

	cred, token, err := issueLauncherCredential(a.DB, l.ID)
	duration := time.Since(started).Round(time.Millisecond).String()
	if err != nil {
		writeLauncherControlAudit(ctx, auditRecord{
			Event:      "launcher.credential_issue",
			LauncherID: l.ID,
			Result:     "error",
			Duration:   duration,
		}, auth)
		switch {
		case isErrLauncherNotFound(err):
			writeError(ctx, w, http.StatusNotFound, "launcher_not_found", "launcher not found")
		case isErrLauncherCredentialExists(err):
			writeError(ctx, w, http.StatusConflict, "launcher_credential_exists", "launcher already has a credential")
		default:
			opLog(ctx).Error("launcher credential issue failed",
				slog.String("operation", "launcher_credential_issue"),
				slog.String("error", err.Error()),
			)
			writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		}
		return
	}

	credJSON := launcherCredentialToJSON(*cred)
	writeLauncherControlAudit(ctx, auditRecord{
		Event:        "launcher.credential_issue",
		LauncherID:   l.ID,
		LauncherName: l.Name,
		CredentialID: cred.ID,
		Result:       "success",
		Duration:     duration,
	}, auth)

	writeJSONRaw(ctx, w, http.StatusCreated, launcherCredentialResponse{
		OK:         true,
		Credential: &credJSON,
		Token:      token,
	})
}

func (a *App) handleGetLauncherCredential(w http.ResponseWriter, r *http.Request) {
	auth, err := a.authenticateLauncherControlRequest(w, r)
	if err != nil || auth == nil {
		return
	}
	ctx := r.Context()

	l, ok := a.requireScopedLauncher(w, r, auth)
	if !ok {
		return
	}

	cred, err := findLauncherCredential(a.DB, l.ID)
	if err != nil {
		if isErrLauncherCredentialNotFound(err) {
			writeError(ctx, w, http.StatusNotFound, "launcher_credential_not_found", "launcher credential not found")
		} else {
			opLog(ctx).Error("launcher credential lookup failed",
				slog.String("operation", "launcher_credential_lookup"),
				slog.String("error", err.Error()),
			)
			writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		}
		return
	}

	credJSON := launcherCredentialToJSON(*cred)
	writeJSONRaw(ctx, w, http.StatusOK, launcherCredentialResponse{OK: true, Credential: &credJSON})
}

func (a *App) handleRotateLauncherCredential(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	auth, err := a.authenticateLauncherControlRequest(w, r)
	if err != nil || auth == nil {
		return
	}
	ctx := r.Context()

	l, ok := a.requireScopedLauncher(w, r, auth)
	if !ok {
		return
	}

	cred, token, err := rotateLauncherCredential(a.DB, l.ID)
	duration := time.Since(started).Round(time.Millisecond).String()
	if err != nil {
		writeLauncherControlAudit(ctx, auditRecord{
			Event:      "launcher.credential_rotate",
			LauncherID: l.ID,
			Result:     "error",
			Duration:   duration,
		}, auth)
		if isErrLauncherCredentialNotFound(err) {
			writeError(ctx, w, http.StatusNotFound, "launcher_credential_not_found", "launcher credential not found")
		} else {
			opLog(ctx).Error("launcher credential rotate failed",
				slog.String("operation", "launcher_credential_rotate"),
				slog.String("error", err.Error()),
			)
			writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		}
		return
	}

	credJSON := launcherCredentialToJSON(*cred)
	writeLauncherControlAudit(ctx, auditRecord{
		Event:        "launcher.credential_rotate",
		LauncherID:   l.ID,
		LauncherName: l.Name,
		CredentialID: cred.ID,
		Result:       "success",
		Duration:     duration,
	}, auth)

	writeJSONRaw(ctx, w, http.StatusOK, launcherCredentialResponse{
		OK:         true,
		Credential: &credJSON,
		Token:      token,
	})
}

func (a *App) handleDeleteLauncherCredential(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	auth, err := a.authenticateLauncherControlRequest(w, r)
	if err != nil || auth == nil {
		return
	}
	ctx := r.Context()

	l, ok := a.requireScopedLauncher(w, r, auth)
	if !ok {
		return
	}

	if err := deleteLauncherCredential(a.DB, l.ID); err != nil {
		duration := time.Since(started).Round(time.Millisecond).String()
		writeLauncherControlAudit(ctx, auditRecord{
			Event:      "launcher.credential_delete",
			LauncherID: l.ID,
			Result:     "error",
			Duration:   duration,
		}, auth)
		if isErrLauncherCredentialNotFound(err) {
			writeError(ctx, w, http.StatusNotFound, "launcher_credential_not_found", "launcher credential not found")
		} else {
			opLog(ctx).Error("launcher credential delete failed",
				slog.String("operation", "launcher_credential_delete"),
				slog.String("error", err.Error()),
			)
			writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		}
		return
	}

	writeLauncherControlAudit(ctx, auditRecord{
		Event:        "launcher.credential_delete",
		LauncherID:   l.ID,
		LauncherName: l.Name,
		Result:       "success",
		Duration:     time.Since(started).Round(time.Millisecond).String(),
	}, auth)

	w.WriteHeader(http.StatusNoContent)
}
