package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// applyLauncherTargetProvenance records the target/resource provenance of a
// launcher-control event from the resolved or resulting Launcher: principal_name
// is the target owner's Principal (never the caller identity), launcher_id and
// launcher_name identify the Launcher, and launcher_scope/launcher_enabled
// project the resolved or resulting Launcher state.
func applyLauncherTargetProvenance(rec *auditRecord, l *LauncherWithPrincipal) {
	if l == nil {
		return
	}
	rec.PrincipalName = l.PrincipalName
	rec.LauncherID = l.ID
	rec.LauncherName = l.Name
	rec.LauncherScope = string(l.ScopeMode)
	rec.LauncherEnabled = &l.Enabled
}

// applyControlAuditProvenance records the initiating provenance of a
// Principal-owned resource control event performed with a Principal
// credential: the initiating credential's ID (initiator_credential_id). Where
// the record does not already name its reachable target it also fills
// principal_name (a Principal credential can only reach its own Principal)
// and credential_id; target provenance from a resolved Launcher or target
// credential always wins. Admin callers carry no credential provenance, and
// Launcher credentials cannot perform control-plane operations.
func applyControlAuditProvenance(rec *auditRecord, auth *controlAuthority) {
	if auth == nil || auth.principalCredential == nil {
		return
	}
	if rec.PrincipalName == "" {
		rec.PrincipalName = auth.principalCredential.PrincipalName
	}
	if rec.InitiatorCredentialID == "" {
		rec.InitiatorCredentialID = auth.principalCredential.CredentialID
	}
	if rec.CredentialID == "" {
		rec.CredentialID = auth.principalCredential.CredentialID
	}
}

// writeLauncherControlAudit writes a launcher-control audit record with the
// target provenance of the resolved or resulting Launcher (when one was
// resolved or created) and the initiating provenance of the authenticated
// control authority applied.
func writeLauncherControlAudit(ctx context.Context, rec auditRecord, auth *controlAuthority, l *LauncherWithPrincipal) {
	applyLauncherTargetProvenance(&rec, l)
	applyControlAuditProvenance(&rec, auth)
	writeRequestContextAudit(ctx, rec)
}

// writeControlAudit writes a Principal-owned resource control audit record
// with the initiating provenance of the authenticated control authority
// applied (target provenance is carried by the record itself).
func writeControlAudit(ctx context.Context, rec auditRecord, auth *controlAuthority) {
	applyControlAuditProvenance(&rec, auth)
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
func (a *App) resolveControlPrincipal(w http.ResponseWriter, r *http.Request, auth *controlAuthority, username string) (*PrincipalWithRoots, bool) {
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
func (a *App) requireScopedLauncher(w http.ResponseWriter, r *http.Request, auth *controlAuthority) (*LauncherWithPrincipal, bool) {
	ctx := r.Context()
	p, ok := a.resolveControlPrincipal(w, r, auth, r.PathValue("username"))
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
	auth, err := a.authenticateControlRequest(w, r, "launcher")
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
		}, auth, nil)
		writeError(ctx, w, http.StatusBadRequest, "missing_username", "username is required")
		return
	}

	var req createLauncherRequest
	if err := decodeJSONRequest(w, r, &req); err != nil {
		writeLauncherControlAudit(ctx, auditRecord{
			Event:    "launcher.create",
			Result:   "invalid_json",
			Duration: time.Since(started).Round(time.Millisecond).String(),
		}, auth, nil)
		writeError(ctx, w, http.StatusBadRequest, "invalid_json", "invalid JSON request")
		return
	}

	p, ok := a.resolveControlPrincipal(w, r, auth, username)
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
		}, auth, nil)
		writeError(ctx, w, http.StatusBadRequest, "invalid_scope", "invalid scope")
		return
	}
	if scopeMode == LauncherScopeInherit && len(req.AllowedRoots) > 0 {
		writeLauncherControlAudit(ctx, auditRecord{
			Event:         "launcher.create",
			PrincipalName: username,
			Result:        "invalid_allowed_roots",
			Duration:      time.Since(started).Round(time.Millisecond).String(),
		}, auth, nil)
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
		}, auth, nil)
		switch {
		case isErrPrincipalNotFound(err):
			writeError(ctx, w, http.StatusNotFound, "principal_not_found", "principal not found")
		case isErrLauncherExists(err):
			writeError(ctx, w, http.StatusConflict, "launcher_exists",
				fmt.Sprintf("launcher %q already exists for principal %q", name, username))
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
		Event:  "launcher.create",
		Result: "success",
		// Target provenance is populated from the created Launcher, so an
		// admin-created Launcher also names its target owner.
		Duration: duration,
	}, auth, l)

	writeJSONRaw(ctx, w, http.StatusCreated, resp)
}

// handleListLaunchers serves GET /principals/{username}/launchers: the list of
// one Principal's Launchers. The path Principal is a required single-Principal
// filter of the shared scope-first list rule.
func (a *App) handleListLaunchers(w http.ResponseWriter, r *http.Request) {
	auth, err := a.authenticateControlRequest(w, r, "launcher")
	if err != nil || auth == nil {
		return
	}
	username := r.PathValue("username")
	if username == "" {
		writeError(r.Context(), w, http.StatusBadRequest, "missing_username", "username is required")
		return
	}
	a.serveLauncherList(w, r, auth, username)
}

// handleListLaunchersForAuthority serves GET /launchers: the scope-first
// launcher list. The authenticated authority establishes the maximum
// visibility and the optional ?principal= filter can only narrow it; the
// daemon remains the authorization authority.
func (a *App) handleListLaunchersForAuthority(w http.ResponseWriter, r *http.Request) {
	auth, err := a.authenticateControlRequest(w, r, "launcher")
	if err != nil || auth == nil {
		return
	}
	a.serveLauncherList(w, r, auth, r.URL.Query().Get("principal"))
}

// serveLauncherList answers a launcher list Query under the scope-first list
// rule: the authority scope plus the optional Principal filter resolve into
// one authorized query predicate. A filtered or single-Principal list audits
// the target Principal; the unfiltered admin list covers every Principal.
func (a *App) serveLauncherList(w http.ResponseWriter, r *http.Request, auth *controlAuthority, principalFilter string) {
	started := time.Now()
	ctx := r.Context()

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

	launchers, err := listLaunchersForScope(a.DB, principalID)
	duration := time.Since(started).Round(time.Millisecond).String()
	if err != nil {
		writeLauncherControlAudit(ctx, auditRecord{
			Event:         "launcher.list",
			PrincipalName: principalName,
			Result:        "error",
			Duration:      duration,
		}, auth, nil)
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
		PrincipalName: principalName,
		Result:        "success",
		Duration:      duration,
	}, auth, nil)

	writeJSONRaw(ctx, w, http.StatusOK, resp)
}

func (a *App) handleShowLauncher(w http.ResponseWriter, r *http.Request) {
	auth, err := a.authenticateControlRequest(w, r, "launcher")
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
	auth, err := a.authenticateControlRequest(w, r, "launcher")
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
		}, auth, nil)
		writeError(ctx, w, http.StatusBadRequest, "invalid_json", "invalid JSON request")
		return
	}
	if req.Name == nil && req.Enabled == nil {
		writeLauncherControlAudit(ctx, auditRecord{
			Event:      "launcher.update",
			LauncherID: l.ID,
			Result:     "missing_field",
			Duration:   time.Since(started).Round(time.Millisecond).String(),
		}, auth, nil)
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
		}, auth, nil)
		switch {
		case isErrLauncherNotFound(err):
			writeError(ctx, w, http.StatusNotFound, "launcher_not_found", "launcher not found")
		case isErrLauncherExists(err):
			writeError(ctx, w, http.StatusConflict, "launcher_exists",
				fmt.Sprintf("launcher %q already exists for principal %q", *req.Name, l.PrincipalName))
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

	// Target provenance is populated from the resulting Launcher, so the
	// success record always names the target owner (principal_name), including
	// for admin-authenticated requests.
	writeLauncherControlAudit(ctx, auditRecord{
		Event:    "launcher.update",
		Result:   "success",
		Duration: duration,
	}, auth, updated)
	writeJSONRaw(ctx, w, http.StatusOK, launcherToJSON(*updated))
}

func (a *App) handleReplaceLauncherAllowedRoots(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	auth, err := a.authenticateControlRequest(w, r, "launcher")
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
		}, auth, nil)
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
		}, auth, nil)
		writeError(ctx, w, http.StatusBadRequest, "invalid_scope", "invalid scope")
		return
	}
	if scopeMode == LauncherScopeRestricted && len(req.AllowedRoots) == 0 {
		writeLauncherControlAudit(ctx, auditRecord{
			Event:      "launcher.scope_replace",
			LauncherID: l.ID,
			Result:     "invalid_allowed_roots",
			Duration:   time.Since(started).Round(time.Millisecond).String(),
		}, auth, nil)
		writeError(ctx, w, http.StatusBadRequest, "invalid_allowed_roots", "restricted scope requires at least one allowed root")
		return
	}
	if scopeMode == LauncherScopeInherit && len(req.AllowedRoots) > 0 {
		writeLauncherControlAudit(ctx, auditRecord{
			Event:      "launcher.scope_replace",
			LauncherID: l.ID,
			Result:     "invalid_allowed_roots",
			Duration:   time.Since(started).Round(time.Millisecond).String(),
		}, auth, nil)
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
		}, auth, nil)
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
		Event:    "launcher.scope_replace",
		Result:   "success",
		Duration: duration,
	}, auth, updated)

	writeJSONRaw(ctx, w, http.StatusOK, launcherToJSON(*updated))
}

func (a *App) handleDeleteLauncher(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	auth, err := a.authenticateControlRequest(w, r, "launcher")
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

	// Best-effort cleanup of runtime directories for invalidated sessions. It
	// runs regardless of the outcome: a durable disable that committed before
	// a later owner-removal failure has already invalidated those sessions,
	// and their IDs are returned with the error so the cleanup is not lost
	// until daemon restart.
	cfg := a.getConfig()
	cleanupSessionRuntimeDirsBestEffort(ctx, "launcher_delete", cfg.RuntimeDir, sessionIDs)

	if err != nil {
		writeLauncherControlAudit(ctx, auditRecord{
			Event:      "launcher.delete",
			LauncherID: l.ID,
			Result:     "error",
			Duration:   duration,
		}, auth, nil)
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

	// Target provenance is populated from the resolved Launcher, so the
	// success record always names the target owner and the resolved state,
	// including for admin-authenticated requests.
	writeLauncherControlAudit(ctx, auditRecord{
		Event:    "launcher.delete",
		Result:   "success",
		Duration: duration,
	}, auth, l)

	w.WriteHeader(http.StatusNoContent)
}

func (a *App) handleIssueLauncherCredential(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	auth, err := a.authenticateControlRequest(w, r, "launcher")
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
		}, auth, nil)
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
		CredentialID: cred.ID,
		Result:       "success",
		Duration:     duration,
	}, auth, l)

	writeJSONRaw(ctx, w, http.StatusCreated, launcherCredentialResponse{
		OK:         true,
		Credential: &credJSON,
		Token:      token,
	})
}

func (a *App) handleGetLauncherCredential(w http.ResponseWriter, r *http.Request) {
	auth, err := a.authenticateControlRequest(w, r, "launcher")
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
	auth, err := a.authenticateControlRequest(w, r, "launcher")
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
		}, auth, nil)
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
		CredentialID: cred.ID,
		Result:       "success",
		Duration:     duration,
	}, auth, l)

	writeJSONRaw(ctx, w, http.StatusOK, launcherCredentialResponse{
		OK:         true,
		Credential: &credJSON,
		Token:      token,
	})
}

func (a *App) handleDeleteLauncherCredential(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	auth, err := a.authenticateControlRequest(w, r, "launcher")
	if err != nil || auth == nil {
		return
	}
	ctx := r.Context()

	l, ok := a.requireScopedLauncher(w, r, auth)
	if !ok {
		return
	}

	deleted, err := deleteLauncherCredential(a.DB, l.ID)
	if err != nil {
		duration := time.Since(started).Round(time.Millisecond).String()
		writeLauncherControlAudit(ctx, auditRecord{
			Event:      "launcher.credential_delete",
			LauncherID: l.ID,
			Result:     "error",
			Duration:   duration,
		}, auth, nil)
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

	// credential_id names the revoked target credential, resolved by the
	// delete itself; target launcher provenance comes from the resolved
	// Launcher, including for admin-authenticated requests.
	writeLauncherControlAudit(ctx, auditRecord{
		Event:        "launcher.credential_delete",
		CredentialID: deleted.ID,
		Result:       "success",
		Duration:     time.Since(started).Round(time.Millisecond).String(),
	}, auth, l)

	w.WriteHeader(http.StatusNoContent)
}
