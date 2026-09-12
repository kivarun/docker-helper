package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
func applyControlAuditProvenance(rec *auditRecord, auth *operatorAuthority) {
	if auth == nil || auth.class != operatorAuthorityPrincipal {
		return
	}
	if rec.PrincipalName == "" {
		rec.PrincipalName = auth.principal.PrincipalName
	}
	if rec.InitiatorCredentialID == "" {
		rec.InitiatorCredentialID = auth.principal.CredentialID
	}
	if rec.CredentialID == "" {
		rec.CredentialID = auth.principal.CredentialID
	}
}

// writeLauncherControlAudit writes a launcher-control audit record with the
// target provenance of the resolved or resulting Launcher (when one was
// resolved or created) and the initiating provenance of the authenticated
// control authority applied.
func writeLauncherControlAudit(ctx context.Context, rec auditRecord, auth *operatorAuthority, l *LauncherWithPrincipal) {
	applyLauncherTargetProvenance(&rec, l)
	applyControlAuditProvenance(&rec, auth)
	writeRequestContextAudit(ctx, rec)
}

// writeControlAudit writes a Principal-owned resource control audit record
// with the initiating provenance of the authenticated control authority
// applied (target provenance is carried by the record itself).
func writeControlAudit(ctx context.Context, rec auditRecord, auth *operatorAuthority) {
	applyControlAuditProvenance(&rec, auth)
	writeRequestContextAudit(ctx, rec)
}

// Launcher JSON contract uses "scope" as the public term and "allowed_roots"
// for the derived 2.1 path-only projection of the canonical stored roots
// (restricted scope only), always serialized as a JSON array — zero roots are
// the empty array, never null. allowed_root_entries is the authoritative rich
// projection of the same entries with the identical ordering contract
// (launcherToJSON owns the projection). principal_id is never
// exposed as public authorization state.
type launcherJSON struct {
	ID                 string             `json:"id"`
	Principal          string             `json:"principal"`
	Name               string             `json:"name"`
	Enabled            bool               `json:"enabled"`
	Scope              string             `json:"scope"`
	AllowedRoots       []string           `json:"allowed_roots"`
	AllowedRootEntries []AllowedRootEntry `json:"allowed_root_entries"`
	CreatedAt          string             `json:"created_at"`
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

// optionalLauncherRootsSlice is the presence-aware legacy path-only roots
// field of the Launcher scope-replace request. Occurrence and value are
// distinct facts: any occurrence — an empty array, JSON null, or a non-empty
// array — is the supplied legacy form, so dual-form detection counts a
// present key regardless of its value (presence and semantic emptiness are
// never conflated). JSON null keeps the 2.1 value semantics of the supplied
// legacy form: the nil slice the 2.1 Go client serializes, meaning no roots.
type optionalLauncherRootsSlice struct {
	present bool
	value   []string
}

// UnmarshalJSON marks the field present on any occurrence, including JSON
// null, which decodes as the supplied legacy form with no roots (the exact
// 2.1 wire semantics where a nil slice serializes as null).
func (s *optionalLauncherRootsSlice) UnmarshalJSON(data []byte) error {
	s.present = true
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return nil
	}
	return json.Unmarshal(data, &s.value)
}

// allowedRootEntryInput is the strict rich form of one restricted root in a
// Launcher scope replacement: exactly the {"path","access"} object with a
// canonical access vocabulary value. The legacy path string is the shape of
// the allowed_roots form and is rejected here, so the two wire forms cannot
// be confused.
type allowedRootEntryInput struct {
	Path   string `json:"path"`
	Access string `json:"access"`
}

// allowedRootEntryInputSlice is the presence-aware rich roots field of the
// Launcher scope-replace request. Any occurrence — an empty array, JSON
// null, or a non-empty array — is the supplied rich form, so dual-form
// detection counts a present key regardless of its value; there is no 2.1
// compatibility reason to treat the rich field's null as absent, and a
// supplied empty rich form is refused by the scope rules. The occurrence
// marks the form; the value semantics stay with the handler.
type allowedRootEntryInputSlice struct {
	present bool
	value   []allowedRootEntryInput
}

// UnmarshalJSON marks the field present on any occurrence, including JSON
// null, and strictly decodes the array with its own decoder: the outer
// DisallowUnknownFields never reaches inside a custom UnmarshalJSON, so the
// nested rich entries are decoded with unknown fields rejected, malformed
// types rejected, and trailing JSON rejected. The entry access values remain
// unparsed here; the canonical parseAllowedRootAccess owner parses them at
// the handler boundary.
func (s *allowedRootEntryInputSlice) UnmarshalJSON(data []byte) error {
	s.present = true
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var value []allowedRootEntryInput
	if err := dec.Decode(&value); err != nil {
		return err
	}
	// After the first successful value, the next decode must return io.EOF:
	// any other result is trailing or malformed JSON after the array. The
	// More() probe alone is not sufficient, because it reports false for a
	// trailing closing bracket such as `[ ... ] ]`.
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return fmt.Errorf("trailing data after allowed_root_entries")
	}
	s.value = value
	return nil
}

// allowedRootsReplaceRequest is the complete-replacement request of the
// Launcher allowed-roots PUT route. The legacy path-only form
// (allowed_roots) and the canonical rich form (allowed_root_entries) are
// mutually exclusive; supplying both is refused even when one of them is
// empty, so the requested policy is never ambiguous.
type allowedRootsReplaceRequest struct {
	Scope              string                     `json:"scope"`
	AllowedRoots       optionalLauncherRootsSlice `json:"allowed_roots"`
	AllowedRootEntries allowedRootEntryInputSlice `json:"allowed_root_entries"`
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
	allowedRoots := allowedRootPaths(l.AllowedRoots)
	if allowedRoots == nil {
		allowedRoots = []string{}
	}
	entries := l.AllowedRoots
	if entries == nil {
		entries = []AllowedRootEntry{}
	}
	return launcherJSON{
		ID:                 l.ID,
		Principal:          l.PrincipalName,
		Name:               l.Name,
		Enabled:            l.Enabled,
		Scope:              string(l.ScopeMode),
		AllowedRoots:       allowedRoots,
		AllowedRootEntries: entries,
		CreatedAt:          l.CreatedAt.Format(time.RFC3339),
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

// launcherAllowedRootAuditResult maps a Launcher allowed-root mutation
// refusal to its stable audit result vocabulary: the same stable refusal
// names the public API reports, so an operator can explain every refused
// policy mutation. Unclassified internal failures keep the generic error
// result.
func launcherAllowedRootAuditResult(err error) string {
	switch {
	case isErrLauncherNotFound(err):
		return "launcher_not_found"
	case isErrUserModeOwnerReserved(err):
		return "user_mode_owner_reserved"
	case isErrInvalidAllowedRoot(err):
		return "invalid_allowed_root"
	case errors.Is(err, ErrAllowedRootNotFound):
		return "allowed_root_not_found"
	case errors.Is(err, ErrInvalidAllowedRootAccess):
		return "invalid_allowed_root_access"
	case isErrLauncherRootOutsidePrincipal(err):
		return "outside_principal_root"
	default:
		return "error"
	}
}

// launcherScopeReplaceAuditResult is the scope-replacement sibling of
// launcherAllowedRootAuditResult: the stable refusal vocabulary of the
// complete-scope mutation.
func launcherScopeReplaceAuditResult(err error) string {
	switch {
	case isErrLauncherNotFound(err):
		return "launcher_not_found"
	case isErrUserModeOwnerReserved(err):
		return "user_mode_owner_reserved"
	case isErrInvalidScope(err):
		return "invalid_scope"
	case isErrInvalidAllowedRoots(err):
		return "invalid_allowed_roots"
	case errors.Is(err, ErrInvalidAllowedRootAccess):
		return "invalid_allowed_root_access"
	case isErrLauncherRootOutsidePrincipal(err):
		return "outside_principal_root"
	default:
		return "error"
	}
}

// resolveControlPrincipal resolves the target Principal for a nested
// /principals/{username}/... route under the given authority through the
// stable Principal-control target owner (resolvePrincipalControlTarget): an
// Admin authority resolves the current Principal named username, while a
// Principal credential targets the exact Principal ID it authenticated as —
// the nested username is an authorization selector only, so a stale authority
// whose Principal was deleted (even if the same username was recreated) fails
// closed as the non-disclosing 404 and never rebinds to the replacement
// Principal. A foreign selector is the same non-disclosing 404.
func (a *App) resolveControlPrincipal(w http.ResponseWriter, r *http.Request, auth *operatorAuthority, username string) (*principalControlTarget, bool) {
	target, err := resolvePrincipalControlTarget(a.DB, auth, username)
	if err != nil {
		writePrincipalControlLookupError(r.Context(), w, err)
		return nil, false
	}
	return target, true
}

// requireScopedLauncher resolves the target Launcher for a Principal-scoped
// Launcher route (/principals/{username}/launchers/{launcher}): the Principal
// target is resolved under the request authority through the stable control
// target owner, then the Launcher selector (name or ID) is resolved under
// that exact Principal identity. Malformed, missing, foreign, and
// nonexistent selectors are the same non-disclosing 404 launcher_not_found.
func (a *App) requireScopedLauncher(w http.ResponseWriter, r *http.Request, auth *operatorAuthority) (*LauncherWithPrincipal, bool) {
	ctx := r.Context()
	target, ok := a.resolveControlPrincipal(w, r, auth, r.PathValue("username"))
	if !ok {
		return nil, false
	}
	l, err := findLauncherForPrincipal(a.DB, target.ID, r.PathValue("launcher"))
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
	auth, err := a.authenticatePrincipalControlRequest(w, r, "launcher")
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

	target, ok := a.resolveControlPrincipal(w, r, auth, username)
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

	// The Launcher creation is a policy-authority mutation: it shares the
	// lifecycle serialization with Session creation so a concurrent create
	// observes either the pre-creation or post-creation ownership, never a
	// mix. createLauncherWithLifecycle owns that boundary and the canonical
	// effective-Principal-root resolution inside it (the current global policy
	// snapshot is read inside the boundary, the same lifecycleMu -> a.mu
	// ordering as config reload).
	l, cred, token, err := a.createLauncherWithLifecycle(target.ID, name, scopeMode, req.AllowedRoots, req.IssueCredential)
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

// handleListLaunchersQuery serves GET /launchers: the top-level launcher list
// entry. It authenticates the Principal-control authority once and delegates
// the whole Query to the single launcher-list owner.
func (a *App) handleListLaunchersQuery(w http.ResponseWriter, r *http.Request) {
	auth, err := a.authenticatePrincipalControlRequest(w, r, "launcher")
	if err != nil || auth == nil {
		return
	}
	a.serveLauncherListQuery(w, r, auth, r.URL.Query().Get("principal"), r.URL.Query().Get("launcher"))
}

// handleListLaunchers serves GET /principals/{username}/launchers: the list of
// one Principal's Launchers. The path Principal is a required single-Principal
// filter of the shared scope-first list rule; it authenticates once and
// delegates to the same launcher-list owner with no Launcher selector.
func (a *App) handleListLaunchers(w http.ResponseWriter, r *http.Request) {
	auth, err := a.authenticatePrincipalControlRequest(w, r, "launcher")
	if err != nil || auth == nil {
		return
	}
	username := r.PathValue("username")
	if username == "" {
		writeError(r.Context(), w, http.StatusBadRequest, "missing_username", "username is required")
		return
	}
	a.serveLauncherListQuery(w, r, auth, username, "")
}

// serveLauncherListQuery is the single launcher-list Query owner under the
// scope-first list rule: resolveListScope resolves the authorized visibility
// once (the authority establishes the maximum, the optional Principal filter
// can only narrow it), then the optional ?launcher= selector narrows that
// resolved scope through one domain Query. One error classification, one
// audit path, and one response construction serve the unfiltered and the
// narrowed Query; a narrowed hit is a one-element collection of the same
// projection. The daemon remains the authorization and filtering authority.
func (a *App) serveLauncherListQuery(w http.ResponseWriter, r *http.Request, auth *operatorAuthority, principalFilter, launcherFilter string) {
	started := time.Now()
	ctx := r.Context()

	scope, ok := a.resolveListScope(w, r, auth, principalFilter)
	if !ok {
		return
	}
	var principalID *int64
	principalName := ""
	if !scope.allPrincipals {
		id := scope.principal.ID
		principalID = &id
		principalName = scope.principal.Name
	}

	launchers, err := queryLaunchersForScope(a.DB, principalID, launcherFilter)
	duration := time.Since(started).Round(time.Millisecond).String()
	if err != nil {
		rec := auditRecord{
			Event:         "launcher.list",
			PrincipalName: principalName,
			Duration:      duration,
		}
		switch {
		case errors.Is(err, ErrLauncherNotFound):
			rec.Result = "launcher_not_found"
			writeLauncherControlAudit(ctx, rec, auth, nil)
			writeError(ctx, w, http.StatusNotFound, "launcher_not_found", "launcher not found")
		case errors.Is(err, ErrLauncherNameRequiresPrincipal):
			rec.Result = "launcher_name_requires_principal"
			writeLauncherControlAudit(ctx, rec, auth, nil)
			writeError(ctx, w, http.StatusBadRequest,
				"launcher_name_requires_principal",
				"launcher name filter requires --principal; without a Principal use a Launcher ID")
		default:
			rec.Result = "error"
			writeLauncherControlAudit(ctx, rec, auth, nil)
			opLog(ctx).Error("launcher list failed",
				slog.String("operation", "launcher_list"),
				slog.String("error", err.Error()),
			)
			writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		}
		return
	}

	// A narrowed success carries the resolved Launcher's full target
	// provenance; an unfiltered list carries no target Launcher provenance.
	var target *LauncherWithPrincipal
	if launcherFilter != "" {
		target = &launchers[0]
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
	}, auth, target)

	writeJSONRaw(ctx, w, http.StatusOK, resp)
}

func (a *App) handleShowLauncher(w http.ResponseWriter, r *http.Request) {
	auth, err := a.authenticatePrincipalControlRequest(w, r, "launcher")
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
	auth, err := a.authenticatePrincipalControlRequest(w, r, "launcher")
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
		result := "error"
		if isErrUserModeOwnerReserved(err) {
			result = "user_mode_owner_reserved"
		}
		writeLauncherControlAudit(ctx, auditRecord{
			Event:      "launcher.update",
			LauncherID: l.ID,
			Result:     result,
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
		case isErrUserModeOwnerReserved(err):
			writeError(ctx, w, http.StatusConflict, "user_mode_owner_reserved",
				"this launcher is managed by transparent user mode and cannot be mutated in this way")
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
	auth, err := a.authenticatePrincipalControlRequest(w, r, "launcher")
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
		}, auth, l)
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
		}, auth, l)
		writeError(ctx, w, http.StatusBadRequest, "invalid_scope", "invalid scope")
		return
	}

	// The two roots wire forms are mutually exclusive: the 2.1 path-only
	// form (allowed_roots) and the canonical rich form (allowed_root_entries)
	// must never be combined — any occurrence of either key, including JSON
	// null and the empty array, is the supplied form, so the requested
	// policy is never ambiguous (the 2.1 Go client serializes a nil slice
	// as null, which keeps its legacy value semantics in the legacy form
	// alone).
	if req.AllowedRoots.present && req.AllowedRootEntries.present {
		writeLauncherControlAudit(ctx, auditRecord{
			Event:      "launcher.scope_replace",
			LauncherID: l.ID,
			Result:     "invalid_allowed_roots",
			Duration:   time.Since(started).Round(time.Millisecond).String(),
		}, auth, l)
		writeError(ctx, w, http.StatusBadRequest, "invalid_allowed_roots",
			"provide either allowed_roots or allowed_root_entries, not both")
		return
	}

	var requestedEntries []AllowedRootEntry
	switch {
	case req.AllowedRootEntries.present:
		if scopeMode == LauncherScopeInherit {
			writeLauncherControlAudit(ctx, auditRecord{
				Event:      "launcher.scope_replace",
				LauncherID: l.ID,
				Result:     "invalid_allowed_roots",
				Duration:   time.Since(started).Round(time.Millisecond).String(),
			}, auth, l)
			writeError(ctx, w, http.StatusBadRequest, "invalid_allowed_roots", "inherit scope cannot carry allowed roots")
			return
		}
		if len(req.AllowedRootEntries.value) == 0 {
			writeLauncherControlAudit(ctx, auditRecord{
				Event:      "launcher.scope_replace",
				LauncherID: l.ID,
				Result:     "invalid_allowed_roots",
				Duration:   time.Since(started).Round(time.Millisecond).String(),
			}, auth, l)
			writeError(ctx, w, http.StatusBadRequest, "invalid_allowed_roots", "restricted scope requires at least one allowed root")
			return
		}
		// The rich form is the canonical representation: every entry carries
		// its access value, parsed here at the request boundary so an empty
		// or unknown spelling is never silently reinterpreted as omission.
		requestedEntries = make([]AllowedRootEntry, 0, len(req.AllowedRootEntries.value))
		for _, in := range req.AllowedRootEntries.value {
			access, aerr := parseAllowedRootAccess(in.Access)
			if aerr != nil {
				writeLauncherControlAudit(ctx, auditRecord{
					Event:      "launcher.scope_replace",
					LauncherID: l.ID,
					Result:     "invalid_access",
					Duration:   time.Since(started).Round(time.Millisecond).String(),
				}, auth, l)
				writeError(ctx, w, http.StatusBadRequest, "invalid_allowed_root_access", "access must be read_write or read_only")
				return
			}
			requestedEntries = append(requestedEntries, AllowedRootEntry{Path: in.Path, Access: access})
		}
	case req.AllowedRoots.present:
		// The legacy form preserves the 2.1 contract exactly: an inherit
		// replacement with an explicitly supplied empty array (or null,
		// which the 2.1 Go client serializes) is the documented valid
		// inherit body; a restricted replacement requires at least one
		// root. The form carries no access value, so every requested root
		// is the canonical read_write grant.
		if scopeMode == LauncherScopeInherit {
			if len(req.AllowedRoots.value) > 0 {
				writeLauncherControlAudit(ctx, auditRecord{
					Event:      "launcher.scope_replace",
					LauncherID: l.ID,
					Result:     "invalid_allowed_roots",
					Duration:   time.Since(started).Round(time.Millisecond).String(),
				}, auth, l)
				writeError(ctx, w, http.StatusBadRequest, "invalid_allowed_roots", "inherit scope cannot carry allowed roots")
				return
			}
			break
		}
		if len(req.AllowedRoots.value) == 0 {
			writeLauncherControlAudit(ctx, auditRecord{
				Event:      "launcher.scope_replace",
				LauncherID: l.ID,
				Result:     "invalid_allowed_roots",
				Duration:   time.Since(started).Round(time.Millisecond).String(),
			}, auth, l)
			writeError(ctx, w, http.StatusBadRequest, "invalid_allowed_roots", "restricted scope requires at least one allowed root")
			return
		}
		requestedEntries = allowedRootEntriesForPaths(req.AllowedRoots.value)
	default:
		if scopeMode == LauncherScopeRestricted {
			writeLauncherControlAudit(ctx, auditRecord{
				Event:      "launcher.scope_replace",
				LauncherID: l.ID,
				Result:     "invalid_allowed_roots",
				Duration:   time.Since(started).Round(time.Millisecond).String(),
			}, auth, l)
			writeError(ctx, w, http.StatusBadRequest, "invalid_allowed_roots", "restricted scope requires at least one allowed root")
			return
		}
	}

	// The Launcher scope replacement is a policy-authority mutation: it shares
	// the lifecycle serialization with Session creation so a concurrent create
	// observes either the pre-replacement or post-replacement scope, never a
	// mix, and a narrowing that linearizes first prevents the Session.
	// replaceLauncherScopeWithLifecycle owns that boundary and the current
	// policy snapshot inside it, and refuses any narrowing or rooting of the
	// reserved user-mode daemon-owner default Launcher before any change.
	updated, err := a.replaceLauncherScopeWithLifecycle(l.ID, scopeMode, requestedEntries)
	duration := time.Since(started).Round(time.Millisecond).String()
	if err != nil {
		// The refusal audit keeps the target provenance of the resolved
		// Launcher and the stable refusal result.
		writeLauncherControlAudit(ctx, auditRecord{
			Event:      "launcher.scope_replace",
			LauncherID: l.ID,
			Result:     launcherScopeReplaceAuditResult(err),
			Duration:   duration,
		}, auth, l)
		switch {
		case isErrLauncherNotFound(err):
			writeError(ctx, w, http.StatusNotFound, "launcher_not_found", "launcher not found")
		case isErrUserModeOwnerReserved(err):
			writeError(ctx, w, http.StatusConflict, "user_mode_owner_reserved",
				"this launcher is managed by transparent user mode and cannot be mutated in this way")
		case isErrInvalidScope(err):
			writeError(ctx, w, http.StatusBadRequest, "invalid_scope", "invalid scope")
		case isErrInvalidAllowedRoots(err):
			writeError(ctx, w, http.StatusBadRequest, "invalid_allowed_roots", "invalid allowed roots")
		case errors.Is(err, ErrInvalidAllowedRootAccess):
			writeError(ctx, w, http.StatusBadRequest, "invalid_allowed_root_access", "access must be read_write or read_only")
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

// launcherAllowedRootResponse is the narrow Launcher allowed-root mutation
// result: the changed flag plus the allowed_roots field identity, mirroring
// the Principal allowed-root mutation contract (principalChangedResponse).
// The full Launcher projection remains the show owner.
type launcherAllowedRootResponse struct {
	OK         bool   `json:"ok"`
	LauncherID string `json:"launcher_id"`
	Field      string `json:"field"`
	Changed    bool   `json:"changed"`
	Path       string `json:"path,omitempty"`
	Access     string `json:"access,omitempty"`
	Message    string `json:"message,omitempty"`
}

// launcherAllowedRootResponseOf composes the narrow mutation response from the
// domain result: a changed=false mutation carries the stable "unchanged"
// message exactly like the Principal allowed-root contract, and the canonical
// path and stored access are always reported for the add and set-access
// mutations — for an idempotent no-op the stored access is the pre-existing
// value, which may differ from the requested one.
func launcherAllowedRootResponseOf(launcherID string, entry AllowedRootEntry, changed bool) launcherAllowedRootResponse {
	resp := launcherAllowedRootResponse{
		OK:         true,
		LauncherID: launcherID,
		Field:      "allowed_roots",
		Changed:    changed,
		Path:       entry.Path,
		Access:     string(entry.Access),
	}
	if !changed {
		resp.Message = "unchanged"
	}
	return resp
}

// handleAddLauncherAllowedRoot adds one allowed root to a Launcher through the
// daemon-owned narrow mutation: the target Launcher is resolved under the
// request authority (requireScopedLauncher), then
// addLauncherAllowedRootWithLifecycle owns the lifecycle serialization, the
// current Principal ceiling, and the reservation guard. Adding the first root
// to an inherit-scope Launcher is the inherit -> restricted narrowing (never an
// authority broadening); the reserved daemon-owner default Launcher is refused.
// The success audit reports the committed post-mutation Launcher projection
// returned by the lifecycle owner — for the first add that is the committed
// restricted scope, never the pre-mutation inherit snapshot.
func (a *App) handleAddLauncherAllowedRoot(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	auth, err := a.authenticatePrincipalControlRequest(w, r, "launcher")
	if err != nil || auth == nil {
		return
	}
	ctx := r.Context()

	l, ok := a.requireScopedLauncher(w, r, auth)
	if !ok {
		return
	}

	var req allowedRootAddRequest
	if err := decodeJSONRequest(w, r, &req); err != nil {
		writeLauncherControlAudit(ctx, auditRecord{
			Event:      "launcher.allowed_root_add",
			LauncherID: l.ID,
			Result:     "invalid_json",
			Duration:   time.Since(started).Round(time.Millisecond).String(),
		}, auth, l)
		writeError(ctx, w, http.StatusBadRequest, "invalid_json", "invalid JSON request")
		return
	}
	if req.Path == "" {
		writeLauncherControlAudit(ctx, auditRecord{
			Event:      "launcher.allowed_root_add",
			LauncherID: l.ID,
			Result:     "missing_path",
			Duration:   time.Since(started).Round(time.Millisecond).String(),
		}, auth, l)
		writeError(ctx, w, http.StatusBadRequest, "missing_path", "path is required")
		return
	}

	// Parse the presence-aware optional access: an omitted field is the
	// canonical read_write grant (the 2.1 path-only semantics); any
	// occurrence — including JSON null and the empty string — must parse, so
	// an empty, null, or unknown spelling is never silently reinterpreted as
	// omission. The refusal audit carries no requested_access: the value was
	// never a canonical access mode.
	requestedAccess := AllowedRootAccessReadWrite
	if req.Access.present {
		parsed, aerr := parseAllowedRootAccess(req.Access.value)
		if aerr != nil {
			writeLauncherControlAudit(ctx, auditRecord{
				Event:      "launcher.allowed_root_add",
				LauncherID: l.ID,
				Result:     "invalid_access",
				Duration:   time.Since(started).Round(time.Millisecond).String(),
			}, auth, l)
			writeError(ctx, w, http.StatusBadRequest, "invalid_allowed_root_access", "access must be read_write or read_only")
			return
		}
		requestedAccess = parsed
	}

	// The narrow add shares the lifecycle serialization with Session creation
	// and the other ownership mutations (see handleReplaceLauncherAllowedRoots):
	// addLauncherAllowedRootWithLifecycle owns that boundary, the current
	// policy snapshot inside it, and the reserved-launcher refusal.
	committed, changed, entry, err := a.addLauncherAllowedRootWithLifecycle(l.ID, req.Path, requestedAccess)
	duration := time.Since(started).Round(time.Millisecond).String()
	if err != nil {
		// The refusal audit keeps the facts the request had already
		// established: the canonical requested access, the stable refusal
		// result, and the target provenance of the resolved Launcher (the
		// mutation committed nothing).
		writeLauncherControlAudit(ctx, auditRecord{
			Event:           "launcher.allowed_root_add",
			LauncherID:      l.ID,
			RequestedAccess: string(requestedAccess),
			Result:          launcherAllowedRootAuditResult(err),
			Duration:        duration,
		}, auth, l)
		switch {
		case isErrLauncherNotFound(err):
			writeError(ctx, w, http.StatusNotFound, "launcher_not_found", "launcher not found")
		case isErrUserModeOwnerReserved(err):
			writeError(ctx, w, http.StatusConflict, "user_mode_owner_reserved",
				"this launcher is managed by transparent user mode and cannot be mutated in this way")
		case isErrInvalidAllowedRoot(err):
			writeError(ctx, w, http.StatusBadRequest, "invalid_allowed_root", "invalid allowed root")
		case errors.Is(err, ErrInvalidAllowedRootAccess):
			writeError(ctx, w, http.StatusBadRequest, "invalid_allowed_root_access", "access must be read_write or read_only")
		case isErrLauncherRootOutsidePrincipal(err):
			writeError(ctx, w, http.StatusBadRequest, "outside_principal_root", "launcher root is not under the effective principal roots")
		default:
			opLog(ctx).Error("launcher allowed_root_add failed",
				slog.String("operation", "launcher_allowed_root_add"),
				slog.String("error", err.Error()),
			)
			writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		}
		return
	}

	writeLauncherControlAudit(ctx, auditRecord{
		Event:               "launcher.allowed_root_add",
		LauncherAllowedRoot: entry.Path,
		RequestedAccess:     string(requestedAccess),
		StoredAccess:        string(entry.Access),
		Result:              "success",
		Duration:            duration,
	}, auth, committed)

	writeJSONRaw(ctx, w, http.StatusOK, launcherAllowedRootResponseOf(committed.ID, entry, changed))
}

// handleRemoveLauncherAllowedRoot removes one stored root from a Launcher
// through the daemon-owned narrow mutation (see handleAddLauncherAllowedRoot
// for the authorization and serialization boundary). The scope mode is never
// changed by removal: removing the last restricted root leaves the Launcher
// restricted with zero roots (fail-closed), and returning to inherited roots is
// the explicit inherit replacement. Because the removal contract guarantees the
// scope mode and every other audited provenance field are identical before and
// after the committed mutation, the pre-mutation read is exactly the committed
// projection for the success audit.
func (a *App) handleRemoveLauncherAllowedRoot(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	auth, err := a.authenticatePrincipalControlRequest(w, r, "launcher")
	if err != nil || auth == nil {
		return
	}
	ctx := r.Context()

	l, ok := a.requireScopedLauncher(w, r, auth)
	if !ok {
		return
	}

	var req allowedRootRequest
	if err := decodeJSONRequest(w, r, &req); err != nil {
		writeLauncherControlAudit(ctx, auditRecord{
			Event:      "launcher.allowed_root_remove",
			LauncherID: l.ID,
			Result:     "invalid_json",
			Duration:   time.Since(started).Round(time.Millisecond).String(),
		}, auth, l)
		writeError(ctx, w, http.StatusBadRequest, "invalid_json", "invalid JSON request")
		return
	}
	if req.Path == "" {
		writeLauncherControlAudit(ctx, auditRecord{
			Event:      "launcher.allowed_root_remove",
			LauncherID: l.ID,
			Result:     "missing_path",
			Duration:   time.Since(started).Round(time.Millisecond).String(),
		}, auth, l)
		writeError(ctx, w, http.StatusBadRequest, "missing_path", "path is required")
		return
	}

	// Same lifecycle serialization boundary as the add and the scope
	// replacement; removeLauncherAllowedRootWithLifecycle owns it.
	changed, canonicalPath, err := a.removeLauncherAllowedRootWithLifecycle(l.ID, req.Path)
	duration := time.Since(started).Round(time.Millisecond).String()
	if err != nil {
		// The refusal audit keeps the target provenance of the resolved
		// Launcher and the stable refusal result.
		writeLauncherControlAudit(ctx, auditRecord{
			Event:      "launcher.allowed_root_remove",
			LauncherID: l.ID,
			Result:     launcherAllowedRootAuditResult(err),
			Duration:   duration,
		}, auth, l)
		switch {
		case isErrLauncherNotFound(err):
			writeError(ctx, w, http.StatusNotFound, "launcher_not_found", "launcher not found")
		case isErrUserModeOwnerReserved(err):
			writeError(ctx, w, http.StatusConflict, "user_mode_owner_reserved",
				"this launcher is managed by transparent user mode and cannot be mutated in this way")
		case isErrInvalidAllowedRoot(err):
			writeError(ctx, w, http.StatusBadRequest, "invalid_allowed_root", "invalid allowed root")
		default:
			opLog(ctx).Error("launcher allowed_root_remove failed",
				slog.String("operation", "launcher_allowed_root_remove"),
				slog.String("error", err.Error()),
			)
			writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		}
		return
	}

	writeLauncherControlAudit(ctx, auditRecord{
		Event:               "launcher.allowed_root_remove",
		LauncherAllowedRoot: canonicalPath,
		Result:              "success",
		Duration:            duration,
	}, auth, l)

	writeJSONRaw(ctx, w, http.StatusOK, launcherAllowedRootResponseOf(l.ID, AllowedRootEntry{Path: canonicalPath}, changed))
}

// handleSetLauncherAllowedRootAccess changes the access mode of exactly one
// stored Launcher root (PATCH .../allowed-roots). It is the targeted access
// mutation: the daemon performs one conditional mutation on the exact
// canonical stored identity — the CLI never performs a read-modify-write over
// the root list, so the daemon owns the mutation and its concurrency
// semantics. Unlike the idempotent remove, a missing stored root is refused
// (404 allowed_root_not_found) so a mistyped path can never be silently
// reported as satisfied, and the reserved user-mode daemon-owner default
// Launcher is refused like every other mutation. The mutation shares the
// lifecycle serialization with Session creation and the other root-policy
// mutations; no ceiling re-check is performed here, because the effective
// policy is composed by the canonical 2.2 effective-root owner at every
// consumption boundary. The scope mode is never changed.
func (a *App) handleSetLauncherAllowedRootAccess(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	auth, err := a.authenticatePrincipalControlRequest(w, r, "launcher")
	if err != nil || auth == nil {
		return
	}
	ctx := r.Context()

	l, ok := a.requireScopedLauncher(w, r, auth)
	if !ok {
		return
	}

	var req allowedRootSetAccessRequest
	if err := decodeJSONRequest(w, r, &req); err != nil {
		writeLauncherControlAudit(ctx, auditRecord{
			Event:      "launcher.allowed_root_set_access",
			LauncherID: l.ID,
			Result:     "invalid_json",
			Duration:   time.Since(started).Round(time.Millisecond).String(),
		}, auth, l)
		writeError(ctx, w, http.StatusBadRequest, "invalid_json", "invalid JSON request")
		return
	}
	if req.Path == "" {
		writeLauncherControlAudit(ctx, auditRecord{
			Event:      "launcher.allowed_root_set_access",
			LauncherID: l.ID,
			Result:     "missing_path",
			Duration:   time.Since(started).Round(time.Millisecond).String(),
		}, auth, l)
		writeError(ctx, w, http.StatusBadRequest, "missing_path", "path is required")
		return
	}
	requestedAccess, aerr := parseAllowedRootAccess(req.Access)
	if aerr != nil {
		// The HTTP code distinguishes the two refusals; the audit result
		// vocabulary is missing_access/invalid_access, and the refusal audit
		// carries no requested_access: the value was never a canonical
		// access mode.
		code := "missing_access"
		result := "missing_access"
		if req.Access != "" {
			code = "invalid_allowed_root_access"
			result = "invalid_access"
		}
		writeLauncherControlAudit(ctx, auditRecord{
			Event:      "launcher.allowed_root_set_access",
			LauncherID: l.ID,
			Result:     result,
			Duration:   time.Since(started).Round(time.Millisecond).String(),
		}, auth, l)
		writeError(ctx, w, http.StatusBadRequest, code, "access must be read_write or read_only")
		return
	}

	// Same lifecycle serialization boundary as the add, the remove, and the
	// scope replacement; setLauncherAllowedRootAccessWithLifecycle owns it.
	changed, entry, err := a.setLauncherAllowedRootAccessWithLifecycle(l.ID, req.Path, requestedAccess)
	duration := time.Since(started).Round(time.Millisecond).String()
	if err != nil {
		// The refusal keeps the facts the request had already established:
		// the canonical requested access, the stable refusal result, and the
		// target provenance of the resolved Launcher. The stored access is
		// never reported for a refusal (nothing was stored), and the
		// canonical targeted identity is carried by the typed not-found
		// refusal when the resolution had already succeeded.
		rec := auditRecord{
			Event:           "launcher.allowed_root_set_access",
			LauncherID:      l.ID,
			RequestedAccess: string(requestedAccess),
			Result:          launcherAllowedRootAuditResult(err),
			Duration:        duration,
		}
		var nf allowedRootNotFoundError
		if errors.As(err, &nf) {
			rec.LauncherAllowedRoot = nf.path
		}
		writeLauncherControlAudit(ctx, rec, auth, l)
		switch {
		case isErrLauncherNotFound(err):
			writeError(ctx, w, http.StatusNotFound, "launcher_not_found", "launcher not found")
		case isErrUserModeOwnerReserved(err):
			writeError(ctx, w, http.StatusConflict, "user_mode_owner_reserved",
				"this launcher is managed by transparent user mode and cannot be mutated in this way")
		case isErrInvalidAllowedRoot(err):
			writeError(ctx, w, http.StatusBadRequest, "invalid_allowed_root", "invalid allowed root")
		case errors.Is(err, ErrInvalidAllowedRootAccess):
			writeError(ctx, w, http.StatusBadRequest, "invalid_allowed_root_access", "access must be read_write or read_only")
		case errors.Is(err, ErrAllowedRootNotFound):
			writeError(ctx, w, http.StatusNotFound, "allowed_root_not_found", "allowed root not found")
		default:
			opLog(ctx).Error("launcher allowed_root_set_access failed",
				slog.String("operation", "launcher_allowed_root_set_access"),
				slog.String("error", err.Error()),
			)
			writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		}
		return
	}

	writeLauncherControlAudit(ctx, auditRecord{
		Event:               "launcher.allowed_root_set_access",
		LauncherAllowedRoot: entry.Path,
		RequestedAccess:     string(requestedAccess),
		StoredAccess:        string(entry.Access),
		Result:              "success",
		Duration:            duration,
	}, auth, l)

	writeJSONRaw(ctx, w, http.StatusOK, launcherAllowedRootResponseOf(l.ID, entry, changed))
}

func (a *App) handleDeleteLauncher(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	auth, err := a.authenticatePrincipalControlRequest(w, r, "launcher")
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
		result := "error"
		if isErrUserModeOwnerReserved(err) {
			result = "user_mode_owner_reserved"
		}
		writeLauncherControlAudit(ctx, auditRecord{
			Event:      "launcher.delete",
			LauncherID: l.ID,
			Result:     result,
			Duration:   duration,
		}, auth, nil)
		switch {
		case isErrLauncherNotFound(err):
			writeError(ctx, w, http.StatusNotFound, "launcher_not_found", "launcher not found")
		case isErrLauncherRuntimeActive(err):
			writeError(ctx, w, http.StatusConflict, "launcher_runtime_active", "launcher has active runtime")
		case isErrUserModeOwnerReserved(err):
			writeError(ctx, w, http.StatusConflict, "user_mode_owner_reserved",
				"this launcher is managed by transparent user mode and cannot be mutated in this way")
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
	auth, err := a.authenticatePrincipalControlRequest(w, r, "launcher")
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
	auth, err := a.authenticatePrincipalControlRequest(w, r, "launcher")
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
	auth, err := a.authenticatePrincipalControlRequest(w, r, "launcher")
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
	auth, err := a.authenticatePrincipalControlRequest(w, r, "launcher")
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
