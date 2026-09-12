package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"
)

// selfType names the one credential class a GET /self response introspects.
// The wire envelope's type field and the audit self_type field carry the same
// vocabulary: principal, launcher, session.
type selfType string

const (
	selfTypePrincipal selfType = "principal"
	selfTypeLauncher  selfType = "launcher"
	selfTypeSession   selfType = "session"
)

// selfResponse is the GET /self wire envelope: ok plus the authenticated
// credential class and that class's own resource document. Resource is
// carried as raw JSON so the concrete resource shape stays the one canonical
// projection of the class (principalSelfResource, launcherSelfResource, or
// sessionShowJSON) without a second discriminated wire type.
type selfResponse struct {
	OK       bool            `json:"ok"`
	Type     string          `json:"type"`
	Resource json.RawMessage `json:"resource"`
}

// principalSelfResource is the Principal self document: the authenticated
// Principal's public identity and stored allowed-root entries plus its
// effective allowed-root entries, all resolved in one coherent policy
// generation. It carries no credential material: no token, no hash, no
// credential IDs, and no foreign credentials.
type principalSelfResource struct {
	Username                    string             `json:"username"`
	UID                         int                `json:"uid"`
	GID                         int                `json:"gid"`
	Home                        string             `json:"home"`
	Enabled                     bool               `json:"enabled"`
	AllowedRootEntries          []AllowedRootEntry `json:"allowed_root_entries"`
	EffectiveAllowedRootEntries []AllowedRootEntry `json:"effective_allowed_root_entries"`
}

// launcherSelfResource is the Launcher self document: the authenticated
// Launcher's public identity and stored allowed-root entries (canonically
// empty for inherit scope) plus its effective allowed-root entries (the
// three-level global/Principal/Launcher composition), all resolved in one
// coherent policy generation. It carries no bearer hash and no parent
// Principal policy beyond the owning Principal name.
type launcherSelfResource struct {
	ID                          string             `json:"id"`
	Name                        string             `json:"name"`
	Principal                   string             `json:"principal"`
	Enabled                     bool               `json:"enabled"`
	Scope                       string             `json:"scope"`
	AllowedRootEntries          []AllowedRootEntry `json:"allowed_root_entries"`
	EffectiveAllowedRootEntries []AllowedRootEntry `json:"effective_allowed_root_entries"`
}

// principalSelfSnapshot is the immutable read-only projection of one coherent
// Principal self state: the owning Principal record plus its stored and
// effective allowed-root entries, resolved under the same lifecycle
// serialization boundary as the other ownership-policy projections.
type principalSelfSnapshot struct {
	Principal Principal
	Stored    []AllowedRootEntry
	Effective []AllowedRootEntry
}

// launcherSelfSnapshot is the immutable read-only projection of one coherent
// Launcher self state: the ownership snapshot of the Launcher and its
// Principal plus the Launcher's effective allowed-root entries, resolved
// under the same lifecycle serialization boundary as the other
// ownership-policy projections.
type launcherSelfSnapshot struct {
	Ownership *sessionOwnershipSnapshot
	Effective []AllowedRootEntry
}

// handleSelf answers GET /self: the one self-introspection endpoint. It
// classifies the request bearer and answers with the matching self resource,
// routing to the existing authentication owners — the admin token
// comparison, the transactional Session filesystem-authority capture
// (captureSessionFilesystemAuthority), and the shared operator credential
// authenticator (authenticateOperatorToken). It performs no owner resolution
// of its own and adds no authentication machinery: a credential either
// already authenticates as exactly one of the classes or receives the
// established non-disclosing 401 authentication contract.
//
//   - Admin token: no self resource. The stable 404 self_not_available
//     contract keeps the narrow self-show HTTP family separate from the
//     admin control planes; the audit carries result self_not_available.
//   - Session bearer: the Session self document, read together with its
//     persisted immutable filesystem snapshot in the same short read
//     transaction the filesystem-capability owner uses.
//   - Principal credential: the Principal self document (own identity,
//     stored roots, effective roots) under the lifecycle serialization
//     boundary.
//   - Launcher credential: the Launcher self document (own identity, stored
//     roots, effective three-level roots) under the same boundary.
//
// A live credential whose owning resource vanished between authentication
// and the coherent read (deleted Principal or Launcher) fails closed with
// the same non-disclosing 401 authentication contract as an unknown
// credential: the self resource no longer exists for the caller and no
// vanished-state detail is disclosed. Database failures are HTTP 500 and
// never a 401. The endpoint is read-only and grants no authority the
// credential does not already have.
func (a *App) handleSelf(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	ctx := r.Context()

	token, ok := parseBearerToken(r)
	if !ok {
		writeAuthFailure(ctx, r, "self.parse_failed")
		writeUnauthorizedAuth(ctx, w)
		return
	}

	// The admin comparison is first, exactly like the operator
	// authenticator: the admin token is answered from the token comparison
	// alone and never causes a credential or Session database lookup. The
	// admin token has no self resource.
	if _, matched := a.matchAdminToken(token); matched {
		writeRequestContextAudit(ctx, auditRecord{
			Event:    "self.show",
			Result:   "self_not_available",
			Duration: time.Since(started).Round(time.Millisecond).String(),
		})
		writeError(ctx, w, http.StatusNotFound, "self_not_available", "no self resource for this authority")
		return
	}

	// Session class: the transactional filesystem-authority capture is the
	// one owner of the live-Session read and its snapshot. A bearer that is
	// not a live Session credential falls through to the operator
	// credential class — the capture miss is not an outcome by itself.
	// Any capture database or integrity failure fails closed immediately.
	sessionAuthority, cerr := a.captureSessionFilesystemAuthority(token)
	if cerr != nil {
		switch cerr.class {
		case sessionAuthorityCaptureNotFound:
			// Fall through to the operator credential class below.
		case sessionAuthorityCaptureIntegrity:
			writeSessionFilesystemAuthorityRejected(ctx, w, "self", cerr.session, cerr.cause)
			return
		default:
			writeAuthFailure(ctx, r, "self.database_error")
			logArgs := []any{
				slog.String("operation", "self_introspect"),
				slog.String("error", cerr.cause.Error()),
			}
			if cerr.session != nil {
				logArgs = append(logArgs, slog.String("session_id", cerr.session.ID))
			}
			opLog(ctx).Error(cerr.logMsg, logArgs...)
			writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
			return
		}
	}

	if sessionAuthority != nil {
		session := sessionAuthority.Session
		resource := marshalSelfResourceOrPanic(ctx, w, sessionShowToJSON(*session, sessionAuthority.Snapshot))
		if resource == nil {
			return
		}
		writeSelfResult(ctx, w, started, selfTypeSession, resource, auditRecord{
			SessionID:     session.ID,
			Workspace:     session.Workspace,
			LauncherID:    session.LauncherID,
			LauncherName:  session.LauncherName,
			PrincipalName: session.PrincipalName,
		})
		return
	}

	authority, err := a.authenticateOperatorToken(token)
	if err != nil {
		if classifyCredentialAuthFailure(err).isExpectedAuthFailure() {
			writeAuthFailure(ctx, r, "self.unauthorized")
			writeUnauthorizedAuth(ctx, w)
			return
		}
		writeAuthFailure(ctx, r, "self.database_error")
		opLog(ctx).Error("self introspection database error",
			slog.String("operation", "self_introspect"),
			slog.String("error", err.Error()),
		)
		writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}

	switch authority.class {
	case operatorAuthorityAdmin:
		// Structurally unreachable (the admin comparison already failed
		// above), but the class contract stays closed and explicit: the
		// admin token keeps the same self_not_available outcome here as in
		// the fast path above.
		writeRequestContextAudit(ctx, auditRecord{
			Event:    "self.show",
			Result:   "self_not_available",
			Duration: time.Since(started).Round(time.Millisecond).String(),
		})
		writeError(ctx, w, http.StatusNotFound, "self_not_available", "no self resource for this authority")
	case operatorAuthorityPrincipal:
		snap, err := a.resolvePrincipalSelfSnapshot(authority.principal.PrincipalID)
		if err != nil {
			if isErrPrincipalNotFound(err) {
				// The owning Principal vanished between authentication and
				// the coherent read: fail closed with the same
				// non-disclosing authentication contract as an unknown
				// credential.
				writeAuthFailure(ctx, r, "self.unauthorized")
				writeUnauthorizedAuth(ctx, w)
				return
			}
			opLog(ctx).Error("self introspection failed",
				slog.String("operation", "self_introspect"),
				slog.String("error", err.Error()),
			)
			writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
			return
		}
		resource := marshalSelfResourceOrPanic(ctx, w, principalSelfResource{
			Username:                    snap.Principal.Username,
			UID:                         snap.Principal.UID,
			GID:                         snap.Principal.GID,
			Home:                        snap.Principal.Home,
			Enabled:                     snap.Principal.Enabled,
			AllowedRootEntries:          ensureRootEntries(snap.Stored),
			EffectiveAllowedRootEntries: ensureRootEntries(snap.Effective),
		})
		if resource == nil {
			return
		}
		writeSelfResult(ctx, w, started, selfTypePrincipal, resource, auditRecord{
			PrincipalName: snap.Principal.Username,
		})
	case operatorAuthorityLauncher:
		snap, err := a.resolveLauncherSelfSnapshot(authority.launcher.LauncherID)
		if err != nil {
			if errors.Is(err, ErrLauncherNotFound) {
				// The owning Launcher vanished between authentication and
				// the coherent read: fail closed with the same
				// non-disclosing authentication contract as an unknown
				// credential.
				writeAuthFailure(ctx, r, "self.unauthorized")
				writeUnauthorizedAuth(ctx, w)
				return
			}
			opLog(ctx).Error("self introspection failed",
				slog.String("operation", "self_introspect"),
				slog.String("error", err.Error()),
			)
			writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
			return
		}
		ownership := snap.Ownership
		resource := marshalSelfResourceOrPanic(ctx, w, launcherSelfResource{
			ID:                          ownership.launcherID,
			Name:                        ownership.launcherName,
			Principal:                   ownership.principalName,
			Enabled:                     ownership.launcherEnabled,
			Scope:                       string(ownership.launcherScope),
			AllowedRootEntries:          ensureRootEntries(ownership.launcherRoots),
			EffectiveAllowedRootEntries: ensureRootEntries(snap.Effective),
		})
		if resource == nil {
			return
		}
		writeSelfResult(ctx, w, started, selfTypeLauncher, resource, auditRecord{
			LauncherID:    ownership.launcherID,
			LauncherName:  ownership.launcherName,
			PrincipalName: ownership.principalName,
		})
	default:
		writeInvalidOperatorAuthority(ctx, r, w, "self", "self_introspect", authority)
	}
}

// resolvePrincipalSelfSnapshot is the lock-owning read form of the Principal
// self projection: the owning Principal record (resolved by its exact
// authenticated Principal ID, so a stale authority never observes a
// recreated same-username Principal), its canonical stored allowed-root
// entries, and its canonical effective allowed-root entries — all under the
// lifecycle serialization boundary, so the projection observes the same
// coherent ownership-policy state model as the other ownership projections.
func (a *App) resolvePrincipalSelfSnapshot(principalID int64) (*principalSelfSnapshot, error) {
	a.lifecycleMu.Lock()
	defer a.lifecycleMu.Unlock()

	p, err := findPrincipalByID(a.DB, int(principalID))
	if err != nil {
		return nil, err
	}
	stored, err := readPrincipalAllowedRoots(a.DB, int64(p.ID))
	if err != nil {
		return nil, err
	}
	effective, err := a.resolveEffectivePrincipalRootEntries(int64(p.ID))
	if err != nil {
		return nil, err
	}
	return &principalSelfSnapshot{Principal: *p, Stored: stored, Effective: effective}, nil
}

// resolveLauncherSelfSnapshot is the lock-owning read form of the Launcher
// self projection: the ownership snapshot of the exact authenticated Launcher
// (Launcher identity, owning Principal, and both root sets in one
// transaction) plus the Launcher's canonical effective allowed-root entries —
// all under the lifecycle serialization boundary. It applies no availability
// gate: a since-disabled Launcher projects truthfully instead of failing,
// exactly like an authenticated read of its state.
func (a *App) resolveLauncherSelfSnapshot(launcherID string) (*launcherSelfSnapshot, error) {
	a.lifecycleMu.Lock()
	defer a.lifecycleMu.Unlock()

	snap, err := a.resolveSessionOwnershipSnapshot(launcherID)
	if err != nil {
		return nil, err
	}

	globalEntries, err := a.appResolvedGlobalRootEntries()
	if err != nil {
		return nil, err
	}
	userMode := a.getConfig().Mode == ModeUser
	var daemonID int64
	if userMode && a.userModeDefault != nil {
		daemonID = a.userModeDefault.principalID
	}
	effective, err := effectiveLauncherAllowedRoots(globalEntries, snap, daemonID, userMode)
	if err != nil {
		return nil, err
	}
	return &launcherSelfSnapshot{Ownership: snap, Effective: effective}, nil
}

// ensureRootEntries serializes an internal nil slice as the empty JSON
// array: the wire contract represents zero roots as [], never null.
func ensureRootEntries(entries []AllowedRootEntry) []AllowedRootEntry {
	if entries == nil {
		return []AllowedRootEntry{}
	}
	return entries
}

// marshalSelfResourceOrPanic marshals one self resource document into the
// envelope's raw resource body. The resource types are plain projections of
// already-validated domain state, so a marshal failure is an internal
// anomaly, answered with the internal-error contract and never silently
// dropped.
func marshalSelfResourceOrPanic(ctx context.Context, w http.ResponseWriter, resource any) json.RawMessage {
	body, err := json.Marshal(resource)
	if err != nil {
		opLog(ctx).Error("cannot marshal self resource",
			slog.String("operation", "self_introspect"),
			slog.String("error", err.Error()),
		)
		writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		return nil
	}
	return body
}

// writeSelfResult audits one successful self introspection with the
// class-wide provenance fields and writes the envelope.
func writeSelfResult(ctx context.Context, w http.ResponseWriter, started time.Time, t selfType, resource json.RawMessage, provenance auditRecord) {
	provenance.Event = "self.show"
	provenance.Result = "success"
	provenance.SelfType = string(t)
	provenance.Duration = time.Since(started).Round(time.Millisecond).String()
	writeRequestContextAudit(ctx, provenance)
	writeJSONRaw(ctx, w, http.StatusOK, selfResponse{OK: true, Type: string(t), Resource: resource})
}
