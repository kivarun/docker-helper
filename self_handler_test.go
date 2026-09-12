package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// selfFixture extends the operator authority fixture with a live Session
// bearer for the session self class.
type selfFixture struct {
	operatorAuthFixture
	sessionToken string
	sessionID    string
}

// setupSelfFixture provisions the operator authority fixture plus one live
// Session created with the principal credential (so the Session's owning
// Launcher and Principal are the fixture ones).
func setupSelfFixture(t *testing.T, app *App) selfFixture {
	t.Helper()
	f := selfFixture{operatorAuthFixture: setupOperatorAuthFixture(t, app)}

	created, err := app.createSessionAuthorized(
		&operatorAuthority{class: operatorAuthorityPrincipal,
			principal: &PrincipalCredentialAuth{
				PrincipalID:   principalIDByName(t, app.DB, f.principalName),
				PrincipalName: f.principalName,
			}},
		createSelector{}, f.workspace, nil,
	)
	if err != nil {
		t.Fatalf("createSessionAuthorized(session bearer): %v", err)
	}
	f.sessionToken = created.Token
	f.sessionID = created.Session.ID
	return f
}

// selfRequest issues one GET /self request against the app with the given
// bearer token value ("": header absent).
func selfRequest(app *App, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/self", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	app.handleSelf(w, req)
	return w
}

// assertSelfEnvelope decodes the successful envelope and returns its decoded
// resource body.
func assertSelfEnvelope(t *testing.T, w *httptest.ResponseRecorder) (string, map[string]any) {
	t.Helper()
	var envelope struct {
		OK       bool            `json:"ok"`
		Type     string          `json:"type"`
		Resource json.RawMessage `json:"resource"`
	}
	if err := json.NewDecoder(w.Body).Decode(&envelope); err != nil {
		t.Fatalf("cannot decode /self envelope: %v (body: %s)", err, w.Body.String())
	}
	if !envelope.OK {
		t.Fatalf("envelope ok = false: %s", w.Body.String())
	}
	var resource map[string]any
	if err := json.Unmarshal(envelope.Resource, &resource); err != nil {
		t.Fatalf("cannot decode /self resource: %v (resource: %s)", err, envelope.Resource)
	}
	return envelope.Type, resource
}

// assertSelfShowAudit asserts the raw audit output carries exactly one
// self.show record with the expected result, no auth.failure record, and no
// secret material. selfType is the expected self_type field value ("" for
// the admin self_not_available outcome).
func assertSelfShowAudit(t *testing.T, buf *bytes.Buffer, wantResult, wantType string) {
	t.Helper()
	lines := findAuthFailureRawLines(buf)
	if len(lines) != 0 {
		t.Errorf("expected no auth.failure records, got %d", len(lines))
	}
	var records []map[string]any
	for _, line := range strings.Split(buf.String(), "\n") {
		if !strings.Contains(line, `"self.show"`) {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("cannot decode self.show record: %v (%s)", err, line)
		}
		records = append(records, rec)
	}
	if len(records) != 1 {
		t.Fatalf("self.show records = %d, want exactly 1 (raw: %s)", len(records), buf.String())
	}
	if records[0]["result"] != wantResult {
		t.Errorf("self.show result = %v, want %v", records[0]["result"], wantResult)
	}
	selfType, _ := records[0]["self_type"].(string)
	if selfType != wantType {
		t.Errorf("self.show self_type = %q, want %q", selfType, wantType)
	}
}

// decodeRootEntries decodes a JSON root-entries projection into the canonical
// rich entry shape for structural comparison (JSON object key order in a
// re-marshaled map is not stable; the entry shape is).
func decodeRootEntries(t *testing.T, raw any) []AllowedRootEntry {
	t.Helper()
	body, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	var entries []AllowedRootEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		t.Fatalf("cannot decode root entries %s: %v", body, err)
	}
	return entries
}

// TestSelfHandleMatrix covers the /self classification matrix: the exact
// status, wire outcome, and audit outcome per bearer class and failure mode.
// The /self auth failures follow the shared non-disclosing authentication
// contract (one auth.failure record, no identity material); the admin class
// has no self resource and is answered with the stable self_not_available
// family.
func TestSelfHandleMatrix(t *testing.T) {
	const message = "Authentication required."
	cases := []struct {
		name       string
		bearer     func(f selfFixture) string
		mutate     func(t *testing.T, app *App, f selfFixture)
		wantStatus int
		wantResult string // non-empty: expected audit result code
		wantType   string // non-empty: expected envelope type on success
	}{
		{
			name:       "missing header",
			bearer:     func(selfFixture) string { return "" },
			wantStatus: http.StatusUnauthorized,
			wantResult: "self.parse_failed",
		},
		{
			name:       "wrong scheme",
			bearer:     func(selfFixture) string { return "Basic dXNlcjpwYXNz" },
			wantStatus: http.StatusUnauthorized,
			wantResult: "self.parse_failed",
		},
		{
			name:       "empty bearer",
			bearer:     func(selfFixture) string { return "Bearer " },
			wantStatus: http.StatusUnauthorized,
			wantResult: "self.parse_failed",
		},
		{
			name:       "unknown token",
			bearer:     func(selfFixture) string { return "dht_unknown_self_token_7k2m9f" },
			wantStatus: http.StatusUnauthorized,
			wantResult: "self.unauthorized",
		},
		{
			name:       "revoked principal credential",
			bearer:     func(f selfFixture) string { return f.revokedToken },
			wantStatus: http.StatusUnauthorized,
			wantResult: "self.unauthorized",
		},
		{
			name:   "disabled principal",
			bearer: func(f selfFixture) string { return f.principalToken },
			mutate: func(t *testing.T, app *App, f selfFixture) {
				disableFixturePrincipal(t, app, f.operatorAuthFixture)
			},
			wantStatus: http.StatusUnauthorized,
			wantResult: "self.unauthorized",
		},
		{
			name:   "disabled launcher",
			bearer: func(f selfFixture) string { return f.launcherToken },
			mutate: func(t *testing.T, app *App, f selfFixture) {
				disableFixtureLauncher(t, app, f.operatorAuthFixture)
			},
			wantStatus: http.StatusUnauthorized,
			wantResult: "self.unauthorized",
		},
		{
			name:       "admin has no self resource",
			bearer:     func(selfFixture) string { return testAdminToken },
			wantStatus: http.StatusNotFound,
			wantResult: "self_not_available",
		},
		{
			name:       "principal credential",
			bearer:     func(f selfFixture) string { return f.principalToken },
			wantStatus: http.StatusOK,
			wantType:   "principal",
		},
		{
			name:       "launcher credential",
			bearer:     func(f selfFixture) string { return f.launcherToken },
			wantStatus: http.StatusOK,
			wantType:   "launcher",
		},
		{
			name:       "session bearer",
			bearer:     func(f selfFixture) string { return f.sessionToken },
			wantStatus: http.StatusOK,
			wantType:   "session",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			auditBuf, _ := setupTestLogging(t)
			app := newTestAppWithAdminToken(t)
			f := setupSelfFixture(t, app)
			if tc.mutate != nil {
				tc.mutate(t, app, f)
			}

			w := selfRequest(app, tc.bearer(f))
			if w.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d, body: %s", w.Code, tc.wantStatus, w.Body.String())
			}

			if tc.wantType == "" {
				// The failure/admin outcomes carry no resource envelope.
				if tc.wantResult == "self_not_available" {
					var body struct {
						OK   bool   `json:"ok"`
						Code string `json:"code"`
					}
					if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
						t.Fatalf("cannot decode response: %v", err)
					}
					if body.OK || body.Code != "self_not_available" {
						t.Fatalf("admin self response = %+v, want ok=false code=self_not_available", body)
					}
					assertSelfShowAudit(t, auditBuf, "self_not_available", "")
					return
				}
				assertUnauthorizedResponse(t, w, message)
				assertSingleAuthFailure(t, auditBuf, authFailureExpectation{
					Method: http.MethodGet,
					Path:   "/self",
					Result: tc.wantResult,
				})
				return
			}

			// The success outcomes: no auth.failure, exactly one self.show
			// success record with the authenticated class, and the matching
			// envelope type.
			selfType, _ := assertSelfEnvelope(t, w)
			if selfType != tc.wantType {
				t.Fatalf("envelope type = %q, want %q", selfType, tc.wantType)
			}
			assertSelfShowAudit(t, auditBuf, "success", tc.wantType)
		})
	}
}

// TestSelfPrincipalProjection proves the Principal self resource projects the
// exact stored identity and the canonical stored/effective allowed-root
// evaluations of the production owners in one coherent generation.
func TestSelfPrincipalProjection(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAdminToken(t)
	f := setupSelfFixture(t, app)
	assertNoAuthFailure(t, auditBuf)

	// Stored policy: one read-write root (the workspace parent) and one
	// read-only root under it.
	inputs := filepath.Join(f.workspace, "inputs")
	if err := os.MkdirAll(inputs, 0755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := addPrincipalAllowedRoot(app.DB, f.principalName, inputs, AllowedRootAccessReadOnly, allowedRootPaths(app.getConfig().AllowedRoots)); err != nil {
		t.Fatalf("addPrincipalAllowedRoot(inputs): %v", err)
	}

	w := selfRequest(app, f.principalToken)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", w.Code, w.Body.String())
	}
	_, resource := assertSelfEnvelope(t, w)

	if resource["username"] != f.principalName {
		t.Errorf("username = %v, want %v", resource["username"], f.principalName)
	}
	if enabled, _ := resource["enabled"].(bool); !enabled {
		t.Errorf("enabled = %v, want true", resource["enabled"])
	}

	// The stored and effective entries must be exactly the canonical
	// evaluations of the production owners for the same state (rich entries
	// with access modes, never the 2.x path-only form).
	pid := principalIDByName(t, app.DB, f.principalName)
	stored, err := readPrincipalAllowedRoots(app.DB, pid)
	if err != nil {
		t.Fatalf("readPrincipalAllowedRoots: %v", err)
	}
	effective, err := app.resolveEffectivePrincipalRootEntries(pid)
	if err != nil {
		t.Fatalf("resolveEffectivePrincipalRootEntries: %v", err)
	}
	gotStored := decodeRootEntries(t, resource["allowed_root_entries"])
	gotEffective := decodeRootEntries(t, resource["effective_allowed_root_entries"])
	if len(gotStored) != len(stored) {
		t.Errorf("allowed_root_entries = %v, want %v", gotStored, stored)
	}
	for i := range stored {
		if gotStored[i] != stored[i] {
			t.Errorf("allowed_root_entries[%d] = %+v, want %+v", i, gotStored[i], stored[i])
		}
	}
	if len(gotEffective) != len(effective) {
		t.Errorf("effective_allowed_root_entries = %v, want %v", gotEffective, effective)
	}
	for i := range effective {
		if gotEffective[i] != effective[i] {
			t.Errorf("effective_allowed_root_entries[%d] = %+v, want %+v", i, gotEffective[i], effective[i])
		}
	}
	if len(stored) != 2 {
		t.Fatalf("fixture stored roots = %d, want 2 (fixture must actually exercise multi-entry policy)", len(stored))
	}
}

// TestSelfLauncherProjection proves the Launcher self resource projects the
// ownership identity and that its effective entries equal the canonical
// create-policy evaluation of the same Launcher (the three-level composition
// owner), for both inherit and restricted scopes.
func TestSelfLauncherProjection(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAdminToken(t)
	f := setupSelfFixture(t, app)
	assertNoAuthFailure(t, auditBuf)

	cred, err := authenticateCredential(app.DB, f.launcherToken)
	if err != nil {
		t.Fatalf("authenticateCredential(launcher): %v", err)
	}
	auth := &operatorAuthority{class: operatorAuthorityLauncher, launcher: cred.Launcher}

	// Inherit scope first: stored canonically empty, effective = the
	// canonical create-policy evaluation of the same authority.
	w := selfRequest(app, f.launcherToken)
	if w.Code != http.StatusOK {
		t.Fatalf("inherit status = %d, body: %s", w.Code, w.Body.String())
	}
	_, resource := assertSelfEnvelope(t, w)
	if resource["id"] != f.launcherID || resource["name"] != f.launcherName {
		t.Errorf("inherit identity = %v/%v, want %v/%v", resource["id"], resource["name"], f.launcherID, f.launcherName)
	}
	if resource["principal"] != f.principalName || resource["scope"] != "inherit" {
		t.Errorf("inherit ownership = %v (principal %v), want inherit/%v", resource["scope"], resource["principal"], f.principalName)
	}
	gotStored, err := json.Marshal(resource["allowed_root_entries"])
	if err != nil {
		t.Fatal(err)
	}
	if string(gotStored) != "[]" {
		t.Errorf("inherit stored roots = %s, want []", gotStored)
	}
	assertEffectiveEqualsCreatePolicy(t, app, auth, resource["effective_allowed_root_entries"], "inherit")

	// Restricted scope: the stored entries are the restricted roots and the
	// effective entries are the three-level composition.
	restrictedRoot := filepath.Join(f.workspace, "restricted")
	if err := os.MkdirAll(restrictedRoot, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := app.replaceLauncherScopeWithLifecycle(f.launcherID, LauncherScopeRestricted, []AllowedRootEntry{
		{Path: restrictedRoot, Access: AllowedRootAccessReadOnly},
	}); err != nil {
		t.Fatalf("replaceLauncherScopeWithLifecycle: %v", err)
	}

	w = selfRequest(app, f.launcherToken)
	if w.Code != http.StatusOK {
		t.Fatalf("restricted status = %d, body: %s", w.Code, w.Body.String())
	}
	_, resource = assertSelfEnvelope(t, w)
	if resource["scope"] != "restricted" {
		t.Errorf("restricted scope = %v, want restricted", resource["scope"])
	}
	gotStored, err = json.Marshal(resource["allowed_root_entries"])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(gotStored), restrictedRoot) {
		t.Errorf("restricted stored roots = %s, want %q present", gotStored, restrictedRoot)
	}
	assertEffectiveEqualsCreatePolicy(t, app, auth, resource["effective_allowed_root_entries"], "restricted")
}

// assertEffectiveEqualsCreatePolicy proves the launcher self effective
// entries equal the canonical create-policy projection of the same authority
// (the accepted three-level composition owner) — not a local recomputation.
func assertEffectiveEqualsCreatePolicy(t *testing.T, app *App, auth *operatorAuthority, got any, phase string) {
	t.Helper()
	policy, err := app.resolveCreatePolicySnapshot(auth, createSelector{}, "")
	if err != nil {
		t.Fatalf("resolveCreatePolicySnapshot(%s): %v", phase, err)
	}
	have := decodeRootEntries(t, got)
	want := policy.EffectiveAllowedRootEntries
	if len(have) != len(want) {
		t.Errorf("%s: effective entries = %v, want create-policy projection %v", phase, have, want)
		return
	}
	for i := range want {
		if have[i] != want[i] {
			t.Errorf("%s: effective entries[%d] = %+v, want %+v", phase, i, have[i], want[i])
		}
	}
}

// TestSelfSessionProjection proves the Session self resource is the session
// show body of the authenticated Session: identity, ownership, expiry, and
// the persisted immutable filesystem snapshot in canonical ordering.
func TestSelfSessionProjection(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAdminToken(t)
	f := setupSelfFixture(t, app)
	assertNoAuthFailure(t, auditBuf)

	w := selfRequest(app, f.sessionToken)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", w.Code, w.Body.String())
	}
	_, resource := assertSelfEnvelope(t, w)

	if resource["id"] != f.sessionID {
		t.Errorf("session id = %v, want %v", resource["id"], f.sessionID)
	}
	if resource["workspace"] != f.workspace {
		t.Errorf("workspace = %v, want %v", resource["workspace"], f.workspace)
	}
	created, _ := resource["created_at"].(string)
	expires, _ := resource["expires_at"].(string)
	if created == "" || expires == "" {
		t.Errorf("created_at/expires_at = %q/%q, want both set", created, expires)
	}

	// The owning Launcher of the created Session (the eager default
	// Launcher of the fixture Principal), not the fixture's explicit
	// 'work' Launcher.
	ownerLauncherID, _ := resource["launcher_id"].(string)
	ownerLauncherName, _ := resource["launcher"].(string)
	if ownerLauncherID == "" || ownerLauncherID == f.launcherID {
		t.Errorf("launcher_id = %q, want the owning default Launcher id", ownerLauncherID)
	}
	if ownerLauncherName != "default" {
		t.Errorf("launcher name = %q, want the owning default Launcher name", ownerLauncherName)
	}

	// The snapshot block is the persisted snapshot: exactly the issued
	// workspace entry with its issued access mode.
	snapshot, ok := resource["filesystem_snapshot"].(map[string]any)
	if !ok {
		t.Fatalf("filesystem_snapshot = %v, want an object", resource["filesystem_snapshot"])
	}
	entries, ok := snapshot["entries"].([]any)
	if !ok {
		t.Fatalf("snapshot entries = %v, want an array", snapshot["entries"])
	}
	if len(entries) != 1 {
		t.Fatalf("snapshot entries = %d, want exactly the issued workspace entry", len(entries))
	}
	entry, ok := entries[0].(map[string]any)
	if !ok {
		t.Fatalf("snapshot entry[0] = %v, want an object", entries[0])
	}
	if entry["path"] != f.workspace {
		t.Errorf("issued entry path = %v, want %v", entry["path"], f.workspace)
	}
	if entry["access"] != string(AllowedRootAccessReadWrite) {
		t.Errorf("issued entry access = %v, want %v", entry["access"], AllowedRootAccessReadWrite)
	}
}

// TestSelfHandleDatabaseError proves a genuine credential authentication
// database error on GET /self stays an internal error (self.database_error
// audit) and is never converted into a 401.
func TestSelfHandleDatabaseError(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAdminToken(t)

	dbPath := app.Config.DatabasePath
	app.DB.Close()
	app.DB = newFailQueryDB(t, dbPath, errMockQueryFail)
	defer app.DB.Close()

	const token = "dht_unknown_self_token_dbfail_9k2m"
	w := selfRequest(app, token)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d, body: %s", w.Code, http.StatusInternalServerError, w.Body.String())
	}
	assertSingleAuthFailure(t, auditBuf, authFailureExpectation{
		Method:        http.MethodGet,
		Path:          "/self",
		Result:        "self.database_error",
		InjectedToken: token,
		InjectedErr:   "mock_query_injection_error_for_testing",
	})
}

// TestSelfNoSecretLeak proves the /self success output and audit trail carry
// no bearer, credential-token, or authorization material: unique markers are
// injected into the request and the raw observable output is scanned.
func TestSelfNoSecretLeak(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAdminToken(t)
	f := setupSelfFixture(t, app)

	const secretMarker = "leakmarker_self_header_9x7k2m4q"
	req := httptest.NewRequest(http.MethodGet, "/self", nil)
	req.Header.Set("Authorization", "Bearer "+f.sessionToken)
	req.Header.Set("X-Test-Secret", secretMarker)
	w := httptest.NewRecorder()
	app.handleSelf(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), secretMarker) || strings.Contains(w.Body.String(), f.sessionToken) {
		t.Fatalf("/self body leaks secret material: %s", w.Body.String())
	}
	raw := auditBuf.String()
	for _, secret := range []string{secretMarker, f.sessionToken, f.principalToken, f.launcherToken, testAdminToken} {
		if strings.Contains(raw, secret) {
			t.Fatalf("audit output leaks secret material: %q present in %s", secret, raw)
		}
	}
	assertSelfShowAudit(t, auditBuf, "success", "session")
}
