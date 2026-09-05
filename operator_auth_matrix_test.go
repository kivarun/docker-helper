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

// Operator-authentication authority matrix over the real public families.
//
// Four public surfaces cover the three operator authority ceilings plus the
// read-only /auth projection:
//
//	admin-only operator   GET /principals   (requireAdmin)
//	Principal control     GET /launchers    (Admin | Principal only)
//	Session control       POST /sessions    (Admin | Principal | Launcher)
//	auth introspection    GET /auth         (all three, projects wire shape)
//
// A Session capability token (dht_...) is a data-plane bearer and never an
// operator authority; it is expected to fail on every operator surface.
// The session-control credential database-error contract is covered by
// TestAuthAuditSessionControlCredentialDatabaseError_CreateSession.

// operatorAuthFixture holds one concrete bearer per operator authority plus
// the identifiers needed to revoke or disable them. Every matrix case builds
// a fresh app and fixture, so owner names never collide across cases.
type operatorAuthFixture struct {
	principalName  string
	principalToken string
	revokedToken   string
	launcherToken  string
	launcherID     string
	launcherName   string
	// workspace is a directory inside the fixture Principal's own allowed
	// root (its OS home), usable as a Session workspace for credential
	// authorities.
	workspace string
}

// setupOperatorAuthFixture provisions one Principal with an active Principal
// credential, a revoked Principal credential, and a Launcher with an active
// Launcher credential, all under the app's allowed root.
func setupOperatorAuthFixture(t *testing.T, app *App) operatorAuthFixture {
	t.Helper()
	const username = "matrixuser"
	home := filepath.Join(app.Config.AllowedRoots[0], "home", username)
	workspace := filepath.Join(home, "proj")
	if err := os.MkdirAll(workspace, 0755); err != nil {
		t.Fatal(err)
	}
	installOSUserMock(t, map[string]string{username: home})
	if _, err := createPrincipal(app.DB, username, app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal(%s): %v", username, err)
	}
	pid := principalIDByName(t, app.DB, username)
	mustAddDefaultLauncher(t, app.DB, pid)

	_, principalToken, err := createPrincipalCredential(app.DB, username, "active")
	if err != nil {
		t.Fatalf("createPrincipalCredential(active): %v", err)
	}
	revoked, revokedToken, err := createPrincipalCredential(app.DB, username, "revoked")
	if err != nil {
		t.Fatalf("createPrincipalCredential(revoked): %v", err)
	}
	if _, err := revokePrincipalCredential(app.DB, revoked.ID); err != nil {
		t.Fatalf("revokePrincipalCredential: %v", err)
	}
	l, _, launcherToken, err := createLauncher(app.DB, pid, "work", LauncherScopeInherit, nil, nil, true)
	if err != nil {
		t.Fatalf("createLauncher: %v", err)
	}

	return operatorAuthFixture{
		principalName:  username,
		principalToken: principalToken,
		revokedToken:   revokedToken,
		launcherToken:  launcherToken,
		launcherID:     l.ID,
		launcherName:   l.Name,
		workspace:      workspace,
	}
}

// disableFixtureLauncher disables the fixture Launcher in place.
func disableFixtureLauncher(t *testing.T, app *App, f operatorAuthFixture) {
	t.Helper()
	disabled := false
	if _, err := persistLauncherChange(app.DB, f.launcherID, nil, &disabled); err != nil {
		t.Fatalf("persistLauncherChange: %v", err)
	}
}

// disableFixturePrincipal disables the fixture Principal in place.
func disableFixturePrincipal(t *testing.T, app *App, f operatorAuthFixture) {
	t.Helper()
	if _, err := persistPrincipalEnabledChange(app.DB, f.principalName, false); err != nil {
		t.Fatalf("persistPrincipalEnabledChange: %v", err)
	}
}

// operatorAuthCase is one authority condition of the matrix: the exact
// Authorization header value ("" = header absent) resolved against a fixture,
// an optional post-fixture state mutation, and the established response and
// audit contract. An empty wantResult means successful authentication with no
// auth.failure record.
type operatorAuthCase struct {
	name       string
	authHeader func(*operatorAuthFixture) string
	mutate     func(*testing.T, *App, operatorAuthFixture)
	wantStatus int
	wantResult string
	// wantAuthResponse, when set, is the exact /auth wire projection of a
	// successful authentication.
	wantAuthResponse func(*operatorAuthFixture) authResponse
}

func bearerOf(f func(*operatorAuthFixture) string) func(*operatorAuthFixture) string {
	return func(fx *operatorAuthFixture) string { return "Bearer " + f(fx) }
}

// caseToken extracts the bearer token value of a case for token-leak
// assertions ("" when the header is not a non-empty Bearer value).
func caseToken(c operatorAuthCase, f *operatorAuthFixture) string {
	v := ""
	if c.authHeader != nil {
		v = c.authHeader(f)
	}
	if strings.HasPrefix(v, "Bearer ") {
		return strings.TrimPrefix(v, "Bearer ")
	}
	return ""
}

// assertSingleAuthFailure asserts exactly one auth.failure audit record with
// the given expectation.
func assertSingleAuthFailure(t *testing.T, buf *bytes.Buffer, exp authFailureExpectation) {
	t.Helper()
	lines := findAuthFailureRawLines(buf)
	if len(lines) != 1 {
		t.Fatalf("expected exactly 1 auth.failure, got %d", len(lines))
	}
	validateAuthFailureRaw(t, lines[0], exp)
}

// assertUnauthorizedResponse checks the established non-disclosing 401
// contract: code "unauthorized", the family message, and WWW-Authenticate.
func assertUnauthorizedResponse(t *testing.T, w *httptest.ResponseRecorder, message string) {
	t.Helper()
	var resp response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}
	if resp.Code != "unauthorized" {
		t.Errorf("code = %q, want %q", resp.Code, "unauthorized")
	}
	if resp.Message != message {
		t.Errorf("message = %q, want %q", resp.Message, message)
	}
	if w.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Errorf("WWW-Authenticate = %q, want Bearer", w.Header().Get("WWW-Authenticate"))
	}
}

// ========================
// Admin-only surface: GET /principals
// ========================

func TestOperatorAuthAdminOnlyMatrix(t *testing.T) {
	const message = "Administrative authentication required."
	cases := []operatorAuthCase{
		{
			name:       "missing header",
			authHeader: func(*operatorAuthFixture) string { return "" },
			wantStatus: http.StatusUnauthorized,
			wantResult: "admin.parse_failed",
		},
		{
			name:       "wrong scheme",
			authHeader: func(*operatorAuthFixture) string { return "Basic dXNlcjpwYXNz" },
			wantStatus: http.StatusUnauthorized,
			wantResult: "admin.parse_failed",
		},
		{
			name:       "empty bearer",
			authHeader: func(*operatorAuthFixture) string { return "Bearer " },
			wantStatus: http.StatusUnauthorized,
			wantResult: "admin.parse_failed",
		},
		{
			name:       "unknown token",
			authHeader: bearerOf(func(*operatorAuthFixture) string { return "dht_unknown_operator_token_9k2m7f" }),
			wantStatus: http.StatusUnauthorized,
			wantResult: "admin.wrong_token",
		},
		{
			name:       "admin token",
			authHeader: bearerOf(func(*operatorAuthFixture) string { return testAdminToken }),
			wantStatus: http.StatusOK,
			wantResult: "",
		},
		{
			// A valid Principal credential is not admin authority; its
			// credential state is neither consulted nor disclosed.
			name:       "principal credential",
			authHeader: bearerOf(func(f *operatorAuthFixture) string { return f.principalToken }),
			wantStatus: http.StatusUnauthorized,
			wantResult: "admin.wrong_token",
		},
		{
			name:       "revoked principal credential",
			authHeader: bearerOf(func(f *operatorAuthFixture) string { return f.revokedToken }),
			wantStatus: http.StatusUnauthorized,
			wantResult: "admin.wrong_token",
		},
		{
			name:       "launcher credential",
			authHeader: bearerOf(func(f *operatorAuthFixture) string { return f.launcherToken }),
			wantStatus: http.StatusUnauthorized,
			wantResult: "admin.wrong_token",
		},
		{
			name:       "session token",
			authHeader: bearerOf(func(*operatorAuthFixture) string { return "dht_session_capability_not_operator" }),
			wantStatus: http.StatusUnauthorized,
			wantResult: "admin.wrong_token",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			auditBuf, _ := setupTestLogging(t)
			app := newTestAppWithAdminToken(t)
			f := setupOperatorAuthFixture(t, app)

			req := httptest.NewRequest(http.MethodGet, "/principals", nil)
			if tc.authHeader != nil {
				if v := tc.authHeader(&f); v != "" {
					req.Header.Set("Authorization", v)
				}
			}
			w := httptest.NewRecorder()
			app.handleListPrincipals(w, req)

			if w.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d, body: %s", w.Code, tc.wantStatus, w.Body.String())
			}
			if tc.wantResult == "" {
				assertNoAuthFailure(t, auditBuf)
				return
			}
			assertUnauthorizedResponse(t, w, message)
			assertSingleAuthFailure(t, auditBuf, authFailureExpectation{
				Method:        http.MethodGet,
				Path:          "/principals",
				Result:        tc.wantResult,
				InjectedToken: caseToken(tc, &f),
			})
		})
	}
}

// TestOperatorAuthAdminOnlyNoCredentialLookup proves the admin-only wrapper
// decides from the admin-token comparison alone: with a credential database
// that fails every query, a non-admin bearer still receives exactly the
// established admin 401 (admin.wrong_token audit, "Administrative
// authentication required."), never a credential-auth outcome or a 500.
func TestOperatorAuthAdminOnlyNoCredentialLookup(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAdminToken(t)
	f := setupOperatorAuthFixture(t, app)

	dbPath := app.Config.DatabasePath
	app.DB.Close()
	app.DB = newFailQueryDB(t, dbPath, errMockQueryFail)
	defer app.DB.Close()

	req := httptest.NewRequest(http.MethodGet, "/principals", nil)
	req.Header.Set("Authorization", "Bearer "+f.principalToken)
	w := httptest.NewRecorder()
	app.handleListPrincipals(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d, body: %s", w.Code, http.StatusUnauthorized, w.Body.String())
	}
	assertUnauthorizedResponse(t, w, "Administrative authentication required.")
	assertSingleAuthFailure(t, auditBuf, authFailureExpectation{
		Method:        http.MethodGet,
		Path:          "/principals",
		Result:        "admin.wrong_token",
		InjectedToken: f.principalToken,
	})
}

// ========================
// Principal control surface: GET /launchers (Admin | Principal only)
// ========================

func TestOperatorAuthPrincipalControlMatrix(t *testing.T) {
	const message = "Authentication required for launcher management."
	cases := []operatorAuthCase{
		{
			name:       "missing header",
			authHeader: func(*operatorAuthFixture) string { return "" },
			wantStatus: http.StatusUnauthorized,
			wantResult: "launcher.parse_failed",
		},
		{
			name:       "wrong scheme",
			authHeader: func(*operatorAuthFixture) string { return "Basic dXNlcjpwYXNz" },
			wantStatus: http.StatusUnauthorized,
			wantResult: "launcher.parse_failed",
		},
		{
			name:       "empty bearer",
			authHeader: func(*operatorAuthFixture) string { return "Bearer " },
			wantStatus: http.StatusUnauthorized,
			wantResult: "launcher.parse_failed",
		},
		{
			name:       "unknown token",
			authHeader: bearerOf(func(*operatorAuthFixture) string { return "dht_unknown_operator_token_9k2m7f" }),
			wantStatus: http.StatusUnauthorized,
			wantResult: "launcher.unauthorized",
		},
		{
			name:       "admin token",
			authHeader: bearerOf(func(*operatorAuthFixture) string { return testAdminToken }),
			wantStatus: http.StatusOK,
			wantResult: "",
		},
		{
			name:       "principal credential",
			authHeader: bearerOf(func(f *operatorAuthFixture) string { return f.principalToken }),
			wantStatus: http.StatusOK,
			wantResult: "",
		},
		{
			name:       "revoked principal credential",
			authHeader: bearerOf(func(f *operatorAuthFixture) string { return f.revokedToken }),
			wantStatus: http.StatusUnauthorized,
			wantResult: "launcher.unauthorized",
		},
		{
			name:       "disabled principal credential",
			authHeader: bearerOf(func(f *operatorAuthFixture) string { return f.principalToken }),
			mutate:     disableFixturePrincipal,
			wantStatus: http.StatusUnauthorized,
			wantResult: "launcher.unauthorized",
		},
		{
			name:       "disabled launcher credential",
			authHeader: bearerOf(func(f *operatorAuthFixture) string { return f.launcherToken }),
			mutate:     disableFixtureLauncher,
			wantStatus: http.StatusUnauthorized,
			wantResult: "launcher.unauthorized",
		},
		{
			// A valid Launcher credential is authenticated but carries no
			// control-plane authority: unauthorized, never a credential
			// not-found and never disclosed as authenticated.
			name:       "active launcher credential unauthorized",
			authHeader: bearerOf(func(f *operatorAuthFixture) string { return f.launcherToken }),
			wantStatus: http.StatusUnauthorized,
			wantResult: "launcher.unauthorized",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			auditBuf, _ := setupTestLogging(t)
			app := newTestAppWithAdminToken(t)
			f := setupOperatorAuthFixture(t, app)
			if tc.mutate != nil {
				tc.mutate(t, app, f)
			}

			req := httptest.NewRequest(http.MethodGet, "/launchers", nil)
			if tc.authHeader != nil {
				if v := tc.authHeader(&f); v != "" {
					req.Header.Set("Authorization", v)
				}
			}
			w := httptest.NewRecorder()
			app.handleListLaunchersForAuthority(w, req)

			if w.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d, body: %s", w.Code, tc.wantStatus, w.Body.String())
			}
			if tc.wantResult == "" {
				assertNoAuthFailure(t, auditBuf)
				return
			}
			assertUnauthorizedResponse(t, w, message)
			assertSingleAuthFailure(t, auditBuf, authFailureExpectation{
				Method:        http.MethodGet,
				Path:          "/launchers",
				Result:        tc.wantResult,
				InjectedToken: caseToken(tc, &f),
			})
		})
	}
}

// TestOperatorAuthPrincipalControlDatabaseError proves a genuine credential
// authentication database error on the Principal-control family stays an
// internal error (HTTP 500, launcher.database_error audit) and is never
// converted into a 401 or a not-found/disabled classification.
func TestOperatorAuthPrincipalControlDatabaseError(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAdminToken(t)

	dbPath := app.Config.DatabasePath
	app.DB.Close()
	app.DB = newFailQueryDB(t, dbPath, errMockQueryFail)
	defer app.DB.Close()

	const token = "dht_unknown_credential_token_q2w4"
	req := httptest.NewRequest(http.MethodGet, "/launchers", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	app.handleListLaunchersForAuthority(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d, body: %s", w.Code, http.StatusInternalServerError, w.Body.String())
	}
	assertSingleAuthFailure(t, auditBuf, authFailureExpectation{
		Method:        http.MethodGet,
		Path:          "/launchers",
		Result:        "launcher.database_error",
		InjectedToken: token,
		InjectedErr:   "mock_query_injection_error_for_testing",
	})
}

// ========================
// Session control surface: POST /sessions (Admin | Principal | Launcher)
// ========================

func TestOperatorAuthSessionControlMatrix(t *testing.T) {
	const message = "Authentication required for session management."
	cases := []operatorAuthCase{
		{
			name:       "missing header",
			authHeader: func(*operatorAuthFixture) string { return "" },
			wantStatus: http.StatusUnauthorized,
			wantResult: "parse_failed",
		},
		{
			name:       "wrong scheme",
			authHeader: func(*operatorAuthFixture) string { return "Basic dXNlcjpwYXNz" },
			wantStatus: http.StatusUnauthorized,
			wantResult: "parse_failed",
		},
		{
			name:       "empty bearer",
			authHeader: func(*operatorAuthFixture) string { return "Bearer " },
			wantStatus: http.StatusUnauthorized,
			wantResult: "parse_failed",
		},
		{
			name:       "unknown token",
			authHeader: bearerOf(func(*operatorAuthFixture) string { return "dht_unknown_operator_token_9k2m7f" }),
			wantStatus: http.StatusUnauthorized,
			wantResult: "credential.not_found",
		},
		{
			// A data-plane Session capability is not an operator bearer.
			name:       "session token",
			authHeader: bearerOf(func(*operatorAuthFixture) string { return "dht_session_capability_not_operator" }),
			wantStatus: http.StatusUnauthorized,
			wantResult: "credential.not_found",
		},
		{
			name:       "admin token",
			authHeader: bearerOf(func(*operatorAuthFixture) string { return testAdminToken }),
			wantStatus: http.StatusCreated,
			wantResult: "",
		},
		{
			name:       "principal credential",
			authHeader: bearerOf(func(f *operatorAuthFixture) string { return f.principalToken }),
			wantStatus: http.StatusCreated,
			wantResult: "",
		},
		{
			// A Launcher credential is a full Session-control authority within
			// its own Launcher.
			name:       "launcher credential",
			authHeader: bearerOf(func(f *operatorAuthFixture) string { return f.launcherToken }),
			wantStatus: http.StatusCreated,
			wantResult: "",
		},
		{
			name:       "revoked principal credential",
			authHeader: bearerOf(func(f *operatorAuthFixture) string { return f.revokedToken }),
			wantStatus: http.StatusUnauthorized,
			wantResult: "credential.revoked",
		},
		{
			name:       "disabled principal credential",
			authHeader: bearerOf(func(f *operatorAuthFixture) string { return f.principalToken }),
			mutate:     disableFixturePrincipal,
			wantStatus: http.StatusUnauthorized,
			wantResult: "principal.disabled",
		},
		{
			// Regression: a disabled Launcher is classified launcher.disabled,
			// never the unknown-token credential.not_found.
			name:       "disabled launcher credential",
			authHeader: bearerOf(func(f *operatorAuthFixture) string { return f.launcherToken }),
			mutate:     disableFixtureLauncher,
			wantStatus: http.StatusUnauthorized,
			wantResult: "launcher.disabled",
		},
		{
			// The owning Principal's disabled state remains semantically
			// explicit when the Launcher itself is still enabled.
			name:       "launcher credential with disabled principal",
			authHeader: bearerOf(func(f *operatorAuthFixture) string { return f.launcherToken }),
			mutate:     disableFixturePrincipal,
			wantStatus: http.StatusUnauthorized,
			wantResult: "principal.disabled",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			auditBuf, _ := setupTestLogging(t)
			app := newTestAppWithAdminToken(t)
			f := setupOperatorAuthFixture(t, app)
			if tc.mutate != nil {
				tc.mutate(t, app, f)
			}

			body, _ := json.Marshal(map[string]string{"workspace": f.workspace})
			req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(body))
			if tc.authHeader != nil {
				if v := tc.authHeader(&f); v != "" {
					req.Header.Set("Authorization", v)
				}
			}
			w := httptest.NewRecorder()
			app.handleCreateSession(w, req)

			if w.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d, body: %s", w.Code, tc.wantStatus, w.Body.String())
			}
			if tc.wantResult == "" {
				assertNoAuthFailure(t, auditBuf)
				assertSessionCreateAuditProvenance(t, auditBuf, tc, &f)
				return
			}
			assertUnauthorizedResponse(t, w, message)
			assertSingleAuthFailure(t, auditBuf, authFailureExpectation{
				Method:        http.MethodPost,
				Path:          "/sessions",
				Result:        tc.wantResult,
				InjectedToken: caseToken(tc, &f),
			})
		})
	}
}

// assertSessionCreateAuditProvenance checks that a successful session.create
// audit record keeps the endpoint-operation provenance of the initiating
// operator authority: a Principal credential names its Principal and
// credential, a Launcher credential additionally names its Launcher.
func assertSessionCreateAuditProvenance(t *testing.T, buf *bytes.Buffer, tc operatorAuthCase, f *operatorAuthFixture) {
	t.Helper()
	raw := findAuditLine(buf, "session.create")
	if raw == "" {
		t.Fatal("expected session.create audit line")
	}
	m := parseAuditMap(t, raw)
	if m["result"] != "success" {
		t.Errorf("result = %v, want success", m["result"])
	}
	byAuthority := map[string]bool{
		"principal credential": true,
		"launcher credential":  true,
	}
	if !byAuthority[tc.name] {
		return
	}
	if m["principal_name"] != f.principalName {
		t.Errorf("principal_name = %v, want %q", m["principal_name"], f.principalName)
	}
	if m["credential_id"] == "" {
		t.Error("credential_id missing in session.create audit")
	}
	if tc.name == "launcher credential" {
		if m["launcher_id"] != f.launcherID {
			t.Errorf("launcher_id = %v, want %q", m["launcher_id"], f.launcherID)
		}
		if m["launcher_name"] != f.launcherName {
			t.Errorf("launcher_name = %v, want %q", m["launcher_name"], f.launcherName)
		}
	}
}

// ========================
// /auth surface: all three authority projections
// ========================

func TestOperatorAuthHandleAuthMatrix(t *testing.T) {
	const message = "Authentication required."
	cases := []operatorAuthCase{
		{
			name:       "missing header",
			authHeader: func(*operatorAuthFixture) string { return "" },
			wantStatus: http.StatusUnauthorized,
			wantResult: "auth.parse_failed",
		},
		{
			name:       "wrong scheme",
			authHeader: func(*operatorAuthFixture) string { return "Basic dXNlcjpwYXNz" },
			wantStatus: http.StatusUnauthorized,
			wantResult: "auth.parse_failed",
		},
		{
			name:       "empty bearer",
			authHeader: func(*operatorAuthFixture) string { return "Bearer " },
			wantStatus: http.StatusUnauthorized,
			wantResult: "auth.parse_failed",
		},
		{
			name:       "unknown token",
			authHeader: bearerOf(func(*operatorAuthFixture) string { return "dht_unknown_operator_token_9k2m7f" }),
			wantStatus: http.StatusUnauthorized,
			wantResult: "auth.unauthorized",
		},
		{
			name:       "revoked principal credential",
			authHeader: bearerOf(func(f *operatorAuthFixture) string { return f.revokedToken }),
			wantStatus: http.StatusUnauthorized,
			wantResult: "auth.unauthorized",
		},
		{
			name:       "disabled principal",
			authHeader: bearerOf(func(f *operatorAuthFixture) string { return f.principalToken }),
			mutate:     disableFixturePrincipal,
			wantStatus: http.StatusUnauthorized,
			wantResult: "auth.unauthorized",
		},
		{
			name:       "disabled launcher",
			authHeader: bearerOf(func(f *operatorAuthFixture) string { return f.launcherToken }),
			mutate:     disableFixtureLauncher,
			wantStatus: http.StatusUnauthorized,
			wantResult: "auth.unauthorized",
		},
		{
			name:       "session token",
			authHeader: bearerOf(func(*operatorAuthFixture) string { return "dht_session_capability_not_operator" }),
			wantStatus: http.StatusUnauthorized,
			wantResult: "auth.unauthorized",
		},
		{
			name:       "admin",
			authHeader: bearerOf(func(*operatorAuthFixture) string { return testAdminToken }),
			wantStatus: http.StatusOK,
			wantResult: "",
			wantAuthResponse: func(*operatorAuthFixture) authResponse {
				return authResponse{Authority: "admin"}
			},
		},
		{
			name:       "principal",
			authHeader: bearerOf(func(f *operatorAuthFixture) string { return f.principalToken }),
			wantStatus: http.StatusOK,
			wantResult: "",
			wantAuthResponse: func(f *operatorAuthFixture) authResponse {
				return authResponse{Authority: "principal", Principal: f.principalName}
			},
		},
		{
			name:       "launcher",
			authHeader: bearerOf(func(f *operatorAuthFixture) string { return f.launcherToken }),
			wantStatus: http.StatusOK,
			wantResult: "",
			wantAuthResponse: func(f *operatorAuthFixture) authResponse {
				return authResponse{
					Authority:  "launcher",
					Principal:  f.principalName,
					LauncherID: f.launcherID,
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			auditBuf, _ := setupTestLogging(t)
			app := newTestAppWithAdminToken(t)
			f := setupOperatorAuthFixture(t, app)
			if tc.mutate != nil {
				tc.mutate(t, app, f)
			}

			req := httptest.NewRequest(http.MethodGet, "/auth", nil)
			if tc.authHeader != nil {
				if v := tc.authHeader(&f); v != "" {
					req.Header.Set("Authorization", v)
				}
			}
			w := httptest.NewRecorder()
			app.handleAuth(w, req)

			if w.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d, body: %s", w.Code, tc.wantStatus, w.Body.String())
			}
			if tc.wantResult == "" {
				assertNoAuthFailure(t, auditBuf)
				var got authResponse
				if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
					t.Fatalf("cannot decode response: %v", err)
				}
				want := tc.wantAuthResponse(&f)
				if got != want {
					t.Errorf("auth response = %+v, want %+v", got, want)
				}
				return
			}
			assertUnauthorizedResponse(t, w, message)
			assertSingleAuthFailure(t, auditBuf, authFailureExpectation{
				Method:        http.MethodGet,
				Path:          "/auth",
				Result:        tc.wantResult,
				InjectedToken: caseToken(tc, &f),
			})
		})
	}
}

// TestOperatorAuthHandleAuthDatabaseError proves a genuine credential
// authentication database error on GET /auth stays an internal error
// (auth.database_error audit) and is never converted into a 401.
func TestOperatorAuthHandleAuthDatabaseError(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAdminToken(t)

	dbPath := app.Config.DatabasePath
	app.DB.Close()
	app.DB = newFailQueryDB(t, dbPath, errMockQueryFail)
	defer app.DB.Close()

	const token = "dht_unknown_credential_token_q2w4"
	req := httptest.NewRequest(http.MethodGet, "/auth", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	app.handleAuth(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d, body: %s", w.Code, http.StatusInternalServerError, w.Body.String())
	}
	assertSingleAuthFailure(t, auditBuf, authFailureExpectation{
		Method:        http.MethodGet,
		Path:          "/auth",
		Result:        "auth.database_error",
		InjectedToken: token,
		InjectedErr:   "mock_query_injection_error_for_testing",
	})
}
