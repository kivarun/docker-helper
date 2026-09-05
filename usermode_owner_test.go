package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// requireUserModeOwnerInvariant asserts the transparent user-mode ownership
// contract for the app's startup-resolved daemon-owner chain: the Principal is
// enabled with zero stored roots, and the default Launcher is enabled, named
// 'default', inherit-scope, and rootless. It uses the production launcher
// contract validator plus direct assertions of the mutable Principal fields.
func requireUserModeOwnerInvariant(t *testing.T, app *App) {
	t.Helper()
	owner := app.userModeDefault
	if owner == nil {
		t.Fatal("app has no user-mode daemon-owner chain")
	}
	p, err := findPrincipalByUsername(app.DB, owner.username)
	if err != nil {
		t.Fatalf("daemon-owner principal vanished: %v", err)
	}
	if !p.Enabled {
		t.Error("daemon-owner principal must stay enabled")
	}
	if len(p.AllowedRoots) != 0 {
		t.Errorf("daemon-owner principal must keep zero stored roots, got %v", p.AllowedRoots)
	}
	if err := validateUserModeDefaultLauncherContract(app.DB, owner.launcherID); err != nil {
		t.Fatalf("daemon-owner default Launcher contract violated: %v", err)
	}
	l, err := findLauncherByID(app.DB, owner.launcherID)
	if err != nil {
		t.Fatalf("daemon-owner default Launcher vanished: %v", err)
	}
	if l.Name != defaultLauncherName {
		t.Errorf("default Launcher name = %q, want %q", l.Name, defaultLauncherName)
	}
}

// decodeAPIError decodes the stable error envelope of a rejected request.
func decodeAPIError(t *testing.T, body []byte) response {
	t.Helper()
	var resp response
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode error response: %v (body=%s)", err, body)
	}
	if resp.OK {
		t.Fatalf("expected ok=false, got body=%s", body)
	}
	return resp
}

// expectReservedResponse asserts a 409 with the stable user_mode_owner_reserved
// code and the non-disclosing message.
func expectReservedResponse(t *testing.T, w *httptest.ResponseRecorder, what string) {
	t.Helper()
	if w.Code != http.StatusConflict {
		t.Fatalf("%s: expected 409, got %d (body=%s)", what, w.Code, w.Body.String())
	}
	resp := decodeAPIError(t, w.Body.Bytes())
	if resp.Code != "user_mode_owner_reserved" {
		t.Errorf("%s: expected code user_mode_owner_reserved, got %q", what, resp.Code)
	}
	if !strings.Contains(resp.Message, "transparent user mode") {
		t.Errorf("%s: expected transparent-user-mode message, got %q", what, resp.Message)
	}
}

// TestUserModeOwnerPrincipalMutationsRejected verifies, through the real
// public API in user mode, that disable/delete/allowed-root mutations of the
// daemon-owner Principal are rejected with the stable code and leave the
// ownership contract unchanged, while harmless no-ops stay coherent.
func TestUserModeOwnerPrincipalMutationsRejected(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	owner := app.userModeDefault.username
	root := app.Config.AllowedRoots[0]

	// disable
	w := launcherRequest(t, app, http.MethodPatch, "/principals/"+owner, testAdminToken, `{"enabled":false}`)
	expectReservedResponse(t, w, "principal disable")
	requireUserModeOwnerInvariant(t, app)

	// delete
	w = launcherRequest(t, app, http.MethodDelete, "/principals/"+owner, testAdminToken, "")
	expectReservedResponse(t, w, "principal delete")
	requireUserModeOwnerInvariant(t, app)

	// allowed-root add (well-formed request under the global root)
	w = launcherRequest(t, app, http.MethodPost, "/principals/"+owner+"/allowed-roots", testAdminToken,
		`{"path":"`+root+`"}`)
	expectReservedResponse(t, w, "principal allowed-root add")
	requireUserModeOwnerInvariant(t, app)

	// allowed-root remove
	w = launcherRequest(t, app, http.MethodDelete, "/principals/"+owner+"/allowed-roots", testAdminToken,
		`{"path":"`+root+`"}`)
	expectReservedResponse(t, w, "principal allowed-root remove")
	requireUserModeOwnerInvariant(t, app)

	// Harmless no-ops remain coherent: re-enabling an enabled Principal is the
	// natural unchanged response.
	w = launcherRequest(t, app, http.MethodPatch, "/principals/"+owner, testAdminToken, `{"enabled":true}`)
	if w.Code != http.StatusOK {
		t.Fatalf("principal re-enable: expected 200, got %d (body=%s)", w.Code, w.Body.String())
	}
	var changed principalChangedResponse
	if err := json.Unmarshal(w.Body.Bytes(), &changed); err != nil {
		t.Fatal(err)
	}
	if changed.Changed || changed.Message != "unchanged" {
		t.Errorf("re-enable of the enabled daemon-owner Principal: got changed=%v message=%q, want unchanged", changed.Changed, changed.Message)
	}
	requireUserModeOwnerInvariant(t, app)

	// The rejection is audited with the stable result code.
	auditBuf, _ := setupTestLogging(t)
	w = launcherRequest(t, app, http.MethodPatch, "/principals/"+owner, testAdminToken, `{"enabled":false}`)
	expectReservedResponse(t, w, "principal disable (audit)")
	for _, rec := range parseAuditRecords(auditBuf) {
		if rec.Event != "principal.enabled_change" {
			continue
		}
		if rec.PrincipalName != owner {
			t.Errorf("audit principal_name = %q, want %q", rec.PrincipalName, owner)
		}
		if rec.Result != "user_mode_owner_reserved" {
			t.Errorf("audit result = %q, want user_mode_owner_reserved", rec.Result)
		}
		return
	}
	t.Fatal("no principal.enabled_change audit record for the rejected disable")
}

// TestUserModeOwnerDefaultLauncherMutationsRejected verifies, through the real
// public API in user mode, that disable/rename/delete/scope mutations of the
// daemon-owner default Launcher are rejected and the Launcher stays
// enabled/default/inherit/zero-roots, while invariant-preserving no-ops stay
// coherent.
func TestUserModeOwnerDefaultLauncherMutationsRejected(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	owner := app.userModeDefault.username
	base := "/principals/" + owner + "/launchers/default"
	proj := testWorkspaceDir(t, app.Config.AllowedRoots[0])

	// disable
	w := launcherRequest(t, app, http.MethodPatch, base, testAdminToken, `{"enabled":false}`)
	expectReservedResponse(t, w, "default launcher disable")
	requireUserModeOwnerInvariant(t, app)

	// rename away from default
	w = launcherRequest(t, app, http.MethodPatch, base, testAdminToken, `{"name":"renamed"}`)
	expectReservedResponse(t, w, "default launcher rename")
	requireUserModeOwnerInvariant(t, app)

	// delete
	w = launcherRequest(t, app, http.MethodDelete, base, testAdminToken, "")
	expectReservedResponse(t, w, "default launcher delete")
	requireUserModeOwnerInvariant(t, app)

	// restricted scope
	w = launcherRequest(t, app, http.MethodPut, base+"/allowed-roots", testAdminToken,
		`{"scope":"restricted","allowed_roots":["`+proj+`"]}`)
	expectReservedResponse(t, w, "default launcher restricted scope")
	requireUserModeOwnerInvariant(t, app)

	// inherit scope with non-empty roots is malformed for any launcher and is
	// rejected before mutation; the invariant is unchanged either way.
	w = launcherRequest(t, app, http.MethodPut, base+"/allowed-roots", testAdminToken,
		`{"scope":"inherit","allowed_roots":["`+proj+`"]}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("inherit with roots: expected 400, got %d (body=%s)", w.Code, w.Body.String())
	}
	if resp := decodeAPIError(t, w.Body.Bytes()); resp.Code != "invalid_allowed_roots" {
		t.Errorf("inherit with roots: expected invalid_allowed_roots, got %q", resp.Code)
	}
	requireUserModeOwnerInvariant(t, app)

	// Harmless no-ops remain coherent: enabled=true, name=default, and the
	// identical inherit scope all succeed without changing the invariant.
	w = launcherRequest(t, app, http.MethodPatch, base, testAdminToken, `{"enabled":true,"name":"default"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("no-op patch: expected 200, got %d (body=%s)", w.Code, w.Body.String())
	}
	if updated := decodeLauncher(t, w); updated.Name != defaultLauncherName || !updated.Enabled {
		t.Errorf("no-op patch changed the launcher: %+v", updated)
	}
	w = launcherRequest(t, app, http.MethodPut, base+"/allowed-roots", testAdminToken,
		`{"scope":"inherit","allowed_roots":[]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("no-op scope replace: expected 200, got %d (body=%s)", w.Code, w.Body.String())
	}
	if updated := decodeLauncher(t, w); updated.Scope != "inherit" || len(updated.AllowedRoots) != 0 {
		t.Errorf("no-op scope replace changed the launcher: %+v", updated)
	}
	requireUserModeOwnerInvariant(t, app)
}

// TestUserModeOwnerSecondLauncherMutable proves the reservation covers only the
// transparent default chain: a second Launcher under the daemon-owner
// Principal and other Principals (including their own 'default' Launchers)
// remain mutable through the real public API.
func TestUserModeOwnerSecondLauncherMutable(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	owner := app.userModeDefault.username

	// An explicit duplicate of the auto-provisioned default keeps the stable
	// UNIQUE conflict: the daemon-owner Principal never gains a second
	// 'default' Launcher.
	w := launcherRequest(t, app, http.MethodPost, "/principals/"+owner+"/launchers", testAdminToken,
		`{"name":"default","scope":"inherit","allowed_roots":[]}`)
	if w.Code != http.StatusConflict {
		t.Fatalf("duplicate default create: expected 409, got %d (body=%s)", w.Code, w.Body.String())
	}
	if resp := decodeAPIError(t, w.Body.Bytes()); resp.Code != "launcher_exists" {
		t.Errorf("duplicate default create: expected launcher_exists, got %q", resp.Code)
	}

	// A second, differently named Launcher under the same Principal is mutable.
	w = launcherRequest(t, app, http.MethodPost, "/principals/"+owner+"/launchers", testAdminToken,
		`{"name":"second","scope":"inherit","allowed_roots":[]}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("second launcher create: expected 201, got %d (body=%s)", w.Code, w.Body.String())
	}
	var created createLauncherResponse
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	second := created.Launcher
	if second.Name != "second" || !second.Enabled || second.Scope != "inherit" {
		t.Fatalf("unexpected second launcher: %+v", second)
	}

	w = launcherRequest(t, app, http.MethodPatch, "/principals/"+owner+"/launchers/second", testAdminToken, `{"enabled":false}`)
	if w.Code != http.StatusOK {
		t.Fatalf("second launcher disable: expected 200, got %d (body=%s)", w.Code, w.Body.String())
	}
	w = launcherRequest(t, app, http.MethodPatch, "/principals/"+owner+"/launchers/second", testAdminToken, `{"name":"third"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("second launcher rename: expected 200, got %d (body=%s)", w.Code, w.Body.String())
	}
	w = launcherRequest(t, app, http.MethodDelete, "/principals/"+owner+"/launchers/third", testAdminToken, "")
	if w.Code != http.StatusNoContent {
		t.Fatalf("second launcher delete: expected 204, got %d (body=%s)", w.Code, w.Body.String())
	}
	w = launcherRequest(t, app, http.MethodGet, "/principals/"+owner+"/launchers/third", testAdminToken, "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("deleted second launcher: expected 404, got %d", w.Code)
	}

	// Another Principal is not reserved either, including its own 'default'
	// Launcher (reservation identity is the startup-resolved ID, never a name).
	home := filepath.Join(app.Config.AllowedRoots[0], "home", "otheruser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}
	installOSUserMock(t, map[string]string{"otheruser": home})
	if _, err := createPrincipal(app.DB, "otheruser", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal(otheruser): %v", err)
	}
	w = launcherRequest(t, app, http.MethodPatch, "/principals/otheruser/launchers/default", testAdminToken, `{"name":"moved"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("other principal default rename: expected 200, got %d (body=%s)", w.Code, w.Body.String())
	}
	w = launcherRequest(t, app, http.MethodPatch, "/principals/otheruser", testAdminToken, `{"enabled":false}`)
	if w.Code != http.StatusOK {
		t.Fatalf("other principal disable: expected 200, got %d (body=%s)", w.Code, w.Body.String())
	}
	w = launcherRequest(t, app, http.MethodDelete, "/principals/otheruser", testAdminToken, "")
	if w.Code != http.StatusNoContent {
		t.Fatalf("other principal delete: expected 204, got %d (body=%s)", w.Code, w.Body.String())
	}
	requireUserModeOwnerInvariant(t, app)
}

// TestUserModeOwnerReservationSystemModeUnaffected verifies that system mode
// (no startup-resolved daemon-owner chain) keeps every Principal/default
// Launcher operation mutable as before, and that the reservation never fires
// merely from a matching username.
func TestUserModeOwnerReservationSystemModeUnaffected(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	app.Config.Mode = ModeSystem
	app.userModeDefault = nil

	// The formerly provisioned owner username is not reserved in system mode:
	// identity comes from the resolved chain, never the name.
	w := launcherRequest(t, app, http.MethodDelete, "/principals/dhtestowner", testAdminToken, "")
	if w.Code != http.StatusNoContent {
		t.Fatalf("system-mode delete of the owner-named principal: expected 204, got %d (body=%s)", w.Code, w.Body.String())
	}

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "sysuser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}
	installOSUserMock(t, map[string]string{"sysuser": home})
	if _, err := createPrincipal(app.DB, "sysuser", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal(sysuser): %v", err)
	}

	w = launcherRequest(t, app, http.MethodPatch, "/principals/sysuser", testAdminToken, `{"enabled":false}`)
	if w.Code != http.StatusOK {
		t.Fatalf("system-mode principal disable: expected 200, got %d (body=%s)", w.Code, w.Body.String())
	}
	w = launcherRequest(t, app, http.MethodPatch, "/principals/sysuser", testAdminToken, `{"enabled":true}`)
	if w.Code != http.StatusOK {
		t.Fatalf("system-mode principal enable: expected 200, got %d (body=%s)", w.Code, w.Body.String())
	}
	w = launcherRequest(t, app, http.MethodPatch, "/principals/sysuser/launchers/default", testAdminToken,
		`{"name":"renamed","enabled":false}`)
	if w.Code != http.StatusOK {
		t.Fatalf("system-mode launcher rename+disable: expected 200, got %d (body=%s)", w.Code, w.Body.String())
	}
	w = launcherRequest(t, app, http.MethodPut, "/principals/sysuser/launchers/renamed/allowed-roots", testAdminToken,
		`{"scope":"restricted","allowed_roots":["`+home+`"]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("system-mode scope replace: expected 200, got %d (body=%s)", w.Code, w.Body.String())
	}
	w = launcherRequest(t, app, http.MethodDelete, "/principals/sysuser/launchers/renamed", testAdminToken, "")
	if w.Code != http.StatusNoContent {
		t.Fatalf("system-mode launcher delete: expected 204, got %d (body=%s)", w.Code, w.Body.String())
	}
	w = launcherRequest(t, app, http.MethodDelete, "/principals/sysuser", testAdminToken, "")
	if w.Code != http.StatusNoContent {
		t.Fatalf("system-mode principal delete: expected 204, got %d (body=%s)", w.Code, w.Body.String())
	}
}

// restartOwnershipDB returns a fresh initialized DB, its path, and a
// policy-legal daemon-owner home, for the restart-invariant test.
func restartOwnershipDB(t *testing.T) (*sql.DB, string, string) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "restart.db")
	db, err := openDatabase(dbPath)
	if err != nil {
		t.Fatalf("openDatabase() error: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initializeDatabase() error: %v", err)
	}
	allowedRoot := testAllowedRootDir(t)
	home := filepath.Join(allowedRoot, "daemon-home")
	if err := os.MkdirAll(home, 0700); err != nil {
		t.Fatalf("cannot create daemon-home: %v", err)
	}
	return db, dbPath, home
}

// userModeOwnerTestApp wires a startup-provisioned ownership DB into a full
// App exactly like runDaemon does, for public-API reservation tests.
func userModeOwnerTestApp(t *testing.T, db *sql.DB, dbPath string, owner *userModeDefaultLauncher) *App {
	t.Helper()
	dir := t.TempDir()
	allowedRoot := testAllowedRootDir(t)
	runtimeDir := filepath.Join(dir, "runtime")
	if err := os.MkdirAll(runtimeDir, 0700); err != nil {
		t.Fatalf("cannot create runtime dir: %v", err)
	}
	app := &App{
		Config: &Config{
			AllowedRoots:          []string{allowedRoot},
			SessionTTL:            24 * time.Hour,
			SocketPath:            filepath.Join(dir, "test.sock"),
			StateDir:              dir,
			RuntimeDir:            runtimeDir,
			DatabasePath:          dbPath,
			AdminTokenPath:        filepath.Join(dir, "admin.token"),
			ShutdownTimeout:       30 * time.Second,
			OperationRetentionTTL: 10 * time.Minute,
			OperationMaxCompleted: 200,
			OperationLogMaxBytes:  4 * 1024 * 1024,
			Mode:                  ModeUser,
		},
		DB:                  db,
		OperationSupervisor: newOperationSupervisor(),
		InspectHelperContainers: func(context.Context, string) ([]helperContainer, error) {
			return nil, nil
		},
		userModeDefault: owner,
	}
	app.AdminTokenHash = sha256.Sum256([]byte(testAdminToken))
	return app
}

// TestUserModeOwnerReservationRestartInvariant is the mandatory restart
// regression: provision the real user-mode ownership at startup, attempt every
// prohibited public mutation, verify each rejection leaves the contract
// intact, then re-run the startup contract (ensureUserModeOwnership) and
// require it to succeed with the identical ownership chain.
func TestUserModeOwnerReservationRestartInvariant(t *testing.T) {
	db, dbPath, home := restartOwnershipDB(t)
	const username = "dho"
	restore := setUserModeDaemonOSSeams(t, 2111, 2111, username, home)
	defer restore()

	// Startup provisioning through the production owner.
	owner, err := ensureUserModeOwnership(db, ModeUser)
	if err != nil {
		t.Fatalf("startup provisioning: %v", err)
	}
	app := userModeOwnerTestApp(t, db, dbPath, owner)
	root := app.Config.AllowedRoots[0]

	prohibited := []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{"principal disable", http.MethodPatch, "/principals/" + username, `{"enabled":false}`},
		{"principal delete", http.MethodDelete, "/principals/" + username, ""},
		{"principal allowed-root add", http.MethodPost, "/principals/" + username + "/allowed-roots", `{"path":"` + root + `"}`},
		{"principal allowed-root remove", http.MethodDelete, "/principals/" + username + "/allowed-roots", `{"path":"` + root + `"}`},
		{"default launcher disable", http.MethodPatch, "/principals/" + username + "/launchers/default", `{"enabled":false}`},
		{"default launcher rename", http.MethodPatch, "/principals/" + username + "/launchers/default", `{"name":"moved"}`},
		{"default launcher delete", http.MethodDelete, "/principals/" + username + "/launchers/default", ""},
		{"default launcher restricted", http.MethodPut, "/principals/" + username + "/launchers/default/allowed-roots", `{"scope":"restricted","allowed_roots":["` + root + `"]}`},
	}
	for _, tc := range prohibited {
		t.Run(tc.name, func(t *testing.T) {
			w := launcherRequest(t, app, tc.method, tc.path, testAdminToken, tc.body)
			expectReservedResponse(t, w, tc.name)
			requireUserModeOwnerInvariant(t, app)
		})
	}

	// Restart-equivalent startup: the same DB and OS identity must still
	// satisfy the transparent contract and resolve the identical chain.
	owner2, err := ensureUserModeOwnership(db, ModeUser)
	if err != nil {
		t.Fatalf("restart contract rejected after public mutations: %v", err)
	}
	if owner2.principalID != owner.principalID || owner2.launcherID != owner.launcherID {
		t.Fatalf("restart re-provisioned the ownership chain: got principal %d launcher %s, want principal %d launcher %s",
			owner2.principalID, owner2.launcherID, owner.principalID, owner.launcherID)
	}
}

// TestUserModeOwnerReservationCurrentRuntimeUsable proves that rejected
// delete/disable attempts leave the cached App.userModeDefault path intact and
// the running daemon fully usable: pre-existing sessions keep authenticating
// and a normal selector-less user-mode Session can still be created.
func TestUserModeOwnerReservationCurrentRuntimeUsable(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	owner := app.userModeDefault
	ws := testWorkspaceDir(t, app.Config.AllowedRoots[0])

	// A selector-less user-mode Session resolves the cached default chain.
	createSession := func() createSessionResponse {
		t.Helper()
		w := launcherRequest(t, app, http.MethodPost, "/sessions", testAdminToken, `{"workspace":"`+ws+`"}`)
		if w.Code != http.StatusCreated {
			t.Fatalf("session create: expected 201, got %d (body=%s)", w.Code, w.Body.String())
		}
		var resp createSessionResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if resp.Session.LauncherID != owner.launcherID {
			t.Fatalf("session launcher_id = %q, want cached default %q", resp.Session.LauncherID, owner.launcherID)
		}
		return resp
	}
	first := createSession()

	// Prohibited mutations are rejected.
	for _, tc := range []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{"principal disable", http.MethodPatch, "/principals/" + owner.username, `{"enabled":false}`},
		{"principal delete", http.MethodDelete, "/principals/" + owner.username, ""},
		{"default launcher disable", http.MethodPatch, "/principals/" + owner.username + "/launchers/default", `{"enabled":false}`},
		{"default launcher delete", http.MethodDelete, "/principals/" + owner.username + "/launchers/default", ""},
	} {
		w := launcherRequest(t, app, tc.method, tc.path, testAdminToken, tc.body)
		expectReservedResponse(t, w, tc.name)
	}

	// The cached projection is unchanged and still resolves.
	if app.userModeDefault != owner {
		t.Fatal("App.userModeDefault was replaced by a rejected mutation")
	}
	l, err := findLauncherByID(app.DB, owner.launcherID)
	if err != nil {
		t.Fatalf("cached default Launcher no longer resolves: %v", err)
	}
	if !l.Enabled || l.ScopeMode != LauncherScopeInherit || l.Name != defaultLauncherName {
		t.Fatalf("cached default Launcher mutated: %+v", l)
	}

	// The pre-existing Session still resolves and the daemon still creates
	// normal selector-less user-mode Sessions.
	w := launcherRequest(t, app, http.MethodGet, "/sessions", testAdminToken, "")
	if w.Code != http.StatusOK {
		t.Fatalf("pre-existing session list: expected 200, got %d (body=%s)", w.Code, w.Body.String())
	}
	var listed listSessionsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range listed.Sessions {
		if s.ID == first.Session.ID {
			found = true
			if s.LauncherID != owner.launcherID {
				t.Errorf("pre-existing session launcher_id = %q, want %q", s.LauncherID, owner.launcherID)
			}
			break
		}
	}
	if !found {
		t.Fatal("pre-existing session disappeared after rejected mutations")
	}
	createSession()
}
