package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
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

// gatedJSONBody is a request body that parks decodeJSONRequest's trailing-EOF
// check: the first Read delivers the JSON payload and signals started; the
// next Read blocks until opened is closed and then reports EOF. This pins a
// mutation request inside the handler prologue (past admin authentication,
// before the policy snapshot and the lifecycle lock) so a concurrent reload's
// setConfig commit and the mutation's critical section are ordered with
// channels only — no timing or sleep.
type gatedJSONBody struct {
	data    []byte
	off     int
	started chan struct{}
	once    sync.Once
	opened  <-chan struct{}
}

func newGatedJSONBody(payload string, started chan struct{}, opened <-chan struct{}) *gatedJSONBody {
	return &gatedJSONBody{data: []byte(payload), started: started, opened: opened}
}

func (b *gatedJSONBody) Read(p []byte) (int, error) {
	if b.off < len(b.data) {
		n := copy(p, b.data[b.off:])
		b.off += n
		b.once.Do(func() { close(b.started) })
		return n, nil
	}
	<-b.opened
	return 0, io.EOF
}

// raceNarrowingReload deterministically orders a narrowing reload and one
// public mutation request through their shared lifecycleMu boundary:
//
//  1. the reload parks inside its critical section (the injected
//     loadAndPrepareRuntimeConfig barrier), holding lifecycleMu;
//  2. the mutation request is served through the real public mux and pinned
//     inside its handler prologue by the gated body;
//  3. the prologue is released, then the reload commits the narrowed
//     configuration and releases the boundary;
//  4. the mutation's critical section therefore runs strictly after the
//     reload's setConfig commit and must observe the narrowed ceiling.
//
// It returns the mutation response and the reload response code after both
// complete.
func raceNarrowingReload(t *testing.T, app *App, narrowRoot string, newMutationRequest func(started, opened chan struct{}) *http.Request) (*httptest.ResponseRecorder, int) {
	t.Helper()

	holding := make(chan struct{})
	gate := make(chan struct{})
	deps := reloadDeps{
		loadAndPrepareRuntimeConfig: func() (*Config, error) {
			close(holding)
			<-gate
			return narrowCfg(t, app, narrowRoot), nil
		},
	}
	reloadCode := make(chan int, 1)
	go func() {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/reload", nil)
		req.Header.Set("Authorization", "Bearer "+testAdminToken)
		app.handleReloadWithDeps(rec, req, deps)
		reloadCode <- rec.Code
	}()

	// The reload holds lifecycleMu, parked before its setConfig commit.
	<-holding

	started := make(chan struct{})
	opened := make(chan struct{})
	req := newMutationRequest(started, opened)
	mux := http.NewServeMux()
	registerRoutes(mux, app)
	rec := httptest.NewRecorder()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		mux.ServeHTTP(rec, req)
		done <- rec
	}()

	// The mutation is past admin authentication, parked before its snapshot
	// and its lifecycle critical section.
	<-started
	close(opened)
	// Yield the test goroutine so the pinned request completes its prologue
	// and parks at the lifecycle boundary before the gate opens. This is a
	// scheduling hand-off, not a timing wait: with the regression, the
	// request's pre-boundary snapshot read (handler argument evaluation) and
	// its park on the held lifecycleMu both complete here; without it, the
	// scheduler tends to run the reload (the last goroutine made runnable)
	// before the request, which would mask the regression.
	runtime.Gosched()
	close(gate)

	return <-done, <-reloadCode
}

// narrowCfg copies the app's current configuration with the global allowed
// roots narrowed to narrowRoot. The real reload setConfig merges only
// configurable fields, so the copy keeps the rest of the runtime state.
func narrowCfg(t *testing.T, app *App, narrowRoot string) *Config {
	t.Helper()
	cfg := app.getConfig()
	cfg.AllowedRoots = []string{narrowRoot}
	return &cfg
}

// expectOutsideGlobalRoot asserts the 400 outside_global_root error contract.
func expectOutsideGlobalRoot(t *testing.T, rec *httptest.ResponseRecorder, what string) {
	t.Helper()
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("%s: expected 400, got %d (body=%s)", what, rec.Code, rec.Body.String())
	}
	if code := decodeAPIError(t, rec.Body.Bytes()).Code; code != "outside_global_root" {
		t.Errorf("%s: expected outside_global_root, got %q", what, code)
	}
}

// TestRaceReloadSerializesPrincipalRootAdd proves the reload boundary owns the
// policy snapshot of a Principal allowed-root add: a reload that narrows the
// global roots and linearizes before the add commits prevents the add, so the
// mutation can never store a root allowed only by the pre-reload
// configuration. The mutation linearizes strictly after the reload's setConfig
// commit (the reload parks inside its lifecycleMu critical section while the
// request is pinned in its handler prologue), so its snapshot is read inside
// the boundary and rejects the stale root with 400 outside_global_root; a
// pre-lock snapshot (the regression) would validate the same root against the
// wider pre-reload ceiling and store it with 200.
func TestRaceReloadSerializesPrincipalRootAdd(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	setupTestLoggingDiscard(t)
	setupLauncherHandlerPrincipal(t, app, "mutator")
	root := app.Config.AllowedRoots[0]
	narrow := filepath.Join(root, "narrow")
	stale := filepath.Join(root, "stale")
	for _, d := range []string{narrow, stale} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}
	// createPrincipal provisions the principal home as the initial stored
	// root; the race must leave exactly that set unchanged.
	before, err := findPrincipalByUsername(app.DB, "mutator")
	if err != nil {
		t.Fatalf("find principal mutator: %v", err)
	}

	narrowRoot := narrow
	rec, reloadCode := raceNarrowingReload(t, app, narrowRoot, func(started, opened chan struct{}) *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/principals/mutator/allowed-roots",
			newGatedJSONBody(`{"path":"`+stale+`"}`, started, opened))
		req.Header.Set("Authorization", "Bearer "+testAdminToken)
		return req
	})

	if reloadCode != http.StatusOK {
		t.Fatalf("reload: expected 200, got %d", reloadCode)
	}
	if got := app.getConfig().AllowedRoots; len(got) != 1 || got[0] != narrowRoot {
		t.Fatalf("reload did not narrow the global roots: %v", got)
	}
	// The add linearized after the narrowed commit: the stale root is outside
	// the new ceiling and must be refused, never stored.
	expectOutsideGlobalRoot(t, rec, "principal allowed-root add")
	p, err := findPrincipalByUsername(app.DB, "mutator")
	if err != nil {
		t.Fatalf("find principal mutator: %v", err)
	}
	if len(p.AllowedRoots) != len(before.AllowedRoots) {
		t.Fatalf("stale root stored outside the narrowed ceiling: %v (was %v)", p.AllowedRoots, before.AllowedRoots)
	}
	for _, r := range before.AllowedRoots {
		if !slices.Contains(p.AllowedRoots, r) {
			t.Fatalf("principal roots changed by the refused add: %v (was %v)", p.AllowedRoots, before.AllowedRoots)
		}
	}
}

// TestRaceReloadSerializesLauncherScopeReplace proves the reload boundary owns
// the policy snapshot of a Launcher scope replacement: a reload that narrows
// the global roots and linearizes before the replacement commits prevents it,
// so the replacement can never store a restricted root allowed only by the
// pre-reload configuration (the effective Principal ceiling is the
// intersection with the global roots the boundary owns). The replacement
// linearizes strictly after the reload's setConfig commit and rejects the
// stale root with 400 outside_principal_root; a pre-lock snapshot (the
// regression) would validate the same root against the wider pre-reload
// ceiling and store it with 200.
func TestRaceReloadSerializesLauncherScopeReplace(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	setupTestLoggingDiscard(t)
	home, _ := setupLauncherHandlerPrincipal(t, app, "mutator")
	root := app.Config.AllowedRoots[0]
	narrow := filepath.Join(root, "narrow")
	if err := os.MkdirAll(narrow, 0755); err != nil {
		t.Fatal(err)
	}
	// The candidate restricted root must be under the Principal's effective
	// ceiling under the pre-reload configuration (home) but outside it once
	// the reload narrows the global roots, so the outcome discriminates the
	// snapshot the replacement validated against.
	stale := filepath.Join(home, "proj")
	if err := os.MkdirAll(stale, 0755); err != nil {
		t.Fatal(err)
	}
	pid := principalIDByName(t, app.DB, "mutator")
	if _, _, _, err := createLauncher(app.DB, pid, "extra", LauncherScopeInherit, nil, nil, false); err != nil {
		t.Fatalf("create launcher extra: %v", err)
	}

	narrowRoot := narrow
	rec, reloadCode := raceNarrowingReload(t, app, narrowRoot, func(started, opened chan struct{}) *http.Request {
		req := httptest.NewRequest(http.MethodPut, "/principals/mutator/launchers/extra/allowed-roots",
			newGatedJSONBody(`{"scope":"restricted","allowed_roots":["`+stale+`"]}`, started, opened))
		req.Header.Set("Authorization", "Bearer "+testAdminToken)
		return req
	})

	if reloadCode != http.StatusOK {
		t.Fatalf("reload: expected 200, got %d", reloadCode)
	}
	if got := app.getConfig().AllowedRoots; len(got) != 1 || got[0] != narrowRoot {
		t.Fatalf("reload did not narrow the global roots: %v", got)
	}
	// The replacement linearized after the narrowed commit: the root under the
	// old wide ceiling is outside the narrowed effective Principal ceiling and
	// must be refused, never stored.
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("launcher scope replace: expected 400, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	if code := decodeAPIError(t, rec.Body.Bytes()).Code; code != "outside_principal_root" {
		t.Errorf("launcher scope replace: expected outside_principal_root, got %q", code)
	}
	var storedRoots int
	if err := app.DB.QueryRow(
		`SELECT COUNT(*) FROM launcher_allowed_roots WHERE launcher_id IN
		   (SELECT id FROM launchers WHERE principal_id = ? AND name = 'extra')`,
		pid).Scan(&storedRoots); err != nil {
		t.Fatalf("count launcher roots: %v", err)
	}
	if storedRoots != 0 {
		t.Fatalf("stale restricted root stored outside the narrowed ceiling: %d rows", storedRoots)
	}
}

// TestUserModeOwnerReservationLookupFailureFailsClosed proves the reservation
// guard never bypasses on a Principal lookup failure: only a genuine
// not-found means "not the reserved Principal"; a database failure aborts the
// mutation (fail-closed). A closed *sql.DB is the existing deterministic seam
// for a lookup that fails with a non-not-found error.
func TestUserModeOwnerReservationLookupFailureFailsClosed(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	if err := app.DB.Close(); err != nil {
		t.Fatalf("close DB: %v", err)
	}
	err := app.rejectReservedPrincipalMutation("dhtestowner")
	if err == nil {
		t.Fatal("reservation lookup failure was bypassed (fail-open)")
	}
	if errors.Is(err, ErrUserModeOwnerReserved) {
		t.Fatalf("reservation lookup failure misreported as the reservation conflict: %v", err)
	}

	// The propagated failure reaches the normal internal-error path through
	// the public API; it is neither misclassified as the reservation conflict
	// nor as principal_not_found.
	w := launcherRequest(t, app, http.MethodPatch, "/principals/dhtestowner", testAdminToken, `{"enabled":false}`)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d (body=%s)", w.Code, w.Body.String())
	}
	if code := decodeAPIError(t, w.Body.Bytes()).Code; code != "internal_error" {
		t.Errorf("expected internal_error, got %q", code)
	}
}
