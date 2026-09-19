package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// rotateThroughMux issues a real POST rotate through the route mux with the
// given bearer and returns the recorder.
func rotateThroughMux(t *testing.T, app *App, username, launcherSelector, bearer string) *httptest.ResponseRecorder {
	t.Helper()
	return launcherAuditRequest(t, app, http.MethodPost,
		"/principals/"+username+"/launchers/"+launcherSelector+"/credential/rotate", bearer, "")
}

// TestLauncherCredentialSelfRotatesOwnCredential proves the
// Launcher-credential self-rotation exception end to end through the real
// rotate route: the authenticated Launcher credential rotates exactly its own
// credential, the response preserves the credential ID and Launcher
// ownership, the old bearer is immediately invalid, the new bearer
// authenticates as exactly the same Launcher, existing Sessions and Launcher
// policy are unchanged, and the credential-row cardinality stays one.
func TestLauncherCredentialSelfRotatesOwnCredential(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app, _, bearerA, l := launcherAuditApp(t, "selfrot1")
	globalRoots := app.Config.AllowedRoots
	home := filepath.Join(allowedRootPaths(globalRoots)[0], "home", "selfrot1")

	// An existing Session owned by the Launcher must survive self-rotation.
	workspace := testWorkspaceDir(t, home)
	created := launcherAuditRequest(t, app, http.MethodPost, "/sessions", bearerA,
		sessionCreateBodyWithLauncherBearer(bearerA, workspace))
	if created.Code != http.StatusCreated {
		t.Fatalf("session create under launcher bearer: got %d %s", created.Code, created.Body.String())
	}
	var createdBody createSessionResponse
	if err := json.Unmarshal(created.Body.Bytes(), &createdBody); err != nil {
		t.Fatal(err)
	}
	sessionID := createdBody.Session.ID

	// Launcher policy snapshot before rotation.
	var beforeName, beforeScope string
	var beforeEnabled bool
	if err := app.DB.QueryRow(`SELECT name, scope_mode, enabled FROM launchers WHERE id = ?`, l.ID).
		Scan(&beforeName, &beforeScope, &beforeEnabled); err != nil {
		t.Fatal(err)
	}

	resp := rotateThroughMux(t, app, "selfrot1", l.ID, bearerA)
	if resp.Code != http.StatusOK {
		t.Fatalf("self-rotate: expected 200, got %d %s", resp.Code, resp.Body.String())
	}
	var rotated launcherCredentialResponse
	if err := json.Unmarshal(resp.Body.Bytes(), &rotated); err != nil {
		t.Fatal(err)
	}
	if rotated.Credential == nil || rotated.Token == "" {
		t.Fatalf("self-rotate response must carry the rotated credential and the new bearer once: %s", resp.Body.String())
	}
	if rotated.Credential.ID == "" {
		t.Error("self-rotate response must preserve the credential ID")
	}

	// Bearer A is immediately invalid; bearer B authenticates as exactly the
	// same Launcher (same stable Launcher ID and same credential ID).
	if w := launcherAuditRequest(t, app, http.MethodGet, "/auth", bearerA, ""); w.Code != http.StatusUnauthorized {
		t.Errorf("old bearer after rotation: expected 401, got %d", w.Code)
	}
	w := launcherAuditRequest(t, app, http.MethodGet, "/auth", rotated.Token, "")
	if w.Code != http.StatusOK {
		t.Fatalf("new bearer /auth: expected 200, got %d", w.Code)
	}
	var auth authResponse
	if err := json.Unmarshal(w.Body.Bytes(), &auth); err != nil {
		t.Fatal(err)
	}
	if auth.Authority != "launcher" || auth.LauncherID != l.ID || auth.Principal != "selfrot1" {
		t.Errorf("new bearer authority = %+v, want launcher %s of selfrot1", auth, l.ID)
	}

	// The rotated credential is the same logical credential: same ID, same
	// Launcher ownership, one row.
	var credLauncherID string
	if err := app.DB.QueryRow(`SELECT launcher_id FROM credentials WHERE id = ?`, rotated.Credential.ID).
		Scan(&credLauncherID); err != nil {
		t.Fatalf("rotated credential lookup: %v", err)
	}
	if credLauncherID != l.ID {
		t.Errorf("rotated credential launcher_id = %q, want %q", credLauncherID, l.ID)
	}
	var count int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM credentials WHERE launcher_id = ?`, l.ID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("credential-row cardinality = %d, want 1", count)
	}

	// Launcher policy is unchanged.
	var afterName, afterScope string
	var afterEnabled bool
	if err := app.DB.QueryRow(`SELECT name, scope_mode, enabled FROM launchers WHERE id = ?`, l.ID).
		Scan(&afterName, &afterScope, &afterEnabled); err != nil {
		t.Fatal(err)
	}
	if afterName != beforeName || afterScope != beforeScope || afterEnabled != beforeEnabled {
		t.Errorf("launcher policy changed on self-rotation: %q/%q/%v -> %q/%q/%v",
			beforeName, beforeScope, beforeEnabled, afterName, afterScope, afterEnabled)
	}

	// The existing Session survived with unchanged ownership.
	var ownedLauncherID string
	if err := app.DB.QueryRow(`SELECT launcher_id FROM sessions WHERE id = ?`, sessionID).
		Scan(&ownedLauncherID); err != nil {
		t.Fatalf("session lookup after rotation: %v", err)
	}
	if ownedLauncherID != l.ID {
		t.Errorf("session launcher ownership changed: %q, want %q", ownedLauncherID, l.ID)
	}

	// The success audit carries the event family, target Launcher ID,
	// credential ID, and Principal provenance, and never either bearer.
	raw := findAuditLine(auditBuf, "launcher.credential_rotate")
	if raw == "" {
		t.Fatalf("expected launcher.credential_rotate audit line\n%s", auditBuf.String())
	}
	m := parseAuditMap(t, raw)
	if m["result"] != "success" || m["launcher_id"] != l.ID || m["credential_id"] != rotated.Credential.ID || m["principal_name"] != "selfrot1" {
		t.Errorf("self-rotate audit provenance = %v", m)
	}
	assertNoSecrets(t, raw, m, bearerA, rotated.Token)
}

// sessionCreateBodyWithLauncherBearer is a helper producing the POST /sessions
// body spelling used by the self-rotation fixtures.
func sessionCreateBodyWithLauncherBearer(bearer, workspace string) string {
	return `{"workspace":"` + workspace + `"}`
}

// TestLauncherCredentialSelfRotateOwnNameSelector proves the own-name
// self-rotation spelling through the real rotate route: the authenticated
// Launcher credential may address itself by its own name — a direct
// comparison with the authenticated owner projection, no name lookup — and
// the mutation is identical to the stable-ID spelling: the same credential
// row keeps its ID, the old bearer dies, and the new bearer authenticates as
// exactly the same Launcher.
func TestLauncherCredentialSelfRotateOwnNameSelector(t *testing.T) {
	app, _, bearerA, l := launcherAuditApp(t, "selfrotn")
	credA, err := findLauncherCredential(app.DB, l.ID)
	if err != nil {
		t.Fatal(err)
	}

	resp := rotateThroughMux(t, app, "selfrotn", l.Name, bearerA)
	if resp.Code != http.StatusOK {
		t.Fatalf("own-name self-rotate: expected 200, got %d %s", resp.Code, resp.Body.String())
	}
	var rotated launcherCredentialResponse
	if err := json.Unmarshal(resp.Body.Bytes(), &rotated); err != nil {
		t.Fatal(err)
	}
	if rotated.Credential == nil || rotated.Credential.ID != credA.ID || rotated.Token == "" {
		t.Fatalf("own-name rotation must preserve the authenticated credential ID %s and return the new bearer once: %s", credA.ID, resp.Body.String())
	}

	// Old bearer dead, new bearer = exactly the same Launcher.
	if w := launcherAuditRequest(t, app, http.MethodGet, "/auth", bearerA, ""); w.Code != http.StatusUnauthorized {
		t.Errorf("old bearer after own-name rotation: expected 401, got %d", w.Code)
	}
	w := launcherAuditRequest(t, app, http.MethodGet, "/auth", rotated.Token, "")
	if w.Code != http.StatusOK {
		t.Fatalf("new bearer /auth after own-name rotation: expected 200, got %d", w.Code)
	}
	var auth authResponse
	if err := json.Unmarshal(w.Body.Bytes(), &auth); err != nil {
		t.Fatal(err)
	}
	if auth.Authority != "launcher" || auth.LauncherID != l.ID || auth.Principal != "selfrotn" {
		t.Errorf("new bearer authority = %+v, want launcher %s of selfrotn", auth, l.ID)
	}
	var count int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM credentials WHERE launcher_id = ?`, l.ID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("credential-row cardinality = %d, want 1", count)
	}
}

// TestLauncherCredentialSelfRotateForeignTargeting proves the self-rotation
// admission is the authenticated owner projection only: a foreign Launcher
// ID, a foreign Launcher name, a foreign Principal path, and another
// Principal's same-name Launcher are all refused with the same constant
// non-disclosing launcher_not_found answer and no foreign-state lookup, and
// the own credential stays valid.
func TestLauncherCredentialSelfRotateForeignTargeting(t *testing.T) {
	app, _, bearerA, l := launcherAuditApp(t, "selfrotf")

	// A real second Principal owning a same-name Launcher, so the
	// same-name case is a genuine cross-Principal path rather than a
	// name-only mismatch.
	globalRoots := app.Config.AllowedRoots
	otherHome := filepath.Join(allowedRootPaths(globalRoots)[0], "home", "otherprincipal")
	if err := os.MkdirAll(otherHome, 0755); err != nil {
		t.Fatal(err)
	}
	orig := OSUserLookup
	OSUserLookup = func(u string) (string, string, string, error) {
		return "2002", "2002", otherHome, nil
	}
	otherP, err := createPrincipal(app.DB, "otherprincipal", globalRoots)
	if err != nil {
		t.Fatalf("createPrincipal(otherprincipal): %v", err)
	}
	OSUserLookup = orig
	if _, _, _, err := createLauncher(app.DB, int64(otherP.ID), "work", LauncherScopeInherit, nil, nil, false); err != nil {
		t.Fatalf("createLauncher(work@otherprincipal): %v", err)
	}

	cases := []struct {
		name     string
		username string
		selector string
	}{
		{name: "foreign launcher ID under own Principal", username: "selfrotf", selector: "dhl_" + "cdcd" + "0000000000000000000000000000"},
		{name: "foreign launcher name under own Principal", username: "selfrotf", selector: "foreignname"},
		{name: "foreign Principal path with own ID", username: "otherprincipal", selector: l.ID},
		{name: "same-name Launcher under another Principal", username: "otherprincipal", selector: "work"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := rotateThroughMux(t, app, tc.username, tc.selector, bearerA)
			if resp.Code != http.StatusNotFound {
				t.Fatalf("expected 404, got %d %s", resp.Code, resp.Body.String())
			}
			errResp := decodeAPIError(t, resp.Body.Bytes())
			if errResp.Code != "launcher_not_found" || errResp.Message != "launcher not found" {
				t.Errorf("refusal = %q/%q, want the constant non-disclosing launcher_not_found", errResp.Code, errResp.Message)
			}
			if !strings.Contains(resp.Body.String(), "launcher not found") || strings.Contains(resp.Body.String(), tc.selector) {
				t.Errorf("refusal must not disclose foreign state, got %s", resp.Body.String())
			}
		})
	}

	// The own credential is untouched by the refusals: bearer A still
	// authenticates and can still rotate self.
	if w := launcherAuditRequest(t, app, http.MethodGet, "/auth", bearerA, ""); w.Code != http.StatusOK {
		t.Fatalf("bearer A must remain valid after foreign-targeting refusals: %d", w.Code)
	}
	resp := rotateThroughMux(t, app, "selfrotf", l.ID, bearerA)
	if resp.Code != http.StatusOK {
		t.Fatalf("self-rotate after refusals: expected 200, got %d %s", resp.Code, resp.Body.String())
	}
}

// TestLauncherCredentialSelfRotateStaleIdentity proves deletion/recreation
// never rebinds an old Launcher authority to a replacement Launcher: the
// credential cascades away with the deleted Launcher, the old bearer answers
// 401 at authentication (it can never rotate the replacement's credential),
// and the replacement Launcher's own credential rotates independently.
func TestLauncherCredentialSelfRotateStaleIdentity(t *testing.T) {
	app, _, _, _ := launcherAuditApp(t, "selfrots")

	// Launcher "work" under the shared Principal, with its own credential.
	l1, _, bearerOld, err := createLauncher(app.DB, principalIDForSelfRotate(t, app, "selfrots"), "work", LauncherScopeInherit, nil, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	_ = bearerOld
	_ = l1

	// Delete the Launcher: the credential row cascades away, so the old
	// bearer stops authenticating at all.
	if _, err := app.DB.Exec(`DELETE FROM launchers WHERE id = ?`, l1.ID); err != nil {
		t.Fatal(err)
	}
	if w := launcherAuditRequest(t, app, http.MethodGet, "/auth", bearerOld, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("stale bearer after launcher deletion: expected 401, got %d", w.Code)
	}

	// Recreate a same-name Launcher: it gets a new stable identity and a new
	// credential. The old bearer must never rotate it (401 at
	// authentication; the request never reaches targeting), and the
	// replacement's own bearer rotates self normally.
	l2, _, bearerNew, err := createLauncher(app.DB, principalIDForSelfRotate(t, app, "selfrots"), "work", LauncherScopeInherit, nil, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if l2.ID == l1.ID {
		t.Fatal("recreated Launcher must carry a new stable identity")
	}
	if resp := rotateThroughMux(t, app, "selfrots", l2.ID, bearerOld); resp.Code != http.StatusUnauthorized {
		t.Errorf("old bearer rotating the replacement Launcher: expected 401, got %d %s", resp.Code, resp.Body.String())
	}
	resp := rotateThroughMux(t, app, "selfrots", l2.ID, bearerNew)
	if resp.Code != http.StatusOK {
		t.Fatalf("replacement Launcher self-rotate: expected 200, got %d %s", resp.Code, resp.Body.String())
	}
}

// principalIDForSelfRotate returns the stored Principal ID of username in the
// self-rotation fixtures.
func principalIDForSelfRotate(t *testing.T, app *App, username string) int64 {
	t.Helper()
	var id int64
	if err := app.DB.QueryRow(`SELECT id FROM principals WHERE username = ?`, username).Scan(&id); err != nil {
		t.Fatalf("principal lookup %s: %v", username, err)
	}
	return id
}

// TestLauncherCredentialSelfRotateStaleAuthRaceFailsClosed is the
// deterministic regression for the auth→mutation replacement race: credential
// A authenticates, the request is parked after authentication (and after the
// self-targeting proof) but before the rotation transaction targets its row,
// credential A is deleted and replacement credential B is issued for the same
// unchanged Launcher, and only then does A's request resume. The exact
// expected-credential targeting must fail A's request closed on the existing
// non-disclosing launcher_credential_not_found refusal — without rotating B,
// without generating a new bearer, and without changing B's row — while B
// self-rotates normally afterwards.
func TestLauncherCredentialSelfRotateStaleAuthRaceFailsClosed(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app, _, bearerA, l := launcherAuditApp(t, "selfrotrace")

	// Credential A is the authenticated authority.
	credA, err := findLauncherCredential(app.DB, l.ID)
	if err != nil {
		t.Fatal(err)
	}

	// Park the request after authentication, before the rotation transaction.
	entered := make(chan struct{})
	release := make(chan struct{})
	origGate := launcherCredentialSelfRotateGate
	launcherCredentialSelfRotateGate = func() {
		close(entered)
		<-release
	}
	t.Cleanup(func() { launcherCredentialSelfRotateGate = origGate })

	// Prove the failed request never generates a bearer: token generation
	// happens only inside the rotation transaction, after the exact
	// credential match. The recorder is installed after the fixtures so it
	// counts only request-time generations.
	origGen := generateCredentialTokenFn
	generated := 0
	generateCredentialTokenFn = func() (string, error) {
		generated++
		return origGen()
	}
	t.Cleanup(func() { generateCredentialTokenFn = origGen })
	generated = 0

	type rotateResult struct {
		w *httptest.ResponseRecorder
	}
	results := make(chan rotateResult, 1)
	go func() {
		results <- rotateResult{w: rotateThroughMux(t, app, "selfrotrace", l.ID, bearerA)}
	}()
	<-entered

	// Mutate the credential store underneath the parked request: delete A,
	// issue replacement B for the same unchanged Launcher.
	if _, err := deleteLauncherCredential(app.DB, l.ID); err != nil {
		t.Fatal(err)
	}
	credB, bearerB, err := issueLauncherCredential(app.DB, l.ID)
	if err != nil {
		t.Fatal(err)
	}
	// B's issuance consumed a token generation; count only request-time
	// generations from here.
	generated = 0
	close(release)

	res := <-results
	if res.w.Code != http.StatusNotFound {
		t.Fatalf("stale A's self-rotation: expected 404, got %d %s", res.w.Code, res.w.Body.String())
	}
	errResp := decodeAPIError(t, res.w.Body.Bytes())
	if errResp.Code != "launcher_credential_not_found" {
		t.Errorf("refusal code = %q, want launcher_credential_not_found", errResp.Code)
	}
	if generated != 0 {
		t.Errorf("the failed stale request generated %d bearer(s); a failed closed rotation must generate none", generated)
	}

	// Replacement B is untouched: its bearer still authenticates as exactly
	// the same Launcher and its credential ID is unchanged.
	w := launcherAuditRequest(t, app, http.MethodGet, "/auth", bearerB, "")
	if w.Code != http.StatusOK {
		t.Fatalf("replacement bearer B after A's failed request: expected 200, got %d", w.Code)
	}
	var auth authResponse
	if err := json.Unmarshal(w.Body.Bytes(), &auth); err != nil {
		t.Fatal(err)
	}
	if auth.Authority != "launcher" || auth.LauncherID != l.ID {
		t.Errorf("B's authority = %+v, want launcher %s", auth, l.ID)
	}
	var currentB string
	if err := app.DB.QueryRow(`SELECT id FROM credentials WHERE launcher_id = ?`, l.ID).Scan(&currentB); err != nil {
		t.Fatal(err)
	}
	if currentB != credB.ID {
		t.Errorf("replacement credential changed: %q -> %q", credB.ID, currentB)
	}
	var count int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM credentials WHERE launcher_id = ?`, l.ID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("credential cardinality = %d, want 1", count)
	}

	// The failure audit records A's initiating provenance, never B as the
	// target, and never either bearer.
	for _, line := range findAuditLinesByEvent(auditBuf, "launcher.credential_rotate") {
		m := parseAuditMap(t, line)
		if m["result"] == "error" {
			if m["launcher_id"] != l.ID || m["credential_id"] != credA.ID {
				t.Errorf("stale-failure audit must carry A's initiating provenance (launcher %s, credential %s), got %v", l.ID, credA.ID, m)
			}
		}
		assertNoSecrets(t, line, m, bearerA, bearerB)
	}

	// B may self-rotate normally.
	launcherCredentialSelfRotateGate = nil
	resp := rotateThroughMux(t, app, "selfrotrace", l.ID, bearerB)
	if resp.Code != http.StatusOK {
		t.Fatalf("B's self-rotation: expected 200, got %d %s", resp.Code, resp.Body.String())
	}
	var rotated launcherCredentialResponse
	if err := json.Unmarshal(resp.Body.Bytes(), &rotated); err != nil {
		t.Fatal(err)
	}
	if rotated.Credential == nil || rotated.Credential.ID != credB.ID {
		t.Errorf("B's rotation must preserve its credential ID %s, got %+v", credB.ID, rotated.Credential)
	}
}

// TestLauncherCredentialSelfRotateOtherControlPlaneForbidden proves the
// self-rotation exception does not open the shared Principal-control
// authenticator: with a Launcher bearer, representative Launcher/Principal
// control endpoints keep their standard 401 unauthorized contract.
func TestLauncherCredentialSelfRotateOtherControlPlaneForbidden(t *testing.T) {
	app, _, bearerA, l := launcherAuditApp(t, "selfrotx")

	cases := []struct {
		name   string
		method string
		path   string
	}{
		{name: "launcher show", method: http.MethodGet, path: "/principals/selfrotx/launchers/" + l.ID},
		{name: "launcher set", method: http.MethodPatch, path: "/principals/selfrotx/launchers/" + l.ID},
		{name: "launcher allowed-root mutation", method: http.MethodPatch, path: "/principals/selfrotx/launchers/" + l.ID + "/allowed-roots"},
		{name: "launcher credential show", method: http.MethodGet, path: "/principals/selfrotx/launchers/" + l.ID + "/credential"},
		{name: "launcher credential delete", method: http.MethodDelete, path: "/principals/selfrotx/launchers/" + l.ID + "/credential"},
		{name: "principal credential rotate", method: http.MethodPost, path: "/principals/selfrotx/credentials/audit/rotate"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := launcherAuditRequest(t, app, tc.method, tc.path, bearerA, "")
			if w.Code != http.StatusUnauthorized {
				t.Errorf("%s: expected 401, got %d %s", tc.name, w.Code, w.Body.String())
			}
		})
	}
}
