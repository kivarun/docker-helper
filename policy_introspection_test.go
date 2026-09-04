package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// setupPolicyPrincipal creates a Principal whose single stored allowed root
// is root (it must be under the app's global allowed root) and returns the
// Principal credential bearer token.
func setupPolicyPrincipal(t *testing.T, app *App, username, root string) string {
	t.Helper()
	home := filepath.Join(app.Config.AllowedRoots[0], "home", username)
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}
	installOSUserMock(t, map[string]string{username: home})
	if _, err := createPrincipal(app.DB, username, app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal(%s): %v", username, err)
	}
	// Replace the seeded home root with the requested root.
	w := launcherRequest(t, app, http.MethodDelete, "/principals/"+username+"/allowed-roots", testAdminToken,
		fmt.Sprintf(`{"path":%q}`, home))
	if w.Code != http.StatusOK {
		t.Fatalf("remove seeded root: %d %s", w.Code, w.Body.String())
	}
	w = launcherRequest(t, app, http.MethodPost, "/principals/"+username+"/allowed-roots", testAdminToken,
		fmt.Sprintf(`{"path":%q}`, root))
	if w.Code != http.StatusOK {
		t.Fatalf("add root %s: %d %s", root, w.Code, w.Body.String())
	}
	_, token, err := createCredential(app.DB, username, "oc")
	if err != nil {
		t.Fatalf("createCredential(%s): %v", username, err)
	}
	return token
}

// createRestrictedLauncherWithCredential creates a restricted Launcher under
// the given Principal with one allowed root and an issued Launcher credential,
// returning the Launcher ID and the Launcher credential bearer token.
func createRestrictedLauncherWithCredential(t *testing.T, app *App, username, name, root string) (string, string) {
	t.Helper()
	w := launcherRequest(t, app, http.MethodPost, "/principals/"+username+"/launchers", testAdminToken,
		fmt.Sprintf(`{"name":%q,"scope":"restricted","allowed_roots":[%q],"issue_credential":true}`, name, root))
	if w.Code != http.StatusCreated {
		t.Fatalf("create restricted launcher: %d %s", w.Code, w.Body.String())
	}
	var created createLauncherResponse
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Credential == nil || created.Token == "" {
		t.Fatalf("expected issued Launcher credential, got %+v", created)
	}
	return created.Launcher.ID, created.Token
}

// decodePolicyRoots decodes the effectiveRootsResponse wire shape.
func decodePolicyRoots(t *testing.T, body string) effectiveRootsResponse {
	t.Helper()
	var resp effectiveRootsResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("decode effective roots response: %v (body=%s)", err, body)
	}
	return resp
}

// decodeCreatePolicy decodes the sessionCreatePolicyResponse wire shape.
func decodeCreatePolicy(t *testing.T, body string) sessionCreatePolicyResponse {
	t.Helper()
	var resp sessionCreatePolicyResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("decode create-policy response: %v (body=%s)", err, body)
	}
	return resp
}

// TestPrincipalEffectiveRootsContractMatrix proves the authorization matrix
// and effective computation of the Principal policy introspection Query:
// an admin token targets any Principal; a Principal credential only its own;
// a foreign selector is the same non-disclosing 404 as an unknown Principal;
// a Launcher credential and an unauthenticated request are unauthorized; and
// the returned roots are the daemon-side global ∩ Principal intersection
// computed by the canonical effectivePrincipalRoots owner.
func TestPrincipalEffectiveRootsContractMatrix(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	proj := filepath.Join(app.Config.AllowedRoots[0], "home", "alice", "proj")
	if err := os.MkdirAll(proj, 0755); err != nil {
		t.Fatal(err)
	}
	aliceToken := setupPolicyPrincipal(t, app, "alice", proj)
	setupPolicyPrincipal(t, app, "bob", app.Config.AllowedRoots[0])

	// Admin targets alice: effective = alice's narrowed stored roots.
	w := launcherRequest(t, app, http.MethodGet, "/principals/alice/effective-allowed-roots", testAdminToken, "")
	if w.Code != http.StatusOK {
		t.Fatalf("admin query: %d %s", w.Code, w.Body.String())
	}
	resp := decodePolicyRoots(t, w.Body.String())
	if !resp.OK || resp.Principal != "alice" {
		t.Fatalf("response = %+v", resp)
	}
	if len(resp.AllowedRoots) != 1 || resp.AllowedRoots[0] != proj {
		t.Fatalf("allowed_roots = %v, want [%s]", resp.AllowedRoots, proj)
	}

	// Admin targets an unknown Principal: non-disclosing 404.
	w = launcherRequest(t, app, http.MethodGet, "/principals/uatmissing/effective-allowed-roots", testAdminToken, "")
	if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "principal_not_found") {
		t.Fatalf("unknown principal: %d %s", w.Code, w.Body.String())
	}

	// Alice's credential targets her own Principal: the same effective roots.
	w = launcherRequest(t, app, http.MethodGet, "/principals/alice/effective-allowed-roots", aliceToken, "")
	if w.Code != http.StatusOK {
		t.Fatalf("own credential query: %d %s", w.Code, w.Body.String())
	}
	if got := decodePolicyRoots(t, w.Body.String()); len(got.AllowedRoots) != 1 || got.AllowedRoots[0] != proj {
		t.Fatalf("own allowed_roots = %v, want [%s]", got.AllowedRoots, proj)
	}

	// Alice's credential targeting bob is the same non-disclosing 404 as
	// an unknown Principal: indistinguishable bodies.
	wForeign := launcherRequest(t, app, http.MethodGet, "/principals/bob/effective-allowed-roots", aliceToken, "")
	if wForeign.Code != http.StatusNotFound {
		t.Fatalf("foreign principal: %d %s", wForeign.Code, wForeign.Body.String())
	}
	wUnknown := launcherRequest(t, app, http.MethodGet, "/principals/uatmissing/effective-allowed-roots", aliceToken, "")
	if wUnknown.Code != http.StatusNotFound || wUnknown.Body.String() != wForeign.Body.String() {
		t.Fatalf("foreign and unknown must be indistinguishable: %q vs %q", wForeign.Body.String(), wUnknown.Body.String())
	}

	// A Launcher credential has no control-plane authority: 401.
	_, launcherToken := createRestrictedLauncherWithCredential(t, app, "alice", "agent", proj)
	w = launcherRequest(t, app, http.MethodGet, "/principals/alice/effective-allowed-roots", launcherToken, "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("launcher credential: %d %s", w.Code, w.Body.String())
	}

	// Unauthenticated: 401.
	w = launcherRequest(t, app, http.MethodGet, "/principals/alice/effective-allowed-roots", "", "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated: %d %s", w.Code, w.Body.String())
	}
}

// TestSessionCreatePolicyContractMatrix proves the Session-create policy
// introspection Query authenticates and resolves exactly like real Session
// creation: a Principal credential resolves its default Launcher's effective
// roots; a restricted Launcher credential resolves its own Launcher's
// narrowed roots (Launcher scope, never the wider Principal scope); a
// system-mode admin without a resolvable Launcher receives the same
// missing-selector contract as real create; and unauthenticated requests
// are rejected.
func TestSessionCreatePolicyContractMatrix(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	aliceRoot := filepath.Join(app.Config.AllowedRoots[0], "home", "alice")
	if err := os.MkdirAll(aliceRoot, 0755); err != nil {
		t.Fatal(err)
	}
	aliceToken := setupPolicyPrincipal(t, app, "alice", aliceRoot)

	// Principal credential: default Launcher effective roots.
	w := launcherRequest(t, app, http.MethodGet, "/sessions/create-policy", aliceToken, "")
	if w.Code != http.StatusOK {
		t.Fatalf("principal credential policy: %d %s", w.Code, w.Body.String())
	}
	resp := decodeCreatePolicy(t, w.Body.String())
	if !resp.OK || resp.Principal != "alice" || resp.Launcher != "default" {
		t.Fatalf("response = %+v", resp)
	}
	if !strings.HasPrefix(resp.LauncherID, launcherIDPrefix) {
		t.Fatalf("launcher_id = %q", resp.LauncherID)
	}
	if len(resp.AllowedRoots) != 1 || resp.AllowedRoots[0] != aliceRoot {
		t.Fatalf("allowed_roots = %v, want [%s]", resp.AllowedRoots, aliceRoot)
	}

	// Restricted Launcher credential: the query must answer with the
	// Launcher's narrowed roots, not the Principal's wider scope. The
	// restricted root must sit under alice's effective Principal ceiling.
	proj := filepath.Join(aliceRoot, "proj")
	if err := os.MkdirAll(proj, 0755); err != nil {
		t.Fatal(err)
	}
	launcherID, launcherToken := createRestrictedLauncherWithCredential(t, app, "alice", "agent", proj)
	w = launcherRequest(t, app, http.MethodGet, "/sessions/create-policy", launcherToken, "")
	if w.Code != http.StatusOK {
		t.Fatalf("launcher credential policy: %d %s", w.Code, w.Body.String())
	}
	resp = decodeCreatePolicy(t, w.Body.String())
	if resp.Principal != "alice" || resp.LauncherID != launcherID || resp.Launcher != "agent" {
		t.Fatalf("response = %+v", resp)
	}
	if len(resp.AllowedRoots) != 1 || resp.AllowedRoots[0] != proj {
		t.Fatalf("launcher-restricted allowed_roots = %v, want [%s]", resp.AllowedRoots, proj)
	}

	// System-mode admin with no selector: the same missing-selector
	// contract real Session create returns. The test app is user mode by
	// default; the deployment mode is a config decision, so flip it for
	// this query.
	app.Config.Mode = ModeSystem
	w = launcherRequest(t, app, http.MethodGet, "/sessions/create-policy", testAdminToken, "")
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "missing_launcher_selector") {
		t.Fatalf("system admin: %d %s", w.Code, w.Body.String())
	}

	// Unauthenticated: 401.
	w = launcherRequest(t, app, http.MethodGet, "/sessions/create-policy", "", "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated: %d %s", w.Code, w.Body.String())
	}
}

// TestSessionCreatePolicyUnavailableLauncher proves the introspection Query
// preserves the real create contract for a disabled Launcher: 422
// launcher_unavailable. A Principal credential still authenticates when its
// Launcher is disabled; the rejection comes from the shared resolution owner.
func TestSessionCreatePolicyUnavailableLauncher(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	aliceToken := setupPolicyPrincipal(t, app, "alice", app.Config.AllowedRoots[0])

	// Disable alice's default Launcher (the one her credential resolves).
	launcherID := mustAddDefaultLauncher(t, app.DB, principalIDByName(t, app.DB, "alice"))
	w := launcherRequest(t, app, http.MethodPatch, "/principals/alice/launchers/"+launcherID, testAdminToken, `{"enabled":false}`)
	if w.Code != http.StatusOK {
		t.Fatalf("disable launcher: %d %s", w.Code, w.Body.String())
	}

	w = launcherRequest(t, app, http.MethodGet, "/sessions/create-policy", aliceToken, "")
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "launcher_unavailable") {
		t.Fatalf("disabled launcher: %d %s", w.Code, w.Body.String())
	}
}

// TestSessionCreatePolicyUserModeAdmin proves the user-mode admin authority
// resolves the daemon-owner default Launcher with the collapsed global roots,
// exactly like real Session creation.
func TestSessionCreatePolicyUserModeAdmin(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	w := launcherRequest(t, app, http.MethodGet, "/sessions/create-policy", testAdminToken, "")
	if w.Code != http.StatusOK {
		t.Fatalf("user-mode admin policy: %d %s", w.Code, w.Body.String())
	}
	resp := decodeCreatePolicy(t, w.Body.String())
	if resp.Principal != "dhtestowner" || resp.Launcher != "default" {
		t.Fatalf("response = %+v", resp)
	}
	if len(resp.AllowedRoots) != 1 || resp.AllowedRoots[0] != app.Config.AllowedRoots[0] {
		t.Fatalf("allowed_roots = %v, want [%s]", resp.AllowedRoots, app.Config.AllowedRoots[0])
	}
}

// ---- completion roots CLI bridge ----

// TestCompletionRootsCLIPrincipal proves the machine-facing principal query
// prints one effective root per line, forwards the bearer, and targets the
// daemon endpoint exactly once with no /auth introspection when --principal
// is explicit.
func TestCompletionRootsCLIPrincipal(t *testing.T) {
	endpoint, tokenPath, requests := startRecordingLauncherCLIServer(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("Authorization = %q", got)
		}
		if r.URL.Path == "/principals/alice/effective-allowed-roots" && r.Method == http.MethodGet {
			writeJSONResponse(w, http.StatusOK, effectiveRootsResponse{
				OK:           true,
				Principal:    "alice",
				AllowedRoots: []string{"/roots/one", "/roots/two"},
			})
			return
		}
		http.NotFound(w, r)
	})

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{
		"completion", "roots", "principal", "--endpoint", endpoint, "--token-file", tokenPath, "--principal", "alice",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, stderr.String())
	}
	if len(*requests) != 1 || (*requests)[0].path != "/principals/alice/effective-allowed-roots" {
		t.Fatalf("requests = %+v, want exactly one effective-roots request", *requests)
	}
	if got, want := stdout.String(), "/roots/one\n/roots/two\n"; got != want {
		t.Errorf("stdout = %q, want %q", got, want)
	}
}

// TestCompletionRootsCLIPrincipalInferred proves that without --principal the
// helper infers the caller's own Principal via GET /auth with the same
// scope-aware rule the launcher command family uses.
func TestCompletionRootsCLIPrincipalInferred(t *testing.T) {
	endpoint, tokenPath, requests := startRecordingLauncherCLIServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/auth" && r.Method == http.MethodGet:
			writeJSONResponse(w, http.StatusOK, authResponse{Authority: "principal", Principal: "alice"})
		case r.URL.Path == "/principals/alice/effective-allowed-roots" && r.Method == http.MethodGet:
			writeJSONResponse(w, http.StatusOK, effectiveRootsResponse{
				OK:           true,
				Principal:    "alice",
				AllowedRoots: []string{"/roots/one"},
			})
		default:
			http.NotFound(w, r)
		}
	})

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{
		"completion", "roots", "principal", "--endpoint", endpoint, "--token-file", tokenPath,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, stderr.String())
	}
	if len(*requests) != 2 || (*requests)[0].path != "/auth" || (*requests)[1].path != "/principals/alice/effective-allowed-roots" {
		t.Fatalf("requests = %+v, want /auth then effective-roots", *requests)
	}
	if got, want := stdout.String(), "/roots/one\n"; got != want {
		t.Errorf("stdout = %q, want %q", got, want)
	}
}

// TestCompletionRootsCLIAdminRequiresPrincipal proves an admin caller must
// name the target explicitly: no target is inferred or searched, and no
// paths are printed.
func TestCompletionRootsCLIAdminRequiresPrincipal(t *testing.T) {
	endpoint, tokenPath, requests := startRecordingLauncherCLIServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth" && r.Method == http.MethodGet {
			writeJSONResponse(w, http.StatusOK, authResponse{Authority: "admin"})
			return
		}
		http.NotFound(w, r)
	})

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{
		"completion", "roots", "principal", "--endpoint", endpoint, "--token-file", tokenPath,
	}, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("admin without --principal must fail, stdout=%s", stdout.String())
	}
	if stdout.String() != "" {
		t.Errorf("no paths may be printed, got %q", stdout.String())
	}
	if len(*requests) != 1 || (*requests)[0].path != "/auth" {
		t.Fatalf("requests = %+v, want only /auth", *requests)
	}
}

// TestCompletionRootsCLIPrincipalEqualsForm proves the --principal=VALUE
// form reaches the same daemon target.
func TestCompletionRootsCLIPrincipalEqualsForm(t *testing.T) {
	endpoint, tokenPath, requests := startRecordingLauncherCLIServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/principals/bob/effective-allowed-roots" && r.Method == http.MethodGet {
			writeJSONResponse(w, http.StatusOK, effectiveRootsResponse{OK: true, Principal: "bob"})
			return
		}
		http.NotFound(w, r)
	})

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{
		"completion", "roots", "principal", "--endpoint", endpoint, "--token-file", tokenPath, "--principal=bob",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, stderr.String())
	}
	if len(*requests) != 1 || (*requests)[0].path != "/principals/bob/effective-allowed-roots" {
		t.Fatalf("requests = %+v", *requests)
	}
}

// TestCompletionRootsCLISession proves the session query prints the
// Session-create effective roots, one path per line.
func TestCompletionRootsCLISession(t *testing.T) {
	endpoint, tokenPath, requests := startRecordingLauncherCLIServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/sessions/create-policy" && r.Method == http.MethodGet {
			writeJSONResponse(w, http.StatusOK, sessionCreatePolicyResponse{
				OK:           true,
				Principal:    "alice",
				LauncherID:   "dhl_x",
				Launcher:     "default",
				AllowedRoots: []string{"/launcher/roots/only"},
			})
			return
		}
		http.NotFound(w, r)
	})

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{
		"completion", "roots", "session", "--endpoint", endpoint, "--token-file", tokenPath,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, stderr.String())
	}
	if len(*requests) != 1 || (*requests)[0].path != "/sessions/create-policy" {
		t.Fatalf("requests = %+v", *requests)
	}
	if got, want := stdout.String(), "/launcher/roots/only\n"; got != want {
		t.Errorf("stdout = %q, want %q", got, want)
	}
}

// TestCompletionRootsCLIUnauthorized proves a daemon rejection surfaces as a
// non-zero exit with no path output, so Bash completion degrades to its
// generic fallback.
func TestCompletionRootsCLIUnauthorized(t *testing.T) {
	endpoint, tokenPath, _ := startRecordingLauncherCLIServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/sessions/create-policy" && r.Method == http.MethodGet {
			writeJSONResponse(w, http.StatusUnauthorized, map[string]any{
				"ok": false, "code": "unauthorized", "message": "Authentication required for session management.",
			})
			return
		}
		http.NotFound(w, r)
	})

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{
		"completion", "roots", "session", "--endpoint", endpoint, "--token-file", tokenPath,
	}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("unauthorized query must fail")
	}
	if stdout.String() != "" {
		t.Errorf("no paths may be printed, got %q", stdout.String())
	}
}
