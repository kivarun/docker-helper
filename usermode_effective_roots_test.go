package main

// User-mode effective-Principal-root surfaces after the single canonical
// policy owner (RC6 blocker 2). The transparent user-mode daemon-owner
// Principal must carry the global allowed-root ceiling on every consuming
// surface — restricted Launcher create, restricted-scope replacement,
// effective-roots introspection (and completion through it), and Session
// creation under a restricted Launcher — while the reserved 'default'
// Launcher stays protected by the reservation owner and system-mode
// semantics are untouched.

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// setupUserModeEffectiveRootsApp provisions a user-mode app whose global
// allowed root R contains a restricted candidate workspace tree
// (R/work/proj) and an outside-global-ceiling sibling directory (outside R,
// policy-legal as a workspace path). Returns the app, R, the restricted
// candidate root, and the outside-ceiling root.
func setupUserModeEffectiveRootsApp(t *testing.T) (*App, string, string, string) {
	t.Helper()
	app := newTestAppWithAdminToken(t)
	root := app.Config.AllowedRoots[0]
	work := filepath.Join(root, "work")
	proj := filepath.Join(work, "proj")
	for _, d := range []string{proj} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	// The outside-ceiling candidate is a sibling of the global allowed root:
	// inside the same policy-legal base directory but outside the ceiling.
	outside, err := os.MkdirTemp(filepath.Dir(root), ".docker-helper-outside-*")
	if err != nil {
		t.Fatalf("allocate outside-ceiling dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(outside) })
	return app, root, work, outside
}

// expectEffectiveRootsResponse decodes a 200 effective-roots response.
func expectEffectiveRootsResponse(t *testing.T, body []byte) []string {
	t.Helper()
	var resp effectiveRootsResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode effective roots response: %v", err)
	}
	return resp.AllowedRoots
}

// TestUserModeOwnerEffectiveRootsIntrospection is the completion-introspection
// regression: the transparent user-mode daemon-owner Principal must report
// the global allowed-root ceiling from
// GET /principals/{username}/effective-allowed-roots — never the empty set
// the competing global∩stored computation produced. The Session-create policy
// introspection (GET /sessions/create-policy, resolved by the same owner) and
// the introspection endpoint must return the same ceiling.
func TestUserModeOwnerEffectiveRootsIntrospection(t *testing.T) {
	app, root, _, _ := setupUserModeEffectiveRootsApp(t)
	owner := app.userModeDefault.username

	w := launcherRequest(t, app, http.MethodGet, "/principals/"+owner+"/effective-allowed-roots", testAdminToken, "")
	if w.Code != http.StatusOK {
		t.Fatalf("effective-roots introspection: expected 200, got %d (body=%s)", w.Code, w.Body.String())
	}
	roots := expectEffectiveRootsResponse(t, w.Body.Bytes())
	if !slices.Equal(roots, []string{root}) {
		t.Fatalf("effective-roots introspection for the daemon-owner Principal = %v, want the global ceiling [%s]", roots, root)
	}

	policy := launcherRequest(t, app, http.MethodGet, "/sessions/create-policy", testAdminToken, "")
	if policy.Code != http.StatusOK {
		t.Fatalf("session create-policy introspection: expected 200, got %d (body=%s)", policy.Code, policy.Body.String())
	}
	var policyResp sessionCreatePolicyResponse
	if err := json.Unmarshal(policy.Body.Bytes(), &policyResp); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(policyResp.AllowedRoots, roots) {
		t.Fatalf("surfaces disagree on the daemon-owner ceiling: introspection=%v create-policy=%v", roots, policyResp.AllowedRoots)
	}
	if !slices.Equal(policyResp.AllowedRoots, []string{root}) {
		t.Fatalf("session create-policy for the daemon-owner chain = %v, want the global ceiling [%s]", policyResp.AllowedRoots, root)
	}
}

// TestUserModeOwnerRestrictedLauncherCreate proves the transparent user-mode
// daemon-owner Principal can create a restricted additional Launcher under
// the global ceiling, that a root outside the ceiling is refused, and that
// the reserved 'default' Launcher is still not restrictable (the reservation
// owner must survive the effective-root unification).
func TestUserModeOwnerRestrictedLauncherCreate(t *testing.T) {
	app, _, work, outside := setupUserModeEffectiveRootsApp(t)
	owner := app.userModeDefault.username

	w := launcherRequest(t, app, http.MethodPost, "/principals/"+owner+"/launchers", testAdminToken,
		`{"name":"work","scope":"restricted","allowed_roots":["`+work+`"]}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("restricted create under the global ceiling: expected 201, got %d (body=%s)", w.Code, w.Body.String())
	}
	var created createLauncherResponse
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Launcher.Scope != string(LauncherScopeRestricted) || !slices.Equal(created.Launcher.AllowedRoots, []string{work}) {
		t.Fatalf("created launcher = %+v, want restricted with stored root [%s]", created.Launcher, work)
	}

	out := launcherRequest(t, app, http.MethodPost, "/principals/"+owner+"/launchers", testAdminToken,
		`{"name":"bad","scope":"restricted","allowed_roots":["`+outside+`"]}`)
	if out.Code != http.StatusBadRequest {
		t.Fatalf("restricted create outside the ceiling: expected 400, got %d (body=%s)", out.Code, out.Body.String())
	}
	if code := decodeAPIError(t, out.Body.Bytes()).Code; code != "outside_principal_root" {
		t.Errorf("expected outside_principal_root, got %q", code)
	}

	// The reserved daemon-owner 'default' Launcher remains protected: it must
	// not become restrictable, and it keeps the transparent contract.
	reserved := launcherRequest(t, app, http.MethodPut, "/principals/"+owner+"/launchers/default/allowed-roots", testAdminToken,
		`{"scope":"restricted","allowed_roots":["`+work+`"]}`)
	if reserved.Code != http.StatusConflict {
		t.Fatalf("restricted scope replace on the reserved default Launcher: expected 409, got %d (body=%s)", reserved.Code, reserved.Body.String())
	}
	if code := decodeAPIError(t, reserved.Body.Bytes()).Code; code != "user_mode_owner_reserved" {
		t.Errorf("expected user_mode_owner_reserved, got %q", code)
	}
}

// TestUserModeOwnerLauncherScopeReplaceRestricted proves the transparent
// user-mode daemon-owner Principal can convert an additional Launcher from
// inherit to restricted scope under the global ceiling, and that a
// replacement root outside the ceiling is refused with the old scope intact.
func TestUserModeOwnerLauncherScopeReplaceRestricted(t *testing.T) {
	app, _, work, outside := setupUserModeEffectiveRootsApp(t)
	owner := app.userModeDefault.username

	w := launcherRequest(t, app, http.MethodPost, "/principals/"+owner+"/launchers", testAdminToken,
		`{"name":"conv","scope":"inherit"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("inherit create: expected 201, got %d (body=%s)", w.Code, w.Body.String())
	}
	var created createLauncherResponse
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}

	replace := launcherRequest(t, app, http.MethodPut, "/principals/"+owner+"/launchers/conv/allowed-roots", testAdminToken,
		`{"scope":"restricted","allowed_roots":["`+work+`"]}`)
	if replace.Code != http.StatusOK {
		t.Fatalf("inherit -> restricted under the global ceiling: expected 200, got %d (body=%s)", replace.Code, replace.Body.String())
	}
	var updated launcherJSON
	if err := json.Unmarshal(replace.Body.Bytes(), &updated); err != nil {
		t.Fatal(err)
	}
	if updated.Scope != string(LauncherScopeRestricted) || !slices.Equal(updated.AllowedRoots, []string{work}) {
		t.Fatalf("replaced launcher = %+v, want restricted with stored root [%s]", updated, work)
	}

	refused := launcherRequest(t, app, http.MethodPut, "/principals/"+owner+"/launchers/conv/allowed-roots", testAdminToken,
		`{"scope":"restricted","allowed_roots":["`+outside+`"]}`)
	if refused.Code != http.StatusBadRequest {
		t.Fatalf("replacement outside the ceiling: expected 400, got %d (body=%s)", refused.Code, refused.Body.String())
	}
	if code := decodeAPIError(t, refused.Body.Bytes()).Code; code != "outside_principal_root" {
		t.Errorf("expected outside_principal_root, got %q", code)
	}
}

// TestUserModeOwnerSessionUnderRestrictedLauncher proves the three-level
// Session policy through the restricted Launcher created under the
// daemon-owner Principal: a workspace inside the restricted root creates a
// Session, a workspace inside the global ceiling but outside the restricted
// root is rejected, and the Session-create introspection for that Launcher's
// Principal keeps reporting the same global ceiling the restricted
// validation used.
func TestUserModeOwnerSessionUnderRestrictedLauncher(t *testing.T) {
	app, root, work, _ := setupUserModeEffectiveRootsApp(t)
	owner := app.userModeDefault.username

	w := launcherRequest(t, app, http.MethodPost, "/principals/"+owner+"/launchers", testAdminToken,
		`{"name":"work","scope":"restricted","allowed_roots":["`+work+`"]}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("restricted create: expected 201, got %d (body=%s)", w.Code, w.Body.String())
	}
	var created createLauncherResponse
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	launcherID := created.Launcher.ID

	other := filepath.Join(root, "other")
	if err := os.MkdirAll(other, 0755); err != nil {
		t.Fatal(err)
	}

	inside := launcherRequest(t, app, http.MethodPost, "/sessions", testAdminToken,
		`{"workspace":"`+filepath.Join(work, "proj")+`","launcher_id":"`+launcherID+`"}`)
	if inside.Code != http.StatusCreated {
		t.Fatalf("session inside the restricted root: expected 201, got %d (body=%s)", inside.Code, inside.Body.String())
	}
	var createdSession createSessionResponse
	if err := json.Unmarshal(inside.Body.Bytes(), &createdSession); err != nil {
		t.Fatal(err)
	}
	if createdSession.Session.LauncherID != launcherID {
		t.Errorf("session owner launcher = %q, want the restricted launcher %q", createdSession.Session.LauncherID, launcherID)
	}
	if createdSession.Session.Workspace != filepath.Join(work, "proj") {
		t.Errorf("session workspace = %q, want %q", createdSession.Session.Workspace, filepath.Join(work, "proj"))
	}
	launcherRequest(t, app, http.MethodDelete, "/sessions/"+createdSession.Session.ID, testAdminToken, "")

	outsideRestricted := launcherRequest(t, app, http.MethodPost, "/sessions", testAdminToken,
		`{"workspace":"`+other+`","launcher_id":"`+launcherID+`"}`)
	if outsideRestricted.Code != http.StatusBadRequest {
		t.Fatalf("session outside the restricted root but inside the ceiling: expected 400, got %d (body=%s)", outsideRestricted.Code, outsideRestricted.Body.String())
	}
	if code := decodeAPIError(t, outsideRestricted.Body.Bytes()).Code; code != "invalid_workspace" {
		t.Errorf("expected invalid_workspace, got %q", code)
	}

	// The introspection surface keeps reporting the same global ceiling the
	// restricted validation consumed.
	roots := expectEffectiveRootsResponse(t, launcherRequest(t, app,
		http.MethodGet, "/principals/"+owner+"/effective-allowed-roots", testAdminToken, "").Body.Bytes())
	if !slices.Equal(roots, []string{root}) {
		t.Fatalf("effective-roots introspection = %v, want the global ceiling [%s]", roots, root)
	}
}
