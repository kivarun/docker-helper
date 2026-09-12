package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// The stale-authority incarnations regressions: a Principal credential
// authority is the exact Principal ID it authenticated as
// (PrincipalCredentialAuth.PrincipalID); the name is selector/display
// provenance only. After that Principal is deleted and the same username is
// recreated as a new incarnation (new AUTOINCREMENT ID), the stale in-flight
// authority must fail closed as principal_not_found — it may never rebind to
// the replacement Principal.
//
// The authority is modeled through the direct post-authentication owner
// (a hand-built PrincipalCredentialAuth): normal re-authentication would
// already reject a deleted credential, so no production fault hook is needed
// and every regression below is fully deterministic.

// stalePrincipalFixture provisions the delete/recreate incarnation premise:
// alice with stored roots [home, extra] and an active Principal credential
// named "default", deleted, then recreated under the same username as a new
// incarnation with its seeded home root and a fresh active credential of the
// same name. It returns the stale post-authentication authority for the
// deleted incarnation, both IDs, and the replacement credential's bearer.
type stalePrincipalFixture struct {
	app      *App
	stale    *operatorAuthority
	oldID    int64
	newID    int64
	home     string
	extra    string
	newToken string
}

func createStalePrincipalFixture(t *testing.T) *stalePrincipalFixture {
	t.Helper()
	app := newTestAppWithAdminToken(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "alice")
	extra := filepath.Join(home, "extra")
	if err := os.MkdirAll(extra, 0755); err != nil {
		t.Fatal(err)
	}
	installOSUserMock(t, map[string]string{"alice": home})

	// Old incarnation: stored roots [home (seeded), extra], active
	// credential "default".
	p, cred, _, err := createPrincipalWithOptionalCredential(app.DB, "alice", app.Config.AllowedRoots, true)
	if err != nil {
		t.Fatalf("create alice: %v", err)
	}
	w := launcherRequest(t, app, http.MethodPost, "/principals/alice/allowed-roots", testAdminToken, fmt.Sprintf(`{"path":%q}`, extra))
	if w.Code != http.StatusOK {
		t.Fatalf("add extra root: %d %s", w.Code, w.Body.String())
	}
	oldID := int64(p.ID)

	// Delete the old incarnation, then recreate the same username as a new
	// one with a fresh active credential of the same name.
	if _, err := deletePrincipal(app.DB, "alice"); err != nil {
		t.Fatalf("delete alice: %v", err)
	}
	newP, _, newToken, err := createPrincipalWithOptionalCredential(app.DB, "alice", app.Config.AllowedRoots, true)
	if err != nil {
		t.Fatalf("recreate alice: %v", err)
	}
	newID := int64(newP.ID)
	if newID == oldID {
		t.Fatalf("incarnation premise violated: recreated Principal reused ID %d", oldID)
	}

	stale := &operatorAuthority{
		class: operatorAuthorityPrincipal,
		principal: &PrincipalCredentialAuth{
			PrincipalID:   oldID,
			PrincipalName: "alice",
			CredentialID:  cred.ID,
		},
	}
	return &stalePrincipalFixture{
		app:      app,
		stale:    stale,
		oldID:    oldID,
		newID:    newID,
		home:     home,
		extra:    extra,
		newToken: newToken,
	}
}

// TestStalePrincipalAuthorityNeverRebindsControlTarget proves the stable
// Principal-control target owner: a stale authority whose Principal was
// deleted fails closed as principal_not_found — never the recreated
// same-username Principal — through both the semantic owner and the HTTP
// mapping entry every nested-route mutation uses (Launcher
// create/patch/delete/scope/credential operations and Principal credential
// rotation). Admin authority over the same username legitimately resolves the
// current incarnation.
func TestStalePrincipalAuthorityNeverRebindsControlTarget(t *testing.T) {
	f := createStalePrincipalFixture(t)

	// The semantic owner fails closed for the stale authority: no target,
	// principal_not_found — never the replacement incarnation.
	target, err := resolvePrincipalControlTarget(f.app.DB, f.stale, "alice")
	if !isErrPrincipalNotFound(err) {
		t.Fatalf("stale control target error = %v, want ErrPrincipalNotFound", err)
	}
	if target != nil {
		t.Fatalf("stale control target resolved %+v, want nil", target)
	}

	// The HTTP mapping entry used by Launcher create/patch/delete/scope/
	// credential operations and Principal credential rotation: the same
	// non-disclosing 404, so no mutation can begin for a stale authority.
	req := httptest.NewRequest(http.MethodPost, "/principals/alice/launchers", nil)
	w := httptest.NewRecorder()
	if _, ok := f.app.resolveControlPrincipal(w, req, f.stale, "alice"); ok {
		t.Fatal("stale authority resolved a control Principal")
	}
	if w.Code != http.StatusNotFound {
		t.Fatalf("stale control principal status = %d, want 404, body: %s", w.Code, w.Body.String())
	}
	if code := decodeAPIError(t, w.Body.Bytes()).Code; code != "principal_not_found" {
		t.Fatalf("stale control principal error code = %q, want principal_not_found", code)
	}

	// Admin authority remains name-oriented at the selector boundary: the
	// current incarnation is the legitimate target.
	admin := &operatorAuthority{class: operatorAuthorityAdmin}
	current, err := resolvePrincipalControlTarget(f.app.DB, admin, "alice")
	if err != nil {
		t.Fatalf("admin control target: %v", err)
	}
	if current.ID != f.newID || current.Name != "alice" {
		t.Fatalf("admin control target = %+v, want the recreated incarnation ID %d", current, f.newID)
	}
}

// TestStalePrincipalAuthorityListScopeNotRebound proves the scope-first list
// rule resolves a Principal credential's visible scope by its exact
// authenticated Principal ID: a stale authority whose Principal was deleted
// answers the non-disclosing 404 for both the empty filter and its own name —
// it never observes the recreated same-username Principal's scope. Admin list
// semantics are unchanged.
func TestStalePrincipalAuthorityListScopeNotRebound(t *testing.T) {
	f := createStalePrincipalFixture(t)

	for _, filter := range []string{"", "alice"} {
		req := httptest.NewRequest(http.MethodGet, "/launchers", nil)
		w := httptest.NewRecorder()
		scope, ok := f.app.resolveListScope(w, req, f.stale, filter)
		if ok {
			t.Fatalf("stale authority (filter %q) authorized list scope %+v", filter, scope)
		}
		if scope.allPrincipals || scope.principal != nil {
			t.Errorf("stale authority (filter %q) resolved scope %+v, want empty", filter, scope)
		}
		if w.Code != http.StatusNotFound {
			t.Errorf("stale authority (filter %q) status = %d, want 404, body: %s", filter, w.Code, w.Body.String())
			continue
		}
		if code := decodeAPIError(t, w.Body.Bytes()).Code; code != "principal_not_found" {
			t.Errorf("stale authority (filter %q) error code = %q, want principal_not_found", filter, code)
		}
	}

	// Admin list semantics are unchanged: the filter resolves the current
	// incarnation.
	admin := &operatorAuthority{class: operatorAuthorityAdmin}
	req := httptest.NewRequest(http.MethodGet, "/launchers", nil)
	w := httptest.NewRecorder()
	scope, ok := f.app.resolveListScope(w, req, admin, "alice")
	if !ok {
		t.Fatalf("admin list scope with filter: %d %s", w.Code, w.Body.String())
	}
	if scope.allPrincipals || scope.principal == nil {
		t.Fatalf("admin list scope = %+v, want the filtered Principal", scope)
	}
	if scope.principal.ID != f.newID || scope.principal.Name != "alice" {
		t.Fatalf("admin list scope principal = %+v, want the recreated incarnation ID %d", scope.principal, f.newID)
	}
}

// TestStalePrincipalAuthorityEffectiveRootsNotRebound proves the effective
// roots introspection distinguishes authority semantics: a stale Principal
// credential authority fails closed as principal_not_found even though the
// same username was recreated (it never observes the replacement
// incarnation), while Admin authority over the same username answers 200 with
// the recreated incarnation's roots — not the deleted incarnation's stored
// root set.
func TestStalePrincipalAuthorityEffectiveRootsNotRebound(t *testing.T) {
	f := createStalePrincipalFixture(t)

	// Stale Principal credential authority: fail closed, never the
	// replacement incarnation.
	_, err := f.app.resolvePrincipalEffectiveRootsSnapshot(f.stale, "alice")
	if !isErrPrincipalNotFound(err) {
		t.Fatalf("stale effective-roots snapshot error = %v, want ErrPrincipalNotFound", err)
	}

	// Admin authority over the same username: the current incarnation's
	// roots. The recreated Principal carries only its seeded home root; the
	// deleted incarnation's extra root must not leak into the projection.
	w := launcherRequest(t, f.app, http.MethodGet, "/principals/alice/effective-allowed-roots", testAdminToken, "")
	if w.Code != http.StatusOK {
		t.Fatalf("admin introspection after recreation: %d %s", w.Code, w.Body.String())
	}
	resp := decodePolicyRoots(t, w.Body.String())
	if !resp.OK || resp.Principal != "alice" {
		t.Fatalf("admin introspection response = %+v", resp)
	}
	if len(resp.AllowedRoots) != 1 || resp.AllowedRoots[0] != f.home {
		t.Fatalf("admin introspection allowed_roots = %v, want the recreated incarnation's [%s]", resp.AllowedRoots, f.home)
	}
}

// TestStalePrincipalAuthorityCannotRotateReplacementCredential proves the
// credential rotation mutation is scoped by the stable Principal ID: the
// rotation addressed at the deleted incarnation's ID fails closed without
// mutating anything, and the recreated same-username Principal's credential —
// which carries the same credential name — keeps its bearer valid. The
// positive control proves ID-keyed rotation still rotates the exact owner it
// names.
func TestStalePrincipalAuthorityCannotRotateReplacementCredential(t *testing.T) {
	f := createStalePrincipalFixture(t)

	// The production rotation attempt under the stale authority fails closed
	// at its first step — the handler's target resolution — so the mutation
	// is never reached, and specifically never against the recreated
	// same-username Principal.
	req := httptest.NewRequest(http.MethodPost, "/principals/alice/credentials/default/rotate", nil)
	w := httptest.NewRecorder()
	if _, ok := f.app.resolveControlPrincipal(w, req, f.stale, "alice"); ok {
		t.Fatal("stale authority resolved a rotation target")
	}
	if w.Code != http.StatusNotFound {
		t.Fatalf("stale rotation target resolution status = %d, want 404, body: %s", w.Code, w.Body.String())
	}

	// The rotation addressed at the deleted incarnation's ID fails closed:
	// no active credential row exists at that principal_id, so neither
	// lookup nor history branch mutates any row — and specifically never the
	// replacement Principal's same-named credential.
	_, _, err := rotatePrincipalCredential(f.app.DB, f.oldID, "default")
	if !isErrCredentialNotFound(err) {
		t.Fatalf("stale rotation error = %v, want ErrCredentialNotFound", err)
	}

	// The replacement credential's bearer remains valid after the failed
	// stale-authority operation: its token hash was never replaced.
	result, err := authenticateCredential(f.app.DB, f.newToken)
	if err != nil {
		t.Fatalf("replacement bearer must remain valid: %v", err)
	}
	if result.Principal == nil || result.Principal.PrincipalID != f.newID || result.Principal.PrincipalName != "alice" {
		t.Fatalf("replacement bearer authenticated as %+v, want the recreated incarnation ID %d", result, f.newID)
	}

	// Positive control: the ID-keyed rotation rotates exactly the owner it
	// names — the recreated incarnation's credential.
	rotated, newToken, err := rotatePrincipalCredential(f.app.DB, f.newID, "default")
	if err != nil {
		t.Fatalf("rotation of the recreated incarnation: %v", err)
	}
	if rotated.PrincipalName != "alice" || rotated.Name != "default" {
		t.Fatalf("rotated credential = %+v, want alice/default", rotated)
	}
	if _, err := authenticateCredential(f.app.DB, f.newToken); err == nil {
		t.Fatal("pre-rotation replacement bearer must be invalid after the positive-control rotation")
	}
	if _, err := authenticateCredential(f.app.DB, newToken); err != nil {
		t.Fatalf("post-rotation bearer must authenticate: %v", err)
	}
}
