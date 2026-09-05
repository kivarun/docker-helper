package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Structural invariants of the common operator authority representation.
//
// The zero value of operatorAuthority is the invalid/uninitialized class:
// it is never a valid authority and must fail closed in every consumer. A
// valid authority names exactly one of the three operator classes and
// carries exactly its matching owner projection; a discriminator/payload
// disagreement is an internal authentication anomaly, never an authorized
// credential.

// TestOperatorAuthorityValidateMatrix proves structural coherence is exactly
// the three valid shapes: an authority fails validation when its class is
// zero/unknown or its discriminator and owner projections disagree, and the
// valid Admin, Principal, and Launcher shapes pass.
func TestOperatorAuthorityValidateMatrix(t *testing.T) {
	principal := &PrincipalCredentialAuth{PrincipalID: 7, PrincipalName: "matrixuser", CredentialID: "pcred"}
	launcher := &LauncherCredentialAuth{LauncherID: "l7", CredentialID: "lcred", PrincipalName: "matrixuser"}

	cases := []struct {
		name    string
		auth    *operatorAuthority
		wantErr bool
	}{
		{name: "valid admin", auth: &operatorAuthority{class: operatorAuthorityAdmin}},
		{name: "valid principal", auth: &operatorAuthority{class: operatorAuthorityPrincipal, principal: principal}},
		{name: "valid launcher", auth: &operatorAuthority{class: operatorAuthorityLauncher, launcher: launcher}},
		{name: "zero value", auth: &operatorAuthority{}, wantErr: true},
		{name: "invalid class constant", auth: &operatorAuthority{class: operatorAuthorityInvalid}, wantErr: true},
		{name: "admin with principal payload", auth: &operatorAuthority{class: operatorAuthorityAdmin, principal: principal}, wantErr: true},
		{name: "admin with launcher payload", auth: &operatorAuthority{class: operatorAuthorityAdmin, launcher: launcher}, wantErr: true},
		{name: "principal with nil principal", auth: &operatorAuthority{class: operatorAuthorityPrincipal}, wantErr: true},
		{name: "principal with launcher payload", auth: &operatorAuthority{class: operatorAuthorityPrincipal, principal: principal, launcher: launcher}, wantErr: true},
		{name: "launcher with nil launcher", auth: &operatorAuthority{class: operatorAuthorityLauncher}, wantErr: true},
		{name: "launcher with principal payload", auth: &operatorAuthority{class: operatorAuthorityLauncher, launcher: launcher, principal: principal}, wantErr: true},
		{name: "unknown class integer", auth: &operatorAuthority{class: operatorAuthorityClass(99)}, wantErr: true},
		{name: "negative class integer", auth: &operatorAuthority{class: operatorAuthorityClass(-1)}, wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.auth.validate()
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Fatalf("validate() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// TestOperatorAuthorityZeroValueFailsClosed is the fail-open regression: the
// zero value of operatorAuthority (class == operatorAuthorityInvalid) must
// authorize nothing. It must not resolve to an admin Session-control scope
// and must not become an all-Principals list visibility; both scope resolvers
// fail closed instead. Against the pre-fix representation (admin as class
// zero) the zero value resolved as admin:true and all-Principals visibility.
func TestOperatorAuthorityZeroValueFailsClosed(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	var auth operatorAuthority
	if err := (&auth).validate(); err == nil {
		t.Fatal("zero-value operatorAuthority validated as a valid authority")
	}

	scope, err := app.resolveSessionControlScope(&auth)
	if err == nil {
		t.Fatalf("zero-value authority resolved a session control scope %+v", scope)
	}
	if scope.admin {
		t.Error("zero-value authority resolved admin session-control scope")
	}
	if scope.principalID != 0 || scope.launcherID != "" {
		t.Errorf("zero-value authority resolved owner scope %+v", scope)
	}

	req := httptest.NewRequest(http.MethodGet, "/launchers", nil)
	w := httptest.NewRecorder()
	listScope, ok := app.resolveListScope(w, req, &auth, "")
	if ok {
		t.Errorf("zero-value authority authorized list scope %+v", listScope)
	}
	if listScope.allPrincipals {
		t.Error("zero-value authority became all-Principals visibility")
	}
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d, body: %s", w.Code, http.StatusInternalServerError, w.Body.String())
	}
}

// TestOperatorAuthorityInvalidClassFailsClosedScopes proves through the
// narrowest practical seam (the scope resolvers, called directly with a
// hand-constructed authority) that a class-invalid authority can never become
// an HTTP 200, an admin scope, or an all-Principals scope: every
// scope-producing consumer rejects it. A Principal-owned resolver
// (resolveControlPrincipal) must also refuse to act as admin authority.
func TestOperatorAuthorityInvalidClassFailsClosedScopes(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	cases := []struct {
		name string
		auth *operatorAuthority
	}{
		{name: "zero value", auth: &operatorAuthority{}},
		{name: "unknown class integer", auth: &operatorAuthority{class: operatorAuthorityClass(42)}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scope, err := app.resolveSessionControlScope(tc.auth)
			if err == nil {
				t.Fatalf("invalid authority resolved session control scope %+v", scope)
			}
			if scope.admin || scope.principalID != 0 || scope.launcherID != "" {
				t.Errorf("invalid authority resolved privileged scope %+v", scope)
			}

			req := httptest.NewRequest(http.MethodGet, "/launchers", nil)
			w := httptest.NewRecorder()
			listScope, ok := app.resolveListScope(w, req, tc.auth, "")
			if ok || listScope.allPrincipals || listScope.principal != nil {
				t.Errorf("invalid authority authorized list scope %+v", listScope)
			}
			if w.Code != http.StatusInternalServerError {
				t.Errorf("list scope status = %d, want %d, body: %s", w.Code, http.StatusInternalServerError, w.Body.String())
			}

			req = httptest.NewRequest(http.MethodGet, "/principals/matrixuser/launchers/l1", nil)
			w = httptest.NewRecorder()
			if _, ok := app.resolveControlPrincipal(w, req, tc.auth, "matrixuser"); ok {
				t.Error("invalid authority resolved a control Principal")
			}
			if w.Code != http.StatusInternalServerError {
				t.Errorf("control principal status = %d, want %d, body: %s", w.Code, http.StatusInternalServerError, w.Body.String())
			}
		})
	}
}
