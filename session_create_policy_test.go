package main

import (
	"errors"
	"testing"
)

// TestCreateSessionGoesThroughResolveCreatePolicy proves createSession is a
// thin wrapper over the single authoritative resolveCreatePolicy path (admin
// authority + omitted selectors). Disabling the launcher-owner 'default'
// Launcher must surface the policy owner's ErrLauncherUnavailable before any
// insert — not a late insert-time error from a manual parallel policy
// construction.
func TestCreateSessionGoesThroughResolveCreatePolicy(t *testing.T) {
	app := newTestApp(t)
	ws := testWorkspaceDir(t, app.Config.AllowedRoots[0].Path)

	if _, err := app.DB.Exec(`UPDATE launchers SET enabled = 0 WHERE id = ?`, testOwnerLauncherID(app)); err != nil {
		t.Fatal(err)
	}

	_, err := createDefaultAdminSessionForTest(app, ws)
	if !errors.Is(err, ErrLauncherUnavailable) {
		t.Fatalf("expected ErrLauncherUnavailable from resolveCreatePolicy, got %v", err)
	}
}

// TestCreateSessionResolvesLauncherOwnerDefault proves the thin wrapper resolves
// the provisioned launcher-owner 'default' Launcher without explicit selectors,
// producing the launcher-owner identity.
func TestCreateSessionResolvesLauncherOwnerDefault(t *testing.T) {
	app := newTestApp(t)
	ws := testWorkspaceDir(t, app.Config.AllowedRoots[0].Path)

	result, err := createDefaultAdminSessionForTest(app, ws)
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}
	if result.Session.LauncherID != testOwnerLauncherID(app) {
		t.Errorf("LauncherID = %q, want launcher-owner default %q", result.Session.LauncherID, testOwnerLauncherID(app))
	}
	if result.Session.PrincipalName != testOwnerUsername {
		t.Errorf("PrincipalName = %q, want %q", result.Session.PrincipalName, testOwnerUsername)
	}
}
