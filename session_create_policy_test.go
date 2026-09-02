package main

import (
	"errors"
	"testing"
)

// TestCreateSessionGoesThroughResolveCreatePolicy proves createSession is a
// thin wrapper over the single authoritative resolveCreatePolicy path (admin
// authority + omitted selectors). Disabling the daemon-owner default Launcher
// must surface the policy owner's ErrLauncherUnavailable before any insert —
// not a late insert-time error from a manual parallel policy construction.
func TestCreateSessionGoesThroughResolveCreatePolicy(t *testing.T) {
	app := newTestApp(t)
	ws := testWorkspaceDir(t, app.Config.AllowedRoots[0])

	if _, err := app.DB.Exec(`UPDATE launchers SET enabled = 0 WHERE id = ?`, app.userModeDefault.launcherID); err != nil {
		t.Fatal(err)
	}

	_, err := app.createSession(ws)
	if !errors.Is(err, ErrLauncherUnavailable) {
		t.Fatalf("expected ErrLauncherUnavailable from resolveCreatePolicy, got %v", err)
	}
}

// TestCreateSessionResolvesDaemonOwnerDefault proves the thin wrapper resolves
// the provisioned daemon-owner 'default' Launcher without explicit selectors
// (the user-mode collapsed policy owner), producing the daemon-owner identity.
func TestCreateSessionResolvesDaemonOwnerDefault(t *testing.T) {
	app := newTestApp(t)
	ws := testWorkspaceDir(t, app.Config.AllowedRoots[0])

	result, err := app.createSession(ws)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}
	if result.Session.LauncherID != app.userModeDefault.launcherID {
		t.Errorf("LauncherID = %q, want daemon-owner default %q", result.Session.LauncherID, app.userModeDefault.launcherID)
	}
	if result.Session.PrincipalName != app.userModeDefault.username {
		t.Errorf("PrincipalName = %q, want %q", result.Session.PrincipalName, app.userModeDefault.username)
	}
}
