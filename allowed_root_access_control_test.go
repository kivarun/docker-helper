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

// mustPrincipalID64 resolves a test Principal's internal ID.
func mustPrincipalID64(t *testing.T, app *App, username string) int64 {
	t.Helper()
	id, err := findPrincipalIDByUsername(app.DB, username)
	if err != nil {
		t.Fatalf("principal %q: %v", username, err)
	}
	return int64(id)
}

// mustStoredPrincipalEntries reads the stored Principal entries.
func mustStoredPrincipalEntries(t *testing.T, app *App, username string) []AllowedRootEntry {
	t.Helper()
	entries, err := readPrincipalAllowedRoots(app.DB, mustPrincipalID64(t, app, username))
	if err != nil {
		t.Fatalf("read principal roots: %v", err)
	}
	return entries
}

// mustStoredPrincipalEntry reads the stored entry for one canonical path.
func mustStoredPrincipalEntry(t *testing.T, app *App, username, path string) AllowedRootEntry {
	t.Helper()
	for _, e := range mustStoredPrincipalEntries(t, app, username) {
		if e.Path == path {
			return e
		}
	}
	t.Fatalf("no stored principal root %q among %v", path, mustStoredPrincipalEntries(t, app, username))
	return AllowedRootEntry{}
}

// mustStoredLauncherEntries reads the stored Launcher entries.
func mustStoredLauncherEntries(t *testing.T, app *App, launcherID string) []AllowedRootEntry {
	t.Helper()
	entries, err := readLauncherAllowedRoots(app.DB, launcherID)
	if err != nil {
		t.Fatalf("read launcher roots: %v", err)
	}
	return entries
}

// setupPrincipalWithRoots creates a Principal (with a credential) under the
// app's global allowed root, returning the home directory.
func setupPrincipalWithRoots(t *testing.T, app *App, username string) string {
	t.Helper()
	home := filepath.Join(app.Config.AllowedRoots[0].Path, "home", username)
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatalf("create home %s: %v", home, err)
	}
	installOSUserMock(t, map[string]string{username: home})
	if _, err := createPrincipal(app.DB, username, app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal(%s): %v", username, err)
	}
	return home
}

// mustSeedPrincipalRoot adds one stored root through the domain owner.
func mustSeedPrincipalRoot(t *testing.T, app *App, username, path string, access AllowedRootAccess) AllowedRootEntry {
	t.Helper()
	_, entry, err := addPrincipalAllowedRoot(app.DB, username, path, access, allowedRootPaths(app.Config.AllowedRoots))
	if err != nil {
		t.Fatalf("seed principal root %q: %v", path, err)
	}
	return entry
}

// =============================================================================
// Presence-aware access on the allowed-root add mutations
// =============================================================================

// TestPrincipalHTTPAddAccessPresence proves the presence contract of the
// optional access field: an omitted field is the canonical read_write grant
// (the 2.1 path-only semantics), an explicitly supplied value must parse, and
// an explicitly empty or unknown spelling is never reinterpreted as omission.
func TestPrincipalHTTPAddAccessPresence(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	username := "addaccessuser"
	home := setupPrincipalWithRoots(t, app, username)

	inner := filepath.Join(home, "inner")
	if err := os.MkdirAll(inner, 0755); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name        string
		body        string
		wantCode    int
		wantAccess  AllowedRootAccess
		wantChanged bool
		wantErrCode string
	}{
		{name: "omitted access is the read_write grant", body: `{"path":"` + inner + `"}`, wantCode: http.StatusOK, wantAccess: AllowedRootAccessReadWrite, wantChanged: true},
		{name: "explicit read_only is persisted", body: `{"path":"` + inner + `","access":"read_only"}`, wantCode: http.StatusOK, wantAccess: AllowedRootAccessReadOnly, wantChanged: true},
		{name: "explicit empty access is a refusal", body: `{"path":"` + inner + `","access":""}`, wantCode: http.StatusBadRequest, wantErrCode: "invalid_allowed_root_access"},
		{name: "null access is a refusal, never a read_write default", body: `{"path":"` + inner + `","access":null}`, wantCode: http.StatusBadRequest, wantErrCode: "invalid_allowed_root_access"},
		{name: "unknown access spelling is a refusal", body: `{"path":"` + inner + `","access":"ro"}`, wantCode: http.StatusBadRequest, wantErrCode: "invalid_allowed_root_access"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Reset the stored root between cases so each case exercises a
			// fresh add on the same path.
			removePrincipalAllowedRoot(app.DB, username, inner)

			w := launcherRequest(t, app, http.MethodPost, "/principals/"+username+"/allowed-roots", testAdminToken, tc.body)
			if w.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d, body=%s", w.Code, tc.wantCode, w.Body.String())
			}
			if tc.wantErrCode != "" {
				var errResp struct {
					Code string `json:"code"`
				}
				if err := json.Unmarshal(w.Body.Bytes(), &errResp); err != nil {
					t.Fatalf("decode error response: %v", err)
				}
				if errResp.Code != tc.wantErrCode {
					t.Errorf("error code = %q, want %q", errResp.Code, tc.wantErrCode)
				}
				for _, e := range mustStoredPrincipalEntries(t, app, username) {
					if e.Path == inner {
						t.Errorf("refused add must not mutate, stored = %v", mustStoredPrincipalEntries(t, app, username))
					}
				}
				return
			}

			var resp principalChangedResponse
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode response: %v (body=%s)", err, w.Body.String())
			}
			if resp.Changed != tc.wantChanged {
				t.Errorf("changed = %v, want %v", resp.Changed, tc.wantChanged)
			}
			if resp.Path != inner {
				t.Errorf("path = %q, want %q", resp.Path, inner)
			}
			if resp.Access != string(tc.wantAccess) {
				t.Errorf("access = %q, want %q", resp.Access, tc.wantAccess)
			}
			if got := mustStoredPrincipalEntry(t, app, username, inner); got != (AllowedRootEntry{Path: inner, Access: tc.wantAccess}) {
				t.Errorf("stored entry = %+v, want [{%s %s}]", got, inner, tc.wantAccess)
			}
		})
	}
}

// TestPrincipalHTTPAddNeverChangesStoredAccess proves the idempotent-create
// contract: re-adding an already-stored root with a different requested access
// leaves the stored access untouched and reports the divergence.
func TestPrincipalHTTPAddNeverChangesStoredAccess(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	username := "addnarrowuser"
	home := setupPrincipalWithRoots(t, app, username)

	inner := filepath.Join(home, "inner")
	if err := os.MkdirAll(inner, 0755); err != nil {
		t.Fatal(err)
	}

	w := launcherRequest(t, app, http.MethodPost, "/principals/"+username+"/allowed-roots", testAdminToken,
		`{"path":"`+inner+`","access":"read_only"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("first add: status = %d, body=%s", w.Code, w.Body.String())
	}

	// Re-adding with the wider read_write grant must not change the stored
	// read_only entry: only set-access changes access.
	w = launcherRequest(t, app, http.MethodPost, "/principals/"+username+"/allowed-roots", testAdminToken,
		`{"path":"`+inner+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("re-add: status = %d, body=%s", w.Code, w.Body.String())
	}
	var resp principalChangedResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Changed {
		t.Error("re-add reported changed")
	}
	if resp.Message != "unchanged" {
		t.Errorf("message = %q, want unchanged", resp.Message)
	}
	if resp.Access != string(AllowedRootAccessReadOnly) {
		t.Errorf("stored access = %q, want read_only (requested read_write must not win)", resp.Access)
	}
	if got := mustStoredPrincipalEntry(t, app, username, inner); got.Access != AllowedRootAccessReadOnly {
		t.Errorf("stored entry after re-add = %+v, want the read_only entry", got)
	}
}

// =============================================================================
// Targeted set-access mutations (Principal)
// =============================================================================

func TestPrincipalHTTPSetAccess(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	username := "setaccessuser"
	home := setupPrincipalWithRoots(t, app, username)

	inner := filepath.Join(home, "inner")
	if err := os.MkdirAll(inner, 0755); err != nil {
		t.Fatal(err)
	}
	mustSeedPrincipalRoot(t, app, username, inner, AllowedRootAccessReadWrite)

	t.Run("narrow read_write to read_only", func(t *testing.T) {
		w := launcherRequest(t, app, http.MethodPatch, "/principals/"+username+"/allowed-roots", testAdminToken,
			`{"path":"`+inner+`","access":"read_only"}`)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
		}
		var resp principalChangedResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if !resp.Changed || resp.Path != inner || resp.Access != "read_only" {
			t.Errorf("response = %+v, want changed=true path=%s access=read_only", resp, inner)
		}
		if got := mustStoredPrincipalEntry(t, app, username, inner); got.Access != AllowedRootAccessReadOnly {
			t.Errorf("stored entry = %+v, want read_only", got)
		}
	})

	t.Run("widen back is the same targeted mutation", func(t *testing.T) {
		w := launcherRequest(t, app, http.MethodPatch, "/principals/"+username+"/allowed-roots", testAdminToken,
			`{"path":"`+inner+`","access":"read_write"}`)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
		}
		if got := mustStoredPrincipalEntry(t, app, username, inner); got.Access != AllowedRootAccessReadWrite {
			t.Errorf("stored entry = %+v, want read_write", got)
		}
	})

	t.Run("same access is the idempotent unchanged no-op", func(t *testing.T) {
		w := launcherRequest(t, app, http.MethodPatch, "/principals/"+username+"/allowed-roots", testAdminToken,
			`{"path":"`+inner+`","access":"read_write"}`)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
		}
		var resp principalChangedResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if resp.Changed || resp.Message != "unchanged" || resp.Access != "read_write" {
			t.Errorf("response = %+v, want unchanged with access read_write", resp)
		}
	})

	t.Run("missing stored root is refused", func(t *testing.T) {
		missing := filepath.Join(home, "not-stored")
		if err := os.MkdirAll(missing, 0755); err != nil {
			t.Fatal(err)
		}
		w := launcherRequest(t, app, http.MethodPatch, "/principals/"+username+"/allowed-roots", testAdminToken,
			`{"path":"`+missing+`","access":"read_only"}`)
		if w.Code != http.StatusNotFound {
			t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "allowed_root_not_found") {
			t.Errorf("body = %s, want allowed_root_not_found", w.Body.String())
		}
	})

	t.Run("symlink alias names the same stored entry", func(t *testing.T) {
		alias := filepath.Join(home, "alias")
		if err := os.Symlink(inner, alias); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Remove(alias) })
		w := launcherRequest(t, app, http.MethodPatch, "/principals/"+username+"/allowed-roots", testAdminToken,
			`{"path":"`+alias+`","access":"read_only"}`)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
		}
		count := 0
		for _, e := range mustStoredPrincipalEntries(t, app, username) {
			if e.Path == inner {
				count++
				if e.Access != AllowedRootAccessReadOnly {
					t.Errorf("stored entry = %+v, want the read_only entry", e)
				}
			}
		}
		if count != 1 {
			t.Errorf("symlink alias created %d entries for %q, want exactly one", count, inner)
		}
	})

	t.Run("request refusals never mutate", func(t *testing.T) {
		before := mustStoredPrincipalEntry(t, app, username, inner)
		tests := []struct {
			name    string
			body    string
			wantErr string
		}{
			{name: "missing path", body: `{"access":"read_only"}`, wantErr: "missing_path"},
			{name: "missing access", body: `{"path":"` + inner + `"}`, wantErr: "missing_access"},
			{name: "empty access", body: `{"path":"` + inner + `","access":""}`, wantErr: "missing_access"},
			{name: "unknown access", body: `{"path":"` + inner + `","access":"ro"}`, wantErr: "invalid_allowed_root_access"},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				w := launcherRequest(t, app, http.MethodPatch, "/principals/"+username+"/allowed-roots", testAdminToken, tc.body)
				if w.Code != http.StatusBadRequest {
					t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
				}
				if !strings.Contains(w.Body.String(), tc.wantErr) {
					t.Errorf("body = %s, want code %q", w.Body.String(), tc.wantErr)
				}
				if got := mustStoredPrincipalEntry(t, app, username, inner); got != before {
					t.Errorf("refused set-access must not mutate, stored = %+v, want %+v", got, before)
				}
			})
		}
	})

	t.Run("principal credential has no mutation authority", func(t *testing.T) {
		_, credToken, err := createPrincipalCredential(app.DB, username, "oc")
		if err != nil {
			t.Fatalf("createPrincipalCredential: %v", err)
		}
		w := launcherRequest(t, app, http.MethodPatch, "/principals/"+username+"/allowed-roots", credToken,
			`{"path":"`+inner+`","access":"read_only"}`)
		if w.Code == http.StatusOK {
			t.Fatalf("principal credential must not mutate principal roots, got %d body=%s", w.Code, w.Body.String())
		}
		if w.Code != http.StatusUnauthorized && w.Code != http.StatusForbidden {
			t.Errorf("status = %d, want 401/403", w.Code)
		}
	})

	t.Run("reserved daemon-owner principal is refused", func(t *testing.T) {
		owner := app.userModeDefault.username
		w := launcherRequest(t, app, http.MethodPatch, "/principals/"+owner+"/allowed-roots", testAdminToken,
			`{"path":"`+inner+`","access":"read_only"}`)
		if w.Code != http.StatusConflict {
			t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "user_mode_owner_reserved") {
			t.Errorf("body = %s, want user_mode_owner_reserved", w.Body.String())
		}
	})
}

// =============================================================================
// Targeted set-access mutations (Launcher)
// =============================================================================

// setupLauncherWithStoredRoot creates a Principal and seeds one restricted
// root on its default Launcher, returning the home, the root, and the
// launcher JSON.
func setupLauncherWithStoredRoot(t *testing.T, app *App, username string) (string, string, launcherJSON) {
	t.Helper()
	home := setupPrincipalWithRoots(t, app, username)
	root := filepath.Join(home, "proj")
	if err := os.MkdirAll(root, 0755); err != nil {
		t.Fatal(err)
	}
	w := launcherRequest(t, app, http.MethodPost, "/principals/"+username+"/launchers/default/allowed-roots", testAdminToken,
		`{"path":"`+root+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("seed launcher root: status = %d, body=%s", w.Code, w.Body.String())
	}
	l := decodeLauncher(t, launcherRequest(t, app, http.MethodGet, "/principals/"+username+"/launchers/default", testAdminToken, ""))
	return home, root, l
}

func TestLauncherHTTPSetAccess(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	username := "lsetaccessuser"
	home, root, l := setupLauncherWithStoredRoot(t, app, username)
	launcherPath := "/principals/" + username + "/launchers/default/allowed-roots"

	t.Run("narrow the stored root", func(t *testing.T) {
		w := launcherRequest(t, app, http.MethodPatch, launcherPath, testAdminToken,
			`{"path":"`+root+`","access":"read_only"}`)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
		}
		var resp launcherAllowedRootResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if !resp.Changed || resp.Path != root || resp.Access != "read_only" || resp.LauncherID != l.ID {
			t.Errorf("response = %+v, want changed path=%s access=read_only launcher=%s", resp, root, l.ID)
		}
		if got := readLauncherScopeMode2(t, app, l.ID); got != LauncherScopeRestricted {
			t.Errorf("set-access changed the scope to %q, want unchanged restricted", got)
		}
		entries := mustStoredLauncherEntries(t, app, l.ID)
		if len(entries) != 1 || entries[0].Access != AllowedRootAccessReadOnly {
			t.Errorf("stored entry = %+v, want read_only", entries)
		}
	})

	t.Run("same access is the idempotent unchanged no-op", func(t *testing.T) {
		w := launcherRequest(t, app, http.MethodPatch, launcherPath, testAdminToken,
			`{"path":"`+root+`","access":"read_only"}`)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
		}
		var resp launcherAllowedRootResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if resp.Changed || resp.Message != "unchanged" || resp.Access != "read_only" {
			t.Errorf("response = %+v, want unchanged", resp)
		}
	})

	t.Run("request refusals", func(t *testing.T) {
		tests := []struct {
			name    string
			body    string
			wantErr string
		}{
			{name: "missing path", body: `{"access":"read_only"}`, wantErr: "missing_path"},
			{name: "missing access", body: `{"path":"` + root + `"}`, wantErr: "missing_access"},
			{name: "unknown access", body: `{"path":"` + root + `","access":"ro"}`, wantErr: "invalid_allowed_root_access"},
			{name: "missing stored root", body: `{"path":"` + filepath.Join(home, "nope") + `","access":"read_only"}`, wantErr: "allowed_root_not_found"},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				w := launcherRequest(t, app, http.MethodPatch, launcherPath, testAdminToken, tc.body)
				wantCode := http.StatusBadRequest
				if tc.wantErr == "allowed_root_not_found" {
					wantCode = http.StatusNotFound
				}
				if w.Code != wantCode {
					t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
				}
				if !strings.Contains(w.Body.String(), tc.wantErr) {
					t.Errorf("body = %s, want %q", w.Body.String(), tc.wantErr)
				}
			})
		}
	})

	t.Run("reserved default launcher of the daemon owner is refused", func(t *testing.T) {
		owner := app.userModeDefault.username
		w := launcherRequest(t, app, http.MethodPatch,
			"/principals/"+owner+"/launchers/default/allowed-roots", testAdminToken,
			`{"path":"`+root+`","access":"read_only"}`)
		if w.Code != http.StatusConflict {
			t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "user_mode_owner_reserved") {
			t.Errorf("body = %s, want user_mode_owner_reserved", w.Body.String())
		}
	})

	_ = home
}

// readLauncherScopeMode2 reads a Launcher's stored scope mode through the
// app database (named distinctly from the domain test helper of the same
// concern to keep this file self-contained).
func readLauncherScopeMode2(t *testing.T, app *App, launcherID string) LauncherScopeMode {
	t.Helper()
	return readLauncherScopeMode(t, app.DB, launcherID)
}

// TestLauncherHTTPAddAccessPresence mirrors the Principal presence contract
// on the Launcher add.
func TestLauncherHTTPAddAccessPresence(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	username := "laddaccessuser"
	home := setupPrincipalWithRoots(t, app, username)
	launcherPath := "/principals/" + username + "/launchers/default/allowed-roots"

	inner := filepath.Join(home, "inner")
	if err := os.MkdirAll(inner, 0755); err != nil {
		t.Fatal(err)
	}

	t.Run("omitted access is the read_write grant", func(t *testing.T) {
		w := launcherRequest(t, app, http.MethodPost, launcherPath, testAdminToken, `{"path":"`+inner+`"}`)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
		}
		var resp launcherAllowedRootResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if !resp.Changed || resp.Access != "read_write" || resp.Path != inner {
			t.Errorf("response = %+v, want changed read_write %s", resp, inner)
		}
		l := decodeLauncher(t, launcherRequest(t, app, http.MethodGet, "/principals/"+username+"/launchers/default", testAdminToken, ""))
		if l.Scope != "restricted" {
			t.Errorf("first add must narrow to restricted, got %q", l.Scope)
		}
	})

	// Reset to inherit and repeat with an explicit access.
	launcherRequest(t, app, http.MethodPut, "/principals/"+username+"/launchers/default/allowed-roots", testAdminToken, `{"scope":"inherit"}`)

	t.Run("explicit read_only is persisted", func(t *testing.T) {
		w := launcherRequest(t, app, http.MethodPost, launcherPath, testAdminToken, `{"path":"`+inner+`","access":"read_only"}`)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
		}
		l := decodeLauncher(t, launcherRequest(t, app, http.MethodGet, "/principals/"+username+"/launchers/default", testAdminToken, ""))
		if len(l.AllowedRootEntries) != 1 || l.AllowedRootEntries[0].Access != AllowedRootAccessReadOnly {
			t.Errorf("stored entries = %+v, want read_only", l.AllowedRootEntries)
		}
	})

	t.Run("explicit empty access is a refusal", func(t *testing.T) {
		w := launcherRequest(t, app, http.MethodPost, launcherPath, testAdminToken, `{"path":"`+inner+`","access":""}`)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "invalid_allowed_root_access") {
			t.Errorf("body = %s, want invalid_allowed_root_access", w.Body.String())
		}
	})

	t.Run("null access is a refusal, never a read_write default", func(t *testing.T) {
		// Reset to inherit so the refused add has nothing to be idempotent
		// against: the only observable fail-open outcome would be a stored
		// entry created by the refused request.
		launcherRequest(t, app, http.MethodPut, "/principals/"+username+"/launchers/default/allowed-roots", testAdminToken, `{"scope":"inherit"}`)
		w := launcherRequest(t, app, http.MethodPost, launcherPath, testAdminToken, `{"path":"`+inner+`","access":null}`)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "invalid_allowed_root_access") {
			t.Errorf("body = %s, want invalid_allowed_root_access", w.Body.String())
		}
		l := decodeLauncher(t, launcherRequest(t, app, http.MethodGet, "/principals/"+username+"/launchers/default", testAdminToken, ""))
		if len(l.AllowedRootEntries) != 0 {
			t.Errorf("refused add must not mutate, stored = %+v", l.AllowedRootEntries)
		}
	})
}

// =============================================================================
// Rich Launcher scope replacement
// =============================================================================

func TestLauncherHTTPReplaceRichEntries(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	username := "lreplaceuser"
	home := setupPrincipalWithRoots(t, app, username)
	launcherPath := "/principals/" + username + "/launchers/default/allowed-roots"

	a := filepath.Join(home, "a")
	b := filepath.Join(home, "b")
	for _, d := range []string{a, b} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("rich form persists mixed access and projects both forms", func(t *testing.T) {
		body := fmt.Sprintf(`{"scope":"restricted","allowed_root_entries":[{"path":%q,"access":"read_write"},{"path":%q,"access":"read_only"}]}`, a, b)
		w := launcherRequest(t, app, http.MethodPut, launcherPath, testAdminToken, body)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
		}
		l := decodeLauncher(t, w)
		if l.Scope != "restricted" {
			t.Fatalf("scope = %q, want restricted", l.Scope)
		}
		if len(l.AllowedRoots) != 2 || len(l.AllowedRootEntries) != 2 {
			t.Fatalf("projections = %v / %v, want two entries each", l.AllowedRoots, l.AllowedRootEntries)
		}
		for i := range l.AllowedRootEntries {
			if l.AllowedRoots[i] != l.AllowedRootEntries[i].Path {
				t.Errorf("projection divergence at %d: %q vs %+v", i, l.AllowedRoots[i], l.AllowedRootEntries[i])
			}
		}
		if l.AllowedRootEntries[0].Access != AllowedRootAccessReadWrite || l.AllowedRootEntries[1].Access != AllowedRootAccessReadOnly {
			t.Errorf("entries = %+v, want lexical order with read_write then read_only", l.AllowedRootEntries)
		}
	})

	t.Run("legacy form is the read_write grant and is compatible with the rich projection", func(t *testing.T) {
		w := launcherRequest(t, app, http.MethodPut, launcherPath, testAdminToken, `{"scope":"restricted","allowed_roots":[`+quoteJSON(t, a)+`]}`)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
		}
		l := decodeLauncher(t, w)
		if len(l.AllowedRootEntries) != 1 || l.AllowedRootEntries[0].Access != AllowedRootAccessReadWrite {
			t.Errorf("entries = %+v, want the read_write grant", l.AllowedRootEntries)
		}
	})

	t.Run("dual-form supply is refused even when one form is empty", func(t *testing.T) {
		w := launcherRequest(t, app, http.MethodPut, launcherPath, testAdminToken,
			`{"scope":"restricted","allowed_roots":[`+quoteJSON(t, a)+`],"allowed_root_entries":[]}`)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "invalid_allowed_roots") {
			t.Errorf("body = %s, want invalid_allowed_roots", w.Body.String())
		}
	})

	t.Run("inherit carries no rich form", func(t *testing.T) {
		w := launcherRequest(t, app, http.MethodPut, launcherPath, testAdminToken,
			`{"scope":"inherit","allowed_root_entries":[]}`)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "invalid_allowed_roots") {
			t.Errorf("body = %s, want invalid_allowed_roots", w.Body.String())
		}
	})

	t.Run("restricted with an empty supplied rich form is refused", func(t *testing.T) {
		w := launcherRequest(t, app, http.MethodPut, launcherPath, testAdminToken,
			`{"scope":"restricted","allowed_root_entries":[]}`)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "restricted scope requires at least one allowed root") {
			t.Errorf("body = %s", w.Body.String())
		}
	})

	t.Run("legacy explicit empty array with inherit stays valid (2.1 contract)", func(t *testing.T) {
		w := launcherRequest(t, app, http.MethodPut, launcherPath, testAdminToken, `{"scope":"inherit","allowed_roots":[]}`)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
		}
		if got := readLauncherScopeMode2(t, app, decodeLauncher(t, w).ID); got != LauncherScopeInherit {
			t.Errorf("scope = %q, want inherit", got)
		}
	})

	t.Run("legacy explicit empty array with restricted is refused", func(t *testing.T) {
		w := launcherRequest(t, app, http.MethodPut, launcherPath, testAdminToken, `{"scope":"restricted","allowed_roots":[]}`)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
		}
	})

	t.Run("rich form rejects bare path strings", func(t *testing.T) {
		w := launcherRequest(t, app, http.MethodPut, launcherPath, testAdminToken,
			`{"scope":"restricted","allowed_root_entries":[`+quoteJSON(t, a)+`]}`)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "invalid_json") {
			t.Errorf("body = %s, want invalid_json (strict object form)", w.Body.String())
		}
	})

	t.Run("rich form rejects an unknown access", func(t *testing.T) {
		w := launcherRequest(t, app, http.MethodPut, launcherPath, testAdminToken,
			`{"scope":"restricted","allowed_root_entries":[{"path":`+quoteJSON(t, a)+`,"access":"ro"}]}`)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "invalid_allowed_root_access") {
			t.Errorf("body = %s, want invalid_allowed_root_access", w.Body.String())
		}
	})

	t.Run("create rejects the rich field as an unknown field", func(t *testing.T) {
		body := `{"scope":"restricted","allowed_root_entries":[{"path":` + quoteJSON(t, a) + `,"access":"read_only"}]}`
		w := launcherRequest(t, app, http.MethodPost, "/principals/"+username+"/launchers", testAdminToken, body)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "invalid_json") {
			t.Errorf("body = %s, want invalid_json", w.Body.String())
		}
	})
}

// TestLauncherHTTPReplaceNullPresenceForms proves the frozen dual-form rule:
// any occurrence of allowed_roots or allowed_root_entries — an empty array,
// JSON null, or a non-empty array — is the supplied form, so presence and
// semantic emptiness are never conflated. The legacy field's JSON null keeps
// its 2.1 value semantics when it is the only supplied form, while the rich
// field's JSON null has no compatibility reason and is refused as an invalid
// rich form.
func TestLauncherHTTPReplaceNullPresenceForms(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	username := "lnullreplaceuser"
	home := setupPrincipalWithRoots(t, app, username)
	launcherPath := "/principals/" + username + "/launchers/default/allowed-roots"

	a := filepath.Join(home, "a")
	if err := os.MkdirAll(a, 0755); err != nil {
		t.Fatal(err)
	}

	t.Run("null allowed_roots alone stays the valid legacy inherit input", func(t *testing.T) {
		w := launcherRequest(t, app, http.MethodPut, launcherPath, testAdminToken, `{"scope":"inherit","allowed_roots":null}`)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
		}
		if got := readLauncherScopeMode2(t, app, decodeLauncher(t, w).ID); got != LauncherScopeInherit {
			t.Errorf("scope = %q, want inherit", got)
		}
	})

	t.Run("null allowed_roots alone with restricted is refused", func(t *testing.T) {
		w := launcherRequest(t, app, http.MethodPut, launcherPath, testAdminToken, `{"scope":"restricted","allowed_roots":null}`)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "invalid_allowed_roots") {
			t.Errorf("body = %s, want invalid_allowed_roots", w.Body.String())
		}
	})

	t.Run("null allowed_root_entries with inherit is an invalid rich form", func(t *testing.T) {
		w := launcherRequest(t, app, http.MethodPut, launcherPath, testAdminToken, `{"scope":"inherit","allowed_root_entries":null}`)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "invalid_allowed_roots") {
			t.Errorf("body = %s, want invalid_allowed_roots", w.Body.String())
		}
	})

	t.Run("null allowed_root_entries with restricted is an invalid rich form", func(t *testing.T) {
		w := launcherRequest(t, app, http.MethodPut, launcherPath, testAdminToken, `{"scope":"restricted","allowed_root_entries":null}`)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "invalid_allowed_roots") {
			t.Errorf("body = %s, want invalid_allowed_roots", w.Body.String())
		}
	})

	t.Run("null allowed_roots plus supplied rich entries is the dual form", func(t *testing.T) {
		w := launcherRequest(t, app, http.MethodPut, launcherPath, testAdminToken,
			`{"scope":"restricted","allowed_roots":null,"allowed_root_entries":[{"path":`+quoteJSON(t, a)+`,"access":"read_only"}]}`)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "provide either allowed_roots or allowed_root_entries, not both") {
			t.Errorf("body = %s, want the dual-form refusal", w.Body.String())
		}
	})

	t.Run("empty allowed_roots plus supplied rich entries is the dual form", func(t *testing.T) {
		w := launcherRequest(t, app, http.MethodPut, launcherPath, testAdminToken,
			`{"scope":"restricted","allowed_roots":[],"allowed_root_entries":[{"path":`+quoteJSON(t, a)+`,"access":"read_only"}]}`)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "provide either allowed_roots or allowed_root_entries, not both") {
			t.Errorf("body = %s, want the dual-form refusal", w.Body.String())
		}
	})

	t.Run("supplied allowed_roots plus null allowed_root_entries is the dual form", func(t *testing.T) {
		w := launcherRequest(t, app, http.MethodPut, launcherPath, testAdminToken,
			`{"scope":"restricted","allowed_roots":[`+quoteJSON(t, a)+`],"allowed_root_entries":null}`)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "provide either allowed_roots or allowed_root_entries, not both") {
			t.Errorf("body = %s, want the dual-form refusal", w.Body.String())
		}
	})

	t.Run("null both forms is the dual form", func(t *testing.T) {
		w := launcherRequest(t, app, http.MethodPut, launcherPath, testAdminToken,
			`{"scope":"inherit","allowed_roots":null,"allowed_root_entries":null}`)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "provide either allowed_roots or allowed_root_entries, not both") {
			t.Errorf("body = %s, want the dual-form refusal", w.Body.String())
		}
	})
}

// TestLauncherHTTPReplaceRichEntryStrictNested proves the rich entry array is
// decoded strictly inside the custom UnmarshalJSON: an unknown nested field is
// refused through the real route (the outer DisallowUnknownFields never
// reaches inside a custom UnmarshalJSON), and the refused replacement never
// mutates the stored scope.
func TestLauncherHTTPReplaceRichEntryStrictNested(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	username := "lstrictreplace"
	_, root, l := setupLauncherWithStoredRoot(t, app, username)
	launcherPath := "/principals/" + username + "/launchers/default/allowed-roots"

	w := launcherRequest(t, app, http.MethodPut, launcherPath, testAdminToken,
		`{"scope":"restricted","allowed_root_entries":[{"path":`+quoteJSON(t, root)+`,"access":"read_only","typo":true}]}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "invalid_json") {
		t.Errorf("body = %s, want invalid_json (strict nested decode)", w.Body.String())
	}
	// Prove the refusal reached the replace route with an intact
	// pre-mutation state: the stored scope is untouched.
	stored := mustStoredLauncherEntries(t, app, l.ID)
	if len(stored) != 1 || stored[0].Path != root {
		t.Errorf("refused replacement must not mutate, stored = %+v", stored)
	}
}

// TestAllowedRootReplaceFieldDecoders proves the presence and strictness
// rules of the two scope-replacement roots decoders directly, so the nested
// strictness is attributed to the custom decoders and not to an outer layer:
//
//   - any occurrence, including JSON null, marks the field present (the
//     frozen contract: a present key is the supplied form regardless of its
//     value);
//   - the rich array is decoded with unknown fields, malformed types, and
//     trailing JSON rejected.
func TestAllowedRootReplaceFieldDecoders(t *testing.T) {
	t.Run("legacy slice is present on null", func(t *testing.T) {
		var s optionalLauncherRootsSlice
		if err := json.Unmarshal([]byte(`null`), &s); err != nil {
			t.Fatal(err)
		}
		if !s.present || s.value != nil {
			t.Errorf("legacy null form = present=%v value=%v, want present with no roots", s.present, s.value)
		}
	})

	t.Run("legacy slice is present on an empty array", func(t *testing.T) {
		var s optionalLauncherRootsSlice
		if err := json.Unmarshal([]byte(`[]`), &s); err != nil {
			t.Fatal(err)
		}
		if !s.present || len(s.value) != 0 {
			t.Errorf("legacy empty form = present=%v value=%v, want present with an empty array", s.present, s.value)
		}
	})

	t.Run("rich slice is present on null", func(t *testing.T) {
		var s allowedRootEntryInputSlice
		if err := json.Unmarshal([]byte(`null`), &s); err != nil {
			t.Fatal(err)
		}
		if !s.present || s.value != nil {
			t.Errorf("rich null form = present=%v value=%v, want present with no entries", s.present, s.value)
		}
	})

	t.Run("rich slice rejects an unknown nested field", func(t *testing.T) {
		var s allowedRootEntryInputSlice
		err := json.Unmarshal([]byte(`[{"path":"/x","access":"read_only","typo":true}]`), &s)
		if err == nil {
			t.Fatal("unknown nested field must be rejected by the strict nested decode")
		}
	})

	t.Run("rich slice rejects a malformed entry type", func(t *testing.T) {
		var s allowedRootEntryInputSlice
		if err := json.Unmarshal([]byte(`["/x"]`), &s); err == nil {
			t.Fatal("a bare path string is not a rich entry object")
		}
	})

	t.Run("rich slice rejects trailing JSON after the array", func(t *testing.T) {
		var s allowedRootEntryInputSlice
		err := s.UnmarshalJSON([]byte(`[{"path":"/x","access":"read_only"}] {"x":1}`))
		if err == nil {
			t.Fatal("trailing JSON after the array must be rejected by the nested decode")
		}
	})

	t.Run("rich slice rejects a malformed trailing token after the array", func(t *testing.T) {
		var s allowedRootEntryInputSlice
		// The EOF check (not a More() probe) refuses this shape: More()
		// reports false for a trailing closing delimiter, so this exact
		// input is the regression case.
		err := s.UnmarshalJSON([]byte(`[{"path":"/x","access":"read_only"}] ]`))
		if err == nil {
			t.Fatal("a malformed trailing token after the array must be rejected by the EOF check")
		}
	})
}

func quoteJSON(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal %q: %v", s, err)
	}
	return string(b)
}

// =============================================================================
// Rich projections
// =============================================================================

// TestPrincipalShowRichProjection proves the show/create projection carries
// the authoritative rich entries beside the derived path-only form, with
// identical ordering and non-nil arrays.
func TestPrincipalShowRichProjection(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	username := "projuser"
	home := setupPrincipalWithRoots(t, app, username)

	// Creation seeds exactly one stored root (the canonical home,
	// read_write); the projection carries that rich entry beside the
	// derived path-only form.
	w := launcherRequest(t, app, http.MethodGet, "/principals/"+username, testAdminToken, "")
	if w.Code != http.StatusOK {
		t.Fatalf("show: status = %d", w.Code)
	}
	var resp principalResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.AllowedRoots == nil || resp.AllowedRootEntries == nil {
		t.Fatalf("stored roots must project non-nil arrays, got %v / %v", resp.AllowedRoots, resp.AllowedRootEntries)
	}
	if len(resp.AllowedRoots) != 1 || len(resp.AllowedRootEntries) != 1 {
		t.Fatalf("creation projection lengths = %d / %d, want 1", len(resp.AllowedRoots), len(resp.AllowedRootEntries))
	}
	if resp.AllowedRootEntries[0].Path != resp.AllowedRoots[0] || resp.AllowedRootEntries[0].Path != home {
		t.Errorf("creation entry = %+v, want the canonical home %q", resp.AllowedRootEntries[0], home)
	}
	if resp.AllowedRootEntries[0].Access != AllowedRootAccessReadWrite {
		t.Errorf("creation access = %q, want read_write", resp.AllowedRootEntries[0].Access)
	}

	a := filepath.Join(home, "a")
	b := filepath.Join(home, "b")
	for _, d := range []string{a, b} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}
	mustSeedPrincipalRoot(t, app, username, a, AllowedRootAccessReadOnly)
	mustSeedPrincipalRoot(t, app, username, b, AllowedRootAccessReadWrite)

	w = launcherRequest(t, app, http.MethodGet, "/principals/"+username, testAdminToken, "")
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.AllowedRoots) != 3 || len(resp.AllowedRootEntries) != 3 {
		t.Fatalf("projection lengths = %d / %d, want 3", len(resp.AllowedRoots), len(resp.AllowedRootEntries))
	}
	for i := range resp.AllowedRootEntries {
		if resp.AllowedRoots[i] != resp.AllowedRootEntries[i].Path {
			t.Errorf("projection divergence at %d: %q vs %+v", i, resp.AllowedRoots[i], resp.AllowedRootEntries[i])
		}
	}
	stored := map[string]AllowedRootAccess{}
	for _, e := range resp.AllowedRootEntries {
		stored[e.Path] = e.Access
	}
	if stored[a] != AllowedRootAccessReadOnly || stored[b] != AllowedRootAccessReadWrite {
		t.Errorf("entries = %+v, want a=read_only b=read_write", resp.AllowedRootEntries)
	}
}

// TestPrincipalShowFieldAllowedRootEntries proves the CLI field extraction
// vocabulary accepts the rich projection field.
func TestPrincipalShowFieldAllowedRootEntries(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	username := "fieldprojuser"
	setupPrincipalWithRoots(t, app, username)

	fields := principalShowFieldNames()
	found := false
	for _, f := range fields {
		if f == "allowed_root_entries" {
			found = true
		}
	}
	if !found {
		t.Errorf("principal show fields %v must contain allowed_root_entries", fields)
	}
}

// TestEffectiveRootsIntrospectionRichProjection proves the read-only
// introspection responses carry the authoritative rich entries beside the
// derived path-only form.
func TestEffectiveRootsIntrospectionRichProjection(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	username := "introspectuser"
	home := setupPrincipalWithRoots(t, app, username)
	_, credToken, err := createPrincipalCredential(app.DB, username, "oc")
	if err != nil {
		t.Fatalf("createPrincipalCredential: %v", err)
	}

	w := launcherRequest(t, app, http.MethodGet, "/principals/"+username+"/effective-allowed-roots", credToken, "")
	if w.Code != http.StatusOK {
		t.Fatalf("introspection: status = %d, body=%s", w.Code, w.Body.String())
	}
	var resp effectiveRootsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.AllowedRoots) == 0 || len(resp.AllowedRoots) != len(resp.AllowedRootEntries) {
		t.Fatalf("projection lengths = %d / %d", len(resp.AllowedRoots), len(resp.AllowedRootEntries))
	}
	for i := range resp.AllowedRootEntries {
		if resp.AllowedRoots[i] != resp.AllowedRootEntries[i].Path {
			t.Errorf("projection divergence at %d", i)
		}
	}
	if resp.AllowedRootEntries[0].Access != AllowedRootAccessReadWrite {
		t.Errorf("entry access = %q, want the collapsed read_write grant", resp.AllowedRootEntries[0].Access)
	}
	_ = home
}

// =============================================================================
// Config CLI
// =============================================================================

// TestConfigAllowedRootSetAccessCLI proves the global set-access mutation:
// the change persists in the canonical object form, an unchanged access is
// the no-op, a missing root mirrors the remove contract (not found, exit 0),
// and an invalid access is a user error before any transaction.
func TestConfigAllowedRootSetAccessCLI(t *testing.T) {
	t.Run("changed", func(t *testing.T) {
		root := testAllowedRootDir(t)
		data, _ := json.Marshal(map[string]any{"allowed_roots": []string{root}, "session_ttl": "12h"})
		configPath := setupConfigTestWithData(t, data)

		var stdout, stderr bytes.Buffer
		code := runCommandWithWriters([]string{"config", "allowed-root", "set-access", root, "read_only"}, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("exit = %d, stderr=%s", code, stderr.String())
		}
		if !strings.Contains(stdout.String(), "changed") || !strings.Contains(stdout.String(), "read_only") {
			t.Errorf("stdout = %q", stdout.String())
		}
		raw := readConfigJSON(t, configPath)
		var entries []AllowedRootEntry
		if err := json.Unmarshal(raw["allowed_roots"], &entries); err != nil {
			t.Fatal(err)
		}
		if len(entries) != 1 || entries[0] != (AllowedRootEntry{Path: root, Access: AllowedRootAccessReadOnly}) {
			t.Errorf("stored entries = %+v, want the read_only object entry", entries)
		}
	})

	t.Run("unchanged", func(t *testing.T) {
		root := testAllowedRootDir(t)
		data, _ := json.Marshal(map[string]any{"allowed_roots": []string{root}, "session_ttl": "12h"})
		configPath := setupConfigTestWithData(t, data)
		before, _ := os.ReadFile(configPath)

		var stdout, stderr bytes.Buffer
		code := runCommandWithWriters([]string{"config", "allowed-root", "set-access", root, "read_write"}, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("exit = %d, stderr=%s", code, stderr.String())
		}
		if !strings.Contains(stdout.String(), "unchanged") {
			t.Errorf("stdout = %q", stdout.String())
		}
		after, _ := os.ReadFile(configPath)
		if string(before) != string(after) {
			t.Error("unchanged set-access must not rewrite the config")
		}
	})

	t.Run("missing stored root is a user error", func(t *testing.T) {
		root := testAllowedRootDir(t)
		data, _ := json.Marshal(map[string]any{"allowed_roots": []string{root}, "session_ttl": "12h"})
		configPath := setupConfigTestWithData(t, data)

		var stdout, stderr bytes.Buffer
		code := runCommandWithWriters([]string{"config", "allowed-root", "set-access", root + "-missing", "read_only"}, &stdout, &stderr)
		if code == 0 {
			t.Fatalf("exit = 0, want a user-facing failure: stdout=%q stderr=%q", stdout.String(), stderr.String())
		}
		if stdout.Len() != 0 {
			t.Errorf("failed mutation must not write stdout, got %q", stdout.String())
		}
		if !strings.Contains(stderr.String(), "not found") {
			t.Errorf("stderr = %q, want the not-found failure", stderr.String())
		}
		verifyConfigUnchanged(t, configPath, data)
	})

	t.Run("missing stored root abandons a pending legacy migration", func(t *testing.T) {
		root := testAllowedRootDir(t)
		data, _ := json.Marshal(map[string]any{"allowed_root": root, "session_ttl": "12h"})
		configPath := setupConfigTestWithData(t, data)

		var stdout, stderr bytes.Buffer
		code := runCommandWithWriters([]string{"config", "allowed-root", "set-access", root + "-missing", "read_only"}, &stdout, &stderr)
		if code == 0 {
			t.Fatalf("exit = 0, want a user-facing failure: stdout=%q stderr=%q", stdout.String(), stderr.String())
		}
		if stdout.Len() != 0 {
			t.Errorf("failed mutation must not write stdout, got %q", stdout.String())
		}
		// The failed targeted mutation must not persist the legacy migration
		// prepared inside the transaction as its side effect.
		verifyConfigUnchanged(t, configPath, data)
	})

	t.Run("invalid access is a user error before the transaction", func(t *testing.T) {
		root := testAllowedRootDir(t)
		data, _ := json.Marshal(map[string]any{"allowed_roots": []string{root}, "session_ttl": "12h"})
		configPath := setupConfigTestWithData(t, data)

		var stdout, stderr bytes.Buffer
		code := runCommandWithWriters([]string{"config", "allowed-root", "set-access", root, "ro"}, &stdout, &stderr)
		if code != 2 {
			t.Fatalf("exit = %d, want 2", code)
		}
		if stdout.Len() != 0 {
			t.Errorf("user error must not write stdout, got %q", stdout.String())
		}
		verifyConfigUnchanged(t, configPath, data)
	})
}

// TestConfigAllowedRootAddAccessFlag proves the global add --access flag:
// the write is the canonical object form, and an idempotent re-add never
// changes the stored access.
func TestConfigAllowedRootAddAccessFlag(t *testing.T) {
	root := testAllowedRootDir(t)
	data, _ := json.Marshal(map[string]any{"allowed_roots": []string{root}, "session_ttl": "12h"})
	configPath := setupConfigTestWithData(t, data)

	inner := filepath.Join(root, "inner")
	if err := os.MkdirAll(inner, 0755); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "allowed-root", "add", "--access", "read_only", inner}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, stderr.String())
	}
	raw := readConfigJSON(t, configPath)
	var entries []AllowedRootEntry
	if err := json.Unmarshal(raw["allowed_roots"], &entries); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		if e.Path == inner {
			found = e.Access == AllowedRootAccessReadOnly
		}
	}
	if !found {
		t.Errorf("stored entries = %+v, want the read_only object entry", entries)
	}

	// Re-adding with the default access must not change the stored access.
	var stdout2, stderr2 bytes.Buffer
	code = runCommandWithWriters([]string{"config", "allowed-root", "add", inner}, &stdout2, &stderr2)
	if code != 0 {
		t.Fatalf("re-add exit = %d, stderr=%s", code, stderr2.String())
	}
	raw = readConfigJSON(t, configPath)
	entries = nil
	if err := json.Unmarshal(raw["allowed_roots"], &entries); err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Path == inner && e.Access != AllowedRootAccessReadOnly {
			t.Errorf("re-add changed the stored access: %+v", entries)
		}
	}
}

// TestConfigAllowedRootInvalidAddAccessIsUserError proves the parse happens
// before any canonicalization or transaction.
func TestConfigAllowedRootInvalidAddAccessIsUserError(t *testing.T) {
	root := testAllowedRootDir(t)
	data, _ := json.Marshal(map[string]any{"allowed_roots": []string{root}, "session_ttl": "12h"})
	configPath := setupConfigTestWithData(t, data)

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "allowed-root", "add", "--access", "ro", root}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if stdout.Len() != 0 {
		t.Errorf("user error must not write stdout, got %q", stdout.String())
	}
	verifyConfigUnchanged(t, configPath, data)
}

// =============================================================================
// Canonical stored-root identity resolution
// =============================================================================

// TestResolveAllowedRootIdentity proves the shared identity owner's rules:
// an existing symlink alias resolves to the same canonical stored identity as
// its target, a path that does not exist keeps the cleaned absolute lexical
// identity, and any other resolution failure (a symlink loop, a permission
// error) fails closed instead of demoting to a lexical lookup.
func TestResolveAllowedRootIdentity(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "target")
	if err := os.MkdirAll(target, 0755); err != nil {
		t.Fatal(err)
	}
	canonical, err := filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatal(err)
	}

	alias := filepath.Join(base, "alias")
	if err := os.Symlink(target, alias); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(alias) })

	// A symlink loop: a -> b and b -> a.
	loopA := filepath.Join(base, "loopA")
	loopB := filepath.Join(base, "loopB")
	if err := os.Symlink(loopB, loopA); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(loopA, loopB); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(loopA); os.Remove(loopB) })

	tests := []struct {
		name    string
		path    string
		want    string
		wantErr bool
	}{
		{name: "existing path resolves to its canonical form", path: target, want: canonical},
		{name: "existing symlink alias names the target's canonical identity", path: alias, want: canonical},
		{name: "missing path keeps the cleaned absolute lexical identity", path: filepath.Join(base, "missing"), want: filepath.Join(base, "missing")},
		{name: "symlink loop fails closed", path: loopA, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			identity, err := resolveAllowedRootIdentity(tc.path)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("identity = %q, want a fail-closed resolution error", identity)
				}
				if !isErrInvalidAllowedRoot(err) {
					t.Errorf("resolution error %v must classify as invalid_allowed_root", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("identity(%s): %v", tc.path, err)
			}
			if identity != tc.want {
				t.Errorf("identity = %q, want %q", identity, tc.want)
			}
		})
	}
}

// TestConfigAllowedRootRemoveIdentityResolution proves the config remove
// resolves identities through the shared owner: a symlink alias names the
// same stored entry as its target, a missing path keeps its lexical stored
// identity, and a non-ENOENT resolution failure refuses the mutation with no
// config change.
func TestConfigAllowedRootRemoveIdentity(t *testing.T) {
	t.Run("symlink alias removes the same canonical stored entry", func(t *testing.T) {
		root := testAllowedRootDir(t)
		other := testAllowedRootDir(t)
		data, _ := json.Marshal(map[string]any{"allowed_roots": []string{root, other}, "session_ttl": "12h"})
		configPath := setupConfigTestWithData(t, data)

		alias := root + "-alias"
		if err := os.Symlink(root, alias); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Remove(alias) })

		var stdout, stderr bytes.Buffer
		code := runCommandWithWriters([]string{"config", "allowed-root", "remove", alias}, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("exit = %d, stderr=%s", code, stderr.String())
		}
		if !strings.Contains(stdout.String(), "removed") {
			t.Errorf("stdout = %q", stdout.String())
		}
		raw := readConfigJSON(t, configPath)
		var entries []AllowedRootEntry
		if err := json.Unmarshal(raw["allowed_roots"], &entries); err != nil {
			t.Fatal(err)
		}
		roots := allowedRootPaths(entries)
		if len(roots) != 1 || roots[0] != other {
			t.Errorf("stored entries = %v, want exactly the alias's canonical entry %q removed", roots, root)
		}
	})

	t.Run("symlink loop refuses the mutation with no config change", func(t *testing.T) {
		root := testAllowedRootDir(t)
		extra := testAllowedRootDir(t)
		data, _ := json.Marshal(map[string]any{"allowed_roots": []string{root, extra}, "session_ttl": "12h"})
		configPath := setupConfigTestWithData(t, data)

		loopA := filepath.Join(root, "loopA")
		loopB := filepath.Join(root, "loopB")
		if err := os.Symlink(loopB, loopA); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(loopA, loopB); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Remove(loopA); os.Remove(loopB) })

		var stdout, stderr bytes.Buffer
		code := runCommandWithWriters([]string{"config", "allowed-root", "remove", loopA}, &stdout, &stderr)
		if code == 0 {
			t.Fatalf("exit = 0, want a fail-closed refusal: stdout=%q stderr=%q", stdout.String(), stderr.String())
		}
		if stdout.Len() != 0 {
			t.Errorf("failed resolution must not write stdout, got %q", stdout.String())
		}
		if !strings.Contains(stderr.String(), "cannot resolve allowed-root identity") {
			t.Errorf("stderr = %q, want the resolution-failure refusal", stderr.String())
		}
		verifyConfigUnchanged(t, configPath, data)
	})
}

// TestConfigAllowedRootRemoveIdentity proves the config remove resolves
// identities through the shared owner above; the config set-access identity
// behavior is covered by TestConfigAllowedRootSetAccessCLI and the
// resolveAllowedRootIdentity table.

// =============================================================================
// Audit mode facts
// =============================================================================

// TestPrincipalSetAccessAuditRequestedAndStored proves the set-access success
// audit records the requested and the actually stored access mode, so an
// operator can distinguish a real narrowing from the idempotent no-op retry.
func TestPrincipalSetAccessAuditRequestedAndStored(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAdminToken(t)
	username := "setaudit"
	home := setupPrincipalWithRoots(t, app, username)
	root := filepath.Join(home, "proj")
	if err := os.MkdirAll(root, 0755); err != nil {
		t.Fatal(err)
	}
	mustSeedPrincipalRoot(t, app, username, root, AllowedRootAccessReadWrite)
	body := `{"path":"` + root + `","access":"read_only"}`

	w := launcherRequest(t, app, http.MethodPatch, "/principals/"+username+"/allowed-roots", testAdminToken, body)
	if w.Code != http.StatusOK {
		t.Fatalf("narrow: status = %d, body=%s", w.Code, w.Body.String())
	}
	lines := findAuditLinesByEvent(auditBuf, "principal.allowed_root_set_access")
	if len(lines) != 1 {
		t.Fatalf("narrow audit lines = %d, want 1\n%s", len(lines), auditBuf.String())
	}
	m := parseAuditMap(t, lines[0])
	if m["result"] != "success" {
		t.Errorf("result = %v, want success", m["result"])
	}
	if m["principal_path"] != root {
		t.Errorf("principal_path = %v, want %s", m["principal_path"], root)
	}
	if m["requested_access"] != "read_only" || m["stored_access"] != "read_only" {
		t.Errorf("narrow audit requested/stored = %v/%v, want read_only/read_only", m["requested_access"], m["stored_access"])
	}
	assertNoSecrets(t, lines[0], m, testAdminToken, testAdminToken)

	// The same-value retry is the unchanged no-op; its audit still records
	// the requested mode as the stored mode.
	w = launcherRequest(t, app, http.MethodPatch, "/principals/"+username+"/allowed-roots", testAdminToken, body)
	if w.Code != http.StatusOK {
		t.Fatalf("retry: status = %d, body=%s", w.Code, w.Body.String())
	}
	lines = findAuditLinesByEvent(auditBuf, "principal.allowed_root_set_access")
	if len(lines) != 2 {
		t.Fatalf("retry audit lines = %d, want 2\n%s", len(lines), auditBuf.String())
	}
	m = parseAuditMap(t, lines[1])
	if m["requested_access"] != "read_only" || m["stored_access"] != "read_only" {
		t.Errorf("retry audit requested/stored = %v/%v, want read_only/read_only", m["requested_access"], m["stored_access"])
	}
}

// TestPrincipalAddAuditAccessDivergence proves the idempotent-create add with
// a conflicting access records requested_access (what was requested) and
// stored_access (what remains) distinctly: the add is accepted unchanged, and
// the audit names the divergence instead of presenting the request as stored.
func TestPrincipalAddAuditAccessDivergence(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAdminToken(t)
	username := "addaudit"
	home := setupPrincipalWithRoots(t, app, username)
	root := filepath.Join(home, "proj")
	if err := os.MkdirAll(root, 0755); err != nil {
		t.Fatal(err)
	}
	mustSeedPrincipalRoot(t, app, username, root, AllowedRootAccessReadOnly)

	w := launcherRequest(t, app, http.MethodPost, "/principals/"+username+"/allowed-roots", testAdminToken,
		`{"path":"`+root+`","access":"read_write"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("conflicting add: status = %d, body=%s", w.Code, w.Body.String())
	}
	raw := findAuditLine(auditBuf, "principal.allowed_root_add")
	if raw == "" {
		t.Fatalf("missing add audit line\n%s", auditBuf.String())
	}
	m := parseAuditMap(t, raw)
	if m["result"] != "success" {
		t.Errorf("result = %v, want success", m["result"])
	}
	if m["requested_access"] != "read_write" {
		t.Errorf("requested_access = %v, want read_write", m["requested_access"])
	}
	if m["stored_access"] != "read_only" {
		t.Errorf("stored_access = %v, want the unchanged read_only", m["stored_access"])
	}
	assertNoSecrets(t, raw, m, testAdminToken, testAdminToken)
}

// TestLauncherSetAccessAuditRequestedAndStored proves the Launcher set-access
// audit carries the same mode facts with the launcher identity, and that a
// conflicting add records the requested-versus-stored divergence.
func TestLauncherSetAccessAuditRequestedAndStored(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAdminToken(t)
	username := "lsetaudit"
	home, root, l := setupLauncherWithStoredRoot(t, app, username)
	_ = home
	launcherPath := "/principals/" + username + "/launchers/default/allowed-roots"

	w := launcherRequest(t, app, http.MethodPatch, launcherPath, testAdminToken,
		`{"path":"`+root+`","access":"read_only"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("narrow: status = %d, body=%s", w.Code, w.Body.String())
	}
	raw := findAuditLine(auditBuf, "launcher.allowed_root_set_access")
	if raw == "" {
		t.Fatalf("missing set-access audit line\n%s", auditBuf.String())
	}
	m := parseAuditMap(t, raw)
	if m["result"] != "success" {
		t.Errorf("result = %v, want success", m["result"])
	}
	if m["launcher_id"] != l.ID {
		t.Errorf("launcher_id = %v, want %s", m["launcher_id"], l.ID)
	}
	if m["requested_access"] != "read_only" || m["stored_access"] != "read_only" {
		t.Errorf("audit requested/stored = %v/%v, want read_only/read_only", m["requested_access"], m["stored_access"])
	}
	assertNoSecrets(t, raw, m, testAdminToken, testAdminToken)

	// Conflicting add: requested read_write, stored read_only.
	w = launcherRequest(t, app, http.MethodPost, launcherPath, testAdminToken,
		`{"path":"`+root+`","access":"read_write"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("conflicting add: status = %d, body=%s", w.Code, w.Body.String())
	}
	lines := findAuditLinesByEvent(auditBuf, "launcher.allowed_root_add")
	if len(lines) == 0 {
		t.Fatalf("missing add audit line\n%s", auditBuf.String())
	}
	m = parseAuditMap(t, lines[len(lines)-1])
	if m["requested_access"] != "read_write" {
		t.Errorf("requested_access = %v, want read_write", m["requested_access"])
	}
	if m["stored_access"] != "read_only" {
		t.Errorf("stored_access = %v, want the unchanged read_only", m["stored_access"])
	}
}

// TestAllowedRootRefusalAuditHasNoAccessFields proves failed control-plane
// requests whose access value was never a canonical vocabulary value never
// carry requested/stored access facts: a refusal has nothing stored to
// report, and an arbitrary spelling is never logged as a canonical access
// mode, so the audit record carries only the refusal result.
func TestAllowedRootRefusalAuditHasNoAccessFields(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAdminToken(t)
	username := "refaudit"
	setupPrincipalWithRoots(t, app, username)

	w := launcherRequest(t, app, http.MethodPatch, "/principals/"+username+"/allowed-roots", testAdminToken,
		`{"path":"/tmp/whatever"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	raw := findAuditLine(auditBuf, "principal.allowed_root_set_access")
	if raw == "" {
		t.Fatalf("missing set-access audit line\n%s", auditBuf.String())
	}
	m := parseAuditMap(t, raw)
	if m["result"] != "missing_access" {
		t.Errorf("result = %v, want missing_access", m["result"])
	}
	if _, ok := m["requested_access"]; ok {
		t.Error("refusal audit must not carry requested_access")
	}
	if _, ok := m["stored_access"]; ok {
		t.Error("refusal audit must not carry stored_access")
	}

	// The add's explicitly supplied unknown access is the same invariant:
	// the parsed canonical access does not exist, so the audit records the
	// stable invalid_access refusal without any access fact.
	w = launcherRequest(t, app, http.MethodPost, "/principals/"+username+"/allowed-roots", testAdminToken,
		`{"path":"/tmp/whatever","access":"ro"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("add status = %d, body=%s", w.Code, w.Body.String())
	}
	raw = findAuditLine(auditBuf, "principal.allowed_root_add")
	if raw == "" {
		t.Fatalf("missing add audit line\n%s", auditBuf.String())
	}
	m = parseAuditMap(t, raw)
	if m["result"] != "invalid_access" {
		t.Errorf("add result = %v, want invalid_access", m["result"])
	}
	if _, ok := m["requested_access"]; ok {
		t.Error("invalid-access add refusal audit must not carry requested_access")
	}
	if _, ok := m["stored_access"]; ok {
		t.Error("invalid-access add refusal audit must not carry stored_access")
	}
	assertNoSecrets(t, raw, m, testAdminToken, testAdminToken)
}

// TestPrincipalSetAccessNotFoundAuditCarriesRequestedAccess proves the
// set-access refusal for a missing stored root keeps the facts the request
// had already established: the canonical requested access is present, the
// stored access is absent (nothing is stored), the result is the stable
// allowed_root_not_found refusal, and the audit names the resolved canonical
// identity that was targeted.
func TestPrincipalSetAccessNotFoundAuditCarriesRequestedAccess(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAdminToken(t)
	username := "notfoundaudit"
	home := setupPrincipalWithRoots(t, app, username)
	missing := filepath.Join(home, "not-stored")
	if err := os.MkdirAll(missing, 0755); err != nil {
		t.Fatal(err)
	}

	w := launcherRequest(t, app, http.MethodPatch, "/principals/"+username+"/allowed-roots", testAdminToken,
		`{"path":"`+missing+`","access":"read_only"}`)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	raw := findAuditLine(auditBuf, "principal.allowed_root_set_access")
	if raw == "" {
		t.Fatalf("missing set-access audit line\n%s", auditBuf.String())
	}
	m := parseAuditMap(t, raw)
	if m["result"] != "allowed_root_not_found" {
		t.Errorf("result = %v, want allowed_root_not_found", m["result"])
	}
	if m["requested_access"] != "read_only" {
		t.Errorf("requested_access = %v, want read_only (the parsed canonical mode)", m["requested_access"])
	}
	if _, ok := m["stored_access"]; ok {
		t.Error("not-found refusal must not carry stored_access")
	}
	if m["principal_path"] != missing {
		t.Errorf("principal_path = %v, want the resolved identity %s", m["principal_path"], missing)
	}
	assertNoSecrets(t, raw, m, testAdminToken, testAdminToken)
}

// TestLauncherSetAccessNotFoundAuditCarriesRequestedAccess mirrors the
// Principal not-found audit contract on the Launcher family and proves the
// refusal keeps the target provenance of the resolved Launcher.
func TestLauncherSetAccessNotFoundAuditCarriesRequestedAccess(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAdminToken(t)
	username := "lnotfoundaudit"
	home, _, l := setupLauncherWithStoredRoot(t, app, username)
	_ = home
	launcherPath := "/principals/" + username + "/launchers/default/allowed-roots"
	missing := filepath.Join(app.Config.AllowedRoots[0].Path, "notfoundaudit-missing")
	if err := os.MkdirAll(missing, 0755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(missing) })

	w := launcherRequest(t, app, http.MethodPatch, launcherPath, testAdminToken,
		`{"path":"`+missing+`","access":"read_only"}`)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	raw := findAuditLine(auditBuf, "launcher.allowed_root_set_access")
	if raw == "" {
		t.Fatalf("missing set-access audit line\n%s", auditBuf.String())
	}
	m := parseAuditMap(t, raw)
	if m["result"] != "allowed_root_not_found" {
		t.Errorf("result = %v, want allowed_root_not_found", m["result"])
	}
	if m["requested_access"] != "read_only" {
		t.Errorf("requested_access = %v, want read_only (the parsed canonical mode)", m["requested_access"])
	}
	if _, ok := m["stored_access"]; ok {
		t.Error("not-found refusal must not carry stored_access")
	}
	if m["launcher_path"] != missing {
		t.Errorf("launcher_path = %v, want the resolved identity %s", m["launcher_path"], missing)
	}
	// The target provenance of the resolved Launcher is retained.
	if m["launcher_id"] != l.ID {
		t.Errorf("launcher_id = %v, want %s", m["launcher_id"], l.ID)
	}
	assertNoSecrets(t, raw, m, testAdminToken, testAdminToken)
}

// TestReservedAddAuditCarriesRequestedAccess proves a refused mutation of the
// reserved user-mode daemon-owner chain keeps the parsed requested access in
// its audit record together with the stable reserved-owner refusal result.
func TestReservedAddAuditCarriesRequestedAccess(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAdminToken(t)
	owner := app.userModeDefault.username
	root := app.Config.AllowedRoots[0].Path

	w := launcherRequest(t, app, http.MethodPost, "/principals/"+owner+"/allowed-roots", testAdminToken,
		`{"path":"`+root+`","access":"read_only"}`)
	expectReservedResponse(t, w, "principal allowed-root add (audit)")

	raw := findAuditLine(auditBuf, "principal.allowed_root_add")
	if raw == "" {
		t.Fatalf("missing add audit line\n%s", auditBuf.String())
	}
	m := parseAuditMap(t, raw)
	if m["result"] != "user_mode_owner_reserved" {
		t.Errorf("result = %v, want user_mode_owner_reserved", m["result"])
	}
	if m["requested_access"] != "read_only" {
		t.Errorf("requested_access = %v, want read_only (the parsed canonical mode)", m["requested_access"])
	}
	if _, ok := m["stored_access"]; ok {
		t.Error("reserved refusal must not carry stored_access")
	}
	if m["principal_name"] != owner {
		t.Errorf("principal_name = %v, want the target owner %q", m["principal_name"], owner)
	}
	assertNoSecrets(t, raw, m, testAdminToken, testAdminToken)
}

// TestLauncherAddRefusalAuditRetainsTargetProvenance proves a Launcher
// allowed-root add refused after the target Launcher was resolved retains the
// target provenance (principal_name, launcher identity) and the stable
// outside_principal_root refusal together with the canonical requested
// access.
func TestLauncherAddRefusalAuditRetainsTargetProvenance(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAdminToken(t)
	username := "lrefaudit"
	home := setupPrincipalWithRoots(t, app, username)
	launcherPath := "/principals/" + username + "/launchers/default/allowed-roots"

	// A directory directly under the global ceiling but outside the
	// Principal's effective root, so the daemon refuses the add after
	// resolving the target Launcher.
	outside := filepath.Join(app.Config.AllowedRoots[0].Path, "outside-principal-root-target")
	if err := os.MkdirAll(outside, 0755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(outside) })
	_ = home

	w := launcherRequest(t, app, http.MethodPost, launcherPath, testAdminToken,
		`{"path":"`+outside+`","access":"read_only"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "outside_principal_root") {
		t.Errorf("body = %s, want outside_principal_root", w.Body.String())
	}
	raw := findAuditLine(auditBuf, "launcher.allowed_root_add")
	if raw == "" {
		t.Fatalf("missing add audit line\n%s", auditBuf.String())
	}
	m := parseAuditMap(t, raw)
	if m["result"] != "outside_principal_root" {
		t.Errorf("result = %v, want outside_principal_root", m["result"])
	}
	if m["requested_access"] != "read_only" {
		t.Errorf("requested_access = %v, want read_only (the parsed canonical mode)", m["requested_access"])
	}
	if _, ok := m["stored_access"]; ok {
		t.Error("refusal audit must not carry stored_access")
	}
	// The target provenance of the resolved Launcher is retained: the target
	// owner's Principal name and the Launcher identity are present.
	if m["principal_name"] != username {
		t.Errorf("principal_name = %v, want the target owner %q", m["principal_name"], username)
	}
	if m["launcher_name"] != defaultLauncherName {
		t.Errorf("launcher_name = %v, want %q", m["launcher_name"], defaultLauncherName)
	}
	if m["launcher_id"] == "" {
		t.Error("refusal audit must retain the resolved launcher_id")
	}
	assertNoSecrets(t, raw, m, testAdminToken, testAdminToken)
}

// TestLauncherScopeReplaceRefusalAuditRetainsTargetProvenance proves every
// pre-mutation scope-replacement refusal keeps the target provenance of the
// resolved Launcher (principal_name, launcher identity): the audit names the
// Launcher the refused request addressed, for the request-side refusals as
// well as for the post-mutation refusals.
func TestLauncherScopeReplaceRefusalAuditRetainsTargetProvenance(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAdminToken(t)
	username := "lscrefprov"
	home, root, l := setupLauncherWithStoredRoot(t, app, username)
	_ = home
	launcherPath := "/principals/" + username + "/launchers/" + defaultLauncherName + "/allowed-roots"

	cases := []struct {
		name   string
		body   string
		result string
	}{
		{
			name:   "invalid scope",
			body:   `{"scope":"bogus"}`,
			result: "invalid_scope",
		},
		{
			// Both roots keys occur — the rich key as JSON null — so the
			// dual-form refusal also proves a null occurrence counts as
			// present.
			name:   "dual form",
			body:   `{"scope":"inherit","allowed_roots":[],"allowed_root_entries":null}`,
			result: "invalid_allowed_roots",
		},
		{
			name:   "invalid rich access",
			body:   `{"scope":"restricted","allowed_root_entries":[{"path":` + quoteJSON(t, root) + `,"access":"typo"}]}`,
			result: "invalid_access",
		},
	}

	for _, tc := range cases {
		w := launcherRequest(t, app, http.MethodPut, launcherPath, testAdminToken, tc.body)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s: status = %d, body=%s", tc.name, w.Code, w.Body.String())
		}
	}

	lines := findAuditLinesByEvent(auditBuf, "launcher.scope_replace")
	if len(lines) != len(cases) {
		t.Fatalf("scope_replace audit lines = %d, want %d\n%s", len(lines), len(cases), auditBuf.String())
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := parseAuditMap(t, lines[i])
			if m["result"] != tc.result {
				t.Errorf("result = %v, want %s", m["result"], tc.result)
			}
			if m["principal_name"] != username {
				t.Errorf("principal_name = %v, want the target owner %q", m["principal_name"], username)
			}
			if m["launcher_name"] != defaultLauncherName {
				t.Errorf("launcher_name = %v, want %q", m["launcher_name"], defaultLauncherName)
			}
			if m["launcher_id"] != l.ID {
				t.Errorf("launcher_id = %v, want %s", m["launcher_id"], l.ID)
			}
			assertNoSecrets(t, lines[i], m, testAdminToken, testAdminToken)
		})
	}
}
