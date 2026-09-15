package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// installRecordingOSUserLookup stubs the OSUserLookup seam with one identity:
// every requested spelling resolves to the same uid/gid/home, which is how a
// libc/NSS resolver aliases a NUL-bearing spelling to the canonical account.
// The exact requested spellings are recorded in call order and returned so a
// test can prove the resolver was or was not consulted.
func installRecordingOSUserLookup(t *testing.T, uid, gid, home string) *[]string {
	t.Helper()
	orig := OSUserLookup
	t.Cleanup(func() { OSUserLookup = orig })
	calls := []string{}
	OSUserLookup = func(username string) (string, string, string, error) {
		calls = append(calls, username)
		return uid, gid, home, nil
	}
	return &calls
}

// principalUsernameGrammarDB returns an App and an OS home directory inside
// the app's allowed root for Principal creation tests. The home is what the
// OSUserLookup seam reports, so a created Principal's default root is inside
// the global ceiling.
func principalUsernameGrammarDB(t *testing.T, app *App, name string) string {
	t.Helper()
	home := filepath.Join(app.Config.AllowedRoots[0].Path, "home", name)
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatalf("cannot create OS home %s: %v", home, err)
	}
	return home
}

// assertNoPrincipalIdentityResidue fails the test when the refused username
// left any Principal ownership state behind: a principals row, a
// principal_allowed_roots row, a launcher, or a Principal credential.
func assertNoPrincipalIdentityResidue(t *testing.T, app *App, username string) {
	t.Helper()
	if _, err := findPrincipalByUsername(app.DB, username); !errors.Is(err, ErrPrincipalNotFound) {
		t.Fatalf("principal row exists for refused username %q: %v", username, err)
	}
	for name, query := range map[string]string{
		"principal_allowed_roots": `SELECT COUNT(*) FROM principal_allowed_roots r
			 JOIN principals p ON p.id = r.principal_id WHERE p.username = ?`,
		"launchers": `SELECT COUNT(*) FROM launchers l
			 JOIN principals p ON p.id = l.principal_id WHERE p.username = ?`,
		"principal credentials": `SELECT COUNT(*) FROM credentials c
			 JOIN principals p ON p.id = c.principal_id
			 WHERE p.username = ? AND c.launcher_id IS NULL`,
	} {
		var count int
		if err := app.DB.QueryRow(query, username).Scan(&count); err != nil {
			t.Fatalf("count %s: %v", name, err)
		}
		if count != 0 {
			t.Fatalf("refused username %q left %d %s row(s)", username, count, name)
		}
	}
}

// TestPrincipalCreateControlUsernameRefusedBeforeOSUserLookup proves the
// Release 2.2 Principal username grammar admission ordering: a spelling that
// is empty of grammar problems passes unchanged, while a spelling carrying a
// Unicode control rune (embedded NUL alias, LF, CR, TAB, SOH, DEL, C1 NEL) is
// refused 400 invalid_username BEFORE the OS account resolver is consulted,
// leaving no Principal, allowed-root, Launcher, or credential state behind.
// The seam resolves every spelling to the same OS identity, so any pre-lookup
// refusal is the grammar's own decision, never an OS-resolution outcome.
func TestPrincipalCreateControlUsernameRefusedBeforeOSUserLookup(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	home := principalUsernameGrammarDB(t, app, "alice")
	calls := installRecordingOSUserLookup(t, "2001", "2001", home)

	hostile := []string{
		"alice\x00alias", // NUL-bearing alias of canonical alice on a libc resolver
		"\x00",           // bare NUL
		"ali\nce",        // LF
		"ali\rce",        // CR
		"ali\tce",        // TAB
		"ali\x01ce",      // SOH (C0)
		"ali\x7fce",      // DEL
		"ali\u0085ce",    // C1 NEL
	}
	for _, username := range hostile {
		for _, issue := range []bool{false, true} {
			body, err := json.Marshal(map[string]any{"username": username, "issue_credential": issue})
			if err != nil {
				t.Fatalf("marshal request body: %v", err)
			}
			w := launcherRequest(t, app, http.MethodPost, "/principals", testAdminToken, string(body))
			if w.Code != http.StatusBadRequest {
				t.Fatalf("username %q issue_credential=%t: expected 400 invalid_username, got %d (body=%s)",
					username, issue, w.Code, w.Body.String())
			}
			var resp map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("username %q: cannot decode error body: %v (body=%s)", username, err, w.Body.String())
			}
			if resp["code"] != "invalid_username" {
				t.Fatalf("username %q: expected code invalid_username, got %v (body=%s)",
					username, resp["code"], w.Body.String())
			}
			if msg, _ := resp["message"].(string); msg != "invalid username" {
				t.Fatalf("username %q: expected bounded message \"invalid username\", got %q", username, msg)
			}
			if issue {
				for _, secretKey := range []string{"token", "credential"} {
					if _, ok := resp[secretKey]; ok {
						t.Fatalf("username %q: refused create leaked %q in the response", username, secretKey)
					}
				}
			}
			if len(*calls) != 0 {
				t.Fatalf("OSUserLookup was consulted for refused username(s) %v; grammar must refuse before the resolver", *calls)
			}
			assertNoPrincipalIdentityResidue(t, app, username)
		}
	}
}

// TestPrincipalCreateNULAliasPersistsDistinctIdentity is the RED defect
// demonstration for M5: with the OSUserLookup seam aliasing a NUL-bearing
// spelling to the canonical account's identity (exactly what the C-string ABI
// does to getpwnam on the shipped cgo backend), the pre-fix creation path
// consults the resolver with the hostile spelling, succeeds, and persists the
// original spelling as a SECOND Principal identity for one OS account.
func TestPrincipalCreateNULAliasPersistsDistinctIdentity(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	home := principalUsernameGrammarDB(t, app, "alice")
	calls := installRecordingOSUserLookup(t, "2001", "2001", home)

	canonicalBody := `{"username":"alice","issue_credential":false}`
	w := launcherRequest(t, app, http.MethodPost, "/principals", testAdminToken, canonicalBody)
	if w.Code != http.StatusCreated {
		t.Fatalf("canonical create: expected 201, got %d (body=%s)", w.Code, w.Body.String())
	}

	aliasBody := `{"username":"alice\u0000alias","issue_credential":false}`
	w2 := launcherRequest(t, app, http.MethodPost, "/principals", testAdminToken, aliasBody)
	if w2.Code != http.StatusCreated {
		t.Fatalf("NUL alias create: expected 201 (defect), got %d (body=%s)", w2.Code, w2.Body.String())
	}

	lookupConsulted := false
	for _, spelling := range *calls {
		if strings.ContainsRune(spelling, 0) {
			lookupConsulted = true
		}
	}
	if !lookupConsulted {
		t.Fatalf("OS resolver was never consulted with the NUL-bearing spelling; calls=%v", *calls)
	}

	var usernames []string
	rows, err := app.DB.Query(
		`SELECT username, uid, gid, home FROM principals
		 WHERE username IN (?, ?) ORDER BY username`,
		"alice", "alice\x00alias",
	)
	if err != nil {
		t.Fatalf("list principals: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var u string
		var uid, gid int
		var homeStored string
		if err := rows.Scan(&u, &uid, &gid, &homeStored); err != nil {
			t.Fatalf("scan principal: %v", err)
		}
		usernames = append(usernames, u)
		if uid != 2001 || gid != 2001 || homeStored != home {
			t.Fatalf("principal %q persisted identity uid=%d gid=%d home=%q, want the aliased OS identity 2001/2001/%q",
				u, uid, gid, homeStored, home)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate principals: %v", err)
	}
	if len(usernames) != 2 {
		t.Fatalf("expected TWO persisted Principal TEXT identities for one OS account, got %v", usernames)
	}
	hasCanonical, hasAlias := false, false
	for _, u := range usernames {
		switch u {
		case "alice":
			hasCanonical = true
		case "alice\x00alias":
			hasAlias = true
		}
	}
	if !hasCanonical || !hasAlias {
		t.Fatalf("expected canonical alice and NUL alias as distinct stored identities, got %v", usernames)
	}
}

// TestPrincipalCreateInvalidUsernameAuditClassified proves a grammar-refused
// Principal creation is classified distinctly in the structured audit (not
// the generic error result), that the supplied PrincipalName is retained in
// the audit through the existing JSON escaping, and that the record carries
// no secret material.
func TestPrincipalCreateInvalidUsernameAuditClassified(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	auditBuf, _ := setupTestLogging(t)
	home := principalUsernameGrammarDB(t, app, "alice")
	installRecordingOSUserLookup(t, "2001", "2001", home)

	w := launcherRequest(t, app, http.MethodPost, "/principals", testAdminToken,
		`{"username":"alice\u0000alias","issue_credential":true}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 invalid_username, got %d (body=%s)", w.Code, w.Body.String())
	}

	lines := findAuditLinesByEvent(auditBuf, "principal.create")
	if len(lines) == 0 {
		t.Fatalf("no principal.create audit record; audit buffer:\n%s", auditBuf.String())
	}
	raw := lines[len(lines)-1]
	m := parseAuditMap(t, raw)
	if m["result"] != "invalid_username" {
		t.Fatalf("audit result = %v, want the distinct invalid_username classification", m["result"])
	}
	if m["principal_name"] != "alice\x00alias" {
		t.Fatalf("audit principal_name = %v, want the supplied spelling round-tripped through the JSON escaping", m["principal_name"])
	}
	if auditHasSecretKey(m) {
		t.Fatalf("refusal audit carries a secret-shaped key: %s", raw)
	}
	assertNoSecrets(t, raw, m, "", testAdminToken)
}
