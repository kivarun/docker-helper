package main

import (
	"encoding/json"
	"errors"
	"fmt"
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

// TestPrincipalCreateNULAliasCannotCoexistWithCanonical proves the M5
// identity invariant on the fixed line: the canonical spelling is created
// (with its optional credential) and the NUL-bearing alias spelling — which
// the seam resolves to the SAME OS identity — is refused 400 invalid_username
// BEFORE the resolver, so SQLite never sees a second Principal TEXT identity
// for one OS account and the alias attempt issues no credential or token.
func TestPrincipalCreateNULAliasCannotCoexistWithCanonical(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	home := principalUsernameGrammarDB(t, app, "alice")
	calls := installRecordingOSUserLookup(t, "2001", "2001", home)

	w := launcherRequest(t, app, http.MethodPost, "/principals", testAdminToken,
		`{"username":"alice","issue_credential":true}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("canonical create: expected 201, got %d (body=%s)", w.Code, w.Body.String())
	}
	var created map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode canonical create response: %v", err)
	}
	if created["uid"] != float64(2001) || created["gid"] != float64(2001) {
		t.Fatalf("canonical create carried uid/gid %v/%v, want the aliased OS identity 2001/2001", created["uid"], created["gid"])
	}

	w2 := launcherRequest(t, app, http.MethodPost, "/principals", testAdminToken,
		`{"username":"alice\u0000alias","issue_credential":true}`)
	if w2.Code != http.StatusBadRequest {
		t.Fatalf("NUL alias create: expected 400 invalid_username, got %d (body=%s)", w2.Code, w2.Body.String())
	}
	var refused map[string]any
	if err := json.Unmarshal(w2.Body.Bytes(), &refused); err != nil {
		t.Fatalf("decode alias refusal: %v", err)
	}
	if refused["code"] != "invalid_username" {
		t.Fatalf("alias refusal code = %v, want invalid_username", refused["code"])
	}
	for _, secretKey := range []string{"token", "credential"} {
		if _, ok := refused[secretKey]; ok {
			t.Fatalf("alias refusal leaked %q in the response", secretKey)
		}
	}

	// The alias attempt must never have consulted the OS resolver: the only
	// lookup is the canonical create's own.
	for _, spelling := range *calls {
		if strings.ContainsRune(spelling, 0) {
			t.Fatalf("OS resolver was consulted with the NUL-bearing spelling: %v", *calls)
		}
	}
	if _, err := findPrincipalByUsername(app.DB, "alice\x00alias"); !errors.Is(err, ErrPrincipalNotFound) {
		t.Fatalf("NUL alias persisted as a Principal row: %v", err)
	}
	p, err := findPrincipalByUsername(app.DB, "alice")
	if err != nil {
		t.Fatalf("canonical principal missing after alias refusal: %v", err)
	}
	if p.Username != "alice" {
		t.Fatalf("stored canonical username = %q, want the exact supplied spelling", p.Username)
	}
	var count int
	if err := app.DB.QueryRow(
		`SELECT COUNT(*) FROM principals WHERE username IN ('alice', ?)`,
		"alice\x00alias",
	).Scan(&count); err != nil {
		t.Fatalf("count aliased identities: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected exactly one Principal identity for one OS account, got %d", count)
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

// TestValidatePrincipalUsernameGrammar is the direct matrix for the one
// Principal username grammar owner: every control-bearing spelling (C0
// including LF/CR/TAB, SOH, DEL, C1 NEL/CSI, embedded NUL) and the empty
// string are refused with the single ErrInvalidPrincipalUsername class,
// while ordinary printable spellings — ASCII, mixed case, spaces,
// punctuation, printable Unicode — are passed to the OS resolver unchanged.
func TestValidatePrincipalUsernameGrammar(t *testing.T) {
	accepted := []string{
		"alice",
		"Alice",
		"root",
		"0",
		"-",
		"a b",                    // ordinary space
		"user.name-1_2",          // punctuation outside any invented regex
		"pünctuation.semi;colon", // printable non-ASCII
		"Ω-user",                 // printable Unicode
		"operation ✔",            // printable symbol + space
	}
	refused := []string{
		"",               // empty
		"\x00",           // bare NUL
		"alice\x00alias", // embedded NUL alias
		"\n",             // LF
		"\r",             // CR
		"\t",             // TAB
		"\x01",           // SOH (C0)
		"ali\nce",        // embedded LF
		"\x7f",           // DEL
		"\u0085",         // C1 NEL
		"\u009b",         // C1 CSI
	}
	for _, username := range accepted {
		if err := validatePrincipalUsername(username); err != nil {
			t.Fatalf("validatePrincipalUsername(%q) = %v, want accepted unchanged", username, err)
		}
	}
	for _, username := range refused {
		err := validatePrincipalUsername(username)
		if !errors.Is(err, ErrInvalidPrincipalUsername) {
			t.Fatalf("validatePrincipalUsername(%q) = %v, want ErrInvalidPrincipalUsername", username, err)
		}
	}
}

// TestPrincipalCreateRefusesInvalidUsernameDomainError proves the domain
// create path itself (the owner of the ordering) refuses a control-bearing
// username with the single ErrInvalidPrincipalUsername class and without
// consulting the OS account resolver.
func TestPrincipalCreateRefusesInvalidUsernameDomainError(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	home := principalUsernameGrammarDB(t, app, "alice")
	calls := installRecordingOSUserLookup(t, "2001", "2001", home)

	for _, username := range []string{"alice\x00alias", "ali\nce", "\x7f", ""} {
		p, cred, token, err := createPrincipalWithOptionalCredential(app.DB, username, app.Config.AllowedRoots, true)
		if !errors.Is(err, ErrInvalidPrincipalUsername) {
			t.Fatalf("create(%q) = %v, want ErrInvalidPrincipalUsername", username, err)
		}
		if p != nil || cred != nil || token != "" {
			t.Fatalf("refused create(%q) returned state (principal=%v credential=%v token=%q)", username, p, cred, token)
		}
	}
	if len(*calls) != 0 {
		t.Fatalf("OSUserLookup consulted for refused spelling(s): %v", *calls)
	}
}

// TestPrincipalCreatePrintableUsernamePassesToResolverUnchanged proves the
// grammar does not invent a wider username regex: ordinary printable
// spellings that look unusual (spaces, punctuation, printable non-ASCII) are
// NOT rejected by the text owner and reach the OS resolver with the exact
// supplied spelling — no trim, no case-fold, no rewrite. The OS resolver
// (here the seam) remains the authority for existence.
func TestPrincipalCreatePrintableUsernamePassesToResolverUnchanged(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	home := principalUsernameGrammarDB(t, app, "alice")
	orig := OSUserLookup
	t.Cleanup(func() { OSUserLookup = orig })
	calls := []string{}
	OSUserLookup = func(username string) (string, string, string, error) {
		calls = append(calls, username)
		return "2002", "2002", home, nil
	}

	for _, username := range []string{"has space", "pünctuation.semi;colon", "Ω-user"} {
		w := launcherRequest(t, app, http.MethodPost, "/principals", testAdminToken,
			fmt.Sprintf(`{"username":%s,"issue_credential":false}`, mustJSONUsername(username)))
		if w.Code != http.StatusCreated {
			t.Fatalf("printable username %q: expected 201, got %d (body=%s)", username, w.Code, w.Body.String())
		}
	}
	want := []string{"has space", "pünctuation.semi;colon", "Ω-user"}
	if len(calls) != len(want) {
		t.Fatalf("resolver calls = %v, want exactly %v", calls, want)
	}
	for i, spelling := range want {
		if calls[i] != spelling {
			t.Fatalf("resolver call %d = %q, want the exact supplied spelling %q (no trim/fold/rewrite)", i, calls[i], spelling)
		}
	}
}

// mustJSONUsername encodes a username as the JSON string literal it must
// travel as on the wire (JSON escapes for control-bearing spellings).
func mustJSONUsername(username string) string {
	encoded, err := json.Marshal(username)
	if err != nil {
		panic(fmt.Sprintf("marshal username: %v", err))
	}
	return string(encoded)
}

// TestPrincipalCreateMissingUsernameStaysMissingUsername proves the empty
// username keeps its established public contract.
func TestPrincipalCreateMissingUsernameStaysMissingUsername(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	home := principalUsernameGrammarDB(t, app, "alice")
	calls := installRecordingOSUserLookup(t, "2001", "2001", home)

	w := launcherRequest(t, app, http.MethodPost, "/principals", testAdminToken,
		`{"issue_credential":true}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d (body=%s)", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["code"] != "missing_username" {
		t.Fatalf("code = %v, want missing_username", resp["code"])
	}
	if len(*calls) != 0 {
		t.Fatalf("OSUserLookup consulted for an empty username: %v", *calls)
	}
}

// TestPrincipalCreateUnknownOSUserStaysOSUserNotFound proves a grammar-valid
// spelling still reaches the OS resolver and keeps the established
// os_user_not_found contract when the account does not exist.
func TestPrincipalCreateUnknownOSUserStaysOSUserNotFound(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	orig := OSUserLookup
	t.Cleanup(func() { OSUserLookup = orig })
	calls := []string{}
	OSUserLookup = func(username string) (string, string, string, error) {
		calls = append(calls, username)
		return "", "", "", fmt.Errorf("no such user %q", username)
	}

	w := launcherRequest(t, app, http.MethodPost, "/principals", testAdminToken,
		`{"username":"ghost","issue_credential":false}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d (body=%s)", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["code"] != "os_user_not_found" {
		t.Fatalf("code = %v, want os_user_not_found", resp["code"])
	}
	if len(calls) != 1 || calls[0] != "ghost" {
		t.Fatalf("resolver calls = %v, want exactly one call with the supplied spelling", calls)
	}
}

// TestPrincipalCreateDuplicateStillPrincipalExists proves the established
// 409 principal_exists contract is unchanged for grammar-valid spellings.
func TestPrincipalCreateDuplicateStillPrincipalExists(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	home := principalUsernameGrammarDB(t, app, "alice")
	installRecordingOSUserLookup(t, "2001", "2001", home)

	w := launcherRequest(t, app, http.MethodPost, "/principals", testAdminToken,
		`{"username":"alice","issue_credential":false}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("first create: expected 201, got %d (body=%s)", w.Code, w.Body.String())
	}
	w2 := launcherRequest(t, app, http.MethodPost, "/principals", testAdminToken,
		`{"username":"alice","issue_credential":false}`)
	if w2.Code != http.StatusConflict {
		t.Fatalf("duplicate create: expected 409, got %d (body=%s)", w2.Code, w2.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w2.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["code"] != "principal_exists" {
		t.Fatalf("code = %v, want principal_exists", resp["code"])
	}
}
