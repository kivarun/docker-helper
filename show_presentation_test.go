package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// TestResourceShowTwoModeContract proves the canonical two-mode presentation
// contract of the resource show commands: the default output is the compact
// human block (through the shared PATH/ACCESS table renderer for allowed
// roots) and the explicit --json flag selects the unchanged canonical JSON
// document. The scalar FIELD extraction of `principal show USER FIELD` keeps
// working and stays exclusive of --json.
func TestResourceShowTwoModeContract(t *testing.T) {
	principalBody := `{"ok":true,"username":"michael","uid":1021,"gid":1021,"home":"/home/michael","enabled":true,` +
		`"allowed_roots":[{"path":"/home/michael","access":"read_write"}]}`
	launcherBody := `{"id":"dhl_1","principal":"alice","name":"build-agent","enabled":true,"scope":"restricted",` +
		`"allowed_roots":[{"path":"/srv/agent","access":"read_only"}],"created_at":"2026-09-17T00:00:00Z"}`

	t.Run("principal show", func(t *testing.T) {
		endpoint, tokenPath, _ := startRecordingLauncherCLIServer(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/principals/michael" && r.Method == http.MethodGet {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(principalBody))
				return
			}
			http.NotFound(w, r)
		})
		base := []string{"principal", "show", "--endpoint", endpoint, "--token-file", tokenPath, "michael"}

		var human, hErr bytes.Buffer
		if code := runCommandWithWriters(base, &human, &hErr); code != 0 {
			t.Fatalf("human exit = %d (stderr=%s)", code, hErr.String())
		}
		for _, want := range []string{"USERNAME: michael", "UID:      1021", "GID:      1021", "HOME:     /home/michael", "ENABLED:  true", "ALLOWED ROOTS", "/home/michael", "read_write"} {
			if !strings.Contains(human.String(), want) {
				t.Errorf("human output missing %q:\n%s", want, human.String())
			}
		}

		var js, jErr bytes.Buffer
		if code := runCommandWithWriters(append(append([]string{}, base[:len(base)-1]...), "--json", "michael"), &js, &jErr); code != 0 {
			t.Fatalf("json exit = %d (stderr=%s)", code, jErr.String())
		}
		if !strings.Contains(js.String(), `"allowed_roots"`) || strings.Contains(js.String(), "USERNAME:") {
			t.Errorf("--json output must be the bare canonical document, got:\n%s", js.String())
		}

		// The scalar FIELD extraction keeps working and is exclusive of --json.
		var field, fErr bytes.Buffer
		if code := runCommandWithWriters(append(append([]string{}, base...), "username"), &field, &fErr); code != 0 {
			t.Fatalf("field exit = %d (stderr=%s)", code, fErr.String())
		}
		if strings.TrimSpace(field.String()) != "michael" {
			t.Errorf("FIELD extraction = %q, want michael", field.String())
		}
		var conflict, cErr bytes.Buffer
		code := runCommandWithWriters(append(append([]string{}, base...), "--json", "username"), &conflict, &cErr)
		if code != 2 || !strings.Contains(cErr.String(), "mutually exclusive") {
			t.Errorf("FIELD + --json must be a local input error, got exit %d stderr=%s", code, cErr.String())
		}
	})

	t.Run("launcher show", func(t *testing.T) {
		endpoint, tokenPath, _ := startRecordingLauncherCLIServer(t, func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/auth":
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"authority":"principal","principal":"alice"}`))
			case r.URL.Path == "/principals/alice/launchers/build-agent":
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(launcherBody))
			default:
				http.NotFound(w, r)
			}
		})
		base := []string{"launcher", "show", "--endpoint", endpoint, "--token-file", tokenPath, "build-agent"}

		var human, hErr bytes.Buffer
		if code := runCommandWithWriters(base, &human, &hErr); code != 0 {
			t.Fatalf("human exit = %d (stderr=%s)", code, hErr.String())
		}
		for _, want := range []string{"ID:        dhl_1", "NAME:      build-agent", "PRINCIPAL: alice", "ENABLED:   true", "SCOPE:     restricted", "ALLOWED ROOTS", "/srv/agent", "read_only"} {
			if !strings.Contains(human.String(), want) {
				t.Errorf("human output missing %q:\n%s", want, human.String())
			}
		}

		var js, jErr bytes.Buffer
		if code := runCommandWithWriters(append(append([]string{}, base[:len(base)-1]...), "--json", "build-agent"), &js, &jErr); code != 0 {
			t.Fatalf("json exit = %d (stderr=%s)", code, jErr.String())
		}
		if !strings.Contains(js.String(), `"scope": "restricted"`) || strings.Contains(js.String(), "SCOPE:") {
			t.Errorf("--json output must be the bare canonical document, got:\n%s", js.String())
		}
	})
}

// firstLine returns the first newline-delimited line of s, so a test can
// match the result line of a command whose stdout carries trailing
// operational notes.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// TestSetAccessSharedPresentation proves the one shared presentation owner of
// the three allowed-root set-access commands (global config, Principal,
// Launcher): the same human mutation line — the subject qualifier appended
// only where the targeting names one — and the same structured result object
// under --json. Unchanged remains success; a missing target stays the
// command's failure; the config transaction reports its legacy-schema
// migration in both modes.
func TestSetAccessSharedPresentation(t *testing.T) {
	t.Run("config", func(t *testing.T) {
		legacyConfig := func() string {
			root := testAllowedRootDir(t)
			data, _ := json.Marshal(map[string]any{"allowed_roots": []string{root}, "session_ttl": "12h"})
			setupConfigTestWithData(t, data)
			return root
		}

		// Changed: the shared config mutation line; the operational
		// "daemon not running" note stays on stdout in human mode.
		root := legacyConfig()
		var human, hErr bytes.Buffer
		if code := runCommandWithWriters([]string{"config", "allowed-root", "set-access", root, "read_only"}, &human, &hErr); code != 0 {
			t.Fatalf("human exit = %d (stderr=%s)", code, hErr.String())
		}
		if firstLine(human.String()) != "changed "+root+" to access read_only" {
			t.Errorf("human output = %q, want the shared config mutation line", human.String())
		}
		if !strings.Contains(human.String(), "daemon not running") {
			t.Errorf("human changed run must keep the operational note on stdout: %q", human.String())
		}

		// Unchanged on the stored access: no write, no note, exact line.
		var unch, uErr bytes.Buffer
		if code := runCommandWithWriters([]string{"config", "allowed-root", "set-access", root, "read_only"}, &unch, &uErr); code != 0 {
			t.Fatalf("unchanged exit = %d (stderr=%s)", code, uErr.String())
		}
		if unch.String() != "unchanged "+root+" (access read_only)\n" {
			t.Errorf("unchanged output = %q, want the shared unchanged line", unch.String())
		}

		// --json selects the shared structured result; the operational note
		// moves to stderr so stdout stays pure JSON.
		root = legacyConfig()
		var js, jErr bytes.Buffer
		if code := runCommandWithWriters([]string{"config", "allowed-root", "set-access", root, "read_only", "--json"}, &js, &jErr); code != 0 {
			t.Fatalf("json exit = %d (stderr=%s)", code, jErr.String())
		}
		var doc map[string]any
		if err := json.Unmarshal(js.Bytes(), &doc); err != nil {
			t.Fatalf("json output is not a document: %v (%s)", err, js.String())
		}
		if len(doc) != 3 || doc["path"] != root || doc["access"] != "read_only" || doc["changed"] != true {
			t.Errorf("json result = %v, want exactly {path, access, changed}", doc)
		}
		if !strings.Contains(jErr.String(), "daemon not running") {
			t.Errorf("--json must move the operational note to stderr, got %q", jErr.String())
		}
	})

	t.Run("config legacy-schema migration is reported in both modes", func(t *testing.T) {
		legacyConfig := func() string {
			root := testAllowedRootDir(t)
			data, _ := json.Marshal(map[string]any{"allowed_root": root, "session_ttl": "12h"})
			setupConfigTestWithData(t, data)
			return root
		}

		root := legacyConfig()
		var human, hErr bytes.Buffer
		if code := runCommandWithWriters([]string{"config", "allowed-root", "set-access", root, "read_write"}, &human, &hErr); code != 0 {
			t.Fatalf("human exit = %d (stderr=%s)", code, hErr.String())
		}
		if firstLine(human.String()) != "unchanged "+root+" (access read_write; legacy schema migrated)" {
			t.Errorf("human output = %q, want the shared migrated unchanged line", human.String())
		}

		root = legacyConfig()
		var js, jErr bytes.Buffer
		if code := runCommandWithWriters([]string{"config", "allowed-root", "set-access", root, "read_write", "--json"}, &js, &jErr); code != 0 {
			t.Fatalf("json exit = %d (stderr=%s)", code, jErr.String())
		}
		var doc map[string]any
		if err := json.Unmarshal(js.Bytes(), &doc); err != nil {
			t.Fatalf("json output is not a document: %v (%s)", err, js.String())
		}
		if len(doc) != 4 || doc["changed"] != false || doc["migrated"] != true {
			t.Errorf("json result = %v, want the unchanged legacy migration reported (changed=false, migrated=true)", doc)
		}
	})

	t.Run("principal", func(t *testing.T) {
		endpoint, tokenPath, _ := startRecordingLauncherCLIServer(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/principals/alice/allowed-roots" && r.Method == http.MethodPatch {
				writeJSONResponse(w, http.StatusOK, principalChangedResponse{
					OK: true, Username: "alice", Field: "allowed_roots", Changed: true,
					Path: "/a", Access: "read_only",
				})
				return
			}
			http.NotFound(w, r)
		})

		var human, hErr bytes.Buffer
		if code := runCommandWithWriters([]string{"principal", "allowed-root", "set-access", "--endpoint", endpoint, "--token-file", tokenPath, "alice", "/a", "read_only"}, &human, &hErr); code != 0 {
			t.Fatalf("human exit = %d (stderr=%s)", code, hErr.String())
		}
		if human.String() != "changed /a to access read_only on principal alice\n" {
			t.Errorf("human output = %q, want the shared line with the principal subject", human.String())
		}

		var js, jErr bytes.Buffer
		if code := runCommandWithWriters([]string{"principal", "allowed-root", "set-access", "--endpoint", endpoint, "--token-file", tokenPath, "--json", "alice", "/a", "read_only"}, &js, &jErr); code != 0 {
			t.Fatalf("json exit = %d (stderr=%s)", code, jErr.String())
		}
		var doc map[string]any
		if err := json.Unmarshal(js.Bytes(), &doc); err != nil {
			t.Fatalf("json output is not a document: %v (%s)", err, js.String())
		}
		if len(doc) != 3 || doc["path"] != "/a" || doc["access"] != "read_only" || doc["changed"] != true {
			t.Errorf("json result = %v, want exactly {path, access, changed}", doc)
		}
	})

	t.Run("principal unchanged stays success", func(t *testing.T) {
		endpoint, tokenPath, _ := startRecordingLauncherCLIServer(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/principals/alice/allowed-roots" && r.Method == http.MethodPatch {
				writeJSONResponse(w, http.StatusOK, principalChangedResponse{
					OK: true, Username: "alice", Field: "allowed_roots", Changed: false,
					Path: "/a", Access: "read_only", Message: "unchanged",
				})
				return
			}
			http.NotFound(w, r)
		})

		var human, hErr bytes.Buffer
		if code := runCommandWithWriters([]string{"principal", "allowed-root", "set-access", "--endpoint", endpoint, "--token-file", tokenPath, "alice", "/a", "read_only"}, &human, &hErr); code != 0 {
			t.Fatalf("human exit = %d (stderr=%s)", code, hErr.String())
		}
		if human.String() != "unchanged /a (access read_only) on principal alice\n" {
			t.Errorf("human output = %q, want the shared unchanged line with the subject", human.String())
		}
	})

	t.Run("principal missing target stays the failure", func(t *testing.T) {
		endpoint, tokenPath, _ := startRecordingLauncherCLIServer(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/principals/alice/allowed-roots" && r.Method == http.MethodPatch {
				writeJSONResponse(w, http.StatusNotFound, map[string]any{
					"ok": false, "code": "not_found", "message": "not found",
				})
				return
			}
			http.NotFound(w, r)
		})

		var human, hErr bytes.Buffer
		if code := runCommandWithWriters([]string{"principal", "allowed-root", "set-access", "--endpoint", endpoint, "--token-file", tokenPath, "alice", "/missing", "read_only"}, &human, &hErr); code == 0 {
			t.Fatalf("missing target exit = 0, want failure (stdout=%q)", human.String())
		}
		if strings.Contains(human.String(), "changed ") || strings.Contains(human.String(), "unchanged ") {
			t.Errorf("failed mutation must not print the shared success line: %q", human.String())
		}
	})

	t.Run("launcher", func(t *testing.T) {
		endpoint, tokenPath, _ := startRecordingLauncherCLIServer(t, func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/principals/alice/launchers/") && r.Method == http.MethodPatch {
				writeJSONResponse(w, http.StatusOK, launcherAllowedRootResponse{
					OK: true, LauncherID: "dhl_1", Field: "allowed_roots", Changed: true,
					Path: "/a", Access: "read_only",
				})
				return
			}
			http.NotFound(w, r)
		})

		var human, hErr bytes.Buffer
		if code := runCommandWithWriters([]string{"launcher", "allowed-root", "set-access", "--endpoint", endpoint, "--token-file", tokenPath, "--principal", "alice", "/a", "read_only", "build-agent"}, &human, &hErr); code != 0 {
			t.Fatalf("human exit = %d (stderr=%s)", code, hErr.String())
		}
		if human.String() != "changed /a to access read_only on launcher build-agent\n" {
			t.Errorf("human output = %q, want the shared line with the launcher subject", human.String())
		}

		var js, jErr bytes.Buffer
		if code := runCommandWithWriters([]string{"launcher", "allowed-root", "set-access", "--endpoint", endpoint, "--token-file", tokenPath, "--principal", "alice", "--json", "/a", "read_only", "build-agent"}, &js, &jErr); code != 0 {
			t.Fatalf("json exit = %d (stderr=%s)", code, jErr.String())
		}
		var doc map[string]any
		if err := json.Unmarshal(js.Bytes(), &doc); err != nil {
			t.Fatalf("json output is not a document: %v (%s)", err, js.String())
		}
		if len(doc) != 3 || doc["path"] != "/a" || doc["access"] != "read_only" || doc["changed"] != true {
			t.Errorf("json result = %v, want exactly {path, access, changed}", doc)
		}
	})
}
