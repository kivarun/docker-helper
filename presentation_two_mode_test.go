package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// twoModeJSON decodes the --json form of a command and fails when stdout is
// not exactly one JSON document (no human text mixed in).
func twoModeJSON(t *testing.T, stdout *bytes.Buffer, stderr *bytes.Buffer, code int) map[string]any {
	t.Helper()
	if code != 0 {
		t.Fatalf("exit = %d (stderr=%s)", code, stderr.String())
	}
	var doc map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("--json stdout is not one document: %v (%s)", err, stdout.String())
	}
	return doc
}

// TestPresentationTwoModeConfigSetUnsetAddRemove proves the local config
// mutation acknowledgements follow the canonical two-mode contract: the
// human ack line by default and the shared CLI-owned result object under
// --json, with operational notes on stderr under --json.
func TestPresentationTwoModeConfigSetUnsetAddRemove(t *testing.T) {
	setup := func(t *testing.T) string {
		root := testAllowedRootDir(t)
		data, _ := json.Marshal(map[string]any{"allowed_roots": []string{root}, "session_ttl": "12h"})
		setupConfigTestWithData(t, data)
		return root
	}

	t.Run("config set", func(t *testing.T) {
		setup(t)
		var stdout, stderr bytes.Buffer
		code := runCommandWithWriters([]string{"config", "set", "log_level", "debug", "--json"}, &stdout, &stderr)
		doc := twoModeJSON(t, &stdout, &stderr, code)
		if len(doc) != 3 || doc["field"] != "log_level" || doc["value"] != "debug" || doc["changed"] != true {
			t.Errorf("json result = %v, want {field, value, changed}", doc)
		}
	})

	t.Run("config set unchanged", func(t *testing.T) {
		setup(t)
		var h1, e1 bytes.Buffer
		if code := runCommandWithWriters([]string{"config", "set", "log_level", "debug"}, &h1, &e1); code != 0 || !strings.Contains(h1.String(), "updated log_level=debug") {
			t.Fatalf("human set = %d %q", code, h1.String())
		}
		var stdout, stderr bytes.Buffer
		code := runCommandWithWriters([]string{"config", "set", "log_level", "debug", "--json"}, &stdout, &stderr)
		doc := twoModeJSON(t, &stdout, &stderr, code)
		if len(doc) != 3 || doc["changed"] != false {
			t.Errorf("unchanged json result = %v, want changed=false", doc)
		}
	})

	t.Run("config unset", func(t *testing.T) {
		setup(t)
		var setOut, setErr bytes.Buffer
		if code := runCommandWithWriters([]string{"config", "set", "log_level", "debug"}, &setOut, &setErr); code != 0 {
			t.Fatalf("set exit = %d (stderr=%s)", code, setErr.String())
		}
		var stdout, stderr bytes.Buffer
		code := runCommandWithWriters([]string{"config", "unset", "log_level", "--json"}, &stdout, &stderr)
		doc := twoModeJSON(t, &stdout, &stderr, code)
		if len(doc) != 2 || doc["field"] != "log_level" || doc["changed"] != true {
			t.Errorf("json result = %v, want {field, changed:true} without a value", doc)
		}
	})

	t.Run("config allowed-root add", func(t *testing.T) {
		root := setup(t)
		inner := filepath.Join(root, "inner")
		if err := os.MkdirAll(inner, 0700); err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		code := runCommandWithWriters([]string{"config", "allowed-root", "add", inner, "--json"}, &stdout, &stderr)
		doc := twoModeJSON(t, &stdout, &stderr, code)
		if len(doc) != 3 || doc["path"] != inner || doc["access"] != "read_write" || doc["changed"] != true {
			t.Errorf("json result = %v, want {path, access, changed}", doc)
		}
	})

	t.Run("config allowed-root remove", func(t *testing.T) {
		root := setup(t)
		inner := filepath.Join(root, "inner")
		if err := os.MkdirAll(inner, 0700); err != nil {
			t.Fatal(err)
		}
		var addOut, addErr bytes.Buffer
		if code := runCommandWithWriters([]string{"config", "allowed-root", "add", inner}, &addOut, &addErr); code != 0 {
			t.Fatalf("add exit = %d (stderr=%s)", code, addErr.String())
		}
		var stdout, stderr bytes.Buffer
		code := runCommandWithWriters([]string{"config", "allowed-root", "remove", root, "--json"}, &stdout, &stderr)
		doc := twoModeJSON(t, &stdout, &stderr, code)
		if len(doc) != 2 || doc["path"] != root || doc["changed"] != true {
			t.Errorf("json result = %v, want {path, changed:true} without access", doc)
		}
	})
}

// TestPresentationTwoModeShowHumanDefaults proves the human-default forms of
// the newly normalized show surfaces.
func TestPresentationTwoModeShowHumanDefaults(t *testing.T) {
	t.Run("config show human field block", func(t *testing.T) {
		root := testAllowedRootDir(t)
		data, _ := json.Marshal(map[string]any{"allowed_roots": []string{root}, "session_ttl": "12h", "log_level": "debug"})
		setupConfigTestWithData(t, data)
		var stdout, stderr bytes.Buffer
		if code := runCommandWithWriters([]string{"config", "show"}, &stdout, &stderr); code != 0 {
			t.Fatalf("exit = %d (stderr=%s)", code, stderr.String())
		}
		human := stdout.String()
		for _, want := range []string{"session_ttl: 12h", "log_level: debug", "admin_token: <redacted>", "ALLOWED ROOTS", root, "read_write"} {
			if !strings.Contains(human, want) {
				t.Errorf("human config show missing %q:\n%s", want, human)
			}
		}
	})

	t.Run("launcher credential show human block", func(t *testing.T) {
		endpoint, tokenPath, _ := startRecordingLauncherCLIServer(t, func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/principals/alice/launchers/") && r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/credential") {
				writeJSONResponse(w, http.StatusOK, launcherCredentialResponse{
					OK:         true,
					Credential: &launcherCredentialJSON{ID: "dhcr_9", CreatedAt: "2026-09-17T00:00:00Z"},
				})
				return
			}
			http.NotFound(w, r)
		})
		var stdout, stderr bytes.Buffer
		if code := runCommandWithWriters([]string{"launcher", "credential", "show", "--endpoint", endpoint, "--token-file", tokenPath, "--principal", "alice", "build-agent"}, &stdout, &stderr); code != 0 {
			t.Fatalf("exit = %d (stderr=%s)", code, stderr.String())
		}
		for _, want := range []string{"ID:        dhcr_9", "CREATED:   2026-09-17T00:00:00Z", "REVOKED:   -"} {
			if !strings.Contains(stdout.String(), want) {
				t.Errorf("human credential show missing %q:\n%s", want, stdout.String())
			}
		}
	})
}

// TestPresentationTwoModeScalarCommands proves the scalar finite results
// follow the two-mode contract: the scalar human line by default and a
// minimal structured result under --json.
func TestPresentationTwoModeScalarCommands(t *testing.T) {
	t.Run("version", func(t *testing.T) {
		var human, hErr bytes.Buffer
		if code := runCommandWithWriters([]string{"version"}, &human, &hErr); code != 0 || strings.TrimSpace(human.String()) != version {
			t.Fatalf("human version = %d %q", code, human.String())
		}
		var stdout, stderr bytes.Buffer
		code := runCommandWithWriters([]string{"version", "--json"}, &stdout, &stderr)
		doc := twoModeJSON(t, &stdout, &stderr, code)
		if len(doc) != 1 || doc["version"] != version {
			t.Errorf("version --json = %v, want {version}", doc)
		}
	})

	t.Run("credential install", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("XDG_CONFIG_HOME", dir)
		token := "dhc_" + strings.Repeat("a", 64)
		var stdout, stderr bytes.Buffer
		// installCredential reads the token from stdin; runCommandWithWriters
		// owns the CLI surface, so drive the same seam through the CLI flag
		// path with a piped token file via --force-free non-tty stdin is not
		// reachable here: the install command reads os.Stdin directly. The
		// --json rendering is proven through the shared CLI handler with a
		// prepared credential file and the --force replacement path.
		if err := os.MkdirAll(filepath.Join(dir, "docker-helper"), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "docker-helper", "credential.token"), []byte(token+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		// Feed the token through the CLI's own stdin (the CLI reads os.Stdin
		// directly; substitute it for this process).
		oldStdin := os.Stdin
		r, w, _ := os.Pipe()
		_, _ = w.Write([]byte(token + "\n"))
		_ = w.Close()
		os.Stdin = r
		code := runCommandWithWriters([]string{"credential", "install", "--force", "--json"}, &stdout, &stderr)
		os.Stdin = oldStdin
		_ = r.Close()
		doc := twoModeJSON(t, &stdout, &stderr, code)
		if len(doc) != 1 || !strings.Contains(doc["path"].(string), "credential.token") {
			t.Errorf("install --json = %v, want {path}", doc)
		}
	})
}

// TestPresentationTwoModeLauncherMutations proves the launcher-family
// human-default conversions and daemon-document --json forms.
func TestPresentationTwoModeLauncherMutations(t *testing.T) {
	launcherBody := `{"id":"dhl_1","principal":"alice","name":"build-agent","enabled":true,"scope":"inherit","allowed_roots":[],"created_at":"2026-09-17T00:00:00Z"}`

	t.Run("launcher set human block + --json document", func(t *testing.T) {
		endpoint, tokenPath, requests := startRecordingLauncherCLIServer(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPatch {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(launcherBody))
				return
			}
			http.NotFound(w, r)
		})
		base := []string{"launcher", "set", "--endpoint", endpoint, "--token-file", tokenPath, "--principal", "alice", "--name", "renamed", "build-agent"}

		var human, hErr bytes.Buffer
		if code := runCommandWithWriters(base, &human, &hErr); code != 0 {
			t.Fatalf("human exit = %d (stderr=%s)", code, hErr.String())
		}
		for _, want := range []string{"ID:        dhl_1", "NAME:      build-agent", "SCOPE:     inherit"} {
			if !strings.Contains(human.String(), want) {
				t.Errorf("human launcher set missing %q:\n%s", want, human.String())
			}
		}

		var js, jErr bytes.Buffer
		if code := runCommandWithWriters(append(append([]string{}, base[:len(base)-1]...), "--json", "build-agent"), &js, &jErr); code != 0 {
			t.Fatalf("json exit = %d (stderr=%s)", code, jErr.String())
		}
		var doc map[string]any
		if err := json.Unmarshal(js.Bytes(), &doc); err != nil {
			t.Fatalf("json output is not a document: %v (%s)", err, js.String())
		}
		if doc["name"] != "build-agent" || doc["id"] != "dhl_1" {
			t.Errorf("json document = %v, want the canonical launcher document", doc)
		}
		_ = requests
	})

	t.Run("launcher delete --json result", func(t *testing.T) {
		endpoint, tokenPath, requests := startRecordingLauncherCLIServer(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodDelete {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			http.NotFound(w, r)
		})
		var human, hErr bytes.Buffer
		if code := runCommandWithWriters([]string{"launcher", "delete", "--endpoint", endpoint, "--token-file", tokenPath, "--principal", "alice", "build-agent"}, &human, &hErr); code != 0 {
			t.Fatalf("human exit = %d (stderr=%s)", code, hErr.String())
		}
		if strings.TrimSpace(human.String()) != "deleted launcher build-agent" {
			t.Errorf("human delete = %q", human.String())
		}
		var js, jErr bytes.Buffer
		if code := runCommandWithWriters([]string{"launcher", "delete", "--endpoint", endpoint, "--token-file", tokenPath, "--principal", "alice", "--json", "build-agent"}, &js, &jErr); code != 0 {
			t.Fatalf("json exit = %d (stderr=%s)", code, jErr.String())
		}
		var doc map[string]any
		if err := json.Unmarshal(js.Bytes(), &doc); err != nil {
			t.Fatalf("json output is not a document: %v (%s)", err, js.String())
		}
		if len(doc) != 2 || doc["launcher"] != "build-agent" || doc["deleted"] != true {
			t.Errorf("json delete result = %v, want {launcher, deleted:true}", doc)
		}
		_ = requests
	})

	t.Run("launcher credential rotate human block + --json", func(t *testing.T) {
		endpoint, tokenPath, _ := startRecordingLauncherCLIServer(t, func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/credential/rotate") && r.Method == http.MethodPost {
				writeJSONResponse(w, http.StatusOK, launcherCredentialResponse{
					OK:         true,
					Credential: &launcherCredentialJSON{ID: "dhcr_1", CreatedAt: "2026-09-17T00:00:00Z"},
					Token:      "secret-lc-rotate-1",
				})
				return
			}
			http.NotFound(w, r)
		})
		base := []string{"launcher", "credential", "rotate", "--endpoint", endpoint, "--token-file", tokenPath, "--principal", "alice", "build-agent"}

		var human, hErr bytes.Buffer
		if code := runCommandWithWriters(base, &human, &hErr); code != 0 {
			t.Fatalf("human exit = %d (stderr=%s)", code, hErr.String())
		}
		for _, want := range []string{"ID:        dhcr_1", "TOKEN:     secret-lc-rotate-1"} {
			if !strings.Contains(human.String(), want) {
				t.Errorf("human rotate missing %q:\n%s", want, human.String())
			}
		}

		var js, jErr bytes.Buffer
		if code := runCommandWithWriters(append(append([]string{}, base[:len(base)-1]...), "--json", "build-agent"), &js, &jErr); code != 0 {
			t.Fatalf("json exit = %d (stderr=%s)", code, jErr.String())
		}
		var doc map[string]any
		if err := json.Unmarshal(js.Bytes(), &doc); err != nil {
			t.Fatalf("json output is not a document: %v (%s)", err, js.String())
		}
		if doc["token"] != "secret-lc-rotate-1" {
			t.Errorf("json rotate = %v, want the issuance document", doc)
		}
	})
}
