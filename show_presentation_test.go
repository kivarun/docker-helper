package main

import (
	"bytes"
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
