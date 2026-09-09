package main

// Canonical one-time credential token install hint. Every CLI command that
// successfully issues a new bearer credential token shown exactly once prints
// the same canonical hint for its credential audience after the main result.
// The hint is a presentation concern: it never re-prints the token and never
// changes the wire contract. Commands whose main result is machine-readable
// JSON keep stdout pure JSON and render the hint on stderr.

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

const (
	// canonical one-time token warning shared by both audiences
	hintTokenWarning = "IMPORTANT: Save the token now. It will not be shown again."
	// principal-audience install instruction
	hintPrincipalInstall = "Give this token securely to the principal."
	hintPrincipalCommand = "The principal installs it with:"
	// launcher-audience install instruction
	hintLauncherInstall = "Install this token in the environment that will act as this Launcher:"
	// shared install command line
	hintInstallCommand = "  docker-helper credential install"
)

// assertPrincipalHint asserts the canonical principal-audience hint block in
// the given stream and that the one-time token never appears there.
func assertPrincipalHint(t *testing.T, stream string, streamName, token string) {
	t.Helper()
	for _, want := range []string{hintTokenWarning, hintPrincipalInstall, hintPrincipalCommand, hintInstallCommand} {
		if !strings.Contains(stream, want) {
			t.Errorf("%s missing canonical principal hint line %q:\n%s", streamName, want, stream)
		}
	}
	if strings.Contains(stream, hintLauncherInstall) {
		t.Errorf("%s must not carry the launcher-audience wording:\n%s", streamName, stream)
	}
	if token != "" && strings.Contains(stream, token) {
		t.Errorf("%s re-printed the one-time token:\n%s", streamName, stream)
	}
}

// assertLauncherHint asserts the canonical launcher-audience hint block in the
// given stream and that neither the token nor the human principal wording
// appears there.
func assertLauncherHint(t *testing.T, stream, streamName, token string) {
	t.Helper()
	for _, want := range []string{hintTokenWarning, hintLauncherInstall, hintInstallCommand} {
		if !strings.Contains(stream, want) {
			t.Errorf("%s missing canonical launcher hint line %q:\n%s", streamName, want, stream)
		}
	}
	if strings.Contains(stream, hintPrincipalInstall) || strings.Contains(stream, hintPrincipalCommand) {
		t.Errorf("%s must not carry the principal-audience wording:\n%s", streamName, stream)
	}
	if token != "" && strings.Contains(stream, token) {
		t.Errorf("%s re-printed the one-time token:\n%s", streamName, stream)
	}
}

// assertNoHint asserts no canonical hint appears in either stream.
func assertNoHint(t *testing.T, stdout, stderr string) {
	t.Helper()
	for _, stream := range []string{stdout, stderr} {
		if strings.Contains(stream, hintTokenWarning) {
			t.Errorf("no credential was issued, but a hint was printed:\n%s", stream)
		}
	}
}

// TestPrincipalCreateCredentialHint proves `principal create` prints the
// canonical principal install hint on stderr exactly when the create issued a
// credential, and that stdout stays pure machine-readable JSON with the token
// printed exactly once.
func TestPrincipalCreateCredentialHint(t *testing.T) {
	issue := func(t *testing.T, flags []string) (int, bytes.Buffer, bytes.Buffer) {
		t.Helper()
		endpoint, tokenPath, _ := startRecordingLauncherCLIServer(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/principals" && r.Method == http.MethodPost {
				body, _ := io.ReadAll(r.Body)
				issued := strings.Contains(string(body), `"issue_credential":true`)
				resp := principalResponse{
					OK:       true,
					Username: "bob",
				}
				if issued {
					resp.Credential = &principalCredentialJSON{ID: "dhcr_1", Principal: "bob", Name: "default"}
					resp.Token = "dhc_" + strings.Repeat("p", 40)
				}
				writeJSONResponse(w, http.StatusCreated, resp)
				return
			}
			http.NotFound(w, r)
		})
		args := append([]string{"principal", "create", "--endpoint", endpoint, "--token-file", tokenPath}, flags...)
		args = append(args, "bob")
		var stdout, stderr bytes.Buffer
		code := runCommandWithWriters(args, &stdout, &stderr)
		return code, stdout, stderr
	}

	// Credential issued: canonical hint on stderr, stdout stays JSON.
	code, stdout, stderr := issue(t, []string{"--issue-credential"})
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, stderr.String())
	}
	var resp principalResponse
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		t.Fatalf("stdout not pure JSON: %v (%s)", err, stdout.String())
	}
	if resp.Token != "dhc_"+strings.Repeat("p", 40) {
		t.Errorf("token in JSON = %q", resp.Token)
	}
	if got := strings.Count(stdout.String(), "dhc_"+strings.Repeat("p", 40)); got != 1 {
		t.Errorf("token printed %d times on stdout, want 1", got)
	}
	assertPrincipalHint(t, stderr.String(), "stderr", "dhc_"+strings.Repeat("p", 40))
	if strings.Contains(stdout.String(), hintTokenWarning) {
		t.Errorf("hint leaked into the machine-readable stdout:\n%s", stdout.String())
	}

	// No credential issued: no hint anywhere.
	code, stdout, stderr = issue(t, []string{"--no-credential"})
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, stderr.String())
	}
	assertNoHint(t, stdout.String(), stderr.String())
}

// TestPrincipalCredentialRotateCredentialHint proves the rotate path applies
// the same canonical principal hint after its machine-readable JSON result.
func TestPrincipalCredentialRotateCredentialHint(t *testing.T) {
	endpoint, tokenPath, requests := startRecordingLauncherCLIServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/auth" && r.Method == http.MethodGet:
			writeJSONResponse(w, http.StatusOK, authResponse{Authority: "principal", Principal: "alice"})
		case r.URL.Path == "/principals/alice/credentials/default/rotate" && r.Method == http.MethodPost:
			writeJSONResponse(w, http.StatusOK, principalCredentialTokenResponse{
				OK:         true,
				Credential: principalCredentialJSON{ID: "dhcr_1", Name: "default", Principal: "alice"},
				Token:      "dhc_" + strings.Repeat("r", 40),
			})
		default:
			http.NotFound(w, r)
		}
	})

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{
		"principal", "credential", "rotate", "--endpoint", endpoint, "--token-file", tokenPath,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, stderr.String())
	}
	if len(*requests) != 2 || (*requests)[1].path != "/principals/alice/credentials/default/rotate" {
		t.Fatalf("requests = %+v, want /auth then rotate", *requests)
	}
	var resp principalCredentialTokenResponse
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		t.Fatalf("stdout not pure JSON: %v (%s)", err, stdout.String())
	}
	if got := strings.Count(stdout.String(), "dhc_"+strings.Repeat("r", 40)); got != 1 {
		t.Errorf("token printed %d times on stdout, want 1", got)
	}
	assertPrincipalHint(t, stderr.String(), "stderr", "dhc_"+strings.Repeat("r", 40))
}

// TestPrincipalCredentialCreateCanonicalHint proves the human-readable create
// result carries the identical canonical principal hint on stdout (the same
// renderer every issuance path uses) and never re-prints the token there.
func TestPrincipalCredentialCreateCanonicalHint(t *testing.T) {
	endpoint, tokenPath, _ := startRecordingLauncherCLIServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/principals/alice/credentials" && r.Method == http.MethodPost {
			writeJSONResponse(w, http.StatusCreated, principalCredentialTokenResponse{
				OK:         true,
				Credential: principalCredentialJSON{ID: "dhcr_7", Name: "default", Principal: "alice"},
				Token:      "dhc_" + strings.Repeat("c", 40),
			})
			return
		}
		http.NotFound(w, r)
	})

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{
		"principal", "credential", "create", "--endpoint", endpoint, "--token-file", tokenPath, "alice",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, stderr.String())
	}
	assertPrincipalHint(t, stdout.String(), "stdout", "")
	// The main result legitimately prints the one-time token exactly once;
	// the canonical hint must never re-print it.
	if got := strings.Count(stdout.String(), "dhc_"+strings.Repeat("c", 40)); got != 1 {
		t.Errorf("token printed %d times on stdout, want 1:\n%s", got, stdout.String())
	}
	if strings.Contains(stderr.String(), hintTokenWarning) {
		t.Errorf("hint must not duplicate onto stderr:\n%s", stderr.String())
	}
}

// TestLauncherCreateCredentialHint proves launcher create renders the
// canonical launcher-audience hint on stderr only when the create issued a
// credential, with stdout kept as pure JSON.
func TestLauncherCreateCredentialHint(t *testing.T) {
	create := func(t *testing.T, issued bool, flags ...string) (int, bytes.Buffer, bytes.Buffer) {
		t.Helper()
		endpoint, tokenPath, _ := startRecordingLauncherCLIServer(t, func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/auth" && r.Method == http.MethodGet:
				writeJSONResponse(w, http.StatusOK, authResponse{Authority: "principal", Principal: "alice"})
			case r.URL.Path == "/principals/alice/launchers" && r.Method == http.MethodPost:
				body, _ := io.ReadAll(r.Body)
				issued := strings.Contains(string(body), `"issue_credential":true`)
				resp := createLauncherResponse{
					OK:       true,
					Launcher: launcherJSON{ID: "dhl_9", Principal: "alice", Name: "agent", Scope: "inherit", AllowedRoots: []string{}, Enabled: true},
				}
				if issued {
					resp.Credential = &launcherCredentialJSON{ID: "dhcr_9"}
					resp.Token = "dhc_" + strings.Repeat("l", 40)
				}
				writeJSONResponse(w, http.StatusCreated, resp)
			default:
				http.NotFound(w, r)
			}
		})
		args := append([]string{"launcher", "create", "--endpoint", endpoint, "--token-file", tokenPath}, flags...)
		args = append(args, "--name", "agent")
		var stdout, stderr bytes.Buffer
		code := runCommandWithWriters(args, &stdout, &stderr)
		return code, stdout, stderr
	}

	// Credential issued: canonical launcher hint on stderr, stdout pure JSON.
	code, stdout, stderr := create(t, true, "--issue-credential")
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, stderr.String())
	}
	var resp createLauncherResponse
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		t.Fatalf("stdout not pure JSON: %v (%s)", err, stdout.String())
	}
	if got := strings.Count(stdout.String(), "dhc_"+strings.Repeat("l", 40)); got != 1 {
		t.Errorf("token printed %d times on stdout, want 1", got)
	}
	assertLauncherHint(t, stderr.String(), "stderr", "dhc_"+strings.Repeat("l", 40))
	if strings.Contains(stdout.String(), hintTokenWarning) {
		t.Errorf("hint leaked into the machine-readable stdout:\n%s", stdout.String())
	}

	// No credential issued: no hint anywhere.
	code, stdout, stderr = create(t, false, "--no-credential")
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, stderr.String())
	}
	assertNoHint(t, stdout.String(), stderr.String())
}

// TestLauncherCredentialCreateAndRotateHint proves both launcher credential
// issuance verbs apply the same canonical launcher hint after their
// machine-readable JSON result.
func TestLauncherCredentialCreateAndRotateHint(t *testing.T) {
	cases := []struct {
		name  string
		verb  string
		serve func(w http.ResponseWriter, r *http.Request)
	}{
		{
			name: "create",
			verb: "create",
			serve: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/principals/alice/launchers/dhl_1/credential" && r.Method == http.MethodPut {
					writeJSONResponse(w, http.StatusCreated, launcherCredentialResponse{
						OK:         true,
						Credential: &launcherCredentialJSON{ID: "dhcr_5"},
						Token:      "dhc_" + strings.Repeat("k", 40),
					})
					return
				}
				http.NotFound(w, r)
			},
		},
		{
			name: "rotate",
			verb: "rotate",
			serve: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/principals/alice/launchers/dhl_1/credential/rotate" && r.Method == http.MethodPost {
					writeJSONResponse(w, http.StatusOK, launcherCredentialResponse{
						OK:         true,
						Credential: &launcherCredentialJSON{ID: "dhcr_5"},
						Token:      "dhc_" + strings.Repeat("t", 40),
					})
					return
				}
				http.NotFound(w, r)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			endpoint, tokenPath, _ := startRecordingLauncherCLIServer(t, tc.serve)
			args := []string{
				"launcher", "credential", tc.verb,
				"--endpoint", endpoint, "--token-file", tokenPath,
				"--principal", "alice", "dhl_1",
			}
			var stdout, stderr bytes.Buffer
			code := runCommandWithWriters(args, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("exit = %d, stderr=%s", code, stderr.String())
			}
			var resp launcherCredentialResponse
			if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
				t.Fatalf("stdout not pure JSON: %v (%s)", err, stdout.String())
			}
			if resp.Token == "" {
				t.Fatalf("no token in response: %s", stdout.String())
			}
			if got := strings.Count(stdout.String(), resp.Token); got != 1 {
				t.Errorf("token printed %d times on stdout, want 1", got)
			}
			assertLauncherHint(t, stderr.String(), "stderr", resp.Token)
		})
	}
}

// TestLauncherCredentialShowNoHint proves the token guard: a launcher
// credential response without a one-time token (show) renders no hint.
func TestLauncherCredentialShowNoHint(t *testing.T) {
	endpoint, tokenPath, _ := startRecordingLauncherCLIServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/auth" && r.Method == http.MethodGet:
			writeJSONResponse(w, http.StatusOK, authResponse{Authority: "principal", Principal: "alice"})
		case r.URL.Path == "/principals/alice/launchers/dhl_1/credential" && r.Method == http.MethodGet:
			writeJSONResponse(w, http.StatusOK, launcherCredentialResponse{
				OK:         true,
				Credential: &launcherCredentialJSON{ID: "dhcr_5"},
			})
		default:
			http.NotFound(w, r)
		}
	})

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{
		"launcher", "credential", "show", "--endpoint", endpoint, "--token-file", tokenPath,
		"--principal", "alice", "dhl_1",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, stderr.String())
	}
	assertNoHint(t, stdout.String(), stderr.String())
}
