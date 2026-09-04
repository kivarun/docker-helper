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

// ---- principal credential CLI (mock daemon) ----

// TestPrincipalCredentialListCLIInfersPrincipal proves the scope-aware
// principal credential list: without an explicit selector the CLI performs
// /auth introspection and lists the authenticated Principal credential's own
// principal — no positional argument required.
func TestPrincipalCredentialListCLIInfersPrincipal(t *testing.T) {
	endpoint, tokenPath, requests := startRecordingLauncherCLIServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/auth" && r.Method == http.MethodGet:
			writeJSONResponse(w, http.StatusOK, authResponse{Authority: "principal", Principal: "alice"})
		case r.URL.Path == "/principals/alice/credentials" && r.Method == http.MethodGet:
			writeJSONResponse(w, http.StatusOK, listCredentialsResponse{
				OK: true,
				Credentials: []credentialJSON{
					{ID: "dhcr_1", Name: "default", CreatedAt: "2026-01-01T00:00:00Z"},
				},
			})
		default:
			http.NotFound(w, r)
		}
	})

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{
		"principal", "credential", "list", "--endpoint", endpoint, "--token-file", tokenPath,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, stderr.String())
	}
	if len(*requests) != 2 || (*requests)[0].path != "/auth" || (*requests)[1].path != "/principals/alice/credentials" {
		t.Fatalf("requests = %+v, want /auth then nested list", *requests)
	}
	if !strings.Contains(stdout.String(), "dhcr_1") || !strings.Contains(stdout.String(), "default") {
		t.Errorf("stdout missing credential row: %s", stdout.String())
	}
}

// TestPrincipalCredentialListCLIAdminRequiresExplicitSelector proves admin
// authentication must name the Principal explicitly for the credential list;
// the error occurs after auth introspection and before any list request.
func TestPrincipalCredentialListCLIAdminRequiresExplicitSelector(t *testing.T) {
	endpoint, tokenPath, requests := startRecordingLauncherCLIServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/auth" && r.Method == http.MethodGet:
			writeJSONResponse(w, http.StatusOK, authResponse{Authority: "admin"})
		default:
			http.NotFound(w, r)
		}
	})

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{
		"principal", "credential", "list", "--endpoint", endpoint, "--token-file", tokenPath,
	}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (stderr=%s)", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "PRINCIPAL is required for admin authentication") {
		t.Errorf("stderr missing admin selector requirement: %s", stderr.String())
	}
	if len(*requests) != 1 || (*requests)[0].path != "/auth" {
		t.Fatalf("requests = %+v, want only /auth (no list request)", *requests)
	}
}

// TestPrincipalCredentialListCLIAdminExplicitSkipsAuth proves an explicit
// selector goes straight to the nested list endpoint with no /auth call: the
// daemon remains the authorization authority.
func TestPrincipalCredentialListCLIAdminExplicitSkipsAuth(t *testing.T) {
	endpoint, tokenPath, requests := startRecordingLauncherCLIServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/principals/bob/credentials" && r.Method == http.MethodGet:
			writeJSONResponse(w, http.StatusOK, listCredentialsResponse{OK: true})
		default:
			http.NotFound(w, r)
		}
	})

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{
		"principal", "credential", "list", "--endpoint", endpoint, "--token-file", tokenPath, "bob",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, stderr.String())
	}
	if len(*requests) != 1 || (*requests)[0].path != "/principals/bob/credentials" {
		t.Fatalf("requests = %+v, want only the nested list", *requests)
	}
	if !strings.Contains(stdout.String(), "No credentials for bob") {
		t.Errorf("stdout missing empty list notice: %s", stdout.String())
	}
}

// TestPrincipalCredentialListCLILauncherCredentialRejected proves a Launcher
// credential bearer cannot drive the Principal credential list.
func TestPrincipalCredentialListCLILauncherCredentialRejected(t *testing.T) {
	endpoint, tokenPath, requests := startRecordingLauncherCLIServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/auth" && r.Method == http.MethodGet:
			writeJSONResponse(w, http.StatusOK, authResponse{Authority: "launcher", LauncherID: "dhl_9"})
		default:
			http.NotFound(w, r)
		}
	})

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{
		"principal", "credential", "list", "--endpoint", endpoint, "--token-file", tokenPath,
	}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (stderr=%s)", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "Launcher credentials do not manage Principal credentials") {
		t.Errorf("stderr missing launcher rejection: %s", stderr.String())
	}
	if len(*requests) != 1 {
		t.Fatalf("requests = %+v, want only /auth", *requests)
	}
}

// TestPrincipalCredentialRotateCLIDefaultAndNameSelector proves the rotate
// CLI: default call resolves the Principal via /auth and rotates "default";
// --name selects another named credential on the same single rotate request.
func TestPrincipalCredentialRotateCLIDefaultAndNameSelector(t *testing.T) {
	endpoint, tokenPath, requests := startRecordingLauncherCLIServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/auth" && r.Method == http.MethodGet:
			writeJSONResponse(w, http.StatusOK, authResponse{Authority: "principal", Principal: "alice"})
		case r.URL.Path == "/principals/alice/credentials/default/rotate" && r.Method == http.MethodPost:
			writeJSONResponse(w, http.StatusOK, createCredentialResponse{
				OK:         true,
				Credential: credentialJSON{ID: "dhcr_1", Name: "default", Principal: "alice"},
				Token:      "new-dhc-token",
			})
		case r.URL.Path == "/principals/alice/credentials/laptop/rotate" && r.Method == http.MethodPost:
			writeJSONResponse(w, http.StatusOK, createCredentialResponse{
				OK:         true,
				Credential: credentialJSON{ID: "dhcr_2", Name: "laptop", Principal: "alice"},
				Token:      "new-dhc-token-2",
			})
		default:
			http.NotFound(w, r)
		}
	})

	// Default rotation: /auth then one atomic rotate request.
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{
		"principal", "credential", "rotate", "--endpoint", endpoint, "--token-file", tokenPath,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("rotate default: exit = %d, stderr=%s", code, stderr.String())
	}
	if len(*requests) != 2 || (*requests)[0].path != "/auth" || (*requests)[1].path != "/principals/alice/credentials/default/rotate" {
		t.Fatalf("requests = %+v, want /auth then default rotate", *requests)
	}
	var resp createCredentialResponse
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		t.Fatalf("stdout not JSON: %v (%s)", err, stdout.String())
	}
	if resp.Token != "new-dhc-token" || resp.Credential.Name != "default" {
		t.Errorf("rotate response = %+v, want token+default name", resp)
	}

	// --name selects another named credential; same single-request shape.
	*requests = nil
	var stdout2, stderr2 bytes.Buffer
	code = runCommandWithWriters([]string{
		"principal", "credential", "rotate", "--name", "laptop", "--endpoint", endpoint, "--token-file", tokenPath,
	}, &stdout2, &stderr2)
	if code != 0 {
		t.Fatalf("rotate --name laptop: exit = %d, stderr=%s", code, stderr2.String())
	}
	if len(*requests) != 2 || (*requests)[1].path != "/principals/alice/credentials/laptop/rotate" {
		t.Fatalf("requests = %+v, want laptop rotate", *requests)
	}
	if err := json.Unmarshal(stdout2.Bytes(), &resp); err != nil {
		t.Fatalf("stdout2 not JSON: %v", err)
	}
	if resp.Token != "new-dhc-token-2" {
		t.Errorf("rotate --name laptop token = %q", resp.Token)
	}
}

// TestPrincipalCredentialRotateCLIAdminExplicit proves admin rotation with an
// explicit PRINCIPAL issues a single rotate request without auth introspection.
func TestPrincipalCredentialRotateCLIAdminExplicit(t *testing.T) {
	endpoint, tokenPath, requests := startRecordingLauncherCLIServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/principals/bob/credentials/default/rotate" && r.Method == http.MethodPost:
			writeJSONResponse(w, http.StatusOK, createCredentialResponse{
				OK:         true,
				Credential: credentialJSON{ID: "dhcr_3", Name: "default", Principal: "bob"},
				Token:      "new-dhc-token-3",
			})
		default:
			http.NotFound(w, r)
		}
	})

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{
		"principal", "credential", "rotate", "--endpoint", endpoint, "--token-file", tokenPath, "bob",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, stderr.String())
	}
	if len(*requests) != 1 || (*requests)[0].path != "/principals/bob/credentials/default/rotate" {
		t.Fatalf("requests = %+v, want single rotate request", *requests)
	}
}

// TestPrincipalCredentialCreateCLIProvesSingleCreateRequest proves the
// canonical create sends exactly one POST and prints the token once.
func TestPrincipalCredentialCreateCLIProvesSingleCreateRequest(t *testing.T) {
	endpoint, tokenPath, requests := startRecordingLauncherCLIServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/principals/alice/credentials" && r.Method == http.MethodPost:
			writeJSONResponse(w, http.StatusCreated, createCredentialResponse{
				OK:         true,
				Credential: credentialJSON{ID: "dhcr_7", Name: "default", Principal: "alice"},
				Token:      "create-secret-42",
			})
		default:
			http.NotFound(w, r)
		}
	})

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{
		"principal", "credential", "create", "--endpoint", endpoint, "--token-file", tokenPath, "alice",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, stderr.String())
	}
	if len(*requests) != 1 || (*requests)[0].path != "/principals/alice/credentials" {
		t.Fatalf("requests = %+v, want single create POST", *requests)
	}
	var req createCredentialRequest
	if err := json.Unmarshal([]byte((*requests)[0].body), &req); err != nil {
		t.Fatalf("decode create body %q: %v", (*requests)[0].body, err)
	}
	if req.Name != "default" {
		t.Errorf("create body name = %q, want default", req.Name)
	}
	if n := strings.Count(stdout.String(), "create-secret-42"); n != 1 {
		t.Errorf("token printed %d times on stdout, want 1", n)
	}
	if n := strings.Count(stderr.String(), "create-secret-42"); n != 0 {
		t.Errorf("token leaked on stderr %d times", n)
	}
}

// TestPrincipalCredentialRevokeCLIProvesSingleRevokeRequest proves revoke
// sends exactly one request and reports idempotent unchanged state.
func TestPrincipalCredentialRevokeCLIProvesSingleRevokeRequest(t *testing.T) {
	endpoint, tokenPath, requests := startRecordingLauncherCLIServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/credentials/dhcr_1/revoke" && r.Method == http.MethodPost:
			writeJSONResponse(w, http.StatusOK, revokeCredentialResponse{OK: true, Message: "unchanged"})
		default:
			http.NotFound(w, r)
		}
	})

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{
		"principal", "credential", "revoke", "--endpoint", endpoint, "--token-file", tokenPath, "dhcr_1",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, stderr.String())
	}
	if len(*requests) != 1 || (*requests)[0].path != "/credentials/dhcr_1/revoke" {
		t.Fatalf("requests = %+v, want single revoke POST", *requests)
	}
	if !strings.Contains(stdout.String(), "revoked dhcr_1") || !strings.Contains(stdout.String(), "was already revoked") {
		t.Errorf("stdout = %s, want revoked + unchanged notice", stdout.String())
	}
}

// ---- launcher credential CLI (create/show) ----

// TestLauncherCredentialCreateCLIProvesConflictOnSecondCreate proves the
// canonical launcher credential create uses the issue endpoint (PUT) and
// surfaces the daemon's already-exists conflict as a normal error.
func TestLauncherCredentialCreateCLIProvesConflictOnSecondCreate(t *testing.T) {
	endpoint, tokenPath, requests := startRecordingLauncherCLIServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/auth" && r.Method == http.MethodGet:
			writeJSONResponse(w, http.StatusOK, authResponse{Authority: "principal", Principal: "alice"})
		case r.URL.Path == "/principals/alice/launchers/default/credential" && r.Method == http.MethodPut:
			writeJSONResponse(w, http.StatusConflict, map[string]any{
				"ok":      false,
				"code":    "credential_already_exists",
				"message": "launcher already has a credential",
			})
		default:
			http.NotFound(w, r)
		}
	})

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{
		"launcher", "credential", "create", "--endpoint", endpoint, "--token-file", tokenPath,
	}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (stderr=%s)", code, stderr.String())
	}
	if len(*requests) != 2 || (*requests)[0].path != "/auth" || (*requests)[1].method != http.MethodPut {
		t.Fatalf("requests = %+v, want /auth then single PUT", *requests)
	}
	if !strings.Contains(stderr.String(), "credential_already_exists") {
		t.Errorf("stderr missing conflict code: %s", stderr.String())
	}
	if strings.Contains(stdout.String(), "credential") {
		t.Errorf("stdout must stay empty on conflict: %s", stdout.String())
	}
}

// TestLauncherCredentialShowCLIGetsCredential proves the canonical show verb
// issues a single GET against the launcher credential resource.
func TestLauncherCredentialShowCLIGetsCredential(t *testing.T) {
	endpoint, tokenPath, requests := startRecordingLauncherCLIServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/auth" && r.Method == http.MethodGet:
			writeJSONResponse(w, http.StatusOK, authResponse{Authority: "principal", Principal: "alice"})
		case r.URL.Path == "/principals/alice/launchers/default/credential" && r.Method == http.MethodGet:
			writeJSONResponse(w, http.StatusOK, launcherCredentialResponse{
				OK:         true,
				Credential: &launcherCredentialJSON{ID: "dhc_9"},
			})
		default:
			http.NotFound(w, r)
		}
	})

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{
		"launcher", "credential", "show", "--endpoint", endpoint, "--token-file", tokenPath,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, stderr.String())
	}
	if len(*requests) != 2 || (*requests)[0].path != "/auth" || (*requests)[1].method != http.MethodGet {
		t.Fatalf("requests = %+v, want /auth then single GET", *requests)
	}
	if !strings.Contains(stdout.String(), "dhc_9") {
		t.Errorf("stdout missing credential id: %s", stdout.String())
	}
}

// ---- Release 2.0 compatibility aliases ----

// TestCredentialAliasesShareCanonicalImplementations proves the top-level
// credential create/list/revoke aliases dispatch the exact same HTTP requests
// as the canonical principal credential commands — same paths, same methods,
// same bodies, no separate business logic.
func TestCredentialAliasesShareCanonicalImplementations(t *testing.T) {
	cases := []struct {
		name  string
		alias []string
		canon []string
		// respond serves the business request after the auth stub.
		respond func(w http.ResponseWriter, r *http.Request)
	}{
		{
			name:  "create",
			alias: []string{"credential", "create", "--endpoint", "EP", "--token-file", "TP", "alice"},
			canon: []string{"principal", "credential", "create", "--endpoint", "EP", "--token-file", "TP", "alice"},
			respond: func(w http.ResponseWriter, r *http.Request) {
				writeJSONResponse(w, http.StatusCreated, createCredentialResponse{
					OK:         true,
					Credential: credentialJSON{ID: "dhcr_7", Name: "default", Principal: "alice"},
					Token:      "alias-secret-42",
				})
			},
		},
		{
			name:  "list",
			alias: []string{"credential", "list", "--endpoint", "EP", "--token-file", "TP", "alice"},
			canon: []string{"principal", "credential", "list", "--endpoint", "EP", "--token-file", "TP", "alice"},
			respond: func(w http.ResponseWriter, r *http.Request) {
				writeJSONResponse(w, http.StatusOK, listCredentialsResponse{
					OK: true,
					Credentials: []credentialJSON{
						{ID: "dhcr_1", Name: "default", CreatedAt: "2026-01-01T00:00:00Z"},
					},
				})
			},
		},
		{
			name:  "revoke",
			alias: []string{"credential", "revoke", "--endpoint", "EP", "--token-file", "TP", "dhcr_1"},
			canon: []string{"principal", "credential", "revoke", "--endpoint", "EP", "--token-file", "TP", "dhcr_1"},
			respond: func(w http.ResponseWriter, r *http.Request) {
				writeJSONResponse(w, http.StatusOK, revokeCredentialResponse{OK: true, Message: "revoked"})
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var aliasOut, aliasErr, canonOut, canonErr bytes.Buffer
			endpoint, tokenPath, aliasReqs := startRecordingLauncherCLIServer(t, func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/auth" && r.Method == http.MethodGet:
					writeJSONResponse(w, http.StatusOK, authResponse{Authority: "principal", Principal: "alice"})
				default:
					tc.respond(w, r)
				}
			})
			args := append([]string{}, tc.alias...)
			for i, a := range args {
				if a == "EP" {
					args[i] = endpoint
				}
				if a == "TP" {
					args[i] = tokenPath
				}
			}
			code := runCommandWithWriters(args, &aliasOut, &aliasErr)
			if code != 0 {
				t.Fatalf("alias exit = %d, stderr=%s", code, aliasErr.String())
			}

			endpoint2, tokenPath2, canonReqs := startRecordingLauncherCLIServer(t, func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/auth" && r.Method == http.MethodGet:
					writeJSONResponse(w, http.StatusOK, authResponse{Authority: "principal", Principal: "alice"})
				default:
					tc.respond(w, r)
				}
			})
			args = append([]string{}, tc.canon...)
			for i, a := range args {
				if a == "EP" {
					args[i] = endpoint2
				}
				if a == "TP" {
					args[i] = tokenPath2
				}
			}
			code = runCommandWithWriters(args, &canonOut, &canonErr)
			if code != 0 {
				t.Fatalf("canonical exit = %d, stderr=%s", code, canonErr.String())
			}

			if len(*aliasReqs) != len(*canonReqs) {
				t.Fatalf("request counts differ: alias %d vs canonical %d", len(*aliasReqs), len(*canonReqs))
			}
			for i := range *aliasReqs {
				if (*aliasReqs)[i].method != (*canonReqs)[i].method || (*aliasReqs)[i].path != (*canonReqs)[i].path {
					t.Errorf("request %d differs: alias %s %s vs canonical %s %s",
						i, (*aliasReqs)[i].method, (*aliasReqs)[i].path, (*canonReqs)[i].method, (*canonReqs)[i].path)
				}
				if (*aliasReqs)[i].body != (*canonReqs)[i].body {
					t.Errorf("request %d body differs: alias %q vs canonical %q", i, (*aliasReqs)[i].body, (*canonReqs)[i].body)
				}
			}
			if aliasOut.String() != canonOut.String() {
				t.Errorf("stdout differs:\nalias: %q\ncanonical: %q", aliasOut.String(), canonOut.String())
			}
		})
	}
}

// TestCredentialAliasListPrincipalInference proves the alias list command
// keeps the same scope-aware inference as the canonical path.
func TestCredentialAliasListPrincipalInference(t *testing.T) {
	endpoint, tokenPath, requests := startRecordingLauncherCLIServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/auth" && r.Method == http.MethodGet:
			writeJSONResponse(w, http.StatusOK, authResponse{Authority: "principal", Principal: "alice"})
		case r.URL.Path == "/principals/alice/credentials" && r.Method == http.MethodGet:
			writeJSONResponse(w, http.StatusOK, listCredentialsResponse{OK: true})
		default:
			http.NotFound(w, r)
		}
	})

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{
		"credential", "list", "--endpoint", endpoint, "--token-file", tokenPath,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, stderr.String())
	}
	if len(*requests) != 2 || (*requests)[1].path != "/principals/alice/credentials" {
		t.Fatalf("requests = %+v, want /auth then nested list", *requests)
	}
	if !strings.Contains(stdout.String(), "No credentials for alice") {
		t.Errorf("stdout = %s", stdout.String())
	}
}

// TestCredentialInstallHelpIsGeneric proves the install help describes both
// credential kinds and none of the removed principal-only phrasings remain.
func TestCredentialInstallHelpIsGeneric(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"credential", "install", "--help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("install --help exit = %d, stderr=%s", code, stderr.String())
	}
	out := stdout.String()
	for _, banned := range []string{
		"Manage principal credentials",
		"principal credential token",
		"intended for principal users",
	} {
		if strings.Contains(out, banned) {
			t.Errorf("install help still contains %q:\n%s", banned, out)
		}
	}
	for _, required := range []string{
		"non-admin credential token",
		"a Principal or a Launcher",
		"owner and authorization scope",
	} {
		if !strings.Contains(out, required) {
			t.Errorf("install help missing %q:\n%s", required, out)
		}
	}
}

// TestCredentialInstallWithPrincipalAndLauncherBearers proves install accepts
// both bearer kinds: the store path is identical and the command does not
// attempt owner resolution locally.
func TestCredentialInstallWithPrincipalAndLauncherBearers(t *testing.T) {
	tokens := []string{
		"dhc_" + strings.Repeat("ab", 32),
		"dhc_" + strings.Repeat("cd", 32),
	}
	for _, tok := range tokens {
		t.Run(tok[4:8], func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("XDG_CONFIG_HOME", dir)
			orig := EffectiveUID
			defer func() { EffectiveUID = orig }()
			EffectiveUID = func() int { return 1000 }

			r, w, _ := os.Pipe()
			go func() {
				fmt.Fprintln(w, tok)
				w.Close()
			}()
			oldStdin := os.Stdin
			os.Stdin = r
			defer func() { os.Stdin = oldStdin }()

			var stdout, stderr bytes.Buffer
			code := runCommandWithWriters([]string{"credential", "install", "--force"}, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("install exit = %d, stderr=%s", code, stderr.String())
			}
			installedBytes, err := os.ReadFile(filepath.Join(dir, "docker-helper", "credential.token"))
			if err != nil {
				t.Fatalf("read installed credential: %v", err)
			}
			if got := strings.TrimSpace(string(installedBytes)); got != tok {
				t.Errorf("stored = %q, want %q", got, tok)
			}
		})
	}
}
