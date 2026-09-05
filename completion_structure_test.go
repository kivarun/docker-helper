package main

import (
	"bytes"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// countGeneratedDefinition counts the emitted function definitions whose name
// matches the given pattern in the generated Bash completion script.
func countGeneratedDefinition(t *testing.T, script, pattern string) int {
	t.Helper()
	re := regexp.MustCompile(pattern)
	return len(re.FindAllString(script, -1))
}

// TestCompletionBashScriptSingleDefinitions protects the collapsed completion
// architecture: one canonical generator emits exactly one implementation of
// every logical function (no base implementation + later overlay redefining
// it) and exactly one registration whose registered function is the canonical
// entry _docker_helper_completion. Only the architectural definitions and the
// registration are counted — not the whole script.
func TestCompletionBashScriptSingleDefinitions(t *testing.T) {
	script := completionScript(t)

	// Exactly one subcommand-completion implementation.
	if got := countGeneratedDefinition(t, script, `(?m)^_docker_helper_complete_subcommands\(\) \{$`); got != 1 {
		t.Errorf("_docker_helper_complete_subcommands defined %d times, want exactly 1", got)
	}

	// Every emitted _docker_helper_* function is defined exactly once: a
	// second definition of any name is the base+overlay layering returning.
	names := regexp.MustCompile(`(?m)^_docker_helper_([a-z_]+)\(\) \{$`).FindAllStringSubmatch(script, -1)
	if len(names) == 0 {
		t.Fatal("no completion functions defined in the generated script")
	}
	seen := make(map[string]int, len(names))
	for _, m := range names {
		seen[m[1]]++
	}
	for name, count := range seen {
		if count != 1 {
			t.Errorf("completion function _%s defined %d times, want exactly 1", name, count)
		}
	}

	// Exactly one registration for docker-helper, and it registers the
	// canonical entry function.
	var registrations []string
	for _, line := range strings.Split(script, "\n") {
		if regexp.MustCompile(`^complete -F \S+ docker-helper$`).MatchString(line) {
			registrations = append(registrations, line)
		}
	}
	if len(registrations) != 1 {
		t.Fatalf("docker-helper registered %d times (%v), want exactly one complete -F registration", len(registrations), registrations)
	}
	registered := strings.Fields(registrations[0])[2]
	if registered != "_docker_helper_completion" {
		t.Errorf("registered completion function = %q, want the canonical _docker_helper_completion", registered)
	}

	// The collapsed wrapper must stay collapsed: no independently named
	// entrypoint layer may reappear between the registration and the entry.
	if strings.Contains(script, "_docker_helper_completion_entrypoint") {
		t.Error("script must not contain the collapsed entrypoint wrapper")
	}
}

// TestCompletionRootsPrincipalDeclaredFlags proves the declared invocation of
// `completion roots principal` is the final behavior: the command's real
// FlagSet, built directly from its NewInvocation with no runtime patch step,
// registers the complete supported flag set.
func TestCompletionRootsPrincipalDeclaredFlags(t *testing.T) {
	fs := flag.NewFlagSet("", flag.ContinueOnError)
	completionRootsPrincipalCommand.NewInvocation(fs)
	for _, name := range []string{"principal", "authority-only", "system", "endpoint", "token-file"} {
		if fs.Lookup(name) == nil {
			t.Errorf("declared FlagSet of completion roots principal is missing --%s", name)
		}
	}
}

// TestCompletionRootsPrincipalInvocationBehavior drives the declared
// invocation of `completion roots principal` through the real CLI dispatch
// against a stub daemon, proving the single declared command keeps both
// modes: --authority-only prints exactly the authenticated operator
// authority, an unknown authority or a query failure exits non-zero, and the
// normal mode prints the effective roots one per line.
func TestCompletionRootsPrincipalInvocationBehavior(t *testing.T) {
	run := func(t *testing.T, extraArgs []string, handler http.HandlerFunc) (stdout, stderr string, code int) {
		t.Helper()
		server := httptest.NewServer(handler)
		t.Cleanup(server.Close)
		tokenPath := filepath.Join(t.TempDir(), "token")
		if err := os.WriteFile(tokenPath, []byte("tok"), 0600); err != nil {
			t.Fatal(err)
		}
		args := append([]string{"--endpoint", server.URL, "--token-file", tokenPath}, extraArgs...)
		var outBuf, errBuf bytes.Buffer
		code = completionRootsPrincipalCommand.dispatchLeaf(
			args, []string{"completion", "roots", "principal"}, &outBuf, &errBuf)
		return outBuf.String(), errBuf.String(), code
	}

	t.Run("authority-only prints the operator authority", func(t *testing.T) {
		out, errOut, code := run(t, []string{"--authority-only"}, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/auth" {
				writeJSONResponse(w, http.StatusOK, authResponse{Authority: "launcher"})
				return
			}
			http.NotFound(w, r)
		})
		if code != 0 || errOut != "" {
			t.Fatalf("authority-only query failed (code=%d, stderr=%q)", code, errOut)
		}
		if strings.TrimSpace(out) != "launcher" {
			t.Fatalf("authority-only output = %q, want exactly the operator authority", out)
		}
	})

	t.Run("authority-only fails on an unknown authority", func(t *testing.T) {
		_, errOut, code := run(t, []string{"--authority-only"}, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/auth" {
				writeJSONResponse(w, http.StatusOK, authResponse{Authority: "mystery"})
				return
			}
			http.NotFound(w, r)
		})
		if code == 0 {
			t.Fatal("unknown authority must exit non-zero")
		}
		if !strings.Contains(errOut, "unknown authority") {
			t.Errorf("stderr = %q, want the unknown-authority diagnostic", errOut)
		}
	})

	t.Run("authority-only fails on a query failure", func(t *testing.T) {
		_, _, code := run(t, []string{"--authority-only"}, func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		})
		if code == 0 {
			t.Fatal("query failure must exit non-zero")
		}
	})

	t.Run("normal mode prints the effective roots", func(t *testing.T) {
		out, errOut, code := run(t, nil, func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/auth":
				writeJSONResponse(w, http.StatusOK, authResponse{Authority: "principal", Principal: "alice"})
			case r.URL.Path == "/principals/alice/effective-allowed-roots":
				writeJSONResponse(w, http.StatusOK, effectiveRootsResponse{
					OK: true, Principal: "alice", AllowedRoots: []string{"/roots/a", "/roots/b"},
				})
			default:
				http.NotFound(w, r)
			}
		})
		if code != 0 || errOut != "" {
			t.Fatalf("roots query failed (code=%d, stderr=%q)", code, errOut)
		}
		if got := strings.Split(strings.TrimSpace(out), "\n"); !slices.Equal(got, []string{"/roots/a", "/roots/b"}) {
			t.Fatalf("roots output = %q, want one root per line", out)
		}
	})
}
