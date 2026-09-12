//go:build linux

package main

// The interactive Readline completion regression: a real PTY, a real
// interactive Bash, and a real TAB. The synthetic harness tests set COMP_WORDS
// by hand, which can never reproduce the physical tokenization production
// completion faces: Readline breaks words at COMP_WORDBREAKS characters, so
// the inline --flag=VALUE form arrives as three physical words (--flag, =,
// VALUE). These tests type real lines and send real TAB keystrokes, proving
// the canonical normalized word view makes the separated --flag VALUE and
// inline --flag=VALUE forms drive identical daemon query semantics and offer
// identical suggestions under real Bash.

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// completionPTY drives an interactive bash over a real PTY.
type completionPTY struct {
	master *os.File
	cmd    *exec.Cmd

	mu       sync.Mutex
	out      bytes.Buffer
	consumed int
}

// startCompletionPTY starts an interactive bash with the completion script
// sourced, reading and writing through a freshly allocated PTY. The built
// docker-helper binary directory is prepended to PATH so the completed line
// and the completion's inner daemon queries resolve the same binary.
func startCompletionPTY(t *testing.T, script string) *completionPTY {
	t.Helper()
	binary := getCompletionBinary(t)

	masterFD, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Skipf("cannot open /dev/ptmx: %v", err)
	}
	master := os.NewFile(uintptr(masterFD), "/dev/ptmx")
	ptyNum, err := unix.IoctlGetUint32(masterFD, unix.TIOCGPTN)
	if err != nil {
		t.Fatalf("TIOCGPTN: %v", err)
	}
	if err := unix.IoctlSetPointerInt(masterFD, unix.TIOCSPTLCK, 0); err != nil {
		t.Fatalf("TIOCSPTLCK: %v", err)
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", ptyNum), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatalf("open pty slave: %v", err)
	}
	// A sane window size keeps Readline's redisplay deterministic.
	if err := unix.IoctlSetWinsize(masterFD, unix.TIOCSWINSZ, &unix.Winsize{Row: 40, Col: 120}); err != nil {
		t.Fatalf("TIOCSWINSZ: %v", err)
	}

	// The script is sourced through a file: typing a multi-KB here-document
	// through the PTY would be slow and fragile.
	scriptPath := filepath.Join(t.TempDir(), "completion.bash")
	if err := os.WriteFile(scriptPath, []byte(script), 0644); err != nil {
		t.Fatalf("write completion script: %v", err)
	}

	cmd := exec.Command("bash", "--noprofile", "--norc", "-i")
	cmd.Env = append(os.Environ(),
		"PS1=R> ",
		"TERM=xterm",
		"PATH="+filepath.Dir(binary)+":"+os.Getenv("PATH"),
	)
	cmd.Stdin = slave
	cmd.Stdout = slave
	cmd.Stderr = slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start interactive bash: %v", err)
	}

	p := &completionPTY{master: master, cmd: cmd}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := master.Read(buf)
			p.mu.Lock()
			p.out.Write(buf[:n])
			p.mu.Unlock()
			if err != nil {
				break
			}
		}
	}()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		_ = master.Close()
		_ = slave.Close()
	})

	// The first prompt proves the shell is reading input.
	p.waitNext(t, "R> ", 10*time.Second)
	p.send(t, "source "+scriptPath+"\n")
	// The next prompt proves sourcing finished.
	p.waitNext(t, "R> ", 10*time.Second)
	return p
}

// send writes raw bytes to the PTY master, i.e. types them into the shell.
func (p *completionPTY) send(t *testing.T, s string) {
	t.Helper()
	if _, err := p.master.WriteString(s); err != nil {
		t.Fatalf("write to pty: %v", err)
	}
}

// waitNext waits until want appears in the output after the consumed offset,
// then consumes through it and returns the segment. Bounded polling of the
// actual PTY state, never an estimated sleep.
func (p *completionPTY) waitNext(t *testing.T, want string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		p.mu.Lock()
		out := p.out.String()
		idx := strings.Index(out[p.consumed:], want)
		if idx >= 0 {
			p.consumed += idx + len(want)
			p.mu.Unlock()
			return out[:p.consumed]
		}
		p.mu.Unlock()
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %q after offset %d; pty output:\n%s", want, p.consumed, out)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// typeAndTab types a partial command line and sends a real TAB, then waits
// until the expected completion insertion appears in the PTY output and
// returns the segment produced by the completion. The insertion itself is the
// completion's observable result: Readline echoes every character it inserts.
func (p *completionPTY) typeAndTab(t *testing.T, line, expect string) string {
	t.Helper()
	p.send(t, line+"\t")
	return p.waitNext(t, expect, 10*time.Second)
}

// resetLine clears any half-typed input with Ctrl-U so the next case starts
// from an empty line.
func (p *completionPTY) resetLine(t *testing.T) {
	t.Helper()
	p.send(t, "\x15")
}

// completionPTYStubHandler builds the daemon surface the interactive cases
// drive, recording every request: an admin bearer answers --principal
// completion from the Principal list, a Principal bearer answers --launcher
// completion with its own Launchers, and the Session-create policy query
// narrows to the restricted root only for the typed killme launcher selector.
func completionPTYStubHandler(rec *policyQueryRecorder, optDir, homeDir string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.record(recordedRequest{r.Method, r.URL.Path, "", r.URL.RawQuery})
		admin := r.Header.Get("Authorization") == "Bearer admin-pty-token"
		switch {
		case r.URL.Path == "/auth" && r.Method == http.MethodGet:
			if admin {
				writeJSONResponse(w, http.StatusOK, authResponse{Authority: "admin"})
			} else {
				writeJSONResponse(w, http.StatusOK, authResponse{Authority: "principal", Principal: "michael"})
			}
		case r.URL.Path == "/principals" && r.Method == http.MethodGet:
			writeJSONResponse(w, http.StatusOK, listPrincipalsResponse{
				OK: true,
				Principals: []principalSummary{
					{Username: "foobar"}, {Username: "zebra"},
				},
			})
		case r.URL.Path == "/launchers" && r.Method == http.MethodGet:
			writeJSONResponse(w, http.StatusOK, listLaunchersResponse{
				OK: true,
				Launchers: []launcherJSON{
					{ID: "dhl_michaelkillme", Principal: "michael", Name: "killme"},
					{ID: "dhl_michaelworker", Principal: "michael", Name: "worker"},
				},
			})
		case r.URL.Path == "/sessions/create-policy" && r.Method == http.MethodGet:
			roots := []string{homeDir}
			if r.URL.Query().Get("launcher") == "killme" {
				roots = []string{optDir}
			}
			writeJSONResponse(w, http.StatusOK, sessionCreatePolicyResponse{
				OK: true, Principal: "alice", LauncherID: "dhl_michaelkillme", Launcher: "killme",
				AllowedRoots: roots,
			})
		default:
			http.NotFound(w, r)
		}
	})
}

// writeCompletionPTYToken writes one stub bearer token file.
func writeCompletionPTYToken(t *testing.T, base, name, token string) string {
	t.Helper()
	path := filepath.Join(base, name)
	if err := os.WriteFile(path, []byte(token), 0600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

// startCompletionPTYServer stubs the daemon over a Unix socket path. The
// endpoint is a socket path: the default COMP_WORDBREAKS breaks URLs at ':'
// and '/', which the HTTP cases below exercise deliberately.
func startCompletionPTYServer(t *testing.T) (sockPath, adminTokenPath, principalTokenPath string, rec *policyQueryRecorder, optDir string) {
	t.Helper()
	base := t.TempDir()
	optDir = filepath.Join(base, "opt", "alice")
	homeDir := filepath.Join(base, "home", "alice")
	for _, dir := range []string{optDir, homeDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	sockPath = filepath.Join(base, "dh-completion.sock")
	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	rec = &policyQueryRecorder{seen: make(chan recordedRequest, 64)}
	server := http.Server{Handler: completionPTYStubHandler(rec, optDir, homeDir)}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		_ = server.Close()
		_ = listener.Close()
		_ = os.Remove(sockPath)
	})
	adminTokenPath = writeCompletionPTYToken(t, base, "admin.token", "admin-pty-token")
	principalTokenPath = writeCompletionPTYToken(t, base, "principal.token", "principal-pty-token")
	return sockPath, adminTokenPath, principalTokenPath, rec, optDir
}

// startCompletionPTYHTTPServer stubs the same daemon surface over an explicit
// loopback HTTP endpoint, with its own request recorder so the tests can
// prove the completion query reached exactly the specified HTTP daemon.
func startCompletionPTYHTTPServer(t *testing.T) (httpEndpoint, adminTokenPath string, rec *policyQueryRecorder, optDir string) {
	t.Helper()
	base := t.TempDir()
	optDir = filepath.Join(base, "opt", "alice")
	homeDir := filepath.Join(base, "home", "alice")
	for _, dir := range []string{optDir, homeDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	rec = &policyQueryRecorder{seen: make(chan recordedRequest, 64)}
	server := httptest.NewServer(completionPTYStubHandler(rec, optDir, homeDir))
	t.Cleanup(server.Close)
	adminTokenPath = writeCompletionPTYToken(t, base, "admin.token", "admin-pty-token")
	return server.URL, adminTokenPath, rec, optDir
}

// TestCompletionInteractiveFlagFormsUnderRealBash types real interactive
// command lines and sends real TAB keystrokes over a PTY, proving the
// separated --flag VALUE and inline --flag=VALUE physical forms produce the
// same daemon query semantics and the same applicable suggestions under the
// default Readline word breaking: the inline form arrives as the three
// physical words (--flag, =, VALUE), which the canonical normalized word view
// merges back into one logical --flag=VALUE word.
func TestCompletionInteractiveFlagFormsUnderRealBash(t *testing.T) {
	sockPath, adminTokenPath, principalTokenPath, rec, optDir := startCompletionPTYServer(t)
	p := startCompletionPTY(t, completionScript(t))

	// --launcher ki<TAB> under a Principal credential: the own Launcher name.
	p.resetLine(t)
	out := p.typeAndTab(t, "docker-helper launcher create --endpoint "+sockPath+" --token-file "+principalTokenPath+" --launcher ki", "killme")
	if !strings.Contains(out, "killme") {
		t.Fatalf("separated --launcher ki<TAB>: completion output missing killme:\n%s", out)
	}

	// --launcher=ki<TAB>: the inline form, physically broken by Readline into
	// --launcher, =, ki — the same suggestion as the separated form.
	p.resetLine(t)
	out = p.typeAndTab(t, "docker-helper launcher create --endpoint "+sockPath+" --token-file "+principalTokenPath+" --launcher=ki", "killme")
	if !strings.Contains(out, "killme") {
		t.Fatalf("inline --launcher=ki<TAB>: completion output missing killme:\n%s", out)
	}

	// --principal foo<TAB> under an admin: the daemon's Principal list.
	p.resetLine(t)
	out = p.typeAndTab(t, "docker-helper launcher create --endpoint "+sockPath+" --token-file "+adminTokenPath+" --principal foo", "foobar")
	if !strings.Contains(out, "foobar") {
		t.Fatalf("separated --principal foo<TAB>: completion output missing foobar:\n%s", out)
	}

	// --principal=foo<TAB>: the inline form, same suggestion.
	p.resetLine(t)
	out = p.typeAndTab(t, "docker-helper launcher create --endpoint "+sockPath+" --token-file "+adminTokenPath+" --principal=foo", "foobar")
	if !strings.Contains(out, "foobar") {
		t.Fatalf("inline --principal=foo<TAB>: completion output missing foobar:\n%s", out)
	}

	// Session-create workspace completion with a typed separated selector:
	// the forwarded --launcher killme resolves the restricted root, whose
	// boundary completes in one TAB from the typed parent.
	p.resetLine(t)
	rec.snapshot() // drain prior requests
	out = p.typeAndTab(t, "docker-helper session create --endpoint "+sockPath+" --token-file "+adminTokenPath+" --launcher killme --workspace "+filepath.Dir(optDir), optDir)
	if !strings.Contains(out, optDir) {
		t.Fatalf("separated selector workspace <TAB>: completion output missing %s:\n%s", optDir, out)
	}
	assertCompletionPTYPolicyQuery(t, rec, "separated", optDir)

	// The inline selector form: the typed-selector extraction must reach the
	// policy query as launcher=killme — never as the bare = physical
	// boundary — so the same restricted root is offered and the daemon query
	// carries the same semantics.
	p.resetLine(t)
	rec.snapshot()
	out = p.typeAndTab(t, "docker-helper session create --endpoint "+sockPath+" --token-file "+adminTokenPath+" --launcher=killme --workspace "+filepath.Dir(optDir), optDir)
	if !strings.Contains(out, optDir) {
		t.Fatalf("inline selector workspace <TAB>: completion output missing %s:\n%s", optDir, out)
	}
	assertCompletionPTYPolicyQuery(t, rec, "inline", optDir)
}

// TestCompletionInteractiveExplicitHTTPEndpoint proves the explicit HTTP
// endpoint forms survive real Readline word breaking and drive the
// daemon-backed completion against the specified daemon: the default
// COMP_WORDBREAKS breaks http://HOST:PORT into the physical pieces
// (http, :, //HOST, :, PORT), which the canonical argument view reassembles
// into the full argument — so the operator forwarding carries the complete
// URL and the query hits exactly that daemon, with the same suggestions the
// Unix-socket control case offers and no generic filesystem fallback.
func TestCompletionInteractiveExplicitHTTPEndpoint(t *testing.T) {
	httpEndpoint, adminTokenPath, httpRec, httpOpt := startCompletionPTYHTTPServer(t)
	p := startCompletionPTY(t, completionScript(t))

	// Separated --endpoint with an http://HOST:PORT URL: --principal foo<TAB>
	// consults the specified HTTP daemon and offers its Principal names.
	p.resetLine(t)
	out := p.typeAndTab(t, "docker-helper launcher create --endpoint "+httpEndpoint+" --token-file "+adminTokenPath+" --principal foo", "foobar")
	if !strings.Contains(out, "foobar") {
		t.Fatalf("separated HTTP endpoint --principal foo<TAB>: completion output missing foobar:\n%s", out)
	}
	assertCompletionPTYHTTPQuery(t, httpRec, "separated endpoint", "/principals", "")

	// Inline --endpoint=URL: the same query semantics and suggestions.
	p.resetLine(t)
	httpRec.snapshot()
	out = p.typeAndTab(t, "docker-helper launcher create --endpoint="+httpEndpoint+" --token-file "+adminTokenPath+" --principal=foo", "foobar")
	if !strings.Contains(out, "foobar") {
		t.Fatalf("inline HTTP endpoint --principal=foo<TAB>: completion output missing foobar:\n%s", out)
	}
	assertCompletionPTYHTTPQuery(t, httpRec, "inline endpoint", "/principals", "")

	// Session-create workspace completion over the explicit HTTP endpoint
	// with a typed inline launcher selector: the restricted root, resolved
	// by the daemon the URL names — never the generic filesystem fallback.
	p.resetLine(t)
	httpRec.snapshot()
	out = p.typeAndTab(t, "docker-helper session create --endpoint "+httpEndpoint+" --token-file "+adminTokenPath+" --launcher=killme --workspace "+filepath.Dir(httpOpt), httpOpt)
	if !strings.Contains(out, httpOpt) {
		t.Fatalf("HTTP endpoint session workspace <TAB>: completion output missing %s:\n%s", httpOpt, out)
	}
	assertCompletionPTYHTTPQuery(t, httpRec, "session policy", "/sessions/create-policy", "launcher=killme")
}

// TestCompletionInteractiveFilesystemRootTreeNavigation proves the
// policy-root tree completion under a real interactive Bash and real TAB
// keystrokes: the /home/michael + /opt/michael sibling-boundary regression
// lists two distinguishable boundary segments (never two identical
// basenames), a unique boundary inserts as a navigable directory (filename
// semantics, trailing separator), the next TAB continues the navigation
// inside the boundary toward the root, and both the separated and the inline
// --filesystem-root forms drive the same daemon-backed tree — on the PATH
// side and, after a real '=' path, on the ACCESS side.
func TestCompletionInteractiveFilesystemRootTreeNavigation(t *testing.T) {
	base := t.TempDir()
	home := filepath.Join(base, "home", "michael")
	opt := filepath.Join(base, "opt", "michael")
	equalsDir := filepath.Join(home, "data", "foo=bar")
	for _, dir := range []string{filepath.Join(home, "BoxProbe"), opt, equalsDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	sockPath := filepath.Join(base, "dh-tree.sock")
	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	server := http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/sessions/create-policy" && r.Method == http.MethodGet {
			writeJSONResponse(w, http.StatusOK, sessionCreatePolicyResponse{
				OK: true, Principal: "michael", LauncherID: "dhl_x", Launcher: "agent",
				AllowedRoots: []string{home, opt},
			})
			return
		}
		http.NotFound(w, r)
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		_ = server.Close()
		_ = listener.Close()
		_ = os.Remove(sockPath)
	})
	tokenPath := writeCompletionPTYToken(t, base, "admin.token", "tree-pty-token")

	p := startCompletionPTY(t, completionScript(t))
	prefix := "docker-helper session create --endpoint " + sockPath + " --token-file " + tokenPath + " "

	// The sibling-boundary regression: from the roots' parent the listing
	// renders the distinguishable home/ and opt/ segments — never the two
	// identical michael/ basenames. The typed line and both TAB keystrokes
	// are sent together (typeAndTab convention); the listing is the
	// completion's observable result.
	p.resetLine(t)
	p.send(t, prefix+"--filesystem-root "+base+"/\t\t")
	out := p.waitNext(t, "opt/", 10*time.Second)
	if !strings.Contains(out, "home/") {
		t.Fatalf("boundary listing must contain both sibling segments:\n%s", out)
	}
	if strings.Contains(out, "michael") {
		t.Fatalf("boundary listing must not offer identical basenames:\n%s", out)
	}

	// A unique boundary from a partial component navigates as a directory:
	// /h<TAB> inserts <base>/home/ with filename semantics and the next TAB
	// continues inside it to the root (the chained result proves the unique
	// boundary stayed navigable instead of terminating the word).
	p.resetLine(t)
	p.send(t, prefix+"--filesystem-root "+base+"/h\t\t")
	p.waitNext(t, filepath.Join(base, "home", "michael")+"/", 10*time.Second)

	// The next two TABs enter the root: the entry TAB rings the bell (two
	// children) and the second TAB lists both.
	p.send(t, "\t\t")
	out = p.waitNext(t, "data/", 10*time.Second)
	if !strings.Contains(out, "BoxProbe/") {
		t.Fatalf("inside-root listing must offer both children:\n%s", out)
	}

	// The inline --filesystem-root=PATH form drives the same tree: /o<TAB>
	// navigates the opt boundary to its root in two TABs.
	p.resetLine(t)
	p.send(t, prefix+"--filesystem-root="+base+"/o\t\t")
	p.waitNext(t, filepath.Join(base, "opt", "michael")+"/", 10*time.Second)

	// The separated ACCESS side after a real '=' path: the final delimiter
	// completes the canonical access vocabulary. Each ACCESS prefix
	// disambiguates to one mode, and the inserted result proves the
	// vocabulary is offered behind the '=' path. Readline renders the
	// inserted word with the '=' separators quoted (they are word-break
	// characters), so the anchored display form carries the backslashes.
	p.resetLine(t)
	out = p.typeAndTab(t, prefix+"--filesystem-root "+equalsDir+"=read_o", "read_only")
	if !strings.Contains(out, `foo\=bar\=read_only`) {
		t.Fatalf("separated ACCESS completion after an '=' path inserted the wrong value:\n%s", out)
	}

	// The inline ACCESS form behind the '=' path completes identically.
	p.resetLine(t)
	out = p.typeAndTab(t, prefix+"--filesystem-root="+equalsDir+"=read_w", "read_write")
	if !strings.Contains(out, `foo\=bar\=read_write`) {
		t.Fatalf("inline ACCESS completion after an '=' path inserted the wrong value:\n%s", out)
	}
}

// TestCompletionInteractiveLauncherAllowedRootFirstPosition proves the
// first-positional contract of launcher allowed-root add/remove under a real
// interactive Bash and real TAB keystrokes: a slash-free word stays
// grammar-ambiguous (one positional means PATH for the default Launcher), so
// completion offers the union of the daemon-backed Launcher selectors and
// the filesystem candidates — a directory with the same prefix as a Launcher
// selector must survive — while a word containing a slash can only be the
// PATH (Launcher names never contain a slash) and completes filesystem
// candidates without a selector query.
func TestCompletionInteractiveLauncherAllowedRootFirstPosition(t *testing.T) {
	sockPath, _, principalTokenPath, rec, _ := startCompletionPTYServer(t)
	base := t.TempDir()
	home := filepath.Join(base, "home")
	for _, sub := range []string{"work", "workspaces", filepath.Join("foo", "bar")} {
		if err := os.MkdirAll(filepath.Join(home, sub), 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, "keepme"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}

	countLaunchers := func(rec *policyQueryRecorder) int {
		n := 0
		for _, req := range rec.snapshot() {
			if req.path == "/launchers" {
				n++
			}
		}
		return n
	}

	p := startCompletionPTY(t, completionScript(t))
	p.send(t, "cd "+home+"\n")
	p.waitNext(t, "R> ", 10*time.Second)

	// Empty first positional: the union of the Launcher selectors and the
	// working directory's entries. With no common prefix to insert, the
	// first TAB rings the bell and the second TAB lists the matches. The
	// wait anchor is the last listed candidate (LC_ALL=C order puts
	// "workspaces/" after "worker"), so the segment spans the whole line.
	p.resetLine(t)
	p.send(t, "docker-helper launcher allowed-root add --endpoint "+sockPath+" --token-file "+principalTokenPath+" ")
	p.waitNext(t, principalTokenPath, 10*time.Second)
	start := p.consumed
	p.send(t, "\t\t")
	out := p.waitNext(t, "workspaces/", 10*time.Second)[start:]
	if !strings.Contains(out, "worker") {
		t.Fatalf("first positional union must not lose the Launcher selectors:\n%s", out)
	}

	// Slash-free prefix "wo": the Launcher selector matching "wo" and the
	// relative PATH candidates matching "wo" — the first TAB inserts the
	// common prefix "work", a bell, then the listing shows the full union.
	p.resetLine(t)
	p.send(t, "docker-helper launcher allowed-root add --endpoint "+sockPath+" --token-file "+principalTokenPath+" wo")
	p.waitNext(t, "wo", 10*time.Second)
	start = p.consumed
	p.send(t, "\t\t\t")
	out = p.waitNext(t, "workspaces/", 10*time.Second)[start:]
	if !strings.Contains(out, "worker") {
		t.Fatalf("slash-free prefix union must offer both the selector and the directory candidates:\n%s", out)
	}

	// Slash word: the PATH candidates only, without a selector query.
	p.resetLine(t)
	p.send(t, "docker-helper launcher allowed-root add --endpoint "+sockPath+" --token-file "+principalTokenPath+" ./wo")
	p.waitNext(t, "./wo", 10*time.Second)
	start = p.consumed
	before := countLaunchers(rec)
	p.send(t, "\t\t\t")
	out = p.waitNext(t, "workspaces/", 10*time.Second)[start:]
	if strings.Contains(out, "worker") {
		t.Fatalf("slash word must not offer Launcher selectors:\n%s", out)
	}
	if got := countLaunchers(rec); got != before {
		t.Fatalf("slash word must not query selectors: %d new /launchers requests", got-before)
	}

	// Nested slash word foo/bar: filesystem only, still no selector query.
	// The single candidate is inserted directly; the segment is captured
	// before typing so the completed word is observable as one piece.
	p.resetLine(t)
	start = p.consumed
	before = countLaunchers(rec)
	p.send(t, "docker-helper launcher allowed-root add --endpoint "+sockPath+" --token-file "+principalTokenPath+" foo/ba\t")
	out = p.waitNext(t, "foo/bar/", 10*time.Second)[start:]
	if strings.Contains(out, "worker") {
		t.Fatalf("slash word must not offer Launcher selectors:\n%s", out)
	}
	if got := countLaunchers(rec); got != before {
		t.Fatalf("slash word must not query selectors: %d new /launchers requests", got-before)
	}

	// Slash word, remove: any filesystem entry, still no selector query.
	p.resetLine(t)
	before = countLaunchers(rec)
	p.send(t, "docker-helper launcher allowed-root remove --endpoint "+sockPath+" --token-file "+principalTokenPath+" ./ke\t")
	p.waitNext(t, "keepme", 10*time.Second)
	if got := countLaunchers(rec); got != before {
		t.Fatalf("remove slash word must not query selectors: %d new /launchers requests", got-before)
	}

	// Explicit first positional typed: the next position completes the
	// PATH only — the typed selector is never re-offered.
	p.resetLine(t)
	p.send(t, "docker-helper launcher allowed-root add --endpoint "+sockPath+" --token-file "+principalTokenPath+" worker ")
	p.waitNext(t, "worker ", 10*time.Second)
	start = p.consumed
	p.send(t, "\t\t")
	out = p.waitNext(t, "workspaces/", 10*time.Second)[start:]
	if strings.Contains(out, "worker") {
		t.Fatalf("PATH completion must not re-offer the typed selector:\n%s", out)
	}
}

// assertCompletionPTYHTTPQuery proves the specified HTTP daemon received the
// expected completion query after the preceding snapshot: the completion
// consulted exactly the endpoint named on the typed command line.
func assertCompletionPTYHTTPQuery(t *testing.T, rec *policyQueryRecorder, form, path, queryContains string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		for _, req := range rec.snapshot() {
			if req.path == path && (queryContains == "" || strings.Contains(req.query, queryContains)) {
				return
			}
			if req.path == path {
				t.Fatalf("%s: the HTTP daemon received %s with %q, want a query containing %q", form, path, req.query, queryContains)
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: the specified HTTP daemon received no %s query", form, path)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// assertCompletionPTYPolicyQuery proves the workspace completion's policy
// query carried the typed killme launcher selector (never the bare = physical
// boundary), so the restricted root came from the daemon's create-policy
// resolution and not from the generic filesystem fallback.
func assertCompletionPTYPolicyQuery(t *testing.T, rec *policyQueryRecorder, form, optDir string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		for _, req := range rec.snapshot() {
			if req.path != "/sessions/create-policy" {
				continue
			}
			if strings.Contains(req.query, "launcher=killme") {
				return
			}
			t.Fatalf("%s form: policy query carried %q, want launcher=killme", form, req.query)
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s form: no /sessions/create-policy query arrived", form)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
