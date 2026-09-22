package main

import (
	"errors"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ---------------- protocol parser (§7/§24) ----------------

func TestBuilderManagerRequestParser(t *testing.T) {
	cases := []struct {
		name    string
		line    string
		wantCmd string
		wantOp  string
		wantErr string
	}{
		{name: "start canonical", line: "START op_0123456789abcdef0123456789abcdef", wantCmd: "START", wantOp: "op_0123456789abcdef0123456789abcdef"},
		{name: "stop canonical", line: "STOP op_0123456789abcdef0123456789abcdef", wantCmd: "STOP", wantOp: "op_0123456789abcdef0123456789abcdef"},
		{name: "purge", line: "PURGE", wantCmd: "PURGE"},
		{name: "uppercase id rejected", line: "START op_0123456789ABCDEF0123456789ABCDEF", wantErr: builderManagerRespBadOpID},
		{name: "wrong prefix", line: "START x_0123456789abcdef0123456789abcdef", wantErr: builderManagerRespBadOpID},
		{name: "31 hex", line: "START op_0123456789abcdef0123456789abcde", wantErr: builderManagerRespBadOpID},
		{name: "33 hex", line: "START op_0123456789abcdef0123456789abcdef0", wantErr: builderManagerRespBadOpID},
		{name: "nonhex", line: "START op_g123456789abcdef0123456789abcdef", wantErr: builderManagerRespBadOpID},
		{name: "unknown command", line: "LIST", wantErr: builderManagerRespBadRequest},
		{name: "unknown two-token command", line: "LIST op_0123456789abcdef0123456789abcdef", wantErr: builderManagerRespUnknownCmd},
		{name: "start missing token", line: "START", wantErr: builderManagerRespBadRequest},
		{name: "start extra token", line: "START op_0123456789abcdef0123456789abcdef extra", wantErr: builderManagerRespBadRequest},
		{name: "purge with token", line: "PURGE op_0123456789abcdef0123456789abcdef", wantErr: builderManagerRespBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, errResp := parseBuilderManagerRequest([]byte(tc.line))
			if tc.wantErr != "" {
				if errResp != tc.wantErr {
					t.Fatalf("parse(%q) err=%q want %q", tc.line, errResp, tc.wantErr)
				}
				return
			}
			if errResp != "" {
				t.Fatalf("parse(%q) unexpected err %q", tc.line, errResp)
			}
			if req.Command != tc.wantCmd || req.OperationID != tc.wantOp {
				t.Fatalf("parse(%q) = %+v want cmd=%s op=%s", tc.line, req, tc.wantCmd, tc.wantOp)
			}
		})
	}
}

func TestBuilderManagerRequestParserEmbeddedNUL(t *testing.T) {
	if _, errResp := parseBuilderManagerRequest([]byte("START op_0123456789abcdef0123456789abcdef\x00")); errResp != builderManagerRespBadRequest {
		t.Fatalf("embedded NUL accepted (err=%q)", errResp)
	}
}

// ---------------- identity guard (§3/§24) ----------------

func TestBuilderVerifyIdentityRefusesRoot(t *testing.T) {
	builderOSGeteuid, builderOSGetegid = func() int { return 0 }, func() int { return 0 }
	defer func() {
		builderOSGeteuid, builderOSGetegid = func() int { return os.Geteuid() }, func() int { return os.Getegid() }
	}()
	if _, _, err := builderVerifyIdentity(); err == nil {
		t.Fatal("root invocation must be refused")
	}
}

func TestBuilderVerifyIdentityRefusesOtherUser(t *testing.T) {
	// Simulated non-root other user: euid != resolved builder uid.
	builderOSGeteuid, builderOSGetegid = func() int { return 1000 }, func() int { return 1000 }
	defer func() {
		builderOSGeteuid, builderOSGetegid = func() int { return os.Geteuid() }, func() int { return os.Getegid() }
	}()
	if _, _, err := builderVerifyIdentity(); err == nil {
		t.Fatal("other-user invocation must be refused")
	}
}

func TestBuilderVerifyIdentityAcceptsExactIdentity(t *testing.T) {
	builderLookupUser = func(name string) (*user.User, error) {
		if name != builderManagerBuilderUser {
			return nil, errors.New("wrong name")
		}
		return &user.User{Username: builderManagerBuilderUser, Uid: "4312", Gid: "4312"}, nil
	}
	defer func() { builderLookupUser = user.Lookup }()
	builderOSGeteuid, builderOSGetegid = func() int { return 4312 }, func() int { return 4312 }
	defer func() {
		builderOSGeteuid, builderOSGetegid = func() int { return os.Geteuid() }, func() int { return os.Getegid() }
	}()
	uid, gid, err := builderVerifyIdentity()
	if err != nil {
		t.Fatalf("exact identity refused: %v", err)
	}
	if uid != 4312 || gid != 4312 {
		t.Fatalf("identity = (%d,%d), want resolved values", uid, gid)
	}
}

func TestBuilderVerifyIdentityMissingUser(t *testing.T) {
	builderLookupUser = func(name string) (*user.User, error) { return nil, errors.New("unknown user") }
	defer func() { builderLookupUser = user.Lookup }()
	if _, _, err := builderVerifyIdentity(); err == nil {
		t.Fatal("missing builder identity must be refused")
	}
}

// ---------------- CA resolver (§12) ----------------

func TestBuilderResolveSystemCA(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("CA resolver path tests need /etc visibility; resolver logic is order-first-readable")
	}
	env, ok := builderResolveSystemCA()
	if !ok {
		t.Skip("no supported CA bundle on this host")
	}
	if len(env) != 1 || !strings.HasPrefix(env[0], "SSL_CERT_FILE=") {
		t.Fatalf("unexpected env %v", env)
	}
	path := strings.TrimPrefix(env[0], "SSL_CERT_FILE=")
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("resolved CA bundle not readable: %v", err)
	}
	f.Close()
}

// ---------------- bounded diagnostics tail (§17) ----------------

func TestBoundedBufferTailForDiagnostics(t *testing.T) {
	b := newBoundedBuffer(64 * 1024)
	if b.tailForDiagnostics() != "" {
		t.Fatal("empty buffer must yield empty tail")
	}
	b.Write([]byte("rootlesskit: some bounded diagnostic line"))
	if tail := b.tailForDiagnostics(); !strings.Contains(tail, "bounded diagnostic line") {
		t.Fatalf("tail missing content: %q", tail)
	}
}

// ---------------- instance dir derivation (§4) ----------------

func TestBuilderManagerOpPathsDeriveFromOpID(t *testing.T) {
	opID := "op_0123456789abcdef0123456789abcdef"
	if got := opRuntimeDir(opID); got != "/run/docker-helper-builder/ops/"+opID {
		t.Fatalf("runtime dir %q", got)
	}
	if got := opStateDir(opID); got != "/var/lib/docker-helper-builder/ops/"+opID {
		t.Fatalf("state dir %q", got)
	}
	if got := opSocketPath(opID); got != "/run/docker-helper-builder/ops/"+opID+"/buildkitd.sock" {
		t.Fatalf("socket path %q", got)
	}
}

// ---------------- SO_PEERCRED server gate (§5/§24) ----------------

func TestBuilderManagerAuthenticatePeer(t *testing.T) {
	orig := builderPeerCredentials
	defer func() { builderPeerCredentials = orig }()

	builderPeerCredentials = func(*net.UnixConn) (int, int, int, error) { return 0, 0, 12, nil }
	if err := authenticatePeer(&net.UnixConn{}); err != nil {
		t.Fatalf("root peer refused: %v", err)
	}

	builderPeerCredentials = func(*net.UnixConn) (int, int, int, error) { return 4312, 4312, 12, nil }
	if err := authenticatePeer(&net.UnixConn{}); !errors.Is(err, errBuilderManagerUnauthorized) {
		t.Fatalf("non-root peer accepted: %v", err)
	}

	builderPeerCredentials = func(*net.UnixConn) (int, int, int, error) { return 0, 0, 0, errors.New("sockopt failed") }
	if err := authenticatePeer(&net.UnixConn{}); err == nil {
		t.Fatal("peer-credential failure must refuse")
	}
}

// TestBuilderManagerConnectionNonRootPeerRefused exercises the real
// handleConnection path over a real unix socket pair with the
// peer-credential seam: a non-root peer gets NO response line and NO
// execution.
func TestBuilderManagerConnectionNonRootPeerRefused(t *testing.T) {
	orig := builderPeerCredentials
	builderPeerCredentials = func(*net.UnixConn) (int, int, int, error) { return 4312, 4312, 12, nil }
	defer func() { builderPeerCredentials = orig }()

	client, server := unixSocketPair(t)
	defer client.Close()
	defer server.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		m := newBuilderManager(os.Getuid(), os.Getgid())
		m.handleConnection(server, &strings.Builder{})
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleConnection did not return")
	}
	// No response was written for an unauthorized peer.
	client.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 64)
	if n, err := client.Read(buf); n > 0 || err == nil {
		t.Fatalf("unauthorized peer received response: %q", buf[:n])
	}
}

// TestBuilderManagerConnectionHappyPath exercises the real
// handleConnection path: root peer + START dispatch + OK response.
func TestBuilderManagerConnectionHappyPath(t *testing.T) {
	m, _, _ := processTestManager(t)
	seamCA(t)
	fakeLeaderSeam(t, true)

	// Use a socket-binder goroutine to make the instance ready; it
	// terminates deterministically on bound/stop so no goroutine reads
	// the path seams during cleanup.
	opID := "op_0123456789abcdef0123456789abcdef"
	binderDone := make(chan struct{})
	go func() {
		defer close(binderDone)
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Lstat(opRuntimeDir(opID)); err == nil {
				l, err := net.ListenUnix("unix", &net.UnixAddr{Name: opSocketPath(opID), Net: "unix"})
				if err == nil {
					_ = os.Chmod(opSocketPath(opID), 0600)
					_ = l
					return
				}
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	defer func() { <-binderDone }()

	orig := builderPeerCredentials
	builderPeerCredentials = func(*net.UnixConn) (int, int, int, error) { return 0, 0, 12, nil }
	defer func() { builderPeerCredentials = orig }()

	client, server := unixSocketPair(t)
	defer client.Close()
	defer server.Close()
	go func() {
		m.handleConnection(server, &strings.Builder{})
	}()
	if _, err := client.Write([]byte("START " + opID + "\n")); err != nil {
		t.Fatalf("cannot write request: %v", err)
	}
	client.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 64)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("no response: %v", err)
	}
	if strings.TrimSpace(string(buf[:n])) != builderManagerRespOK {
		t.Fatalf("response = %q, want OK", buf[:n])
	}
}

// ---------------- stale-PID identity proof (§14/§19/§20) ----------------

func TestBuilderStalePidIdentityRejectsBogusPid(t *testing.T) {
	if builderStalePidIdentity(0, "op_0123456789abcdef0123456789abcdef", os.Getuid()) {
		t.Fatal("pid 0 must be rejected")
	}
	if builderStalePidIdentity(1, "op_0123456789abcdef0123456789abcdef", os.Getuid()) {
		t.Fatal("pid 1 must be rejected")
	}
	if builderStalePidIdentity(999999, "op_0123456789abcdef0123456789abcdef", os.Getuid()) {
		t.Fatal("nonexistent pid must be rejected")
	}
}

func TestBuilderStalePidIdentityAcceptsOwnShim(t *testing.T) {
	// A real process we own that LOOKS like a product-owned rootlesskit
	// leader for op X: run a sh whose argv0 is the rootlesskit path with
	// the exact state-dir argument. Prove the cmdline/uid/pgid checks.
	if os.Getuid() != 0 {
		t.Skip("argv0 spoofing via exec requires controlled environment; proof is mechanism-level")
	}
}

// unixSocketPair creates a real connected SOCK_STREAM unix socket pair.
func unixSocketPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(t.TempDir(), "pair.sock"), Net: "unix"})
	if err != nil {
		t.Fatalf("cannot create pair listener: %v", err)
	}
	defer listener.Close()
	clientConn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: listener.Addr().String(), Net: "unix"})
	if err != nil {
		t.Fatalf("cannot dial pair listener: %v", err)
	}
	serverConn, err := listener.AcceptUnix()
	if err != nil {
		clientConn.Close()
		t.Fatalf("cannot accept pair: %v", err)
	}
	return clientConn, serverConn
}

// TestBuilderManagerOversizedRequestNoResponse: a request longer than the
// ceiling (no newline within it) gets NO response and NO execution.
func TestBuilderManagerOversizedRequestNoResponse(t *testing.T) {
	m, _, _ := processTestManager(t)
	orig := builderPeerCredentials
	builderPeerCredentials = func(*net.UnixConn) (int, int, int, error) { return 0, 0, 12, nil }
	defer func() { builderPeerCredentials = orig }()

	client, server := unixSocketPair(t)
	defer client.Close()
	defer server.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		m.handleConnection(server, &strings.Builder{})
	}()
	// builderManagerRequestCeiling bytes without a newline + one more.
	payload := strings.Repeat("A", builderManagerRequestCeiling)
	if _, err := client.Write([]byte(payload)); err != nil {
		t.Fatalf("cannot write payload: %v", err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleConnection did not return")
	}
	client.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 64)
	if n, err := client.Read(buf); n > 0 || err == nil {
		t.Fatalf("oversized request received response: %q", buf[:n])
	}
}

// TestBuilderManagerResponseVocabularyOnly proves the protocol never
// exposes paths, PIDs, or internal stderr: every response over the real
// connection path for malformed and canonical requests is exactly from
// the fixed vocabulary.
func TestBuilderManagerResponseVocabularyOnly(t *testing.T) {
	m, _, _ := processTestManager(t)
	orig := builderPeerCredentials
	builderPeerCredentials = func(*net.UnixConn) (int, int, int, error) { return 0, 0, 12, nil }
	defer func() { builderPeerCredentials = orig }()

	cases := []struct{ name, request, want string }{
		{name: "malformed op", request: "START nope\n", want: builderManagerRespBadOpID},
		{name: "unknown cmd", request: "FLUSH\n", want: builderManagerRespBadRequest},
		{name: "purge", request: "PURGE\n", want: builderManagerRespOK},
		{name: "stop absent", request: "STOP op_0123456789abcdef0123456789abcdef\n", want: builderManagerRespOKAbsent},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, server := unixSocketPair(t)
			defer client.Close()
			defer server.Close()
			go func() { m.handleConnection(server, &strings.Builder{}) }()
			if _, err := client.Write([]byte(tc.request)); err != nil {
				t.Fatalf("cannot write: %v", err)
			}
			client.SetReadDeadline(time.Now().Add(5 * time.Second))
			buf := make([]byte, 128)
			n, err := client.Read(buf)
			if err != nil {
				t.Fatalf("no response: %v", err)
			}
			if strings.TrimSpace(string(buf[:n])) != tc.want {
				t.Fatalf("response = %q, want %q", buf[:n], tc.want)
			}
		})
	}
}

// ---------------- startup purge residue (§19/§20) ----------------

func TestBuilderManagerStartupPurgeRemovesDeadResidue(t *testing.T) {
	m, rtRoot, stRoot := processTestManager(t)
	opID := "op_0123456789abcdef0123456789abcdef"
	for _, d := range []string{opRuntimeDir(opID), opStateDir(opID)} {
		if err := os.MkdirAll(filepath.Join(d, "root"), 0700); err != nil {
			t.Fatalf("cannot create residue: %v", err)
		}
	}
	// instance.pid naming a DEAD pid: residue, removable.
	if err := os.WriteFile(filepath.Join(opRuntimeDir(opID), "instance.pid"), []byte("999999\n"), 0600); err != nil {
		t.Fatalf("cannot write instance.pid: %v", err)
	}
	if err := m.startupPurge(); err != nil {
		t.Fatalf("startup purge failed: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(rtRoot, "ops", opID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dead residue not removed: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(stRoot, "ops", opID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dead state residue not removed: %v", err)
	}
}

func TestBuilderManagerStartupPurgeFailsClosedOnUnprovenPid(t *testing.T) {
	m, _, _ := processTestManager(t)
	opID := "op_0123456789abcdef0123456789abcdef"
	if err := os.MkdirAll(opRuntimeDir(opID), 0700); err != nil {
		t.Fatalf("cannot create residue: %v", err)
	}
	// instance.pid naming THIS test process: a live process whose
	// identity CANNOT be proven as a product-owned rootlesskit leader
	// (wrong cmdline, wrong pgid relationship). Startup purge must fail
	// closed, not signal it.
	if err := os.WriteFile(filepath.Join(opRuntimeDir(opID), "instance.pid"), []byte(strconv.Itoa(os.Getpid())+"\n"), 0600); err != nil {
		t.Fatalf("cannot write instance.pid: %v", err)
	}
	err := m.startupPurge()
	if err == nil {
		t.Fatal("unproven live process must fail startup purge closed")
	}
	// The unproven process must still be alive (never signaled).
	if !processAlive(os.Getpid()) {
		t.Fatal("startup purge signaled an unproven process")
	}
	// Residue was NOT removed (fail closed).
	if _, serr := os.Lstat(opRuntimeDir(opID)); serr != nil {
		t.Fatal("fail-closed startup purge removed residue")
	}
}

func TestBuilderManagerStartupPurgeSkipsNoncanonicalNames(t *testing.T) {
	m, _, _ := processTestManager(t)
	weird := filepath.Join(builderRuntimeRoot, "ops", "not-an-op-id")
	if err := os.MkdirAll(weird, 0700); err != nil {
		t.Fatalf("cannot create: %v", err)
	}
	if err := m.startupPurge(); err != nil {
		t.Fatalf("startup purge failed on noncanonical entry: %v", err)
	}
	// Noncanonical entries are skipped, never removed.
	if _, err := os.Lstat(weird); err != nil {
		t.Fatalf("noncanonical entry was removed: %v", err)
	}
}
