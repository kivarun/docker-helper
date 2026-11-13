package main

import (
	"context"
	"errors"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// rpcTestEndpoint mounts a test unix endpoint for the client seam and
// returns the listener + the path (restored on cleanup).
func rpcTestEndpoint(t *testing.T) (*net.UnixListener, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "manager.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatalf("cannot create test endpoint: %v", err)
	}
	orig := builderClientSocketPath
	builderClientSocketPath = path
	t.Cleanup(func() {
		builderClientSocketPath = orig
		listener.Close()
	})
	return listener, path
}

// startHoldFixture is the test-owned fixture for handlers that hold an
// accepted START connection open without replying (the START-ambiguity
// proofs). The release channel is created in the owning test goroutine
// BEFORE the fake server starts and passed to every handler, so no handler
// ever registers cleanup itself. Cleanup closes the channel exactly once,
// stops the accept loop, and joins the accept goroutine and every
// connection handler BEFORE it returns — the later cleanups (peer/UID
// seams, socket-path restore) never observe a live handler, goroutine, or
// accepted connection.
type startHoldFixture struct {
	release  chan struct{}
	listener *net.UnixListener
	acceptor chan struct{} // closed when the accept loop has exited
	handlers sync.WaitGroup
}

func newStartHoldFixture(t *testing.T, listener *net.UnixListener) *startHoldFixture {
	t.Helper()
	f := &startHoldFixture{
		release:  make(chan struct{}),
		listener: listener,
		acceptor: make(chan struct{}),
	}
	t.Cleanup(func() {
		close(f.release)
		// Stop accepting first so no handler can be added after the
		// join below started (second Close is a no-op for the endpoint
		// cleanup).
		listener.Close()
		<-f.acceptor
		f.handlers.Wait()
	})
	return f
}

// serve runs the accept loop until the listener is closed. Each accepted
// connection is served by one tracked handler goroutine: it reads one
// bounded request line and calls handle; a non-empty return value is the
// exact response line, an empty return value holds the connection open
// without replying (the START ambiguity) until the release channel fires.
func (f *startHoldFixture) serve(handle func(line string) string) {
	go func() {
		defer close(f.acceptor)
		for {
			conn, err := f.listener.AcceptUnix()
			if err != nil {
				return
			}
			f.handlers.Add(1)
			go func() {
				defer f.handlers.Done()
				defer conn.Close()
				buf := make([]byte, builderManagerRequestCeiling)
				_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				n, err := conn.Read(buf)
				if err != nil {
					return
				}
				line := strings.TrimRight(string(buf[:n]), "\n")
				if reply := handle(line); reply != "" {
					_, _ = conn.Write([]byte(reply + "\n"))
				}
			}()
		}
	}()
}

// fakeManagerPeer replaces the client peer-credential seam so tests can
// prove the verify-before-write contract without real cross-UID peers.
func fakeManagerPeer(t *testing.T, uid, gid int) {
	t.Helper()
	orig := builderClientPeerCredentials
	builderClientPeerCredentials = func(*net.UnixConn) (int, int, int, error) { return uid, gid, 0, nil }
	t.Cleanup(func() { builderClientPeerCredentials = orig })
}

func fakeManagerUID(t *testing.T, uid, gid int) {
	t.Helper()
	orig := builderClientManagerUID
	builderClientManagerUID = func() (int, int, error) { return uid, gid, nil }
	t.Cleanup(func() { builderClientManagerUID = orig })
}

func TestBuilderClientRejectsWrongManagerPeerUID(t *testing.T) {
	listener, _ := rpcTestEndpoint(t)
	fakeManagerUID(t, 4312, 4312)
	fakeManagerPeer(t, 666, 4312)
	go func() {
		for {
			conn, err := listener.AcceptUnix()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	c := &builderManagerClient{}
	_, err := c.Start(context.Background(), "op_0123456789abcdef0123456789abcdef", nil)
	if err == nil {
		t.Fatal("wrong manager peer uid must be rejected before write")
	}
	var unreachable *builderClientUnreachable
	if !errors.As(err, &unreachable) {
		t.Fatalf("wrong peer must classify as unreachable, got %v", err)
	}
	if strings.Contains(err.Error(), "OK") {
		t.Fatalf("protocol vocabulary leaked into error: %v", err)
	}
}

func TestBuilderClientRejectsWrongManagerPeerGID(t *testing.T) {
	listener, _ := rpcTestEndpoint(t)
	fakeManagerUID(t, 4312, 4312)
	fakeManagerPeer(t, 4312, 666)
	go func() {
		for {
			conn, err := listener.AcceptUnix()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	c := &builderManagerClient{}
	if err := c.Purge(context.Background()); err == nil {
		t.Fatal("wrong manager peer gid must be rejected")
	}
}

// TestBuilderClientAmbiguousStartConvergesWithFreshContextStop: the read
// endpoint accepts and holds the connection open without replying; the
// START read times out; Start must converge with a fresh-context STOP and
// that STOP must actually reach the fake manager (proof: the fake manager
// records it) even though the caller context was already cancelled.
func TestBuilderClientAmbiguousStartConvergesWithFreshContextStop(t *testing.T) {
	listener, _ := rpcTestEndpoint(t)
	fakeManagerUID(t, 4312, 4312)
	fakeManagerPeer(t, 4312, 4312)

	requests := make(chan string, 8)
	f := newStartHoldFixture(t, listener)
	f.serve(func(line string) string {
		requests <- line
		if strings.HasPrefix(line, "STOP ") {
			return builderManagerRespOKAbsent
		}
		// START: hold the connection open without replying -> client
		// read timeout (ambiguous).
		return ""
	})

	c := &builderManagerClient{}
	ctx, cancel := context.WithCancel(context.Background())
	go time.AfterFunc(50*time.Millisecond, cancel)
	_, err := c.Start(ctx, "op_0123456789abcdef0123456789abcdef", nil)
	cancel()
	if err == nil {
		t.Fatal("ambiguous START must not report success")
	}

	// The convergence STOP must have arrived on a fresh context (the
	// caller context was cancelled before the STOP ran). Drain the
	// recorded START first, then require the STOP.
	deadline := time.After(10 * time.Second)
	for {
		select {
		case line := <-requests:
			if strings.HasPrefix(line, "STOP op_0123456789abcdef0123456789abcdef") {
				return // converged: prove branch reached
			}
			// START or another request: keep waiting for the STOP.
		case <-deadline:
			t.Fatal("convergence STOP never reached the manager")
		}
	}
}

// TestBuilderClientLostStopSingleRetry: STOP response ambiguous exactly
// once; the retry succeeds and no further attempts occur.
func TestBuilderClientLostStopSingleRetry(t *testing.T) {
	listener, _ := rpcTestEndpoint(t)
	fakeManagerUID(t, 4312, 4312)
	fakeManagerPeer(t, 4312, 4312)

	var stopMu sync.Mutex
	stopCount := 0
	go func() {
		attempts := 0
		for {
			conn, err := listener.AcceptUnix()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				buf := make([]byte, builderManagerRequestCeiling)
				_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				n, err := conn.Read(buf)
				if err != nil {
					return
				}
				line := strings.TrimRight(string(buf[:n]), "\n")
				if !strings.HasPrefix(line, "STOP ") {
					return
				}
				stopMu.Lock()
				attempts++
				stopCount = attempts
				got := attempts
				stopMu.Unlock()
				if got == 1 {
					// First attempt: unknowable (close without reply).
					return
				}
				_, _ = conn.Write([]byte(builderManagerRespOKAbsent + "\n"))
			}()
		}
	}()

	c := &builderManagerClient{}
	err := c.Stop(context.Background(), "op_0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("Stop with single ambiguous attempt must converge: %v", err)
	}
	stopMu.Lock()
	got := stopCount
	stopMu.Unlock()
	if got != 2 {
		t.Fatalf("stop attempts = %d, want exactly 2 (no infinite retry)", got)
	}
}

func TestBuilderClientLostStopTwiceUnknowable(t *testing.T) {
	listener, _ := rpcTestEndpoint(t)
	fakeManagerUID(t, 4312, 4312)
	fakeManagerPeer(t, 4312, 4312)
	go func() {
		for {
			conn, err := listener.AcceptUnix()
			if err != nil {
				return
			}
			// Always close without replying: both attempts unknowable.
			conn.Close()
		}
	}()
	c := &builderManagerClient{}
	err := c.Stop(context.Background(), "op_0123456789abcdef0123456789abcdef")
	if err == nil {
		t.Fatal("twice-unknowable STOP must return an internal cleanup error")
	}
}

func TestBuilderClientMapsWellFormedErr(t *testing.T) {
	listener, _ := rpcTestEndpoint(t)
	fakeManagerUID(t, 4312, 4312)
	fakeManagerPeer(t, 4312, 4312)
	go func() {
		for {
			conn, err := listener.AcceptUnix()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				buf := make([]byte, builderManagerRequestCeiling)
				_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				n, _ := conn.Read(buf)
				line := strings.TrimRight(string(buf[:n]), "\n")
				if strings.HasPrefix(line, "START ") {
					_, _ = conn.Write([]byte(builderManagerRespAtCeiling + "\n"))
				}
			}()
		}
	}()
	c := &builderManagerClient{}
	_, err := c.Start(context.Background(), "op_0123456789abcdef0123456789abcdef", nil)
	var mgrErr *builderManagerError
	if !errors.As(err, &mgrErr) {
		t.Fatalf("well-formed ERR must map to typed manager error, got %v", err)
	}
	if mgrErr.kind != builderManagerRespAtCeiling {
		t.Fatalf("mapped kind = %q", mgrErr.kind)
	}
}

func TestBuilderClientStartRefusesNoncanonicalID(t *testing.T) {
	c := &builderManagerClient{}
	if _, err := c.Start(context.Background(), "OP_UPPER", nil); err == nil {
		t.Fatal("noncanonical op id must be refused client-side")
	}
}

// TestBuilderClientAmbiguousStartErrStopIsNotProvenConvergence is the
// compensating-STOP regression: after an ambiguous START, a WELL-FORMED
// ERR reply from the compensating STOP must NOT count as proven
// convergence. The manager answered but refused the compensation — the
// operation instance may still be live — so Start must return an explicit
// refused-compensation failure, not the proven-convergence verdict of the
// OK/OK-absent path.
func TestBuilderClientAmbiguousStartErrStopIsNotProvenConvergence(t *testing.T) {
	listener, _ := rpcTestEndpoint(t)
	fakeManagerUID(t, 4312, 4312)
	fakeManagerPeer(t, 4312, 4312)
	f := newStartHoldFixture(t, listener)
	f.serve(func(line string) string {
		if strings.HasPrefix(line, "STOP ") {
			// The manager refuses the compensating STOP with a
			// well-formed protocol error.
			return builderManagerRespInternal
		}
		return "" // START held: ambiguous after cancel
	})
	c := &builderManagerClient{}
	ctx, cancel := context.WithCancel(context.Background())
	go time.AfterFunc(50*time.Millisecond, cancel)
	_, err := c.Start(ctx, "op_0123456789abcdef0123456789abcdef", nil)
	cancel()
	if err == nil {
		t.Fatal("refused compensation must fail closed")
	}
	if !strings.Contains(err.Error(), "compensating STOP was refused") {
		t.Fatalf("refused compensation must be the explicit failure, got %q", err)
	}
	// The refused-compensation failure wraps the manager's refusal kind.
	var mgrErr *builderManagerError
	if !errors.As(err, &mgrErr) || mgrErr.kind != builderManagerRespInternal {
		t.Fatalf("refused compensation must carry the manager refusal kind, got %v", err)
	}
}

// TestBuilderClientAmbiguousStartErrStopDistinctFromProvenConvergence
// proves the two verdicts are distinguishable: with an OK-absent
// compensating STOP the error is the proven-convergence verdict (no
// refused-compensation wording); with an ERR STOP it is the refused-
// compensation failure. The regression: both collapsed into the identical
// typed error.
func TestBuilderClientAmbiguousStartErrStopDistinctFromProvenConvergence(t *testing.T) {
	for _, tc := range []struct {
		name        string
		stopResp    string
		wantRefusal bool
	}{
		{name: "OK absent proves convergence", stopResp: builderManagerRespOKAbsent, wantRefusal: false},
		{name: "OK proves convergence", stopResp: builderManagerRespOK, wantRefusal: false},
		{name: "ERR internal refuses the compensation", stopResp: builderManagerRespInternal, wantRefusal: true},
		{name: "ERR operation_exists refuses the compensation", stopResp: builderManagerRespOpExists, wantRefusal: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener, _ := rpcTestEndpoint(t)
			fakeManagerUID(t, 4312, 4312)
			fakeManagerPeer(t, 4312, 4312)
			f := newStartHoldFixture(t, listener)
			f.serve(func(line string) string {
				if strings.HasPrefix(line, "STOP ") {
					return tc.stopResp
				}
				return "" // START held: ambiguous after cancel
			})
			c := &builderManagerClient{}
			ctx, cancel := context.WithCancel(context.Background())
			go time.AfterFunc(50*time.Millisecond, cancel)
			_, err := c.Start(ctx, "op_0123456789abcdef0123456789abcdef", nil)
			cancel()
			if err == nil {
				t.Fatal("ambiguous START must never report success")
			}
			gotRefusal := strings.Contains(err.Error(), "compensating STOP was refused")
			if gotRefusal != tc.wantRefusal {
				t.Fatalf("stopResp %q: refused-compensation verdict = %v, want %v (err: %v)", tc.stopResp, gotRefusal, tc.wantRefusal, err)
			}
		})
	}
}

// TestBuilderClientStartDeadlineBounded: an endpoint that never replies
// makes Start return boundedly (caller-context cancellation unblocks the
// read); the read deadline constant covers the no-cancel case.
func TestBuilderClientStartDeadlineBounded(t *testing.T) {
	listener, _ := rpcTestEndpoint(t)
	fakeManagerUID(t, 4312, 4312)
	fakeManagerPeer(t, 4312, 4312)
	f := newStartHoldFixture(t, listener)
	f.serve(func(line string) string {
		if strings.HasPrefix(line, "STOP ") {
			return builderManagerRespOKAbsent
		}
		return "" // START: hold, never reply
	})
	c := &builderManagerClient{}
	ctx, cancel := context.WithCancel(context.Background())
	go time.AfterFunc(100*time.Millisecond, cancel)
	start := time.Now()
	_, err := c.Start(ctx, "op_0123456789abcdef0123456789abcdef", nil)
	elapsed := time.Since(start)
	cancel()
	if err == nil {
		t.Fatal("no-reply endpoint must produce an error")
	}
	// Cancelled caller context: the Start must return boundedly, not
	// hang until the 60s read deadline.
	if elapsed > builderClientStopRead {
		t.Fatalf("Start returned after %v; not bounded by caller context", elapsed)
	}
}

// unused guards
var (
	_ = os.Geteuid
	_ = user.Lookup
)

// TestBuilderClientStartTypedCategorySuccessBoundaries proves the typed
// START success contract at the client boundary: exactly the canonical
// category tokens succeed and carry their parsed value to the caller,
// every other START success shape (bare OK, boundary-invalid, non-
// canonical, extra/missing tokens) is malformed — ambiguous — and the
// compensating STOP reaches the manager (fail-closed, no category).
func TestBuilderClientStartTypedCategorySuccessBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name     string
		response string
		want     builderCategory
		wantOK   bool
	}{
		{name: "c1", response: builderManagerStartSuccessResponse(builderCategory(1)), want: builderCategory(1), wantOK: true},
		{name: "c1023", response: builderManagerStartSuccessResponse(builderCategory(1023)), want: builderCategory(1023), wantOK: true},
		{name: "c7", response: builderManagerStartSuccessResponse(builderCategory(7)), want: builderCategory(7), wantOK: true},
		{name: "bare OK is malformed for START", response: builderManagerRespOK},
		{name: "c0 invalid", response: builderManagerStartSuccessResponse(builderCategory(0))},
		{name: "c1024 invalid", response: builderManagerStartSuccessResponse(builderCategory(1024))},
		{name: "zero-padded token noncanonical", response: "OK c01"},
		{name: "non-numeric token", response: "OK cx"},
		{name: "empty token", response: "OK "},
		{name: "double space", response: "OK  c1"},
		{name: "extra token", response: "OK c1 extra"},
		{name: "OK absent is malformed for START", response: builderManagerRespOKAbsent},
		{name: "no space", response: "OKc1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener, _ := rpcTestEndpoint(t)
			fakeManagerUID(t, 4312, 4312)
			fakeManagerPeer(t, 4312, 4312)

			requests := make(chan string, 8)
			go func() {
				for {
					conn, err := listener.AcceptUnix()
					if err != nil {
						return
					}
					go func() {
						defer conn.Close()
						buf := make([]byte, builderManagerRequestCeiling)
						_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
						n, err := conn.Read(buf)
						if err != nil {
							return
						}
						line := strings.TrimRight(string(buf[:n]), "\n")
						requests <- line
						switch {
						case strings.HasPrefix(line, "STOP "):
							_, _ = conn.Write([]byte(builderManagerRespOKAbsent + "\n"))
						case strings.HasPrefix(line, "START "):
							// Every case actually sends its scripted
							// response: the malformedness of each shape is
							// exercised on the wire, not approximated by
							// an EOF shortcut.
							_, _ = conn.Write([]byte(tc.response + "\n"))
						}
					}()
				}
			}()

			c := &builderManagerClient{}
			category, err := c.Start(context.Background(), "op_0123456789abcdef0123456789abcdef", nil)
			if !tc.wantOK {
				if err == nil {
					t.Fatalf("response %q must not report START success", tc.response)
				}
				if category != 0 {
					t.Fatalf("response %q returned category %s with an error", tc.response, category)
				}
				// Fail-closed proof: the compensating STOP reached the
				// manager (the malformed START response is ambiguous, and
				// only proven convergence ends the attempt).
				deadline := time.After(10 * time.Second)
				for {
					select {
					case line := <-requests:
						if strings.HasPrefix(line, "STOP op_0123456789abcdef0123456789abcdef") {
							return
						}
					case <-deadline:
						t.Fatalf("response %q: compensating STOP never reached the manager", tc.response)
					}
				}
			}
			if err != nil {
				t.Fatalf("response %q must report START success with the category, got %v", tc.response, err)
			}
			if category != tc.want {
				t.Fatalf("response %q returned category %s, want %s", tc.response, category, tc.want)
			}
			select {
			case line := <-requests:
				if strings.HasPrefix(line, "STOP ") {
					t.Fatalf("successful START must not compensate: STOP %q observed", line)
				}
			default:
			}
		})
	}
}

// TestBuilderClientStopRejectsCategorySuccessForm proves the wrong-command
// success form fails closed on STOP: "OK <token>" is malformed for STOP,
// the ambiguity retry runs exactly once, and a second malformed reply
// surfaces as the twice-unknowable failure — never as convergence.
func TestBuilderClientStopRejectsCategorySuccessForm(t *testing.T) {
	listener, _ := rpcTestEndpoint(t)
	fakeManagerUID(t, 4312, 4312)
	fakeManagerPeer(t, 4312, 4312)

	var stopMu sync.Mutex
	stopCount := 0
	go func() {
		for {
			conn, err := listener.AcceptUnix()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				buf := make([]byte, builderManagerRequestCeiling)
				_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				n, err := conn.Read(buf)
				if err != nil {
					return
				}
				line := strings.TrimRight(string(buf[:n]), "\n")
				if !strings.HasPrefix(line, "STOP ") {
					return
				}
				stopMu.Lock()
				stopCount++
				stopMu.Unlock()
				_, _ = conn.Write([]byte(builderManagerStartSuccessResponse(builderCategory(1)) + "\n"))
			}()
		}
	}()

	c := &builderManagerClient{}
	err := c.Stop(context.Background(), "op_0123456789abcdef0123456789abcdef")
	if err == nil {
		t.Fatal("a category success form must never report STOP convergence")
	}
	if !strings.Contains(err.Error(), "twice unknowable") {
		t.Fatalf("STOP must fail closed as twice unknowable, got %v", err)
	}
	stopMu.Lock()
	got := stopCount
	stopMu.Unlock()
	if got != 2 {
		t.Fatalf("stop attempts = %d, want exactly 2 (one ambiguity retry)", got)
	}
}

// TestBuilderClientPurgeRejectsCategorySuccessForm proves the
// wrong-command success form fails closed on PURGE: "OK <token>" is
// malformed for PURGE and must not report convergence.
func TestBuilderClientPurgeRejectsCategorySuccessForm(t *testing.T) {
	listener, _ := rpcTestEndpoint(t)
	fakeManagerUID(t, 4312, 4312)
	fakeManagerPeer(t, 4312, 4312)
	go func() {
		for {
			conn, err := listener.AcceptUnix()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				buf := make([]byte, builderManagerRequestCeiling)
				_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				n, err := conn.Read(buf)
				if err != nil {
					return
				}
				line := strings.TrimRight(string(buf[:n]), "\n")
				if line == builderManagerCmdPurge {
					_, _ = conn.Write([]byte(builderManagerStartSuccessResponse(builderCategory(1)) + "\n"))
				}
			}()
		}
	}()

	c := &builderManagerClient{}
	if err := c.Purge(context.Background()); err == nil {
		t.Fatal("a category success form must never report PURGE convergence")
	}
}

// TestBuilderClientStartFragmentedResponseCompletesToFullLine is the
// framing regression (P21-E-R1-C1): the manager sends "OK c1" WITHOUT the
// terminating newline and holds the connection open, then later completes
// the response as "0\n". The client must not interpret the incomplete
// prefix (never c1): it must still be waiting when only the fragment has
// arrived, and the final accepted category must be c10 — the complete
// line "OK c10".
func TestBuilderClientStartFragmentedResponseCompletesToFullLine(t *testing.T) {
	listener, _ := rpcTestEndpoint(t)
	fakeManagerUID(t, 4312, 4312)
	fakeManagerPeer(t, 4312, 4312)

	fragmentWritten := make(chan struct{})
	release := make(chan struct{})
	go func() {
		conn, err := listener.AcceptUnix()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, builderManagerRequestCeiling)
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Read(buf); err != nil {
			return
		}
		// Fragment one: an incomplete prefix — no terminating newline.
		_, _ = conn.Write([]byte("OK c1"))
		close(fragmentWritten)
		<-release
		// Fragment two completes the line: "OK c1" + "0\n" = "OK c10".
		_, _ = conn.Write([]byte("0\n"))
	}()

	c := &builderManagerClient{}
	result := make(chan struct {
		category builderCategory
		err      error
	}, 1)
	go func() {
		category, err := c.Start(context.Background(), "op_0123456789abcdef0123456789abcdef", nil)
		result <- struct {
			category builderCategory
			err      error
		}{category, err}
	}()

	<-fragmentWritten
	// The incomplete prefix must not have been accepted: Start is still
	// waiting for the terminating newline.
	select {
	case got := <-result:
		t.Fatalf("incomplete prefix accepted without the newline: category=%s err=%v", got.category, got.err)
	default:
	}

	close(release)
	select {
	case got := <-result:
		if got.err != nil {
			t.Fatalf("complete line must succeed, got %v", got.err)
		}
		if got.category != builderCategory(10) {
			t.Fatalf("final accepted category = %s, want c10 (the complete line)", got.category)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Start never consumed the completed response line")
	}
}

// TestBuilderClientStartTruncatedResponseEOFCompensates proves the
// truncated-response contract: a response prefix without a terminating
// newline followed by EOF is ambiguous (never a success), the
// compensating STOP reaches the manager, and no category is returned.
func TestBuilderClientStartTruncatedResponseEOFCompensates(t *testing.T) {
	listener, _ := rpcTestEndpoint(t)
	fakeManagerUID(t, 4312, 4312)
	fakeManagerPeer(t, 4312, 4312)

	requests := make(chan string, 8)
	go func() {
		for {
			conn, err := listener.AcceptUnix()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				buf := make([]byte, builderManagerRequestCeiling)
				_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				n, err := conn.Read(buf)
				if err != nil {
					return
				}
				line := strings.TrimRight(string(buf[:n]), "\n")
				requests <- line
				switch {
				case strings.HasPrefix(line, "STOP "):
					_, _ = conn.Write([]byte(builderManagerRespOKAbsent + "\n"))
				case strings.HasPrefix(line, "START "):
					// Truncated response: an incomplete prefix, then EOF.
					_, _ = conn.Write([]byte("OK c1"))
				}
			}()
		}
	}()

	c := &builderManagerClient{}
	category, err := c.Start(context.Background(), "op_0123456789abcdef0123456789abcdef", nil)
	if err == nil {
		t.Fatal("a truncated response must never report START success")
	}
	if category != 0 {
		t.Fatalf("truncated response returned category %s with an error", category)
	}
	deadline := time.After(10 * time.Second)
	for {
		select {
		case line := <-requests:
			if strings.HasPrefix(line, "STOP op_0123456789abcdef0123456789abcdef") {
				return // compensation proved on the wire
			}
		case <-deadline:
			t.Fatal("compensating STOP never reached the manager")
		}
	}
}
