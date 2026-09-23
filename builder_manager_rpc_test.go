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
	err := c.Start(context.Background(), "op_0123456789abcdef0123456789abcdef")
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
				if strings.HasPrefix(line, "STOP ") {
					_, _ = conn.Write([]byte(builderManagerRespOKAbsent + "\n"))
					return
				}
				// START: hold the connection open without replying ->
				// client read timeout (ambiguous).
				select {}
			}()
		}
	}()

	c := &builderManagerClient{}
	ctx, cancel := context.WithCancel(context.Background())
	go time.AfterFunc(50*time.Millisecond, cancel)
	err := c.Start(ctx, "op_0123456789abcdef0123456789abcdef")
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
	err := c.Start(context.Background(), "op_0123456789abcdef0123456789abcdef")
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
	if err := c.Start(context.Background(), "OP_UPPER"); err == nil {
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
				if strings.HasPrefix(line, "STOP ") {
					// The manager refuses the compensating STOP with a
					// well-formed protocol error.
					_, _ = conn.Write([]byte(builderManagerRespInternal + "\n"))
					return
				}
				select {} // START: hold, never reply (ambiguous after cancel)
			}()
		}
	}()
	c := &builderManagerClient{}
	ctx, cancel := context.WithCancel(context.Background())
	go time.AfterFunc(50*time.Millisecond, cancel)
	err := c.Start(ctx, "op_0123456789abcdef0123456789abcdef")
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
						if strings.HasPrefix(line, "STOP ") {
							_, _ = conn.Write([]byte(tc.stopResp + "\n"))
							return
						}
						select {} // START held: ambiguous after cancel
					}()
				}
			}()
			c := &builderManagerClient{}
			ctx, cancel := context.WithCancel(context.Background())
			go time.AfterFunc(50*time.Millisecond, cancel)
			err := c.Start(ctx, "op_0123456789abcdef0123456789abcdef")
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
				if strings.HasPrefix(line, "STOP ") {
					_, _ = conn.Write([]byte(builderManagerRespOKAbsent + "\n"))
					return
				}
				select {} // START: hold, never reply
			}()
		}
	}()
	c := &builderManagerClient{}
	ctx, cancel := context.WithCancel(context.Background())
	go time.AfterFunc(100*time.Millisecond, cancel)
	start := time.Now()
	err := c.Start(ctx, "op_0123456789abcdef0123456789abcdef")
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
