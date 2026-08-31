package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

// startTestHTTPServer starts a production-style HTTP server (newHTTPServerWith
// Timeouts) on a real loopback listener with the given connection-lifetime
// bounds and registers the given routes.
func startTestHTTPServer(t *testing.T, to serverTimeouts, register func(*http.ServeMux)) (*http.Server, net.Listener) {
	t.Helper()
	mux := http.NewServeMux()
	register(mux)
	server := newHTTPServerWithTimeouts(mux, to)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go server.Serve(listener) //nolint:errcheck
	t.Cleanup(func() { server.Close() })
	return server, listener
}

// readHTTPGet performs a prompt GET of path against addr and returns the body.
func readHTTPGet(t *testing.T, addr, path string) string {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	defer conn.Close()
	req, _ := http.NewRequest("GET", "http://x"+path, nil)
	if err := req.Write(conn); err != nil {
		t.Fatalf("write request: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(body)
}

// pipeListener is a deterministic net.Listener built on net.Pipe pairs: every
// Dial returns the client end of a fresh pipe whose server end is delivered to
// the next Accept. net.Pipe is unbuffered, so a server Write blocks until the
// peer reads — the slow-reader test never depends on host TCP buffer sizes.
type pipeListener struct {
	accept chan net.Conn
}

func newPipeListener() *pipeListener {
	return &pipeListener{accept: make(chan net.Conn, 8)}
}

func (l *pipeListener) Accept() (net.Conn, error) {
	c, ok := <-l.accept
	if !ok {
		return nil, io.EOF
	}
	return c, nil
}

func (l *pipeListener) Close() error {
	close(l.accept)
	return nil
}

func (l *pipeListener) Addr() net.Addr { return pipeAddr{} }

// Dial creates a fresh net.Pipe pair: the server end is delivered to the next
// Accept and the client end is returned.
func (l *pipeListener) Dial() net.Conn {
	server, client := net.Pipe()
	l.accept <- server
	return client
}

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "pipe" }

// A. SLOW BODY: valid headers + Content-Length, body never finished. The
// request must be terminated within the bounded ReadTimeout while a concurrent
// normal request is still served.
func TestServerSlowRequestBodyTerminatesWithinReadTimeout(t *testing.T) {
	const readTimeout = 300 * time.Millisecond
	to := serverTimeouts{
		readHeader:       time.Second,
		read:             readTimeout,
		idle:             time.Second,
		responseDelivery: time.Second,
	}
	bodyReadDone := make(chan struct{})
	_, listener := startTestHTTPServer(t, to, func(mux *http.ServeMux) {
		mux.HandleFunc("POST /", func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			close(bodyReadDone)
			w.WriteHeader(http.StatusOK)
		})
		mux.HandleFunc("GET /ok", func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "ok-normal")
		})
	})

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := fmt.Fprintf(conn, "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 10000\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, "partial-body"); err != nil {
		t.Fatal(err)
	}

	// While the slow-body request is pending, a normal request must still be
	// served concurrently.
	if got := readHTTPGet(t, listener.Addr().String(), "/ok"); got != "ok-normal" {
		t.Fatalf("concurrent normal request body = %q, want ok-normal", got)
	}

	// The handler's body read must be unblocked within a bounded window.
	start := time.Now()
	select {
	case <-bodyReadDone:
	case <-time.After(3 * time.Second):
		t.Fatal("slow-body request not terminated within bounded ReadTimeout")
	}
	elapsed := time.Since(start)
	if elapsed < readTimeout/2 {
		t.Fatalf("body read terminated too early (%v), not via ReadTimeout", elapsed)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("body read not terminated within ReadTimeout bound: %v", elapsed)
	}
}

// B. IDLE KEEP-ALIVE: a completed HTTP/1.1 request leaves the connection open;
// the server must close it within IdleTimeout when nothing further is sent.
func TestServerIdleKeepAliveClosedWithinIdleTimeout(t *testing.T) {
	const idleTimeout = 250 * time.Millisecond
	to := serverTimeouts{
		readHeader:       time.Second,
		read:             5 * time.Second,
		idle:             idleTimeout,
		responseDelivery: time.Second,
	}
	_, listener := startTestHTTPServer(t, to, func(mux *http.ServeMux) {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "ok")
		})
	})

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	req, _ := http.NewRequest("GET", "http://x/", nil)
	if err := req.Write(conn); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "ok" {
		t.Fatalf("body = %q, want ok", body)
	}

	// Now idle: send nothing further. IdleTimeout must close the connection.
	start := time.Now()
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("expected the idle connection to be closed, got data instead")
	}
	elapsed := time.Since(start)
	conn.SetReadDeadline(time.Time{})
	if elapsed < 100*time.Millisecond {
		t.Fatalf("connection closed too early (%v), not via IdleTimeout", elapsed)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("idle connection not closed within IdleTimeout bound: %v", elapsed)
	}
}

// C. SLOW READER: the client requests a large response and does not read it.
// The handler's write must be unblocked by the response-delivery deadline, and
// the server must remain healthy for a fresh connection.
func TestServerSlowReaderUnblockedByResponseDeliveryDeadline(t *testing.T) {
	const deliveryWindow = 200 * time.Millisecond
	to := serverTimeouts{
		readHeader:       time.Second,
		read:             5 * time.Second,
		idle:             time.Second,
		responseDelivery: deliveryWindow,
	}
	mux := http.NewServeMux()
	writeReturned := make(chan struct{})
	mux.HandleFunc("/big", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("x"), 512*1024))
		close(writeReturned)
	})
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	})
	server := newHTTPServerWithTimeouts(mux, to)
	pl := newPipeListener()
	go server.Serve(pl) //nolint:errcheck
	defer server.Close()

	// Slow reader: request the large response, then stop reading.
	client := pl.Dial()
	defer client.Close()
	if _, err := fmt.Fprintf(client, "GET /big HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	select {
	case <-writeReturned:
	case <-time.After(3 * time.Second):
		t.Fatal("handler write not unblocked by the response-delivery deadline")
	}
	elapsed := time.Since(start)
	if elapsed < deliveryWindow/2 {
		t.Fatalf("write unblocked too early (%v), not via delivery deadline", elapsed)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("write not unblocked within delivery bound: %v", elapsed)
	}

	// Server remains healthy: a fresh connection completes normally.
	okClient := pl.Dial()
	defer okClient.Close()
	req, _ := http.NewRequest("GET", "http://x/ok", nil)
	if err := req.Write(okClient); err != nil {
		t.Fatal(err)
	}
	okClient.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(okClient), req)
	if err != nil {
		t.Fatalf("server unhealthy after slow reader: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "ok" {
		t.Fatalf("server unhealthy after slow reader: body = %q", body)
	}
}

// D. LONG COMPUTATION BEFORE FIRST BYTE: handler computation longer than the
// response-delivery window must succeed. The delivery budget starts at the
// first response write, not when the request headers are read.
func TestServerLongPreResponseComputationNotBounded(t *testing.T) {
	const deliveryWindow = 150 * time.Millisecond
	const computeDelay = 500 * time.Millisecond
	to := serverTimeouts{
		readHeader:       time.Second,
		read:             5 * time.Second,
		idle:             time.Second,
		responseDelivery: deliveryWindow,
	}
	_, listener := startTestHTTPServer(t, to, func(mux *http.ServeMux) {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(computeDelay)
			io.WriteString(w, "ok")
		})
	})

	start := time.Now()
	body := readHTTPGet(t, listener.Addr().String(), "/")
	elapsed := time.Since(start)
	if body != "ok" {
		t.Fatalf("body = %q, want ok (long pre-response computation must succeed)", body)
	}
	if elapsed < computeDelay {
		t.Fatalf("response returned before handler computation completed: %v", elapsed)
	}
}

// E. NORMAL LARGE RESPONSE: a prompt reader completes a large response with no
// false response-delivery timeout.
func TestServerNormalLargeResponseSucceeds(t *testing.T) {
	const deliveryWindow = time.Second
	const size = 256 * 1024
	to := serverTimeouts{
		readHeader:       time.Second,
		read:             5 * time.Second,
		idle:             time.Second,
		responseDelivery: deliveryWindow,
	}
	_, listener := startTestHTTPServer(t, to, func(mux *http.ServeMux) {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(w, bytes.NewReader(bytes.Repeat([]byte("e"), size)))
		})
	})

	if got := readHTTPGet(t, listener.Addr().String(), "/"); len(got) != size {
		t.Fatalf("got %d bytes, want %d", len(got), size)
	}
}

// F. KEEP-ALIVE DEADLINE RESET: after one response armed the write-deadline
// mechanism, the same keep-alive connection must serve a second request whose
// response starts well past the first response's delivery window — the
// previous deadline must not leak into the next request.
func TestServerKeepAliveResponseDeadlineReset(t *testing.T) {
	const deliveryWindow = 250 * time.Millisecond
	to := serverTimeouts{
		readHeader:       time.Second,
		read:             5 * time.Second,
		idle:             5 * time.Second,
		responseDelivery: deliveryWindow,
	}
	_, listener := startTestHTTPServer(t, to, func(mux *http.ServeMux) {
		mux.HandleFunc("/fast", func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "ok-fast")
		})
		mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(600 * time.Millisecond)
			io.WriteString(w, "ok-slow")
		})
	})

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	br := bufio.NewReader(conn)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	// Request 1 arms the response-delivery deadline on this connection.
	req1, _ := http.NewRequest("GET", "http://x/fast", nil)
	if err := req1.Write(conn); err != nil {
		t.Fatal(err)
	}
	resp1, err := http.ReadResponse(br, req1)
	if err != nil {
		t.Fatal(err)
	}
	b1, _ := io.ReadAll(resp1.Body)
	resp1.Body.Close()
	if string(b1) != "ok-fast" {
		t.Fatalf("request 1 body = %q, want ok-fast", b1)
	}

	// Request 2 on the SAME connection: its first write happens well past
	// request 1's delivery window, so a leaked deadline would fail it.
	req2, _ := http.NewRequest("GET", "http://x/slow", nil)
	if err := req2.Write(conn); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	resp2, err := http.ReadResponse(br, req2)
	if err != nil {
		t.Fatalf("request 2 failed after request 1 exercised the deadline mechanism: %v", err)
	}
	b2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	elapsed := time.Since(start)
	if string(b2) != "ok-slow" {
		t.Fatalf("request 2 body = %q, want ok-slow", b2)
	}
	if elapsed < 400*time.Millisecond {
		t.Fatalf("request 2 did not outlast the delivery window (%v); reset not exercised", elapsed)
	}
}

// H. FLUSH-ARMED SLOW CLIENT: the handler's first response write is Flush()
// (no WriteHeader/Write before it). A non-reading client blocks that flush; the
// response-delivery deadline armed at the flush must unblock it. Without the
// arm in Flush, a flush-only handler would block forever.
func TestServerFirstResponseFlushArmsDeliveryDeadline(t *testing.T) {
	const deliveryWindow = 200 * time.Millisecond
	to := serverTimeouts{
		readHeader:       time.Second,
		read:             5 * time.Second,
		idle:             time.Second,
		responseDelivery: deliveryWindow,
	}
	mux := http.NewServeMux()
	flushReturned := make(chan struct{})
	mux.HandleFunc("/flush", func(w http.ResponseWriter, r *http.Request) {
		w.(http.Flusher).Flush()
		close(flushReturned)
	})
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	})
	server := newHTTPServerWithTimeouts(mux, to)
	pl := newPipeListener()
	go server.Serve(pl) //nolint:errcheck
	defer server.Close()

	// Non-reading client: request the flush-only endpoint, then never read.
	client := pl.Dial()
	defer client.Close()
	if _, err := fmt.Fprintf(client, "GET /flush HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	select {
	case <-flushReturned:
	case <-time.After(3 * time.Second):
		t.Fatal("flush-only handler blocked forever: Flush did not arm the delivery deadline")
	}
	elapsed := time.Since(start)
	if elapsed < deliveryWindow/2 {
		t.Fatalf("flush unblocked too early (%v), not via delivery deadline", elapsed)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("flush not unblocked within delivery bound: %v", elapsed)
	}

	// Server remains healthy for a fresh connection.
	okClient := pl.Dial()
	defer okClient.Close()
	req, _ := http.NewRequest("GET", "http://x/ok", nil)
	if err := req.Write(okClient); err != nil {
		t.Fatal(err)
	}
	okClient.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(okClient), req)
	if err != nil {
		t.Fatalf("server unhealthy after flush-armed slow client: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "ok" {
		t.Fatalf("server unhealthy after flush-armed slow client: body = %q", body)
	}
}

// G. EXISTING HEADER BOUND: the production server must keep ReadHeaderTimeout
// at 10s, and the production connection-lifetime bounds must be applied.
func TestProductionServerReadHeaderTimeoutPreserved(t *testing.T) {
	s := newHTTPServer(http.NewServeMux())
	if s.ReadHeaderTimeout != 10*time.Second {
		t.Fatalf("ReadHeaderTimeout = %v, want 10s", s.ReadHeaderTimeout)
	}
}

func TestProductionServerConnectionLifetimeBounds(t *testing.T) {
	to := productionServerTimeouts()
	if to.read != 30*time.Second {
		t.Errorf("read = %v, want 30s", to.read)
	}
	if to.idle != 30*time.Second {
		t.Errorf("idle = %v, want 30s", to.idle)
	}
	if to.responseDelivery != 30*time.Second {
		t.Errorf("responseDelivery = %v, want 30s", to.responseDelivery)
	}

	s := newHTTPServer(http.NewServeMux())
	if s.ReadTimeout != to.read {
		t.Errorf("server ReadTimeout = %v, want %v", s.ReadTimeout, to.read)
	}
	if s.IdleTimeout != to.idle {
		t.Errorf("server IdleTimeout = %v, want %v", s.IdleTimeout, to.idle)
	}
}
