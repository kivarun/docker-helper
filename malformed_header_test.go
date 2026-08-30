package main

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestServerMalformedHeaderBytesNotInOperationalLog verifies the operational
// error-message surface for attacker-controlled malformed request headers.
//
// An attacker sends a malformed request header containing a raw terminal
// control byte (ESC 0x1b) and a unique marker. The daemon's production HTTP
// server must reject the request, and neither the attacker bytes nor the raw
// control byte may enter the operational log (stream=operational).
//
// The operational ErrorLog bridge is proven live (a synthetic bridge line
// appears), so the absence of the attacker bytes is a real invariant rather
// than a vacuous pass.
func TestServerMalformedHeaderBytesNotInOperationalLog(t *testing.T) {
	_, opBuf := setupTestLogging(t)

	mux := http.NewServeMux()
	server := newHTTPServer(mux)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go server.Serve(listener) //nolint:errcheck

	waitForDialReady(t, "tcp", listener.Addr().String())

	marker := "MARKER_ESC_"
	payload := "GET / HTTP/1.1\r\nX-Evil: " + marker + "\x1b[2JX\r\nHost: localhost\r\n\r\n"

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	conn.Close()

	if !strings.Contains(string(buf[:n]), "400") {
		t.Fatalf("expected 400 rejection of malformed request, got: %q", string(buf[:n]))
	}

	server.ErrorLog.Print("operational-bridge-live")
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(opBuf.String(), "operational-bridge-live") {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(opBuf.String(), "operational-bridge-live") {
		t.Fatal("operational ErrorLog bridge is not live; absence assertion would be vacuous")
	}

	if strings.Contains(opBuf.String(), marker) {
		t.Errorf("attacker header bytes leaked into operational log:\n%s", opBuf.String())
	}
	if bytes.Contains(opBuf.Bytes(), []byte{0x1b}) {
		t.Errorf("raw attacker control byte leaked into operational log:\n%q", opBuf.Bytes())
	}
}

// TestMalformedResponseHeaderErrorEscapesRawInput guards the
// GO-2026-5039 / CVE-2026-42507 fix (net/textproto echoing arbitrary input into
// errors). The net/http client parses an attacker-controlled malformed response
// header that embeds a raw terminal control byte (ESC 0x1b). The resulting
// error must still reference the input, but the raw control byte must be
// escaped — otherwise attacker bytes could be injected into logs/terminals.
//
// This test fails against the pre-fix toolchain (go1.23.12), where the raw
// 0x1b byte appears verbatim in the error.
func TestMalformedResponseHeaderErrorEscapesRawInput(t *testing.T) {
	marker := "MARKER_ESC_"
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		io.WriteString(conn, "HTTP/1.1 200 OK\r\nX-Evil: "+marker+"\x1b[2JX\r\nContent-Length: 0\r\n\r\n")
		conn.Close()
	}()

	transport := &http.Transport{
		DialContext: (&net.Dialer{Timeout: 2 * time.Second}).DialContext,
	}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	resp, err := client.Get("http://" + listener.Addr().String() + "/")
	if resp != nil {
		resp.Body.Close()
	}
	if err == nil {
		t.Fatal("expected malformed-header parse error, got nil")
	}

	es := err.Error()
	if !strings.Contains(es, marker) {
		t.Fatalf("error must reference the attacker input, got: %q", es)
	}
	if strings.Contains(es, "\x1b") {
		t.Fatalf("raw attacker control byte present in error (vulnerable net/textproto behavior): %q", es)
	}
}
