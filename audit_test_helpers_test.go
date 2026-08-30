package main

// Shared audit assertion helpers for the daemon-audit tests. One test concept
// -> one test-helper owner: any test file that asserts on structured audit
// JSON (parseAuditMap / assertNoSecrets / assertNoInjectedError /
// findAuthFailureRawLines / validateAuthFailureRaw) imports these from here
// rather than redefining them.

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// parseAuditMap unmarshals raw audit JSON; fails the test on error.
func parseAuditMap(t *testing.T, raw string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("cannot parse audit JSON: %v: %s", err, raw)
	}
	return m
}

// auditHasSecretKey returns true when the map contains a key whose
// lower-case form is "token" or "authorization".
func auditHasSecretKey(m map[string]any) bool {
	for k := range m {
		lk := strings.ToLower(k)
		if lk == "token" || lk == "authorization" {
			return true
		}
	}
	return false
}

// assertNoSecrets verifies that raw audit JSON does not leak tokens or
// Authorization header values, and does not carry secret keys.
func assertNoSecrets(t *testing.T, raw string, m map[string]any, token, adminToken string) {
	t.Helper()
	if auditHasSecretKey(m) {
		t.Error("audit has secret key (token/authorization)")
	}
	if token != "" && strings.Contains(raw, token) {
		t.Error("audit contains session token")
	}
	if adminToken != "" && strings.Contains(raw, adminToken) {
		t.Error("audit contains admin token")
	}
	if strings.Contains(raw, "Authorization") {
		t.Error("audit contains Authorization")
	}
}

// assertNoInjectedError checks that the raw audit JSON does not contain
// the injected error text (full string, not just the result field).
func assertNoInjectedError(t *testing.T, raw string, injected string) {
	t.Helper()
	if injected == "" {
		return
	}
	if strings.Contains(raw, injected) {
		t.Errorf("audit leaks injected error text %q in raw JSON", injected)
	}
}

// findAuthFailureRawLines returns every raw JSON line whose event is
// auth.failure.
func findAuthFailureRawLines(buf *bytes.Buffer) []string {
	var lines []string
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			continue
		}
		if evt, ok := m["event"].(string); ok && evt == "auth.failure" {
			lines = append(lines, line)
		}
	}
	return lines
}

// authFailureExpectation describes every required property of an auth.failure
// audit record that a test asserts. All fields are optional (zero value means
// "not expected / nothing to assert"); call sites state only what they mean.
type authFailureExpectation struct {
	Method        string // expected HTTP method
	Path          string // expected request path
	Result        string // expected result code
	InjectedToken string // bearer token value sent in the request (must not leak)
	InjectedErr   string // injected DB error text (must not leak)
	AuthHeader    string // full Authorization header value (must not leak)
	HeaderMarker  string // custom header value (must not leak)
	BodyMarker    string // request-body value (must not leak)
}

// validateAuthFailureRaw checks every required property on the raw audit JSON
// for an auth.failure event against the given expectation.
func validateAuthFailureRaw(t *testing.T, raw string, exp authFailureExpectation) {
	t.Helper()

	m := parseAuditMap(t, raw)

	// --- required fields ---
	if m["event"] != "auth.failure" {
		t.Errorf("event: expected 'auth.failure', got %v", m["event"])
	}
	if exp.Method != "" && m["method"] != exp.Method {
		t.Errorf("method: expected %q, got %v", exp.Method, m["method"])
	}
	if exp.Path != "" && m["path"] != exp.Path {
		t.Errorf("path: expected %q, got %v", exp.Path, m["path"])
	}
	if exp.Result != "" && m["result"] != exp.Result {
		t.Errorf("result: expected %q, got %v", exp.Result, m["result"])
	}

	// --- session_id must be completely absent ---
	if _, exists := m["session_id"]; exists {
		t.Error("session_id key must not be present in auth.failure audit record")
	}

	// --- generic secret-leak checks ---
	assertNoSecrets(t, raw, m, exp.InjectedToken, "")

	// --- no full Authorization header value ---
	if exp.AuthHeader != "" && strings.Contains(raw, exp.AuthHeader) {
		t.Errorf("raw JSON contains Authorization header value %q", exp.AuthHeader)
	}

	// --- no injected error text ---
	assertNoInjectedError(t, raw, exp.InjectedErr)

	// --- no internal error text ---
	for _, text := range []string{
		"session not found",
		"ErrSessionNotFound",
		"cannot find session",
		"sql.ErrNoRows",
	} {
		if strings.Contains(raw, text) {
			t.Errorf("raw JSON contains internal error text %q", text)
		}
	}

	// --- no request body content ---
	if strings.Contains(raw, "alpine:latest") {
		t.Error("raw JSON contains request body content (image)")
	}
	if strings.Contains(raw, "Content-Type") {
		t.Error("raw JSON contains request header Content-Type")
	}

	// --- no custom header marker ---
	if exp.HeaderMarker != "" && strings.Contains(raw, exp.HeaderMarker) {
		t.Errorf("raw JSON contains custom header marker %q", exp.HeaderMarker)
	}

	// --- no body marker ---
	if exp.BodyMarker != "" && strings.Contains(raw, exp.BodyMarker) {
		t.Errorf("raw JSON contains body marker %q", exp.BodyMarker)
	}
}
