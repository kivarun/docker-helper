package main

import (
	"bytes"
	"net/http/httptest"
	"testing"
)

func TestDecodeJSONRequest_TrailingWhitespaceAccepted(t *testing.T) {
	buf := bytes.NewReader([]byte(`{"image":"alpine:3.24"}   `))
	r := httptest.NewRequest("POST", "/pull", buf)
	w := httptest.NewRecorder()
	var req pullRequest
	if err := decodeJSONRequest(w, r, &req); err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
	if req.Image != "alpine:3.24" {
		t.Fatalf("unexpected image: %s", req.Image)
	}
}

func TestDecodeJSONRequest_TrailingNewlineAccepted(t *testing.T) {
	buf := bytes.NewReader([]byte(`{"image":"alpine:3.24"}
`))
	r := httptest.NewRequest("POST", "/pull", buf)
	w := httptest.NewRecorder()
	var req pullRequest
	if err := decodeJSONRequest(w, r, &req); err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
}

func TestDecodeJSONRequest_SecondJSONValueRejected(t *testing.T) {
	buf := bytes.NewReader([]byte(`{"image":"alpine:3.24"} {"image":"other:tag"}`))
	r := httptest.NewRequest("POST", "/pull", buf)
	w := httptest.NewRecorder()
	var req pullRequest
	if err := decodeJSONRequest(w, r, &req); err == nil {
		t.Fatal("expected error for trailing JSON value")
	}
}

func TestDecodeJSONRequest_TrailingGarbageRejected(t *testing.T) {
	buf := bytes.NewReader([]byte(`{"image":"alpine:3.24"} garbage`))
	r := httptest.NewRequest("POST", "/pull", buf)
	w := httptest.NewRecorder()
	var req pullRequest
	if err := decodeJSONRequest(w, r, &req); err == nil {
		t.Fatal("expected error for trailing garbage")
	}
}

func TestDecodeJSONRequest_TrailingArrayRejected(t *testing.T) {
	buf := bytes.NewReader([]byte(`{"image":"alpine:3.24"} [1,2,3]`))
	r := httptest.NewRequest("POST", "/pull", buf)
	w := httptest.NewRecorder()
	var req pullRequest
	if err := decodeJSONRequest(w, r, &req); err == nil {
		t.Fatal("expected error for trailing array")
	}
}

func TestDecodeJSONRequest_UnknownFieldRejected(t *testing.T) {
	buf := bytes.NewReader([]byte(`{"image":"alpine:3.24","unknown_field":true}`))
	r := httptest.NewRequest("POST", "/pull", buf)
	w := httptest.NewRecorder()
	var req pullRequest
	if err := decodeJSONRequest(w, r, &req); err == nil {
		t.Fatal("expected error for unknown field")
	}
}

func TestDecodeJSONRequest_EmptyBodyRejected(t *testing.T) {
	r := httptest.NewRequest("POST", "/pull", bytes.NewReader(nil))
	w := httptest.NewRecorder()
	var req pullRequest
	if err := decodeJSONRequest(w, r, &req); err == nil {
		t.Fatal("expected error for empty body")
	}
}

func TestDecodeJSONRequest_MalformedJSONRejected(t *testing.T) {
	r := httptest.NewRequest("POST", "/pull", bytes.NewReader([]byte(`{invalid`)))
	w := httptest.NewRecorder()
	var req pullRequest
	if err := decodeJSONRequest(w, r, &req); err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestDecodeJSONRequest_OversizedBodyRejected(t *testing.T) {
	large := make([]byte, 17*1024)
	large[0] = '{'
	large[len(large)-2] = '}'
	large[len(large)-1] = '\n'
	r := httptest.NewRequest("POST", "/pull", bytes.NewReader(large))
	w := httptest.NewRecorder()
	var req pullRequest
	if err := decodeJSONRequest(w, r, &req); err == nil {
		t.Fatal("expected error for oversized body")
	}
}

func TestDecodeJSONRequest_BuildRequest(t *testing.T) {
	buf := bytes.NewReader([]byte(`{"context":".","dockerfile":"Dockerfile","image":"myapp:v1"}   `))
	r := httptest.NewRequest("POST", "/build", buf)
	w := httptest.NewRecorder()
	var req buildRequest
	if err := decodeJSONRequest(w, r, &req); err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
}

// TestDecodeJSONRequest_BuildRequestHasNoCallerNetworkOrPrivilegeKnobs proves
// the accepted Release 2.2 build boundary (H1 disposition): the public build
// request grammar carries no caller-controlled builder network or privileged
// entitlement knob — a caller-supplied network/privilege field is an unknown
// field refused by the strict request decode. A builder network mode or
// entitlement can only ever be introduced through the explicitly accepted
// server-owned sandbox policy (Release 2.4 build sandbox design), never as a
// hidden caller field.
func TestDecodeJSONRequest_BuildRequestHasNoCallerNetworkOrPrivilegeKnobs(t *testing.T) {
	for _, body := range []string{
		`{"context":".","dockerfile":"Dockerfile","image":"myapp:v1","network":"none"}`,
		`{"context":".","dockerfile":"Dockerfile","image":"myapp:v1","network":"host"}`,
		`{"context":".","dockerfile":"Dockerfile","image":"myapp:v1","privileged":true}`,
		`{"context":".","dockerfile":"Dockerfile","image":"myapp:v1","allow_entitlements":["network_host"]}`,
	} {
		r := httptest.NewRequest("POST", "/build", bytes.NewReader([]byte(body)))
		w := httptest.NewRecorder()
		var req buildRequest
		if err := decodeJSONRequest(w, r, &req); err == nil {
			t.Fatalf("build request %s must be refused: the grammar carries no caller-controlled network or privilege knob", body)
		}
	}
}

func TestDecodeJSONRequest_RunRequest(t *testing.T) {
	buf := bytes.NewReader([]byte(`{"image":"alpine:3.24"}
`))
	r := httptest.NewRequest("POST", "/run", buf)
	w := httptest.NewRecorder()
	var req runRequest
	if err := decodeJSONRequest(w, r, &req); err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
}

func TestDecodeJSONRequest_SessionRequest(t *testing.T) {
	buf := bytes.NewReader([]byte(`{"workspace":"/tmp/ws"}   `))
	r := httptest.NewRequest("POST", "/sessions", buf)
	w := httptest.NewRecorder()
	var req sessionRequest
	if err := decodeJSONRequest(w, r, &req); err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
}
