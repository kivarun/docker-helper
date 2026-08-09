package main

import (
	"bytes"
	"net/http/httptest"
	"testing"
)

func TestDecodeJSONRequest_TrailingWhitespaceAccepted(t *testing.T) {
	buf := bytes.NewReader([]byte(`{"image":"alpine:3.24"}   `))
	r := httptest.NewRequest("POST", "/pull", buf)
	var req pullRequest
	if err := decodeJSONRequest(r, &req); err != nil {
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
	var req pullRequest
	if err := decodeJSONRequest(r, &req); err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
}

func TestDecodeJSONRequest_SecondJSONValueRejected(t *testing.T) {
	buf := bytes.NewReader([]byte(`{"image":"alpine:3.24"} {"image":"other:tag"}`))
	r := httptest.NewRequest("POST", "/pull", buf)
	var req pullRequest
	if err := decodeJSONRequest(r, &req); err == nil {
		t.Fatal("expected error for trailing JSON value")
	}
}

func TestDecodeJSONRequest_TrailingGarbageRejected(t *testing.T) {
	buf := bytes.NewReader([]byte(`{"image":"alpine:3.24"} garbage`))
	r := httptest.NewRequest("POST", "/pull", buf)
	var req pullRequest
	if err := decodeJSONRequest(r, &req); err == nil {
		t.Fatal("expected error for trailing garbage")
	}
}

func TestDecodeJSONRequest_TrailingArrayRejected(t *testing.T) {
	buf := bytes.NewReader([]byte(`{"image":"alpine:3.24"} [1,2,3]`))
	r := httptest.NewRequest("POST", "/pull", buf)
	var req pullRequest
	if err := decodeJSONRequest(r, &req); err == nil {
		t.Fatal("expected error for trailing array")
	}
}

func TestDecodeJSONRequest_UnknownFieldRejected(t *testing.T) {
	buf := bytes.NewReader([]byte(`{"image":"alpine:3.24","unknown_field":true}`))
	r := httptest.NewRequest("POST", "/pull", buf)
	var req pullRequest
	if err := decodeJSONRequest(r, &req); err == nil {
		t.Fatal("expected error for unknown field")
	}
}

func TestDecodeJSONRequest_EmptyBodyRejected(t *testing.T) {
	r := httptest.NewRequest("POST", "/pull", bytes.NewReader(nil))
	var req pullRequest
	if err := decodeJSONRequest(r, &req); err == nil {
		t.Fatal("expected error for empty body")
	}
}

func TestDecodeJSONRequest_MalformedJSONRejected(t *testing.T) {
	r := httptest.NewRequest("POST", "/pull", bytes.NewReader([]byte(`{invalid`)))
	var req pullRequest
	if err := decodeJSONRequest(r, &req); err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestDecodeJSONRequest_OversizedBodyRejected(t *testing.T) {
	large := make([]byte, 17*1024)
	large[0] = '{'
	large[len(large)-2] = '}'
	large[len(large)-1] = '\n'
	r := httptest.NewRequest("POST", "/pull", bytes.NewReader(large))
	var req pullRequest
	if err := decodeJSONRequest(r, &req); err == nil {
		t.Fatal("expected error for oversized body")
	}
}

func TestDecodeJSONRequest_BuildRequest(t *testing.T) {
	buf := bytes.NewReader([]byte(`{"context":".","dockerfile":"Dockerfile","image":"myapp:v1"}   `))
	r := httptest.NewRequest("POST", "/build", buf)
	var req buildRequest
	if err := decodeJSONRequest(r, &req); err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
}

func TestDecodeJSONRequest_RunRequest(t *testing.T) {
	buf := bytes.NewReader([]byte(`{"image":"alpine:3.24"}
`))
	r := httptest.NewRequest("POST", "/run", buf)
	var req runRequest
	if err := decodeJSONRequest(r, &req); err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
}

func TestDecodeJSONRequest_SessionRequest(t *testing.T) {
	buf := bytes.NewReader([]byte(`{"workspace":"/tmp/ws"}   `))
	r := httptest.NewRequest("POST", "/sessions", buf)
	var req sessionRequest
	if err := decodeJSONRequest(r, &req); err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
}
