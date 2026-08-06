package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseBearerTokenValid(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer dht_token123")

	token, ok := parseBearerToken(req)
	if !ok {
		t.Fatal("expected token to be parsed")
	}
	if token != "dht_token123" {
		t.Errorf("expected token 'dht_token123', got %q", token)
	}
}

func TestParseBearerTokenMissingHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	_, ok := parseBearerToken(req)
	if ok {
		t.Error("expected token to be rejected")
	}
}

func TestParseBearerTokenWrongScheme(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Basic abc")

	_, ok := parseBearerToken(req)
	if ok {
		t.Error("expected token to be rejected")
	}
}

func TestParseBearerTokenBearerOnly(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer")

	_, ok := parseBearerToken(req)
	if ok {
		t.Error("expected token to be rejected")
	}
}

func TestParseBearerTokenEmptyToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer ")

	_, ok := parseBearerToken(req)
	if ok {
		t.Error("expected token to be rejected")
	}
}

func TestParseBearerTokenExtraSpacesBefore(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer    token")

	_, ok := parseBearerToken(req)
	if ok {
		t.Error("expected token to be rejected")
	}
}

func TestParseBearerTokenExtraTextAfter(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer token extra")

	_, ok := parseBearerToken(req)
	if ok {
		t.Error("expected token to be rejected")
	}
}

func TestParseBearerTokenWrongCase(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "bearer token")

	_, ok := parseBearerToken(req)
	if ok {
		t.Error("expected token to be rejected")
	}
}

func TestParseBearerTokenTabInToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer token\textra")

	_, ok := parseBearerToken(req)
	if ok {
		t.Error("expected token to be rejected")
	}
}
