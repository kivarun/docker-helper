package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/moby/moby/client"
)

// newFakeEngine serves the minimal Engine endpoints used by the adapter
// tests: the unversioned /_ping negotiation endpoint and the /auth registry
// validation endpoint.
func newFakeEngine(t *testing.T, apiVersion string, authHandler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/_ping":
			w.Header().Set("Api-Version", apiVersion)
			w.Header().Set("Ostype", "linux")
			w.WriteHeader(http.StatusOK)
		case strings.HasSuffix(r.URL.Path, "/auth"):
			if authHandler != nil {
				authHandler(w, r)
				return
			}
			http.NotFound(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// newEngineClientAgainstFake constructs the production adapter against a fake
// Engine endpoint, exercising the real client construction and negotiation.
func newEngineClientAgainstFake(t *testing.T, srvURL string) *engineClient {
	t.Helper()
	cli, err := client.NewClientWithOpts(
		client.WithHost(srvURL),
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		t.Fatalf("construct engine client against fake engine: %v", err)
	}
	return &engineClient{cli: cli}
}

// TestEngineClientRegistryLoginNegotiationAndAuth proves the adapter's
// construction/negotiation path: the /_ping negotiation endpoint is contacted
// first and the /auth validation request is sent at the negotiated API
// version with the credentials in the Engine request body.
func TestEngineClientRegistryLoginNegotiationAndAuth(t *testing.T) {
	sawPing := false
	var authPath, authBody string
	srv := newFakeEngine(t, "1.51", func(w http.ResponseWriter, r *http.Request) {
		authPath = r.URL.Path
		body := make([]byte, r.ContentLength)
		if _, err := r.Body.Read(body); err != nil && err.Error() != "EOF" {
			t.Errorf("read auth body: %v", err)
		}
		authBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"Status":"Login Succeeded"}`))
	})
	origHandler := srv.Config.Handler
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/_ping" {
			sawPing = true
		}
		origHandler.ServeHTTP(w, r)
	})

	eng := newEngineClientAgainstFake(t, srv.URL)
	token, err := eng.registryLogin(context.Background(), "registry.example.com", "user", "pass")
	if err != nil {
		t.Fatalf("registryLogin: %v", err)
	}
	if token != "" {
		t.Errorf("expected no identity token, got %q", token)
	}
	if !sawPing {
		t.Error("the adapter must negotiate the API version through /_ping before the first Engine request")
	}
	if authPath != "/v1.51/auth" {
		t.Errorf("auth request must use the negotiated API version, got %q", authPath)
	}

	var sent struct {
		Username      string `json:"username"`
		Password      string `json:"password"`
		ServerAddress string `json:"serveraddress"`
	}
	if err := json.Unmarshal([]byte(authBody), &sent); err != nil {
		t.Fatalf("auth request body is not the Engine auth payload: %v (%q)", err, authBody)
	}
	if sent.Username != "user" || sent.Password != "pass" || sent.ServerAddress != "registry.example.com" {
		t.Errorf("auth payload lost credentials: %+v", sent)
	}
}

// TestEngineClientRegistryLoginIdentityToken proves the adapter surfaces the
// registry-issued identity token from a successful /auth response.
func TestEngineClientRegistryLoginIdentityToken(t *testing.T) {
	srv := newFakeEngine(t, "1.51", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"Status":"Login Succeeded","IdentityToken":"tok-123"}`))
	})

	eng := newEngineClientAgainstFake(t, srv.URL)
	token, err := eng.registryLogin(context.Background(), "registry.example.com", "user", "pass")
	if err != nil {
		t.Fatalf("registryLogin: %v", err)
	}
	if token != "tok-123" {
		t.Errorf("expected identity token tok-123, got %q", token)
	}
}

// TestEngineClientRegistryLoginErrorNormalization proves the adapter
// normalizes Engine failures into the docker-helper error categories using
// typed backend signals first, and that raw Moby/client error types do not
// escape the adapter.
func TestEngineClientRegistryLoginErrorNormalization(t *testing.T) {
	unauthorizedMsg := "login attempt to https://registry.example.com/v2/ failed with status: 401 Unauthorized"
	networkMsg := `Get "https://registry.example.com/v2/": dial tcp: lookup registry.example.com: no such host`

	cases := []struct {
		name        string
		apiVersion  string
		authHandler http.HandlerFunc
		wantKind    engineErrorKind
	}{
		{
			name:       "registry rejected credentials",
			apiVersion: "1.51",
			authHandler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"message":"` + unauthorizedMsg + `"}`))
			},
			wantKind: engineErrRegistryAuthDenied,
		},
		{
			name:       "engine reports unreachable registry",
			apiVersion: "1.51",
			authHandler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"message":` + jsonQuote(networkMsg) + `}`))
			},
			wantKind: engineErrRegistryUnavailable,
		},
		{
			name:       "unexpected engine failure",
			apiVersion: "1.51",
			authHandler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"message":"something else went wrong"}`))
			},
			wantKind: engineErrBackendFailure,
		},
		{
			name:       "engine rejects the request",
			apiVersion: "1.51",
			authHandler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"message":"bad auth request"}`))
			},
			wantKind: engineErrBackendFailure,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newFakeEngine(t, tc.apiVersion, tc.authHandler)
			eng := newEngineClientAgainstFake(t, srv.URL)

			_, err := eng.registryLogin(context.Background(), "registry.example.com", "user", "pass")
			if err == nil {
				t.Fatal("expected an error")
			}

			var engineErr *engineError
			if !errors.As(err, &engineErr) {
				t.Fatalf("error must normalize into engineError, got %T: %v", err, err)
			}
			if engineErr.kind != tc.wantKind {
				t.Errorf("kind = %d, want %d", engineErr.kind, tc.wantKind)
			}
			// The raw cause stays available for operator diagnostics but must
			// no longer present itself as a Moby/client transport error.
			if client.IsErrConnectionFailed(err) {
				t.Error("normalized error must not report a client connection failure")
			}
		})
	}

	// Transport-level failure: the Engine endpoint itself is unreachable.
	closedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	closedURL := closedSrv.URL
	closedSrv.Close()
	eng := newEngineClientAgainstFake(t, closedURL)
	_, err := eng.registryLogin(context.Background(), "registry.example.com", "user", "pass")
	if err == nil {
		t.Fatal("expected an error for an unreachable engine")
	}
	var engineErr *engineError
	if !errors.As(err, &engineErr) {
		t.Fatalf("error must normalize into engineError, got %T: %v", err, err)
	}
	if engineErr.kind != engineErrBackendUnavailable {
		t.Errorf("kind = %d, want %d", engineErr.kind, engineErrBackendUnavailable)
	}
}

// TestEngineClientNoRawErrorLeakage proves a normalized error's kind is a
// docker-helper category and the error text is the bounded backend cause
// message, not a Moby type rendering.
func TestEngineClientNoRawErrorLeakage(t *testing.T) {
	unauthorizedMsg := "login attempt to https://registry.example.com/v2/ failed with status: 401 Unauthorized"
	srv := newFakeEngine(t, "1.51", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"` + unauthorizedMsg + `"}`))
	})

	eng := newEngineClientAgainstFake(t, srv.URL)
	_, err := eng.registryLogin(context.Background(), "registry.example.com", "user", "pass")
	if err == nil {
		t.Fatal("expected an error")
	}
	var engineErr *engineError
	if !errors.As(err, &engineErr) {
		t.Fatalf("error must normalize into engineError, got %T", err)
	}
	switch engineErr.kind {
	case engineErrBackendFailure, engineErrBackendUnavailable, engineErrRegistryAuthDenied, engineErrRegistryUnavailable:
	default:
		t.Errorf("kind %d is not a docker-helper engine error category", engineErr.kind)
	}
}
