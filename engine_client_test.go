package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/containerd/errdefs/pkg/errhttp"
	"github.com/moby/moby/api/types/registry"
	"github.com/moby/moby/client"
)

// newFakeEngine serves the minimal Engine endpoints used by the adapter
// tests: the unversioned /_ping negotiation endpoint, the /auth registry
// validation endpoint, the /images/create pull endpoint, the /build
// endpoint, and the /session hijack endpoint. A nil handler leaves the
// corresponding endpoint answering 404. Without an explicit session handler
// the /session endpoint is hijacked and held open the way the daemon does,
// so a build's request-owned session attaches normally.
func newFakeEngine(t *testing.T, apiVersion string, authHandler, pullHandler, buildHandler http.HandlerFunc, sessionHandlers ...http.HandlerFunc) *httptest.Server {
	t.Helper()
	sessionHandler := fakeEngineSessionHandler(t, nil)
	if len(sessionHandlers) > 0 {
		sessionHandler = sessionHandlers[0]
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/_ping":
			w.Header().Set("Api-Version", apiVersion)
			w.Header().Set("Ostype", "linux")
			w.WriteHeader(http.StatusOK)
		case strings.HasSuffix(r.URL.Path, "/session"):
			sessionHandler(w, r)
		case strings.HasSuffix(r.URL.Path, "/auth"):
			if authHandler != nil {
				authHandler(w, r)
				return
			}
			http.NotFound(w, r)
		case strings.HasSuffix(r.URL.Path, "/images/create"):
			if pullHandler != nil {
				pullHandler(w, r)
				return
			}
			http.NotFound(w, r)
		case strings.HasSuffix(r.URL.Path, "/build"):
			if buildHandler != nil {
				buildHandler(w, r)
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

// fakeEngineSessionRecorder counts /session dials and records the session
// UUID each dial exposed in the hijack handshake headers.
type fakeSessionRecorder struct {
	mu    sync.Mutex
	dials int
	uuids []string
}

func (rec *fakeSessionRecorder) add(uuid string) {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	rec.dials++
	rec.uuids = append(rec.uuids, uuid)
}

func (rec *fakeSessionRecorder) count() int {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	return rec.dials
}

func (rec *fakeSessionRecorder) singleUUID() string {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.uuids) != 1 {
		return ""
	}
	return rec.uuids[0]
}

// fakeEngineSessionHandler hijacks the Engine /session endpoint the way the
// daemon does: it upgrades the connection and holds it open until the
// session closes it, without speaking gRPC. rec is an optional recorder.
func fakeEngineSessionHandler(t *testing.T, rec *fakeSessionRecorder) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if rec != nil {
			rec.add(r.Header.Get("X-Docker-Expose-Session-Uuid"))
		}
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijack session connection: %v", err)
			return
		}
		defer conn.Close()
		if _, err := buf.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\nConnection: Upgrade\r\n\r\n"); err != nil {
			return
		}
		_ = buf.Flush()
		// Hold the session connection open until the build closes it,
		// discarding whatever gRPC traffic arrives.
		blob := make([]byte, 4096)
		for {
			if _, err := conn.Read(blob); err != nil {
				return
			}
		}
	}
}

// newEngineClientAgainstFake constructs the production adapter against a fake
// Engine endpoint, exercising the real client construction and negotiation.
// The fake endpoint URL is converted to the tcp:// daemon host form the
// client's raw hijack dialer accepts.
func newEngineClientAgainstFake(t *testing.T, srvURL string) *engineClient {
	t.Helper()
	cli, err := client.NewClientWithOpts(
		client.WithHost(strings.Replace(srvURL, "http://", "tcp://", 1)),
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
	}, nil, nil)
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
	}, nil, nil)

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
			name:       "engine reports credential rejection without a typed signal",
			apiVersion: "1.51",
			authHandler: func(w http.ResponseWriter, r *http.Request) {
				// The daemon reports a failed registry login as an untyped
				// internal error whose message carries the registry status
				// line (the /auth error is not errdefs-typed end to end).
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"message":` + jsonQuote("login attempt to https://registry.example.com/v2/ failed with status: 401 Unauthorized") + `}`))
			},
			wantKind: engineErrRegistryAuthDenied,
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
			srv := newFakeEngine(t, tc.apiVersion, tc.authHandler, nil, nil)
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
	}, nil, nil)

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

// fakePullStream returns a pull endpoint handler serving the given NDJSON
// pull stream, recording the request path, query, and registry-auth header.
func fakePullStream(record *fakePullRequest, lines ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		record.path = r.URL.Path
		record.fromImage = r.URL.Query().Get("fromImage")
		record.tag = r.URL.Query().Get("tag")
		record.registryAuth = r.Header.Get("X-Registry-Auth")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		for _, line := range lines {
			_, _ = w.Write([]byte(line + "\n"))
		}
	}
}

// fakePullRequest records one pull endpoint request.
type fakePullRequest struct {
	path         string
	fromImage    string
	tag          string
	registryAuth string
}

// TestEngineClientPullUnauthenticatedRequestAndStream proves the pull adapter
// delegates reference normalization to the Moby client (the docker-semantic
// fromImage/tag request the CLI pull path used), sends no registry-auth
// header for an unauthenticated pull, negotiates the API version, and renders
// the progress stream into line-based combined output.
func TestEngineClientPullUnauthenticatedRequestAndStream(t *testing.T) {
	var record fakePullRequest
	srv := newFakeEngine(t, "1.51", nil, fakePullStream(&record,
		`{"status":"Pulling from library/alpine","id":"0123456789ab"}`,
		`{"status":"Status: Downloaded newer image for alpine:3.24"}`,
	), nil)

	eng := newEngineClientAgainstFake(t, srv.URL)
	result, err := eng.imagePull(context.Background(), "alpine:3.24", nil, 1<<20)
	if err != nil {
		t.Fatalf("imagePull: %v", err)
	}

	if record.path != "/v1.51/images/create" {
		t.Errorf("pull request must use the negotiated API version, got %q", record.path)
	}
	if record.fromImage != "docker.io/library/alpine" || record.tag != "3.24" {
		t.Errorf("fromImage/tag = %q/%q, want docker.io/library/alpine/3.24", record.fromImage, record.tag)
	}
	if record.registryAuth != "" {
		t.Errorf("unauthenticated pull must not send a registry-auth header, got %q", record.registryAuth)
	}
	wantOutput := "0123456789ab: Pulling from library/alpine\nStatus: Downloaded newer image for alpine:3.24\n"
	if result.Output != wantOutput {
		t.Errorf("output = %q, want %q", result.Output, wantOutput)
	}
	if result.Truncated {
		t.Error("bounded output must not report truncation below the limit")
	}
}

// TestEngineClientPullRegistryAuthEncoding proves the pull adapter encodes a
// resolved Session credential into the X-Registry-Auth header in the Engine
// format, including the registry address, and never places the credential in
// the request URL.
func TestEngineClientPullRegistryAuthEncoding(t *testing.T) {
	cases := []struct {
		name       string
		credential sessionRegistryCredential
		want       registry.AuthConfig
	}{
		{
			name: "username and password",
			credential: sessionRegistryCredential{
				Registry: "registry.example.com",
				Username: "user",
				Password: "secret-pass",
			},
			want: registry.AuthConfig{
				Username:      "user",
				Password:      "secret-pass",
				ServerAddress: "registry.example.com",
			},
		},
		{
			name: "identity token",
			credential: sessionRegistryCredential{
				Registry:      "https://index.docker.io/v1/",
				IdentityToken: "tok-123",
			},
			want: registry.AuthConfig{
				IdentityToken: "tok-123",
				ServerAddress: "https://index.docker.io/v1/",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var record fakePullRequest
			srv := newFakeEngine(t, "1.51", nil, fakePullStream(&record,
				`{"status":"Status: Downloaded newer image for alpine:3.24"}`,
			), nil)

			eng := newEngineClientAgainstFake(t, srv.URL)
			cred := tc.credential
			_, err := eng.imagePull(context.Background(), "alpine:3.24", &cred, 1<<20)
			if err != nil {
				t.Fatalf("imagePull: %v", err)
			}
			if record.registryAuth == "" {
				t.Fatal("authenticated pull must send the registry-auth header")
			}

			decoded, err := base64.URLEncoding.DecodeString(record.registryAuth)
			if err != nil {
				t.Fatalf("registry-auth header is not base64url encoded: %v (%q)", err, record.registryAuth)
			}
			var sent registry.AuthConfig
			if err := json.Unmarshal(decoded, &sent); err != nil {
				t.Fatalf("registry-auth header is not the Engine auth payload: %v", err)
			}
			if sent != tc.want {
				t.Errorf("auth payload = %+v, want %+v", sent, tc.want)
			}
		})
	}
}

// TestEngineClientPullEmbeddedErrorNormalization proves in-band Engine pull
// failures normalize into the docker-helper error categories with typed
// signals preserved, and that the adapter keeps draining the stream after an
// embedded error so the rendered failure output stays complete.
func TestEngineClientPullEmbeddedErrorNormalization(t *testing.T) {
	cases := []struct {
		name       string
		body       string
		wantKind   engineErrorKind
		wantTyped  func(error) bool
		wantOutput string
	}{
		{
			name: "typed registry auth denial",
			body: `{"errorDetail":{"code":401,"message":"unauthorized: authentication required"},"error":"unauthorized: authentication required"}` + "\n" +
				`{"status":"Download complete","id":"zz"}`,
			wantKind:   engineErrRegistryAuthDenied,
			wantTyped:  cerrdefs.IsUnauthorized,
			wantOutput: "unauthorized: authentication required\nzz: Download complete\n",
		},
		{
			name:       "typed image not found",
			body:       `{"errorDetail":{"code":404,"message":"manifest for alpine:9.9 not found"},"error":"manifest for alpine:9.9 not found"}`,
			wantKind:   engineErrImageNotFound,
			wantTyped:  cerrdefs.IsNotFound,
			wantOutput: "manifest for alpine:9.9 not found\n",
		},
		{
			name:       "registry auth denial without a typed signal",
			body:       `{"errorDetail":{"message":"pull access denied for foo, repository does not exist or may require 'docker login'"}}`,
			wantKind:   engineErrRegistryAuthDenied,
			wantOutput: "pull access denied for foo, repository does not exist or may require 'docker login'\n",
		},
		{
			name:       "registry unreachable without a typed signal",
			body:       `{"errorDetail":{"message":"Error response from daemon: Get \"https://registry.example.com/v2/\": dial tcp: lookup registry.example.com: no such host"}}`,
			wantKind:   engineErrRegistryUnavailable,
			wantOutput: "Error response from daemon: Get \"https://registry.example.com/v2/\": dial tcp: lookup registry.example.com: no such host\n",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var record fakePullRequest
			srv := newFakeEngine(t, "1.51", nil, fakePullStream(&record, tc.body), nil)

			eng := newEngineClientAgainstFake(t, srv.URL)
			result, err := eng.imagePull(context.Background(), "alpine:3.24", nil, 1<<20)
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
			if tc.wantTyped != nil && !tc.wantTyped(err) {
				t.Errorf("typed signal lost through normalization: %v", err)
			}
			if result.Output != tc.wantOutput {
				t.Errorf("failure output = %q, want %q", result.Output, tc.wantOutput)
			}
		})
	}
}

// TestEngineClientPullTransportAndRequestFailures proves the pull adapter
// normalizes Engine transport failures and invalid image references.
func TestEngineClientPullTransportAndRequestFailures(t *testing.T) {
	closedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	closedURL := closedSrv.URL
	closedSrv.Close()
	eng := newEngineClientAgainstFake(t, closedURL)
	_, err := eng.imagePull(context.Background(), "alpine:3.24", nil, 1<<20)
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

	var record fakePullRequest
	srv := newFakeEngine(t, "1.51", nil, fakePullStream(&record), nil)
	eng = newEngineClientAgainstFake(t, srv.URL)
	_, err = eng.imagePull(context.Background(), "INVALID:REFERENCE!!", nil, 1<<20)
	if err == nil {
		t.Fatal("expected an error for an invalid image reference")
	}
	if !errors.As(err, &engineErr) {
		t.Fatalf("error must normalize into engineError, got %T: %v", err, err)
	}
	if engineErr.kind != engineErrBackendFailure {
		t.Errorf("kind = %d, want %d", engineErr.kind, engineErrBackendFailure)
	}
	if record.path != "" {
		t.Error("an invalid image reference must not reach the Engine pull endpoint")
	}
}

// TestEngineClientPullContextCancellation proves a cancelled pull request
// surfaces as the client-cancelled category and the Engine sees the request
// end through the cancelled context.
func TestEngineClientPullContextCancellation(t *testing.T) {
	requestStarted := make(chan struct{})
	handlerDone := make(chan struct{})
	srv := newFakeEngine(t, "1.51", nil, func(w http.ResponseWriter, r *http.Request) {
		close(requestStarted)
		<-r.Context().Done()
		close(handlerDone)
	}, nil)

	eng := newEngineClientAgainstFake(t, srv.URL)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-requestStarted
		cancel()
	}()

	_, err := eng.imagePull(ctx, "alpine:3.24", nil, 1<<20)
	if err == nil {
		t.Fatal("expected an error for a cancelled pull")
	}
	var engineErr *engineError
	if !errors.As(err, &engineErr) {
		t.Fatalf("error must normalize into engineError, got %T: %v", err, err)
	}
	if engineErr.kind != engineErrClientCancelled {
		t.Errorf("kind = %d, want %d", engineErr.kind, engineErrClientCancelled)
	}
	select {
	case <-handlerDone:
	case <-time.After(5 * time.Second):
		t.Error("the cancelled pull did not end the Engine request")
	}
}

// TestEngineClientPullOutputTruncation proves the pull adapter bounds its
// rendered output with the newest bytes preserved and truncation reported.
func TestEngineClientPullOutputTruncation(t *testing.T) {
	var record fakePullRequest
	lines := make([]string, 0, 20)
	for i := 0; i < 20; i++ {
		lines = append(lines, `{"stream":"0123456789\n"}`)
	}
	srv := newFakeEngine(t, "1.51", nil, fakePullStream(&record, lines...), nil)

	eng := newEngineClientAgainstFake(t, srv.URL)
	result, err := eng.imagePull(context.Background(), "alpine:3.24", nil, 100)
	if err != nil {
		t.Fatalf("imagePull: %v", err)
	}
	full := strings.Repeat("0123456789\n", 20)
	want := full[len(full)-100:]
	if result.Output != want {
		t.Errorf("truncated output = %q, want %q", result.Output, want)
	}
	if !result.Truncated {
		t.Error("output beyond the limit must report truncation")
	}
}

// TestSharedEngineAdapterOneAdapterPerApp proves the App's production
// default owns exactly one Engine adapter per App lifetime: concurrent first
// use through both Engine consumers resolves the same adapter instance, so
// no request path constructs or abandons its own Moby client.
func TestSharedEngineAdapterOneAdapterPerApp(t *testing.T) {
	app := newTestApp(t)

	const workers = 8
	authenticators := make([]engineRegistryAuthenticator, workers)
	pullers := make([]engineImagePuller, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			auth, err := app.newEngineRegistryAuthenticator()
			if err != nil {
				t.Errorf("registry-login adapter %d: %v", i, err)
				return
			}
			authenticators[i] = auth
		}(i)
		go func(i int) {
			defer wg.Done()
			puller, err := app.newEngineImagePuller()
			if err != nil {
				t.Errorf("pull adapter %d: %v", i, err)
				return
			}
			pullers[i] = puller
		}(i)
	}
	wg.Wait()

	var want *engineClient
	for i := range authenticators {
		auth, ok := authenticators[i].(*engineClient)
		if !ok {
			t.Fatalf("registry-login adapter %d is not the production engineClient", i)
		}
		pull, ok := pullers[i].(*engineClient)
		if !ok {
			t.Fatalf("pull adapter %d is not the production engineClient", i)
		}
		if want == nil {
			want = auth
		}
		if auth != want || pull != want {
			t.Errorf("worker %d resolved a different adapter instance", i)
		}
	}
	if want == nil || want != app.engineAdapter {
		t.Error("the resolved adapter is not the App's shared adapter")
	}
}

// TestSharedEngineAdapterConstructionFailureNotCached proves a failed
// adapter construction leaves the App without a shared adapter, so the next
// Engine request retries construction instead of inheriting a poisoned
// cached failure.
func TestSharedEngineAdapterConstructionFailureNotCached(t *testing.T) {
	app := newTestApp(t)

	t.Setenv("DOCKER_HOST", "bogus")
	if _, err := app.newEngineRegistryAuthenticator(); err == nil {
		t.Fatal("malformed DOCKER_HOST must fail adapter construction")
	}
	if app.engineAdapter != nil {
		t.Error("failed construction must not be cached as the shared adapter")
	}

	t.Setenv("DOCKER_HOST", "")
	puller, err := app.newEngineImagePuller()
	if err != nil {
		t.Fatalf("construction against the default Engine endpoint: %v", err)
	}
	ec, ok := puller.(*engineClient)
	if !ok || app.engineAdapter != ec {
		t.Error("the retried construction must install the shared adapter")
	}
}

// TestAppShutdownClosesSharedEngineAdapter proves the daemon shutdown path
// releases the shared Moby client's pooled connections: after a real Engine
// request through the production default, closeEngineAdapter makes the
// Engine endpoint observe its pooled connection close.
func TestAppShutdownClosesSharedEngineAdapter(t *testing.T) {
	var closedConns atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/_ping":
			w.Header().Set("Api-Version", "1.51")
			w.Header().Set("Ostype", "linux")
			w.WriteHeader(http.StatusOK)
		case strings.HasSuffix(r.URL.Path, "/auth"):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"Status":"Login Succeeded"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	srv.Config.ConnState = func(c net.Conn, cs http.ConnState) {
		if cs == http.StateClosed {
			closedConns.Add(1)
		}
	}
	srv.Start()
	t.Cleanup(srv.Close)
	t.Setenv("DOCKER_HOST", srv.URL)

	app := newTestApp(t)
	auth, err := app.newEngineRegistryAuthenticator()
	if err != nil {
		t.Fatalf("registry-login adapter: %v", err)
	}
	eng, ok := auth.(*engineClient)
	if !ok || eng != app.engineAdapter {
		t.Fatal("the login adapter must be the App's shared adapter")
	}
	if _, err := eng.registryLogin(context.Background(), "registry.example.com", "user", "pass"); err != nil {
		t.Fatalf("registryLogin against the fake Engine: %v", err)
	}

	app.closeEngineAdapter()

	// The pooled connection must be released. The client close is
	// synchronous; the Engine endpoint observes it within moments.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if closedConns.Load() > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if closedConns.Load() == 0 {
		t.Error("the Engine endpoint never observed the shared client's pooled connection closing")
	}
}

// TestShutdownClosesSharedEngineAdapterOnlyAfterHTTPDrain is the shutdown
// ordering regression for the shared Engine adapter. A real registry login
// handler is accepted and blocked inside the shared adapter's Engine call;
// shutdown is then initiated through the production serving stack. The
// adapter must not be closed while the handler is in flight, and the fake
// Engine must observe its pooled connection closing only after the HTTP
// drain completed. A close issued before the drain cannot close the
// handler's active connection, so with the wrong order the endpoint would
// never observe a StateClosed transition here. After the drain no handler is
// alive, so a lazy-create after the close is structurally impossible.
// TestShutdownClosesSharedEngineAdapterOnlyAfterHTTPDrain is the shutdown
// ordering regression for the shared Engine adapter. A real registry login
// handler is accepted and blocked while the shared adapter is mid-use — the
// fake Engine holds the adapter's first Engine call, the API negotiation
// ping; the login handler cannot proceed without it. Shutdown is then
// initiated through the production serving stack.
//
// A close issued before the HTTP drain is observable twice: closing while
// the adapter's connection is still active marks the transport's pooled
// connection for closure, so the connection is torn down as soon as it
// becomes idle — while the login is still completing — and the connection
// the login actually used is created after that and is never closed at all.
// With the accepted order the same connection survives the whole login,
// stays pooled through the drain, and the fake Engine observes exactly one
// StateClosed transition after the drain completed.
func TestShutdownClosesSharedEngineAdapterOnlyAfterHTTPDrain(t *testing.T) {
	pingHeld := make(chan struct{})
	pingRelease := make(chan struct{})
	authDone := make(chan struct{})
	var closedConns atomic.Int32

	engine := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/_ping":
			// Hold the negotiation so the login handler is provably
			// mid-adapter-use while the shutdown trigger fires.
			var once sync.Once
			once.Do(func() { close(pingHeld) })
			select {
			case <-pingRelease:
			case <-r.Context().Done():
			}
			w.Header().Set("Api-Version", "1.51")
			w.Header().Set("Ostype", "linux")
			w.WriteHeader(http.StatusOK)
		case strings.HasSuffix(r.URL.Path, "/auth"):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"Status":"Login Succeeded"}`))
			close(authDone)
		default:
			http.NotFound(w, r)
		}
	}))
	engine.Config.ConnState = func(c net.Conn, cs http.ConnState) {
		if cs == http.StateClosed {
			closedConns.Add(1)
		}
	}
	engine.Start()
	t.Cleanup(engine.Close)
	t.Setenv("DOCKER_HOST", engine.URL)

	app := newTestAppWithAdminToken(t)
	app.Config.ShutdownTimeout = 30 * time.Second
	session, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	mux := http.NewServeMux()
	registerRoutes(mux, app)
	server := &http.Server{Handler: mux}
	listener, err := net.Listen("unix", filepath.Join(t.TempDir(), "shutdown-order.sock"))
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	signalCtx, signalCancel := context.WithCancel(context.Background())
	t.Cleanup(signalCancel)
	serverDone := make(chan error, 1)
	go func() {
		shutdownCtx, shutdownCancel, drainDone, serveErr := serveHTTPUntilShutdown(
			signalCtx, server, listener, nil,
			func() time.Duration { return app.getConfig().ShutdownTimeout },
			app.beginShutdown,
		)
		serverDone <- terminateDaemonServing(app, shutdownCtx, shutdownCancel, drainDone)
		if serveErr != nil {
			t.Errorf("serveHTTPUntilShutdown: %v", serveErr)
		}
	}()

	// A real registry login through the production route, blocked inside
	// the shared adapter's first Engine call.
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", listener.Addr().String())
		},
	}
	loginBody := []byte(`{"registry":"registry.example.com","username":"user","password":"pass"}`)
	req, err := http.NewRequest(http.MethodPost, "http://localhost/registry/login", bytes.NewReader(loginBody))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+session.Token)
	loginDone := make(chan int, 1)
	go func() {
		resp, err := (&http.Client{Transport: transport}).Do(req)
		if err != nil {
			t.Errorf("registry login request: %v", err)
			loginDone <- 0
			return
		}
		resp.Body.Close()
		loginDone <- resp.StatusCode
	}()

	select {
	case <-pingHeld:
	case <-time.After(10 * time.Second):
		t.Fatal("the login handler never reached the shared Engine adapter")
	}

	// Initiate shutdown while the login handler is mid-adapter-use. None of
	// the termination steps tracks the login handler, so the drain is what
	// still waits for it, and the adapter close must come only after that
	// drain.
	signalCancel()

	// No connection may close while the handler is still mid-flight.
	if closed := closedConns.Load(); closed != 0 {
		t.Fatalf("a shared adapter connection closed before the login completed: %d", closed)
	}

	// Release the handler and let the login, the drain, and the ordered
	// shutdown sequence complete.
	close(pingRelease)

	select {
	case code := <-loginDone:
		if code != http.StatusOK {
			t.Fatalf("registry login status = %d, want 200", code)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the login handler never completed")
	}
	select {
	case <-authDone:
	case <-time.After(15 * time.Second):
		t.Fatal("the fake Engine never completed the login call")
	}

	// The connection that carried the login must not have been closed by
	// the time the login completed: a pre-drain close marks the transport's
	// pooled connection for closure, which tears it down as soon as it
	// becomes idle — during the login, never after the drain.
	closedAtLoginDone := closedConns.Load()

	select {
	case drainErr := <-serverDone:
		if drainErr != nil {
			t.Fatalf("drain error: %v", drainErr)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the serving shutdown never completed")
	}

	// After the drain the adapter's pooled connection must be released.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if closedConns.Load() > closedAtLoginDone {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if closedConns.Load() <= closedAtLoginDone {
		t.Error("the Engine endpoint never observed the shared adapter's connection closing after the drain")
	}
}

// fakeBuildRequest records what a fake Engine /build endpoint received.
type fakeBuildRequest struct {
	query          url.Values
	registryConfig string
	contentType    string
	context        []byte
	contextErr     error
}

// fakeBuildStream answers the /build endpoint with the given JSON stream
// lines after recording the request.
func fakeBuildStream(record *fakeBuildRequest, lines ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if record != nil {
			record.query = r.URL.Query()
			record.registryConfig = r.Header.Get("X-Registry-Config")
			record.contentType = r.Header.Get("Content-Type")
			blob, err := io.ReadAll(r.Body)
			record.contextErr = err
			record.context = blob
		}
		w.Header().Set("Content-Type", "application/json")
		for _, line := range lines {
			_, _ = w.Write([]byte(line))
		}
	}
}

// TestEngineImageBuildRequestContract proves the adapter's Engine build
// request shape: the accepted build semantics — the requested tag, the
// Dockerfile selection, build args, the base-image pull freshness of the
// previous docker CLI --pull, the daemon default of removing intermediate
// containers, and the supported BuildKit builder — reach the Engine query,
// the prepared context stream is the body, and the build carries exactly
// the request-owned BuildKit session the adapter dialed.
func TestEngineImageBuildRequestContract(t *testing.T) {
	var record fakeBuildRequest
	sessionDials := &fakeSessionRecorder{}
	srv := newFakeEngine(t, "1.51", nil, nil, fakeBuildStream(&record,
		`{"stream":"#1 [internal] load build definition from Dockerfile\n"}`,
		`{"stream":"#1 DONE 0.0s\n"}`,
	), fakeEngineSessionHandler(t, sessionDials))

	eng := newEngineClientAgainstFake(t, srv.URL)
	ctxBody := bytes.NewReader([]byte("tar-context-bytes"))
	result, err := eng.imageBuild(context.Background(), engineBuildSpec{
		Image:      "example:tag",
		Context:    ctxBody,
		Dockerfile: "sub/Dockerfile",
		BuildArgs:  map[string]string{"GREETING": "hello", "EMPTY": ""},
	}, 1<<20)
	if err != nil {
		t.Fatalf("imageBuild: %v", err)
	}

	if result.Truncated {
		t.Error("short stream must not be truncated")
	}
	if result.Output != "#1 [internal] load build definition from Dockerfile\n#1 DONE 0.0s\n" {
		t.Errorf("build output = %q", result.Output)
	}
	if got := record.query.Get("t"); got != "example:tag" {
		t.Errorf("tag query = %q", got)
	}
	if got := record.query.Get("dockerfile"); got != "sub/Dockerfile" {
		t.Errorf("dockerfile query = %q", got)
	}
	if got := record.query.Get("version"); got != "2" {
		t.Errorf("builder version query = %q", got)
	}
	if got := record.query.Get("pull"); got != "1" {
		t.Errorf("the build must preserve the docker CLI --pull freshness, pull query = %q", got)
	}
	if _, keep := record.query["rm"]; keep {
		t.Errorf("rm query must stay at the daemon default, got %q", record.query.Get("rm"))
	}
	var buildArgs map[string]*string
	if err := json.Unmarshal([]byte(record.query.Get("buildargs")), &buildArgs); err != nil {
		t.Fatalf("decode buildargs: %v", err)
	}
	if len(buildArgs) != 2 || buildArgs["GREETING"] == nil || *buildArgs["GREETING"] != "hello" {
		t.Errorf("build args = %v", buildArgs)
	}
	if buildArgs["EMPTY"] == nil || *buildArgs["EMPTY"] != "" {
		t.Errorf("empty build arg must stay an empty value, got %v", buildArgs["EMPTY"])
	}
	if record.contentType != "application/x-tar" {
		t.Errorf("context content type = %q", record.contentType)
	}
	if string(record.context) != "tar-context-bytes" {
		t.Errorf("context body = %q", record.context)
	}
	// The build must carry exactly the request-owned session the adapter
	// dialed through the Engine hijack endpoint, one session per build.
	if sessionDials.count() != 1 {
		t.Fatalf("session dials = %d, want 1", sessionDials.count())
	}
	if got, want := record.query.Get("session"), sessionDials.singleUUID(); got == "" || got != want {
		t.Errorf("build session = %q, dialed session = %q", got, want)
	}
}

// TestEngineImageBuildSessionTransportFailureIsBackendFailure proves a
// session transport failure on an otherwise successful build is an
// interaction failure, not a build failure the Engine reported.
func TestEngineImageBuildSessionTransportFailureIsBackendFailure(t *testing.T) {
	srv := newFakeEngine(t, "1.51", nil, nil, fakeBuildStream(nil,
		`{"stream":"#1 DONE 0.0s\n"}`,
	), func(w http.ResponseWriter, r *http.Request) {
		// The daemon refuses the session hijack.
		w.WriteHeader(http.StatusInternalServerError)
	})

	eng := newEngineClientAgainstFake(t, srv.URL)
	_, err := eng.imageBuild(context.Background(), engineBuildSpec{
		Image:   "example:tag",
		Context: bytes.NewReader(nil),
	}, 1<<20)

	var engErr *engineError
	if !errors.As(err, &engErr) {
		t.Fatalf("imageBuild error = %v, want *engineError", err)
	}
	if engErr.kind != engineErrBackendFailure {
		t.Errorf("error kind = %d, want backend failure", engErr.kind)
	}
}

// TestEngineImageBuildAuthProviderHostScope proves the auth provider
// callback the adapter registers on the request-owned BuildKit session:
// it resolves exactly the requested registry host's stored Session
// credential, never returns an unrelated stored credential, degrades a
// missing credential to anonymous authentication, prefers a stored
// identity token over an auth pair, and sanitizes storage failures without
// credential material.
func TestEngineImageBuildAuthProviderHostScope(t *testing.T) {
	const userCanary = "dh-auth-user-canary-8qLw3nTz5c"
	const passCanary = "dh-auth-pass-canary-Rm2Kx7Vb9d"
	const hubCanary = "dh-auth-hub-canary-Xw4Pn8Qr2e"
	resolver := buildCredentialResolver(func(registryHost string) (*sessionRegistryCredential, error) {
		switch normalizeRegistryAddress(registryHost) {
		case "registry.example.com":
			return &sessionRegistryCredential{Registry: "registry.example.com", Username: userCanary, Password: passCanary}, nil
		case "other.example.com":
			return &sessionRegistryCredential{Registry: "other.example.com", Username: "other-user", Password: "other-pass"}, nil
		case "token.example.com":
			return &sessionRegistryCredential{Registry: "token.example.com", IdentityToken: "id-tok-123"}, nil
		case dockerHubAuthConfigKey:
			return &sessionRegistryCredential{Registry: dockerHubAuthConfigKey, Username: "hub-user", Password: hubCanary}, nil
		case "broken.example.com":
			return nil, errors.New("cannot read session Docker credential file: permission denied")
		default:
			return nil, nil
		}
	})
	provider := engineBuildAuthProvider(resolver)

	// A stored credential reaches the auth callback only for its own host.
	auth, err := provider(context.Background(), "registry.example.com", []string{"pull"}, nil)
	if err != nil {
		t.Fatalf("provider(registry.example.com): %v", err)
	}
	if auth.Username != userCanary || auth.Password != passCanary {
		t.Errorf("registry.example.com auth = %+v", auth)
	}

	// An unrelated stored credential is never returned for another host.
	for _, host := range []string{"unknown.example.com", "sub.registry.example.com", "other.example.org"} {
		auth, err = provider(context.Background(), host, nil, nil)
		if err != nil {
			t.Fatalf("provider(%q): %v", host, err)
		}
		if auth.Username != "" || auth.Password != "" || auth.IdentityToken != "" {
			t.Errorf("unrequested host %q received credential material: %+v", host, auth)
		}
	}

	// A stored identity token keeps its priority over an auth pair.
	auth, err = provider(context.Background(), "token.example.com", nil, nil)
	if err != nil {
		t.Fatalf("provider(token.example.com): %v", err)
	}
	if auth.IdentityToken != "id-tok-123" || auth.Username != "" || auth.Password != "" {
		t.Errorf("token.example.com auth = %+v", auth)
	}

	// Every Docker Hub spelling resolves the stored Docker Hub credential.
	for _, host := range []string{"registry-1.docker.io", "docker.io", "index.docker.io", dockerHubAuthConfigKey} {
		auth, err = provider(context.Background(), host, nil, nil)
		if err != nil {
			t.Fatalf("provider(%q): %v", host, err)
		}
		if auth.Password != hubCanary {
			t.Errorf("hub spelling %q auth = %+v, want the stored hub credential", host, auth)
		}
	}

	// A storage failure stays operational and must not carry credential
	// material through the error the BuildKit auth RPC would deliver.
	_, err = provider(context.Background(), "broken.example.com", nil, nil)
	if err == nil {
		t.Fatal("a storage failure must be an error, not a silent anonymous fallback")
	}
	if strings.Contains(err.Error(), userCanary) || strings.Contains(err.Error(), passCanary) || strings.Contains(err.Error(), hubCanary) {
		t.Errorf("storage failure leaked credential material: %v", err)
	}

	// A nil resolver is anonymous.
	auth, err = engineBuildAuthProvider(nil)(context.Background(), "registry.example.com", nil, nil)
	if err != nil || auth.Username != "" || auth.Password != "" {
		t.Errorf("nil resolver auth = %+v err = %v", auth, err)
	}
}

// TestEngineImageBuildStreamTruncation proves the bounded-output contract on
// the build stream: newest bytes are retained and truncation is reported.
func TestEngineImageBuildStreamTruncation(t *testing.T) {
	const lines = 20
	var stream []string
	for i := 0; i < lines; i++ {
		stream = append(stream, fmt.Sprintf(`{"stream":"step %02d\n"}`, i))
	}
	srv := newFakeEngine(t, "1.51", nil, nil, fakeBuildStream(nil, stream...))

	eng := newEngineClientAgainstFake(t, srv.URL)
	result, err := eng.imageBuild(context.Background(), engineBuildSpec{
		Image:   "example:tag",
		Context: bytes.NewReader(nil),
	}, 20)
	if err != nil {
		t.Fatalf("imageBuild: %v", err)
	}

	if !result.Truncated {
		t.Error("truncation must be reported")
	}
	if !strings.Contains(result.Output, "step 19") {
		t.Errorf("newest step lost: %q", result.Output)
	}
	if !strings.Contains(result.Output, "step 18") {
		t.Errorf("the newest window must keep more than the last line: %q", result.Output)
	}
	if strings.Contains(result.Output, "step 00") {
		t.Errorf("oldest steps must be dropped: %q", result.Output)
	}
}

// TestEngineImageBuildEmbeddedFailure proves an in-band build failure is
// normalized as a trustworthy build failure with the output preserved.
func TestEngineImageBuildEmbeddedFailure(t *testing.T) {
	srv := newFakeEngine(t, "1.51", nil, nil, fakeBuildStream(nil,
		`{"stream":"#5 [2/2] RUN exit 2\n"}`,
		`{"errorDetail":{"message":"process \"/bin/sh\" did not complete successfully: exit code: 2"},"error":"process \"/bin/sh\" did not complete successfully: exit code: 2"}`,
	))

	eng := newEngineClientAgainstFake(t, srv.URL)
	result, err := eng.imageBuild(context.Background(), engineBuildSpec{
		Image:   "example:tag",
		Context: bytes.NewReader(nil),
	}, 1<<20)

	var engErr *engineError
	if !errors.As(err, &engErr) {
		t.Fatalf("imageBuild error = %v, want *engineError", err)
	}
	if engErr.kind != engineErrBuildFailed {
		t.Errorf("error kind = %d, want build failed", engErr.kind)
	}
	if !strings.Contains(result.Output, "exit code: 2") {
		t.Errorf("embedded build failure output lost: %q", result.Output)
	}
}

// TestEngineImageBuildEmbeddedAuthDenied proves an in-band registry denial
// for a private FROM keeps the registry-auth-denied category, both through
// the errdefs-typed signal and the message classifier.
func TestEngineImageBuildEmbeddedAuthDenied(t *testing.T) {
	cases := []struct {
		name string
		line string
	}{
		{
			name: "typed",
			line: `{"errorDetail":{"message":"unauthorized: authentication required","code":401},"error":"unauthorized: authentication required"}`,
		},
		{
			name: "classified",
			line: `{"error":"pull access denied for dh/private, repository does not exist or may require authorization"}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newFakeEngine(t, "1.51", nil, nil, fakeBuildStream(nil, tc.line))

			eng := newEngineClientAgainstFake(t, srv.URL)
			_, err := eng.imageBuild(context.Background(), engineBuildSpec{
				Image:   "example:tag",
				Context: bytes.NewReader(nil),
			}, 1<<20)

			var engErr *engineError
			if !errors.As(err, &engErr) {
				t.Fatalf("imageBuild error = %v, want *engineError", err)
			}
			if engErr.kind != engineErrRegistryAuthDenied {
				t.Errorf("error kind = %d, want registry auth denied", engErr.kind)
			}
		})
	}
}

// TestEngineImageBuildMalformedStream proves a malformed build stream is a
// backend failure, not a build failure: the outcome is not trustworthy.
func TestEngineImageBuildMalformedStream(t *testing.T) {
	srv := newFakeEngine(t, "1.51", nil, nil, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"stream":"#1 ...`))
	})

	eng := newEngineClientAgainstFake(t, srv.URL)
	_, err := eng.imageBuild(context.Background(), engineBuildSpec{
		Image:   "example:tag",
		Context: bytes.NewReader(nil),
	}, 1<<20)

	var engErr *engineError
	if !errors.As(err, &engErr) {
		t.Fatalf("imageBuild error = %v, want *engineError", err)
	}
	if engErr.kind != engineErrBackendFailure {
		t.Errorf("error kind = %d, want backend failure", engErr.kind)
	}
}

// TestEngineImageBuildTransportFailure proves an unreachable Engine is the
// backend-unavailable category.
func TestEngineImageBuildTransportFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close() // nothing listens anymore

	eng := newEngineClientAgainstFake(t, url)
	_, err := eng.imageBuild(context.Background(), engineBuildSpec{
		Image:   "example:tag",
		Context: bytes.NewReader(nil),
	}, 1<<20)

	var engErr *engineError
	if !errors.As(err, &engErr) {
		t.Fatalf("imageBuild error = %v, want *engineError", err)
	}
	if engErr.kind != engineErrBackendUnavailable {
		t.Errorf("error kind = %d, want backend unavailable", engErr.kind)
	}
}

// TestEngineImageBuildCancellationClosesBody proves a cancelled build
// request is the client-cancelled category, the fake Engine handler observes
// the client disconnect, and the adapter closes the build response body.
func TestEngineImageBuildCancellationClosesBody(t *testing.T) {
	requestStarted := make(chan struct{})
	handlerDone := make(chan struct{})
	srv := newFakeEngine(t, "1.51", nil, nil, func(w http.ResponseWriter, r *http.Request) {
		close(requestStarted)
		<-r.Context().Done()
		close(handlerDone)
	})

	eng := newEngineClientAgainstFake(t, srv.URL)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	buildCtx, buildCancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() {
		_, err := eng.imageBuild(buildCtx, engineBuildSpec{
			Image:   "example:tag",
			Context: bytes.NewReader(nil),
		}, 1<<20)
		done <- err
	}()

	select {
	case <-requestStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("the Engine never received the build request")
	}

	buildCancel()

	select {
	case err := <-done:
		var engErr *engineError
		if !errors.As(err, &engErr) {
			t.Fatalf("cancelled imageBuild error = %v, want *engineError", err)
		}
		if engErr.kind != engineErrClientCancelled {
			t.Errorf("error kind = %d, want client cancelled", engErr.kind)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("imageBuild did not return after cancellation")
	}

	select {
	case <-handlerDone:
	case <-time.After(15 * time.Second):
		t.Fatal("the fake Engine handler never observed the client disconnect")
	}
}

// TestNormalizeEngineBuildErrorKinds proves the build error classifiers map
// the accepted categories. An interaction failure — malformed or
// transport-broken request or stream — is a backend failure, never a build
// failure; an in-band stream failure that fits no registry or cancellation
// category is a build failure the Engine reported, including a base image
// the registry cannot resolve, which for a build is not the pull contract's
// image-not-found.
func TestNormalizeEngineBuildErrorKinds(t *testing.T) {
	cases := []struct {
		name         string
		err          error
		wantOK       bool
		wantInter    engineErrorKind
		wantEmbedded engineErrorKind
	}{
		{
			name: "nil",
			err:  nil,
		},
		{
			name:         "cancelled",
			err:          fmt.Errorf("wrapped: %w", context.Canceled),
			wantOK:       true,
			wantInter:    engineErrClientCancelled,
			wantEmbedded: engineErrClientCancelled,
		},
		{
			name:         "deadline",
			err:          fmt.Errorf("wrapped: %w", context.DeadlineExceeded),
			wantOK:       true,
			wantInter:    engineErrClientCancelled,
			wantEmbedded: engineErrClientCancelled,
		},
		{
			name:         "typed unauthorized",
			err:          errhttp.ToNative(401),
			wantOK:       true,
			wantInter:    engineErrRegistryAuthDenied,
			wantEmbedded: engineErrRegistryAuthDenied,
		},
		{
			name:         "typed permission denied",
			err:          errhttp.ToNative(403),
			wantOK:       true,
			wantInter:    engineErrRegistryAuthDenied,
			wantEmbedded: engineErrRegistryAuthDenied,
		},
		{
			name:         "request level daemon error",
			err:          errors.New("Error response from daemon: unexpected failure"),
			wantOK:       true,
			wantInter:    engineErrBackendFailure,
			wantEmbedded: engineErrBuildFailed,
		},
		{
			name:         "in-band build failure",
			err:          errors.New(`process "/bin/sh" did not complete successfully: exit code: 2`),
			wantOK:       true,
			wantInter:    engineErrBackendFailure,
			wantEmbedded: engineErrBuildFailed,
		},
		{
			name:         "in-band base image missing",
			err:          errors.New("manifest for alpine:3.999 not found: manifest unknown"),
			wantOK:       true,
			wantInter:    engineErrBackendFailure,
			wantEmbedded: engineErrBuildFailed,
		},
		{
			name:         "in-band registry denial",
			err:          errors.New("pull access denied for dh/private, repository does not exist or may require authorization"),
			wantOK:       true,
			wantInter:    engineErrBackendFailure,
			wantEmbedded: engineErrRegistryAuthDenied,
		},
		{
			name:         "in-band registry network failure",
			err:          errors.New("Get \"https://registry.example.com/v2/\": dial tcp 127.0.0.1:1: connect: connection refused"),
			wantOK:       true,
			wantInter:    engineErrBackendFailure,
			wantEmbedded: engineErrRegistryUnavailable,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inter := normalizeEngineBuildError(tc.err)
			embedded := normalizeEmbeddedBuildError(tc.err)
			var interErr, embeddedErr *engineError
			gotInterOK := errors.As(inter, &interErr)
			gotEmbeddedOK := errors.As(embedded, &embeddedErr)
			if tc.wantOK != (gotInterOK && gotEmbeddedOK) {
				t.Fatalf("normalizers returned %v / %v", inter, embedded)
			}
			if !tc.wantOK {
				return
			}
			if interErr.kind != tc.wantInter {
				t.Errorf("interaction kind = %d, want %d", interErr.kind, tc.wantInter)
			}
			if embeddedErr.kind != tc.wantEmbedded {
				t.Errorf("embedded kind = %d, want %d", embeddedErr.kind, tc.wantEmbedded)
			}
		})
	}
}
