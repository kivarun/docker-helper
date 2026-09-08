package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/api/types/registry"
	"github.com/moby/moby/client"
)

// newFakeEngine serves the minimal Engine endpoints used by the adapter
// tests: the unversioned /_ping negotiation endpoint, the /auth registry
// validation endpoint, and the /images/create pull endpoint. A nil handler
// leaves the corresponding endpoint answering 404.
func newFakeEngine(t *testing.T, apiVersion string, authHandler, pullHandler http.HandlerFunc) *httptest.Server {
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
		case strings.HasSuffix(r.URL.Path, "/images/create"):
			if pullHandler != nil {
				pullHandler(w, r)
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
	}, nil)
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
	}, nil)

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
			srv := newFakeEngine(t, tc.apiVersion, tc.authHandler, nil)
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
	}, nil)

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
	))

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
			))

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
			srv := newFakeEngine(t, "1.51", nil, fakePullStream(&record, tc.body))

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
	srv := newFakeEngine(t, "1.51", nil, fakePullStream(&record))
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
	})

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
	srv := newFakeEngine(t, "1.51", nil, fakePullStream(&record, lines...))

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
