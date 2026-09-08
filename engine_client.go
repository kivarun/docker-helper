package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/containerd/errdefs/pkg/errhttp"
	authtypes "github.com/docker/cli/cli/config/types"
	"github.com/moby/buildkit/session"
	"github.com/moby/buildkit/session/auth/authprovider"
	"github.com/moby/moby/api/pkg/authconfig"
	buildtypes "github.com/moby/moby/api/types/build"
	"github.com/moby/moby/api/types/jsonstream"
	"github.com/moby/moby/api/types/registry"
	"github.com/moby/moby/client"
)

// engineRegistryAuthenticator is the narrow Engine surface consumed by the
// registry-login path. The production implementation is the single Engine
// adapter owner below; tests may substitute a narrower authenticator.
type engineRegistryAuthenticator interface {
	// registryLogin validates registry credentials through the Engine. It
	// returns the identity token issued by the registry, if any, and a
	// normalized engineError on failure.
	registryLogin(ctx context.Context, registry, username, password string) (identityToken string, err error)
}

// engineImagePuller is the narrow Engine surface consumed by the pull path.
// The production implementation is the single Engine adapter owner below;
// tests may substitute a narrower puller.
type engineImagePuller interface {
	// imagePull pulls imageRef through the Engine, rendering the pull
	// progress stream into bounded combined output. credential selects a
	// stored Session registry credential; nil pulls unauthenticated. On
	// failure the result still carries the output rendered before the
	// failure and err is a normalized engineError.
	imagePull(ctx context.Context, imageRef string, credential *sessionRegistryCredential, outputLimit int64) (enginePullResult, error)
}

// engineImageBuilder is the narrow Engine surface consumed by the build
// path. The production implementation is the single Engine adapter owner
// below; tests may substitute a narrower builder.
type engineImageBuilder interface {
	// imageBuild builds through the Engine ImageBuild endpoint, consuming
	// the prepared trusted context stream and rendering the build progress
	// stream into bounded combined output. On failure the result still
	// carries the output rendered before the failure and err is a
	// normalized engineError.
	imageBuild(ctx context.Context, spec engineBuildSpec, outputLimit int64) (engineBuildResult, error)
}

// engineBuildSpec is one prepared build request for the Engine adapter.
// Context is the tar stream of the staged, helper-owned build context; the
// adapter consumes the prepared trusted context and is not the
// workspace-policy owner. Credentials resolves stored Session registry
// credentials just in time, for exactly the registry host BuildKit asks
// about through the request-owned auth session; the adapter never logs or
// echoes credential material.
type engineBuildSpec struct {
	Image       string
	Context     io.Reader
	Dockerfile  string
	BuildArgs   map[string]string
	Credentials buildCredentialResolver
}

// engineBuildResult is the bounded combined output of one Engine build.
type engineBuildResult struct {
	Output    string
	Truncated bool
}

// enginePullResult is the bounded combined output of one Engine pull.
type enginePullResult struct {
	Output    string
	Truncated bool
}

// engineErrorKind is a normalized category of an Engine failure. The kinds
// map one-to-one onto the accepted registry-login failure codes; they never
// carry raw backend payloads.
type engineErrorKind int

const (
	// engineErrBackendFailure means the Engine interaction failed in an
	// unexpected way that does not fit a recognized category; a trustworthy
	// result cannot be derived from it.
	engineErrBackendFailure engineErrorKind = iota
	// engineErrBackendUnavailable means the Engine endpoint itself cannot be
	// reached or observed.
	engineErrBackendUnavailable
	// engineErrRegistryAuthDenied means the Engine reports that the registry
	// rejected the supplied credentials.
	engineErrRegistryAuthDenied
	// engineErrRegistryUnavailable means the Engine is reachable but reports
	// that the registry cannot be reached.
	engineErrRegistryUnavailable
	// engineErrImageNotFound means the Engine reports that the requested
	// image or manifest does not exist on the registry.
	engineErrImageNotFound
	// engineErrBuildFailed means the Engine reported a terminal build
	// failure inside the build stream: the build mechanism rejected or
	// failed the build, and the bounded output is a trustworthy negative
	// result.
	engineErrBuildFailed
	// engineErrClientCancelled means the request context was cancelled
	// before the Engine operation completed (client disconnect, shutdown,
	// or deadline).
	engineErrClientCancelled
)

// engineError is a normalized Engine failure. Error deliberately exposes only
// the normalized category: raw backend payloads must not leak through ordinary
// logging or public error handling. The cause remains available through Unwrap
// for narrow internal classification/diagnostics that explicitly opt into it.
type engineError struct {
	kind  engineErrorKind
	cause error
}

func (e *engineError) Error() string {
	switch e.kind {
	case engineErrBackendUnavailable:
		return "docker engine unavailable"
	case engineErrRegistryAuthDenied:
		return "registry authentication denied"
	case engineErrRegistryUnavailable:
		return "registry unavailable"
	case engineErrImageNotFound:
		return "image not found"
	case engineErrBuildFailed:
		return "image build failed"
	case engineErrClientCancelled:
		return "request cancelled"
	default:
		return "docker engine failure"
	}
}

func (e *engineError) Unwrap() error { return e.cause }

// engineClient is the single production Docker Engine adapter owner for
// Release 3. It owns Moby client construction, API negotiation, and the
// normalization of Engine failures into docker-helper error categories.
// The App holds one engineClient for its lifetime and resolves it for every
// Engine consumer — registry login, pull, and further Engine API
// migrations — instead of constructing one per request. The Moby client is
// built for that shared use: API version negotiation is single-flighted
// under the client's own lock, and the HTTP transport is the stdlib
// concurrency contract. Moby request/response types stay inside the
// adapter; production callers pass and receive domain values and
// normalized errors only.
type engineClient struct {
	cli *client.Client
}

// newEngineClient constructs the Engine adapter against the configured
// Engine endpoint with API version negotiation, matching the reviewed D0.1
// client configuration. The App creates it once per lifetime through
// sharedEngineAdapter; construction does not dial the Engine, so it fails
// only on malformed Engine endpoint configuration.
func newEngineClient() (*engineClient, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("cannot construct docker engine client: %w", err)
	}
	return &engineClient{cli: cli}, nil
}

// close releases the shared Moby client's pooled idle connections to the
// Engine endpoint. Connections with in-flight requests are untouched; the
// App calls this once at daemon shutdown after Engine request termination.
func (e *engineClient) close() {
	if e.cli != nil {
		_ = e.cli.Close()
	}
}

// registryLogin validates registry credentials through the Engine /auth
// endpoint — the same daemon operation the docker CLI login path delegated
// to. The credential is handed to the Engine only for this validation; the
// adapter returns the registry-issued identity token, if any.
func (e *engineClient) registryLogin(ctx context.Context, registryAddr, username, password string) (string, error) {
	resp, err := e.cli.RegistryLogin(ctx, client.RegistryLoginOptions{
		Username:      username,
		Password:      password,
		ServerAddress: registryAddr,
	})
	if err != nil {
		return "", normalizeEngineRegistryError(err)
	}
	return resp.Auth.IdentityToken, nil
}

// normalizeEngineRegistryError maps an Engine failure to the normalized
// error categories. Typed backend signals are preferred; the message
// classifier is used only for Engine-reported registry failures, which the
// Engine exposes without a stable typed signal.
func normalizeEngineRegistryError(err error) error {
	if err == nil {
		return nil
	}
	if client.IsErrConnectionFailed(err) {
		return &engineError{kind: engineErrBackendUnavailable, cause: err}
	}
	if cerrdefs.IsUnauthorized(err) {
		return &engineError{kind: engineErrRegistryAuthDenied, cause: err}
	}
	switch classifyDockerError(err.Error()) {
	case dockerErrorAuthDenied:
		return &engineError{kind: engineErrRegistryAuthDenied, cause: err}
	case dockerErrorNetwork:
		return &engineError{kind: engineErrRegistryUnavailable, cause: err}
	default:
		return &engineError{kind: engineErrBackendFailure, cause: err}
	}
}

// newEngineRegistryAuthenticator returns the Engine adapter for the
// registry-login path: the test seam when set, otherwise the App's shared
// adapter.
func (a *App) newEngineRegistryAuthenticator() (engineRegistryAuthenticator, error) {
	if a.NewEngineClientFn != nil {
		return a.NewEngineClientFn()
	}
	return a.sharedEngineAdapter()
}

// newEngineImagePuller returns the Engine adapter for the pull path: the
// test seam when set, otherwise the App's shared adapter.
func (a *App) newEngineImagePuller() (engineImagePuller, error) {
	if a.NewEnginePullFn != nil {
		return a.NewEnginePullFn()
	}
	return a.sharedEngineAdapter()
}

// newEngineImageBuilder returns the Engine adapter for the build path: the
// test seam when set, otherwise the App's shared adapter.
func (a *App) newEngineImageBuilder() (engineImageBuilder, error) {
	if a.NewEngineBuildFn != nil {
		return a.NewEngineBuildFn()
	}
	return a.sharedEngineAdapter()
}

// engineBuildStreamMessage extends the Engine JSON stream message with the
// bare "error" field the docker JSON stream convention carries alongside
// errorDetail, which the docker CLI also honors as the error message.
type engineBuildStreamMessage struct {
	jsonstream.Message
	ErrorMessage string `json:"error,omitempty"`
}

// engineStreamError is an Engine-reported pull failure carried inside the
// pull progress stream: the daemon relays registry failures as in-band
// jsonstream errors rather than HTTP statuses. Unwrap exposes the errdefs
// category matching the reported HTTP status, mirroring how the Moby client
// types embedded stream errors; a zero status carries no typed signal and the
// message classifier decides the category.
type engineStreamError struct {
	message string
	code    int
}

func (e *engineStreamError) Error() string { return e.message }

func (e *engineStreamError) Unwrap() error {
	if e.code == 0 {
		return nil
	}
	return errhttp.ToNative(e.code)
}

// imagePull pulls imageRef through the Engine /images/create pull stream —
// the same daemon operation the docker CLI pull path delegated to. The
// credential, when present, is encoded into the X-Registry-Auth header for
// the Engine only; it never enters argv, environment, logs, audit, or errors.
//
// The progress stream is rendered in the line-based form the docker CLI
// printed for pull output and accumulated in a bounded buffer; an Engine
// error reported inside the stream is appended to the output and normalized.
// The stream is always drained to EOF so the Engine sees a completed read.
func (e *engineClient) imagePull(ctx context.Context, imageRef string, credential *sessionRegistryCredential, outputLimit int64) (enginePullResult, error) {
	opts := client.ImagePullOptions{}
	if credential != nil {
		encoded, err := authconfig.Encode(registry.AuthConfig{
			Username:      credential.Username,
			Password:      credential.Password,
			IdentityToken: credential.IdentityToken,
			ServerAddress: credential.Registry,
		})
		if err != nil {
			return enginePullResult{}, &engineError{kind: engineErrBackendFailure, cause: err}
		}
		opts.RegistryAuth = encoded
	}

	resp, err := e.cli.ImagePull(ctx, imageRef, opts)
	if err != nil {
		return enginePullResult{}, normalizeEnginePullError(err)
	}

	buf := newBoundedBuffer(outputLimit)
	var streamErr error
	var embedded *jsonstream.Error
	for msg, msgErr := range resp.JSONMessages(ctx) {
		if msgErr != nil {
			streamErr = msgErr
			continue
		}
		if msg.Error != nil {
			buf.Write([]byte(msg.Error.Message + "\n"))
			if embedded == nil {
				embedded = msg.Error
			}
			continue
		}
		buf.Write([]byte(renderEngineStreamMessage(msg)))
	}

	if embedded != nil {
		data, _, truncated := buf.Range(0)
		return enginePullResult{Output: string(data), Truncated: truncated}, normalizeEnginePullError(&engineStreamError{
			message: embedded.Message,
			code:    embedded.Code,
		})
	}
	if streamErr != nil {
		data, _, truncated := buf.Range(0)
		return enginePullResult{Output: string(data), Truncated: truncated}, normalizeEnginePullError(streamErr)
	}
	data, _, truncated := buf.Range(0)
	return enginePullResult{Output: string(data), Truncated: truncated}, nil
}

// renderEngineStreamMessage renders one Engine progress message in the
// line-based form the docker CLI printed for pull and build output: raw
// stream text verbatim, otherwise the status line, prefixed with the layer
// ID when the message carries one.
func renderEngineStreamMessage(msg jsonstream.Message) string {
	switch {
	case msg.Stream != "":
		return msg.Stream
	case msg.Status != "":
		if msg.ID != "" {
			return msg.ID + ": " + msg.Status + "\n"
		}
		return msg.Status + "\n"
	default:
		return ""
	}
}

// buildkitSessionSharedKey is the stable session handshake identity shared
// by every docker-helper build session. It is not a secret and carries no
// credential material.
const buildkitSessionSharedKey = "docker-helper"

// imageBuild builds through the Engine ImageBuild endpoint — the same
// daemon operation the docker CLI build path delegated to. The adapter owns
// one request-scoped BuildKit session per build: it registers the
// host-scoped auth provider on it, dials the Engine's /session hijack
// endpoint through the shared Engine client, and hands the session ID to
// the build so the daemon resolves remote sources through that session.
// Docker/BuildKit owns Dockerfile and source semantics; the adapter never
// parses the Dockerfile to discover registries or pre-pull base images.
// PullParent preserves the base-image freshness the previous docker CLI
// --pull produced.
//
// The progress stream is rendered in the line-based form the docker CLI
// printed for build output and accumulated in a bounded buffer; the stream
// is always consumed to its terminal outcome so an in-band build failure is
// detected even after the buffer cap. A build failure the Engine reports
// inside the stream is a trustworthy negative result; a malformed or
// transport-broken stream is not.
func (e *engineClient) imageBuild(ctx context.Context, spec engineBuildSpec, outputLimit int64) (engineBuildResult, error) {
	sess, sessErr := session.NewSession(ctx, buildkitSessionSharedKey)
	if sessErr != nil {
		return engineBuildResult{}, &engineError{kind: engineErrBackendFailure, cause: fmt.Errorf("cannot start build session: %w", sessErr)}
	}
	// The auth provider resolves stored Session credentials just in time for
	// exactly the registry host BuildKit asks about; credential material
	// reaches only that host's auth RPC, never logs or errors.
	sess.Allow(authprovider.NewDockerAuthProvider(authprovider.DockerAuthProviderConfig{
		AuthConfigProvider: engineBuildAuthProvider(spec.Credentials),
	}))

	// One context drives the build and its session, so request cancellation
	// and daemon shutdown terminate both.
	buildCtx, cancelBuild := context.WithCancel(ctx)
	defer cancelBuild()

	sessionDone := make(chan error, 1)
	go func() {
		// Run dials the daemon's /session hijack endpoint through the shared
		// Engine client and serves the session until the build closes it.
		sessionDone <- sess.Run(buildCtx, func(runCtx context.Context, proto string, meta map[string][]string) (net.Conn, error) {
			return e.cli.DialHijack(runCtx, "/session", proto, meta)
		})
	}()

	opts := client.ImageBuildOptions{
		Tags:       []string{spec.Image},
		Dockerfile: spec.Dockerfile,
		Remove:     true, // keep the daemon default of removing intermediate containers
		Version:    buildtypes.BuilderBuildKit,
		PullParent: true, // the base-image freshness the previous docker CLI --pull produced
		SessionID:  sess.ID(),
	}
	if len(spec.BuildArgs) > 0 {
		// The Engine build request carries build-arg values as pointers so
		// an empty value stays an empty value.
		buildArgs := make(map[string]*string, len(spec.BuildArgs))
		for key, value := range spec.BuildArgs {
			value := value
			buildArgs[key] = &value
		}
		opts.BuildArgs = buildArgs
	}

	resp, err := e.cli.ImageBuild(buildCtx, spec.Context, opts)
	if err != nil {
		return engineBuildResult{}, finalizeEngineBuildSession(ctx, sess, sessionDone, normalizeEngineBuildError(err))
	}
	defer resp.Body.Close()

	buf := newBoundedBuffer(outputLimit)
	var streamErr error
	var embedded *jsonstream.Error
	dec := json.NewDecoder(resp.Body)
	for {
		// engineBuildStreamMessage extends the Engine JSON stream message
		// with the bare "error" field the docker JSON stream convention
		// carries alongside errorDetail; the docker CLI honors it too.
		var msg engineBuildStreamMessage
		if err := dec.Decode(&msg); err != nil {
			if !errors.Is(err, io.EOF) {
				streamErr = err
			}
			break
		}
		switch {
		case msg.Error != nil:
			buf.Write([]byte(msg.Error.Message + "\n"))
			if embedded == nil {
				embedded = msg.Error
			}
		case msg.ErrorMessage != "":
			buf.Write([]byte(msg.ErrorMessage + "\n"))
			if embedded == nil {
				embedded = &jsonstream.Error{Message: msg.ErrorMessage}
			}
		default:
			buf.Write([]byte(renderEngineStreamMessage(msg.Message)))
		}
	}

	data, _, truncated := buf.Range(0)
	var buildErr error
	switch {
	case embedded != nil:
		buildErr = normalizeEmbeddedBuildError(&engineStreamError{
			message: embedded.Message,
			code:    embedded.Code,
		})
	case streamErr != nil:
		buildErr = normalizeEngineBuildError(streamErr)
	}
	return engineBuildResult{Output: string(data), Truncated: truncated},
		finalizeEngineBuildSession(ctx, sess, sessionDone, buildErr)
}

// engineBuildAuthProvider adapts the host-scoped Session credential resolver
// to the BuildKit auth provider callback. BuildKit asks for exactly the
// registry host it is resolving; the callback reads only that host's stored
// Session credential, so an unrelated stored credential is never returned.
// Nothing stored for the host degrades to anonymous authentication; a store
// read failure is an operational build failure, not a silent fallback.
func engineBuildAuthProvider(resolve buildCredentialResolver) authprovider.AuthConfigProvider {
	return func(_ context.Context, host string, _ []string, _ authprovider.ExpireCachedAuthCheck) (authtypes.AuthConfig, error) {
		if resolve == nil {
			return authtypes.AuthConfig{}, nil
		}
		credential, err := resolve(host)
		if err != nil {
			return authtypes.AuthConfig{}, err
		}
		if credential == nil {
			return authtypes.AuthConfig{}, nil
		}
		auth := authtypes.AuthConfig{ServerAddress: host}
		if credential.IdentityToken != "" {
			auth.IdentityToken = credential.IdentityToken
			return auth, nil
		}
		auth.Username = credential.Username
		auth.Password = credential.Password
		return auth, nil
	}
}

// finalizeEngineBuildSession closes the request-owned BuildKit session on
// every build exit path and joins its goroutine; the join is bounded by the
// build context. A session transport failure is reported only when the build
// produced no error of its own: a broken session transport is an
// interaction failure, not a build failure the Engine reported. A session
// error caused by cancellation is not a failure.
func finalizeEngineBuildSession(ctx context.Context, sess *session.Session, sessionDone <-chan error, buildErr error) error {
	sess.Close()
	var runErr error
	select {
	case runErr = <-sessionDone:
	case <-ctx.Done():
		runErr = nil
	}
	if buildErr != nil {
		return buildErr
	}
	if runErr == nil || errors.Is(runErr, context.Canceled) || errors.Is(runErr, context.DeadlineExceeded) {
		return nil
	}
	return &engineError{kind: engineErrBackendFailure, cause: runErr}
}

// normalizeEngineBuildError maps a build interaction failure to the
// normalized error categories. Typed backend signals are preferred. An
// interaction failure that prevents a trustworthy build outcome — a
// malformed or transport-broken request or stream — is a backend failure,
// not a build failure the Engine reported.
func normalizeEngineBuildError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return &engineError{kind: engineErrClientCancelled, cause: err}
	}
	if client.IsErrConnectionFailed(err) {
		return &engineError{kind: engineErrBackendUnavailable, cause: err}
	}
	if cerrdefs.IsUnauthorized(err) || cerrdefs.IsPermissionDenied(err) {
		return &engineError{kind: engineErrRegistryAuthDenied, cause: err}
	}
	return &engineError{kind: engineErrBackendFailure, cause: err}
}

// normalizeEmbeddedBuildError classifies a build failure the Engine reported
// inside the build stream. Registry signals keep their categories so the
// credential contract stays observable for private FROM builds; every
// remaining in-stream failure is a build failure the Engine reported, and
// the bounded output is a trustworthy negative result.
func normalizeEmbeddedBuildError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return &engineError{kind: engineErrClientCancelled, cause: err}
	}
	if cerrdefs.IsUnauthorized(err) || cerrdefs.IsPermissionDenied(err) {
		return &engineError{kind: engineErrRegistryAuthDenied, cause: err}
	}
	switch classifyDockerError(err.Error()) {
	case dockerErrorAuthDenied:
		return &engineError{kind: engineErrRegistryAuthDenied, cause: err}
	case dockerErrorNetwork:
		return &engineError{kind: engineErrRegistryUnavailable, cause: err}
	default:
		return &engineError{kind: engineErrBuildFailed, cause: err}
	}
}

// normalizeEnginePullError maps an Engine pull failure to the normalized
// error categories. Typed backend signals are preferred, including the
// errdefs category carried by in-band stream errors; the message classifier
// is used only for Engine-reported registry failures without a typed signal.
// A cancelled request context is its own category so shutdown/cancellation
// is never misreported as an Engine or registry failure.
func normalizeEnginePullError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return &engineError{kind: engineErrClientCancelled, cause: err}
	}
	if client.IsErrConnectionFailed(err) {
		return &engineError{kind: engineErrBackendUnavailable, cause: err}
	}
	if cerrdefs.IsNotFound(err) {
		return &engineError{kind: engineErrImageNotFound, cause: err}
	}
	if cerrdefs.IsUnauthorized(err) || cerrdefs.IsPermissionDenied(err) {
		return &engineError{kind: engineErrRegistryAuthDenied, cause: err}
	}
	switch classifyDockerError(err.Error()) {
	case dockerErrorAuthDenied:
		return &engineError{kind: engineErrRegistryAuthDenied, cause: err}
	case dockerErrorNetwork:
		return &engineError{kind: engineErrRegistryUnavailable, cause: err}
	case dockerErrorImageNotFound:
		return &engineError{kind: engineErrImageNotFound, cause: err}
	default:
		return &engineError{kind: engineErrBackendFailure, cause: err}
	}
}

// errorKindOf reports the normalized category of an adapter error, or the
// backend-failure category for an unclassified error.
func errorKindOf(err error) engineErrorKind {
	var engErr *engineError
	if errors.As(err, &engErr) {
		return engErr.kind
	}
	return engineErrBackendFailure
}
