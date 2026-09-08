package main

import (
	"context"
	"errors"
	"fmt"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/containerd/errdefs/pkg/errhttp"
	"github.com/moby/moby/api/pkg/authconfig"
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
	// engineErrClientCancelled means the pull request context was cancelled
	// before the pull completed (client disconnect, shutdown, or deadline).
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
	case engineErrClientCancelled:
		return "pull request cancelled"
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
		buf.Write([]byte(renderEnginePullMessage(msg)))
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

// renderEnginePullMessage renders one Engine pull progress message in the
// line-based form the docker CLI printed for pull output: raw stream text
// verbatim, otherwise the status line, prefixed with the layer ID when the
// message carries one.
func renderEnginePullMessage(msg jsonstream.Message) string {
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
