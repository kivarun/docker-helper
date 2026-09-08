package main

import (
	"context"
	"fmt"

	cerrdefs "github.com/containerd/errdefs"
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
)

// engineError is a normalized Engine failure. The raw backend error is kept
// only as the unwrappable cause for operator diagnostics; public-facing
// handlers map the kind to a sanitized code and never copy cause text.
type engineError struct {
	kind  engineErrorKind
	cause error
}

func (e *engineError) Error() string { return e.cause.Error() }
func (e *engineError) Unwrap() error { return e.cause }

// engineClient is the single production Docker Engine adapter owner for
// Release 3. It owns Moby client construction, API negotiation, and the
// normalization of Engine failures into docker-helper error categories.
// Moby request/response types stay inside the adapter; production callers
// pass and receive domain values and normalized errors only.
type engineClient struct {
	cli *client.Client
}

// newEngineClient constructs the Engine adapter against the configured
// Engine endpoint with API version negotiation, matching the reviewed D0.1
// client configuration.
func newEngineClient() (*engineClient, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("cannot construct docker engine client: %w", err)
	}
	return &engineClient{cli: cli}, nil
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
	case dockerErrorNetwork:
		return &engineError{kind: engineErrRegistryUnavailable, cause: err}
	default:
		return &engineError{kind: engineErrBackendFailure, cause: err}
	}
}

// newEngineRegistryAuthenticator returns the Engine adapter for the
// registry-login path. Production default (nil NewEngineClientFn) constructs
// the single engineClient adapter.
func (a *App) newEngineRegistryAuthenticator() (engineRegistryAuthenticator, error) {
	if a.NewEngineClientFn != nil {
		return a.NewEngineClientFn()
	}
	return newEngineClient()
}
