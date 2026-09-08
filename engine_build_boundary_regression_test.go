package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	controlapi "github.com/moby/buildkit/api/services/control"
	buildkitauth "github.com/moby/buildkit/session/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// TestEngineBuildTraceRendererCancellationDoesNotBlockProducer is the full-review
// regression for the renderer lifetime edge: progressui exits when the request
// context is cancelled, while the Engine stream decoder may still have buffered
// trace aux records to consume. Once the renderer is gone, feeding more than the
// channel capacity must remain bounded so build/session finalization stays
// reachable.
func TestEngineBuildTraceRendererCancellationDoesNotBlockProducer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var out bytes.Buffer
	renderer, err := newEngineBuildTraceRenderer(ctx, &out)
	if err != nil {
		t.Fatalf("newEngineBuildTraceRenderer: %v", err)
	}

	trace, err := proto.Marshal(&controlapi.StatusResponse{
		Vertexes: []*controlapi.Vertex{{Digest: "v1", Name: "trace"}},
	})
	if err != nil {
		t.Fatalf("marshal trace: %v", err)
	}
	payload, err := json.Marshal(trace)
	if err != nil {
		t.Fatalf("marshal trace payload: %v", err)
	}

	cancel()
	select {
	case <-renderer.done:
	case <-time.After(2 * time.Second):
		t.Fatal("renderer did not stop after cancellation")
	}

	producerDone := make(chan struct{})
	go func() {
		defer close(producerDone)
		for i := 0; i < 64; i++ {
			renderer.pushAux(buildkitTraceAuxID, json.RawMessage(payload))
		}
		renderer.close()
	}()

	select {
	case <-producerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("trace producer blocked after the renderer exited")
	}
}

// TestEngineBuildAuthServerUsesCredentialsWithoutClientTokenState proves the
// production BuildKit attachable deliberately declines token authority and
// serves the exact-host credential directly. In particular, exercising this
// path must not create Docker CLI config/token-seed state under DOCKER_CONFIG;
// the request-owned Session has no hidden persistent auth state outside the
// docker-helper credential store.
func TestEngineBuildAuthServerUsesCredentialsWithoutClientTokenState(t *testing.T) {
	dockerConfig := filepath.Join(t.TempDir(), "docker-config")
	t.Setenv("DOCKER_CONFIG", dockerConfig)

	resolver := buildCredentialResolver(func(host string) (*sessionRegistryCredential, error) {
		if host != "registry.example.com" {
			return nil, nil
		}
		return &sessionRegistryCredential{
			Registry: "registry.example.com",
			Username: "user",
			Password: "secret",
		}, nil
	})
	server := newEngineBuildAuthServer(resolver)

	credentials, err := server.Credentials(context.Background(), &buildkitauth.CredentialsRequest{Host: "registry.example.com"})
	if err != nil {
		t.Fatalf("Credentials: %v", err)
	}
	if credentials.Username != "user" || credentials.Secret != "secret" {
		t.Fatalf("credentials = %+v, want exact-host username/secret", credentials)
	}

	anonymous, err := server.Credentials(context.Background(), &buildkitauth.CredentialsRequest{Host: "other.example.com"})
	if err != nil {
		t.Fatalf("anonymous Credentials: %v", err)
	}
	if anonymous.Username != "" || anonymous.Secret != "" {
		t.Fatalf("unrelated host received credentials: %+v", anonymous)
	}

	_, err = server.GetTokenAuthority(context.Background(), &buildkitauth.GetTokenAuthorityRequest{Host: "registry.example.com"})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("GetTokenAuthority code = %s, want Unavailable", status.Code(err))
	}

	if _, err := os.Stat(dockerConfig); !os.IsNotExist(err) {
		t.Fatalf("BuildKit auth path created hidden Docker config/token state at %s: %v", dockerConfig, err)
	}
}

// TestEngineBuildAuthServerIdentityToken keeps the previous identity-token
// precedence when converting the host-scoped Session credential into the
// BuildKit Credentials RPC shape.
func TestEngineBuildAuthServerIdentityToken(t *testing.T) {
	server := newEngineBuildAuthServer(func(host string) (*sessionRegistryCredential, error) {
		return &sessionRegistryCredential{
			Registry:      host,
			Username:      "ignored-user",
			Password:      "ignored-password",
			IdentityToken: "identity-token",
		}, nil
	})

	credentials, err := server.Credentials(context.Background(), &buildkitauth.CredentialsRequest{Host: "registry.example.com"})
	if err != nil {
		t.Fatalf("Credentials: %v", err)
	}
	if credentials.Username != "" || credentials.Secret != "identity-token" {
		t.Fatalf("identity-token credentials = %+v", credentials)
	}
}
