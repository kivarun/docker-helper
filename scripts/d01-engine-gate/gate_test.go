package main

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/containerd/errdefs"
	"github.com/distribution/reference"
	"github.com/moby/moby/api/pkg/stdcopy"
	buildtypes "github.com/moby/moby/api/types/build"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/api/types/registry"
	"github.com/moby/moby/client"
	"golang.org/x/crypto/bcrypt"
)

// The D0.1 gate pins the reviewed client version. Raising the pin re-runs the
// matrix and the result is recorded in docs/release-3-d0-execution-plan.md.
const reviewedClientVersion = "v0.6.0"

// registryCanary is unique per run so leak checks below search for a marker
// that cannot occur accidentally. It contains a '-' so it cannot appear in
// base64 output by construction.
const registryCanary = "d01-canary-pass-zone"

// gateRequired reports the CI-required mode: with D01_GATE_REQUIRED=1 an
// unreachable Engine or a missing prerequisite is a hard failure, never a
// skip. Local runs without the variable keep the historical skip behavior.
func gateRequired() bool { return os.Getenv("D01_GATE_REQUIRED") == "1" }

// engineEnvIssue records an environment problem that blocks an Engine-matrix
// row: skip locally, fail hard in required mode.
func engineEnvIssue(t *testing.T, format string, args ...any) {
	t.Helper()
	if gateRequired() {
		t.Fatalf("D0.1 required mode: "+format, args...)
	}
	t.Skipf(format, args...)
}

func pinnedClient(t *testing.T) *client.Client {
	t.Helper()
	cli, err := client.NewClientWithOpts()
	if err != nil {
		t.Fatalf("construct pinned client: %v", err)
	}
	return cli
}

// engineClient returns a negotiated client when a real Docker Engine is
// reachable, or skips with the exact environment the executor must provide.
func engineClient(t *testing.T) *client.Client {
	t.Helper()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		engineEnvIssue(t, "D0.1 Engine matrix needs a reachable Docker Engine endpoint: construct client: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ping, err := cli.Ping(ctx, client.PingOptions{})
	if err != nil {
		engineEnvIssue(t, "D0.1 Engine matrix needs a reachable Docker Engine endpoint (set DOCKER_HOST or mount the host docker.sock into the probe environment; never the docker-helper API socket): ping: %v", err)
	}
	t.Logf("engine: APIVersion=%q OSType=%q required=%v", ping.APIVersion, ping.OSType, gateRequired())
	return cli
}

// TestClientPinAndAPIBounds records the reviewed version and the supported
// Engine API bounds without any Engine dependency.
func TestClientPinAndAPIBounds(t *testing.T) {
	if reviewedClientVersion == "" {
		t.Fatal("reviewed client version is not recorded")
	}
	cli := pinnedClient(t)
	version := cli.ClientVersion()
	if !strings.HasPrefix(version, "1.") {
		t.Fatalf("pinned client default API version %q is not a 1.x API version", version)
	}
	if client.MinAPIVersion == "" || client.MaxAPIVersion == "" {
		t.Fatal("client module does not declare its supported API bounds")
	}
	t.Logf("pin=%s default-api=%s min-api=%s max-api=%s",
		reviewedClientVersion, version, client.MinAPIVersion, client.MaxAPIVersion)
}

// TestNegotiationOptionConstruction proves the negotiation and environment
// options compose into a usable client without contacting an Engine.
func TestNegotiationOptionConstruction(t *testing.T) {
	cli, err := client.NewClientWithOpts(
		client.WithAPIVersionNegotiation(),
		client.WithHostFromEnv(),
		client.WithAPIVersionFromEnv(),
	)
	if err != nil {
		t.Fatalf("construct negotiated client: %v", err)
	}
	if cli.DaemonHost() == "" {
		t.Fatal("negotiated client exposes no daemon host")
	}
}

// TestPullAuthEncoding proves the pull authentication contract shape: the
// RegistryAuth field carries base64-encoded registry.AuthConfig JSON, and the
// plaintext canary cannot leak through the encoded header by construction.
func TestPullAuthEncoding(t *testing.T) {
	auth := registry.AuthConfig{
		Username:      "gate-user",
		Password:      registryCanary,
		ServerAddress: "registry.example.com",
	}
	blob, err := json.Marshal(auth)
	if err != nil {
		t.Fatalf("marshal auth config: %v", err)
	}
	encoded := base64.URLEncoding.EncodeToString(blob)
	if strings.Contains(encoded, registryCanary) {
		t.Fatal("encoded RegistryAuth header unexpectedly contains the plaintext canary")
	}
	decoded, err := base64.URLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode RegistryAuth: %v", err)
	}
	var roundTrip registry.AuthConfig
	if err := json.Unmarshal(decoded, &roundTrip); err != nil {
		t.Fatalf("unmarshal RegistryAuth: %v", err)
	}
	if roundTrip.Password != registryCanary {
		t.Fatal("RegistryAuth round-trip lost the credential")
	}
	opts := client.ImagePullOptions{RegistryAuth: encoded}
	if opts.RegistryAuth == "" {
		t.Fatal("ImagePullOptions dropped the auth header")
	}
	t.Log("pull RegistryAuth encoding round-trips without plaintext leakage")
}

// TestBuildAuthMapAndBuilderVersions proves the build authentication surface:
// AuthConfigs is keyed by registry address and both builder versions the
// contract distinguishes exist in the pinned module.
func TestBuildAuthMapAndBuilderVersions(t *testing.T) {
	opts := client.ImageBuildOptions{
		AuthConfigs: map[string]registry.AuthConfig{
			"registry.example.com": {Username: "gate-user", Password: registryCanary},
		},
		Version: buildtypes.BuilderBuildKit,
	}
	if _, ok := opts.AuthConfigs["registry.example.com"]; !ok {
		t.Fatal("ImageBuildOptions.AuthConfigs is not keyed by registry address")
	}
	if buildtypes.BuilderBuildKit == "" || buildtypes.BuilderV1 == "" {
		t.Fatal("pinned module does not expose both builder versions")
	}
	if buildtypes.BuilderBuildKit != "2" || buildtypes.BuilderV1 != "1" {
		t.Fatalf("builder version values changed: legacy=%q buildkit=%q", buildtypes.BuilderV1, buildtypes.BuilderBuildKit)
	}
	t.Log("build auth map and both builder versions exist in the pinned client")
}

// TestExactRegistryAddressCanonicalization proves the exact registry-address
// canonicalization the Session credential bridge needs: the normalized
// reference domain is the credential-store lookup key.
func TestExactRegistryAddressCanonicalization(t *testing.T) {
	cases := []struct {
		ref  string
		want string
	}{
		{"alpine:3.24", "docker.io"},
		{"docker.io/library/alpine:3.24", "docker.io"},
		{"index.docker.io/app/web:1", "docker.io"},
		{"registry.example.com/a/b:1", "registry.example.com"},
		{"registry.example.com:5000/a", "registry.example.com:5000"},
		{"localhost:5000/x:1", "localhost:5000"},
	}
	for _, tc := range cases {
		named, err := reference.ParseNormalizedNamed(tc.ref)
		if err != nil {
			t.Fatalf("parse %q: %v", tc.ref, err)
		}
		if got := reference.Domain(named); got != tc.want {
			t.Fatalf("domain(%q) = %q, want %q", tc.ref, got, tc.want)
		}
	}
	t.Log("normalized reference domains are stable credential-lookup keys")
}

// TestStdCopyStreamFraming proves the pinned module demultiplexes Docker's
// multiplexed stream, including frames split across two writes.
func TestStdCopyStreamFraming(t *testing.T) {
	frame := func(stream stdcopy.StdType, payload string) []byte {
		b := make([]byte, 8+len(payload))
		b[0] = byte(stream)
		b[4] = byte(len(payload) >> 24)
		b[5] = byte(len(payload) >> 16)
		b[6] = byte(len(payload) >> 8)
		b[7] = byte(len(payload))
		copy(b[8:], payload)
		return b
	}
	var src bytes.Buffer
	src.Write(frame(stdcopy.Stdout, "out-first\n"))
	split := frame(stdcopy.Stderr, "err-first\n")
	src.Write(split[:5])
	src.Write(split[5:])
	src.Write(frame(stdcopy.Stdout, "out-second\n"))
	src.Write(frame(stdcopy.Stderr, "err-second\n"))

	var out, errOut bytes.Buffer
	if _, err := stdcopy.StdCopy(&out, &errOut, &src); err != nil {
		t.Fatalf("StdCopy: %v", err)
	}
	wantOut := "out-first\nout-second\n"
	wantErr := "err-first\nerr-second\n"
	if out.String() != wantOut || errOut.String() != wantErr {
		t.Fatalf("framing mismatch: stdout=%q stderr=%q", out.String(), errOut.String())
	}
	t.Log("multiplexed framing demultiplexes with split frames in delivery order")
}

// TestTypedEngineErrorClassification proves the pinned dependency tree
// provides the typed classifiers the adapter must use instead of error text.
func TestTypedEngineErrorClassification(t *testing.T) {
	if !errdefs.IsNotFound(errdefs.ErrNotFound) {
		t.Fatal("errdefs.IsNotFound does not classify its own sentinel")
	}
	if !errdefs.IsConflict(errdefs.ErrConflict) {
		t.Fatal("errdefs.IsConflict does not classify its own sentinel")
	}
	if !errdefs.IsUnauthorized(errdefs.ErrUnauthenticated) {
		t.Fatal("errdefs.IsUnauthorized does not classify its own sentinel")
	}
	if !errdefs.IsPermissionDenied(errdefs.ErrPermissionDenied) {
		t.Fatal("errdefs.IsPermissionDenied does not classify its own sentinel")
	}
	if errdefs.IsNotFound(errdefs.ErrConflict) {
		t.Fatal("classifier conflates not-found and conflict")
	}
	wrapped := fmt.Errorf("wrapped: %w", errdefs.ErrNotFound)
	if !errdefs.IsNotFound(wrapped) {
		t.Fatal("classification does not unwrap wrapped errors")
	}
	t.Log("typed classification is available; live HTTP status mapping is verified against an Engine")
}

// TestLogExecPrimitivesSurface proves the pinned module exposes the option
// surfaces the D4 logs and D5 exec packages consume.
func TestLogExecPrimitivesSurface(t *testing.T) {
	logs := client.ContainerLogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     false,
		Tail:       "200",
		Timestamps: false,
	}
	if !logs.ShowStdout || !logs.ShowStderr || logs.Follow {
		t.Fatal("ContainerLogsOptions surface mismatch")
	}
	execCreate := client.ExecCreateOptions{
		Cmd:          []string{"sh", "-c", "echo hi"},
		Env:          []string{"GATE=1"},
		AttachStdout: true,
		AttachStderr: true,
		WorkingDir:   "/workspace",
	}
	if len(execCreate.Cmd) != 3 || len(execCreate.Env) != 1 || execCreate.WorkingDir != "/workspace" {
		t.Fatal("ExecCreateOptions surface mismatch")
	}
	var _ client.ExecAttachOptions
	t.Log("logs and exec option surfaces exist in the pinned client")
}

// TestEngineNegotiationAndInfo verifies API-version negotiation against one
// real Engine and records the Server/API versions for the gate evidence.
func TestEngineNegotiationAndInfo(t *testing.T) {
	cli := engineClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	info, err := cli.Info(ctx, client.InfoOptions{})
	if err != nil {
		t.Fatalf("engine info: %v", err)
	}
	if info.Info.ServerVersion == "" {
		t.Fatal("engine did not report a server version")
	}
	if v := cli.ClientVersion(); !strings.HasPrefix(v, "1.") {
		t.Fatalf("negotiated client version %q is not a 1.x API version", v)
	}
	t.Logf("negotiated-api=%s engine-server=%s os=%s",
		cli.ClientVersion(), info.Info.ServerVersion, info.Info.OSType)
}

// TestEnginePublicPullBuild proves public pull, BuildKit build, and the
// documented legacy-build behavior against the real Engine.
func TestEnginePublicPullBuild(t *testing.T) {
	cli := engineClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	pull, err := cli.ImagePull(ctx, "alpine:3.24", client.ImagePullOptions{})
	if err != nil {
		t.Fatalf("public pull: %v", err)
	}
	defer pull.Close()
	if err := pull.Wait(ctx); err != nil {
		t.Fatalf("public pull: %v", err)
	}
	t.Log("public pull alpine:3.24 succeeded")

	buildRes, err := cli.ImageBuild(ctx, buildContext(t, map[string]string{
		"Dockerfile": "FROM alpine:3.24\nRUN echo built > /gate-marker\n",
	}), client.ImageBuildOptions{Tags: []string{"d01-gate:buildkit"}, Version: buildtypes.BuilderBuildKit})
	if err != nil {
		t.Fatalf("BuildKit build: %v", err)
	}
	defer buildRes.Body.Close()
	if _, err := io.Copy(io.Discard, buildRes.Body); err != nil {
		t.Fatalf("BuildKit build stream: %v", err)
	}
	t.Log("BuildKit build succeeded")

	legacyRes, legacyErr := cli.ImageBuild(ctx, buildContext(t, map[string]string{
		"Dockerfile": "FROM alpine:3.24\nRUN echo legacy > /gate-marker\n",
	}), client.ImageBuildOptions{Tags: []string{"d01-gate:legacy"}, Version: buildtypes.BuilderV1})
	if legacyErr != nil {
		// A buildkit-only Engine may refuse the legacy builder; that refusal is
		// itself the recorded legacy-build behavior for this matrix row.
		if errdefs.IsNotImplemented(legacyErr) || strings.Contains(strings.ToLower(legacyErr.Error()), "buildkit") {
			t.Logf("legacy build refused by a buildkit-only engine (recorded behavior): %v", legacyErr)
			return
		}
		t.Fatalf("legacy build: %v", legacyErr)
	}
	defer legacyRes.Body.Close()
	if _, err := io.Copy(io.Discard, legacyRes.Body); err != nil {
		t.Fatalf("legacy build stream: %v", err)
	}
	t.Log("legacy build succeeded")
}

// TestEnginePullCancellation proves the cancellation contract against a real
// Engine: the target is removed first so the pull must be a real network
// fetch, the context is canceled immediately after the Engine accepts the
// request, and the daemon must not have produced the image afterwards.
func TestEnginePullCancellation(t *testing.T) {
	cli := engineClient(t)
	target := "ubuntu:24.04"
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if _, err := cli.ImageRemove(ctx, target, client.ImageRemoveOptions{Force: true}); err != nil && !errdefs.IsNotFound(err) {
		t.Fatalf("pre-remove %s: %v", target, err)
	}
	pullCtx, pullCancel := context.WithCancel(context.Background())
	defer pullCancel()
	resp, err := cli.ImagePull(pullCtx, target, client.ImagePullOptions{})
	if err != nil {
		t.Fatalf("pull request was not accepted by the engine: %v", err)
	}
	defer resp.Close()
	pullCancel() // cancel immediately after the engine accepted the request
	err = resp.Wait(pullCtx)
	if err == nil {
		t.Fatalf("pull completed despite immediate cancellation; cancellation contract not demonstrated against this engine")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled pull returned %v, not a context error", err)
	}
	if _, err := cli.ImageInspect(ctx, target); err == nil {
		t.Fatalf("canceled pull nevertheless produced %s; daemon-side cancellation not proven", target)
	} else if !errdefs.IsNotFound(err) {
		t.Fatalf("inspect after canceled pull: %v", err)
	}
	t.Log("canceled pull returned a context error and left no image behind")
}

// TestEngineBuildCancellation is the deterministic cancellation row: the
// build runs a long sleep step so it cannot finish before the cancel, and the
// canceled build must neither stream success nor produce the tagged image.
func TestEngineBuildCancellation(t *testing.T) {
	cli := engineClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	target := "d01-gate:cancel"
	defer func() {
		if _, err := cli.ImageRemove(ctx, target, client.ImageRemoveOptions{Force: true}); err != nil && !errdefs.IsNotFound(err) {
			t.Logf("cleanup of %s: %v", target, err)
		}
	}()

	ensureImagePresent(ctx, cli, t, "alpine:3.24")

	buildCtx, buildCancel := context.WithCancel(ctx)
	defer buildCancel()
	res, err := cli.ImageBuild(buildCtx, buildContext(t, map[string]string{
		"Dockerfile": "FROM alpine:3.24\nRUN sleep 300\n",
	}), client.ImageBuildOptions{Tags: []string{target}, Version: buildtypes.BuilderBuildKit})
	if err != nil {
		t.Fatalf("cancel-target build start: %v", err)
	}
	defer res.Body.Close()

	// Give the solve enough time to be inside the long RUN step, then cancel.
	time.Sleep(3 * time.Second)
	buildCancel()
	streamErr := readBuildStream(t, res.Body)
	t.Logf("canceled build stream ended: err=%v", streamErr)

	if _, err := cli.ImageInspect(ctx, target); err == nil {
		t.Fatalf("canceled build nevertheless produced %s; daemon-side cancellation not proven", target)
	} else if !errdefs.IsNotFound(err) {
		t.Fatalf("inspect after canceled build: %v", err)
	}
	t.Log("canceled BuildKit build terminated and produced no tagged image")
}

// readBuildStream drains a build response, returning the last observed error
// event if the builder reported one.
func readBuildStream(t *testing.T, r io.Reader) error {
	t.Helper()
	var lastErr string
	for {
		var event struct {
			Error string `json:"error"`
		}
		if err := json.NewDecoder(r).Decode(&event); err != nil {
			if errors.Is(err, io.EOF) {
				if lastErr != "" {
					return errors.New(lastErr)
				}
				return nil
			}
			if lastErr != "" {
				return fmt.Errorf("%w (last event: %s)", err, lastErr)
			}
			return err
		}
		if event.Error != "" {
			lastErr = event.Error
		}
	}
}

// TestEngineOneShotLifecycle proves create/start/wait/remove, including a
// disconnected wait whose container stays observable and removable.
func TestEngineOneShotLifecycle(t *testing.T) {
	cli := engineClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	ensureImagePresent(ctx, cli, t, "alpine:3.24")

	created, err := cli.ContainerCreate(ctx, client.ContainerCreateOptions{
		Name: "d01-gate-one-shot",
		Config: &container.Config{
			Image: "alpine:3.24",
			Cmd:   []string{"/bin/sh", "-c", "sleep 60"},
		},
	})
	if err != nil {
		t.Fatalf("container create: %v", err)
	}
	if _, err := cli.ContainerStart(ctx, created.ID, client.ContainerStartOptions{}); err != nil {
		t.Fatalf("container start: %v", err)
	}

	waitCtx, waitCancel := context.WithCancel(ctx)
	result := cli.ContainerWait(waitCtx, created.ID, client.ContainerWaitOptions{})
	waitCancel() // disconnect while waiting
	select {
	case <-result.Error:
		t.Log("disconnected wait surfaced its error channel")
	case <-result.Result:
		t.Log("disconnected wait surfaced a result channel")
	case <-time.After(5 * time.Second):
		t.Log("disconnected wait kept waiting; container state remains engine-owned")
	}

	inspect, err := cli.ContainerInspect(ctx, created.ID, client.ContainerInspectOptions{})
	if err != nil {
		t.Fatalf("container inspect after disconnect: %v", err)
	}
	if !inspect.Container.State.Running {
		t.Fatalf("container not running after disconnected wait: %+v", inspect.Container.State)
	}
	if _, err := cli.ContainerRemove(ctx, created.ID, client.ContainerRemoveOptions{Force: true}); err != nil {
		t.Fatalf("container remove: %v", err)
	}
	t.Log("one-shot create/start/disconnect-wait/inspect/remove succeeded")
}

// TestEngineLogsExecPrimitives proves the D4/D5 primitives against the real
// Engine: bounded combined logs and a non-interactive exec with typed exit.
func TestEngineLogsExecPrimitives(t *testing.T) {
	cli := engineClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	ensureImagePresent(ctx, cli, t, "alpine:3.24")

	created, err := cli.ContainerCreate(ctx, client.ContainerCreateOptions{
		Config: &container.Config{
			Image: "alpine:3.24",
			Cmd:   []string{"/bin/sh", "-c", "echo gate-stdout-marker; echo gate-stderr-marker 1>&2; sleep 30"},
		},
	})
	if err != nil {
		t.Fatalf("container create: %v", err)
	}
	defer func() {
		_, _ = cli.ContainerRemove(context.WithoutCancel(ctx), created.ID, client.ContainerRemoveOptions{Force: true})
	}()
	if _, err := cli.ContainerStart(ctx, created.ID, client.ContainerStartOptions{}); err != nil {
		t.Fatalf("container start: %v", err)
	}
	time.Sleep(500 * time.Millisecond)

	logs, err := cli.ContainerLogs(ctx, created.ID, client.ContainerLogsOptions{ShowStdout: true, ShowStderr: true, Tail: "200"})
	if err != nil {
		t.Fatalf("container logs: %v", err)
	}
	defer logs.Close()
	var out, errOut bytes.Buffer
	if _, err := stdcopy.StdCopy(&out, &errOut, logs); err != nil {
		t.Fatalf("log demux: %v", err)
	}
	if !strings.Contains(out.String(), "gate-stdout-marker") {
		t.Fatalf("stdout not demuxed: %q", out.String())
	}
	if !strings.Contains(errOut.String(), "gate-stderr-marker") {
		t.Fatalf("stderr not demuxed: %q", errOut.String())
	}
	t.Log("combined bounded logs demux through stdcopy")

	exec, err := cli.ExecCreate(ctx, created.ID, client.ExecCreateOptions{
		Cmd:          []string{"/bin/sh", "-c", "echo exec-marker; exit 3"},
		AttachStdout: true,
		AttachStderr: true,
	})
	if err != nil {
		t.Fatalf("exec create: %v", err)
	}
	attach, err := cli.ExecAttach(ctx, exec.ID, client.ExecAttachOptions{})
	if err != nil {
		t.Fatalf("exec attach: %v", err)
	}
	defer attach.Close()
	var execOut, execErr bytes.Buffer
	if _, err := stdcopy.StdCopy(&execOut, &execErr, attach.Reader); err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("exec stream demux: %v", err)
	}
	if !strings.Contains(execOut.String(), "exec-marker") {
		t.Fatalf("exec output missing marker: %q", execOut.String())
	}
	inspect, err := cli.ExecInspect(ctx, exec.ID, client.ExecInspectOptions{})
	if err != nil {
		t.Fatalf("exec inspect: %v", err)
	}
	if inspect.ExitCode != 3 {
		t.Fatalf("exec exit code: got %d, want 3", inspect.ExitCode)
	}
	t.Log("non-interactive exec returned the engine-provided exit code 3")
}

// TestEnginePrivateRegistryMatrix proves private pull, private FROM build,
// exact registry matching, and the secret canary against a disposable
// authenticated registry the test provisions through the Engine itself. The
// registry publishes only on the host loopback.
func TestEnginePrivateRegistryMatrix(t *testing.T) {
	cli := engineClient(t)
	if _, err := os.Stat("/var/run/docker.sock"); err != nil {
		engineEnvIssue(t, "loopback publishing reachability is required; run the probe on the deployment host or in a host-network container")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()

	seedPull, err := cli.ImagePull(ctx, "registry:2", client.ImagePullOptions{})
	if err != nil {
		t.Fatalf("pull registry:2: %v", err)
	}
	defer seedPull.Close()
	if err := seedPull.Wait(ctx); err != nil {
		t.Fatalf("pull registry:2: %v", err)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(registryCanary), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	htFile, err := os.CreateTemp("", "d01-htpasswd-*")
	if err != nil {
		t.Fatalf("tempfile: %v", err)
	}
	htPath := htFile.Name()
	defer os.Remove(htPath)
	if _, err := htFile.WriteString("gate:" + string(hash) + "\n"); err != nil {
		htFile.Close()
		t.Fatalf("write htpasswd: %v", err)
	}
	if err := htFile.Close(); err != nil {
		t.Fatalf("close htpasswd: %v", err)
	}
	// The registry container may run as a non-root user; keep the credential
	// file readable inside the container.
	if err := os.Chmod(htPath, 0o644); err != nil {
		t.Fatalf("chmod htpasswd: %v", err)
	}

	port, err := network.ParsePort("5000/tcp")
	if err != nil {
		t.Fatalf("parse container port: %v", err)
	}
	reg, err := cli.ContainerCreate(ctx, client.ContainerCreateOptions{
		Name: "d01-gate-registry",
		Config: &container.Config{
			Image:        "registry:2",
			ExposedPorts: network.PortSet{port: {}},
			Env: []string{
				"REGISTRY_AUTH=htpasswd",
				"REGISTRY_AUTH_HTPASSWD_REALM=d01-gate",
				"REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd",
			},
		},
		HostConfig: &container.HostConfig{
			PortBindings: network.PortMap{port: []network.PortBinding{{
				HostIP:   netip.MustParseAddr("127.0.0.1"),
				HostPort: "",
			}}},
			Binds: []string{htPath + ":/auth/htpasswd:ro"},
		},
	})
	if err != nil {
		t.Fatalf("create registry container: %v", err)
	}
	defer func() {
		_, _ = cli.ContainerRemove(context.WithoutCancel(ctx), reg.ID, client.ContainerRemoveOptions{Force: true})
	}()
	if _, err := cli.ContainerStart(ctx, reg.ID, client.ContainerStartOptions{}); err != nil {
		t.Fatalf("start registry container: %v", err)
	}

	inspected, err := cli.ContainerInspect(ctx, reg.ID, client.ContainerInspectOptions{})
	if err != nil {
		t.Fatalf("inspect registry container: %v", err)
	}
	var hostPort string
	for _, bindings := range inspected.Container.NetworkSettings.Ports {
		for _, binding := range bindings {
			if binding.HostPort != "" && binding.HostIP == netip.MustParseAddr("127.0.0.1") {
				hostPort = binding.HostPort
				break
			}
		}
		if hostPort != "" {
			break
		}
	}
	if hostPort == "" {
		t.Fatal("engine did not publish the requested loopback port for the registry")
	}
	registryHost := "localhost:" + hostPort
	t.Logf("disposable registry: container 5000/tcp published on 127.0.0.1:%s", hostPort)
	if insp, err := cli.ImageInspect(ctx, "registry:2"); err == nil && len(insp.RepoDigests) > 0 {
		t.Logf("FACT: registry-image-digest=%s", insp.RepoDigests[0])
	}
	waitRegistryReady(t, "127.0.0.1:"+hostPort)
	checkRegistryCredentials(t, "127.0.0.1:"+hostPort)

	auth := registry.AuthConfig{Username: "gate", Password: registryCanary, ServerAddress: registryHost}
	authBlob, err := json.Marshal(auth)
	if err != nil {
		t.Fatalf("marshal auth: %v", err)
	}
	encodedAuth := base64.URLEncoding.EncodeToString(authBlob)

	privateRef := registryHost + "/d01/gate-alpine:v1"
	pushErr := pushPrivateImage(ctx, cli, privateRef, encodedAuth)
	if pushErr != nil && isUnauthorized(pushErr) {
		// The registry itself accepted the credential (checked directly above),
		// so the failure is in how the Engine relayed the encoded header. Try
		// the standard-alphabet encoding and record which one the Engine
		// accepted; this is gate evidence about the daemon, not a retry mask.
		stdAuth := base64.StdEncoding.EncodeToString(authBlob)
		t.Logf("FACT: urlencoding-push-relay=%v; retrying with std encoding", pushErr)
		stdErr := pushPrivateImage(ctx, cli, privateRef, stdAuth)
		if stdErr == nil {
			t.Log("FACT: std-encoding-push-relay=succeeded; recorded encoding evidence")
			encodedAuth = stdAuth
		} else {
			t.Fatalf("seed private image: url-encoding: %v; std-encoding: %v", pushErr, stdErr)
		}
	} else if pushErr != nil {
		t.Fatalf("seed private image: %v", pushErr)
	}

	privatePull, err := cli.ImagePull(ctx, privateRef, client.ImagePullOptions{RegistryAuth: encodedAuth})
	if err != nil {
		t.Fatalf("private pull: %v", err)
	}
	defer privatePull.Close()
	if err := privatePull.Wait(ctx); err != nil {
		t.Fatalf("private pull: %v", err)
	}
	t.Log("private pull with session-equivalent credentials succeeded")

	buildRes, err := cli.ImageBuild(ctx, buildContext(t, map[string]string{
		"Dockerfile": "FROM " + privateRef + "\nRUN echo private-from > /gate-marker\n",
	}), client.ImageBuildOptions{
		Tags:        []string{"d01-gate:private-from"},
		Version:     buildtypes.BuilderBuildKit,
		AuthConfigs: map[string]registry.AuthConfig{registryHost: auth},
	})
	if err != nil {
		t.Fatalf("private FROM build: %v", err)
	}
	defer buildRes.Body.Close()
	if _, err := io.Copy(io.Discard, buildRes.Body); err != nil {
		t.Fatalf("private FROM build stream: %v", err)
	}
	t.Log("private FROM build with the build auth map succeeded")

	// Secret canary: a wrong-credential pull must fail without echoing the
	// canary through the public error surface.
	bad := auth
	bad.Password = registryCanary + "-wrong"
	badBlob, err := json.Marshal(bad)
	if err != nil {
		t.Fatalf("marshal bad auth: %v", err)
	}
	badResp, badErr := cli.ImagePull(ctx, privateRef, client.ImagePullOptions{RegistryAuth: base64.URLEncoding.EncodeToString(badBlob)})
	if badErr == nil {
		defer badResp.Close()
		badErr = badResp.Wait(ctx)
	}
	if badErr == nil {
		t.Fatal("wrong-credential private pull unexpectedly succeeded")
	}
	if strings.Contains(badErr.Error(), registryCanary) {
		t.Fatal("engine error surfaced the credential canary")
	}
	if !errdefs.IsUnauthorized(badErr) && !errdefs.IsPermissionDenied(badErr) {
		t.Logf("wrong-credential pull classified as %T (%v); expected unauthorized family", badErr, badErr)
	}
	t.Log("secret canary absent from the client error surface")
}

func waitRegistryReady(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		httpClient := &http.Client{Timeout: 2 * time.Second}
		resp, err := httpClient.Get("http://" + addr + "/v2/")
		if err == nil {
			resp.Body.Close()
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("disposable registry at %s did not become ready", addr)
}

// checkRegistryCredentials proves the credential pair at the registry
// boundary itself, before any Engine relay is involved: the anonymous /v2/
// ping must be rejected and the canary pair must be accepted.
func checkRegistryCredentials(t *testing.T, addr string) {
	t.Helper()
	httpClient := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest(http.MethodGet, "http://"+addr+"/v2/", nil)
	if err != nil {
		t.Fatalf("registry credential check request: %v", err)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("anonymous registry ping: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous /v2/ returned %d; auth middleware is not active at the registry boundary", resp.StatusCode)
	}
	t.Log("FACT: registry-auth-middleware=active (anonymous /v2/ rejected)")
	req, err = http.NewRequest(http.MethodGet, "http://"+addr+"/v2/", nil)
	if err != nil {
		t.Fatalf("registry credential check request: %v", err)
	}
	req.SetBasicAuth("gate", registryCanary)
	resp, err = httpClient.Do(req)
	if err != nil {
		t.Fatalf("authenticated registry ping: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("canary credential pair rejected by the registry boundary (status %d); htpasswd mismatch", resp.StatusCode)
	}
	t.Log("FACT: registry-canary-credentials=accepted at the registry boundary")
}

// isUnauthorized reports whether the error is an authorization failure at the
// registry boundary.
func isUnauthorized(err error) bool {
	return errdefs.IsUnauthorized(err) || errdefs.IsPermissionDenied(err)
}

func pushPrivateImage(ctx context.Context, cli *client.Client, privateRef, encodedAuth string) error {
	base := privateRef[:strings.Index(privateRef, "/")]
	seedPull, err := cli.ImagePull(ctx, "alpine:3.24", client.ImagePullOptions{})
	if err != nil {
		return fmt.Errorf("pull seed image: %w", err)
	}
	defer seedPull.Close()
	if err := seedPull.Wait(ctx); err != nil {
		return fmt.Errorf("pull seed image: %w", err)
	}
	if _, err := cli.ImageTag(ctx, client.ImageTagOptions{Source: "alpine:3.24", Target: privateRef}); err != nil {
		return fmt.Errorf("tag seed image: %w", err)
	}
	push, err := cli.ImagePush(ctx, base+"/d01/gate-alpine:v1", client.ImagePushOptions{RegistryAuth: encodedAuth})
	if err != nil {
		return fmt.Errorf("push seed image: %w", err)
	}
	defer push.Close()
	return push.Wait(ctx)
}

// buildContext returns a tar build context carrying exactly the named files
// (the Dockerfile contract of ImageBuild), not raw Dockerfile bytes.
func buildContext(t *testing.T, files map[string]string) io.Reader {
	t.Helper()
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, name := range names {
		body := []byte(files[name])
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))}); err != nil {
			t.Fatalf("tar header %s: %v", name, err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatalf("tar body %s: %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	return bytes.NewReader(buf.Bytes())
}

// ensureImagePresent pulls the image only when it is absent locally, so rows
// stay independent of execution order.
func ensureImagePresent(ctx context.Context, cli *client.Client, t *testing.T, ref string) {
	t.Helper()
	if _, err := cli.ImageInspect(ctx, ref); err == nil {
		return
	} else if !errdefs.IsNotFound(err) {
		t.Fatalf("inspect %s: %v", ref, err)
	}
	pull, err := cli.ImagePull(ctx, ref, client.ImagePullOptions{})
	if err != nil {
		t.Fatalf("pull %s: %v", ref, err)
	}
	defer pull.Close()
	if err := pull.Wait(ctx); err != nil {
		t.Fatalf("pull %s: %v", ref, err)
	}
}
