package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/containerd/errdefs"
	buildtypes "github.com/moby/moby/api/types/build"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

// D0.1 restart procedures. These rows deliberately restart/kill a DISPOSABLE
// Engine while requests are active; the matrix tests above never restart the
// Engine endpoint because it may be a shared daemon. They are gated behind
// D01_GATE_RESTART=1: setting it is the operator's declaration that the
// DOCKER_HOST endpoint is a disposable Engine that may be killed and
// restarted (the Phase-0 workflow does this against disposable DinD daemons).
//
// Required environment in that mode:
//   - D01_RESTART_SUPERVISOR_HOST: a second Docker endpoint managing the
//     disposable engine container (the runner host daemon in the Phase-0
//     workflow). It is used ONLY to kill/restart that one container.
//   - D01_DISPOSABLE_ENGINE_NAME: the name of the disposable engine container.
//
// The supervisor endpoint must be a different daemon from the Engine under
// test, and the named container must be a DinD container; both are asserted
// before any kill.

const (
	restartGateEnv        = "D01_GATE_RESTART"
	restartSupervisorEnv  = "D01_RESTART_SUPERVISOR_HOST"
	disposableEngineEnv   = "D01_DISPOSABLE_ENGINE_NAME"
	restartBuildImageTag  = "d01-gate-restart:active-build"
	restartBuildSleepSecs = 300
	restartOneshotName    = "d01-restart-oneshot"
	restartCreatedName    = "d01-restart-created"
	restartPingTimeout    = 180 * time.Second
	restartErrorBound     = 45 * time.Second
	restartKillElapsed    = 18 * time.Second
)

// restartGate reports whether the disposable-Engine restart rows are enabled.
func restartGate() bool { return os.Getenv(restartGateEnv) == "1" }

// restartSupervisorClient returns the client for the daemon managing the
// disposable engine container.
func restartSupervisorClient(t *testing.T) *client.Client {
	t.Helper()
	host := os.Getenv(restartSupervisorEnv)
	if host == "" {
		t.Fatalf("%s must name the Docker endpoint that manages the disposable engine container", restartSupervisorEnv)
	}
	cli, err := client.NewClientWithOpts(client.WithHost(host), client.WithAPIVersionNegotiation())
	if err != nil {
		t.Fatalf("construct supervisor client (%s): %v", host, err)
	}
	return cli
}

// disposableEngineFacts verifies the supervisor actually manages the declared
// disposable engine container and returns its name. The safety checks make a
// misconfigured kill fail before anything is killed.
func disposableEngineFacts(t *testing.T, sup *client.Client) string {
	t.Helper()
	name := os.Getenv(disposableEngineEnv)
	if name == "" {
		t.Fatalf("%s must name the disposable engine container", disposableEngineEnv)
	}
	engineHost := os.Getenv("DOCKER_HOST")
	if engineHost != "" && engineHost == os.Getenv(restartSupervisorEnv) {
		t.Fatalf("the Engine under test (%s) and the restart supervisor are the same endpoint; refusing to restart a possibly shared daemon", engineHost)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	insp, err := sup.ContainerInspect(ctx, name, client.ContainerInspectOptions{})
	if err != nil {
		if errdefs.IsNotFound(err) {
			t.Fatalf("disposable engine container %q not found on the supervisor endpoint %s", name, sup.DaemonHost())
		}
		t.Fatalf("inspect disposable engine container %q: %v", name, err)
	}
	if !insp.Container.State.Running {
		t.Fatalf("disposable engine container %q is not running (state %+v)", name, insp.Container.State)
	}
	if !strings.Contains(strings.ToLower(insp.Container.Config.Image), "dind") {
		t.Fatalf("refusing to restart %q: its image %q is not a DinD image", name, insp.Container.Config.Image)
	}
	t.Logf("supervisor manages disposable engine %q (image %q)", name, insp.Container.Config.Image)
	return name
}

// killDisposableEngine kills the disposable engine container (the Engine dies
// abruptly while requests are in flight).
func killDisposableEngine(t *testing.T, sup *client.Client, name string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := sup.ContainerKill(ctx, name, client.ContainerKillOptions{Signal: "SIGKILL"}); err != nil {
		t.Fatalf("kill disposable engine %q: %v", name, err)
	}
	t.Logf("disposable engine %q killed (SIGKILL)", name)
}

// startDisposableEngine restarts the disposable engine container and waits
// until the Engine under test answers again.
func startDisposableEngine(t *testing.T, sup *client.Client, name string, cli *client.Client) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := sup.ContainerStart(ctx, name, client.ContainerStartOptions{}); err != nil {
		t.Fatalf("start disposable engine %q: %v", name, err)
	}
	deadline := time.Now().Add(restartPingTimeout)
	for {
		pingCtx, pingCancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := cli.Ping(pingCtx, client.PingOptions{})
		pingCancel()
		if err == nil {
			t.Logf("disposable engine %q recovered and answers again", name)
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("Engine did not recover within %s after restarting %q: last ping error: %v", restartPingTimeout, name, err)
		}
		time.Sleep(2 * time.Second)
	}
}

// isBoundedTransportContextError classifies the bounded caller termination
// the contract requires when the Engine dies mid-request: a transport-level
// connection/stream error or a context error — never a silent success and
// never a protocol answer from a daemon that cannot answer anymore.
func isBoundedTransportContextError(err error) bool {
	if err == nil {
		return false
	}
	switch {
	case errors.Is(err, io.ErrUnexpectedEOF),
		errors.Is(err, io.EOF),
		errors.Is(err, context.Canceled),
		errors.Is(err, context.DeadlineExceeded),
		errors.Is(err, net.ErrClosed),
		errors.Is(err, syscall.ECONNRESET),
		errors.Is(err, syscall.ECONNREFUSED),
		errors.Is(err, syscall.EPIPE):
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return true
	}
	return false
}

// buildStreamWatcher follows an active build's progress stream. It counts
// received progress events (BuildKit progress format varies across Engine
// versions: plain "stream" text, binary aux traces, or both), keeps bounded
// textual evidence, records any builder error event, and collects the bounded
// terminal error of the stream reader.
type buildStreamWatcher struct {
	mu          sync.Mutex
	events      int
	streamLines []string
	buildError  string
	done        chan error
}

const maxStreamEvidence = 20

func watchBuildStream(r io.Reader) *buildStreamWatcher {
	w := &buildStreamWatcher{done: make(chan error, 1)}
	go func() {
		dec := json.NewDecoder(r)
		for {
			var event struct {
				Stream string `json:"stream"`
				Error  string `json:"error"`
			}
			if err := dec.Decode(&event); err != nil {
				if errors.Is(err, io.EOF) {
					w.done <- nil
				} else {
					w.done <- err
				}
				return
			}
			w.mu.Lock()
			w.events++
			if event.Stream != "" {
				w.streamLines = append(w.streamLines, strings.TrimSpace(event.Stream))
				if len(w.streamLines) > maxStreamEvidence {
					w.streamLines = w.streamLines[1:]
				}
			}
			if event.Error != "" {
				w.buildError = event.Error
			}
			w.mu.Unlock()
		}
	}()
	return w
}

// state returns the evidence collected so far.
func (w *buildStreamWatcher) state() (events int, streamEvidence string, buildError string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.events, strings.Join(w.streamLines, " | "), w.buildError
}

// TestEngineRestartDuringActiveOperation proves the daemon-shutdown
// cancellation row: a deterministic long-running build is active when the
// disposable Engine dies; the caller terminates with a bounded typed
// transport/context error (no hang, no ambiguous success); the Engine's
// recovery is observable; and the interrupted build produced no tagged image.
func TestEngineRestartDuringActiveOperation(t *testing.T) {
	if !restartGate() {
		t.Skipf("restart procedures require %s=1 and a disposable Engine endpoint", restartGateEnv)
	}
	cli := engineClient(t)
	sup := restartSupervisorClient(t)
	engineName := disposableEngineFacts(t, sup)
	ensureImagePresent(context.Background(), cli, t, "alpine:3.24")

	buildCtx, buildCancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer buildCancel()
	buildStart := time.Now()
	res, err := cli.ImageBuild(buildCtx, buildContext(t, map[string]string{
		"Dockerfile": "FROM alpine:3.24\nRUN sleep " + strconv.Itoa(restartBuildSleepSecs) + "\n",
	}), client.ImageBuildOptions{
		Tags:    []string{restartBuildImageTag},
		Version: buildtypes.BuilderBuildKit,
	})
	if err != nil {
		t.Fatalf("active build request: %v", err)
	}
	defer func() { _ = res.Body.Close() }()

	// The build runs a single RUN step that sleeps for a known, much longer
	// time than the kill delay, so from the moment the Engine accepted the
	// request the solve is guaranteed to still be running at the kill.
	// BuildKit's textual progress format varies across Engine versions, so
	// the watcher records received progress events and bounded stream
	// evidence instead of matching a step header, and the no-produced-image
	// assertion after recovery proves the build was not complete at the kill.
	watcher := watchBuildStream(res.Body)

	// Wait for the Engine to stream build progress (activity evidence), and
	// stop early with the collected evidence if the build ended on its own.
	for {
		events, streamEvidence, buildError := watcher.state()
		if events > 0 {
			t.Logf("build is streaming progress: %d event(s); last lines: %s", events, streamEvidence)
			break
		}
		select {
		case err := <-watcher.done:
			buildCancel()
			events, streamEvidence, buildError = watcher.state()
			t.Fatalf("build stream ended before the kill (not an active-operation kill): readerErr=%v builderError=%q events=%d lines=%s",
				err, buildError, events, streamEvidence)
		case <-time.After(restartKillElapsed / 2):
			if time.Since(buildStart) >= restartKillElapsed/2 {
				t.Logf("no build progress event within %s; the request is still open and the sleep step guarantees an active solve; killing now",
					restartKillElapsed/2)
				break
			}
		}
		if time.Since(buildStart) >= restartKillElapsed/2 {
			break
		}
	}

	// Guard: the stream must not have ended (build finished/failed) before
	// the kill.
	select {
	case err := <-watcher.done:
		buildCancel()
		events, streamEvidence, buildError := watcher.state()
		t.Fatalf("build stream ended before the kill (not an active-operation kill): readerErr=%v builderError=%q events=%d lines=%s",
			err, buildError, events, streamEvidence)
	default:
	}

	if elapsed := time.Since(buildStart); elapsed < restartKillElapsed {
		time.Sleep(restartKillElapsed - elapsed)
	}
	t.Logf("killing the Engine %s after the build request was accepted (the %ds sleep step cannot have completed)",
		time.Since(buildStart).Round(time.Millisecond), restartBuildSleepSecs)

	killDisposableEngine(t, sup, engineName)
	select {
	case streamErr := <-watcher.done:
		events, streamEvidence, buildError := watcher.state()
		if streamErr == nil && buildError == "" {
			t.Fatalf("active build stream ended with success while the Engine was killed mid-build; ambiguous success (events=%d lines=%s)", events, streamEvidence)
		}
		if streamErr == nil {
			// The stream ended cleanly right at the kill carrying a builder
			// error event; a daemon that died cannot produce one, so treat
			// only a genuine builder error as evidence and fail otherwise.
			t.Fatalf("active build stream ended cleanly with builderError=%q at the kill; events=%d lines=%s", buildError, events, streamEvidence)
		}
		if !isBoundedTransportContextError(streamErr) {
			t.Fatalf("active build terminated with an unclassifiable error (want a bounded transport/context error): %v (events=%d lines=%s)", streamErr, events, streamEvidence)
		}
		t.Logf("active build terminated with a bounded typed transport/context error: %v", streamErr)
	case <-time.After(restartErrorBound):
		t.Fatalf("active build did not terminate within %s after the Engine was killed (hang)", restartErrorBound)
	}

	startDisposableEngine(t, sup, engineName, cli)

	recoverCtx, recoverCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer recoverCancel()
	if _, err := cli.ImageInspect(recoverCtx, restartBuildImageTag); err == nil {
		t.Fatalf("build interrupted by an Engine restart nevertheless produced %s", restartBuildImageTag)
	} else if !errdefs.IsNotFound(err) {
		t.Fatalf("inspect interrupted build image: %v", err)
	}
	t.Logf("interrupted build produced no tagged image on the recovered Engine (kill at +%.1fs, step needs %ds)",
		restartKillElapsed.Seconds(), restartBuildSleepSecs)

	if _, err := cli.ImageRemove(recoverCtx, restartBuildImageTag, client.ImageRemoveOptions{Force: true}); err != nil && !errdefs.IsNotFound(err) {
		t.Fatalf("cleanup of %s: %v", restartBuildImageTag, err)
	}
	containers, err := cli.ContainerList(recoverCtx, client.ContainerListOptions{All: true})
	if err != nil {
		t.Fatalf("list containers for leak check: %v", err)
	}
	for _, c := range containers.Items {
		for _, n := range c.Names {
			if strings.HasPrefix(n, "/d01-") {
				t.Fatalf("leaked test container %q survived the Engine restart", n)
			}
		}
	}
	t.Log("engine restart during active operation: bounded typed error, observable recovery, no leaked resources")
}

// TestEngineOneShotLifecycleAcrossRestart proves the one-shot lifecycle row
// across an Engine restart: a waiting one-shot workload is interrupted by the
// Engine dying (bounded typed error, no ambiguous success), a second workload
// created before the restart keeps its durable created state, the lifecycle
// continues after recovery, and cleanup/remove works on the recovered Engine.
func TestEngineOneShotLifecycleAcrossRestart(t *testing.T) {
	if !restartGate() {
		t.Skipf("restart procedures require %s=1 and a disposable Engine endpoint", restartGateEnv)
	}
	cli := engineClient(t)
	sup := restartSupervisorClient(t)
	engineName := disposableEngineFacts(t, sup)
	ensureImagePresent(context.Background(), cli, t, "alpine:3.24")

	setupCtx, setupCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer setupCancel()
	created, err := cli.ContainerCreate(setupCtx, client.ContainerCreateOptions{
		Name: restartOneshotName,
		Config: &container.Config{
			Image: "alpine:3.24",
			Cmd:   []string{"/bin/sh", "-c", "sleep 300"},
		},
	})
	if err != nil {
		t.Fatalf("one-shot create: %v", err)
	}
	if _, err := cli.ContainerStart(setupCtx, created.ID, client.ContainerStartOptions{}); err != nil {
		t.Fatalf("one-shot start: %v", err)
	}
	createdEarly, err := cli.ContainerCreate(setupCtx, client.ContainerCreateOptions{
		Name: restartCreatedName,
		Config: &container.Config{
			Image: "alpine:3.24",
			Cmd:   []string{"/bin/sh", "-c", "sleep 30"},
		},
	})
	if err != nil {
		t.Fatalf("created-state create: %v", err)
	}
	t.Logf("one-shot workload %s running; second workload %s in created state", created.ID[:12], createdEarly.ID[:12])

	waitCtx, waitCancel := context.WithCancel(context.Background())
	defer waitCancel()
	wait := cli.ContainerWait(waitCtx, created.ID, client.ContainerWaitOptions{})
	time.Sleep(5 * time.Second) // the wait request is established on the Engine

	killDisposableEngine(t, sup, engineName)
	select {
	case waitErr := <-wait.Error:
		if !isBoundedTransportContextError(waitErr) {
			t.Fatalf("interrupted one-shot wait terminated with an unclassifiable error (want a bounded transport/context error): %v", waitErr)
		}
		t.Logf("interrupted one-shot wait terminated with a bounded typed transport/context error: %v", waitErr)
	case resp := <-wait.Result:
		t.Fatalf("interrupted one-shot wait returned a successful wait response (status %+v) while the Engine was killed; ambiguous success", resp)
	case <-time.After(restartErrorBound):
		t.Fatalf("interrupted one-shot wait did not terminate within %s after the Engine was killed (hang)", restartErrorBound)
	}

	startDisposableEngine(t, sup, engineName, cli)

	recoverCtx, recoverCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer recoverCancel()
	oneshot, err := cli.ContainerInspect(recoverCtx, created.ID, client.ContainerInspectOptions{})
	if err != nil {
		t.Fatalf("inspect one-shot workload after Engine recovery: %v", err)
	}
	if oneshot.Container.State.Running {
		t.Fatalf("one-shot workload still reports running after the Engine was killed and restarted: %+v", oneshot.Container.State)
	}
	t.Logf("post-restart one-shot workload state: status=%s exit=%d (Engine was killed hard)",
		oneshot.Container.State.Status, oneshot.Container.State.ExitCode)
	createdInspect, err := cli.ContainerInspect(recoverCtx, createdEarly.ID, client.ContainerInspectOptions{})
	if err != nil {
		t.Fatalf("inspect created-state workload after Engine recovery: %v", err)
	}
	if createdInspect.Container.State.Status != "created" {
		t.Fatalf("created-state workload did not survive the Engine restart: %+v", createdInspect.Container.State)
	}
	t.Log("created-state workload preserved its durable state across the Engine restart")

	removeCtx, removeCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer removeCancel()
	if _, err := cli.ContainerRemove(removeCtx, created.ID, client.ContainerRemoveOptions{Force: true}); err != nil {
		t.Fatalf("cleanup remove of the interrupted one-shot workload: %v", err)
	}
	if _, err := cli.ContainerInspect(removeCtx, created.ID, client.ContainerInspectOptions{}); !errdefs.IsNotFound(err) {
		t.Fatalf("removed one-shot workload must be absent with a typed NotFound error, got: %v", err)
	}
	t.Log("interrupted one-shot workload cleaned up with a typed absence after Engine recovery")

	// The lifecycle continues after recovery: the created-state workload is
	// started, waits for its deterministic exit, and is removed.
	startCtx, startCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer startCancel()
	if _, err := cli.ContainerStart(startCtx, createdEarly.ID, client.ContainerStartOptions{}); err != nil {
		t.Fatalf("start created-state workload after Engine recovery: %v", err)
	}
	waitCtx2, waitCancel2 := context.WithTimeout(context.Background(), 120*time.Second)
	defer waitCancel2()
	wait2 := cli.ContainerWait(waitCtx2, createdEarly.ID, client.ContainerWaitOptions{Condition: container.WaitConditionNextExit})
	var exitStatus container.WaitResponse
	select {
	case exitStatus = <-wait2.Result:
	case err := <-wait2.Error:
		t.Fatalf("wait for started created-state workload: %v", err)
	case <-time.After(120 * time.Second):
		t.Fatal("started created-state workload did not exit within 120s")
	}
	t.Logf("continued one-shot lifecycle after Engine recovery: exit status %+v", exitStatus)
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cleanupCancel()
	if _, err := cli.ContainerRemove(cleanupCtx, createdEarly.ID, client.ContainerRemoveOptions{Force: true}); err != nil {
		t.Fatalf("cleanup remove of the continued workload: %v", err)
	}
	if _, err := cli.ContainerInspect(cleanupCtx, createdEarly.ID, client.ContainerInspectOptions{}); !errdefs.IsNotFound(err) {
		t.Fatalf("removed continued workload must be absent with a typed NotFound error, got: %v", err)
	}

	leakCtx, leakCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer leakCancel()
	containers, err := cli.ContainerList(leakCtx, client.ContainerListOptions{All: true})
	if err != nil {
		t.Fatalf("list containers for leak check: %v", err)
	}
	for _, c := range containers.Items {
		for _, n := range c.Names {
			if strings.HasPrefix(n, "/d01-restart-") {
				t.Fatalf("leaked test container %q survived the one-shot lifecycle", n)
			}
		}
	}
	t.Log("one-shot lifecycle across Engine restart: bounded typed error, unambiguous post-restart states, cleanup after recovery")
}
