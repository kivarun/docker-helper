package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
	"golang.org/x/crypto/bcrypt"
)

// TestRegistryLoginEngineIntegration validates the migrated production
// registry-login path end to end against a disposable authenticated
// registry provisioned through a real Docker Engine:
//
//   - the production adapter (nil test seam, Engine endpoint from the
//     environment) validates correct and wrong credentials;
//   - a successful login persists the credential in the protected Session
//     Docker config store in the docker CLI config format;
//   - the stored credential stays consumable by the legacy Docker CLI
//     backend that build still uses (the cross-version regression
//     constraint, probed with a CLI pull against the same config format);
//   - the credential canaries never appear in the HTTP response, audit
//     capture, daemon log capture, or SQLite content.
//
// The test skips unless a Docker Engine is reachable. It provisions the
// registry with the Phase-0 mechanics (loopback-only publication, disposable
// credential volume) without importing the instrument.
func TestRegistryLoginEngineIntegration(t *testing.T) {
	dockerAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()

	provisioning, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		t.Fatalf("construct engine provisioning client: %v", err)
	}

	const userCanary = "dh-prod-login-user-canary-Bm5Jt7Yw2r"
	const passCanary = "dh-prod-login-pass-canary-Vk8Qn4Zs6h"

	registryHost := provisionDisposableRegistry(t, ctx, provisioning, "dh-login-auth-volume", userCanary, passCanary)

	// Production path: real adapter (nil seam, Engine endpoint from the
	// environment), test app, and one Session bearer.
	auditBuf, opBuf := setupTestLogging(t)
	app := newTestAppWithAdminToken(t)
	app.NewEngineClientFn = nil

	session, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	blob, _ := json.Marshal(map[string]string{
		"registry": registryHost,
		"username": userCanary,
		"password": passCanary,
	})
	req, _ := http.NewRequest(http.MethodPost, "/registry/login", bytes.NewReader(blob))
	req.Header.Set("Authorization", "Bearer "+session.Token)
	w := httptest.NewRecorder()
	app.handleRegistryLogin(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("correct credentials rejected: %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), passCanary) || strings.Contains(w.Body.String(), userCanary) {
		t.Error("HTTP response contains credential material")
	}

	// The stored credential is the validated pair for the exact registry.
	entry, ok, err := readSessionRegistryCredential(app.Config.RuntimeDir, session.Session.ID, registryHost)
	if err != nil || !ok {
		t.Fatalf("stored credential missing: ok=%v err=%v", ok, err)
	}
	storedUser, storedPass, err := decodeSessionDockerAuth(entry.Auth)
	if err != nil {
		t.Fatalf("decode stored credential: %v", err)
	}
	if storedUser != userCanary || storedPass != passCanary {
		t.Error("stored credential lost the validated pair")
	}

	// Wrong credentials are rejected at the registry boundary and destroy
	// nothing.
	blob, _ = json.Marshal(map[string]string{
		"registry": registryHost,
		"username": userCanary,
		"password": passCanary + "-wrong",
	})
	req, _ = http.NewRequest(http.MethodPost, "/registry/login", bytes.NewReader(blob))
	req.Header.Set("Authorization", "Bearer "+session.Token)
	w = httptest.NewRecorder()
	app.handleRegistryLogin(w, req)
	if w.Code != http.StatusUnprocessableEntity {
		// Record the engine's normalized view of the rejection as a fact
		// before failing. The cause text is checked against both canaries
		// first; registry credential material is never printed.
		eng, engErr := newEngineClient()
		if engErr == nil {
			defer eng.close()
			_, loginErr := eng.registryLogin(context.WithoutCancel(ctx), registryHost, userCanary, passCanary+"-wrong")
			if loginErr != nil {
				cause := loginErr.Error()
				if !strings.Contains(cause, passCanary) && !strings.Contains(cause, userCanary) {
					t.Logf("FACT: wrong-credential engine error: kind-normalized=%v raw-cause=%q", errorKindOf(loginErr), cause)
				} else {
					t.Logf("FACT: wrong-credential engine error cause withheld (contained credential material)")
				}
			}
		}
		t.Fatalf("wrong credentials must return 422, got %d %s", w.Code, w.Body.String())
	}
	var failure response
	if err := json.NewDecoder(w.Body).Decode(&failure); err != nil {
		t.Fatalf("decode failure response: %v", err)
	}
	if failure.Code != "registry_auth_denied" {
		t.Errorf("wrong-credential failure code = %q, want registry_auth_denied", failure.Code)
	}
	if strings.Contains(w.Body.String(), passCanary) || strings.Contains(w.Body.String(), passCanary+"-wrong") {
		t.Error("failure response contains credential material")
	}
	entry, ok, err = readSessionRegistryCredential(app.Config.RuntimeDir, session.Session.ID, registryHost)
	if err != nil || !ok {
		t.Fatalf("failed validation destroyed the stored credential: ok=%v err=%v", ok, err)
	}
	storedUser, storedPass, err = decodeSessionDockerAuth(entry.Auth)
	if err != nil {
		t.Fatalf("decode surviving credential: %v", err)
	}
	if storedUser != userCanary || storedPass != passCanary {
		t.Error("failed validation changed the stored credential")
	}

	// Canary containment across the helper-side sinks: audit capture,
	// daemon operational log capture, and SQLite content. The credential
	// may appear only in the protected session Docker config.json.
	for _, sink := range []struct{ name, blob string }{
		{"audit", auditBuf.String()},
		{"operational log", opBuf.String()},
	} {
		if strings.Contains(sink.blob, passCanary) || strings.Contains(sink.blob, userCanary) {
			t.Errorf("%s contains credential material", sink.name)
		}
	}
	dbBlob, err := os.ReadFile(app.Config.DatabasePath)
	if err != nil {
		t.Fatalf("read SQLite file: %v", err)
	}
	if strings.Contains(string(dbBlob), passCanary) || strings.Contains(string(dbBlob), userCanary) {
		t.Error("SQLite database contains credential material")
	}

	// The persisted representation stays consumable by the legacy Docker CLI
	// backend that pull/build still use: a pull through the session Docker
	// config succeeds against the private registry.
	privateRef := registryHost + "/dh-login/private:v1"
	if _, err := provisioning.ImageTag(ctx, client.ImageTagOptions{Source: "alpine:3.24", Target: privateRef}); err != nil {
		t.Fatalf("tag private image: %v", err)
	}
	authBlob, err := json.Marshal(map[string]any{
		"username":      userCanary,
		"password":      passCanary,
		"serveraddress": registryHost,
	})
	if err != nil {
		t.Fatalf("marshal push auth: %v", err)
	}
	push, err := provisioning.ImagePush(ctx, privateRef, client.ImagePushOptions{RegistryAuth: base64.StdEncoding.EncodeToString(authBlob)})
	if err != nil {
		t.Fatalf("push private image: %v", err)
	}
	if err := push.Wait(ctx); err != nil {
		t.Fatalf("push private image: %v", err)
	}

	dockerDir := sessionDockerDir(app.Config.RuntimeDir, session.Session.ID)
	pull := exec.CommandContext(ctx, "docker", "--config", dockerDir, "pull", privateRef)
	pullOut, pullErr := pull.CombinedOutput()
	if pullErr != nil {
		t.Fatalf("legacy docker CLI pull with the stored credential failed: %v\n%s", pullErr, pullOut)
	}
	t.Log("legacy docker CLI probe consumed the stored session credential successfully")
}

// provisionDisposableRegistry provisions an authenticated disposable
// registry through the given Engine client with the Phase-0 mechanics
// (loopback-only publication, disposable credential volume) and returns its
// loopback address. The container and the credential volume are removed on
// test cleanup. Before returning, the registry is verified ready with its
// auth middleware active: an anonymous /v2/ request is rejected and the
// canary credential pair is accepted.
func provisionDisposableRegistry(t *testing.T, ctx context.Context, provisioning *client.Client, volumeName, userCanary, passCanary string) string {
	t.Helper()

	hash, err := bcrypt.GenerateFromPassword([]byte(passCanary), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}

	seedPull, err := provisioning.ImagePull(ctx, "registry:2", client.ImagePullOptions{})
	if err != nil {
		t.Fatalf("pull registry:2: %v", err)
	}
	if err := seedPull.Wait(ctx); err != nil {
		t.Fatalf("pull registry:2: %v", err)
	}

	seedImagePull, err := provisioning.ImagePull(ctx, "alpine:3.24", client.ImagePullOptions{})
	if err != nil {
		t.Fatalf("pull alpine:3.24: %v", err)
	}
	if err := seedImagePull.Wait(ctx); err != nil {
		t.Fatalf("pull alpine:3.24: %v", err)
	}

	if _, err := provisioning.VolumeCreate(ctx, client.VolumeCreateOptions{Name: volumeName}); err != nil {
		t.Fatalf("create auth volume: %v", err)
	}
	t.Cleanup(func() {
		_, _ = provisioning.VolumeRemove(context.WithoutCancel(ctx), volumeName, client.VolumeRemoveOptions{Force: true})
	})

	seed, err := provisioning.ContainerCreate(ctx, client.ContainerCreateOptions{
		Config: &container.Config{
			Image: "alpine:3.24",
			Cmd:   []string{"sh", "-c", `printf '%s:%s\n' "$DH_USER" "$DH_HASH" > /auth/htpasswd`},
			Env:   []string{"DH_USER=" + userCanary, "DH_HASH=" + string(hash)},
		},
		HostConfig: &container.HostConfig{Binds: []string{volumeName + ":/auth"}},
	})
	if err != nil {
		t.Fatalf("create htpasswd helper: %v", err)
	}
	if _, err := provisioning.ContainerStart(ctx, seed.ID, client.ContainerStartOptions{}); err != nil {
		t.Fatalf("start htpasswd helper: %v", err)
	}
	waitResult := provisioning.ContainerWait(ctx, seed.ID, client.ContainerWaitOptions{})
	select {
	case <-waitResult.Result:
	case waitErr := <-waitResult.Error:
		t.Fatalf("wait htpasswd helper: %v", waitErr)
	}

	port, err := network.ParsePort("5000/tcp")
	if err != nil {
		t.Fatalf("parse container port: %v", err)
	}
	reg, err := provisioning.ContainerCreate(ctx, client.ContainerCreateOptions{
		Config: &container.Config{
			Image:        "registry:2",
			ExposedPorts: network.PortSet{port: {}},
			Env: []string{
				"REGISTRY_AUTH=htpasswd",
				"REGISTRY_AUTH_HTPASSWD_REALM=dh-registry",
				"REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd",
			},
		},
		HostConfig: &container.HostConfig{
			PortBindings: network.PortMap{port: []network.PortBinding{{
				HostIP:   netip.MustParseAddr("127.0.0.1"),
				HostPort: "",
			}}},
			Binds: []string{volumeName + ":/auth:ro"},
		},
	})
	if err != nil {
		t.Fatalf("create registry container: %v", err)
	}
	t.Cleanup(func() {
		_, _ = provisioning.ContainerRemove(context.WithoutCancel(ctx), reg.ID, client.ContainerRemoveOptions{Force: true})
	})
	if _, err := provisioning.ContainerStart(ctx, reg.ID, client.ContainerStartOptions{}); err != nil {
		t.Fatalf("start registry container: %v", err)
	}

	inspected, err := provisioning.ContainerInspect(ctx, reg.ID, client.ContainerInspectOptions{})
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
	// Address the published binding by its exact IPv4 loopback address.
	// The binding exists only on 127.0.0.1, while "localhost" may resolve
	// to ::1 first, and the exact address keeps image references and the
	// stored credential key deterministic.
	registryHost := "127.0.0.1:" + hostPort
	t.Logf("disposable registry: container 5000/tcp published on 127.0.0.1:%s", hostPort)

	waitRegistryEndpointReady(t, registryHost)
	// The registry boundary is authenticated before the production path runs.
	anonymous, anonymousErr := registryV2Ping(registryHost, "", "")
	if anonymousErr != nil {
		t.Fatalf("anonymous registry ping: %v", anonymousErr)
	}
	anonymous.Body.Close()
	if anonymous.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous /v2/ returned %d; auth middleware is not active", anonymous.StatusCode)
	}
	authorized, authorizedErr := registryV2Ping(registryHost, userCanary, passCanary)
	if authorizedErr != nil {
		t.Fatalf("authenticated registry ping: %v", authorizedErr)
	}
	authorized.Body.Close()
	if authorized.StatusCode != http.StatusOK {
		t.Fatalf("canary credential pair rejected by the registry boundary (status %d)", authorized.StatusCode)
	}

	return registryHost
}

// waitRegistryEndpointReady polls the registry /v2/ endpoint until it
// answers, with a container-log diagnostic on timeout.
func waitRegistryEndpointReady(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := registryV2Ping(addr, "", "")
		if err == nil {
			resp.Body.Close()
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Logf("disposable registry at %s did not become ready", addr)
	if cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation()); err == nil {
		logs, err := cli.ContainerLogs(context.Background(), "registry", client.ContainerLogsOptions{ShowStdout: true, ShowStderr: true, Tail: "20"})
		if err == nil {
			body, _ := io.ReadAll(logs)
			logs.Close()
			var plain bytes.Buffer
			_, _ = stdcopy.StdCopy(&plain, io.Discard, bytes.NewReader(body))
			t.Logf("FACT: registry-log-tail:\n%s", plain.String())
		}
	}
	t.FailNow()
}

// registryV2Ping performs one /v2/ probe with optional basic-auth
// credentials.
func registryV2Ping(addr, username, password string) (*http.Response, error) {
	httpClient := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest(http.MethodGet, "http://"+addr+"/v2/", nil)
	if err != nil {
		return nil, err
	}
	if username != "" {
		req.SetBasicAuth(username, password)
	}
	return httpClient.Do(req)
}
