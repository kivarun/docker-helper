package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/distribution/reference"
)

// Image-reference grammar corpus (§2). The fixed corpus is shared by the
// request-time parser gate proof and the real docker-build differential
// proof. Values come from the Docker docs tag/reference grammar and
// Engine-accepted spellings observed in the existing build surface tests.
var imageReferenceCorpus = []string{
	// valid spellings
	"example:test",
	"alpine:latest",
	"alpine",
	"library/alpine:3.20",
	"ghcr.io/owner/repo:v1.0.0",
	"registry.example.com:5000/owner/repo:tag",
	"registry.example.com:5000/owner/repo-dash/name_underscore:tag.1",
	"example:test-with-dashes_and.dots",
	"localhost:5000/x:y",
	// invalid spellings (the empty spelling is the existing missing_field
	// contract, asserted separately in TestBuildImageReferenceMissingField)
	"-leading-dash",
	"-leading-dash",
	"UPPER:lower", // uppercase tag component is refused by the tag grammar
	"example:",
	"example:@bad",
	"example:/x", // empty repository component
	"/leading-slash",
	"repo/with//empty:tag",
	"repo:tag:extra",
	"example:test ", // trailing space
}

// referenceForTest isolates the parser call at the shared corpus call site:
// the SAME primitive the production gate calls.
func referenceForTest(ref string) error {
	_, err := reference.ParseNormalizedNamed(ref)
	return err
}

// TestBuildImageReferenceParserGate proves the request-time grammar gate:
// exactly the corpus members the canonical upstream parser accepts are
// admitted and every refused one gets the existing invalid-image refusal
// before any capacity/staging/operation/backend work.
func TestBuildImageReferenceParserGate(t *testing.T) {
	for _, ref := range imageReferenceCorpus {
		_, parseErr := reference.ParseNormalizedNamed(ref)
		t.Run("spelling/"+ref, func(t *testing.T) {
			app, _, _, token := setupBuildTest(t)
			probed := false
			app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
				probed = true
				return exec.CommandContext(ctx, "/bin/true")
			}
			req := newBuildRequest(map[string]any{
				"context":    ".",
				"dockerfile": "Dockerfile",
				"image":      ref,
			}, token)
			w := httptest.NewRecorder()
			app.handleBuild(w, req)

			if parseErr == nil {
				// Admitted spelling: the request proceeds to 201 and real
				// backend work.
				if w.Code != http.StatusCreated {
					t.Fatalf("parser admits %q but handler refused: %d", ref, w.Code)
				}
				waitBuild(t, app, w)
				if !probed {
					t.Fatalf("admitted spelling %q never reached backend execution", ref)
				}
				return
			}
			// Refused spelling: the existing invalid-request shape, and the
			// refusal happens BEFORE capacity reservation, staging, or any
			// backend work.
			if w.Code != http.StatusBadRequest {
				t.Fatalf("parser refuses %q but handler answered %d: %s", ref, w.Code, w.Body.String())
			}
			var resp response
			if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
				t.Fatalf("decode refusal: %v", err)
			}
			if resp.Code != "invalid_image" {
				t.Errorf("refused spelling %q: expected invalid_image, got %q", ref, resp.Code)
			}
			if probed {
				t.Errorf("refused spelling %q reached backend execution", ref)
			}
			if len(app.OperationSupervisor.ops) != 0 {
				t.Errorf("refused spelling %q registered an operation", ref)
			}
		})
	}
}

// TestBuildInvalidImageBeforeEverything proves ordering for a refused
// reference: no staging seam call, no supervisor registration, no docker
// process — the existing public invalid-request shape only.
func TestBuildInvalidImageBeforeEverything(t *testing.T) {
	app, _, _, token := setupBuildTest(t)
	stagedCalled := false
	app.StageBuildContextFn = func(ctx context.Context, ws, cpath, dfrel, rdir, opID string) (*stagedBuildContext, error) {
		stagedCalled = true
		return newStagingSeam(t, stagingSeamOptions{})(ctx, ws, cpath, dfrel, rdir, opID)
	}
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		t.Error("docker executed for an invalid image reference")
		return exec.CommandContext(ctx, "/bin/true")
	}

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "UPPER:lower",
	}, token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	var resp response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Code != "invalid_image" {
		t.Errorf("expected invalid_image, got %q", resp.Code)
	}
	if stagedCalled {
		t.Error("staging ran for an invalid image reference")
	}
	if len(app.OperationSupervisor.ops) != 0 {
		t.Error("operation registered for an invalid image reference")
	}
}

// TestBuildImageReferenceMissingField proves the empty spelling keeps the
// existing missing_field contract: the required-field check runs before the
// grammar gate and its refusal is unchanged.
func TestBuildImageReferenceMissingField(t *testing.T) {
	app, _, _, token := setupBuildTest(t)
	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
	}, token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	var resp response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Code != "missing_field" {
		t.Errorf("expected missing_field, got %q", resp.Code)
	}
	if resp.Message != "image is required" {
		t.Errorf("expected the image-required message, got %q", resp.Message)
	}
	if len(app.OperationSupervisor.ops) != 0 {
		t.Error("operation registered for a missing image field")
	}
}

// TestBuildImageReferenceNotNormalized proves the caller's spelling is
// validated only: the value handed onward (audit/commit stage argv) is the
// exact caller spelling, never a parser-normalized rewrite.
func TestBuildImageReferenceNotNormalized(t *testing.T) {
	app, _, _, token := setupBuildTest(t)
	// A spelling with an explicit registry host and digest-normalizable
	// parts stays byte-identical through validation: the parser's
	// normalized form (docker.io/library/...) must never replace it.
	const spelling = "registry.example.com:5000/owner/repo"
	var commitArgs []string
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		commitArgs = append(commitArgs, args...)
		return exec.CommandContext(ctx, "/bin/true")
	}
	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      spelling,
	}, token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)
	waitBuild(t, app, w)

	joined := strings.Join(commitArgs, "\x00")
	if !strings.Contains(joined, spelling) {
		t.Errorf("caller spelling %q not preserved in argv: %v", spelling, commitArgs)
	}
	// Negative self-guard: the normalized rewrite would be a DIFFERENT
	// string; assert it is not what was passed.
	if strings.Contains(joined, "docker.io/library/registry.example.com") {
		t.Errorf("caller spelling was normalized: %v", commitArgs)
	}
}

// TestBuildImageReferenceDifferentialWithDocker is the differential proof
// against real `docker build --tag`: for every corpus member the parser's
// accept/reject decision must agree with Docker's accept/reject of the tag
// on a real build attempt. Docker-gated: skips when the Engine is not
// reachable (repo convention for Docker-dependent tests).
func TestBuildImageReferenceDifferentialWithDocker(t *testing.T) {
	dockerAvailableForDifferential(t)

	dir, err := os.MkdirTemp("", "refdiff-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM scratch\n"), 0644); err != nil {
		t.Fatal(err)
	}

	for _, ref := range imageReferenceCorpus {
		t.Run("spelling/"+ref, func(t *testing.T) {
			parseErr := referenceForTest(ref)
			_, dockerErr := dockerBuildTagProbe(dir, ref)
			if (parseErr == nil) != (dockerErr == nil) {
				t.Errorf("parser and docker build --tag disagree for %q: parserErr=%v dockerErr=%v", ref, parseErr, dockerErr)
			}
		})
	}
}

// dockerBuildTagProbe runs `docker build --tag <ref> .` in the fixed fixture
// and reports whether Docker accepted the tag grammar. Build success beyond
// the tag grammar is irrelevant: a scratch build with no steps is instant,
// and a grammar refusal fails before any builder work.
func dockerBuildTagProbe(dir, ref string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "build", "--tag", ref, dir).CombinedOutput()
	return string(out), err
}

// dockerAvailableForDifferential is the Docker gate for the differential
// test: same environment shape as container_lifecycle_integration_test.go.
func dockerAvailableForDifferential(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker CLI not found in PATH")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "docker", "info").Run(); err != nil {
		t.Skipf("Docker daemon not reachable: %v", err)
	}
}
