package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// runWithNMOUNTS posts a run request carrying n caller mounts of the same
// valid workspace source to distinct targets, through the real handler.
func runWithNMOUNTS(t *testing.T, app *App, token string, n int) *httptest.ResponseRecorder {
	t.Helper()
	mounts := make([]string, 0, n)
	for i := 0; i < n; i++ {
		mounts = append(mounts, fmt.Sprintf(`{"source":".","target":"/m%d"}`, i))
	}
	body := fmt.Sprintf(`{"image":"alpine:3.24","command":["true"],"mounts":[%s]}`, strings.Join(mounts, ","))
	req := httptest.NewRequest("POST", "/run", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.handleRun(w, req)
	return w
}

// TestRunOverMountLimitRefusedBeforePreparation proves the caller-mount
// ceiling: a request with maxRunMounts+1 mounts is refused with the single
// bounded client-input refusal before any lease, path probing, exposure
// resolution, pin, workload-MAC preparation, or Operation reservation. The
// 16 KiB request-body limit is not the security owner of this count.
// RED evidence at the starting SHA: an over-limit request reaches pin
// preparation.
func TestRunOverMountLimitRefusedBeforePreparation(t *testing.T) {
	app := newSystemModeRunTestApp(t)
	result, err := createSystemSession(t, app)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	var pinCount atomic.Int32
	app.PinMountSourceFn = func(sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
		pinCount.Add(1)
		return &pinnedMount{PinnedPath: "/tmp/test-mount", cleanup: func() error { return nil }}, nil
	}

	w := runWithNMOUNTS(t, app, result.Token, maxRunMounts+1)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("over-limit mounts: expected %d, got %d (%s)", http.StatusBadRequest, w.Code, w.Body.String())
	}
	if code := decodeRejectedResponse(t, w); code != "too_many_mounts" {
		t.Fatalf("over-limit mounts code: expected too_many_mounts, got %q", code)
	}
	if got := pinCount.Load(); got != 0 {
		t.Fatalf("over-limit mount request reached pin preparation: %d pins", got)
	}
}

// TestRunExactlyAtMountLimitAccepted proves exactly-at-limit succeeds: every
// caller mount is validated and pinned as before, with no behavior change at
// the boundary.
func TestRunExactlyAtMountLimitAccepted(t *testing.T) {
	app := newSystemModeRunTestApp(t)
	result, err := createSystemSession(t, app)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	var pinCount atomic.Int32
	app.PinMountSourceFn = func(sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
		pinCount.Add(1)
		return &pinnedMount{PinnedPath: "/tmp/test-mount", cleanup: func() error { return nil }}, nil
	}

	w := runWithNMOUNTS(t, app, result.Token, maxRunMounts)
	if w.Code != http.StatusCreated {
		t.Fatalf("exactly-at-limit mounts: expected %d, got %d (%s)", http.StatusCreated, w.Code, w.Body.String())
	}
	if got := pinCount.Load(); got != int32(maxRunMounts) {
		t.Fatalf("expected %d pins for exactly-at-limit mounts, got %d", maxRunMounts, got)
	}
}

// TestRunDuplicateMountsEachCountAgainstLimit proves duplicates consume slots:
// the same source/target spelling repeated maxRunMounts+1 times is refused.
// RED evidence at the starting SHA: duplicates bypass the count entirely.
func TestRunDuplicateMountsEachCountAgainstLimit(t *testing.T) {
	app := newSystemModeRunTestApp(t)
	result, err := createSystemSession(t, app)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	mounts := make([]string, 0, maxRunMounts+1)
	for i := 0; i < maxRunMounts+1; i++ {
		mounts = append(mounts, `{"source":".","target":"/data"}`)
	}
	body := fmt.Sprintf(`{"image":"alpine:3.24","command":["true"],"mounts":[%s]}`, strings.Join(mounts, ","))
	req := httptest.NewRequest("POST", "/run", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("duplicate over-limit mounts: expected %d, got %d (%s)", http.StatusBadRequest, w.Code, w.Body.String())
	}
	if code := decodeRejectedResponse(t, w); code != "too_many_mounts" {
		t.Fatalf("duplicate over-limit mounts code: expected too_many_mounts, got %q", code)
	}
}

// TestRunUserModeSameMountCeiling proves user mode obeys the same fixed
// caller-mount ceiling without gaining system-mode mechanics.
func TestRunUserModeSameMountCeiling(t *testing.T) {
	app := newTestAppWithAdminTokenAndStaging(t)
	app.OperationSupervisor = newOperationSupervisor()
	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0].Path))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	w := runWithNMOUNTS(t, app, result.Token, maxRunMounts+1)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("user mode over-limit mounts: expected %d, got %d (%s)", http.StatusBadRequest, w.Code, w.Body.String())
	}
	if code := decodeRejectedResponse(t, w); code != "too_many_mounts" {
		t.Fatalf("user mode over-limit mounts code: expected too_many_mounts, got %q", code)
	}
}

// TestRunHelperSocketProjectionDoesNotConsumeMountSlots proves the
// server-owned helper_socket projection is not a caller mount: a request
// with helper_socket and exactly maxRunMounts caller mounts is accepted.
func TestRunHelperSocketProjectionDoesNotConsumeMountSlots(t *testing.T) {
	app := newSystemModeRunTestApp(t)
	result, err := createSystemSession(t, app)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	var pinCount atomic.Int32
	app.PinMountSourceFn = func(sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
		pinCount.Add(1)
		return &pinnedMount{PinnedPath: t.TempDir(), cleanup: func() error { return nil }}, nil
	}

	mounts := make([]string, 0, maxRunMounts)
	for i := 0; i < maxRunMounts; i++ {
		mounts = append(mounts, fmt.Sprintf(`{"source":".","target":"/m%d"}`, i))
	}
	body := fmt.Sprintf(`{"image":"alpine:3.24","helper_socket":true,"command":["true"],"mounts":[%s]}`, strings.Join(mounts, ","))
	req := httptest.NewRequest("POST", "/run", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("helper_socket with exactly-at-limit caller mounts: expected %d, got %d (%s)", http.StatusCreated, w.Code, w.Body.String())
	}
	if got := pinCount.Load(); got != int32(maxRunMounts) {
		t.Fatalf("expected %d caller-mount pins, got %d", maxRunMounts, got)
	}
}

// TestRunReadOnlyAndWritableMountsCountEqually proves the read-only flag does
// not change the count: maxRunMounts read-only mounts are accepted and one
// more is refused.
func TestRunReadOnlyAndWritableMountsCountEqually(t *testing.T) {
	app := newSystemModeRunTestApp(t)
	result, err := createSystemSession(t, app)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	var pinCount atomic.Int32
	app.PinMountSourceFn = func(sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
		pinCount.Add(1)
		// A real pinned directory: read-only exposures are inspected through
		// the pinned node kind by the workload MAC backend.
		return &pinnedMount{PinnedPath: t.TempDir(), cleanup: func() error { return nil }}, nil
	}

	mounts := make([]string, 0, maxRunMounts+1)
	for i := 0; i < maxRunMounts; i++ {
		mounts = append(mounts, fmt.Sprintf(`{"source":".","target":"/m%d","read_only":true}`, i))
	}
	body := fmt.Sprintf(`{"image":"alpine:3.24","command":["true"],"mounts":[%s]}`, strings.Join(mounts, ","))
	req := httptest.NewRequest("POST", "/run", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.handleRun(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("exactly-at-limit read-only mounts: expected %d, got %d (%s)", http.StatusCreated, w.Code, w.Body.String())
	}
	if got := pinCount.Load(); got != int32(maxRunMounts) {
		t.Fatalf("expected %d pins for read-only mounts, got %d", maxRunMounts, got)
	}

	// One more read-only mount is refused.
	mounts = append(mounts, fmt.Sprintf(`{"source":".","target":"/m%d","read_only":true}`, maxRunMounts))
	overBody := fmt.Sprintf(`{"image":"alpine:3.24","command":["true"],"mounts":[%s]}`, strings.Join(mounts, ","))
	overReq := httptest.NewRequest("POST", "/run", strings.NewReader(overBody))
	overReq.Header.Set("Authorization", "Bearer "+result.Token)
	overReq.Header.Set("Content-Type", "application/json")
	overW := httptest.NewRecorder()
	app.handleRun(overW, overReq)
	if overW.Code != http.StatusBadRequest {
		t.Fatalf("over-limit read-only mounts: expected %d, got %d (%s)", http.StatusBadRequest, overW.Code, overW.Body.String())
	}
	if code := decodeRejectedResponse(t, overW); code != "too_many_mounts" {
		t.Fatalf("over-limit read-only mounts code: expected too_many_mounts, got %q", code)
	}
}
