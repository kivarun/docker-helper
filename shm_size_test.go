package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"testing"
)

// --- validateShmSize unit tests ---

func TestValidateShmSizeEmpty(t *testing.T) {
	size, err := validateShmSize("")
	if err != nil {
		t.Errorf("expected nil error for empty string, got %v", err)
	}
	if size != 0 {
		t.Errorf("expected 0, got %d", size)
	}
}

func TestValidateShmSizeBytes(t *testing.T) {
	size, err := validateShmSize("1")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if size != 1 {
		t.Errorf("expected 1, got %d", size)
	}
}

func TestValidateShmSizeKilobytes(t *testing.T) {
	size, err := validateShmSize("64k")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if size != 64*1024 {
		t.Errorf("expected %d, got %d", 64*1024, size)
	}
}

func TestValidateShmSizeMegabytes(t *testing.T) {
	size, err := validateShmSize("512m")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if size != 512*1024*1024 {
		t.Errorf("expected %d, got %d", 512*1024*1024, size)
	}
}

func TestValidateShmSizeGigabytes(t *testing.T) {
	size, err := validateShmSize("1g")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if size != 1024*1024*1024 {
		t.Errorf("expected %d, got %d", 1024*1024*1024, size)
	}
}

func TestValidateShmSizeMaxLimit(t *testing.T) {
	size, err := validateShmSize("2g")
	if err != nil {
		t.Fatalf("expected nil error for 2g, got %v", err)
	}
	if size != 2*1024*1024*1024 {
		t.Errorf("expected %d, got %d", 2*1024*1024*1024, size)
	}
}

func TestValidateShmSizeCaseInsensitive(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  int64
	}{
		{"64K", 64 * 1024},
		{"512M", 512 * 1024 * 1024},
		{"1G", 1024 * 1024 * 1024},
		{"2G", 2 * 1024 * 1024 * 1024},
	} {
		size, err := validateShmSize(tc.input)
		if err != nil {
			t.Fatalf("validateShmSize(%q): expected nil error, got %v", tc.input, err)
		}
		if size != tc.want {
			t.Errorf("validateShmSize(%q): expected %d, got %d", tc.input, tc.want, size)
		}
	}
}

func TestValidateShmSizeOverLimit(t *testing.T) {
	_, err := validateShmSize("3g")
	if err == nil {
		t.Error("expected error for 3g (over 2 GiB limit)")
	}
}

func TestValidateShmSizeZero(t *testing.T) {
	for _, tc := range []string{"0", "0m"} {
		t.Run(tc, func(t *testing.T) {
			_, err := validateShmSize(tc)
			if err == nil {
				t.Errorf("expected error for %q", tc)
			}
		})
	}
}

func TestValidateShmSizeNegative(t *testing.T) {
	_, err := validateShmSize("-1g")
	if err == nil {
		t.Error("expected error for -1g")
	}
}

func TestValidateShmSizePlusSign(t *testing.T) {
	_, err := validateShmSize("+1g")
	if err == nil {
		t.Error("expected error for +1g")
	}
}

func TestValidateShmSizeDecimal(t *testing.T) {
	_, err := validateShmSize("1.5g")
	if err == nil {
		t.Error("expected error for 1.5g")
	}
}

func TestValidateShmSizeSpace(t *testing.T) {
	_, err := validateShmSize("1 g")
	if err == nil {
		t.Error("expected error for '1 g'")
	}
}

func TestValidateShmSizeLeadingSpace(t *testing.T) {
	_, err := validateShmSize(" 1g")
	if err == nil {
		t.Error("expected error for ' 1g'")
	}
}

func TestValidateShmSizeTrailingSpace(t *testing.T) {
	_, err := validateShmSize("1g ")
	if err == nil {
		t.Error("expected error for '1g '")
	}
}

func TestValidateShmSizeInvalidUnit(t *testing.T) {
	_, err := validateShmSize("1x")
	if err == nil {
		t.Error("expected error for 1x")
	}
}

func TestValidateShmSizeOnlyUnit(t *testing.T) {
	_, err := validateShmSize("g")
	if err == nil {
		t.Error("expected error for 'g'")
	}
}

func TestValidateShmSizeOverflow(t *testing.T) {
	_, err := validateShmSize("99999999999999999999999g")
	if err == nil {
		t.Error("expected error for overflow value")
	}
}

// --- handleRun integration tests ---

func TestRunShmSizeOmitted(t *testing.T) {
	app := newTestAppWithAuth(t)
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	var capturedArgs []string
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		capturedArgs = args
		return exec.CommandContext(ctx, "/bin/true")
	}

	reqBody := map[string]string{"image": "alpine:latest"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleRun(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	for i, arg := range capturedArgs {
		if arg == "--shm-size" {
			t.Errorf("expected no --shm-size in args, found at index %d: %v", i, capturedArgs)
			return
		}
	}
}

func TestRunShmSizeEmpty(t *testing.T) {
	app := newTestAppWithAuth(t)
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	var capturedArgs []string
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		capturedArgs = args
		return exec.CommandContext(ctx, "/bin/true")
	}

	reqBody := map[string]any{
		"image":    "alpine:latest",
		"shm_size": "",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleRun(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	for i, arg := range capturedArgs {
		if arg == "--shm-size" {
			t.Errorf("expected no --shm-size in args, found at index %d: %v", i, capturedArgs)
			return
		}
	}
}

func TestRunShmSizeValid(t *testing.T) {
	app := newTestAppWithAuth(t)
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	var capturedArgs []string
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		capturedArgs = args
		return exec.CommandContext(ctx, "/bin/true")
	}

	reqBody := map[string]any{
		"image":    "alpine:latest",
		"shm_size": "512m",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleRun(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	// Verify --shm-size is present with the correct byte value.
	wantBytes := "536870912" // 512 * 1024 * 1024
	for i, arg := range capturedArgs {
		if arg == "--shm-size" && i+1 < len(capturedArgs) {
			if capturedArgs[i+1] != wantBytes {
				t.Errorf("expected --shm-size %s, got %s", wantBytes, capturedArgs[i+1])
			}
			return
		}
	}
	t.Errorf("expected --shm-size in args, got %v", capturedArgs)
}

func TestRunShmSizePlacementBeforeImage(t *testing.T) {
	app := newTestAppWithAuth(t)
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	var capturedArgs []string
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		capturedArgs = args
		return exec.CommandContext(ctx, "/bin/true")
	}

	reqBody := map[string]any{
		"image":    "myimage:test",
		"shm_size": "1g",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleRun(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	// Find --shm-size and image positions.
	shmIdx := -1
	imageIdx := -1
	for i, arg := range capturedArgs {
		if arg == "--shm-size" {
			shmIdx = i
		}
		if arg == "myimage:test" {
			imageIdx = i
		}
	}

	if shmIdx == -1 {
		t.Fatalf("expected --shm-size in args, got %v", capturedArgs)
	}
	if imageIdx == -1 {
		t.Fatalf("expected image in args, got %v", capturedArgs)
	}
	if shmIdx >= imageIdx {
		t.Errorf("--shm-size (idx %d) must come before image (idx %d)", shmIdx, imageIdx)
	}
}

func TestRunShmSizeInvalidRejected(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		t.Fatal("ExecCommandContext should not be called for invalid shm_size")
		return exec.CommandContext(ctx, "/bin/true")
	}

	for _, shmSize := range []string{"0", "-1g", "1.5g", "3g", "1x", "g", " 1g", "1 g"} {
		t.Run(shmSize, func(t *testing.T) {
			reqBody := map[string]any{
				"image":    "alpine:latest",
				"shm_size": shmSize,
			}
			body, _ := json.Marshal(reqBody)

			req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+result.Token)
			w := httptest.NewRecorder()

			app.handleRun(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected %d, got %d", http.StatusBadRequest, w.Code)
			}

			var resp response
			if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
				t.Fatalf("cannot decode response: %v", err)
			}

			if resp.Code != "invalid_shm_size" {
				t.Errorf("expected code 'invalid_shm_size', got %q", resp.Code)
			}
		})
	}
}

func TestRunShmSizeAuditIncluded(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app := newTestAppWithAuth(t)
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	reqBody := map[string]any{
		"image":    "alpine:latest",
		"shm_size": "256m",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleRun(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}
	opID, ok := resp["operation_id"].(string)
	if !ok || opID == "" {
		t.Fatal("expected operation_id in response")
	}
	op := app.OperationRegistry.get(opID)
	if op == nil {
		t.Fatal("operation not found in registry")
	}
	op.Wait()

	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	var startRec, finishRec *auditRecord
	for i := range records {
		if records[i].Event == "run.start" {
			startRec = &records[i]
		}
		if records[i].Event == "run.finish" {
			finishRec = &records[i]
		}
	}

	if startRec == nil {
		t.Fatal("run.start audit not found")
	}
	if startRec.ShmSize != "256m" {
		t.Errorf("run.start: expected shm_size '256m', got %q", startRec.ShmSize)
	}

	if finishRec == nil {
		t.Fatal("run.finish audit not found")
	}
	if finishRec.ShmSize != "256m" {
		t.Errorf("run.finish: expected shm_size '256m', got %q", finishRec.ShmSize)
	}
}

func TestRunShmSizeAuditOmitted(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app := newTestAppWithAuth(t)
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	reqBody := map[string]string{"image": "alpine:latest"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleRun(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}
	opID, ok := resp["operation_id"].(string)
	if !ok || opID == "" {
		t.Fatal("expected operation_id in response")
	}
	op := app.OperationRegistry.get(opID)
	if op == nil {
		t.Fatal("operation not found in registry")
	}
	op.Wait()

	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	for _, rec := range records {
		if rec.Event == "run.start" || rec.Event == "run.finish" {
			if rec.ShmSize != "" {
				t.Errorf("expected empty shm_size in %s audit, got %q", rec.Event, rec.ShmSize)
			}
		}
	}
}
