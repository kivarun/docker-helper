package main

import (
	"net/http"
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
	app := newTestAppWithAdminToken(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	captured := setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	w := postRun(t, app, result.Token, map[string]any{"image": "alpine:latest"})
	if w.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, w.Code)
	}

	if spec := captured.lastSpec(); spec.ShmSize != 0 {
		t.Errorf("shm size = %d, want unset (0)", spec.ShmSize)
	}
}

func TestRunShmSizeEmpty(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	captured := setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	w := postRun(t, app, result.Token, map[string]any{
		"image":    "alpine:latest",
		"shm_size": "",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, w.Code)
	}

	if spec := captured.lastSpec(); spec.ShmSize != 0 {
		t.Errorf("shm size = %d, want unset (0)", spec.ShmSize)
	}
}

func TestRunShmSizeValid(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	captured := setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	w := postRun(t, app, result.Token, map[string]any{
		"image":    "alpine:latest",
		"shm_size": "512m",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, w.Code)
	}

	if spec := captured.lastSpec(); spec.ShmSize != 512*1024*1024 {
		t.Errorf("shm size = %d, want %d", spec.ShmSize, 512*1024*1024)
	}
}

func TestRunShmSizeLimitPassedUnchanged(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	captured := setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	w := postRun(t, app, result.Token, map[string]any{
		"image":    "myimage:test",
		"shm_size": "2g",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, w.Code)
	}

	if spec := captured.lastSpec(); spec.ShmSize != 2*1024*1024*1024 {
		t.Errorf("shm size = %d, want %d", spec.ShmSize, 2*1024*1024*1024)
	}
}

func TestRunShmSizeInvalidRejected(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	captured := setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	for _, shmSize := range []string{"0", "-1g", "1.5g", "3g", "1x", "g", " 1g", "1 g"} {
		t.Run(shmSize, func(t *testing.T) {
			w := postRun(t, app, result.Token, map[string]any{
				"image":    "alpine:latest",
				"shm_size": shmSize,
			})

			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected %d, got %d", http.StatusBadRequest, w.Code)
			}

			resp := decodeRunResponse(t, w)
			if resp.Code != "invalid_shm_size" {
				t.Errorf("expected code 'invalid_shm_size', got %q", resp.Code)
			}
		})
	}

	if captured.reached() {
		t.Error("Engine runner must not be called for rejected shm sizes")
	}
}

func TestRunShmSizeAuditIncluded(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app := newTestAppWithAdminToken(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	w := postRun(t, app, result.Token, map[string]any{
		"image":    "alpine:latest",
		"shm_size": "256m",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, w.Code)
	}

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

	app := newTestAppWithAdminToken(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	w := postRun(t, app, result.Token, map[string]any{"image": "alpine:latest"})
	if w.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, w.Code)
	}

	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	for _, rec := range records {
		if rec.Event == "run.start" || rec.Event == "run.finish" {
			if rec.ShmSize != "" {
				t.Errorf("expected empty shm_size in %s audit, got %q", rec.Event, rec.ShmSize)
			}
		}
	}
}
