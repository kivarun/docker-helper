package main

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

// runEngineError builds a normalized Engine failure for run tests.
func runEngineError(kind engineErrorKind) error {
	return &engineError{kind: kind, cause: errors.New("engine probe")}
}

// TestRunSynchronousSuccess proves the synchronous run contract on the
// production handler: the flat result comes back in the response with the
// terminal exit code and bounded combined output, no operation identity is
// issued, and no run Operation is registered.
func TestRunSynchronousSuccess(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app := newTestAppWithAdminToken(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}

	setupRunSeam(t, app, runSeamOptions{Output: "container output\n", ExitCode: 0})

	w := postRun(t, app, result.Token, map[string]any{
		"image":   "alpine:latest",
		"command": []string{"echo", "hello"},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	respBody := w.Body.Bytes()
	resp := decodeRunResponse(t, w)
	if !resp.OK || resp.Code != "" || resp.Message != "" {
		t.Errorf("success response = %+v", resp)
	}
	if resp.Output != "container output\n" {
		t.Errorf("output = %q", resp.Output)
	}
	if resp.Truncated {
		t.Error("short output must not be truncated")
	}
	if resp.Duration == "" {
		t.Error("duration must be set")
	}
	if resp.ExitCode == nil || *resp.ExitCode != 0 {
		t.Errorf("exit_code = %v, want 0", resp.ExitCode)
	}

	assertNoRunOperation(t, app, respBody)

	// No operation identity in the audit either.
	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	for _, rec := range records {
		if rec.OperationID != "" {
			t.Errorf("run audit must not carry operation_id: %+v", rec)
		}
	}
}

// TestRunNonZeroExitIsWorkloadResult proves a non-zero container exit stays
// a workload result: HTTP 200, ok false, code container_exit_nonzero, the
// actual exit code, and the bounded combined output.
func TestRunNonZeroExitIsWorkloadResult(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app := newTestAppWithAdminToken(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}

	setupRunSeam(t, app, runSeamOptions{Output: "error output", ExitCode: 7})

	w := postRun(t, app, result.Token, map[string]any{
		"image":   "alpine:latest",
		"command": []string{"sh", "-c", "exit 7"},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	respBody := w.Body.Bytes()
	resp := decodeRunResponse(t, w)
	if resp.OK {
		t.Errorf("non-zero exit must not be ok: %+v", resp)
	}
	if resp.Code != "container_exit_nonzero" {
		t.Errorf("code = %q, want container_exit_nonzero", resp.Code)
	}
	if resp.ExitCode == nil || *resp.ExitCode != 7 {
		t.Errorf("exit_code = %v, want 7", resp.ExitCode)
	}
	if resp.Output != "error output" {
		t.Errorf("output = %q", resp.Output)
	}
	if resp.Duration == "" {
		t.Error("duration must be set")
	}

	assertNoRunOperation(t, app, respBody)

	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	foundFinish := false
	for _, rec := range records {
		if rec.Event == "run.finish" {
			foundFinish = true
			if rec.Result != "container_exit_nonzero" {
				t.Errorf("finish result = %q, want container_exit_nonzero", rec.Result)
			}
			if rec.ExitCode == nil || *rec.ExitCode != 7 {
				t.Errorf("audit exit_code = %v, want 7", rec.ExitCode)
			}
		}
	}
	if !foundFinish {
		t.Error("run.finish audit record missing")
	}
}

// TestRunExitCode125IsStillAWorkloadResult proves the terminal container
// exit code from the Engine wait is a workload result, not a docker CLI
// classification: exit 125 reaches the client as container_exit_nonzero
// with the actual code.
func TestRunExitCode125IsStillAWorkloadResult(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}

	setupRunSeam(t, app, runSeamOptions{Output: "image not found\n", ExitCode: 125})

	w := postRun(t, app, result.Token, map[string]any{
		"image": "alpine:latest",
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	resp := decodeRunResponse(t, w)
	if resp.OK || resp.Code != "container_exit_nonzero" || resp.ExitCode == nil || *resp.ExitCode != 125 {
		t.Errorf("exit 125 response = %+v", resp)
	}
}

// TestRunEngineFailureClassification proves the canonical Engine failure
// contract for run: no exit code is guessed from the failure, the response
// carries the normalized code and bounded output, and the failure response
// never carries an operation identity.
func TestRunEngineFailureClassification(t *testing.T) {
	cases := []struct {
		name         string
		err          error
		wantStatus   int
		wantCode     string
		wantExitCode bool
	}{
		{
			name:       "backend unavailable",
			err:        runEngineError(engineErrBackendUnavailable),
			wantStatus: http.StatusServiceUnavailable,
			wantCode:   "backend_unavailable",
		},
		{
			name:       "backend failure",
			err:        runEngineError(engineErrBackendFailure),
			wantStatus: http.StatusBadGateway,
			wantCode:   "backend_failure",
		},
		{
			name:       "image not found",
			err:        runEngineError(engineErrImageNotFound),
			wantStatus: http.StatusNotFound,
			wantCode:   "image_not_found",
		},
		{
			name:       "registry auth denied",
			err:        runEngineError(engineErrRegistryAuthDenied),
			wantStatus: http.StatusUnprocessableEntity,
			wantCode:   "registry_auth_denied",
		},
		{
			name:       "registry unavailable",
			err:        runEngineError(engineErrRegistryUnavailable),
			wantStatus: http.StatusBadGateway,
			wantCode:   "registry_unavailable",
		},
		{
			name:       "unclassified failure",
			err:        errors.New("raw engine payload probe"),
			wantStatus: http.StatusBadGateway,
			wantCode:   "backend_failure",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			auditBuf, _ := setupTestLogging(t)

			app := newTestAppWithAdminToken(t)
			app.OperationSupervisor = newOperationSupervisor()

			result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
			if err != nil {
				t.Fatalf("createSessionAuthorized() error: %v", err)
			}

			setupRunSeam(t, app, runSeamOptions{
				Output: "partial output",
				Err:    tc.err,
			})

			w := postRun(t, app, result.Token, map[string]any{
				"image":   "alpine:latest",
				"command": []string{"true"},
			})

			if w.Code != tc.wantStatus {
				t.Fatalf("expected status %d, got %d: %s", tc.wantStatus, w.Code, w.Body.String())
			}

			respBody := w.Body.Bytes()
			resp := decodeRunResponse(t, w)
			if resp.OK || resp.Code != tc.wantCode {
				t.Errorf("response = %+v, want code %s", resp, tc.wantCode)
			}
			if resp.ExitCode != nil {
				t.Errorf("Engine failure must not guess an exit code: %+v", resp)
			}
			if resp.Output != "partial output" {
				t.Errorf("output before failure = %q", resp.Output)
			}

			assertNoRunOperation(t, app, respBody)

			records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
			foundFinish := false
			for _, rec := range records {
				if rec.Event == "run.finish" {
					foundFinish = true
					if rec.Result != "docker_run_failed" {
						t.Errorf("finish result = %q, want docker_run_failed", rec.Result)
					}
					if rec.ExitCode != nil {
						t.Errorf("audit must not carry a guessed exit code: %+v", rec)
					}
				}
			}
			if !foundFinish {
				t.Error("run.finish audit record missing")
			}
		})
	}
}

// TestRunAdapterConstructionFailure proves a failed Engine adapter
// construction is a bounded run failure, not a panic or a leak.
func TestRunAdapterConstructionFailure(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}

	setupRunSeam(t, app, runSeamOptions{ConstructErr: errors.New("no engine endpoint")})

	w := postRun(t, app, result.Token, map[string]any{"image": "alpine:latest"})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected %d, got %d: %s", http.StatusInternalServerError, w.Code, w.Body.String())
	}

	resp := decodeRunResponse(t, w)
	if resp.OK || resp.Code != "docker_run_failed" {
		t.Errorf("response = %+v", resp)
	}
	if resp.ExitCode != nil {
		t.Errorf("no exit code on construction failure: %+v", resp)
	}

	assertNoRunOperation(t, app, w.Body.Bytes())
}

// TestRunEnginePayloadStaysOutOfLogs proves the operational log records only
// the normalized category, never the raw Engine payload or the workload
// output.
func TestRunEnginePayloadStaysOutOfLogs(t *testing.T) {
	_, opBuf := setupTestLogging(t)

	app := newTestAppWithAdminToken(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}

	setupRunSeam(t, app, runSeamOptions{
		Output: "workload output marker outputmarker-9z4k",
		Err:    runEngineError(engineErrBackendFailure),
	})

	w := postRun(t, app, result.Token, map[string]any{"image": "alpine:latest"})
	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected %d, got %d", http.StatusBadGateway, w.Code)
	}

	logs := opBuf.String()
	if strings.Contains(logs, "raw engine payload") || strings.Contains(logs, "outputmarker-9z4k") {
		t.Errorf("raw payload or workload output leaked into operational logs: %s", logs)
	}
}
