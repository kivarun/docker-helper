package main

import (
	"net/http"
	"testing"
)

func TestRunImageOptionInjectionRejected(t *testing.T) {
	cases := []struct {
		name string
		body map[string]any
	}{
		{
			name: "mount flag injection",
			body: map[string]any{
				"image":   "--mount=type=bind,source=/,target=/host",
				"command": []string{"attacker/image", "command"},
			},
		},
		{
			name: "single dash",
			body: map[string]any{"image": "-invalid"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			auditBuf, _ := setupTestLogging(t)

			app := newTestAppWithAdminToken(t)
			app.OperationSupervisor = newOperationSupervisor()

			result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
			if err != nil {
				t.Fatalf("createSession: %v", err)
			}

			captured := setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

			w := postRun(t, app, result.Token, tc.body)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected status %d, got %d", http.StatusBadRequest, w.Code)
			}

			resp := decodeRunResponse(t, w)
			if resp.Code != "invalid_image" {
				t.Errorf("expected code 'invalid_image', got %q", resp.Code)
			}

			if captured.reached() {
				t.Error("Engine runner must not be invoked for a rejected image")
			}

			assertNoRunOperation(t, app, w.Body.Bytes())

			records := parseAuditRecords(auditBuf)
			for _, rec := range records {
				if rec.Event == "run.start" {
					t.Error("run.start audit must not be emitted for rejected image")
				}
			}
		})
	}
}
