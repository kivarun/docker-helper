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

			app := newTestAppWithAuth(t)
			app.OperationRegistry = newOperationRegistry()

			result, err := app.createSession(app.Config.AllowedRoot)
			if err != nil {
				t.Fatalf("createSession: %v", err)
			}

			dockerCalled := false
			app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
				dockerCalled = true
				return exec.CommandContext(ctx, "true")
			}

			body, _ := json.Marshal(tc.body)
			req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+result.Token)
			w := httptest.NewRecorder()

			app.handleRun(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected status %d, got %d", http.StatusBadRequest, w.Code)
			}

			var resp map[string]any
			if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
				t.Fatalf("cannot decode response: %v", err)
			}
			if code, ok := resp["code"].(string); !ok || code != "invalid_image" {
				t.Errorf("expected code 'invalid_image', got %q", code)
			}

			if dockerCalled {
				t.Error("Docker must not be invoked for rejected image")
			}

			if len(app.OperationRegistry.ops) != 0 {
				t.Error("no operation should be registered for rejected image")
			}

			records := parseAuditRecords(auditBuf)
			for _, rec := range records {
				if rec.Event == "run.start" {
					t.Error("run.start audit must not be emitted for rejected image")
				}
			}
		})
	}
}
