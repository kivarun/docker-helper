package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRunImageOptionInjectionRejected(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app := newTestAppWithAuth(t)
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	reqBody := map[string]any{
		"image":   "--mount=type=bind,source=/,target=/host",
		"command": []string{"attacker/image", "command"},
	}
	body, _ := json.Marshal(reqBody)

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

	// Docker must not have been invoked (no ExecCommandContext set).
	// Operation must not be registered — the rejection happens before tryCreate.

	// run.start must not appear in audit.
	records := parseAuditRecords(auditBuf)
	for _, rec := range records {
		if rec.Event == "run.start" {
			t.Error("run.start audit must not be emitted for rejected image")
		}
	}
}

func TestRunImageSingleDashRejected(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app := newTestAppWithAuth(t)
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	reqBody := map[string]string{"image": "-invalid"}
	body, _ := json.Marshal(reqBody)

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

	// Operation must not be registered — the rejection happens before tryCreate.

	records := parseAuditRecords(auditBuf)
	for _, rec := range records {
		if rec.Event == "run.start" {
			t.Error("run.start audit must not be emitted for rejected image")
		}
	}
}

func TestRunImageValidReferencesAccepted(t *testing.T) {
	// Verify that legitimate image references are not rejected by the dash check.
	validImages := []string{
		"alpine:latest",
		"alpine:3.19",
		"registry.example.com/myimage",
		"registry.example.com:5000/myimage:tag",
		"myimage@sha256:abc123",
		"myimage:latest",
	}

	for _, image := range validImages {
		t.Run(image, func(t *testing.T) {
			app := newTestAppWithAuth(t)

			result, err := app.createSession(app.Config.AllowedRoot)
			if err != nil {
				t.Fatalf("createSession: %v", err)
			}

			reqBody := map[string]string{"image": image}
			body, _ := json.Marshal(reqBody)

			req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+result.Token)
			w := httptest.NewRecorder()

			app.handleRun(w, req)

			// Should not return 400 invalid_image for valid references.
			// It may return other errors (e.g. 500 if docker not available),
			// but must not reject with invalid_image.
			if w.Code == http.StatusBadRequest {
				var resp map[string]any
				if err := json.NewDecoder(w.Body).Decode(&resp); err == nil {
					if code, ok := resp["code"].(string); ok && code == "invalid_image" {
						t.Errorf("valid image %q incorrectly rejected with invalid_image", image)
					}
				}
			}
		})
	}
}
