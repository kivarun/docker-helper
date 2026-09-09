package main

import (
	"fmt"
	"net/http"
	"slices"
	"testing"
)

func TestRunEnvironmentSingleVar(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}

	captured := setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	w := postRun(t, app, result.Token, map[string]any{
		"image": "alpine:latest",
		"environment": map[string]string{
			"KEY": "value",
		},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	if spec := captured.lastSpec(); spec.Env["KEY"] != "value" {
		t.Errorf("environment = %+v, want KEY=value", spec.Env)
	}
}

func TestRunEnvironmentMultipleVars(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}

	captured := setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	w := postRun(t, app, result.Token, map[string]any{
		"image": "alpine:latest",
		"environment": map[string]string{
			"A": "1",
			"B": "2",
		},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	env := captured.lastSpec().Env
	if len(env) != 2 || env["A"] != "1" || env["B"] != "2" {
		t.Errorf("environment = %+v, want A=1 and B=2", env)
	}
}

func TestRunEnvironmentEmptyValue(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}

	captured := setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	w := postRun(t, app, result.Token, map[string]any{
		"image": "alpine:latest",
		"environment": map[string]string{
			"FLAG": "",
		},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	env := captured.lastSpec().Env
	if value, ok := env["FLAG"]; !ok || value != "" {
		t.Errorf("environment = %+v, want FLAG present with empty value", env)
	}
}

func TestRunEnvironmentInvalidName(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}

	w := postRun(t, app, result.Token, map[string]any{
		"image": "alpine:latest",
		"environment": map[string]string{
			"INVALID-NAME": "value",
		},
	})

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestRunEnvironmentNameStartsWithDigit(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}

	w := postRun(t, app, result.Token, map[string]any{
		"image": "alpine:latest",
		"environment": map[string]string{
			"1NAME": "value",
		},
	})

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestRunEnvironmentNameWithSpace(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}

	w := postRun(t, app, result.Token, map[string]any{
		"image": "alpine:latest",
		"environment": map[string]string{
			"NAME WITH SPACE": "value",
		},
	})

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestRunEnvironmentNameWithDash(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}

	w := postRun(t, app, result.Token, map[string]any{
		"image": "alpine:latest",
		"environment": map[string]string{
			"NAME-DASH": "value",
		},
	})

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

// TestRunEngineCreateConfiguration proves the prepared run spec maps onto
// the exact Engine create configuration the docker CLI run path produced:
// user identity, security option, reserved labels, sorted environment, and
// the command image/argv layout.
func TestRunEngineCreateConfiguration(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}

	captured := setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	w := postRun(t, app, result.Token, map[string]any{
		"image":       "alpine:latest",
		"entrypoint":  "/bin/sh",
		"command":     []string{"-c", "echo hello"},
		"environment": map[string]string{"KEY": "value"},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	spec := captured.lastSpec()

	// The prepared trusted spec carries the resolved identity, the
	// user-mode security option, the reserved labels, and the caller
	// environment.
	expectedUID, expectedGID, err := resolveSessionExecutionIdentity(app.DB, &result.Session)
	if err != nil {
		t.Fatalf("resolveSessionExecutionIdentity() error: %v", err)
	}
	if spec.User != fmt.Sprintf("%d:%d", expectedUID, expectedGID) {
		t.Errorf("user = %q, want %d:%d", spec.User, expectedUID, expectedGID)
	}
	if len(spec.SecurityOpt) != 1 || spec.SecurityOpt[0] != "label=disable" {
		t.Errorf("securityOpt = %+v, want [label=disable]", spec.SecurityOpt)
	}
	expectedLabels := []string{
		runtimeLabelSchema + "=" + runtimeLabelSchemaValue,
		runtimeLabelSessionID + "=" + result.Session.ID,
		runtimeLabelLauncherID + "=" + result.Session.LauncherID,
		runtimeLabelPrincipalName + "=" + result.Session.PrincipalName,
	}
	if !slices.Equal(spec.Labels, expectedLabels) {
		t.Errorf("labels = %+v, want %+v", spec.Labels, expectedLabels)
	}
	if spec.Env["KEY"] != "value" {
		t.Errorf("env = %+v, want KEY=value", spec.Env)
	}
	if spec.Image != "alpine:latest" || spec.Entrypoint != "/bin/sh" {
		t.Errorf("image/entrypoint = %q/%q", spec.Image, spec.Entrypoint)
	}
	if !slices.Equal(spec.Command, []string{"-c", "echo hello"}) {
		t.Errorf("command = %+v", spec.Command)
	}
}
