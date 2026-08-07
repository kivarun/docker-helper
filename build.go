package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var imagePattern = regexp.MustCompile(`^[a-zA-Z0-9._/-]+:[a-zA-Z0-9._-]+$`)

type buildRequest struct {
	Context    string `json:"context"`
	Dockerfile string `json:"dockerfile"`
	Image      string `json:"image"`
}

func defaultBuildCommand(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	return cmd.CombinedOutput()
}

func (a *App) handleBuild(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}

	var req buildRequest

	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	contextPath, dockerfilePath, err := validateBuildRequest(session.Workspace, req)
	if err != nil {
		writeErrorWithCode(w, http.StatusBadRequest, "invalid_build_context", err.Error())
		return
	}

	writeAudit(auditRecord{
		Event:     "build.start",
		SessionID: session.ID,
		Image:     req.Image,
		Context:   req.Context,
		Dockerfile: req.Dockerfile,
	})

	started := time.Now()

	args := []string{
		"build",
		"--pull",
		"--provenance=false",
		"--sbom=false",
		"--file", dockerfilePath,
		"--tag", req.Image,
		contextPath,
	}

	buildCmd := a.BuildCommand
	if buildCmd == nil {
		buildCmd = defaultBuildCommand
	}

	output, err := buildCmd("docker", args...)
	duration := time.Since(started).Round(time.Millisecond).String()

	var result string
	var exitCode *int

	if err != nil {
		exitCode = extractExitCode(err)
		result = "build_error"

		writeJSON(w, http.StatusInternalServerError, response{
			OK:       false,
			Message:  fmt.Sprintf("docker build failed: %v", err),
			Output:   string(output),
			Duration: duration,
		})
	} else {
		result = "success"

		writeJSON(w, http.StatusOK, response{
			OK:       true,
			Message:  "image built successfully",
			Output:   string(output),
			Duration: duration,
		})
	}

	writeAudit(auditRecord{
		Event:     "build.finish",
		SessionID: session.ID,
		Image:     req.Image,
		Context:   req.Context,
		Dockerfile: req.Dockerfile,
		Result:    result,
		ExitCode:  exitCode,
		Duration:  duration,
	})
}

func validateBuildRequest(workspace string, req buildRequest) (string, string, error) {
	if req.Context == "" || req.Dockerfile == "" || req.Image == "" {
		return "", "", errors.New("context, dockerfile and image are required")
	}

	if filepath.IsAbs(req.Dockerfile) {
		return "", "", errors.New("dockerfile must be relative to context")
	}

	if !imagePattern.MatchString(req.Image) {
		return "", "", errors.New("invalid image name or tag")
	}

	var err error
	workspace, err = filepath.EvalSymlinks(workspace)
	if err != nil {
		return "", "", fmt.Errorf("cannot resolve workspace: %w", err)
	}

	var contextPath string

	if filepath.IsAbs(req.Context) {
		contextPath, err = filepath.Abs(req.Context)
		if err != nil {
			return "", "", fmt.Errorf("cannot resolve context: %w", err)
		}
	} else {
		contextPath = filepath.Join(workspace, req.Context)
	}

	contextPath, err = filepath.EvalSymlinks(contextPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", "", fmt.Errorf("context does not exist: %s", req.Context)
		}
		return "", "", fmt.Errorf("cannot resolve context: %w", err)
	}

	if !isInside(workspace, contextPath) {
		return "", "", fmt.Errorf("context must be inside workspace: %s", req.Context)
	}

	info, err := os.Stat(contextPath)
	if err != nil {
		return "", "", fmt.Errorf("cannot access context: %w", err)
	}
	if !info.IsDir() {
		return "", "", errors.New("context is not a directory")
	}

	dockerfilePath := filepath.Join(contextPath, req.Dockerfile)
	dockerfilePath, err = filepath.EvalSymlinks(dockerfilePath)
	if err != nil {
		return "", "", fmt.Errorf("cannot resolve dockerfile: %w", err)
	}

	if !isInside(contextPath, dockerfilePath) {
		return "", "", errors.New("dockerfile escapes build context")
	}

	info, err = os.Stat(dockerfilePath)
	if err != nil {
		return "", "", fmt.Errorf("cannot access dockerfile: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", "", errors.New("dockerfile is not a regular file")
	}

	return contextPath, dockerfilePath, nil
}

func isInside(parent, child string) bool {
	relative, err := filepath.Rel(parent, child)
	if err != nil {
		return false
	}

	return relative != ".." &&
		!strings.HasPrefix(relative, ".."+string(filepath.Separator))
}
