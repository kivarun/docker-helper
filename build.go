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

func (a *App) handleBuild(w http.ResponseWriter, r *http.Request) {
	var req buildRequest

	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	contextPath, dockerfilePath, err := validateBuildRequest(a.Config.AllowedRoot, req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	started := time.Now()

	cmd := exec.Command(
		"docker", "build",
		"--pull",
		"--provenance=false",
		"--sbom=false",
		"--file", dockerfilePath,
		"--tag", req.Image,
		contextPath,
	)

	output, err := cmd.CombinedOutput()
	duration := time.Since(started).Round(time.Millisecond).String()

	if err != nil {
		writeJSON(w, http.StatusInternalServerError, response{
			OK:       false,
			Message:  fmt.Sprintf("docker build failed: %v", err),
			Output:   string(output),
			Duration: duration,
		})
		return
	}

	writeJSON(w, http.StatusOK, response{
		OK:       true,
		Message:  "image built successfully",
		Output:   string(output),
		Duration: duration,
	})
}

func validateBuildRequest(allowedRoot string, req buildRequest) (string, string, error) {
	if req.Context == "" || req.Dockerfile == "" || req.Image == "" {
		return "", "", errors.New("context, dockerfile and image are required")
	}

	if filepath.IsAbs(req.Dockerfile) {
		return "", "", errors.New("dockerfile must be relative to context")
	}

	if !imagePattern.MatchString(req.Image) {
		return "", "", errors.New("invalid image name or tag")
	}

	rootPath, err := filepath.EvalSymlinks(allowedRoot)
	if err != nil {
		return "", "", fmt.Errorf("cannot resolve allowed root: %w", err)
	}

	contextPath, err := filepath.Abs(req.Context)
	if err != nil {
		return "", "", fmt.Errorf("cannot resolve context: %w", err)
	}

	contextPath, err = filepath.EvalSymlinks(contextPath)
	if err != nil {
		return "", "", fmt.Errorf("cannot resolve context: %w", err)
	}

	if !isInside(rootPath, contextPath) {
		return "", "", fmt.Errorf("context must be inside %s", rootPath)
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
