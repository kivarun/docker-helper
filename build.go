package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var imagePattern = regexp.MustCompile(`^[a-zA-Z0-9._/-]+:[a-zA-Z0-9._-]+$`)

var ErrInternal = errors.New("internal error")

type buildRequest struct {
	Context    string `json:"context"`
	Dockerfile string `json:"dockerfile"`
	Image      string `json:"image"`
}

func (a *App) handleBuild(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}

	ctx := withSessionID(r.Context(), session.ID)

	var req buildRequest

	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&req); err != nil {
		writeError(ctx, w, http.StatusBadRequest, "invalid_json", "invalid JSON request")
		return
	}

	contextPath, dockerfilePath, err := validateBuildRequest(session.Workspace, req)
	if err != nil {
		if errors.Is(err, ErrInternal) {
			opLog(ctx).Error("build validation error",
				slog.String("operation", "build_validate"),
				slog.String("error", err.Error()),
			)
			writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
			return
		}
		writeError(ctx, w, http.StatusBadRequest, "invalid_build_context", "invalid build context")
		return
	}

	writeAuditWithRequestID(ctx, auditRecord{
		Event:      "build.start",
		SessionID:  session.ID,
		Image:      req.Image,
		Context:    req.Context,
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

	buildCmd := a.ExecCommand
	if buildCmd == nil {
		buildCmd = defaultExecCommand
	}

	output, err := buildCmd("docker", args...)
	duration := time.Since(started).Round(time.Millisecond).String()

	var result string
	var exitCode *int

	if err != nil {
		exitCode = extractExitCode(err)
		result = "build_error"

		opLog(ctx).Error("docker build error",
			slog.String("operation", "build"),
			slog.String("error", err.Error()),
		)

		writeJSON(ctx, w, http.StatusInternalServerError, response{
			OK:       false,
			Code:     "docker_build_failed",
			Message:  "docker build failed",
			Output:   string(output),
			Duration: duration,
		})
	} else {
		result = "success"

		writeJSON(ctx, w, http.StatusOK, response{
			OK:       true,
			Message:  "image built successfully",
			Output:   string(output),
			Duration: duration,
		})
	}

	writeAuditWithRequestID(ctx, auditRecord{
		Event:      "build.finish",
		SessionID:  session.ID,
		Image:      req.Image,
		Context:    req.Context,
		Dockerfile: req.Dockerfile,
		Result:     result,
		ExitCode:   exitCode,
		Duration:   duration,
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
		return "", "", fmt.Errorf("cannot resolve workspace: %w: %w", err, ErrInternal)
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
