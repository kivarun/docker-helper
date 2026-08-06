package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	// Пока ограничиваем helper только рабочими репозиториями пользователя.
	allowedRoot = "/home/michael/work/git"

	socketPath = "/run/user/1000/docker-helper.sock"
)

var imagePattern = regexp.MustCompile(`^[a-zA-Z0-9._/-]+:[a-zA-Z0-9._-]+$`)

type buildRequest struct {
	Context    string `json:"context"`
	Dockerfile string `json:"dockerfile"`
	Image      string `json:"image"`
}

type runRequest struct {
	Image   string   `json:"image"`
        Entrypoint string   `json:"entrypoint,omitempty"`
	Command []string `json:"command,omitempty"`
}

type response struct {
	OK       bool   `json:"ok"`
	Message  string `json:"message,omitempty"`
	Output   string `json:"output,omitempty"`
	Duration string `json:"duration,omitempty"`
}

func main() {
	if err := os.RemoveAll(socketPath); err != nil {
		log.Fatal(err)
	}

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatal(err)
	}

	if err := os.Chmod(socketPath, 0600); err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /build", handleBuild)
	mux.HandleFunc("GET /health", handleHealth)
        mux.HandleFunc("POST /run", handleRun)

	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("docker-helper listening on %s", socketPath)

	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, response{
		OK:      true,
		Message: "docker-helper is running",
	})
}

func handleBuild(w http.ResponseWriter, r *http.Request) {
	var req buildRequest

	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	contextPath, dockerfilePath, err := validateBuildRequest(req)
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

func validateBuildRequest(req buildRequest) (string, string, error) {
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

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, response{
		OK:      false,
		Message: message,
	})
}

func writeJSON(w http.ResponseWriter, status int, value response) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf("failed to encode response: %v", err)
	}
}

func handleRun(w http.ResponseWriter, r *http.Request) {
	var req runRequest

	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	if req.Image == "" {
		writeError(w, http.StatusBadRequest, "image is required")
		return
	}

	if !imagePattern.MatchString(req.Image) {
		writeError(w, http.StatusBadRequest, "invalid image name or tag")
		return
	}

	started := time.Now()

	args := []string{
		"run",
		"--rm",
	}

        if req.Entrypoint != "" {
		args = append(args, "--entrypoint", req.Entrypoint)
	}

	args = append(args, req.Image)
	args = append(args, req.Command...)

	cmd := exec.Command("docker", args...)

	output, err := cmd.CombinedOutput()

	duration := time.Since(started).Round(time.Millisecond).String()

	if err != nil {
		writeJSON(w, http.StatusInternalServerError, response{
			OK:       false,
			Message:  fmt.Sprintf("docker run failed: %v", err),
			Output:   string(output),
			Duration: duration,
		})
		return
	}

	writeJSON(w, http.StatusOK, response{
		OK:       true,
		Message:  "container finished successfully",
		Output:   string(output),
		Duration: duration,
	})
}

