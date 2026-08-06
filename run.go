package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"time"
)

type runRequest struct {
	Image      string   `json:"image"`
	Entrypoint string   `json:"entrypoint,omitempty"`
	Command    []string `json:"command,omitempty"`
}

func (a *App) handleRun(w http.ResponseWriter, r *http.Request) {
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