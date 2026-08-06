package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"regexp"
	"sort"
	"time"
)

var envNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

type runRequest struct {
	Image       string            `json:"image"`
	Entrypoint  string            `json:"entrypoint,omitempty"`
	Command     []string          `json:"command,omitempty"`
	Environment map[string]string `json:"environment,omitempty"`
}

func defaultRunCommand(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	return cmd.CombinedOutput()
}

func maskEnvValue(name, value string) string {
	runes := []rune(value)
	if len(runes) == 0 {
		return fmt.Sprintf("%s=\"\" (length=0)", name)
	}
	masked := string(runes[0]) + "***"
	return fmt.Sprintf("%s=%s (length=%d)", name, masked, len(runes))
}

func (a *App) handleRun(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireSession(w, r); !ok {
		return
	}

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

	for name := range req.Environment {
		if !envNamePattern.MatchString(name) {
			writeError(w, http.StatusBadRequest, "invalid environment variable name: "+name)
			return
		}
	}

	for name, value := range req.Environment {
		log.Printf("env: %s", maskEnvValue(name, value))
	}

	started := time.Now()

	args := []string{
		"run",
		"--rm",
	}

	if req.Entrypoint != "" {
		args = append(args, "--entrypoint", req.Entrypoint)
	}

	if len(req.Environment) > 0 {
		names := make([]string, 0, len(req.Environment))
		for name := range req.Environment {
			names = append(names, name)
		}
		sort.Strings(names)

		for _, name := range names {
			args = append(args, "--env", name+"="+req.Environment[name])
		}
	}

	args = append(args, req.Image)
	args = append(args, req.Command...)

	runCmd := a.RunCommand
	if runCmd == nil {
		runCmd = defaultRunCommand
	}

	output, err := runCmd("docker", args...)

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
