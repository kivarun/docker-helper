package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
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
	Mounts      []mountRequest    `json:"mounts,omitempty"`
}

type mountRequest struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"read_only,omitempty"`
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

func writeErrorWithCode(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, response{
		OK:      false,
		Code:    code,
		Message: message,
	})
}

func validateMount(mount mountRequest, workspace string) error {
	if mount.Source == "" {
		return fmt.Errorf("mount source is required")
	}

	if filepath.IsAbs(mount.Source) {
		return fmt.Errorf("mount source must be relative: %s", mount.Source)
	}

	if mount.Target == "" {
		return fmt.Errorf("mount target is required")
	}

	if !filepath.IsAbs(mount.Target) {
		return fmt.Errorf("mount target must be absolute: %s", mount.Target)
	}

	cleaned := filepath.Clean(mount.Target)
	if cleaned == "." || cleaned == ".." || filepath.IsAbs(cleaned) && cleaned == "/" {
		return fmt.Errorf("mount target is invalid: %s", mount.Target)
	}

	sourcePath := filepath.Join(workspace, mount.Source)
	sourcePath, err := filepath.Abs(sourcePath)
	if err != nil {
		return fmt.Errorf("cannot resolve mount source: %w", err)
	}

	sourcePath, err = filepath.EvalSymlinks(sourcePath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("mount source does not exist: %s", mount.Source)
		}
		return fmt.Errorf("cannot resolve mount source: %w", err)
	}

	if !isInside(workspace, sourcePath) {
		return fmt.Errorf("mount source escapes workspace: %s", mount.Source)
	}

	info, err := os.Stat(sourcePath)
	if err != nil {
		return fmt.Errorf("cannot access mount source: %w", err)
	}

	if !info.Mode().IsDir() && !info.Mode().IsRegular() {
		return fmt.Errorf("mount source is not a directory or regular file: %s", mount.Source)
	}

	return nil
}

func (a *App) handleRun(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
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

	targetSeen := make(map[string]bool)
	resolvedMounts := make([]struct {
		Source string
		Target string
		RO     bool
	}, 0, len(req.Mounts))

	for _, mount := range req.Mounts {
		if err := validateMount(mount, session.Workspace); err != nil {
			writeErrorWithCode(w, http.StatusBadRequest, "invalid_mount", err.Error())
			return
		}

		if targetSeen[mount.Target] {
			writeErrorWithCode(w, http.StatusBadRequest, "invalid_mount", "duplicate mount target: "+mount.Target)
			return
		}
		targetSeen[mount.Target] = true

		sourcePath := filepath.Join(session.Workspace, mount.Source)
		sourcePath, _ = filepath.Abs(sourcePath)
		sourcePath, _ = filepath.EvalSymlinks(sourcePath)

		resolvedMounts = append(resolvedMounts, struct {
			Source string
			Target string
			RO     bool
		}{
			Source: sourcePath,
			Target: mount.Target,
			RO:     mount.ReadOnly,
		})
	}

	started := time.Now()

	args := []string{
		"run",
		"--rm",
		"--security-opt", "label=disable",
		"--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
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

	for _, m := range resolvedMounts {
		mountSpec := fmt.Sprintf("type=bind,source=%s,target=%s", m.Source, m.Target)
		if m.RO {
			mountSpec += ",readonly"
		}
		args = append(args, "--mount", mountSpec)
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
