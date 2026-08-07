package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

var envNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func extractExitCode(err error) *int {
	var exitCoder interface{ ExitCode() int }
	if errors.As(err, &exitCoder) {
		code := exitCoder.ExitCode()
		return &code
	}
	return nil
}

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

type resolvedMount struct {
	HostPath string
	Target   string
	ReadOnly bool
}

func defaultRunCommand(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	return cmd.CombinedOutput()
}

func resolveMount(mount mountRequest, workspace string) (*resolvedMount, error) {
	if mount.Source == "" {
		return nil, fmt.Errorf("mount source is required")
	}

	if filepath.IsAbs(mount.Source) {
		return nil, fmt.Errorf("mount source must be relative: %s", mount.Source)
	}

	if mount.Target == "" {
		return nil, fmt.Errorf("mount target is required")
	}

	if !filepath.IsAbs(mount.Target) {
		return nil, fmt.Errorf("mount target must be absolute: %s", mount.Target)
	}

	cleaned := filepath.Clean(mount.Target)
	if cleaned == "." || cleaned == ".." {
		return nil, fmt.Errorf("mount target is invalid: %s", mount.Target)
	}

	if strings.Contains(cleaned, ",") {
		return nil, fmt.Errorf("mount target contains unsupported character: %s", cleaned)
	}

	sourcePath := filepath.Join(workspace, mount.Source)
	sourcePath, err := filepath.Abs(sourcePath)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve mount source: %w", err)
	}

	sourcePath, err = filepath.EvalSymlinks(sourcePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("mount source does not exist: %s", mount.Source)
		}
		return nil, fmt.Errorf("cannot resolve mount source: %w", err)
	}

	if strings.Contains(sourcePath, ",") {
		return nil, fmt.Errorf("mount source contains unsupported character: %s", sourcePath)
	}

	if !isInside(workspace, sourcePath) {
		return nil, fmt.Errorf("mount source escapes workspace: %s", mount.Source)
	}

	info, err := os.Stat(sourcePath)
	if err != nil {
		return nil, fmt.Errorf("cannot access mount source: %w", err)
	}

	if !info.Mode().IsDir() && !info.Mode().IsRegular() {
		return nil, fmt.Errorf("mount source is not a directory or regular file: %s", mount.Source)
	}

	return &resolvedMount{
		HostPath: sourcePath,
		Target:   cleaned,
		ReadOnly: mount.ReadOnly,
	}, nil
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
		writeError(w, http.StatusBadRequest, "invalid_json", "invalid JSON request")
		return
	}

	if req.Image == "" {
		writeError(w, http.StatusBadRequest, "invalid_image", "image is required")
		return
	}

	if !imagePattern.MatchString(req.Image) {
		writeError(w, http.StatusBadRequest, "invalid_image", "invalid image name or tag")
		return
	}

	for name := range req.Environment {
		if !envNamePattern.MatchString(name) {
			writeError(w, http.StatusBadRequest, "invalid_environment", "invalid environment variable name")
			return
		}
	}

	envNames := make([]string, 0, len(req.Environment))
	for name := range req.Environment {
		envNames = append(envNames, name)
	}
	sort.Strings(envNames)

	for _, name := range envNames {
		log.Printf("env: %s", maskEnvValue(name, req.Environment[name]))
	}

	targetSeen := make(map[string]bool)
	resolvedMounts := make([]resolvedMount, 0, len(req.Mounts))

	for _, mount := range req.Mounts {
		resolved, err := resolveMount(mount, session.Workspace)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_mount", "invalid mount")
			return
		}

		if targetSeen[resolved.Target] {
			writeError(w, http.StatusBadRequest, "invalid_mount", "invalid mount")
			return
		}
		targetSeen[resolved.Target] = true

		resolvedMounts = append(resolvedMounts, *resolved)
	}

	mountAudit := make([]auditMount, 0, len(req.Mounts))
	for _, m := range req.Mounts {
		mountAudit = append(mountAudit, auditMount{
			Source:   m.Source,
			Target:   m.Target,
			ReadOnly: m.ReadOnly,
		})
	}

	writeAudit(auditRecord{
		Event:     "run.start",
		SessionID: session.ID,
		Image:     req.Image,
		Command:   req.Command,
		Mounts:    mountAudit,
		EnvKeys:   envNames,
	})

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

	for _, name := range envNames {
		args = append(args, "--env", name+"="+req.Environment[name])
	}

	for _, m := range resolvedMounts {
		mountSpec := fmt.Sprintf("type=bind,source=%s,target=%s", m.HostPath, m.Target)
		if m.ReadOnly {
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

	var result string
	var exitCode *int

	if err != nil {
		if ec := extractExitCode(err); ec != nil && *ec != 125 {
			exitCode = ec
			result = "container_exit_nonzero"

			writeJSON(w, http.StatusOK, response{
				OK:       false,
				Code:     "container_exit_nonzero",
				Message:  "container exited with non-zero status",
				Output:   string(output),
				Duration: duration,
				ExitCode: exitCode,
			})
		} else {
			exitCode = extractExitCode(err)
			result = "docker_error"

			log.Printf("docker run error: %v", err)

			writeJSON(w, http.StatusInternalServerError, response{
				OK:       false,
				Code:     "docker_run_failed",
				Message:  "docker run failed",
				Output:   string(output),
				Duration: duration,
			})
		}
	} else {
		result = "success"

		writeJSON(w, http.StatusOK, response{
			OK:       true,
			Message:  "container finished successfully",
			Output:   string(output),
			Duration: duration,
		})
	}

	writeAudit(auditRecord{
		Event:     "run.finish",
		SessionID: session.ID,
		Image:     req.Image,
		Command:   req.Command,
		Mounts:    mountAudit,
		EnvKeys:   envNames,
		Result:    result,
		ExitCode:  exitCode,
		Duration:  duration,
	})
}
