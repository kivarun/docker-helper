package main

import (
	"context"
	"errors"
	"fmt"
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

// defaultExecCommand is the default Docker subprocess executor.
func defaultExecCommand(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	return cmd.CombinedOutput()
}

type runRequest struct {
	Image       string            `json:"image"`
	Entrypoint  string            `json:"entrypoint,omitempty"`
	Workdir     string            `json:"workdir,omitempty"`
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

	ctx := withSessionID(r.Context(), session.ID)

	var req runRequest

	if err := decodeJSONRequest(w, r, &req); err != nil {
		writeError(ctx, w, http.StatusBadRequest, "invalid_json", "invalid JSON request")
		return
	}

	if req.Image == "" {
		writeError(ctx, w, http.StatusBadRequest, "invalid_image", "image is required")
		return
	}

	if req.Workdir != "" {
		if !filepath.IsAbs(req.Workdir) {
			writeError(ctx, w, http.StatusBadRequest, "invalid_workdir", "workdir must be an absolute path")
			return
		}
	}

	for name := range req.Environment {
		if !envNamePattern.MatchString(name) {
			writeError(ctx, w, http.StatusBadRequest, "invalid_environment", "invalid environment variable name")
			return
		}
	}

	envNames := make([]string, 0, len(req.Environment))
	for name := range req.Environment {
		envNames = append(envNames, name)
	}
	sort.Strings(envNames)

	targetSeen := make(map[string]bool)
	resolvedMounts := make([]resolvedMount, 0, len(req.Mounts))

	for _, mount := range req.Mounts {
		resolved, err := resolveMount(mount, session.Workspace)
		if err != nil {
			writeError(ctx, w, http.StatusBadRequest, "invalid_mount", "invalid mount")
			return
		}

		if targetSeen[resolved.Target] {
			writeError(ctx, w, http.StatusBadRequest, "invalid_mount", "invalid mount")
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

	var cmdArgCount *int
	if len(req.Command) > 0 {
		n := len(req.Command)
		cmdArgCount = &n
	}

	writeAuditWithRequestID(ctx, auditRecord{
		Event:           "run.start",
		SessionID:       session.ID,
		Image:           req.Image,
		CommandArgCount: cmdArgCount,
		Mounts:          mountAudit,
		EnvKeys:         envNames,
	})

	// Create run operation and register it.
	cfg := a.getConfig()
	bufSize := cfg.BuildLogMaxBytes

	op := newRunOperation(session.ID, req.Image, bufSize)
	op.auditCommandArgCount = cmdArgCount
	op.auditMounts = mountAudit
	op.auditEnvKeys = envNames

	if a.OperationRegistry != nil {
		if !a.OperationRegistry.tryCreate(op) {
			writeError(ctx, w, http.StatusServiceUnavailable, "shutting_down", "daemon is shutting down")
			return
		}
		a.OperationRegistry.cleanup(cfg.OperationRetentionTTL, cfg.OperationMaxCompleted)
	}

	// Build docker run command.
	args := []string{
		"run",
		"--rm",
		"--security-opt", "label=disable",
		"--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
	}

	if req.Entrypoint != "" {
		args = append(args, "--entrypoint", req.Entrypoint)
	}

	if req.Workdir != "" {
		args = append(args, "--workdir", req.Workdir)
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

	cmdCtx, cancel := context.WithCancel(context.Background())

	cmd := a.newRunCmd(cmdCtx, "docker", args...)

	// Assign LogBuffer directly to stdout/stderr for thread-safe capture.
	cmd.Stdout = op.LogBuffer
	cmd.Stderr = op.LogBuffer

	// Start the process under op.mu so terminateAll can synchronize:
	// either we start the process (started=true), or terminateAll marks
	// it as terminated. There is no intermediate state.
	op.mu.Lock()
	if op.terminated {
		op.mu.Unlock()
		cancel()
		msg := "run cancelled: daemon is shutting down"
		op.fail("docker_run_failed", msg, nil)
		writeJSONRaw(ctx, w, http.StatusCreated, map[string]any{
			"ok":           true,
			"operation_id": op.ID,
			"status":       op.State,
		})
		return
	}
	startTime := time.Now()
	op.StartedAt = &startTime
	op.cmd = cmd

	// cmd.Start() is called while holding op.mu so terminateAll cannot
	// race between checking started and setting terminated.
	err := cmd.Start()
	op.started = err == nil
	op.mu.Unlock()

	if err != nil {
		cancel()
		msg := fmt.Sprintf("cannot start run: %v", err)
		op.fail("docker_run_failed", msg, nil)
		writeJSONRaw(ctx, w, http.StatusCreated, map[string]any{
			"ok":           true,
			"operation_id": op.ID,
			"status":       op.State,
		})
		return
	}

	// Start goroutine for process completion.
	go func() {
		defer cancel()
		a.waitRunCompletion(op, startTime)
	}()

	writeJSONRaw(ctx, w, http.StatusCreated, map[string]any{
		"ok":           true,
		"operation_id": op.ID,
		"status":       operationRunning,
	})
}

// newRunCmd creates a new exec.Cmd for run operations.
// It uses ExecCommandContext if set (test seam), otherwise default.
func (a *App) newRunCmd(ctx context.Context, name string, args ...string) *exec.Cmd {
	if a.ExecCommandContext != nil {
		return a.ExecCommandContext(ctx, name, args...)
	}
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd
}

// waitRunCompletion waits for the run process to finish and transitions
// the operation to succeeded or failed. It is the single owner of cmd.Wait().
func (a *App) waitRunCompletion(op *operation, started time.Time) {
	err := op.cmd.Wait()
	duration := time.Since(started).Round(time.Millisecond).String()

	exitCode := extractExitCode(err)

	if err != nil {
		resultCode := "docker_run_failed"
		if exitCode != nil && *exitCode != 125 {
			resultCode = "container_exit_nonzero"
		}
		op.fail(resultCode, "docker run failed", exitCode, &duration)
		return
	}

	op.succeed(&duration)
}
