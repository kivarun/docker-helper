package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
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

// readContainerIDFromCidfile reads the container ID from a Docker --cidfile.
// Returns empty string if the file doesn't exist, is empty, or is malformed.
func readContainerIDFromCidfile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	id := strings.TrimSpace(string(data))
	if id == "" {
		return ""
	}
	return id
}

// waitForContainerID polls the cidfile until the container ID appears or the
// context expires. This handles the race where Docker daemon publishes the
// container ID asynchronously after cmd.Start().
// Returns empty string if the context expires before the ID is available.
func waitForContainerID(ctx context.Context, op *operation) string {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			// Context expired; try one final read before giving up.
			return readContainerIDFromCidfile(op.cidfile)
		case <-op.done:
			// Operation completed while we were waiting — no cleanup needed.
			return ""
		case <-ticker.C:
			if id := readContainerIDFromCidfile(op.cidfile); id != "" {
				return id
			}
		}
	}
}

// killContainerBestEffort attempts to kill a Docker container by ID.
// This is a bounded, best-effort operation used during force shutdown.
// If the container is already gone or the command fails, the error is
// logged but not propagated — "container already gone" is a success.
func (a *App) killContainerBestEffort(ctx context.Context, containerID string) {
	cmd := exec.CommandContext(ctx, "docker", "kill", containerID)
	if err := cmd.Run(); err != nil {
		// Container already gone or docker not available — acceptable.
		// Do not log the container ID to avoid unnecessary traceability.
		slog.Warn("daemon-side container cleanup failed", "error", err)
	}
}

// cleanupCidfile removes the cidfile for a run operation.
// This is called when the operation fails before the process starts
// or when the process completes normally.
func cleanupCidfile(op *operation) {
	if op.cidfile != "" {
		os.Remove(op.cidfile)
	}
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

	// Create run operation and register it.
	cfg := a.getConfig()
	bufSize := cfg.BuildLogMaxBytes

	op := newRunOperation(session.ID, req.Image, bufSize)
	op.auditCommandArgCount = cmdArgCount
	op.auditMounts = mountAudit
	op.auditEnvKeys = envNames

	// Create a unique cidfile for daemon-side container lifecycle management.
	// The path is in the helper-owned runtime directory, never user-controlled.
	if cfg.RuntimeDir != "" {
		op.cidfile = filepath.Join(cfg.RuntimeDir, op.ID+".cid")
	}

	if a.OperationRegistry != nil {
		if !a.OperationRegistry.tryCreate(op) {
			writeError(ctx, w, http.StatusServiceUnavailable, "shutting_down", "daemon is shutting down")
			return
		}
		a.OperationRegistry.cleanup(cfg.OperationRetentionTTL, cfg.OperationMaxCompleted)
	}

	writeAuditWithRequestID(ctx, auditRecord{
		Event:           "run.start",
		SessionID:       session.ID,
		OperationID:     op.ID,
		Image:           req.Image,
		CommandArgCount: cmdArgCount,
		Mounts:          mountAudit,
		EnvKeys:         envNames,
	})

	// Build docker run command.
	args := []string{
		"run",
		"--rm",
		"--security-opt", "label=disable",
		"--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
	}

	if op.cidfile != "" {
		args = append(args, "--cidfile", op.cidfile)
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

	result := startOperationProcess(cmd, op, cancel, func() {
		cleanupCidfile(op)
	}, func(err error) {
		cleanupCidfile(op)
		msg := fmt.Sprintf("cannot start run: %v", err)
		op.fail("docker_run_failed", msg, nil)
		writeJSONRaw(ctx, w, http.StatusCreated, map[string]any{
			"ok":           true,
			"operation_id": op.ID,
			"status":       op.State,
		})
	})

	if result.Terminated {
		msg := "run cancelled: daemon is shutting down"
		op.fail("docker_run_failed", msg, nil)
		writeJSONRaw(ctx, w, http.StatusCreated, map[string]any{
			"ok":           true,
			"operation_id": op.ID,
			"status":       op.State,
		})
		return
	}
	if !result.Started {
		return
	}

	// Start goroutine for process completion.
	go func() {
		defer cancel()
		a.waitRunCompletion(op, *op.StartedAt)
	}()

	writeJSONRaw(ctx, w, http.StatusCreated, map[string]any{
		"ok":           true,
		"operation_id": op.ID,
		"status":       operationRunning,
	})
}

// newOperationCmd creates a new exec.Cmd for operation processes.
// It uses ExecCommandContext if set (test seam), otherwise default.
func (a *App) newOperationCmd(ctx context.Context, name string, args ...string) *exec.Cmd {
	if a.ExecCommandContext != nil {
		return a.ExecCommandContext(ctx, name, args...)
	}
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd
}

// newRunCmd is an alias for newOperationCmd for run operations.
func (a *App) newRunCmd(ctx context.Context, name string, args ...string) *exec.Cmd {
	return a.newOperationCmd(ctx, name, args...)
}

// waitRunCompletion waits for the run process to finish and transitions
// the operation to succeeded or failed. It is the single owner of cmd.Wait().
func (a *App) waitRunCompletion(op *operation, started time.Time) {
	err := op.cmd.Wait()

	// Clean up the cidfile regardless of outcome.
	// The container is already handled by --rm (normal exit) or
	// daemon-side kill (force shutdown), so the cidfile is no longer needed.
	cleanupCidfile(op)

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
