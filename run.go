package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var envNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// maxShmSize is the hard-coded maximum shm_size for Release 1.
// This is an implementation constant, not a configurable value.
const maxShmSize = 2 * 1024 * 1024 * 1024 // 2 GiB

// validateShmSize parses and validates an shm_size string.
// Accepted formats: N (bytes), Nk, Nm, Ng (case-insensitive unit).
// Returns the validated size in bytes, or an error if the value is
// invalid, zero, negative, or exceeds maxShmSize.
func validateShmSize(raw string) (int64, error) {
	if raw == "" {
		return 0, nil
	}

	// Must start with a digit.
	if len(raw) == 0 || raw[0] < '0' || raw[0] > '9' {
		return 0, fmt.Errorf("invalid shm size")
	}

	// Determine the unit suffix (last character, if alphabetic).
	var unit string
	var numStr string
	if len(raw) > 1 && (raw[len(raw)-1] >= 'a' && raw[len(raw)-1] <= 'z' || raw[len(raw)-1] >= 'A' && raw[len(raw)-1] <= 'Z') {
		unit = strings.ToLower(string(raw[len(raw)-1]))
		numStr = raw[:len(raw)-1]
	} else {
		numStr = raw
	}

	// numStr must not be empty.
	if numStr == "" {
		return 0, fmt.Errorf("invalid shm size")
	}

	// Parse the numeric part. Reject anything that isn't a plain integer.
	num, err := strconv.ParseUint(numStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid shm size")
	}

	// Apply the unit multiplier.
	var multiplier uint64
	switch unit {
	case "":
		multiplier = 1
	case "k":
		multiplier = 1024
	case "m":
		multiplier = 1024 * 1024
	case "g":
		multiplier = 1024 * 1024 * 1024
	default:
		return 0, fmt.Errorf("invalid shm size")
	}

	// Check for overflow before multiplication.
	if multiplier > 0 && num > math.MaxUint64/multiplier {
		return 0, fmt.Errorf("invalid shm size")
	}

	total := num * multiplier

	// Must be > 0.
	if total == 0 {
		return 0, fmt.Errorf("invalid shm size")
	}

	// Must not exceed the hard limit.
	if total > maxShmSize {
		return 0, fmt.Errorf("invalid shm size")
	}

	return int64(total), nil
}

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
	cmd := a.newOperationCmd(ctx, "docker", "kill", containerID)
	if err := cmd.Run(); err != nil {
		// Container already gone or docker not available — acceptable.
		// Do not log the container ID to avoid unnecessary traceability.
		opLog(ctx).Warn("daemon-side container cleanup failed",
			slog.String("error", err.Error()),
		)
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

	shmSizeBytes, err := validateShmSize(req.ShmSize)
	if err != nil {
		writeError(ctx, w, http.StatusBadRequest, "invalid_shm_size", "invalid shm size")
		return
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

	// Get config to check trusted CA injection mode.
	cfg := a.getConfig()

	// Check for trusted CA mount overlap when injection is active.
	if cfg.TrustedCAInjection == "auto" {
		for _, m := range req.Mounts {
			if isTrustedCAMountOverlap(m.Target) {
				writeError(ctx, w, http.StatusBadRequest, "invalid_mount", "invalid mount")
				return
			}
		}
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

	// Determine trusted CA injection.
	trustedCAInjected := cfg.TrustedCAInjection == "auto" && cfg.TrustedCAPreparedDir != ""

	// Build environment list: user env + injected CA env (only if not already set).
	allEnv := make(map[string]string)
	for k, v := range req.Environment {
		allEnv[k] = v
	}
	if trustedCAInjected {
		if _, exists := allEnv[trustedCAEnvSSLDir]; !exists {
			allEnv[trustedCAEnvSSLDir] = trustedCAEnvSSLDirValue
		}
		if _, exists := allEnv[trustedCAEnvNodeExtra]; !exists {
			allEnv[trustedCAEnvNodeExtra] = trustedCAEnvNodeExtraValue
		}
	}

	// Sort all environment names for deterministic argv.
	sortedEnvNames := make([]string, 0, len(allEnv))
	for name := range allEnv {
		sortedEnvNames = append(sortedEnvNames, name)
	}
	sort.Strings(sortedEnvNames)

	// Audit env keys are only the user-provided ones (already sorted above).

	// Ensure the session Docker config directory exists before registering
	// the operation so that a failure here does not leave a zombie operation.
	dockerDir, err := ensureSessionDockerDir(cfg.RuntimeDir, session.ID)
	if err != nil {
		opLog(ctx).Error("cannot create session Docker directory",
			slog.String("operation", "run"),
			slog.String("error", err.Error()),
		)
		writeError(ctx, w, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}

	bufSize := cfg.OperationLogMaxBytes

	// Create run operation and register it.
	op := newRunOperation(session.ID, req.Image, bufSize)
	op.auditCommandArgCount = cmdArgCount
	op.auditMounts = mountAudit
	op.auditEnvKeys = envNames
	op.auditTrustedCAInjected = trustedCAInjected
	if shmSizeBytes > 0 {
		op.auditShmSize = req.ShmSize
	}

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
		Event:             "run.start",
		SessionID:         session.ID,
		OperationID:       op.ID,
		Image:             req.Image,
		CommandArgCount:   cmdArgCount,
		Mounts:            mountAudit,
		EnvKeys:           envNames,
		ShmSize:           op.auditShmSize,
		TrustedCAInjected: trustedCAInjected,
	})

	// Build docker run command.
	args := []string{
		"--config", dockerDir,
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

	// Add all environment variables (user + injected CA) in sorted order.
	for _, name := range sortedEnvNames {
		args = append(args, "--env", name+"="+allEnv[name])
	}

	// Add trusted CA injection mount (not included in user mounts audit).
	if trustedCAInjected {
		caMountSpec := fmt.Sprintf("type=bind,source=%s,target=%s,readonly",
			cfg.TrustedCAPreparedDir, trustedCAContainerDir)
		args = append(args, "--mount", caMountSpec)
	}

	for _, m := range resolvedMounts {
		mountSpec := fmt.Sprintf("type=bind,source=%s,target=%s", m.HostPath, m.Target)
		if m.ReadOnly {
			mountSpec += ",readonly"
		}
		args = append(args, "--mount", mountSpec)
	}

	if shmSizeBytes > 0 {
		args = append(args, "--shm-size", strconv.FormatInt(shmSizeBytes, 10))
	}

	args = append(args, req.Image)
	args = append(args, req.Command...)

	cmdCtx, cancel := context.WithCancel(context.Background())

	cmd := a.newOperationCmd(cmdCtx, "docker", args...)

	result := startOperationProcess(cmd, op)

	if result.Terminated {
		cancel()
		cleanupCidfile(op)
		msg := "run cancelled: daemon is shutting down"
		if op.reason == terminationCancelled {
			msg = "run cancelled"
			op.fail(resultCancelled, msg, nil)
		} else {
			op.fail("docker_run_failed", msg, nil)
		}
		writeOperationCreated(ctx, w, op.ID, op.State)
		return
	}
	if result.Err != nil {
		cancel()
		cleanupCidfile(op)
		msg := fmt.Sprintf("cannot start run: %v", result.Err)
		op.fail("docker_run_failed", msg, nil)
		writeOperationCreated(ctx, w, op.ID, op.State)
		return
	}

	// Start goroutine for process completion.
	go func() {
		defer cancel()
		a.waitRunCompletion(op, *op.StartedAt)
	}()

	writeOperationCreated(ctx, w, op.ID, operationRunning)
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

// waitRunCompletion waits for the run process to finish and transitions
// the operation to succeeded or failed. It is the single owner of cmd.Wait().
func (a *App) waitRunCompletion(op *operation, started time.Time) {
	err := op.cmd.Wait()

	// Clean up the cidfile regardless of outcome.
	// The container is already handled by --rm (normal exit) or
	// daemon-side kill (force shutdown), so the cidfile is no longer needed.
	cleanupCidfile(op)

	duration := time.Since(started).Round(time.Millisecond).String()

	op.mu.Lock()
	wasCancelled := op.reason == terminationCancelled
	op.mu.Unlock()

	exitCode := extractExitCode(err)

	if err != nil {
		if wasCancelled {
			op.fail(resultCancelled, "run cancelled", exitCode, &duration)
			return
		}
		resultCode := "docker_run_failed"
		if exitCode != nil && *exitCode != 125 {
			resultCode = "container_exit_nonzero"
		}
		op.fail(resultCode, "docker run failed", exitCode, &duration)
		return
	}

	op.succeed(&duration)
}
