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
		writeOperationRejected(ctx, w, http.StatusBadRequest, "run", "invalid_json", "invalid JSON request", session.PrincipalName)
		return
	}

	if req.Image == "" {
		writeOperationRejected(ctx, w, http.StatusBadRequest, "run", "invalid_image", "image is required", session.PrincipalName)
		return
	}

	if strings.HasPrefix(req.Image, "-") {
		writeOperationRejected(ctx, w, http.StatusBadRequest, "run", "invalid_image", "image must not start with '-'", session.PrincipalName)
		return
	}

	if req.Workdir != "" {
		if !filepath.IsAbs(req.Workdir) {
			writeOperationRejected(ctx, w, http.StatusBadRequest, "run", "invalid_workdir", "workdir must be an absolute path", session.PrincipalName)
			return
		}
	}

	for name := range req.Environment {
		if !envNamePattern.MatchString(name) {
			writeOperationRejected(ctx, w, http.StatusBadRequest, "run", "invalid_environment", "invalid environment variable name", session.PrincipalName)
			return
		}
	}

	shmSizeBytes, err := validateShmSize(req.ShmSize)
	if err != nil {
		writeOperationRejected(ctx, w, http.StatusBadRequest, "run", "invalid_shm_size", "invalid shm size", session.PrincipalName)
		return
	}

	envNames := make([]string, 0, len(req.Environment))
	for name := range req.Environment {
		envNames = append(envNames, name)
	}
	sort.Strings(envNames)

	// Get config for deployment mode and trusted CA injection.
	cfg := a.getConfig()

	targetSeen := make(map[string]bool)
	resolvedMounts := make([]resolvedMount, 0, len(req.Mounts))

	for _, mount := range req.Mounts {
		resolved, err := resolveMount(mount, session.Workspace)
		if err != nil {
			writeOperationRejected(ctx, w, http.StatusBadRequest, "run", "invalid_mount", "invalid mount", session.PrincipalName)
			return
		}

		if cfg.Mode == ModeUser && resolved.HostPath != session.Workspace {
			writeOperationRejected(ctx, w, http.StatusBadRequest, "run", "invalid_mount", "invalid mount", session.PrincipalName)
			return
		}

		if targetSeen[resolved.Target] {
			writeOperationRejected(ctx, w, http.StatusBadRequest, "run", "invalid_mount", "invalid mount", session.PrincipalName)
			return
		}
		targetSeen[resolved.Target] = true

		resolvedMounts = append(resolvedMounts, *resolved)
	}

	// Check for trusted CA mount overlap when injection is active.
	if cfg.TrustedCAInjection == "auto" {
		for _, m := range req.Mounts {
			if isTrustedCAMountOverlap(m.Target) {
				writeOperationRejected(ctx, w, http.StatusBadRequest, "run", "invalid_mount", "invalid mount", session.PrincipalName)
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

	// Resolve execution identity before registering the operation.
	// Failure here means no operation is created and docker is not called.
	execUID, execGID, err := resolveSessionExecutionIdentity(a.DB, session)
	if err != nil {
		opLog(ctx).Error("cannot resolve session execution identity",
			slog.String("operation", "run"),
			slog.String("error", err.Error()),
		)
		writeOperationRejected(ctx, w, http.StatusInternalServerError, "run", "internal_error", "internal server error", session.PrincipalName)
		return
	}

	// Ensure the session Docker config directory exists before registering
	// the operation so that a failure here does not leave a zombie operation.
	dockerDir, err := ensureSessionDockerDir(cfg.RuntimeDir, session.ID)
	if err != nil {
		opLog(ctx).Error("cannot create session Docker directory",
			slog.String("operation", "run"),
			slog.String("error", err.Error()),
		)
		writeOperationRejected(ctx, w, http.StatusInternalServerError, "run", "internal_error", "internal server error", session.PrincipalName)
		return
	}

	// In system mode, determine the MAC backend before pin creation,
	// operation registration, and run.start audit.
	// Note: ensureSessionDockerDir() above is a filesystem side effect
	// that occurs before detection; it is idempotent and safe to create
	// early. Detection failure still prevents Docker invocation.
	// A detection failure or unsupported configuration must fail closed.
	securityOpt := ""
	if cfg.Mode == ModeSystem {
		backend, err := detectLSM()
		if err != nil {
			opLog(ctx).Error("cannot determine MAC backend",
				slog.String("operation", "run"),
				slog.String("error", err.Error()),
			)
			writeOperationRejected(ctx, w, http.StatusInternalServerError, "run", "internal_error", "internal server error", session.PrincipalName)
			return
		}
		switch backend {
		case LSMSelinux:
			securityOpt = "label=type:docker_helper_container_t"
		case LSMAppArmor:
			securityOpt = "label=disable"
		default:
			// LSMNone: no supported MAC backend active — fail closed.
			opLog(ctx).Error("no MAC backend active for system mode",
				slog.String("operation", "run"),
				slog.String("backend", string(backend)),
			)
			writeOperationRejected(ctx, w, http.StatusInternalServerError, "run", "internal_error", "internal server error", session.PrincipalName)
			return
		}
	} else {
		// User mode: disable SELinux labels (existing behavior)
		securityOpt = "label=disable"
	}

	bufSize := cfg.OperationLogMaxBytes

	// Create run operation and register it.
	op := newRunOperation(session.ID, req.Image, bufSize, session.PrincipalName)
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

	// In system mode, pin each mount source to a helper-owned destination.
	// In user mode, use the resolved host paths directly.
	pinnedMounts := make([]*pinnedMount, 0, len(resolvedMounts))
	if cfg.Mode == ModeSystem {
		for i, m := range resolvedMounts {
			pm, err := a.pinMount(session.Workspace, m.HostPath, cfg.RuntimeDir, op.ID, i)
			if err != nil {
				// Fail closed: do not use original pathname.
				for j := len(pinnedMounts) - 1; j >= 0; j-- {
					if ce := pinnedMounts[j].Cleanup(); ce != nil {
						opLog(ctx).Error("pin cleanup failed",
							slog.String("operation", "run"),
							slog.String("error", ce.Error()),
						)
					}
				}
				opLog(ctx).Error("cannot pin mount source",
					slog.String("operation", "run"),
					slog.String("error", err.Error()),
				)
				writeOperationRejected(ctx, w, http.StatusInternalServerError, "run", "internal_error", "internal server error", session.PrincipalName)
				return
			}
			pinnedMounts = append(pinnedMounts, pm)
		}
	}

	// Store pins in operation before registering so the operation owns them.
	op.pinnedMounts = pinnedMounts

	// Register the operation. Single tryCreate after all pins are created.
	if a.OperationRegistry != nil {
		if !a.OperationRegistry.tryCreate(op) {
			for j := len(pinnedMounts) - 1; j >= 0; j-- {
				if ce := pinnedMounts[j].Cleanup(); ce != nil {
					opLog(ctx).Error("pin cleanup failed",
						slog.String("operation", "run"),
						slog.String("error", ce.Error()),
					)
				}
			}
			writeOperationRejected(ctx, w, http.StatusServiceUnavailable, "run", "shutting_down", "daemon is shutting down", session.PrincipalName)
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
		PrincipalName:     session.PrincipalName,
	})

	// Container security label determined above (before pins/registration/audit).
	args := []string{
		"--config", dockerDir,
		"run",
		"--rm",
		"--user", fmt.Sprintf("%d:%d", execUID, execGID),
		"--security-opt", securityOpt,
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

	// Add user mounts: pinned paths in system mode, resolved paths in user mode.
	for i, m := range resolvedMounts {
		hostPath := m.HostPath
		if cfg.Mode == ModeSystem {
			hostPath = pinnedMounts[i].HostPath
		}
		mountSpec := fmt.Sprintf("type=bind,source=%s,target=%s", hostPath, m.Target)
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
		if ce := cleanupPinnedMounts(op); ce != nil {
			opLog(ctx).Error("pin cleanup failed",
				slog.String("operation", "run"),
				slog.String("error", ce.Error()),
			)
		}
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
		if ce := cleanupPinnedMounts(op); ce != nil {
			opLog(ctx).Error("pin cleanup failed",
				slog.String("operation", "run"),
				slog.String("error", ce.Error()),
			)
		}
		opLog(ctx).Error("cannot start run process",
			slog.String("operation", "run"),
			slog.String("error", result.Err.Error()),
		)
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

	// Clean up pinned mounts after cmd.Wait completes.
	cleanupErr := cleanupPinnedMounts(op)
	if cleanupErr != nil {
		opLog(context.Background()).Error("pinned mount cleanup failed",
			slog.String("operation_id", op.ID),
			slog.String("error", cleanupErr.Error()),
		)
	}

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

// cleanupPinnedMounts cleans up all pinned mounts for an operation in
// reverse order. It is concurrency-safe via pinnedMount.Cleanup().
func cleanupPinnedMounts(op *operation) error {
	var errs []error
	for i := len(op.pinnedMounts) - 1; i >= 0; i-- {
		if err := op.pinnedMounts[i].Cleanup(); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("cleanup: %v", errs)
	}
	return nil
}
