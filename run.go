package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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

// helperSocketContainerDir is the fixed in-container mount target of the
// server-owned helper runtime projection. The workload reaches the existing
// helper Unix socket through it. The bind source is always the daemon's own
// runtime directory; the client selects only the boolean capability.
const helperSocketContainerDir = "/run/docker-helper"

// isHelperSocketMountOverlap reports whether a user mount target overlaps
// the server-owned helper runtime projection: an exact match with the
// injected mount point, a descendant of it, or one of its ancestors. A
// caller-owned mount must not be able to shadow, replace, or partially
// cover the projection. Applied only when helper_socket is requested.
func isHelperSocketMountOverlap(target string) bool {
	return pathOverlap(filepath.Clean(target), helperSocketContainerDir) != pathDisjoint
}

type resolvedMount struct {
	SourcePath string
	Target     string
	ReadOnly   bool
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

	if !pathWithin(workspace, sourcePath) {
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
		SourcePath: sourcePath,
		Target:     cleaned,
		ReadOnly:   mount.ReadOnly,
	}, nil
}

// generateRunRequestID returns a fresh path-safe identifier for one
// synchronous run request. A synchronous run has no operation identity; the
// identifier scopes only the helper-owned request state the run creates —
// the inode-pinned mount staging directories — and is never public.
func generateRunRequestID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("cannot generate run request ID: %v", err))
	}
	return "run_" + hex.EncodeToString(b)
}

// runAuditBase returns the attribution and metadata fields shared by the
// run.start and run.finish audit records. Env keys are names only; mounts
// are the caller mounts as the caller mounted them; the injected
// helper-socket projection appears only as the helper_socket capability
// fact, never as a caller mount.
func runAuditBase(session *Session, req runRequest, envNames []string, mountAudit []auditMount, auditShmSize string, trustedCAInjected, helperSocket bool, cmdArgCount *int) auditRecord {
	return auditRecord{
		SessionID:         session.ID,
		Image:             req.Image,
		CommandArgCount:   cmdArgCount,
		Mounts:            mountAudit,
		EnvKeys:           envNames,
		ShmSize:           auditShmSize,
		TrustedCAInjected: trustedCAInjected,
		HelperSocket:      helperSocket,
		PrincipalName:     session.PrincipalName,
		LauncherID:        session.LauncherID,
		LauncherName:      session.LauncherName,
	}
}

func (a *App) handleRun(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSessionCapability(w, r)
	if !ok {
		return
	}

	ctx := withSessionID(r.Context(), session.ID)

	var req runRequest

	if err := decodeJSONRequest(w, r, &req); err != nil {
		writeDockerActionRejected(ctx, w, http.StatusBadRequest, "run", "invalid_json", "invalid JSON request", session.PrincipalName)
		return
	}

	if req.Image == "" {
		writeDockerActionRejected(ctx, w, http.StatusBadRequest, "run", "invalid_image", "image is required", session.PrincipalName)
		return
	}

	if strings.HasPrefix(req.Image, "-") {
		writeDockerActionRejected(ctx, w, http.StatusBadRequest, "run", "invalid_image", "image must not start with '-'", session.PrincipalName)
		return
	}

	if req.Workdir != "" {
		if !filepath.IsAbs(req.Workdir) {
			writeDockerActionRejected(ctx, w, http.StatusBadRequest, "run", "invalid_workdir", "workdir must be an absolute path", session.PrincipalName)
			return
		}
	}

	for name := range req.Environment {
		if !envNamePattern.MatchString(name) {
			writeDockerActionRejected(ctx, w, http.StatusBadRequest, "run", "invalid_environment", "invalid environment variable name", session.PrincipalName)
			return
		}
	}

	shmSizeBytes, err := validateShmSize(req.ShmSize)
	if err != nil {
		writeDockerActionRejected(ctx, w, http.StatusBadRequest, "run", "invalid_shm_size", "invalid shm size", session.PrincipalName)
		return
	}

	envNames := make([]string, 0, len(req.Environment))
	for name := range req.Environment {
		envNames = append(envNames, name)
	}
	sort.Strings(envNames)

	// Get config for deployment mode and trusted CA injection.
	cfg := a.getConfig()

	// helper_socket is a system-mode server-owned capability. User mode
	// fails closed before any lease, pin, or Engine container creation.
	if req.HelperSocket && cfg.Mode != ModeSystem {
		writeDockerActionRejected(ctx, w, http.StatusBadRequest, "run", "invalid_helper_socket", "helper_socket is not supported in user mode", session.PrincipalName)
		return
	}

	// Acquire workspace-use lease BEFORE any filesystem access that depends
	// on workspace MAC coverage. This reserves MAC state through pre-run work.
	var leaseRelease func()
	if a.MACCoordinator != nil {
		var leaseErr error
		_, leaseRelease, leaseErr = a.MACCoordinator.AcquireWorkspaceUse(session.ID, session.Workspace)
		if leaseErr != nil {
			opLog(ctx).Error("cannot acquire workspace-use lease",
				slog.String("operation", "run"),
				slog.String("error", leaseErr.Error()),
			)
			writeDockerActionRejected(ctx, w, http.StatusInternalServerError, "run", "internal_error", "internal server error", session.PrincipalName)
			return
		}
	}

	targetSeen := make(map[string]bool)
	resolvedMounts := make([]resolvedMount, 0, len(req.Mounts))

	for _, mount := range req.Mounts {
		resolved, err := resolveMount(mount, session.Workspace)
		if err != nil {
			if leaseRelease != nil {
				leaseRelease()
			}
			writeDockerActionRejected(ctx, w, http.StatusBadRequest, "run", "invalid_mount", "invalid mount", session.PrincipalName)
			return
		}

		if cfg.Mode == ModeUser && resolved.SourcePath != session.Workspace {
			if leaseRelease != nil {
				leaseRelease()
			}
			writeDockerActionRejected(ctx, w, http.StatusBadRequest, "run", "invalid_mount", "invalid mount", session.PrincipalName)
			return
		}

		if targetSeen[resolved.Target] {
			if leaseRelease != nil {
				leaseRelease()
			}
			writeDockerActionRejected(ctx, w, http.StatusBadRequest, "run", "invalid_mount", "invalid mount", session.PrincipalName)
			return
		}
		targetSeen[resolved.Target] = true

		resolvedMounts = append(resolvedMounts, *resolved)
	}

	// Check for trusted CA mount overlap when injection is active.
	if cfg.TrustedCAInjection == "auto" {
		for _, m := range req.Mounts {
			if isTrustedCAMountOverlap(m.Target) {
				if leaseRelease != nil {
					leaseRelease()
				}
				writeDockerActionRejected(ctx, w, http.StatusBadRequest, "run", "invalid_mount", "invalid mount", session.PrincipalName)
				return
			}
		}
	}

	// When the helper runtime projection is active, caller-owned mounts
	// may not overlap the server-owned projection: exact target, ancestor,
	// or descendant.
	if req.HelperSocket {
		for _, m := range req.Mounts {
			if isHelperSocketMountOverlap(m.Target) {
				if leaseRelease != nil {
					leaseRelease()
				}
				writeDockerActionRejected(ctx, w, http.StatusBadRequest, "run", "invalid_mount", "invalid mount", session.PrincipalName)
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

	// Audit env keys are only the user-provided ones (already sorted above).

	// Resolve the stored Session credential for the image's registry just
	// in time, from the one protected credential store. It is used only if
	// the requested image is absent and an implicit pull is required,
	// exactly as the docker CLI run path resolved it. A reference with no
	// registry or no stored credential pulls unauthenticated; a store read
	// failure is operational.
	credential, _, err := resolveSessionRegistryCredential(cfg.RuntimeDir, session.ID, req.Image)
	if err != nil {
		if leaseRelease != nil {
			leaseRelease()
		}
		opLog(ctx).Error("cannot read session registry credential",
			slog.String("operation", "run"),
			slog.String("error", err.Error()),
		)
		writeDockerActionRejected(ctx, w, http.StatusInternalServerError, "run", "internal_error", "internal server error", session.PrincipalName)
		return
	}

	// Resolve execution identity before admitting the request.
	// Failure here means nothing is admitted and the Engine is not called.
	execUID, execGID, err := resolveSessionExecutionIdentity(a.DB, session)
	if err != nil {
		if leaseRelease != nil {
			leaseRelease()
		}
		opLog(ctx).Error("cannot resolve session execution identity",
			slog.String("operation", "run"),
			slog.String("error", err.Error()),
		)
		writeDockerActionRejected(ctx, w, http.StatusInternalServerError, "run", "internal_error", "internal server error", session.PrincipalName)
		return
	}

	// In system mode, determine the MAC backend before admission and pin
	// creation. A detection failure or unsupported configuration must fail
	// closed.
	securityOpt := ""
	if cfg.Mode == ModeSystem {
		backend, err := detectLSM()
		if err != nil {
			if leaseRelease != nil {
				leaseRelease()
			}
			opLog(ctx).Error("cannot determine MAC backend",
				slog.String("operation", "run"),
				slog.String("error", err.Error()),
			)
			writeDockerActionRejected(ctx, w, http.StatusInternalServerError, "run", "internal_error", "internal server error", session.PrincipalName)
			return
		}
		switch backend {
		case LSMSELinux:
			securityOpt = "label=type:docker_helper_container_t"
		case LSMAppArmor:
			securityOpt = "label=disable"
		default:
			// LSMNone: no supported MAC backend active — fail closed.
			if leaseRelease != nil {
				leaseRelease()
			}
			opLog(ctx).Error("no MAC backend active for system mode",
				slog.String("operation", "run"),
				slog.String("backend", string(backend)),
			)
			writeDockerActionRejected(ctx, w, http.StatusInternalServerError, "run", "internal_error", "internal server error", session.PrincipalName)
			return
		}
	} else {
		// User mode: disable SELinux labels (existing behavior)
		securityOpt = "label=disable"
	}

	// Synchronous Engine runs are admitted through the coordinator with the
	// run's Launcher admission state: daemon-shutdown refusal,
	// Launcher-quiesce refusal, request-context cancellation, and bounded
	// shutdown termination are its contract. A synchronous run has no
	// operation identity.
	engineCtx, syncReq, decision := a.SyncExecutionCoordinator.admitLauncherScoped(ctx, session.LauncherID, a.OperationSupervisor.launcherQuiesced)
	if decision != admissionAccepted {
		if leaseRelease != nil {
			leaseRelease()
		}
		if decision == admissionRefusedShutdown {
			writeDockerActionRejected(ctx, w, http.StatusServiceUnavailable, "run", "shutting_down", "daemon is shutting down", session.PrincipalName)
		} else {
			writeDockerActionRejected(ctx, w, http.StatusUnprocessableEntity, "run", "launcher_unavailable", "launcher is not available", session.PrincipalName)
		}
		return
	}
	defer syncReq.end()

	// In system mode, pin each mount source to a helper-owned destination.
	// In user mode, use the resolved host paths directly. From here the
	// request owns the pin cleanup — on success, failure, cancellation, and
	// shutdown alike — and releases the workspace-use lease only when the
	// workspace-dependent cleanup completed.
	runID := generateRunRequestID()
	pinnedMounts := make([]*pinnedMount, 0, len(resolvedMounts))
	if cfg.Mode == ModeSystem {
		for i, m := range resolvedMounts {
			pm, err := a.pinWorkspaceMountSource(session.Workspace, m.SourcePath, cfg.RuntimeDir, runID, i)
			if err != nil {
				cleanupPinnedMountList(pinnedMounts)
				if leaseRelease != nil {
					leaseRelease()
				}
				opLog(ctx).Error("cannot pin mount source",
					slog.String("operation", "run"),
					slog.String("session_id", session.ID),
					slog.String("error", err.Error()),
				)
				writeDockerActionRejected(engineCtx, w, http.StatusInternalServerError, "run", "internal_error", "internal server error", session.PrincipalName)
				return
			}
			pinnedMounts = append(pinnedMounts, pm)
		}
	}
	defer func() {
		cleanupErr := cleanupPinnedMountList(pinnedMounts)
		if cleanupErr != nil {
			opLog(ctx).Error("pinned mount cleanup failed — MAC lease intentionally retained because workspace-dependent cleanup did not complete",
				slog.String("operation", "run"),
				slog.String("session_id", session.ID),
				slog.String("error", cleanupErr.Error()),
			)
			return
		}
		if leaseRelease != nil {
			leaseRelease()
		}
	}()

	auditShmSize := ""
	if shmSizeBytes > 0 {
		auditShmSize = req.ShmSize
	}
	helperSocket := req.HelperSocket && cfg.Mode == ModeSystem

	writeRequestContextAudit(ctx, func() auditRecord {
		rec := runAuditBase(session, req, envNames, mountAudit, auditShmSize, trustedCAInjected, helperSocket, cmdArgCount)
		rec.Event = "run.start"
		return rec
	}())

	// Build the trusted Engine run spec from the already-resolved values.
	// The adapter owns only Engine protocol mechanics; no policy decision
	// is made here or inside it.
	engineMounts := make([]engineRunMount, 0, len(resolvedMounts)+2)

	// Trusted CA injection mount (not included in user mounts audit).
	if trustedCAInjected {
		engineMounts = append(engineMounts, engineRunMount{
			Source:   cfg.TrustedCAPreparedDir,
			Target:   trustedCAContainerDir,
			ReadOnly: true,
		})
	}

	// The server-owned helper runtime projection (not included in user
	// mounts audit): a read-only bind of the daemon's own runtime directory
	// at the fixed container target, giving the workload transport
	// reachability to the existing helper Unix socket.
	if helperSocket {
		engineMounts = append(engineMounts, engineRunMount{
			Source:   cfg.RuntimeDir,
			Target:   helperSocketContainerDir,
			ReadOnly: true,
		})
	}

	// User mounts: pinned paths in system mode, resolved paths in user mode.
	for i, m := range resolvedMounts {
		source := m.SourcePath
		if cfg.Mode == ModeSystem {
			source = pinnedMounts[i].PinnedPath
		}
		engineMounts = append(engineMounts, engineRunMount{
			Source:   source,
			Target:   m.Target,
			ReadOnly: m.ReadOnly,
		})
	}

	spec := engineRunSpec{
		Image:       req.Image,
		Entrypoint:  req.Entrypoint,
		Command:     req.Command,
		Workdir:     req.Workdir,
		Env:         allEnv,
		User:        fmt.Sprintf("%d:%d", execUID, execGID),
		SecurityOpt: []string{securityOpt},
		Labels:      runtimeLabelsFor(session),
		Mounts:      engineMounts,
		ShmSize:     shmSizeBytes,
		Credential:  credential,
	}

	started := time.Now()
	runner, err := a.newEngineContainerRunner()
	if err != nil {
		opLog(ctx).Error("cannot construct docker engine adapter",
			slog.String("operation", "run"),
		)
		duration := time.Since(started).Round(time.Millisecond).String()
		finishAudit := runAuditBase(session, req, envNames, mountAudit, auditShmSize, trustedCAInjected, helperSocket, cmdArgCount)
		finishAudit.Event = "run.finish"
		finishAudit.Result = "docker_run_failed"
		writeRequestContextAudit(ctx, finishAudit)
		writeJSONRaw(engineCtx, w, http.StatusInternalServerError, runResponse{
			OK:       false,
			Code:     "docker_run_failed",
			Message:  "docker run failed",
			Duration: duration,
		})
		return
	}

	result, runErr := runner.containerRun(engineCtx, spec, cfg.OperationLogMaxBytes)
	duration := time.Since(started).Round(time.Millisecond).String()

	var exitCode *int
	if runErr == nil {
		code := result.ExitCode
		exitCode = &code
	}

	finishAudit := runAuditBase(session, req, envNames, mountAudit, auditShmSize, trustedCAInjected, helperSocket, cmdArgCount)
	finishAudit.Event = "run.finish"
	finishAudit.Duration = duration

	if runErr == nil && result.ExitCode == 0 {
		finishAudit.Result = "succeeded"
		writeRequestContextAudit(ctx, finishAudit)
		writeJSONRaw(engineCtx, w, http.StatusOK, runResponse{
			OK:        true,
			Output:    result.Output,
			Truncated: result.Truncated,
			Duration:  duration,
			ExitCode:  exitCode,
		})
		return
	}

	if runErr == nil {
		// A non-zero container exit is a workload result, not a backend
		// protocol failure.
		finishAudit.Result = "container_exit_nonzero"
		finishAudit.ExitCode = exitCode
		writeRequestContextAudit(ctx, finishAudit)
		writeJSONRaw(engineCtx, w, http.StatusOK, runResponse{
			OK:        false,
			Code:      "container_exit_nonzero",
			Message:   "container exited with a non-zero code",
			Output:    result.Output,
			Truncated: result.Truncated,
			Duration:  duration,
			ExitCode:  exitCode,
		})
		return
	}

	var engErr *engineError
	if !errors.As(runErr, &engErr) {
		engErr = &engineError{kind: engineErrBackendFailure, cause: runErr}
	}

	auditResult := "docker_run_failed"
	if engErr.kind == engineErrClientCancelled {
		auditResult = "cancelled"
		// A cancelled run produces no trustworthy exit code.
		exitCode = nil
	}
	finishAudit.Result = auditResult
	finishAudit.ExitCode = exitCode
	if engErr.kind != engineErrClientCancelled {
		// Operational logs record only the normalized category. Raw
		// Engine payloads and workload output stay behind the adapter
		// boundary and never reach journald.
		opLog(ctx).Error("run failed",
			slog.String("operation", "run"),
			slog.Int("engine_error_kind", int(engErr.kind)),
		)
	}
	writeRequestContextAudit(ctx, finishAudit)
	writeRunEngineFailure(engineCtx, w, engErr, result, duration)
}

// writeRunEngineFailure maps a normalized Engine run failure to the accepted
// synchronous run failure contract. The response never carries credentials,
// raw Engine payloads, or workload output beyond the bounded capture; a
// cancelled run produces no trustworthy result, exactly as the killed docker
// CLI did.
func writeRunEngineFailure(ctx context.Context, w http.ResponseWriter, engErr *engineError, result engineRunResult, duration string) {
	switch engErr.kind {
	case engineErrImageNotFound:
		writeJSONRaw(ctx, w, http.StatusNotFound, runResponse{
			OK:        false,
			Code:      "image_not_found",
			Message:   "image not found",
			Output:    result.Output,
			Truncated: result.Truncated,
			Duration:  duration,
		})
	case engineErrRegistryAuthDenied:
		writeJSONRaw(ctx, w, http.StatusUnprocessableEntity, runResponse{
			OK:        false,
			Code:      "registry_auth_denied",
			Message:   "registry authentication denied",
			Output:    result.Output,
			Truncated: result.Truncated,
			Duration:  duration,
		})
	case engineErrRegistryUnavailable:
		writeJSONRaw(ctx, w, http.StatusBadGateway, runResponse{
			OK:        false,
			Code:      "registry_unavailable",
			Message:   "registry unreachable or backend failure",
			Output:    result.Output,
			Truncated: result.Truncated,
			Duration:  duration,
		})
	case engineErrBackendUnavailable:
		writeJSONRaw(ctx, w, http.StatusServiceUnavailable, runResponse{
			OK:        false,
			Code:      "backend_unavailable",
			Message:   "docker engine unavailable",
			Output:    result.Output,
			Truncated: result.Truncated,
			Duration:  duration,
		})
	case engineErrBackendFailure:
		writeJSONRaw(ctx, w, http.StatusBadGateway, runResponse{
			OK:        false,
			Code:      "backend_failure",
			Message:   "unexpected docker engine failure",
			Output:    result.Output,
			Truncated: result.Truncated,
			Duration:  duration,
		})
	default:
		writeJSONRaw(ctx, w, http.StatusInternalServerError, runResponse{
			OK:        false,
			Code:      "docker_run_failed",
			Message:   "docker run failed",
			Output:    result.Output,
			Truncated: result.Truncated,
			Duration:  duration,
		})
	}
}

// newDockerCommand creates a new exec.Cmd for a Docker command.
// It uses ExecCommandContext if set (test seam), otherwise default.
func (a *App) newDockerCommand(ctx context.Context, name string, args ...string) *exec.Cmd {
	if a.ExecCommandContext != nil {
		return a.ExecCommandContext(ctx, name, args...)
	}
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd
}

// cleanupPinnedMountList cleans up pinned mounts in reverse order. It is
// concurrency-safe via pinnedMount.Cleanup().
func cleanupPinnedMountList(pinnedMounts []*pinnedMount) error {
	var errs []error
	for i := len(pinnedMounts) - 1; i >= 0; i-- {
		if err := pinnedMounts[i].Cleanup(); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("cleanup: %v", errs)
	}
	return nil
}
