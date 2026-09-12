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

// helperSocketContainerDir is the fixed in-container mount target of the
// server-owned helper runtime projection. The workload reaches the existing
// helper Unix socket through it. The bind source is always the daemon's own
// runtime directory; the client selects only the boolean capability.
const helperSocketContainerDir = "/run/docker-helper"

// helperSocketLocatorEnv is the server-owned socket locator environment
// variable the daemon provides to the workload alongside the helper runtime
// projection. The socket is transport reachability only; the Session bearer
// authority is a separate capability and is never injected (the workload
// receives the credential only when the caller passes it explicitly).
const helperSocketLocatorEnv = "DOCKER_HELPER_SOCKET_PATH"

// helperSocketLocatorEnvValue is the canonical locator value: the fixed
// in-container projection target plus the helper Unix socket file name. A
// caller-supplied locator must match exactly or the request is refused.
const helperSocketLocatorEnvValue = helperSocketContainerDir + "/docker-helper.sock"

// isHelperSocketMountOverlap reports whether a user mount target overlaps
// the server-owned helper runtime projection: an exact match with the
// injected mount point, a descendant of it, or one of its ancestors. A
// caller-owned mount must not be able to shadow, replace, or partially
// cover the projection. Applied only when helper_socket is requested.
func isHelperSocketMountOverlap(target string) bool {
	return pathOverlap(filepath.Clean(target), helperSocketContainerDir) != pathDisjoint
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
	cmd := a.newDockerCommand(ctx, "docker", "kill", containerID)
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
	SourcePath string
	Target     string
	ReadOnly   bool
}

// resolveMount resolves one caller mount request into its canonical mount
// facts. The source grammar is two-form: a relative source is resolved
// against the session workspace (the existing convenience, and a structural
// boundary — the workspace-relative spelling can never reach another issued
// root), and an absolute source is an absolute host path. Both forms
// canonicalize to the same identity rules: the resolved path must exist as a
// directory or regular file, and the canonical resolved path (never the
// caller spelling, which may name a symlink alias) is the only policy
// identity later authorized against the issued Session filesystem snapshot
// by resolveSessionFilesystemExposure.
func resolveMount(mount mountRequest, workspace string) (*resolvedMount, error) {
	if mount.Source == "" {
		return nil, fmt.Errorf("mount source is required")
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

	sourcePath := mount.Source
	if !filepath.IsAbs(sourcePath) {
		joined := filepath.Join(workspace, sourcePath)
		abs, err := filepath.Abs(joined)
		if err != nil {
			return nil, fmt.Errorf("cannot resolve mount source: %w", err)
		}
		sourcePath = abs
	}

	var err error
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

	if !filepath.IsAbs(sourcePath) {
		return nil, fmt.Errorf("mount source is not absolute: %s", mount.Source)
	}

	// The workspace-relative grammar keeps the mount scoped to the session
	// workspace. An absolute source skips this proof: its authority is the
	// issued Session filesystem snapshot alone, proven by the exposure
	// resolution.
	if !filepath.IsAbs(mount.Source) {
		if !pathWithin(workspace, sourcePath) {
			return nil, fmt.Errorf("mount source escapes workspace: %s", mount.Source)
		}
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

func (a *App) handleRun(w http.ResponseWriter, r *http.Request) {
	authority, ok := a.requireSessionFilesystemCapability(w, r, "run")
	if !ok {
		return
	}
	session := authority.Session

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
	// fails closed before any lease, pin, or operation state exists.
	if req.HelperSocket && cfg.Mode != ModeSystem {
		writeDockerActionRejected(ctx, w, http.StatusBadRequest, "run", "invalid_helper_socket", "helper_socket is not supported in user mode", session.PrincipalName)
		return
	}

	// With the helper runtime projection active, the server owns the socket
	// locator: the caller may either omit it or supply exactly the canonical
	// value. A conflicting locator is refused fail-closed before any lease,
	// pin, operation, or Docker state exists; it is never silently
	// overwritten. Without helper_socket the locator is an ordinary caller
	// environment variable with unchanged behavior.
	if req.HelperSocket && cfg.Mode == ModeSystem {
		if v, exists := req.Environment[helperSocketLocatorEnv]; exists && v != helperSocketLocatorEnvValue {
			writeDockerActionRejected(ctx, w, http.StatusBadRequest, "run", "invalid_helper_socket", "helper_socket requires the canonical socket locator", session.PrincipalName)
			return
		}
	}

	// Acquire workspace-use lease BEFORE any filesystem access that depends
	// on workspace MAC coverage. This reserves MAC state through pre-registration work.
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

		// User-mode backend-safety boundary (Release 2.2): user mode has no
		// inode-pinning handoff, so dockerd would consume the bind source
		// through its pathname. Only the canonical workspace root carries the
		// established pathname-stability invariant (the sandbox cannot write
		// its parent, so it cannot replace the workspace directory entry);
		// a relative "." mount, a workspace-root symlink alias, and an
		// absolute spelling resolving exactly to the canonical workspace all
		// canonicalize to that one stable source. Every other source — child
		// or file, relative or absolute, disjoint absolute — is refused as
		// invalid_mount before any pin, operation, or Docker state exists.
		// This is the user-mode source-shape restriction of the same
		// workspace-root-only contract the Session-create filesystem-root
		// boundary enforces; the immutable Session snapshot remains the
		// filesystem access-mode owner.
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

	var cmdArgCount *int
	if len(req.Command) > 0 {
		n := len(req.Command)
		cmdArgCount = &n
	}

	// Resolve the data-plane filesystem exposure of every mount against the
	// persisted immutable Session filesystem snapshot — the filesystem
	// authority issued at Session creation. Policy identity is only the
	// canonical resolved source; the caller spelling (including symlinks)
	// never selects an access mode. Read-only requests are permitted from
	// either access mode; writable requests require the snapshot owner's
	// writable-parent query. A refusal happens before any mount pin,
	// operation, or Docker state exists, and the lease is released.
	exposurePlan := make([]sessionFilesystemExposure, 0, len(resolvedMounts))
	for i, resolved := range resolvedMounts {
		exposure, err := resolveSessionFilesystemExposure(authority.Snapshot, resolved.SourcePath, resolved.Target, resolved.ReadOnly)
		if err != nil {
			if leaseRelease != nil {
				leaseRelease()
			}
			if errors.Is(err, ErrReadOnlyRoot) {
				writeRunReadOnlyRootRejected(ctx, w, session, req.Mounts[i], exposure)
				return
			}
			if errors.Is(err, ErrOutsideSessionSnapshot) {
				// An ordinary caller policy mistake: the source was never
				// issued to this Session. The stable non-disclosing
				// invalid_mount contract answers before any pin,
				// operation, or Docker state exists.
				writeDockerActionRejected(ctx, w, http.StatusBadRequest, "run", "invalid_mount", "invalid mount", session.PrincipalName)
				return
			}
			opLog(ctx).Error("cannot resolve session filesystem exposure",
				slog.String("operation", "run"),
				slog.String("error", err.Error()),
			)
			writeDockerActionRejected(ctx, w, http.StatusInternalServerError, "run", "internal_error", "internal server error", session.PrincipalName)
			return
		}
		exposurePlan = append(exposurePlan, exposure)
	}

	// Audit mounts keep the existing caller fields and project the resolved
	// policy facts (canonical source, effective snapshot access, and the
	// writable-exposure permission — false is meaningful and must survive).
	mountAudit := make([]auditMount, 0, len(exposurePlan))
	for i := range exposurePlan {
		mountAudit = append(mountAudit, auditMount{
			Source:          req.Mounts[i].Source,
			Target:          req.Mounts[i].Target,
			ReadOnly:        req.Mounts[i].ReadOnly,
			ResolvedSource:  exposurePlan[i].SourcePath,
			Access:          string(exposurePlan[i].Access),
			WritableAllowed: &exposurePlan[i].WritableAllowed,
		})
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
	// Server-owned socket locator injection (only when absent): with the
	// helper runtime projection the workload always receives the canonical
	// locator; a caller-supplied identical value is accepted and stays a
	// single argv entry (the map is keyed by name). The injection is
	// server-owned and is not a caller env key, so the audit env keys stay
	// caller-provided only. No Session token is ever injected here.
	if req.HelperSocket && cfg.Mode == ModeSystem {
		if _, exists := allEnv[helperSocketLocatorEnv]; !exists {
			allEnv[helperSocketLocatorEnv] = helperSocketLocatorEnvValue
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

	// Ensure the session Docker config directory exists before registering
	// the operation so that a failure here does not leave a zombie operation.
	dockerDir, err := ensureSessionDockerDir(cfg.RuntimeDir, session.ID)
	if err != nil {
		if leaseRelease != nil {
			leaseRelease()
		}
		opLog(ctx).Error("cannot create session Docker directory",
			slog.String("operation", "run"),
			slog.String("error", err.Error()),
		)
		writeDockerActionRejected(ctx, w, http.StatusInternalServerError, "run", "internal_error", "internal server error", session.PrincipalName)
		return
	}

	// In system mode, the workload MAC coordinator (2.2.6) decides the
	// container security options and materializes the accepted exposure plan
	// through the active backend. A missing coordinator means no supported
	// MAC backend is active — fail closed before any state exists.
	var securityOpts []string
	if cfg.Mode == ModeSystem {
		if a.WorkloadMAC == nil {
			if leaseRelease != nil {
				leaseRelease()
			}
			opLog(ctx).Error("no MAC backend active for system mode",
				slog.String("operation", "run"),
			)
			writeDockerActionRejected(ctx, w, http.StatusInternalServerError, "run", "internal_error", "internal server error", session.PrincipalName)
			return
		}
	} else {
		// User mode: disable SELinux labels (existing behavior).
		securityOpts = []string{"label=disable"}
	}

	bufSize := cfg.OperationLogMaxBytes

	// Create run operation and register it.
	op := newRunOperation(session.ID, req.Image, bufSize, session.PrincipalName, session.LauncherID, session.LauncherName)
	op.auditCommandArgCount = cmdArgCount
	op.auditMounts = mountAudit
	op.auditEnvKeys = envNames
	op.auditTrustedCAInjected = trustedCAInjected
	op.auditHelperSocket = req.HelperSocket && cfg.Mode == ModeSystem
	if cfg.Mode == ModeSystem && a.WorkloadMAC != nil {
		op.auditWorkloadMACBackend = string(a.WorkloadMAC.Backend())
	}
	// Associate the lease with the operation immediately so every failure
	// path — pre-admission rollback included — releases it through the one
	// rollback owner.
	op.macLeaseRelease = leaseRelease
	if shmSizeBytes > 0 {
		op.auditShmSize = req.ShmSize
	}

	// Create a unique cidfile for daemon-side container lifecycle management.
	// The path is in the helper-owned runtime directory, never user-controlled.
	if cfg.RuntimeDir != "" {
		op.cidfile = filepath.Join(cfg.RuntimeDir, op.ID+".cid")
	}

	// In system mode, pin each mount source to a helper-owned destination.
	// In user mode, use the resolved host paths directly. Pins are appended
	// to the operation incrementally so the shared rollback owner sees the
	// exact prepared state on failure.
	pinnedMounts := make([]*pinnedMount, 0, len(resolvedMounts))
	if cfg.Mode == ModeSystem {
		for i, m := range resolvedMounts {
			pm, err := a.pinMountSource(m.SourcePath, cfg.RuntimeDir, op.ID, i)
			if err != nil {
				opLog(ctx).Error("cannot pin mount source",
					slog.String("operation", "run"),
					slog.String("error", err.Error()),
				)
				a.rollbackRunPreparation(ctx, op)
				writeDockerActionRejected(ctx, w, http.StatusInternalServerError, "run", "internal_error", "internal server error", session.PrincipalName)
				return
			}
			op.pinnedMounts = append(op.pinnedMounts, pm)
			pinnedMounts = append(pinnedMounts, pm)
		}
	}

	// Workload MAC materialization (2.2.6, system mode only): after the
	// pins, because the SELinux accepted mechanism projects from the pinned
	// kernel source; before admission and container creation, because no
	// admitted or running workload may exist without validated workload
	// MAC state.
	if cfg.Mode == ModeSystem {
		pinnedSources := make([]string, len(pinnedMounts))
		for i, pm := range pinnedMounts {
			pinnedSources[i] = pm.PinnedPath
		}
		prepared, err := a.WorkloadMAC.Prepare(workloadPreparation{
			OperationID:   op.ID,
			SessionID:     session.ID,
			Exposures:     exposurePlan,
			PinnedSources: pinnedSources,
		})
		if err != nil {
			opLog(ctx).Error("cannot prepare workload MAC state",
				slog.String("operation", "run"),
				slog.String("operation_id", op.ID),
				slog.String("backend", string(a.WorkloadMAC.Backend())),
				slog.String("error", err.Error()),
			)
			var retained *workloadMACRetainedError
			if errors.As(err, &retained) {
				// Partial MAC state could not be rolled back: the pins and
				// the workspace-use lease that the projections depend on
				// must remain until startup reconciliation. No container
				// was started.
				opLog(ctx).Error("workload MAC state retained after prepare failure — dependent pins and workspace lease intentionally retained",
					slog.String("operation", "run"),
					slog.String("operation_id", op.ID),
				)
			} else {
				a.rollbackRunPreparation(ctx, op)
			}
			writeDockerActionRejected(ctx, w, http.StatusInternalServerError, "run", "internal_error", "internal server error", session.PrincipalName)
			return
		}
		op.workloadMAC = prepared
		securityOpts = prepared.SecurityOpts
	}

	// Register the operation. Single admit after pins and MAC preparation.
	if a.OperationSupervisor != nil {
		if decision := a.OperationSupervisor.admit(op); decision != admissionAccepted {
			a.rollbackRunPreparation(ctx, op)
			if decision == admissionRefusedShutdown {
				writeDockerActionRejected(ctx, w, http.StatusServiceUnavailable, "run", "shutting_down", "daemon is shutting down", session.PrincipalName)
			} else {
				writeDockerActionRejected(ctx, w, http.StatusUnprocessableEntity, "run", "launcher_unavailable", "launcher is not available", session.PrincipalName)
			}
			return
		}
		a.OperationSupervisor.pruneCompleted(cfg.OperationRetentionTTL, cfg.OperationMaxCompleted)
	}

	writeRequestContextAudit(ctx, auditRecord{
		Event:              "run.start",
		SessionID:          session.ID,
		OperationID:        op.ID,
		Image:              req.Image,
		CommandArgCount:    cmdArgCount,
		Mounts:             mountAudit,
		EnvKeys:            envNames,
		ShmSize:            op.auditShmSize,
		TrustedCAInjected:  trustedCAInjected,
		HelperSocket:       op.auditHelperSocket,
		WorkloadMACBackend: op.auditWorkloadMACBackend,
		PrincipalName:      session.PrincipalName,
		LauncherID:         session.LauncherID,
		LauncherName:       session.LauncherName,
	})

	// Container security options come from the prepared workload MAC state
	// in system mode and from the fixed user-mode label disable otherwise.
	args := []string{
		"--config", dockerDir,
		"run",
		"--rm",
		"--user", fmt.Sprintf("%d:%d", execUID, execGID),
	}
	for _, opt := range securityOpts {
		args = append(args, "--security-opt", opt)
	}

	// Add the reserved helper-owned runtime labels. Values derive from the
	// resolved Session ownership chain plus the server-generated operation
	// ID, never from caller input.
	for _, l := range runtimeLabelsForRun(session, op.ID) {
		args = append(args, "--label", l)
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

	// Add the server-owned helper runtime projection (not included in user
	// mounts audit): a read-only bind of the daemon's own runtime directory
	// at the fixed container target, giving the workload transport
	// reachability to the existing helper Unix socket.
	if req.HelperSocket && cfg.Mode == ModeSystem {
		args = append(args, "--mount", fmt.Sprintf("type=bind,source=%s,target=%s,readonly",
			cfg.RuntimeDir, helperSocketContainerDir))
	}

	// Add user mounts from the accepted exposure plan: the bind source is
	// the prepared MAC materialization source in system mode (the existing
	// pin, or the helper-owned projection path for a SELinux read-only
	// exposure) and the canonical resolved path in user mode; the readonly
	// flag follows exactly the caller-requested consumption mode, never the
	// snapshot access of the source.
	for i, exposure := range exposurePlan {
		dockerBindSource := exposure.SourcePath
		if cfg.Mode == ModeSystem {
			dockerBindSource = op.workloadMAC.MountSources[i]
		}
		mountSpec := fmt.Sprintf("type=bind,source=%s,target=%s", dockerBindSource, exposure.Target)
		if exposure.RequestedReadOnly {
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

	cmd := a.newDockerCommand(cmdCtx, "docker", args...)

	result := startOperationProcess(cmd, op)

	if result.Terminated {
		cancel()
		// No container exists by construction: the operation was terminated
		// before the process could start. Reverse the prepared resources in
		// ownership order.
		a.rollbackRunPreparation(ctx, op)
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
		a.rollbackRunPreparation(ctx, op)
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

// newDockerCommand creates a new exec.Cmd for a Docker command.
// It uses ExecCommandContext if set (test seam), otherwise default.
func (a *App) newDockerCommand(ctx context.Context, name string, args ...string) *exec.Cmd {
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

	// The Docker CLI process finished. The correlated container is not
	// assumed gone: the single run cleanup owner proves container absence
	// first and then releases workload MAC state, pins, lease, and cidfile
	// in the frozen ownership order. A failed proof retains state for
	// reconciliation instead of weakening confinement.
	a.cleanupAfterRunProcess(op)

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
