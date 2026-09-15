package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
)

// ErrStaleRotation is returned by rotateAdminToken when the authorizing
// token is no longer the current admin token at commit time. This can
// happen when two concurrent rotations race: the first commits, invalidating
// the second's authorizing token.
var ErrStaleRotation = errors.New("stale admin token rotation")

type App struct {
	mu     sync.RWMutex
	Config *Config
	// lifecycleMu serializes ownership-lifecycle control-plane mutations that
	// share admission authority (Launcher create / PATCH rename+enable+disable /
	// scope replace / delete, Principal allowed-root add+remove / enabled
	// transition / delete, config reload) together with Session creation
	// (createSessionAuthorized). Ordinary Session reads/deletion, data-plane
	// (admit / pull / build / run) requests, and read-only ownership queries
	// are excluded, so only lifecycle mutations and session creation contend.
	// It is never acquired recursively; the lifecycle mutators split into
	// lock-owning and *Locked-variant (lock-already-held) helpers.
	lifecycleMu         sync.Mutex
	DB                  *sql.DB
	AdminTokenHash      [sha256.Size]byte
	ExecCommandContext  func(context.Context, string, ...string) *exec.Cmd
	OperationSupervisor *operationSupervisor
	// PinMountSourceFn is a test seam for the inode-pinning primitive.
	// Production default calls the real pinMountSource; tests can return
	// a fake pinnedMount with controlled Cleanup behavior.
	PinMountSourceFn func(sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error)
	// StageBuildContextFn is a test seam for the build context staging primitive.
	// Production default calls the real StageBuildContext; tests can return
	// a fake stagedBuildContext with controlled Cleanup behavior.
	StageBuildContextFn func(ctx context.Context, workspace, contextPath, dockerfileRel, runtimeDir, operationID string) (*stagedBuildContext, error)
	// RotateRenameFn is a test seam for the final atomic rename in
	// rotateAdminToken. Production default is os.Rename; tests can fail it
	// deterministically.
	RotateRenameFn func(oldpath, newpath string) error
	// MACCoordinator is the session MAC coordinator owner.
	// nil in user mode or when no MAC driver is active.
	MACCoordinator *sessionMACCoordinator
	// WorkloadMAC is the workload MAC coordinator owner (2.2.6). It owns
	// operation/container-lifetime workload MAC state, separate from the
	// session MAC coordinator's Session workspace coverage. nil in user
	// mode or when no MAC backend is active.
	WorkloadMAC *workloadMACCoordinator
	// InspectOperationContainers, when set, overrides the Docker-based
	// correlated-run container inspection used by the container-absence
	// proof. It is a narrow test seam; production shells out to the Docker
	// CLI with the reserved label set.
	InspectOperationContainers func(ctx context.Context, operationID, sessionID string) ([]helperContainer, error)
	// InspectHelperContainers, when set, overrides the Docker-based helper
	// container inspection used by checked Launcher/Principal deletion. It is a
	// narrow test seam; production default shells out to the Docker CLI.
	InspectHelperContainers func(ctx context.Context, launcherID string) ([]helperContainer, error)
	// userModeDefault is the user-mode daemon-owner Principal/Launcher resolved
	// at startup by ensureUserModeOwnership. nil in system mode.
	userModeDefault *userModeDefaultLauncher
}

// pinMountSource calls PinMountSourceFn if set, otherwise the
// real pinMountSource.
func (a *App) pinMountSource(sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
	if a.PinMountSourceFn != nil {
		return a.PinMountSourceFn(sourcePath, runtimeDir, operationID, mountIndex)
	}
	return pinMountSource(sourcePath, runtimeDir, operationID, mountIndex)
}

// stageBuildContext calls StageBuildContextFn if set, otherwise the real StageBuildContext.
func (a *App) stageBuildContext(ctx context.Context, workspace, contextPath, dockerfileRel, runtimeDir, operationID string) (*stagedBuildContext, error) {
	if a.StageBuildContextFn != nil {
		return a.StageBuildContextFn(ctx, workspace, contextPath, dockerfileRel, runtimeDir, operationID)
	}
	return StageBuildContext(ctx, workspace, contextPath, dockerfileRel, runtimeDir, operationID)
}

// getConfig returns a snapshot copy of the current configuration under a read lock.
// The caller receives an independent copy that cannot be mutated by setConfig.
func (a *App) getConfig() Config {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return *a.Config
}

// setConfig atomically replaces the configuration pointer.
// Only configurable fields are taken from newCfg; computed paths are preserved
// from the current configuration. Configurable fields: allowed_roots,
// session_ttl, log_level, audit_enabled, shutdown_timeout,
// operation_retention_ttl, operation_max_completed, operation_log_max_bytes.
func (a *App) setConfig(newCfg *Config) {
	a.mu.Lock()
	defer a.mu.Unlock()
	merged := *newCfg
	merged.SocketPath = a.Config.SocketPath
	merged.InstanceLockPath = a.Config.InstanceLockPath
	merged.StateDir = a.Config.StateDir
	merged.RuntimeDir = a.Config.RuntimeDir
	merged.DatabasePath = a.Config.DatabasePath
	merged.AdminTokenPath = a.Config.AdminTokenPath
	a.Config = &merged
}

// adminTokenStagingName is the one fixed staging pathname of the admin-token
// replacement lifecycle, a sibling of the token file. A fixed staging name —
// not a random tempfile — is what the shipped confined policy can express as
// a narrow per-pathname contract: AppArmor grants write/rename access to
// exactly this pathname, and the SELinux policy labels exactly this pathname
// as the token replacement object through an exact filename transition.
// It is an internal implementation pathname, not a config/API/CLI surface.
const adminTokenStagingName = ".admin-token.new"

// rotateAdminToken generates a new admin token, writes it to the token file
// atomically, and updates the in-memory hash. The old token is immediately
// invalidated. Returns the new token (never logged).
//
// The caller must have already authorized with the current admin token.
// The whole replacement lifecycle runs under the existing admin-token hash
// commit lock (a.mu): the authorizing token is verified current BEFORE the
// staging pathname is touched, so a stale concurrent rotation fails without
// touching the winner's state or the staging pathname. The staging file is
// created, written, chmod'd 0600, fsynced, and closed at the fixed staging
// pathname, then atomically renamed onto the token file. Every failure —
// including a failed rename — leaves the current token file and the runtime
// hash unchanged, removes the staging file, and returns an error; crash
// residue at the exact staging pathname is cleaned by the next rotation.
func (a *App) rotateAdminToken(authorizingHash [sha256.Size]byte) (string, error) {
	// Generate a new admin token.
	newToken, err := generateAdminToken()
	if err != nil {
		return "", err
	}
	newHash := sha256.Sum256([]byte(newToken))

	// Resolve the token file and the fixed staging pathname before taking
	// the commit lock. The admin token path is preserved across config
	// reloads, so the snapshot is stable for the whole lifecycle.
	cfg := a.getConfig()
	tokenPath := cfg.AdminTokenPath
	stagingPath := filepath.Join(filepath.Dir(tokenPath), adminTokenStagingName)

	// Commit under the existing rotation/hash lock: verify, stage, replace,
	// update the runtime hash as one serialized lifecycle.
	a.mu.Lock()
	defer a.mu.Unlock()

	// Verify the authorizing token is still the current one BEFORE touching
	// the staging pathname: a stale concurrent rotation commits nothing and
	// must not observe or mutate the winner's staging state.
	if a.AdminTokenHash != authorizingHash {
		return "", ErrStaleRotation
	}

	// Clean crash residue from a previous rotation that died between staging
	// and rename, so the exact staging pathname cannot permanently prevent a
	// later valid rotation. Any other removal failure is fatal to this
	// rotation: writing over unremovable residue is not a safe replacement.
	if err := os.Remove(stagingPath); err != nil && !os.IsNotExist(err) {
		return "", fmt.Errorf("cannot clean stale token staging file: %w", err)
	}

	// Create the exact staging pathname, never a random tempfile.
	f, err := os.OpenFile(stagingPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", fmt.Errorf("cannot create token staging file: %w", err)
	}
	cleanupStaging := func() {
		f.Close()
		os.Remove(stagingPath)
	}

	// Write token + newline.
	if _, err := f.WriteString(newToken + "\n"); err != nil {
		cleanupStaging()
		return "", fmt.Errorf("cannot write token file: %w", err)
	}
	// Set permissions explicitly (also proves the MAC setattr permission).
	if err := f.Chmod(0600); err != nil {
		cleanupStaging()
		return "", fmt.Errorf("cannot set token file permissions: %w", err)
	}
	// Sync to disk.
	if err := f.Sync(); err != nil {
		cleanupStaging()
		return "", fmt.Errorf("cannot sync token file: %w", err)
	}
	// Close the file.
	if err := f.Close(); err != nil {
		os.Remove(stagingPath)
		return "", fmt.Errorf("cannot close token staging file: %w", err)
	}

	// Atomic replacement through the deterministic test seam or os.Rename.
	rename := os.Rename
	if a.RotateRenameFn != nil {
		rename = a.RotateRenameFn
	}
	if err := rename(stagingPath, tokenPath); err != nil {
		os.Remove(stagingPath)
		return "", fmt.Errorf("cannot replace token file: %w", err)
	}

	// Update in-memory hash.
	a.AdminTokenHash = newHash

	return newToken, nil
}

// getAdminTokenHash returns a copy of the current admin token hash.
func (a *App) getAdminTokenHash() [sha256.Size]byte {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.AdminTokenHash
}

// principalEnabledChangeResult is the explicit result of a principal
// enabled-state transition. Changed indicates whether the state actually
// transitioned. RevokedSessionIDs lists session IDs deleted when disabling.
// LauncherAdmissions is the final operation-admission state for every child
// Launcher after the committed transition, computed transactionally (closed
// iff Principal.enabled or the child's own Launcher.enabled does not hold),
// so callers apply it in memory after commit without another DB read.
type principalEnabledChangeResult struct {
	Changed            bool
	RevokedSessionIDs  []string
	LauncherAdmissions []launcherAdmission
}

// applyPrincipalEnabledChange is the App-level lifecycle operation for
// transitioning a principal's enabled state. It:
//   - updates the principal enabled state in the database;
//   - when disabling, collects and deletes that principal's sessions
//     in the same DB transaction;
//   - commits the DB transaction;
//   - after successful commit, releases every deleted session binding
//     through the MAC coordinator;
//   - returns explicit Changed and RevokedSessionIDs.
//
// Running operations are NOT terminated. Existing session-use leases
// continue to hold the MAC boundary until the operation releases its lease.
func (a *App) applyPrincipalEnabledChange(username string, enabled bool) (principalEnabledChangeResult, error) {
	result, err := persistPrincipalEnabledChange(a.DB, username, enabled)
	if err != nil {
		return principalEnabledChangeResult{}, err
	}

	if result.Changed && len(result.RevokedSessionIDs) > 0 {
		a.releaseSessionBindings(result.RevokedSessionIDs)
	}

	return result, nil
}

// deletePrincipalWithMAC is the App-level lifecycle operation for
// deleting a principal. It:
//   - collects session IDs;
//   - deletes the principal's sessions;
//   - deletes the principal;
//   - commits the DB transaction;
//   - after successful commit, releases every deleted session binding
//     through the MAC coordinator.
//
// Returns the deleted session IDs for best-effort runtime directory cleanup.
// Running operations are NOT terminated. Existing session-use leases
// continue to hold the MAC boundary until the operation releases its lease.
func (a *App) deletePrincipalWithMAC(username string) ([]string, error) {
	sessionIDs, err := deletePrincipal(a.DB, username)
	if err != nil {
		return nil, err
	}

	a.releaseSessionBindings(sessionIDs)
	return sessionIDs, nil
}

// releaseSessionBindings releases MAC bindings for the given session IDs
// through the MAC coordinator. No-op if the coordinator is nil.
func (a *App) releaseSessionBindings(sessionIDs []string) {
	if a.MACCoordinator == nil {
		return
	}
	for _, id := range sessionIDs {
		a.MACCoordinator.ReleaseSessionBinding(id)
	}
}
