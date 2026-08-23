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
	mu                 sync.RWMutex
	Config             *Config
	DB                 *sql.DB
	AdminTokenHash     [sha256.Size]byte
	ExecCommandContext func(context.Context, string, ...string) *exec.Cmd
	OperationRegistry  *operationRegistry
	// PinMountFn is a test seam for the inode-pinning primitive.
	// Production default calls the real PinMount; tests can return
	// a fake pinnedMount with controlled Cleanup behavior.
	PinMountFn func(workspace, sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error)
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
}

// pinMount calls PinMountFn if set, otherwise the real PinMount.
func (a *App) pinMount(workspace, sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
	if a.PinMountFn != nil {
		return a.PinMountFn(workspace, sourcePath, runtimeDir, operationID, mountIndex)
	}
	return PinMount(workspace, sourcePath, runtimeDir, operationID, mountIndex)
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
// from the current configuration. Configurable fields: allowed_root,
// session_ttl, log_level, audit_enabled, shutdown_timeout,
// operation_retention_ttl, operation_max_completed, operation_log_max_bytes.
func (a *App) setConfig(newCfg *Config) {
	a.mu.Lock()
	defer a.mu.Unlock()
	merged := *newCfg
	merged.SocketPath = a.Config.SocketPath
	merged.LockPath = a.Config.LockPath
	merged.StateDir = a.Config.StateDir
	merged.RuntimeDir = a.Config.RuntimeDir
	merged.DatabasePath = a.Config.DatabasePath
	merged.AdminTokenPath = a.Config.AdminTokenPath
	a.Config = &merged
}

// rotateAdminToken generates a new admin token, writes it to the token file
// atomically, and updates the in-memory hash. The old token is immediately
// invalidated. Returns the new token (never logged).
//
// The caller must have already authorized with the current admin token.
// The function verifies that the authorizing token is still current before
// committing the rotation, preventing stale concurrent rotations.
func (a *App) rotateAdminToken(authorizingHash [sha256.Size]byte) (string, error) {
	// Generate new token using the standard generator.
	newToken, err := generateToken()
	if err != nil {
		return "", err
	}
	newHash := sha256.Sum256([]byte(newToken))

	// Get a snapshot of the config for the token path.
	cfg := a.getConfig()
	tokenPath := cfg.AdminTokenPath

	// Prepare temp file in the same directory as the target.
	dir := filepath.Dir(tokenPath)
	tmpFile, err := os.CreateTemp(dir, ".admin-token-*")
	if err != nil {
		return "", fmt.Errorf("cannot create temp token file: %w", err)
	}
	tmpPath := tmpFile.Name()
	cleanup := func() {
		tmpFile.Close()
		os.Remove(tmpPath)
	}

	// Write token + newline.
	if _, err := tmpFile.WriteString(newToken + "\n"); err != nil {
		cleanup()
		return "", fmt.Errorf("cannot write token file: %w", err)
	}
	// Set permissions before closing.
	if err := tmpFile.Chmod(0600); err != nil {
		cleanup()
		return "", fmt.Errorf("cannot set token file permissions: %w", err)
	}
	// Sync to disk.
	if err := tmpFile.Sync(); err != nil {
		cleanup()
		return "", fmt.Errorf("cannot sync token file: %w", err)
	}
	// Close the file.
	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpPath)
		return "", fmt.Errorf("cannot close temp token file: %w", err)
	}

	// Atomic commit: verify authorizing token is still current,
	// then rename and update runtime hash under write lock.
	a.mu.Lock()
	defer a.mu.Unlock()

	// Verify the authorizing token is still the current one.
	if a.AdminTokenHash != authorizingHash {
		// Stale concurrent rotation: another rotation already committed.
		os.Remove(tmpPath)
		return "", ErrStaleRotation
	}

	// Atomic rename.
	rename := os.Rename
	if a.RotateRenameFn != nil {
		rename = a.RotateRenameFn
	}
	if err := rename(tmpPath, tokenPath); err != nil {
		os.Remove(tmpPath)
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
