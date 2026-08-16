package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
)

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

// generateAdminToken generates a new random admin token (32 bytes, hex-encoded).
func generateAdminToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("cannot generate random token: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// rotateAdminToken generates a new admin token, writes it to the token file
// atomically, and updates the in-memory hash. The old token is immediately
// invalidated. Returns the new token (never logged).
func (a *App) rotateAdminToken() (string, error) {
	newToken, err := generateAdminToken()
	if err != nil {
		return "", err
	}

	newHash := sha256.Sum256([]byte(newToken))

	// Write the new token to the file atomically (write to temp, rename).
	dir := filepath.Dir(a.Config.AdminTokenPath)
	tmpFile, err := os.CreateTemp(dir, ".admin-token-*")
	if err != nil {
		return "", fmt.Errorf("cannot create temp token file: %w", err)
	}
	tmpPath := tmpFile.Name()

	if _, err := tmpFile.WriteString(newToken + "\n"); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return "", fmt.Errorf("cannot write token file: %w", err)
	}
	if err := tmpFile.Chmod(0600); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return "", fmt.Errorf("cannot set token file permissions: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpPath)
		return "", fmt.Errorf("cannot close temp token file: %w", err)
	}
	if err := os.Rename(tmpPath, a.Config.AdminTokenPath); err != nil {
		os.Remove(tmpPath)
		return "", fmt.Errorf("cannot replace token file: %w", err)
	}

	// Update the in-memory hash under the lock.
	a.mu.Lock()
	a.AdminTokenHash = newHash
	a.mu.Unlock()

	return newToken, nil
}

// getAdminTokenHash returns a copy of the current admin token hash.
func (a *App) getAdminTokenHash() [sha256.Size]byte {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.AdminTokenHash
}
