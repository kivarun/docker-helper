package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"os/exec"
	"sync"
)

type App struct {
	mu                 sync.RWMutex
	Config             *Config
	DB                 *sql.DB
	AdminTokenHash     [sha256.Size]byte
	ExecCommand        func(string, ...string) ([]byte, error)
	ExecCommandContext func(context.Context, string, ...string) *exec.Cmd
	OperationRegistry  *operationRegistry
}

// getConfig returns a snapshot copy of the current configuration under a read lock.
// The caller receives an independent copy that cannot be mutated by setConfig.
func (a *App) getConfig() Config {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return *a.Config
}

// setConfig atomically replaces the configuration pointer.
// Only configurable fields (allowed_root, session_ttl, log_level,
// audit_enabled) are taken from newCfg; computed paths are preserved
// from the current configuration.
func (a *App) setConfig(newCfg *Config) {
	a.mu.Lock()
	defer a.mu.Unlock()
	merged := *newCfg
	merged.SocketPath = a.Config.SocketPath
	merged.LockPath = a.Config.LockPath
	merged.StateDir = a.Config.StateDir
	merged.DatabasePath = a.Config.DatabasePath
	merged.AdminTokenPath = a.Config.AdminTokenPath
	a.Config = &merged
}
