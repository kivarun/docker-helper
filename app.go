package main

import (
	"crypto/sha256"
	"database/sql"
	"sync"
)

type App struct {
	mu             sync.RWMutex
	Config         *Config
	DB             *sql.DB
	AdminTokenHash [sha256.Size]byte
	RunCommand     func(string, ...string) ([]byte, error)
	BuildCommand   func(string, ...string) ([]byte, error)
	PullCommand    func(string, ...string) ([]byte, error)
}

// getConfig returns the current configuration under a read lock.
func (a *App) getConfig() *Config {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.Config
}

// setConfig updates the configurable fields of the current configuration:
// allowed_root, session_ttl, log_level, audit_enabled.
// Computed paths (socket, database, etc.) remain unchanged.
func (a *App) setConfig(newCfg *Config) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.Config.AllowedRoot = newCfg.AllowedRoot
	a.Config.SessionTTL = newCfg.SessionTTL
	a.Config.LogLevel = newCfg.LogLevel
	a.Config.AuditEnabled = newCfg.AuditEnabled
}
