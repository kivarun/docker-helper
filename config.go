package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Config struct {
	AllowedRoot           string
	SessionTTL            time.Duration
	LogLevel              slog.Level
	AuditEnabled          bool
	SocketPath            string
	LockPath              string
	StateDir              string
	RuntimeDir            string
	DatabasePath          string
	AdminTokenPath        string
	ShutdownTimeout       time.Duration
	OperationRetentionTTL time.Duration
	OperationMaxCompleted int
	OperationLogMaxBytes  int64
}

type fileConfig struct {
	AllowedRoot           string `json:"allowed_root"`
	SessionTTL            string `json:"session_ttl"`
	Level                 string `json:"log_level,omitempty"`
	AuditEnabled          *bool  `json:"audit_enabled,omitempty"`
	ShutdownTimeout       string `json:"shutdown_timeout,omitempty"`
	OperationRetentionTTL string `json:"operation_retention_ttl,omitempty"`
	OperationMaxCompleted *int   `json:"operation_max_completed,omitempty"`
	OperationLogMaxBytes  *int64 `json:"operation_log_max_bytes,omitempty"`
}

func parseLogLevel(s string) (slog.Level, error) {
	switch s {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("invalid log_level %q: must be one of debug, info, warn, error", s)
	}
}

func ptrOf[T any](v T) *T {
	return &v
}

// reservedConfigFields are computed or read-only and must not appear in config.json.
var reservedConfigFields = map[string]bool{
	"audit_enabled_source": true,
	"config_path":          true,
	"config_dir":           true,
	"runtime_dir":          true,
	"socket_path":          true,
	"lock_path":            true,
	"state_dir":            true,
	"database_path":        true,
	"admin_token_path":     true,
	"admin_token":          true,
}

// validateNoReservedFields checks that no reserved field appears in the config JSON.
// It returns an error naming the first offending field found.
func validateNoReservedFields(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("cannot parse config: %w", err)
	}
	for field := range raw {
		if reservedConfigFields[field] {
			return fmt.Errorf("%s is computed and cannot be configured", field)
		}
	}
	return nil
}

func getConfigPath() string {
	if p := os.Getenv("DOCKER_HELPER_CONFIG"); p != "" {
		return p
	}

	xdgConfig := os.Getenv("XDG_CONFIG_HOME")
	if xdgConfig == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		xdgConfig = filepath.Join(home, ".config")
	}

	return filepath.Join(xdgConfig, "docker-helper", "config.json")
}

func getConfigDir() string {
	return filepath.Dir(getConfigPath())
}

func getRuntimeDir() (string, error) {
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		return "", errors.New("XDG_RUNTIME_DIR is not set, cannot determine runtime directory")
	}
	return filepath.Join(dir, "docker-helper"), nil
}

func getStateDir() string {
	xdgState := os.Getenv("XDG_STATE_HOME")
	if xdgState == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		xdgState = filepath.Join(home, ".local", "state")
	}

	return filepath.Join(xdgState, "docker-helper")
}

func loadConfig() (*Config, error) {
	configPath := getConfigPath()

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read config: %w", err)
	}

	// Check for reserved fields that must not appear in config.json.
	if err := validateNoReservedFields(data); err != nil {
		return nil, err
	}

	var fc fileConfig

	if err := json.Unmarshal(data, &fc); err != nil {
		return nil, fmt.Errorf("cannot parse config: %w", err)
	}

	if err := validateAllowedRootValue(fc.AllowedRoot); err != nil {
		return nil, err
	}

	ttl, err := parseSessionTTL(fc.SessionTTL)
	if err != nil {
		return nil, err
	}

	level := slog.LevelInfo
	if fc.Level != "" {
		level, err = parseLogLevel(fc.Level)
		if err != nil {
			return nil, err
		}
	}

	auditEnabled := resolveAuditEnabled(fc.AuditEnabled, level)

	shutdownTimeout := 30 * time.Second
	if fc.ShutdownTimeout != "" {
		st, err := parseDurationPositive(fc.ShutdownTimeout, "shutdown_timeout")
		if err != nil {
			return nil, err
		}
		shutdownTimeout = st
	}

	opRetentionTTL := 10 * time.Minute
	if fc.OperationRetentionTTL != "" {
		ort, err := parseDurationPositive(fc.OperationRetentionTTL, "operation_retention_ttl")
		if err != nil {
			return nil, err
		}
		opRetentionTTL = ort
	}

	opMaxCompleted := 200
	if fc.OperationMaxCompleted != nil {
		opMaxCompleted = *fc.OperationMaxCompleted
	}

	operationLogMaxBytes := int64(4 * 1024 * 1024)
	if fc.OperationLogMaxBytes != nil {
		operationLogMaxBytes = *fc.OperationLogMaxBytes
	}

	runtimeDir, err := getRuntimeDir()
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(runtimeDir, 0700); err != nil {
		return nil, fmt.Errorf("cannot create runtime directory: %w", err)
	}

	stateDir := getStateDir()

	// Derive configDir from configPath so DOCKER_HELPER_CONFIG is respected.
	configDir := filepath.Dir(configPath)

	adminTokenPath := filepath.Join(configDir, "admin.token")

	socketPath := filepath.Join(runtimeDir, "docker-helper.sock")

	return &Config{
		AllowedRoot:           fc.AllowedRoot,
		SessionTTL:            ttl,
		LogLevel:              level,
		AuditEnabled:          auditEnabled,
		SocketPath:            socketPath,
		LockPath:              socketPath + ".lock",
		StateDir:              stateDir,
		RuntimeDir:            runtimeDir,
		DatabasePath:          filepath.Join(stateDir, "docker-helper.db"),
		AdminTokenPath:        adminTokenPath,
		ShutdownTimeout:       shutdownTimeout,
		OperationRetentionTTL: opRetentionTTL,
		OperationMaxCompleted: opMaxCompleted,
		OperationLogMaxBytes:  operationLogMaxBytes,
	}, nil
}

func resolveAuditEnabled(cfg *bool, level slog.Level) bool {
	if cfg != nil {
		return *cfg
	}
	return level == slog.LevelDebug
}

// parseDurationPositive parses a Go duration string and returns an error if
// the value is not a valid positive duration.
func parseDurationPositive(s, name string) (time.Duration, error) {
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("cannot parse %s %q: %w", name, s, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%s must be a positive duration", name)
	}
	return d, nil
}

// validateAllowedRootValue validates that the parsed allowed_root value
// is non-empty and an absolute path.
func validateAllowedRootValue(s string) error {
	if s == "" {
		return fmt.Errorf("allowed_root must be a non-empty absolute path")
	}
	if !filepath.IsAbs(s) {
		return fmt.Errorf("allowed_root must be a non-empty absolute path")
	}
	return nil
}

// parseSessionTTL parses and validates the session_ttl value.
// It returns an error if the value is not a valid positive duration.
func parseSessionTTL(s string) (time.Duration, error) {
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("cannot parse session_ttl %q: %w", s, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("session_ttl must be a positive duration")
	}
	return d, nil
}

func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("cannot generate random bytes: %w", err)
	}
	return "dht_" + hex.EncodeToString(b), nil
}

func runInit(allowedRoot string, stdout, stderr io.Writer) error {
	if allowedRoot == "" {
		var err error
		allowedRoot, err = os.Getwd()
		if err != nil {
			return fmt.Errorf("cannot determine current working directory: %w", err)
		}
	}

	configPath := getConfigPath()
	configDir := filepath.Dir(configPath)
	stateDir := getStateDir()

	if err := os.MkdirAll(configDir, 0700); err != nil {
		return fmt.Errorf("cannot create config directory: %w", err)
	}

	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return fmt.Errorf("cannot create state directory: %w", err)
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
defaultConfig := fileConfig{
		AllowedRoot:           allowedRoot,
		SessionTTL:            "12h",
		Level:                 "info",
		ShutdownTimeout:       "30s",
		OperationRetentionTTL: "10m",
		OperationMaxCompleted: ptrOf(200),
		OperationLogMaxBytes:  ptrOf(int64(4 * 1024 * 1024)),
	}

		data, err := json.MarshalIndent(defaultConfig, "", "  ")
		if err != nil {
			return fmt.Errorf("cannot marshal config: %w", err)
		}
		data = append(data, '\n')

		if err := os.WriteFile(configPath, data, 0600); err != nil {
			return fmt.Errorf("cannot write config: %w", err)
		}
	}

	adminTokenPath := filepath.Join(configDir, "admin.token")

	if _, err := os.Stat(adminTokenPath); err == nil {
		fmt.Fprintln(stderr, "admin.token already exists at:")
		fmt.Fprintln(stderr, adminTokenPath)
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Will not overwrite. Use a future token rotation command to replace it.")
		return errors.New("admin.token already exists")
	}

	token, err := generateToken()
	if err != nil {
		return err
	}

	if err := os.WriteFile(adminTokenPath, []byte(token+"\n"), 0600); err != nil {
		return fmt.Errorf("cannot write admin token: %w", err)
	}

	fmt.Fprintln(stdout, "Docker Helper initialized successfully.")
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "Admin token:")
	fmt.Fprintln(stdout, token)
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "Stored at:")
	fmt.Fprintln(stdout, adminTokenPath)
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "Configuration:")
	fmt.Fprintln(stdout, configPath)

	return nil
}

// resolveAllowedRoot normalizes and validates an allowed-root path.
// It expands ~/ prefixes, resolves to an absolute canonical path,
// and verifies that the path exists and is a directory.
// The caller must provide a non-empty path.
func resolveAllowedRoot(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("allowed root must be a non-empty absolute path")
	}

	path = expandTilde(path)

	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("allowed root must be an absolute path: %w", err)
	}

	info, err := os.Stat(abs)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("allowed root does not exist: %s", abs)
		}
		return "", fmt.Errorf("cannot stat allowed root: %w", err)
	}

	if !info.IsDir() {
		return "", fmt.Errorf("allowed root is not a directory: %s", abs)
	}

	cleaned, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("cannot resolve allowed root path: %w", err)
	}

	return cleaned, nil
}

// expandTilde expands a path starting with ~/ to the user's home directory.
// It does not perform shell expansion, environment-variable expansion, or globbing.
func expandTilde(path string) string {
	if !strings.HasPrefix(path, "~/") && path != "~" {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	if path == "~" {
		return home
	}
	return filepath.Join(home, path[2:])
}

// promptAllowedRoot prompts the user for an allowed root directory.
// It uses the provided default value and reads from stdin.
func promptAllowedRoot(defaultPath string, stdin io.Reader, stderr io.Writer) (string, error) {
	fmt.Fprintf(stderr, "Enter allowed root directory:\n")
	fmt.Fprintf(stderr, "[%s]:\n", defaultPath)

	scanner := bufio.NewScanner(stdin)
	if !scanner.Scan() {
		return "", errors.New("failed to read input")
	}

	input := scanner.Text()
	if input == "" {
		return defaultPath, nil
	}
	return input, nil
}
