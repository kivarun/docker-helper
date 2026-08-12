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
	// Trusted CA injection (runtime-only, computed from file config).
	TrustedCAInjection   string // "disabled" or "auto"
	TrustedCAPath        string // absolute path to CA file (only when auto)
	TrustedCAPreparedDir string // computed: prepared runtime directory (not in JSON/show)
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
	TrustedCAPath         string `json:"trusted_ca_path,omitempty"`
	TrustedCAInjection    string `json:"trusted_ca_injection,omitempty"`
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

// deprecatedConfigFields were renamed and must not appear in config.json.
// The map value is the new field name for the diagnostic message.
var deprecatedConfigFields = map[string]string{
	"build_log_max_bytes": "operation_log_max_bytes",
}

// validateNoDeprecatedRawFields checks that no deprecated field appears in the raw config map.
// It returns an error with a clear rename diagnostic.
func validateNoDeprecatedRawFields(raw map[string]json.RawMessage) error {
	for old, newField := range deprecatedConfigFields {
		if _, ok := raw[old]; ok {
			return fmt.Errorf("%s was renamed to %s", old, newField)
		}
	}
	return nil
}

// validateNoDeprecatedFields checks that no deprecated field appears in the config JSON.
// It returns an error with a clear rename diagnostic.
func validateNoDeprecatedFields(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("cannot parse config: %w", err)
	}
	return validateNoDeprecatedRawFields(raw)
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

	// Validate the raw config document before decoding into fileConfig.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("cannot parse config: %w", err)
	}
	if err := validateRawConfig(raw); err != nil {
		return nil, err
	}

	var fc fileConfig
	if err := json.Unmarshal(data, &fc); err != nil {
		return nil, fmt.Errorf("cannot parse config: %w", err)
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

	// Parse trusted_ca_injection (default: "disabled").
	trustedCAInjection := fc.TrustedCAInjection
	if trustedCAInjection == "" {
		trustedCAInjection = "disabled"
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

	cfg := &Config{
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
		TrustedCAInjection:    trustedCAInjection,
		TrustedCAPath:         fc.TrustedCAPath,
	}

	// Prepare CA injection if enabled.
	if trustedCAInjection == "auto" {
		if cfg.TrustedCAPath == "" {
			return nil, fmt.Errorf("trusted_ca_path is required when trusted_ca_injection is \"auto\"")
		}
		preparedDir, err := prepareCAInjection(runtimeDir, cfg.TrustedCAPath)
		if err != nil {
			return nil, err
		}
		cfg.TrustedCAPreparedDir = preparedDir
	}

	return cfg, nil
}

func resolveAuditEnabled(cfg *bool, level slog.Level) bool {
	if cfg != nil {
		return *cfg
	}
	return level == slog.LevelDebug
}

// resolveTrustedCAInjection returns the effective injection mode.
// Default is "disabled" when the field is absent.
func resolveTrustedCAInjection(s string) string {
	if s == "" {
		return "disabled"
	}
	return s
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

// validateRawConfig validates the known fields in a raw config map.
// It does not require XDG_RUNTIME_DIR and does not create directories.
// Returns an error if the document is malformed or known fields are invalid.
func validateRawConfig(raw map[string]json.RawMessage) error {
	if raw == nil {
		return fmt.Errorf("configuration is not a JSON object")
	}

	// Reject reserved/computed fields.
	for field := range raw {
		if reservedConfigFields[field] {
			return fmt.Errorf("%s is computed and cannot be configured", field)
		}
	}

	// Reject deprecated config keys with a clear rename diagnostic.
	if err := validateNoDeprecatedRawFields(raw); err != nil {
		return err
	}

	// Validate allowed_root: must exist as a non-empty absolute string.
	if v, ok := raw["allowed_root"]; ok {
		var s string
		if err := json.Unmarshal(v, &s); err != nil {
			return fmt.Errorf("allowed_root must be a JSON string")
		}
		if err := validateAllowedRootValue(s); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("allowed_root is required")
	}

	// Validate session_ttl: must exist as a valid positive duration string.
	if v, ok := raw["session_ttl"]; ok {
		var s string
		if err := json.Unmarshal(v, &s); err != nil {
			return fmt.Errorf("session_ttl must be a JSON string")
		}
		if _, err := parseSessionTTL(s); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("session_ttl is required")
	}

	// Validate log_level if present.
	if v, ok := raw["log_level"]; ok {
		var s string
		if err := json.Unmarshal(v, &s); err != nil {
			return fmt.Errorf("log_level must be a JSON string")
		}
		if _, err := parseLogLevel(s); err != nil {
			return err
		}
	}

	// Validate audit_enabled if present: must be a JSON boolean.
	if v, ok := raw["audit_enabled"]; ok {
		var b bool
		if err := json.Unmarshal(v, &b); err != nil {
			return fmt.Errorf("audit_enabled must be a JSON boolean")
		}
		_ = b
	}

	// Validate shutdown_timeout if present.
	if v, ok := raw["shutdown_timeout"]; ok {
		var s string
		if err := json.Unmarshal(v, &s); err != nil {
			return fmt.Errorf("shutdown_timeout must be a JSON string")
		}
		if _, err := parseDurationPositive(s, "shutdown_timeout"); err != nil {
			return err
		}
	}

	// Validate operation_retention_ttl if present.
	if v, ok := raw["operation_retention_ttl"]; ok {
		var s string
		if err := json.Unmarshal(v, &s); err != nil {
			return fmt.Errorf("operation_retention_ttl must be a JSON string")
		}
		if _, err := parseDurationPositive(s, "operation_retention_ttl"); err != nil {
			return err
		}
	}

	// Validate operation_max_completed if present.
	if v, ok := raw["operation_max_completed"]; ok {
		var n int
		if err := json.Unmarshal(v, &n); err != nil {
			return fmt.Errorf("operation_max_completed must be a JSON integer")
		}
		if n <= 0 {
			return fmt.Errorf("operation_max_completed must be a positive integer")
		}
	}

	// Validate operation_log_max_bytes if present.
	if v, ok := raw["operation_log_max_bytes"]; ok {
		var n int64
		if err := json.Unmarshal(v, &n); err != nil {
			return fmt.Errorf("operation_log_max_bytes must be a JSON integer")
		}
		if n <= 0 {
			return fmt.Errorf("operation_log_max_bytes must be a positive integer")
		}
	}

	// Validate trusted_ca_injection if present.
	if v, ok := raw["trusted_ca_injection"]; ok {
		var s string
		if err := json.Unmarshal(v, &s); err != nil {
			return fmt.Errorf("trusted_ca_injection must be a JSON string")
		}
		if s != "disabled" && s != "auto" {
			return fmt.Errorf("trusted_ca_injection must be \"disabled\" or \"auto\"")
		}
		// "auto" requires trusted_ca_path.
		if s == "auto" {
			if pv, ok := raw["trusted_ca_path"]; ok {
				var p string
				if err := json.Unmarshal(pv, &p); err != nil {
					return fmt.Errorf("trusted_ca_path must be a JSON string")
				}
				if p == "" {
					return fmt.Errorf("trusted_ca_path is required when trusted_ca_injection is \"auto\"")
				}
				if !filepath.IsAbs(p) {
					return fmt.Errorf("trusted_ca_path must be an absolute path")
				}
			} else {
				return fmt.Errorf("trusted_ca_path is required when trusted_ca_injection is \"auto\"")
			}
		}
	}

	// Validate trusted_ca_path if present (must be absolute).
	if v, ok := raw["trusted_ca_path"]; ok {
		var p string
		if err := json.Unmarshal(v, &p); err != nil {
			return fmt.Errorf("trusted_ca_path must be a JSON string")
		}
		if p != "" && !filepath.IsAbs(p) {
			return fmt.Errorf("trusted_ca_path must be an absolute path")
		}
	}

	return nil
}

// validateCAConfig performs a CA-specific preflight check before the config
// is persisted. It only runs when the effective trusted_ca_injection is "auto".
// It validates the CA file and openssl availability without requiring
// XDG_RUNTIME_DIR, creating directories, or materializing artifacts.
func validateCAConfig(raw map[string]json.RawMessage) error {
	injRaw, ok := raw["trusted_ca_injection"]
	if !ok {
		return nil
	}
	var inj string
	if err := json.Unmarshal(injRaw, &inj); err != nil {
		return nil // validation error will be caught by validateRawConfig
	}
	if inj != "auto" {
		return nil
	}

	pathRaw, ok := raw["trusted_ca_path"]
	if !ok {
		return nil // validation error will be caught by validateRawConfig
	}
	var caPath string
	if err := json.Unmarshal(pathRaw, &caPath); err != nil {
		return nil
	}
	if caPath == "" {
		return nil
	}

	if _, err := validateCAFile(caPath); err != nil {
		return err
	}

	if _, err := computeOpenSSLHash(caPath); err != nil {
		return err
	}

	return nil
}
