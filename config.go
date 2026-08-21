package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"
)

// DeploymentMode represents the deployment mode of the daemon.
type DeploymentMode string

const (
	ModeUser   DeploymentMode = "user"
	ModeSystem DeploymentMode = "system"
)

// systemUserUnitPath is the system-wide location of the user systemd unit
// installed by the RPM/DEB package. The init command copies this file to
// the user's ~/.config/systemd/user/ directory on first initialization.
const systemUserUnitPath = "/usr/lib/systemd/user/docker-helper.service"

// EffectiveUID returns the effective UID of the process.
// Can be replaced in tests.
var EffectiveUID = func() int { return os.Geteuid() }

// resolveDeploymentMode determines the deployment mode from the effective UID.
func resolveDeploymentMode() DeploymentMode {
	if EffectiveUID() == 0 {
		return ModeSystem
	}
	return ModeUser
}

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
	// Deployment mode (computed from effective UID).
	Mode DeploymentMode
	// HTTPAddress is the loopback TCP listen address for system mode.
	HTTPAddress string
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
	HTTPAddress           string `json:"http_address,omitempty"`
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

type configFieldSpec struct {
	name     string
	writable bool
	required bool
}

var configFields = []configFieldSpec{
	{name: "allowed_root", writable: true, required: true},
	{name: "session_ttl", writable: true, required: true},
	{name: "log_level", writable: true},
	{name: "audit_enabled", writable: true},
	{name: "shutdown_timeout", writable: true},
	{name: "operation_retention_ttl", writable: true},
	{name: "operation_max_completed", writable: true},
	{name: "operation_log_max_bytes", writable: true},
	{name: "trusted_ca_path", writable: true},
	{name: "trusted_ca_injection", writable: true},
	{name: "http_address", writable: true},
	{name: "audit_enabled_source"},
	{name: "config_path"},
	{name: "config_dir"},
	{name: "runtime_dir"},
	{name: "socket_path"},
	{name: "lock_path"},
	{name: "state_dir"},
	{name: "database_path"},
	{name: "admin_token_path"},
	{name: "admin_token"},
	{name: "mode"},
}

func lookupConfigField(name string) (configFieldSpec, bool) {
	for _, f := range configFields {
		if f.name == name {
			return f, true
		}
	}
	return configFieldSpec{}, false
}

func isKnownField(name string) bool {
	_, ok := lookupConfigField(name)
	return ok
}

func isReadOnlyField(name string) bool {
	f, ok := lookupConfigField(name)
	return ok && !f.writable
}

func isRequiredField(name string) bool {
	f, ok := lookupConfigField(name)
	return ok && f.required
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

func getConfigPath() string {
	if p := os.Getenv("DOCKER_HELPER_CONFIG"); p != "" {
		return p
	}

	mode := resolveDeploymentMode()
	if mode == ModeSystem {
		return "/etc/docker-helper/config.json"
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

// getConfigPathFunc is injectable for testing.
var getConfigPathFunc = getConfigPath

func getConfigDir() string {
	return filepath.Dir(getConfigPath())
}

func getRuntimeDir() (string, error) {
	mode := resolveDeploymentMode()
	if mode == ModeSystem {
		return "/run/docker-helper", nil
	}

	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		return "", errors.New("XDG_RUNTIME_DIR is not set, cannot determine runtime directory")
	}
	return filepath.Join(dir, "docker-helper"), nil
}

func getStateDir() string {
	mode := resolveDeploymentMode()
	if mode == ModeSystem {
		return "/var/lib/docker-helper"
	}

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
	configPath := getConfigPathFunc()

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

	// The runtime allowed_root must be the canonical, policy-validated form.
	// This closes the manual-config symlink bypass: a config.json that points
	// allowed_root at a symlink into a forbidden tree is rejected here, before
	// any runtime/state filesystem side effects.
	allowedRoot, err := canonicalizeWorkspaceRootForAdd(fc.AllowedRoot)
	if err != nil {
		return nil, fmt.Errorf("invalid allowed_root: %w", err)
	}

	ec := resolveEffectiveConfig(fc)

	level, err := parseLogLevel(ec.LogLevel)
	if err != nil {
		return nil, err
	}

	shutdownTimeout, err := parseDurationPositive(ec.ShutdownTimeout, "shutdown_timeout")
	if err != nil {
		return nil, err
	}

	opRetentionTTL, err := parseDurationPositive(ec.OperationRetentionTTL, "operation_retention_ttl")
	if err != nil {
		return nil, err
	}

	trustedCAInjection := ec.TrustedCAInjection

	// HTTPAddress: loadConfig always defaults to DefaultHTTPAddress (mode-specific
	// behavior is only for TCP listener creation, not for the Config value).
	httpAddress := DefaultHTTPAddress
	if fc.HTTPAddress != "" {
		if err := validateHTTPAddress(fc.HTTPAddress); err != nil {
			return nil, err
		}
		httpAddress = fc.HTTPAddress
	}

	mode := resolveDeploymentMode()
	runtimeDir, err := getRuntimeDir()
	if err != nil {
		return nil, err
	}

	// Create runtime directory with mode-appropriate permissions.
	if mode == ModeSystem {
		if err := os.MkdirAll(runtimeDir, 0755); err != nil {
			return nil, fmt.Errorf("cannot create runtime directory: %w", err)
		}
	} else {
		if err := os.MkdirAll(runtimeDir, 0700); err != nil {
			return nil, fmt.Errorf("cannot create runtime directory: %w", err)
		}
	}

	stateDir := getStateDir()

	// Derive configDir from configPath so DOCKER_HELPER_CONFIG is respected.
	configDir := filepath.Dir(configPath)

	adminTokenPath := filepath.Join(configDir, "admin.token")

	socketPath := filepath.Join(runtimeDir, "docker-helper.sock")

	cfg := &Config{
		AllowedRoot:           allowedRoot,
		SessionTTL:            ttl,
		LogLevel:              level,
		AuditEnabled:          ec.AuditEnabled,
		SocketPath:            socketPath,
		LockPath:              socketPath + ".lock",
		StateDir:              stateDir,
		RuntimeDir:            runtimeDir,
		DatabasePath:          filepath.Join(stateDir, "docker-helper.db"),
		AdminTokenPath:        adminTokenPath,
		ShutdownTimeout:       shutdownTimeout,
		OperationRetentionTTL: opRetentionTTL,
		OperationMaxCompleted: ec.OperationMaxCompleted,
		OperationLogMaxBytes:  ec.OperationLogMaxBytes,
		Mode:                  mode,
		HTTPAddress:           httpAddress,
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
			return nil, &trustedCAPreparationError{Err: err}
		}
		cfg.TrustedCAPreparedDir = preparedDir
	}

	return cfg, nil
}

// resolveAuditEnabled returns the effective audit_enabled value.
// When cfg is non-nil, the explicit value always wins.
// When cfg is nil (absent from config file):
//   - system mode: audit is always enabled regardless of log_level;
//   - user mode: audit is enabled only when log_level is debug.
func resolveAuditEnabled(cfg *bool, level slog.Level, mode DeploymentMode) bool {
	if cfg != nil {
		return *cfg
	}
	if mode == ModeSystem {
		return true
	}
	return level == slog.LevelDebug
}

// resolveAuditSource returns the source description for audit_enabled.
// "explicit" — the operator set audit_enabled in config.
// "system_default" — audit_enabled absent, system mode defaults to enabled.
// "log_level" — audit_enabled absent, user mode derived from log_level.
func resolveAuditSource(cfg *bool, mode DeploymentMode) string {
	if cfg != nil {
		return "explicit"
	}
	if mode == ModeSystem {
		return "system_default"
	}
	return "log_level"
}

// resolveTrustedCAInjection returns the effective injection mode.
// Default is "disabled" when the field is absent.
func resolveTrustedCAInjection(s string) string {
	if s == "" {
		return "disabled"
	}
	return s
}

// effectiveConfigValues holds the effective (default-applied) output values
// for config-backed fields. It is the single source of truth for what
// `docker-helper config show` and `docker-helper config show FIELD` display.
type effectiveConfigValues struct {
	LogLevel              string // default "info"
	AuditEnabled          bool   // derived from mode/log_level unless explicit
	AuditEnabledSource    string // "explicit", "system_default", or "log_level"
	ShutdownTimeout       string // default "30s"
	OperationRetentionTTL string // default "10m"
	OperationMaxCompleted int    // default 200
	OperationLogMaxBytes  int64  // default 4194304
	TrustedCAInjection    string // default "disabled"
	HTTPAddress           string // mode-specific (system: default 127.0.0.1:52375, user: "")
}

// resolveEffectiveConfig computes the effective config values from a fileConfig.
// This is the single authoritative source for effective defaults.
func resolveEffectiveConfig(fc fileConfig) effectiveConfigValues {
	level := fc.Level
	if level == "" {
		level = "info"
	}
	slogLevel, _ := parseLogLevel(level)
	mode := resolveDeploymentMode()
	auditEnabled := resolveAuditEnabled(fc.AuditEnabled, slogLevel, mode)
	auditSource := resolveAuditSource(fc.AuditEnabled, mode)
	shutdownTimeout := fc.ShutdownTimeout
	if shutdownTimeout == "" {
		shutdownTimeout = "30s"
	}
	operationRetentionTTL := fc.OperationRetentionTTL
	if operationRetentionTTL == "" {
		operationRetentionTTL = "10m"
	}
	operationMaxCompleted := 200
	if fc.OperationMaxCompleted != nil {
		operationMaxCompleted = *fc.OperationMaxCompleted
	}
	operationLogMaxBytes := int64(4 * 1024 * 1024)
	if fc.OperationLogMaxBytes != nil {
		operationLogMaxBytes = *fc.OperationLogMaxBytes
	}
	trustedCAInjection := resolveTrustedCAInjection(fc.TrustedCAInjection)
	httpAddress := resolveHTTPAddress(fc.HTTPAddress)
	return effectiveConfigValues{
		LogLevel:              level,
		AuditEnabled:          auditEnabled,
		AuditEnabledSource:    auditSource,
		ShutdownTimeout:       shutdownTimeout,
		OperationRetentionTTL: operationRetentionTTL,
		OperationMaxCompleted: operationMaxCompleted,
		OperationLogMaxBytes:  operationLogMaxBytes,
		TrustedCAInjection:    trustedCAInjection,
		HTTPAddress:           httpAddress,
	}
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
// is non-empty, absolute, and passes the workspace root security policy.
// Note: this is a lexical check only (no filesystem access); the full
// canonicalization + policy is applied by canonicalizeWorkspaceRootForAdd.
func validateAllowedRootValue(s string) error {
	if s == "" {
		return fmt.Errorf("allowed_root must be a non-empty absolute path")
	}
	if !filepath.IsAbs(s) {
		return fmt.Errorf("allowed_root must be a non-empty absolute path")
	}
	// Apply the security policy to the canonical path.
	return validateWorkspaceRootPolicy(filepath.Clean(s))
}

// validateHTTPAddress validates that the http_address value is a loopback
// IPv4 address with a valid port (1..65535).
func validateHTTPAddress(s string) error {
	if s == "" {
		return fmt.Errorf("http_address must not be empty")
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return fmt.Errorf("http_address must be in the form 127.0.0.1:PORT: %v", err)
	}
	if host != "127.0.0.1" {
		return fmt.Errorf("http_address: host must be 127.0.0.1 (got %s)", host)
	}
	portNum, err := strconv.Atoi(port)
	if err != nil || portNum < 1 || portNum > 65535 {
		return fmt.Errorf("http_address: port must be 1..65535 (got %s)", port)
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

// installUserSystemdUnit copies the system-wide user systemd unit to the
// user's ~/.config/systemd/user/ directory and runs daemon-reload.
// It is a no-op if the user unit already exists or the system unit is not found.
// Can be replaced in tests.
var installUserSystemdUnit = func(stdout, stderr io.Writer) {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	userUnitDir := filepath.Join(home, ".config", "systemd", "user")
	userUnitPath := filepath.Join(userUnitDir, "docker-helper.service")

	// Do not overwrite an existing user unit.
	if _, err := os.Stat(userUnitPath); err == nil {
		return
	}

	// Source unit must exist (RPM/DEB install).
	data, err := os.ReadFile(systemUserUnitPath)
	if err != nil {
		return
	}

	if err := os.MkdirAll(userUnitDir, 0700); err != nil {
		fmt.Fprintf(stderr, "warning: cannot create systemd user directory: %v\n", err)
		return
	}
	if err := os.WriteFile(userUnitPath, data, 0644); err != nil {
		fmt.Fprintf(stderr, "warning: cannot install systemd user unit: %v\n", err)
		return
	}

	fmt.Fprintln(stdout, "Systemd user unit installed at:")
	fmt.Fprintln(stdout, userUnitPath)

	// Best-effort daemon-reload.
	if err := exec.Command("systemctl", "--user", "daemon-reload").Run(); err != nil {
		fmt.Fprintf(stderr, "warning: systemctl --user daemon-reload failed: %v\n", err)
		fmt.Fprintf(stdout, "\n")
		fmt.Fprintf(stdout, "To start the service:\n")
		fmt.Fprintf(stdout, "  systemctl --user daemon-reload\n")
		fmt.Fprintf(stdout, "  systemctl --user enable --now docker-helper\n")
	} else {
		fmt.Fprintf(stdout, "\n")
		fmt.Fprintf(stdout, "To start the service:\n")
		fmt.Fprintf(stdout, "  systemctl --user enable --now docker-helper\n")
	}
}

// initCoreResult is the result of running the core init logic.
type initCoreResult struct {
	allowedRoot    string
	token          string
	configPath     string
	adminTokenPath string
}

// initCore performs the file-based initialization (config and token).
// It does not perform any AppArmor operations.
func initCore(allowedRoot string, stdout, stderr io.Writer) (*initCoreResult, error) {
	mode := resolveDeploymentMode()
	configPath := getConfigPathFunc()
	configDir := filepath.Dir(configPath)
	stateDir := getStateDir()

	// Create directories with mode-appropriate permissions.
	if mode == ModeSystem {
		if err := os.MkdirAll(configDir, 0755); err != nil {
			return nil, fmt.Errorf("cannot create config directory: %w", err)
		}
	} else {
		if err := os.MkdirAll(configDir, 0700); err != nil {
			return nil, fmt.Errorf("cannot create config directory: %w", err)
		}
	}

	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return nil, fmt.Errorf("cannot create state directory: %w", err)
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
			return nil, fmt.Errorf("cannot marshal config: %w", err)
		}
		data = append(data, '\n')

		if err := os.WriteFile(configPath, data, 0600); err != nil {
			return nil, fmt.Errorf("cannot write config: %w", err)
		}
	}

	adminTokenPath := filepath.Join(configDir, "admin.token")

	if _, err := os.Stat(adminTokenPath); err == nil {
		fmt.Fprintln(stderr, "admin.token already exists at:")
		fmt.Fprintln(stderr, adminTokenPath)
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Will not overwrite. Use `docker-helper admin token rotate` to replace it.")
		return nil, errors.New("admin.token already exists")
	}

	token, err := generateToken()
	if err != nil {
		return nil, err
	}

	if err := os.WriteFile(adminTokenPath, []byte(token+"\n"), 0600); err != nil {
		return nil, fmt.Errorf("cannot write admin token: %w", err)
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

	if mode == ModeUser {
		installUserSystemdUnit(stdout, stderr)
	}

	return &initCoreResult{
		allowedRoot:    allowedRoot,
		token:          token,
		configPath:     configPath,
		adminTokenPath: adminTokenPath,
	}, nil
}

// initSystemWithAppArmor performs system-mode initialization with AppArmor integration.
// core is the file-based init function (injectable for testing).
func initSystemWithAppArmor(allowedRoot string, stdout, stderr io.Writer,
	addRoot func(string) (rootResult, error),
	removeRoot func(string) (rootResult, error),
	core func(string, io.Writer, io.Writer) error,
) error {
	configPath := getConfigPathFunc()
	configDir := filepath.Dir(configPath)
	adminTokenPath := filepath.Join(configDir, "admin.token")

	// Preflight 1: check existing admin.token before any AppArmor changes.
	if _, err := os.Stat(adminTokenPath); err == nil {
		fmt.Fprintln(stderr, "admin.token already exists at:")
		fmt.Fprintln(stderr, adminTokenPath)
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Will not overwrite. Use `docker-helper admin token rotate` to replace it.")
		return errors.New("admin.token already exists")
	}

	// Preflight 2: read existing config if present to check for mismatch.
	var existingAllowedRoot string
	configExists := false

	if stat, err := os.Stat(configPath); err == nil {
		if stat.IsDir() {
			// config.json as a directory is an operational failure.
			return fmt.Errorf("configuration path is a directory: %s", configPath)
		}
		configExists = true
		data, err := os.ReadFile(configPath)
		if err != nil {
			return fmt.Errorf("cannot read existing configuration: %w", err)
		}

		var raw map[string]json.RawMessage
		if err := json.Unmarshal(data, &raw); err != nil {
			return fmt.Errorf("cannot parse existing configuration: %w", err)
		}
		if err := validateRawConfig(raw); err != nil {
			return fmt.Errorf("existing configuration is invalid: %w", err)
		}

		var fc fileConfig
		if err := json.Unmarshal(data, &fc); err != nil {
			return fmt.Errorf("cannot decode existing configuration: %w", err)
		}

		existingAllowedRoot = fc.AllowedRoot
	} else if !os.IsNotExist(err) {
		// Non-ENOENT error is operational failure.
		return fmt.Errorf("cannot stat existing configuration: %w", err)
	}

	// Canonicalize the allowed root for comparison.
	effectiveAllowedRoot, err := resolveAllowedRoot(allowedRoot)
	if err != nil {
		return err
	}

	// Preflight 3: check for mismatch with existing config.
	if configExists && existingAllowedRoot != "" {
		existingCanonical, err := resolveAllowedRoot(existingAllowedRoot)
		if err != nil {
			return fmt.Errorf("cannot canonicalize existing allowed_root: %w", err)
		}
		if existingCanonical != effectiveAllowedRoot {
			return &inputError{msg: fmt.Sprintf("existing configuration allowed_root is %s, but init requested %s", existingCanonical, effectiveAllowedRoot)}
		}
	}

	// All preflight passed. Now modify AppArmor.
	appArmorResult, err := addRoot(effectiveAllowedRoot)
	if err != nil {
		return err
	}

	// Run core init.
	err = core(allowedRoot, stdout, stderr)
	if err != nil {
		// Rollback AppArmor if we added a new root.
		if appArmorResult.Changed {
			_, rollbackErr := removeRoot(appArmorResult.Path)
			if rollbackErr != nil {
				return fmt.Errorf("init failed: %w; AppArmor rollback also failed: %v", err, rollbackErr)
			}
		}
		return err
	}

	// Print AppArmor status after successful init.
	if appArmorResult.Changed {
		fmt.Fprintf(stdout, "AppArmor workspace root added: %s\n", appArmorResult.Path)
	} else {
		fmt.Fprintf(stdout, "AppArmor workspace root already present: %s\n", appArmorResult.Path)
	}

	return nil
}

// initSystemSELinux performs system-mode initialization under SELinux
// without AppArmor root management. It performs the same preflight checks
// as initSystemWithAppArmor but skips the AppArmor-specific steps.
// core is the file-based init function (injectable for testing).
func initSystemSELinux(allowedRoot string, stdout, stderr io.Writer,
	core func(string, io.Writer, io.Writer) error,
) error {
	configPath := getConfigPathFunc()
	configDir := filepath.Dir(configPath)
	adminTokenPath := filepath.Join(configDir, "admin.token")

	// Preflight 1: check existing admin.token.
	if _, err := os.Stat(adminTokenPath); err == nil {
		fmt.Fprintln(stderr, "admin.token already exists at:")
		fmt.Fprintln(stderr, adminTokenPath)
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Will not overwrite. Use `docker-helper admin token rotate` to replace it.")
		return errors.New("admin.token already exists")
	}

	// Preflight 2: read existing config if present to check for mismatch.
	var existingAllowedRoot string
	configExists := false

	if stat, err := os.Stat(configPath); err == nil {
		if stat.IsDir() {
			return fmt.Errorf("configuration path is a directory: %s", configPath)
		}
		configExists = true
		data, err := os.ReadFile(configPath)
		if err != nil {
			return fmt.Errorf("cannot read existing configuration: %w", err)
		}

		var raw map[string]json.RawMessage
		if err := json.Unmarshal(data, &raw); err != nil {
			return fmt.Errorf("cannot parse existing configuration: %w", err)
		}
		if err := validateRawConfig(raw); err != nil {
			return fmt.Errorf("existing configuration is invalid: %w", err)
		}

		var fc fileConfig
		if err := json.Unmarshal(data, &fc); err != nil {
			return fmt.Errorf("cannot decode existing configuration: %w", err)
		}

		existingAllowedRoot = fc.AllowedRoot
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("cannot stat existing configuration: %w", err)
	}

	// Canonicalize the allowed root for comparison.
	effectiveAllowedRoot, err := resolveAllowedRoot(allowedRoot)
	if err != nil {
		return err
	}

	// Preflight 3: check for mismatch with existing config.
	if configExists && existingAllowedRoot != "" {
		existingCanonical, err := resolveAllowedRoot(existingAllowedRoot)
		if err != nil {
			return fmt.Errorf("cannot canonicalize existing allowed_root: %w", err)
		}
		if existingCanonical != effectiveAllowedRoot {
			return &inputError{msg: fmt.Sprintf("existing configuration allowed_root is %s, but init requested %s", existingCanonical, effectiveAllowedRoot)}
		}
	}

	// Run core init.
	return core(allowedRoot, stdout, stderr)
}

// runInit orchestrates the initialization process based on deployment mode.
func runInit(allowedRoot string, stdout, stderr io.Writer) error {
	if allowedRoot == "" {
		var err error
		allowedRoot, err = os.Getwd()
		if err != nil {
			return fmt.Errorf("cannot determine current working directory: %w", err)
		}
	}

	mode := resolveDeploymentMode()

	if mode == ModeUser {
		// User mode: check if system daemon is running.
		if systemSocketExists() {
			return initUserWithSystemDaemon(stdout, stderr)
		}
		// No system daemon: check Docker access.
		if err := checkDockerAccess(); err != nil {
			return fmt.Errorf("no system daemon and cannot connect to Docker daemon: %w", err)
		}
		// Docker accessible: standalone user init with admin token.
		_, err := initCore(allowedRoot, stdout, stderr)
		return err
	}

	// System mode: dispatch by MAC backend.
	backend, err := detectLSM()
	if err != nil {
		return fmt.Errorf("system mode requires an active MAC backend: %w", err)
	}
	if backend == LSMNone {
		return fmt.Errorf("no MAC backend active (system mode requires AppArmor or enforcing SELinux)")
	}

	switch backend {
	case LSMAppArmor:
		return initSystemWithAppArmor(allowedRoot, stdout, stderr,
			getAppArmorAddRoot(),
			getAppArmorRemoveRoot(),
			func(ar string, so, se io.Writer) error {
				_, err := initCore(ar, so, se)
				return err
			},
		)
	case LSMSelinux:
		return initSystemSELinux(allowedRoot, stdout, stderr,
			func(ar string, so, se io.Writer) error {
				_, err := initCore(ar, so, se)
				return err
			},
		)
	default:
		return fmt.Errorf("unknown MAC backend: %s", backend)
	}
}

// checkDockerAccess checks if the Docker daemon is reachable by connecting
// to its Unix socket directly. Returns nil if Docker is accessible.
// Can be replaced in tests.
var checkDockerAccess = func() error {
	paths := []string{"/run/docker.sock", "/var/run/docker.sock"}
	if host := os.Getenv("DOCKER_HOST"); strings.HasPrefix(host, "unix://") {
		paths = []string{strings.TrimPrefix(host, "unix://")}
	}
	for _, p := range paths {
		conn, err := net.DialTimeout("unix", p, time.Second)
		if err == nil {
			conn.Close()
			return nil
		}
	}
	return errors.New("cannot connect to Docker daemon")
}

// initUserWithSystemDaemon prompts for a credential token and installs it
// for use with the system daemon. This is used when the user runs init
// but the system daemon is already running.
func initUserWithSystemDaemon(stdout, stderr io.Writer) error {
	fmt.Fprintln(stderr, "System daemon detected.")
	fmt.Fprintln(stderr, "Enter credential token provided by the admin:")

	isTerminal := term.IsTerminal(int(os.Stdin.Fd()))
	var token string
	var err error
	if isTerminal {
		token, err = readTokenHidden("Credential token: ", stderr)
	} else {
		token, err = readTokenFromReader(os.Stdin)
	}
	if err != nil {
		return err
	}

	if err := validateCredentialToken(token); err != nil {
		return err
	}

	// Check if same token is already installed.
	if verifyCredentialToken(token) == nil {
		fmt.Fprintln(stdout, "Credential already installed.")
		return nil
	}

	// Install credential.
	credPath, err := installCredential(credentialInstallConfig{
		reader:     strings.NewReader(token),
		writer:     safeWriteCredential,
		uid:        EffectiveUID,
		isTerminal: func() bool { return isTerminal },
		readPassword: func() (string, error) {
			return token, nil
		},
		force: false,
	})
	if err != nil {
		if errors.Is(err, ErrCredentialAlreadyExists) {
			fmt.Fprintln(stderr, "Use --force to replace the existing credential.")
		}
		return err
	}

	fmt.Fprintln(stdout, "Credential installed successfully.")
	fmt.Fprintf(stdout, "Stored at: %s\n", credPath)
	return nil
}

// appArmorAddRoot and appArmorRemoveRoot are injectable production seams
// for testing CLI exit codes without requiring real AppArmor.
var (
	appArmorAddRoot = func() func(string) (rootResult, error) {
		return func(path string) (rootResult, error) {
			mgr := newProductionApparmorManager()
			return mgr.addRoot(path)
		}
	}
	appArmorRemoveRoot = func() func(string) (rootResult, error) {
		return func(path string) (rootResult, error) {
			mgr := newProductionApparmorManager()
			return mgr.removeRoot(path)
		}
	}
)

func getAppArmorAddRoot() func(string) (rootResult, error) {
	return appArmorAddRoot()
}

func getAppArmorRemoveRoot() func(string) (rootResult, error) {
	return appArmorRemoveRoot()
}

// resolveAllowedRoot normalizes and validates an allowed-root path.
// It expands ~/ prefixes, resolves to an absolute canonical path,
// and verifies that the path exists and is a directory.
// The caller must provide a non-empty path.
func resolveAllowedRoot(path string) (string, error) {
	return canonicalizeWorkspaceRootForAdd(path)
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
		if isReadOnlyField(field) {
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
// It validates the CA file without requiring
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

	caData, err := readValidatedCAFile(caPath)
	if err != nil {
		return err
	}

	// Compute the openssl-compatible hash to verify the certificate is valid.
	cert, err := validateCAPEM(caData)
	if err != nil {
		return err
	}
	computeOpenSSLHash(cert)

	return nil
}
