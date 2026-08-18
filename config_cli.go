package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

var configCommand = &Command{
	Name:    "config",
	Summary: "Inspect and modify configuration",
	Subcommands: []*Command{
		configShowCommand,
		configSetCommand,
		configUnsetCommand,
	},
}

// deprecatedFieldMessage returns the rename diagnostic for a deprecated field.
func deprecatedFieldMessage(name string) string {
	if newField, ok := deprecatedConfigFields[name]; ok {
		return fmt.Sprintf("error: %s was renamed to %s\n", name, newField)
	}
	return ""
}

func isRuntimeDependent(name string) bool {
	switch name {
	case "runtime_dir", "socket_path", "lock_path":
		return true
	default:
		return false
	}
}

// isPureComputed returns true for fields that can be resolved without
// reading config.json (config_path, config_dir, admin_token_path, mode).
func isPureComputed(name string) bool {
	switch name {
	case "config_path", "config_dir", "admin_token_path", "mode":
		return true
	default:
		return false
	}
}

var configShowCommand = &Command{
	Name:       "show",
	Summary:    "Show configuration values",
	Usage:      "docker-helper config show [FIELD]",
	MinPosArgs: 0,
	MaxPosArgs: 1,
	Help: `Without FIELD, prints the complete effective configuration as JSON.
With FIELD, prints only that field's scalar value followed by a newline.

The general JSON output redacts admin_token.
"config show admin_token" intentionally prints the complete real token.

Fields:
  allowed_root
  session_ttl
  log_level
  audit_enabled
  audit_enabled_source
  config_path
  config_dir
  runtime_dir
  socket_path
  lock_path
  state_dir
  database_path
  admin_token_path
  admin_token
  shutdown_timeout
  operation_retention_ttl
  operation_max_completed
  operation_log_max_bytes
  trusted_ca_path
  trusted_ca_injection
  mode
  http_address`,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				args := fs.Args()
				if len(args) == 0 {
					return configShowAll(stdout, stderr)
				}
				return configShowField(args[0], stdout, stderr)
			},
		}
	},
}

var configSetCommand = &Command{
	Name:       "set",
	Summary:    "Set a configuration value",
	Usage:      "docker-helper config set FIELD VALUE",
	MinPosArgs: 2,
	MaxPosArgs: 2,
	Help: `Writable fields:
  allowed_root            non-empty absolute path (required)
  session_ttl             positive Go duration, for example 30m or 12h (required)
  log_level               debug, info, warn, or error
  audit_enabled           true or false
  shutdown_timeout        positive Go duration, for example 30s (default 30s)
  operation_retention_ttl positive Go duration, for example 10m (default 10m)
  operation_max_completed positive integer (default 200)
  operation_log_max_bytes positive integer, bytes (default 4194304 = 4 MiB)
  trusted_ca_path         absolute path to a single PEM X.509 CA file (optional)
  trusted_ca_injection    "disabled" or "auto" (default "disabled")
  http_address            127.0.0.1:PORT, system mode only, restart required

Trusted CA injection:
  To enable, set trusted_ca_path first, then set trusted_ca_injection to auto.
  The host "openssl" binary must be available in PATH.
  CA injection only affects containers started via POST /run.

To disable, set trusted_ca_injection to disabled first, then optionally
unset trusted_ca_path.

http_address is startup-only: the change is written to disk and
requires a daemon restart to take effect.

A successful command reports either "updated" or "unchanged".
If the daemon is running, the change is applied immediately,
except for startup-only fields such as http_address.
If the daemon is not running, the change is written to disk and
will apply on the next start.`,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				args := fs.Args()
				return configSet(args[0], args[1], stdout, stderr)
			},
		}
	},
}

var configUnsetCommand = &Command{
	Name:       "unset",
	Summary:    "Unset a configuration value",
	Usage:      "docker-helper config unset FIELD",
	MinPosArgs: 1,
	MaxPosArgs: 1,
	Help: `Unsettable fields:
  log_level               removing it restores the effective default info
  audit_enabled           removing it restores behavior derived from log_level
  shutdown_timeout        removing it restores the default 30s
  operation_retention_ttl removing it restores the default 10m
  operation_max_completed removing it restores the default 200
  operation_log_max_bytes removing it restores the default 4 MiB
  trusted_ca_path         removing it clears the CA file path
  trusted_ca_injection    removing it restores the default "disabled"
  http_address            removing it restores the default 127.0.0.1:52375

trusted_ca_path cannot be unset while trusted_ca_injection is "auto".
Set trusted_ca_injection to "disabled" first.

http_address is startup-only: unsetting it requires a daemon restart
to take effect. The default 127.0.0.1:52375 is restored after restart.

A successful command reports either "unset" or "unchanged".
If the daemon is running, the change is applied immediately,
except for startup-only fields such as http_address.
If the daemon is not running, the change is written to disk and
will apply on the next start.`,
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				args := fs.Args()
				return configUnset(args[0], stdout, stderr)
			},
		}
	},
}

// loadRawConfig reads config.json from disk as a raw JSON map.
// It parses the top-level JSON object and returns the raw map and config path.
// Semantic validation (reserved fields, deprecated fields, value constraints)
// is performed by validateRawConfig, not by this function.
// Returns the raw map, the config file path, and any error.
func loadRawConfig() (map[string]json.RawMessage, string, error) {
	configPath := getConfigPath()
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, "", err
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, "", err
	}
	if raw == nil {
		return nil, "", fmt.Errorf("configuration is not a JSON object")
	}

	return raw, configPath, nil
}

// decodeFileConfig decodes a raw config map into a fileConfig struct.
// It does not perform disk I/O.
func decodeFileConfig(raw map[string]json.RawMessage) (*fileConfig, error) {
	data, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	var fc fileConfig
	if err := json.Unmarshal(data, &fc); err != nil {
		return nil, err
	}
	return &fc, nil
}

func safeWriteConfig(configPath string, data []byte) error {
	dir := filepath.Dir(configPath)
	tmp, err := os.CreateTemp(dir, "config-*.json.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, configPath); err != nil {
		os.Remove(tmpName)
		return err
	}
	return nil
}

// persistRawConfig validates, encodes, and atomically writes the raw config.
func persistRawConfig(configPath string, raw map[string]json.RawMessage) error {
	if err := validateRawConfig(raw); err != nil {
		return err
	}
	if err := validateCAConfig(raw); err != nil {
		return err
	}
	data, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return fmt.Errorf("cannot encode JSON: %w", err)
	}
	data = append(data, '\n')
	return safeWriteConfig(configPath, data)
}

func getRuntimeDirSafe() string {
	if resolveDeploymentMode() == ModeSystem {
		return "/run/docker-helper"
	}
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, "docker-helper")
}

func configShowAll(stdout, stderr io.Writer) int {
	raw, configPath, err := loadRawConfig()
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	if err := validateRawConfig(raw); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	fc, err := decodeFileConfig(raw)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	ec := resolveEffectiveConfig(*fc)

	configDir := filepath.Dir(configPath)
	runtimeDir := getRuntimeDirSafe()
	stateDir := getStateDir()
	socketPath := ""
	lockPath := ""
	if runtimeDir != "" {
		socketPath = filepath.Join(runtimeDir, "docker-helper.sock")
		lockPath = socketPath + ".lock"
	}
	databasePath := filepath.Join(stateDir, "docker-helper.db")
	adminTokenPath := filepath.Join(configDir, "admin.token")

	result := map[string]any{
		"allowed_root":            fc.AllowedRoot,
		"session_ttl":             fc.SessionTTL,
		"log_level":               ec.LogLevel,
		"audit_enabled":           ec.AuditEnabled,
		"audit_enabled_source":    ec.AuditEnabledSource,
		"config_path":             configPath,
		"config_dir":              configDir,
		"runtime_dir":             runtimeDir,
		"socket_path":             socketPath,
		"lock_path":               lockPath,
		"state_dir":               stateDir,
		"database_path":           databasePath,
		"admin_token_path":        adminTokenPath,
		"admin_token":             "<redacted>",
		"shutdown_timeout":        ec.ShutdownTimeout,
		"operation_retention_ttl": ec.OperationRetentionTTL,
		"operation_max_completed": ec.OperationMaxCompleted,
		"operation_log_max_bytes": ec.OperationLogMaxBytes,
		"trusted_ca_path":         fc.TrustedCAPath,
		"trusted_ca_injection":    ec.TrustedCAInjection,
		"mode":                    resolveDeploymentMode(),
		"http_address":            ec.HTTPAddress,
	}

	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(result); err != nil {
		fmt.Fprintf(stderr, "error: cannot encode JSON: %v\n", err)
		return 1
	}
	return 0
}

// resolveHTTPAddress returns the effective HTTP address.
// If the configured value is empty, returns the default for system mode or empty for user mode.
func resolveHTTPAddress(configured string) string {
	if configured != "" {
		return configured
	}
	if resolveDeploymentMode() == ModeSystem {
		return DefaultHTTPAddress
	}
	return ""
}

func configShowField(field string, stdout, stderr io.Writer) int {
	if msg := deprecatedFieldMessage(field); msg != "" {
		fmt.Fprint(stderr, msg)
		return 2
	}
	if !isKnownField(field) {
		fmt.Fprintf(stderr, "error: unknown field %q\n", field)
		return 2
	}

	// Bootstrap fields: never parse config.json.
	// admin_token reads only the token file.
	if field == "admin_token" {
		configPath := getConfigPath()
		configDir := filepath.Dir(configPath)
		adminTokenPath := filepath.Join(configDir, "admin.token")
		data, err := os.ReadFile(adminTokenPath)
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
		token := strings.TrimSpace(string(data))
		if token == "" {
			fmt.Fprintf(stderr, "error: admin token file is empty\n")
			return 1
		}
		fmt.Fprintln(stdout, token)
		return 0
	}

	// Pure computed fields: resolve from paths without reading config.json.
	if isPureComputed(field) {
		configPath := getConfigPath()
		configDir := filepath.Dir(configPath)
		switch field {
		case "config_path":
			fmt.Fprintln(stdout, configPath)
		case "config_dir":
			fmt.Fprintln(stdout, configDir)
		case "admin_token_path":
			fmt.Fprintln(stdout, filepath.Join(configDir, "admin.token"))
		case "mode":
			fmt.Fprintln(stdout, resolveDeploymentMode())
		}
		return 0
	}

	// All other fields: single read of config.json.
	raw, _, err := loadRawConfig()
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	if err := validateRawConfig(raw); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	// http_address: resolve from config, with default.
	if field == "http_address" {
		fc, err := decodeFileConfig(raw)
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
		fmt.Fprintln(stdout, resolveHTTPAddress(fc.HTTPAddress))
		return 0
	}

	// Runtime-dependent fields: validate config first, then check XDG_RUNTIME_DIR.
	// In system mode, runtime dir is always available (/run/docker-helper).
	if isRuntimeDependent(field) {
		runtimeDir := getRuntimeDirSafe()
		if runtimeDir == "" {
			fmt.Fprintf(stderr, "error: XDG_RUNTIME_DIR is not set, cannot determine %s\n", field)
			return 1
		}
		switch field {
		case "runtime_dir":
			fmt.Fprintln(stdout, runtimeDir)
		case "socket_path":
			fmt.Fprintln(stdout, filepath.Join(runtimeDir, "docker-helper.sock"))
		case "lock_path":
			fmt.Fprintln(stdout, filepath.Join(runtimeDir, "docker-helper.sock.lock"))
		}
		return 0
	}

	// Config-backed fields: decode from raw (already validated above).
	fc, err := decodeFileConfig(raw)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	ec := resolveEffectiveConfig(*fc)

	stateDir := getStateDir()

	switch field {
	case "allowed_root":
		fmt.Fprintln(stdout, fc.AllowedRoot)
	case "session_ttl":
		fmt.Fprintln(stdout, fc.SessionTTL)
	case "log_level":
		fmt.Fprintln(stdout, ec.LogLevel)
	case "audit_enabled":
		fmt.Fprintln(stdout, ec.AuditEnabled)
	case "audit_enabled_source":
		fmt.Fprintln(stdout, ec.AuditEnabledSource)
	case "state_dir":
		fmt.Fprintln(stdout, stateDir)
	case "database_path":
		fmt.Fprintln(stdout, filepath.Join(stateDir, "docker-helper.db"))
	case "shutdown_timeout":
		fmt.Fprintln(stdout, ec.ShutdownTimeout)
	case "operation_retention_ttl":
		fmt.Fprintln(stdout, ec.OperationRetentionTTL)
	case "operation_max_completed":
		fmt.Fprintln(stdout, ec.OperationMaxCompleted)
	case "operation_log_max_bytes":
		fmt.Fprintln(stdout, ec.OperationLogMaxBytes)
	case "trusted_ca_path":
		fmt.Fprintln(stdout, fc.TrustedCAPath)
	case "trusted_ca_injection":
		fmt.Fprintln(stdout, ec.TrustedCAInjection)
	default:
		fmt.Fprintf(stderr, "error: unknown field %q\n", field)
		return 2
	}
	return 0
}

func configSet(field, value string, stdout, stderr io.Writer) int {
	if msg := deprecatedFieldMessage(field); msg != "" {
		fmt.Fprint(stderr, msg)
		return 2
	}
	if !isKnownField(field) {
		fmt.Fprintf(stderr, "error: unknown field %q\n", field)
		return 2
	}
	if isReadOnlyField(field) {
		fmt.Fprintf(stderr, "error: field %q is read-only\n", field)
		return 2
	}

	switch field {
	case "allowed_root":
		if value == "" {
			fmt.Fprintf(stderr, "error: allowed_root must be a non-empty path\n")
			return 2
		}
		if !filepath.IsAbs(value) {
			fmt.Fprintf(stderr, "error: allowed_root must be a non-empty absolute path\n")
			return 2
		}
		canonical, err := canonicalizeWorkspaceRootForAdd(value)
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 2
		}
		// Persist the canonical form so the stored value cannot later be
		// retargeted through symlink manipulation.
		value = canonical
	case "session_ttl":
		if _, err := time.ParseDuration(value); err != nil {
			fmt.Fprintf(stderr, "error: invalid duration %q: %v\n", value, err)
			return 2
		}
		if d, _ := time.ParseDuration(value); d <= 0 {
			fmt.Fprintf(stderr, "error: session_ttl must be a positive duration\n")
			return 2
		}
	case "log_level":
		if _, err := parseLogLevel(value); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 2
		}
	case "audit_enabled":
		if value != "true" && value != "false" {
			fmt.Fprintf(stderr, "error: audit_enabled must be true or false\n")
			return 2
		}
	case "shutdown_timeout":
		if _, err := parseDurationPositive(value, "shutdown_timeout"); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 2
		}
	case "operation_retention_ttl":
		if _, err := parseDurationPositive(value, "operation_retention_ttl"); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 2
		}
	case "operation_max_completed":
		var n int
		if _, err := fmt.Sscanf(value, "%d", &n); err != nil || n <= 0 {
			fmt.Fprintf(stderr, "error: operation_max_completed must be a positive integer\n")
			return 2
		}
	case "operation_log_max_bytes":
		var n int64
		if _, err := fmt.Sscanf(value, "%d", &n); err != nil || n <= 0 {
			fmt.Fprintf(stderr, "error: operation_log_max_bytes must be a positive integer\n")
			return 2
		}
	case "trusted_ca_path":
		if value != "" && !filepath.IsAbs(value) {
			fmt.Fprintf(stderr, "error: trusted_ca_path must be an absolute path\n")
			return 2
		}
	case "trusted_ca_injection":
		if value != "disabled" && value != "auto" {
			fmt.Fprintf(stderr, "error: trusted_ca_injection must be \"disabled\" or \"auto\"\n")
			return 2
		}
	case "http_address":
		if resolveDeploymentMode() != ModeSystem {
			fmt.Fprintln(stderr, "error: http_address is only used in system mode")
			return 2
		}
		if err := validateHTTPAddress(value); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 2
		}
	}

	raw, configPath, err := loadRawConfig()
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	// Compute the JSON-encoded value for the field.
	var newValue json.RawMessage
	switch field {
	case "allowed_root":
		newValue, _ = json.Marshal(value)
	case "session_ttl":
		newValue, _ = json.Marshal(value)
	case "log_level":
		newValue, _ = json.Marshal(value)
	case "audit_enabled":
		newValue, _ = json.Marshal(value == "true")
	case "shutdown_timeout":
		newValue, _ = json.Marshal(value)
	case "operation_retention_ttl":
		newValue, _ = json.Marshal(value)
	case "operation_max_completed":
		var n int
		fmt.Sscanf(value, "%d", &n)
		newValue, _ = json.Marshal(n)
	case "operation_log_max_bytes":
		var n int64
		fmt.Sscanf(value, "%d", &n)
		newValue, _ = json.Marshal(n)
	case "trusted_ca_path":
		newValue, _ = json.Marshal(value)
	case "trusted_ca_injection":
		newValue, _ = json.Marshal(value)
	case "http_address":
		newValue, _ = json.Marshal(value)
	}

	// Compare with the existing explicit JSON member.
	if existing, ok := raw[field]; ok && bytes.Equal(existing, newValue) {
		// Validate the existing configuration before returning unchanged.
		if err := validateRawConfig(raw); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
		if err := validateCAConfig(raw); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "unchanged %s=%s\n", field, value)
		return 0
	}

	raw[field] = newValue

	exitCode, daemonNotRunning := applyConfigChangeTransactionally(
		configPath,
		field,
		value,
		func() ([]byte, error) {
			encoded, _ := json.MarshalIndent(raw, "", "  ")
			return append(encoded, '\n'), nil
		},
		stdout,
		stderr,
	)
	if exitCode != 0 {
		return exitCode
	}
	fmt.Fprintf(stdout, "updated %s=%s\n", field, value)
	if field == "http_address" {
		fmt.Fprintln(stdout, "restart required")
	} else if daemonNotRunning {
		fmt.Fprintln(stdout, "daemon not running; change will apply on next start")
	}
	return 0
}

func configUnset(field string, stdout, stderr io.Writer) int {
	if msg := deprecatedFieldMessage(field); msg != "" {
		fmt.Fprint(stderr, msg)
		return 2
	}
	if !isKnownField(field) {
		fmt.Fprintf(stderr, "error: unknown field %q\n", field)
		return 2
	}
	if isReadOnlyField(field) {
		fmt.Fprintf(stderr, "error: field %q is read-only\n", field)
		return 2
	}
	if isRequiredField(field) {
		fmt.Fprintf(stderr, "error: field %q is required and cannot be unset\n", field)
		return 2
	}

	raw, configPath, err := loadRawConfig()
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	// Check if the member is already absent.
	if _, ok := raw[field]; !ok {
		// Validate the existing configuration before returning unchanged.
		if err := validateRawConfig(raw); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
		if err := validateCAConfig(raw); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "unchanged %s is already unset\n", field)
		return 0
	}

	delete(raw, field)

	exitCode, daemonNotRunning := applyConfigChangeTransactionally(
		configPath,
		field,
		"",
		func() ([]byte, error) {
			encoded, _ := json.MarshalIndent(raw, "", "  ")
			return append(encoded, '\n'), nil
		},
		stdout,
		stderr,
	)
	if exitCode != 0 {
		return exitCode
	}
	fmt.Fprintln(stdout, "unset", field)
	if field == "http_address" {
		fmt.Fprintln(stdout, "restart required")
	} else if daemonNotRunning {
		fmt.Fprintln(stdout, "daemon not running; change will apply on next start")
	}
	return 0
}

// configChangeLockPath returns the lock file path for serializing config
// mutations across processes. It sits beside the config file.
func configChangeLockPath(configPath string) string {
	return configPath + ".lock"
}

// acquireConfigChangeLock opens the lock file and acquires an exclusive
// non-blocking flock. Returns the open file that must stay open for the lock
// to remain held, or an error if another process holds it.
func acquireConfigChangeLock(configPath string) (*os.File, error) {
	f, err := os.OpenFile(configChangeLockPath(configPath), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("cannot open config lock: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if err == syscall.EWOULDBLOCK {
			return nil, errors.New("another config operation is in progress")
		}
		return nil, fmt.Errorf("cannot acquire config lock: %w", err)
	}
	return f, nil
}

// reloadResult captures the outcome of a transactional reload attempt.
type reloadResult int

const (
	reloadSuccess          reloadResult = iota // daemon accepted the new config
	reloadDaemonNotRunning                     // daemon is not running
	reloadRejected                             // daemon rejected (HTTP 4xx/5xx)
	reloadTransportError                       // transport error (not daemon-not-running)
)

// applyConfigChangeTransactionally performs the atomic write + reload + rollback
// transaction for a config set/unset operation.
//
// It returns (exitCode, daemonWasNotRunning).
// The caller prints "updated"/"unset" before the daemon-not-running message
// to avoid false success output on rollback.
func applyConfigChangeTransactionally(
	configPath string,
	field string,
	value string,
	encodeNew func() ([]byte, error),
	stdout, stderr io.Writer,
) (int, bool) {
	// Acquire process-level lock.
	lockFile, err := acquireConfigChangeLock(configPath)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1, false
	}
	defer lockFile.Close()

	// Save original bytes for rollback.
	original, err := os.ReadFile(configPath)
	if err != nil {
		fmt.Fprintf(stderr, "error: cannot read current config: %v\n", err)
		return 1, false
	}

	// Encode new config.
	newData, err := encodeNew()
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1, false
	}

	// Validate the new config before writing. We re-parse it to exercise
	// the same validation path as persistRawConfig.
	var newRaw map[string]json.RawMessage
	if err := json.Unmarshal(newData, &newRaw); err != nil {
		fmt.Fprintf(stderr, "error: cannot parse new config: %v\n", err)
		return 1, false
	}
	if err := validateRawConfig(newRaw); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1, false
	}
	if err := validateCAConfig(newRaw); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1, false
	}

	// Atomically write new config.
	if err := safeWriteConfig(configPath, newData); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1, false
	}

	// http_address is startup-only: no reload.
	if field == "http_address" {
		return 0, false
	}

	// Attempt reload.
	result := attemptReload(stdout, stderr)
	switch result {
	case reloadSuccess:
		return 0, false
	case reloadDaemonNotRunning:
		return 0, true
	case reloadRejected, reloadTransportError:
		// Rollback: restore original bytes.
		if rollErr := safeWriteConfig(configPath, original); rollErr != nil {
			fmt.Fprintf(stderr, "error: reload failed and rollback failed: %v; rollback: %v\n",
				rollErr, "cannot restore config.json")
			return 1, false
		}

		// Re-reload to synchronize runtime with restored file.
		reReloadResult := attemptReloadQuiet()
		rollbackMsg := ""
		if reReloadResult == reloadRejected || reReloadResult == reloadTransportError {
			rollbackMsg = "; re-reload after rollback also failed"
		}

		fmt.Fprintf(stderr, "error: config change rolled back%v\n", rollbackMsg)
		return 1, false
	}

	return 0, false
}

// attemptReload calls POST /reload and returns a structured result.
// It prints warnings to stderr on rejection/transport error.
func attemptReload(stdout, stderr io.Writer) reloadResult {
	client, resolveErr := resolveOperatorClient(operatorClientOptions{})
	if resolveErr != nil {
		// Cannot construct client (missing runtime dir, token, etc.).
		// This is a local error, NOT proof the daemon is not running.
		// Treat as transport error so rollback triggers.
		fmt.Fprintf(stderr, "warning: reload failed: %v\n", resolveErr)
		return reloadTransportError
	}

	resp, reqErr := client.doAuthenticatedRequest("POST", "/reload", nil)
	if reqErr != nil {
		if isDaemonNotRunning(reqErr) {
			return reloadDaemonNotRunning
		}
		fmt.Fprintf(stderr, "warning: reload failed: %v\n", reqErr)
		return reloadTransportError
	}
	defer resp.Body.Close()

	_, bodyErr := client.readResponseBody(resp)
	if bodyErr != nil {
		fmt.Fprintf(stderr, "warning: reload failed: %v\n", bodyErr)
		return reloadRejected
	}

	return reloadSuccess
}

// attemptReloadQuiet is like attemptReload but does not print anything.
// Used for the re-reload after rollback.
func attemptReloadQuiet() reloadResult {
	client, resolveErr := resolveOperatorClient(operatorClientOptions{})
	if resolveErr != nil {
		return reloadTransportError
	}

	resp, reqErr := client.doAuthenticatedRequest("POST", "/reload", nil)
	if reqErr != nil {
		if isDaemonNotRunning(reqErr) {
			return reloadDaemonNotRunning
		}
		return reloadTransportError
	}
	defer resp.Body.Close()

	_, bodyErr := client.readResponseBody(resp)
	if bodyErr != nil {
		return reloadRejected
	}

	return reloadSuccess
}

// isDaemonNotRunning returns true if the error indicates the daemon
// is not listening on the socket. Only transport-level errors are
// checked; local errors (missing token, bad config) never qualify.
func isDaemonNotRunning(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "no such file") ||
		strings.Contains(msg, "no such file or directory")
}
