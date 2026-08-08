package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
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

var (
	writableFields = []string{"allowed_root", "session_ttl", "log_level", "audit_enabled"}
	requiredFields = map[string]bool{"allowed_root": true, "session_ttl": true}
	computedFields = map[string]bool{
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
	readOnlyFields = map[string]bool{
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
	allFields = []string{
		"allowed_root",
		"session_ttl",
		"log_level",
		"audit_enabled",
		"audit_enabled_source",
		"config_path",
		"config_dir",
		"runtime_dir",
		"socket_path",
		"lock_path",
		"state_dir",
		"database_path",
		"admin_token_path",
		"admin_token",
	}
)

func isKnownField(name string) bool {
	for _, f := range allFields {
		if f == name {
			return true
		}
	}
	return false
}

func isWritable(name string) bool {
	for _, f := range writableFields {
		if f == name {
			return true
		}
	}
	return false
}

func isRuntimeDependent(name string) bool {
	switch name {
	case "runtime_dir", "socket_path", "lock_path":
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
	NewInvocation: func(fs *flag.FlagSet) Invocation {
		return Invocation{
			Run: func(stdout, stderr io.Writer) int {
				args := fs.Args()
				return configUnset(args[0], stdout, stderr)
			},
		}
	},
}

func loadFileConfig() (*fileConfig, string, error) {
	configPath := getConfigPath()
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, "", err
	}
	var fc fileConfig
	if err := json.Unmarshal(data, &fc); err != nil {
		return nil, "", err
	}
	return &fc, configPath, nil
}

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
	return raw, configPath, nil
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

func getRuntimeDirSafe() string {
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, "docker-helper")
}

func configShowAll(stdout, stderr io.Writer) int {
	fc, configPath, err := loadFileConfig()
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

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

	level := fc.Level
	if level == "" {
		level = "info"
	}

	auditEnabled := resolveAuditEnabledForShow(fc.AuditEnabled, level)
	auditSource := "log_level"
	if fc.AuditEnabled != nil {
		auditSource = "explicit"
	}

	adminToken := "<redacted>"
	if data, err := os.ReadFile(adminTokenPath); err == nil {
		adminToken = "<redacted>"
		_ = data
	}

	result := map[string]any{
		"allowed_root":         fc.AllowedRoot,
		"session_ttl":          fc.SessionTTL,
		"log_level":            level,
		"audit_enabled":        auditEnabled,
		"audit_enabled_source": auditSource,
		"config_path":          configPath,
		"config_dir":           configDir,
		"runtime_dir":          runtimeDir,
		"socket_path":          socketPath,
		"lock_path":            lockPath,
		"state_dir":            stateDir,
		"database_path":        databasePath,
		"admin_token_path":     adminTokenPath,
		"admin_token":          adminToken,
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

func slogLevelFromString(s string) int {
	switch s {
	case "debug":
		return -4
	case "info":
		return 0
	case "warn":
		return 4
	case "error":
		return 8
	default:
		return 0
	}
}

func resolveAuditEnabledForShow(cfg *bool, levelStr string) bool {
	level := slogLevelFromString(levelStr)
	if cfg != nil {
		return *cfg
	}
	return level == -4
}

func configShowField(field string, stdout, stderr io.Writer) int {
	if !isKnownField(field) {
		fmt.Fprintf(stderr, "error: unknown field %q\n", field)
		return 2
	}

	if field == "admin_token" {
		configPath := getConfigPath()
		adminTokenPath := filepath.Join(filepath.Dir(configPath), "admin.token")
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

	fc, configPath, err := loadFileConfig()
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	configDir := filepath.Dir(configPath)
	stateDir := getStateDir()

	switch field {
	case "allowed_root":
		fmt.Fprintln(stdout, fc.AllowedRoot)
	case "session_ttl":
		fmt.Fprintln(stdout, fc.SessionTTL)
	case "log_level":
		level := fc.Level
		if level == "" {
			level = "info"
		}
		fmt.Fprintln(stdout, level)
	case "audit_enabled":
		level := fc.Level
		if level == "" {
			level = "info"
		}
		auditEnabled := resolveAuditEnabledForShow(fc.AuditEnabled, level)
		fmt.Fprintln(stdout, auditEnabled)
	case "audit_enabled_source":
		if fc.AuditEnabled != nil {
			fmt.Fprintln(stdout, "explicit")
		} else {
			fmt.Fprintln(stdout, "log_level")
		}
	case "config_path":
		fmt.Fprintln(stdout, configPath)
	case "config_dir":
		fmt.Fprintln(stdout, configDir)
	case "state_dir":
		fmt.Fprintln(stdout, stateDir)
	case "database_path":
		fmt.Fprintln(stdout, filepath.Join(stateDir, "docker-helper.db"))
	case "admin_token_path":
		fmt.Fprintln(stdout, filepath.Join(configDir, "admin.token"))
	default:
		fmt.Fprintf(stderr, "error: unknown field %q\n", field)
		return 2
	}
	return 0
}

func configSet(field, value string, stdout, stderr io.Writer) int {
	if !isKnownField(field) {
		fmt.Fprintf(stderr, "error: unknown field %q\n", field)
		return 2
	}
	if readOnlyFields[field] {
		fmt.Fprintf(stderr, "error: field %q is read-only\n", field)
		return 2
	}

	switch field {
	case "allowed_root":
		if value == "" || !filepath.IsAbs(value) {
			fmt.Fprintf(stderr, "error: allowed_root must be a non-empty absolute path\n")
			return 2
		}
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
	}

	raw, configPath, err := loadRawConfig()
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	switch field {
	case "allowed_root":
		raw["allowed_root"], _ = json.Marshal(value)
	case "session_ttl":
		raw["session_ttl"], _ = json.Marshal(value)
	case "log_level":
		raw["log_level"], _ = json.Marshal(value)
	case "audit_enabled":
		b, _ := json.Marshal(value == "true")
		raw["audit_enabled"] = b
	}

	data, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "error: cannot encode JSON: %v\n", err)
		return 1
	}
	data = append(data, '\n')

	if err := safeWriteConfig(configPath, data); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	return 0
}

func configUnset(field string, stdout, stderr io.Writer) int {
	if !isKnownField(field) {
		fmt.Fprintf(stderr, "error: unknown field %q\n", field)
		return 2
	}
	if readOnlyFields[field] {
		fmt.Fprintf(stderr, "error: field %q is read-only\n", field)
		return 2
	}
	if requiredFields[field] {
		fmt.Fprintf(stderr, "error: field %q is required and cannot be unset\n", field)
		return 2
	}

	raw, configPath, err := loadRawConfig()
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	delete(raw, field)

	data, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "error: cannot encode JSON: %v\n", err)
		return 1
	}
	data = append(data, '\n')

	if err := safeWriteConfig(configPath, data); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	return 0
}
