package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

type Config struct {
	AllowedRoot    string
	SessionTTL     time.Duration
	LogLevel       slog.Level
	SocketPath     string
	LockPath       string
	StateDir       string
	DatabasePath   string
	AdminTokenPath string
}

type fileConfig struct {
	AllowedRoot string `json:"allowed_root"`
	SessionTTL  string `json:"session_ttl"`
	Level       string `json:"log_level,omitempty"`
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
	xdgConfig := os.Getenv("XDG_CONFIG_HOME")
	if xdgConfig == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		xdgConfig = filepath.Join(home, ".config")
	}

	return filepath.Join(xdgConfig, "docker-helper")
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

	var fc fileConfig

	if err := json.Unmarshal(data, &fc); err != nil {
		return nil, fmt.Errorf("cannot parse config: %w", err)
	}

	ttl, err := time.ParseDuration(fc.SessionTTL)
	if err != nil {
		return nil, fmt.Errorf("cannot parse session_ttl %q: %w", fc.SessionTTL, err)
	}

	level := slog.LevelInfo
	if fc.Level != "" {
		level, err = parseLogLevel(fc.Level)
		if err != nil {
			return nil, err
		}
	}

	runtimeDir, err := getRuntimeDir()
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(runtimeDir, 0700); err != nil {
		return nil, fmt.Errorf("cannot create runtime directory: %w", err)
	}

	stateDir := getStateDir()

	configDir := getConfigDir()

	adminTokenPath := filepath.Join(configDir, "admin.token")

	socketPath := filepath.Join(runtimeDir, "docker-helper.sock")

	return &Config{
		AllowedRoot:    fc.AllowedRoot,
		SessionTTL:     ttl,
		LogLevel:       level,
		SocketPath:     socketPath,
		LockPath:       socketPath + ".lock",
		StateDir:       stateDir,
		DatabasePath:   filepath.Join(stateDir, "docker-helper.db"),
		AdminTokenPath: adminTokenPath,
	}, nil
}

func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("cannot generate random bytes: %w", err)
	}
	return "dht_" + hex.EncodeToString(b), nil
}

func runInit() error {
	configDir := getConfigDir()
	stateDir := getStateDir()

	if err := os.MkdirAll(configDir, 0700); err != nil {
		return fmt.Errorf("cannot create config directory: %w", err)
	}

	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return fmt.Errorf("cannot create state directory: %w", err)
	}

	configPath := getConfigPath()

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		defaultConfig := fileConfig{
			AllowedRoot: "/home/michael/work/git",
			SessionTTL:  "12h",
			Level:       "info",
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
		fmt.Fprintln(os.Stderr, "admin.token already exists at:")
		fmt.Fprintln(os.Stderr, adminTokenPath)
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Will not overwrite. Use a future token rotation command to replace it.")
		return errors.New("admin.token already exists")
	}

	token, err := generateToken()
	if err != nil {
		return err
	}

	if err := os.WriteFile(adminTokenPath, []byte(token+"\n"), 0600); err != nil {
		return fmt.Errorf("cannot write admin token: %w", err)
	}

	fmt.Println("Docker Helper initialized successfully.")
	fmt.Println()
	fmt.Println("Admin token:")
	fmt.Println(token)
	fmt.Println()
	fmt.Println("Stored at:")
	fmt.Println(adminTokenPath)
	fmt.Println()
	fmt.Println("Configuration:")
	fmt.Println(configPath)

	return nil
}
