package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// runReload is the CLI entry point for the reload command.
func runReload(stdout, stderr io.Writer) int {
	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	tokenSource, err := func() (func() (string, error), error) {
		src, err := readAdminTokenPlain(cfg.AdminTokenPath)
		if err != nil {
			return nil, err
		}
		return func() (string, error) { return src, nil }, nil
	}()
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	client := newReloadClient(cfg.SocketPath, tokenSource)
	if err := client.reload(); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	fmt.Fprintln(stdout, "reloaded")
	return 0
}

// handleReload reloads the configuration from disk and updates the daemon's
// runtime configuration. Only configurable fields are updated:
// allowed_root, session_ttl, log_level, audit_enabled.
// Computed paths (socket, database, etc.) remain unchanged.
//
// If the new configuration is invalid, the daemon keeps its current
// configuration and returns an error.
func (a *App) handleReload(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdmin(w, r) {
		return
	}

	newCfg, err := loadConfig()
	if err != nil {
		writeError(r.Context(), w, http.StatusBadRequest,
			"invalid_config",
			fmt.Sprintf("cannot load configuration: %v", err),
		)
		return
	}

	a.setConfig(newCfg)

	// Re-initialize loggers with the new log level and audit setting.
	// This updates opLogger and auditWriter in place.
	initLoggers(opWriter, auditWriter, newCfg.LogLevel, newCfg.AuditEnabled)

	if opLogger != nil {
		opLogger.Info("configuration reloaded",
			slog.String("allowed_root", newCfg.AllowedRoot),
			slog.String("session_ttl", newCfg.SessionTTL.String()),
			slog.String("log_level", newCfg.LogLevel.String()),
			slog.Bool("audit_enabled", newCfg.AuditEnabled),
		)
	}

	writeJSON(r.Context(), w, http.StatusOK, response{
		OK:      true,
		Message: "configuration reloaded",
	})
}

// reloadClient provides the CLI-side HTTP client for the reload endpoint.
type reloadClient struct {
	client *apiClient
}

func newReloadClient(socketPath string, tokenSource func() (string, error)) *reloadClient {
	return &reloadClient{
		client: newUnixAPIClientWithTimeout(socketPath, tokenSource, 5*time.Second),
	}
}

func (c *reloadClient) reload() error {
	resp, err := c.client.doAuthenticatedRequest("POST", "/reload", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("cannot read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var result map[string]any
		if jsonErr := json.Unmarshal(body, &result); jsonErr == nil {
			if msg, ok := result["message"].(string); ok {
				return fmt.Errorf("%s", msg)
			}
		}
		return fmt.Errorf("API error: status %d", resp.StatusCode)
	}

	return nil
}
