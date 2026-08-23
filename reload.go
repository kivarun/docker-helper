package main

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// runReload is the CLI entry point for the reload command.
func runReload(stdout, stderr io.Writer, opts operatorClientOptions) int {
	client, err := resolveOperatorClient(opts)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	resp, err := client.doAuthenticatedRequest("POST", "/reload", nil)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	defer resp.Body.Close()

	_, err = client.readResponseBody(resp)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	fmt.Fprintln(stdout, "reloaded")
	return 0
}

// reloadDeps are the production dependencies for handleReload.
// Tests may inject their own to avoid real filesystem or LSM calls.
type reloadDeps struct {
	loadConfig             func() (*Config, error)
	deploymentMode         func() DeploymentMode
	detectLSM              func() (LSMBackend, error)
	verifySELinuxWorkspace func(string) error
	apparmorListRoots      func() ([]string, error)
}

// handleReload reloads the configuration from disk and updates the daemon's
// runtime configuration. Configurable fields updated: allowed_roots,
// session_ttl, log_level, audit_enabled, shutdown_timeout,
// operation_retention_ttl, operation_max_completed, operation_log_max_bytes,
// trusted_ca_path, trusted_ca_injection.
// Computed paths (socket, database, etc.) and startup-only fields (http_address)
// remain unchanged.
//
// In system mode, verifies configured allowed_roots are usable under the
// active MAC backend (SELinux workspace labels or AppArmor managed roots).
//
// If the new configuration is invalid, the daemon keeps its current
// configuration and returns an error.
func (a *App) handleReload(w http.ResponseWriter, r *http.Request) {
	a.handleReloadWithDeps(w, r, reloadDeps{
		loadConfig:             loadConfig,
		deploymentMode:         resolveDeploymentMode,
		detectLSM:              detectLSM,
		verifySELinuxWorkspace: newSELinuxWorkspaceManager().verifyWorkspaceLabel,
		apparmorListRoots:      apparmorManagedRoots,
	})
}

// handleReloadWithDeps is the implementation of handleReload with
// injectable dependencies for testing.
func (a *App) handleReloadWithDeps(w http.ResponseWriter, r *http.Request, deps reloadDeps) {
	if !a.requireAdmin(w, r) {
		return
	}

	started := time.Now()
	ctx := r.Context()

	newCfg, err := deps.loadConfig()
	if err != nil {
		duration := time.Since(started).Round(time.Millisecond).String()
		diagnostic := "invalid configuration"
		var caErr *trustedCAPreparationError
		if errors.As(err, &caErr) {
			diagnostic = caErr.Error()
		}
		opLog(ctx).Error("reload config error",
			slog.String("operation", "reload"),
			slog.String("error", err.Error()),
			slog.String("diagnostic", diagnostic),
		)
		writeAuditWithRequestID(ctx, auditRecord{
			Event:    "config.reload",
			Result:   "invalid_config",
			Duration: duration,
		})
		writeError(ctx, w, http.StatusBadRequest,
			"invalid_config",
			diagnostic,
		)
		return
	}

	// System mode: verify configured allowed_roots are usable under the active MAC backend.
	if err := verifyAllowedRootsMAC(
		newCfg.AllowedRoots,
		deps.deploymentMode(),
		deps.detectLSM,
		deps.verifySELinuxWorkspace,
		deps.apparmorListRoots,
	); err != nil {
		duration := time.Since(started).Round(time.Millisecond).String()
		opLog(ctx).Error("reload MAC verification failed",
			slog.String("operation", "reload"),
			slog.String("error", err.Error()),
		)
		writeAuditWithRequestID(ctx, auditRecord{
			Event:    "config.reload",
			Result:   "mac_verification_failed",
			Duration: duration,
		})
		writeError(ctx, w, http.StatusBadRequest,
			"mac_verification_failed",
			err.Error(),
		)
		return
	}

	// Preserve startup-only fields that cannot be changed at runtime.
	oldCfg := a.getConfig()
	newCfg.HTTPAddress = oldCfg.HTTPAddress

	a.setConfig(newCfg)

	// Snapshot writers under read lock, then re-initialize loggers
	// with the new log level and audit setting under write lock.
	opW, audW := logging.snapshotWriters()

	// Capture old audit_enabled state before reconfiguring.
	oldAuditEnabled, _, _ := logging.snapshotAudit()

	// When audit is being disabled (true->false), write the success event
	// before reconfiguring so the record is actually emitted.
	if oldAuditEnabled && !newCfg.AuditEnabled {
		duration := time.Since(started).Round(time.Millisecond).String()
		writeAuditWithRequestID(ctx, auditRecord{
			Event:    "config.reload",
			Result:   "success",
			Duration: duration,
		})
		logging.configure(opW, audW, newCfg.LogLevel, newCfg.AuditEnabled)
	} else {
		logging.configure(opW, audW, newCfg.LogLevel, newCfg.AuditEnabled)
		duration := time.Since(started).Round(time.Millisecond).String()
		writeAuditWithRequestID(ctx, auditRecord{
			Event:    "config.reload",
			Result:   "success",
			Duration: duration,
		})
	}

	opLog(ctx).Info("configuration reloaded",
		slog.Any("allowed_roots", newCfg.AllowedRoots),
		slog.String("session_ttl", newCfg.SessionTTL.String()),
		slog.String("log_level", newCfg.LogLevel.String()),
		slog.Bool("audit_enabled", newCfg.AuditEnabled),
		slog.String("shutdown_timeout", newCfg.ShutdownTimeout.String()),
		slog.String("operation_retention_ttl", newCfg.OperationRetentionTTL.String()),
		slog.Int("operation_max_completed", newCfg.OperationMaxCompleted),
		slog.Int64("operation_log_max_bytes", newCfg.OperationLogMaxBytes),
		slog.String("trusted_ca_injection", newCfg.TrustedCAInjection),
		slog.String("trusted_ca_path", newCfg.TrustedCAPath),
	)

	writeJSON(r.Context(), w, http.StatusOK, response{
		OK:      true,
		Message: "configuration reloaded",
	})
}

// verifyAllowedRootsMAC verifies that configured global allowed_roots are
// usable under the active MAC backend. It is the shared internal verifier
// used by both runServe startup and handleReload.
//
// SELinux: /home roots require no managed label; non-home roots use
// verifyWorkspaceLabel.
//
// AppArmor: every configured global allowed root must be covered by at least
// one managed AppArmor root. Coverage means configured == managed or
// configured is a descendant of managed. Extra/stale managed roots are
// acceptable (confinement metadata, not authorization).
func verifyAllowedRootsMAC(
	roots []string,
	mode DeploymentMode,
	detectLSM func() (LSMBackend, error),
	verifySELinuxWorkspace func(string) error,
	apparmorListRoots func() ([]string, error),
) error {
	if mode != ModeSystem {
		return nil
	}

	backend, err := detectLSM()
	if err != nil {
		return err
	}

	switch backend {
	case LSMSelinux:
		for _, root := range roots {
			if isHomeRoot(root) {
				continue
			}
			if err := verifySELinuxWorkspace(root); err != nil {
				return err
			}
		}
		return nil

	case LSMAppArmor:
		managed, err := apparmorListRoots()
		if err != nil {
			return fmt.Errorf("cannot read managed AppArmor roots: %w", err)
		}
		for _, root := range roots {
			if isHomeRoot(root) {
				continue
			}
			if !apparmorRootCovered(root, managed) {
				return fmt.Errorf(
					"allowed root %s is not covered by managed AppArmor roots; add it via: docker-helper config allowed-root add %s",
					root, root,
				)
			}
		}
		return nil

	default:
		return nil
	}
}

// apparmorRootCovered returns true if root is covered by at least one
// managed AppArmor root. Coverage means root equals managed or root is
// a descendant of managed.
func apparmorRootCovered(root string, managed []string) bool {
	for _, m := range managed {
		if root == m {
			return true
		}
		if isProperDescendant(root, m) {
			return true
		}
	}
	return false
}
