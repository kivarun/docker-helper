package main

// run_cleanup.go — the single cleanup owner for terminal run paths
// (Release 2.2 Phase 2.2.6).
//
// Every path where a Docker process/container may exist, and every path
// where it provably cannot, converges here. The staged progression is
// frozen (Release 2.2 MAC lifecycle):
//
//	container proven absent
//	  -> workload MAC state removed
//	  -> source pins removed
//	  -> durable workload ownership record/state removed
//	  -> workspace-use lease released
//	  -> cidfile removed
//
// The durable ownership record is removed only after every stage it
// anchors is positively proven done: until then it is the reconciliation
// retry marker that still binds the surviving helper state to the
// operation.
//
// A cleanup failure at any stage retains everything the failed stage
// depends on and is left to startup reconciliation; a cleanup failure is
// never silently turned into forgotten state.

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// containerAbsenceProofTimeout bounds the Docker queries of one
// container-absence proof so a stuck Docker daemon cannot block operation
// completion indefinitely.
const containerAbsenceProofTimeout = 10 * time.Second

// cleanupAfterRunProcess is the post-start terminal cleanup owner. The
// container-absence proof runs first: no workload MAC state, pin, or lease
// may be released while a correlated container may still run. User mode has
// no workload MAC state and keeps the existing behavior exactly.
func (a *App) cleanupAfterRunProcess(op *operation) {
	ctx := withSessionID(context.Background(), op.SessionID)

	if op.workloadMAC == nil {
		// User mode: application policy plus Docker/VFS, no workload MAC
		// state, no pins, no lease. Existing behavior, unchanged.
		cleanupCidfile(op)
		return
	}

	// Stage 1: prove container absence. One proven-owned correlated
	// container is force-removed through the existing Docker cleanup
	// mechanism and its absence is verified. An ambiguous or unverifiable
	// Docker state retains all dependent helper state, fail closed.
	proofCtx, cancel := context.WithTimeout(ctx, containerAbsenceProofTimeout)
	proofErr := a.proveRunContainerAbsent(proofCtx, op)
	cancel()
	if proofErr != nil {
		opLog(ctx).Error("container absence could not be proven — workload MAC state, pins, and lease intentionally retained",
			slog.String("operation", "run"),
			slog.String("operation_id", op.ID),
			slog.String("error", proofErr.Error()),
		)
		return
	}

	// Stage 2: release the workload MAC state.
	if err := op.workloadMAC.Cleanup(); err != nil {
		opLog(ctx).Error("workload MAC cleanup failed — dependent pins and workspace lease intentionally retained",
			slog.String("operation", "run"),
			slog.String("operation_id", op.ID),
			slog.String("error", err.Error()),
		)
		return
	}

	// Stage 3: release the source pins only after the MAC state that may
	// depend on them is gone.
	cleanupErr := cleanupPinnedMounts(op)
	if cleanupErr != nil {
		opLog(ctx).Error("pinned mount cleanup failed — durable workload ownership record and workspace lease intentionally retained",
			slog.String("operation", "run"),
			slog.String("operation_id", op.ID),
			slog.String("error", cleanupErr.Error()),
		)
		return
	}

	// Stage 4: the durable ownership record is removed only after the
	// backend/kernel MAC state and the pins are positively proven gone;
	// until then it is the reconciliation retry marker for whatever
	// helper state remains.
	if err := a.WorkloadMAC.removeWorkloadMACState(op.ID); err != nil {
		opLog(ctx).Error("durable workload ownership state removal failed — workspace lease intentionally retained",
			slog.String("operation", "run"),
			slog.String("operation_id", op.ID),
			slog.String("error", err.Error()),
		)
		return
	}

	// Stage 5: release the workspace-use lease.
	if op.macLeaseRelease != nil {
		op.macLeaseRelease()
	}

	// Stage 6: the cidfile is no longer needed once every owned resource is
	// released.
	cleanupCidfile(op)
}

// rollbackRunPreparation reverses prepared run resources before any
// container can exist: workload MAC state, pins, the durable ownership
// record, lease, cidfile. It is used by every pre-start failure path (MAC
// preparation failure, MAC validation failure, admission refusal, shutdown
// gate before process start, and cmd.Start failure). No container exists by
// construction, so no container-absence proof is needed.
func (a *App) rollbackRunPreparation(ctx context.Context, op *operation) {
	if op.workloadMAC != nil {
		if err := op.workloadMAC.Cleanup(); err != nil {
			opLog(ctx).Error("workload MAC cleanup failed — dependent pins and workspace lease intentionally retained",
				slog.String("operation", "run"),
				slog.String("operation_id", op.ID),
				slog.String("error", err.Error()),
			)
			return
		}
	}
	cleanupErr := cleanupPinnedMounts(op)
	if cleanupErr != nil {
		opLog(ctx).Error("pin cleanup failed — durable workload ownership record and MAC lease intentionally retained",
			slog.String("operation", "run"),
			slog.String("operation_id", op.ID),
			slog.String("error", cleanupErr.Error()),
		)
		return
	}
	if a.WorkloadMAC != nil {
		// The durable ownership record is removed only after the MAC
		// state and the pins are positively proven released (absence of
		// both is success on this pre-container path).
		if err := a.WorkloadMAC.removeWorkloadMACState(op.ID); err != nil {
			opLog(ctx).Error("durable workload ownership state removal failed — MAC lease intentionally retained",
				slog.String("operation", "run"),
				slog.String("operation_id", op.ID),
				slog.String("error", err.Error()),
			)
			return
		}
	}
	if op.macLeaseRelease != nil {
		op.macLeaseRelease()
	}
	cleanupCidfile(op)
}

// proveRunContainerAbsent is the canonical container-absence proof owner.
// It queries the Docker container list for the operation's reserved label
// correlation and classifies the outcome:
//
//   - no correlated container: proven absent;
//   - exactly one proven helper-owned correlated container: force-removed
//     through the Docker cleanup mechanism and verified absent;
//   - anything ambiguous (Docker unavailable, more than one claimant,
//     unclassifiable state): an error — the caller must retain state.
func (a *App) proveRunContainerAbsent(ctx context.Context, op *operation) error {
	containers, err := a.inspectOperationContainers(ctx, op.ID, op.SessionID)
	if err != nil {
		return fmt.Errorf("correlated container state is ambiguous: %w", err)
	}
	switch {
	case len(containers) == 0:
		return nil
	case len(containers) > 1:
		return fmt.Errorf("%d correlated containers claim one operation; refusing to guess", len(containers))
	}
	container := containers[0]
	if classifyHelperContainerState(container.State) == helperStateUnknown {
		return fmt.Errorf("correlated container state %q is unclassifiable; refusing removal", container.State)
	}
	if err := a.forceRemoveRunContainer(ctx, container.ID); err != nil {
		return fmt.Errorf("cannot remove proven-owned correlated container: %w", err)
	}
	after, err := a.inspectOperationContainers(ctx, op.ID, op.SessionID)
	if err != nil {
		return fmt.Errorf("cannot verify correlated container removal: %w", err)
	}
	if len(after) != 0 {
		return fmt.Errorf("correlated container removal could not be verified")
	}
	return nil
}

// InspectOperationContainers, when set, overrides the Docker-based
// correlated-run container inspection used by the container-absence proof.
// It is a narrow test seam; production shells out to the Docker CLI with
// the reserved label set.

// inspectOperationContainers lists helper-owned containers correlated with
// one run operation by the reserved label set (schema, operation, session).
func (a *App) inspectOperationContainers(ctx context.Context, operationID, sessionID string) ([]helperContainer, error) {
	if a.InspectOperationContainers != nil {
		return a.InspectOperationContainers(ctx, operationID, sessionID)
	}
	cmd := a.newDockerCommand(ctx, "docker", "ps", "-a",
		"--filter", "label="+runtimeLabelSchema+"="+runtimeLabelSchemaValue,
		"--filter", "label="+runtimeLabelOperationID+"="+operationID,
		"--filter", "label="+runtimeLabelSessionID+"="+sessionID,
		// docker ps renders .State as a plain string; it is classified
		// explicitly by classifyHelperContainerState.
		"--format", "{{.ID}} {{.State}}")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("cannot inspect correlated run containers: %w", err)
	}
	return parseHelperContainerList(string(out))
}

// inspectCorrelatedRunContainers is the startup-reconciliation default
// correlated-container inspection. It runs without an App instance (before
// the HTTP server exists) and shells out to the Docker CLI directly.
func inspectCorrelatedRunContainers(ctx context.Context, operationID, sessionID string) ([]helperContainer, error) {
	cmd := exec.CommandContext(ctx, "docker", "ps", "-a",
		"--filter", "label="+runtimeLabelSchema+"="+runtimeLabelSchemaValue,
		"--filter", "label="+runtimeLabelOperationID+"="+operationID,
		"--filter", "label="+runtimeLabelSessionID+"="+sessionID,
		"--format", "{{.ID}} {{.State}}")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("cannot inspect correlated run containers: %w", err)
	}
	return parseHelperContainerList(string(out))
}

// forceRemoveCorrelatedContainerByCLI force-removes one proven-owned
// correlated container through the Docker CLI. Used by startup
// reconciliation, where no App request context exists.
func forceRemoveCorrelatedContainerByCLI(ctx context.Context, containerID string) error {
	cmd := exec.CommandContext(ctx, "docker", "rm", "-f", containerID)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cannot remove correlated container: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// forceRemoveRunContainer is the App-wired force removal used by the
// container-absence proof; it honors the ExecCommandContext test seam.
func (a *App) forceRemoveRunContainer(ctx context.Context, containerID string) error {
	cmd := a.newDockerCommand(ctx, "docker", "rm", "-f", containerID)
	var stderr syncBuffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cannot remove correlated container: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// parseHelperContainerList parses the docker ps output shape shared by the
// helper container inspection owners.
func parseHelperContainerList(out string) ([]helperContainer, error) {
	trimmed := strings.TrimSpace(out)
	if trimmed == "" {
		return nil, nil
	}
	var containers []helperContainer
	for _, line := range strings.Split(trimmed, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) != 2 {
			return nil, fmt.Errorf("unexpected docker ps output: %q", line)
		}
		containers = append(containers, helperContainer{ID: parts[0], State: parts[1]})
	}
	return containers, nil
}

// syncBuffer is a minimal concurrent-safe byte buffer for command stderr.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
