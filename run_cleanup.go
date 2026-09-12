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
//	  -> session-use lease released
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
	"time"
)

// containerAbsenceProofTimeout bounds the Docker queries of one
// container-absence proof so a stuck Docker daemon cannot block operation
// completion indefinitely.
const containerAbsenceProofTimeout = 10 * time.Second

// workloadCleanupStageName identifies one authoritative stage of the frozen
// Release 2.2 cleanup dependency order.
type workloadCleanupStageName string

const (
	cleanupStageContainerProof workloadCleanupStageName = "container_absence_proof"
	cleanupStageWorkloadMAC    workloadCleanupStageName = "workload_mac_state"
	cleanupStageSourcePins     workloadCleanupStageName = "source_pins"
	cleanupStageOwnershipState workloadCleanupStageName = "workload_ownership_state"
	cleanupStageWorkspaceLease workloadCleanupStageName = "workspace_use_lease"
	cleanupStageCidfile        workloadCleanupStageName = "cidfile"
)

// canonicalWorkloadCleanupOrder is the frozen dependency order of the
// Release 2.2 cleanup lifecycle. Every cleanup path — post-start cleanup,
// pre-container rollback, startup reconciliation — executes a subsequence
// of exactly this order, and runCleanupSequence refuses any stage list
// that would reorder it.
var canonicalWorkloadCleanupOrder = []workloadCleanupStageName{
	cleanupStageContainerProof,
	cleanupStageWorkloadMAC,
	cleanupStageSourcePins,
	cleanupStageOwnershipState,
	cleanupStageWorkspaceLease,
	cleanupStageCidfile,
}

// cleanupStage is one authoritative cleanup operation: a stage name from
// the canonical order plus the operation that performs it. A nil run
// function is a skipped stage (the path has nothing of that kind to
// release, for example no lease in startup reconciliation).
type cleanupStage struct {
	name workloadCleanupStageName
	run  func() error
}

// runCleanupOutcome classifies the terminal result of one ordered cleanup
// execution: either every stage completed, or the named stage failed and
// the dependent state of every later stage is retained (fail closed) for
// startup reconciliation.
type runCleanupOutcome struct {
	completed     bool
	retainedStage workloadCleanupStageName
	err           error
}

// runCleanupSequence is the single owner of the frozen Release 2.2 cleanup
// order and of its retained-versus-completed classification. Post-start
// cleanup, pre-container rollback, and startup reconciliation build their
// stage lists as subsequences of canonicalWorkloadCleanupOrder and execute
// them here; backend-specific cleanup stays inside the backends.
type runCleanupSequence struct {
	stages []cleanupStage
}

// newRunCleanupSequence builds one ordered cleanup execution and proves the
// stage list is a subsequence of the canonical order, so a caller cannot
// silently express a reordered cleanup.
func newRunCleanupSequence(stages ...cleanupStage) runCleanupSequence {
	pos := map[workloadCleanupStageName]int{}
	for i, name := range canonicalWorkloadCleanupOrder {
		pos[name] = i
	}
	last := -1
	for _, stage := range stages {
		p, ok := pos[stage.name]
		if !ok {
			panic("runCleanupSequence: unknown cleanup stage " + stage.name)
		}
		if p <= last {
			panic("runCleanupSequence: cleanup stages out of canonical order at " + stage.name)
		}
		last = p
	}
	return runCleanupSequence{stages: stages}
}

// run executes the stages in canonical order and stops at the first
// failure. The returned outcome is the single classification every caller
// logs and acts on: a completed outcome means every listed stage is
// positively done; a retained outcome means the named stage failed and
// every later dependent stage must be retained.
func (s runCleanupSequence) run() runCleanupOutcome {
	for _, stage := range s.stages {
		if stage.run == nil {
			continue
		}
		if err := stage.run(); err != nil {
			return runCleanupOutcome{retainedStage: stage.name, err: err}
		}
	}
	return runCleanupOutcome{completed: true}
}

// logRunCleanupOutcome records one ordered cleanup outcome in the
// operational log. A completed outcome is silent; a retained outcome names
// the failed stage, the operation correlation, and the cause, and states
// the fail-closed dependency retention explicitly. It carries no secrets.
func logRunCleanupOutcome(ctx context.Context, path, operationID string, outcome runCleanupOutcome) {
	if outcome.completed {
		return
	}
	opLog(ctx).Error("ordered cleanup stage failed — dependent state intentionally retained for reconciliation",
		slog.String("operation", path),
		slog.String("operation_id", operationID),
		slog.String("stage", string(outcome.retainedStage)),
		slog.String("error", outcome.err.Error()),
	)
}

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

	outcome := newRunCleanupSequence(
		cleanupStage{
			name: cleanupStageContainerProof,
			run: func() error {
				proofCtx, cancel := context.WithTimeout(ctx, containerAbsenceProofTimeout)
				defer cancel()
				return a.proveRunContainerAbsent(proofCtx, op)
			},
		},
		cleanupStage{name: cleanupStageWorkloadMAC, run: op.workloadMAC.Cleanup},
		cleanupStage{name: cleanupStageSourcePins, run: func() error { return cleanupPinnedMounts(op) }},
		cleanupStage{name: cleanupStageOwnershipState, run: func() error {
			return a.WorkloadMAC.removeWorkloadMACState(op.ID)
		}},
		cleanupStage{name: cleanupStageWorkspaceLease, run: func() error {
			if op.macLeaseRelease != nil {
				op.macLeaseRelease()
			}
			return nil
		}},
		cleanupStage{name: cleanupStageCidfile, run: func() error { cleanupCidfile(op); return nil }},
	).run()
	logRunCleanupOutcome(ctx, "run", op.ID, outcome)
}

// rollbackRunPreparation reverses prepared run resources before any
// container can exist: workload MAC state, pins, the durable ownership
// record, lease, cidfile. It is used by every pre-start failure path (MAC
// preparation failure, MAC validation failure, admission refusal, shutdown
// gate before process start, and cmd.Start failure). No container exists by
// construction, so no container-absence proof is needed; the dependency
// order is otherwise the canonical one.
func (a *App) rollbackRunPreparation(ctx context.Context, op *operation) {
	outcome := newRunCleanupSequence(
		cleanupStage{name: cleanupStageWorkloadMAC, run: func() error {
			if op.workloadMAC == nil {
				return nil
			}
			return op.workloadMAC.Cleanup()
		}},
		cleanupStage{name: cleanupStageSourcePins, run: func() error { return cleanupPinnedMounts(op) }},
		cleanupStage{name: cleanupStageOwnershipState, run: func() error {
			if a.WorkloadMAC == nil {
				return nil
			}
			return a.WorkloadMAC.removeWorkloadMACState(op.ID)
		}},
		cleanupStage{name: cleanupStageWorkspaceLease, run: func() error {
			if op.macLeaseRelease != nil {
				op.macLeaseRelease()
			}
			return nil
		}},
		cleanupStage{name: cleanupStageCidfile, run: func() error { cleanupCidfile(op); return nil }},
	).run()
	logRunCleanupOutcome(ctx, "run", op.ID, outcome)
}

// proveRunContainerAbsent runs the canonical container-absence proof for
// one run operation over the App-wired Docker provenance.
func (a *App) proveRunContainerAbsent(ctx context.Context, op *operation) error {
	return proveOperationContainerAbsent(ctx, a.runContainerProvenance(), op.ID, op.SessionID)
}

// containerProvenance abstracts the Docker mechanics of the correlated
// container proof: how the correlated container set is inspected and how a
// proven-owned container is force-removed. The run path and the startup
// reconciliation share one proof algorithm and differ only in this wiring.
type containerProvenance struct {
	inspect func(ctx context.Context, operationID, sessionID string) ([]helperContainer, error)
	remove  func(ctx context.Context, containerID string) error
}

// dockerCommandFactory constructs one Docker CLI command. It is the only
// legitimate variation between the Docker provenance wirings: the run path
// injects the App-owned construction (which honors the ExecCommandContext
// test seam), startup reconciliation injects direct exec construction.
type dockerCommandFactory func(ctx context.Context, name string, args ...string) *exec.Cmd

// runContainerProvenance is the App-wired Docker provenance: it honors the
// InspectOperationContainers test seam and the ExecCommandContext-wrapped
// command construction.
func (a *App) runContainerProvenance() containerProvenance {
	return containerProvenance{
		inspect: a.inspectOperationContainers,
		remove:  a.forceRemoveRunContainer,
	}
}

// cliContainerProvenance is the startup-reconciliation Docker provenance.
// It runs without an App instance (before the HTTP server exists) and uses
// the direct-exec command construction of the same single mechanism owners.
func cliContainerProvenance() containerProvenance {
	return containerProvenance{
		inspect: func(ctx context.Context, operationID, sessionID string) ([]helperContainer, error) {
			return inspectCorrelatedContainers(ctx, exec.CommandContext, operationID, sessionID)
		},
		remove: func(ctx context.Context, containerID string) error {
			return forceRemoveCorrelatedContainer(ctx, exec.CommandContext, containerID)
		},
	}
}

// proveOperationContainerAbsent is the canonical container-absence proof
// owner, shared by the run path and startup reconciliation. It queries the
// Docker container list for the operation's reserved label correlation and
// classifies the outcome:
//
//   - no correlated container: proven absent;
//   - exactly one proven helper-owned correlated container: force-removed
//     through the Docker cleanup mechanism and verified absent;
//   - anything ambiguous (Docker unavailable, more than one claimant,
//     unclassifiable state): an error — the caller must retain state.
func proveOperationContainerAbsent(ctx context.Context, prov containerProvenance, operationID, sessionID string) error {
	containers, err := prov.inspect(ctx, operationID, sessionID)
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
	if err := prov.remove(ctx, container.ID); err != nil {
		return fmt.Errorf("cannot remove proven-owned correlated container: %w", err)
	}
	after, err := prov.inspect(ctx, operationID, sessionID)
	if err != nil {
		return fmt.Errorf("cannot verify correlated container removal: %w", err)
	}
	if len(after) != 0 {
		return fmt.Errorf("correlated container removal could not be verified")
	}
	return nil
}

// inspectOperationContainers lists helper-owned containers correlated with
// one run operation by the reserved label set (schema, operation, session).
// The InspectOperationContainers test seam overrides the Docker-based
// inspection; otherwise the single inspectCorrelatedContainers mechanism
// owner runs with the App-owned command construction.
func (a *App) inspectOperationContainers(ctx context.Context, operationID, sessionID string) ([]helperContainer, error) {
	if a.InspectOperationContainers != nil {
		return a.InspectOperationContainers(ctx, operationID, sessionID)
	}
	return inspectCorrelatedContainers(ctx, a.newDockerCommand, operationID, sessionID)
}

// inspectCorrelatedContainers is the single Docker CLI mechanism owner of the
// correlated-run container inspection: one docker ps filter set, one output
// format, one parse, one error wrap. Only the command construction is
// injected (dockerCommandFactory): the run path supplies the App-owned
// construction (honoring the ExecCommandContext test seam), startup
// reconciliation supplies direct exec construction.
func inspectCorrelatedContainers(ctx context.Context, newCommand dockerCommandFactory, operationID, sessionID string) ([]helperContainer, error) {
	cmd := newCommand(ctx, "docker", "ps", "-a",
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

// forceRemoveRunContainer is the App-wired force removal used by the
// container-absence proof; the ExecCommandContext test seam is honored by the
// App command construction. It delegates to the single mechanism owner.
func (a *App) forceRemoveRunContainer(ctx context.Context, containerID string) error {
	return forceRemoveCorrelatedContainer(ctx, a.newDockerCommand, containerID)
}

// forceRemoveCorrelatedContainer is the single Docker CLI mechanism owner of
// the force removal of one proven-owned correlated container. Only the
// command construction is injected (dockerCommandFactory).
func forceRemoveCorrelatedContainer(ctx context.Context, newCommand dockerCommandFactory, containerID string) error {
	cmd := newCommand(ctx, "docker", "rm", "-f", containerID)
	var stderr bytes.Buffer
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
