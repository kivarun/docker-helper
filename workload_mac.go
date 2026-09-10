package main

// workload_mac.go — the backend-neutral workload MAC lifecycle owner
// (Release 2.2 Phase 2.2.6).
//
// The coordinator materializes an already-accepted 2.2.5 filesystem exposure
// plan through the active MAC backend. It is deliberately narrow:
//
//   - it never reads allowed-root tables, Session snapshots, LookupAccess,
//     or CanExposeWritable;
//   - it never resolves hierarchy or widens an accepted exposure;
//   - its lifetime is one run Operation and its correlated container, never
//     a Principal, Launcher, Session, or allowed root.
//
// Session workspace coverage (boundaries, bindings, leases, labeling, daemon
// managed boundaries) remains owned exclusively by sessionMACCoordinator.
//
// Durable ownership state is written before the first kernel-side MAC
// resource of an operation so a daemon crash always leaves startup
// reconciliation able to prove ownership of whatever kernel state remains.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// workloadMACStateSchema is the invariant schema value of the durable
// workload ownership record. A record without this exact value is not
// recognized as current-owner state and is retained, never deleted.
const workloadMACStateSchema = 1

// workloadMACStateRootName is the directory name of the workload MAC state
// hierarchy under both the helper state directory and the helper runtime
// directory.
const workloadMACStateRootName = "workload-mac"

// workloadMACStateDirPerm is the mode of every helper-owned workload MAC
// state directory. No caller-controlled component lives inside.
const workloadMACStateDirPerm = 0700

// workloadReconcileScanTimeout bounds each Docker query and each backend
// cleanup performed during startup reconciliation so a stuck Docker daemon
// cannot hang daemon startup indefinitely.
const workloadReconcileScanTimeout = 30 * time.Second

// workloadMountReadyTimeout bounds the wait for one projection mount to
// become ready during backend preparation.
const workloadMountReadyTimeout = 10 * time.Second

// workloadWorkerExitTimeout bounds the wait for one owned projection worker
// to exit after its mount was removed.
const workloadWorkerExitTimeout = 5 * time.Second

// workloadPreparation carries the accepted application-decision facts one
// backend needs. It contains no policy authority: the exposure plan was
// already accepted by the 2.2.5 application layer.
type workloadPreparation struct {
	OperationID string
	SessionID   string
	// Exposures is the accepted exposure plan in accepted order.
	Exposures []sessionFilesystemExposure
	// PinnedSources is index-parallel to Exposures: the pinned kernel
	// materialization source for each mount in system mode. Policy identity
	// remains the canonical exposure SourcePath; pinned paths are only the
	// stable kernel source a backend may project from.
	PinnedSources []string
	// StateDir is the durable owned state directory for this operation
	// (already created and owned by the coordinator).
	StateDir string
	// RuntimeDir is the transient owned runtime directory for this
	// operation (already created and owned by the coordinator).
	RuntimeDir string
}

// preparedWorkloadMAC is the single backend-neutral prepared result of one
// workload MAC preparation. It carries only the downstream materialization
// facts the run pipeline consumes: the Docker security options that select
// the prepared MAC state and the per-mount bind sources after projection.
// It holds no policy authority and exposes no helper paths to callers.
type preparedWorkloadMAC struct {
	Backend LSMBackend
	// SecurityOpts is the deterministic --security-opt list for the
	// prepared workload.
	SecurityOpts []string
	// MountSources is index-parallel to the accepted exposure plan: the
	// Docker bind source for each mount after MAC materialization
	// (pinned path, or helper-owned projection path for SELinux RO binds).
	MountSources []string

	cleanup     func() error
	cleanupOnce sync.Once
	cleanupErr  error
}

// Cleanup releases the prepared workload MAC state. It is idempotent and
// concurrency-safe: repeated or parallel calls execute the backend cleanup
// exactly once and return the result of the first call. A failure retains
// the owned state for startup reconciliation.
func (p *preparedWorkloadMAC) Cleanup() error {
	if p == nil {
		return nil
	}
	p.cleanupOnce.Do(func() {
		p.cleanupErr = p.cleanup()
	})
	return p.cleanupErr
}

// workloadMACRecord is the durable ownership record for one operation's
// workload MAC state. It is written atomically before the first kernel-side
// MAC resource of the operation is created.
//
// The record deliberately carries no backend identity beyond the exact
// backend enum: every backend-specific kernel identity (for example the
// AppArmor profile name) is derived deterministically from the schema and
// the Operation ID at validation/cleanup time. Storing a second owner of a
// derivable name would create a crash window in which the durable record
// and the derived identity could disagree.
type workloadMACRecord struct {
	Schema      int    `json:"schema"`
	OperationID string `json:"operation_id"`
	SessionID   string `json:"session_id"`
	Backend     string `json:"backend"`
	CreatedAt   string `json:"created_at"`
	// StateDir is not serialized: the coordinator resolves the directory
	// that owns the record and fills it before backend validation/cleanup.
	StateDir string `json:"-"`
	// RuntimeDir is not serialized either; resolved with StateDir.
	RuntimeDir string `json:"-"`
}

// StateDirPath returns the resolved durable state directory of the record.
func (r *workloadMACRecord) StateDirPath() string {
	return r.StateDir
}

// RuntimeDirPath returns the resolved transient runtime directory of the
// record.
func (r *workloadMACRecord) RuntimeDirPath() string {
	return r.RuntimeDir
}

// workloadMACRetainedError marks a failed workload MAC preparation whose
// partial MAC state could not be rolled back and remains on the host. The
// caller MUST retain every dependent resource — source pins and the
// workspace-use lease — so startup reconciliation can still release the
// full ownership state; removing pins or releasing the lease would strand
// live MAC kernel state on deleted sources.
type workloadMACRetainedError struct {
	err error
}

func (e *workloadMACRetainedError) Error() string {
	return "workload MAC state retained after failed preparation: " + e.err.Error()
}

func (e *workloadMACRetainedError) Unwrap() error { return e.err }

// workloadMACBackend is the backend-specific adapter for workload MAC
// preparation and owned-state cleanup. The backend MUST NOT query Sessions,
// allowed roots, or snapshots, and MUST NOT re-decide any access mode.
type workloadMACBackend interface {
	// backend returns the active backend identity.
	backend() LSMBackend
	// prepare materializes the accepted exposure plan. The coordinator has
	// already created the durable ownership record and both state roots.
	// On failure the backend must have attempted to roll back every
	// kernel-side resource it created; whether that rollback succeeded is
	// observable only through the coordinator's retained-outcome contract.
	prepare(p workloadPreparation) (*preparedWorkloadMAC, error)
	// validateOwnedState proves the durable state is exact and current-owner.
	// Reconciliation retains anything that fails validation.
	validateOwnedState(record workloadMACRecord) error
	// cleanupOwnedState removes the kernel workload state and helper files
	// of one owned record. Called only for positively identified owned
	// state whose correlated container is proven absent.
	cleanupOwnedState(record workloadMACRecord) error
}

// workloadMACCoordinator is the single owner of operation-lifetime workload
// MAC state. It selects the already-detected active backend, owns the
// helper-owned state hierarchy and startup reconciliation, and produces the
// one backend-neutral prepared result. Session workspace coverage stays with
// sessionMACCoordinator.
type workloadMACCoordinator struct {
	backend workloadMACBackend
	// stateRoot is <helper state dir>/workload-mac (durable ownership).
	stateRoot string
	// runtimeRoot is <helper runtime dir>/workload-mac (transient backend
	// runtime facts such as projection mountpoints).
	runtimeRoot string
	// inspectContainers classifies Docker containers correlated with one
	// operation by the reserved label set. Production shells out to the
	// Docker CLI; tests inject a seam.
	inspectContainers func(ctx context.Context, operationID, sessionID string) ([]helperContainer, error)
	// removeContainer force-removes one proven-owned correlated container.
	removeContainer func(ctx context.Context, containerID string) error
	// cleanupStalePins removes leftover inode pins of one proven-gone
	// operation and returns the failure that forces the caller to retain
	// the durable ownership record. Production uses the deterministic pin
	// layout; tests may replace it.
	cleanupStalePins func(operationID string) error
}

// newWorkloadMACCoordinatorForMode builds the workload MAC coordinator for
// the given deployment mode. It returns nil for non-system mode and when no
// supported MAC backend is active (mirroring the session MAC coordinator
// invariant), so run requests fail closed per request in that case.
func newWorkloadMACCoordinatorForMode(cfg *Config, detectLSM func() (LSMBackend, error)) (*workloadMACCoordinator, error) {
	if cfg.Mode != ModeSystem {
		return nil, nil
	}
	backend, err := detectLSM()
	if err != nil {
		return nil, err
	}
	c := &workloadMACCoordinator{
		stateRoot:   filepath.Join(cfg.StateDir, workloadMACStateRootName),
		runtimeRoot: filepath.Join(cfg.RuntimeDir, workloadMACStateRootName),
	}
	switch backend {
	case LSMAppArmor:
		c.backend = newWorkloadAppArmorBackend()
	case LSMSELinux:
		c.backend = newWorkloadSELinuxBackend()
	default:
		return nil, nil
	}
	c.inspectContainers = inspectCorrelatedRunContainers
	c.removeContainer = forceRemoveCorrelatedContainerByCLI
	c.cleanupStalePins = c.cleanupStalePinsIn
	if err := ensureWorkloadStateRoot(c.stateRoot); err != nil {
		return nil, err
	}
	if err := ensureWorkloadStateRoot(c.runtimeRoot); err != nil {
		return nil, err
	}
	return c, nil
}

// ensureWorkloadStateRoot creates one state-root hierarchy directory with
// helper-owned 0700 mode.
func ensureWorkloadStateRoot(root string) error {
	if err := os.MkdirAll(root, workloadMACStateDirPerm); err != nil {
		return fmt.Errorf("cannot create workload MAC state root %s: %w", root, err)
	}
	return nil
}

// Backend returns the active backend identity.
func (c *workloadMACCoordinator) Backend() LSMBackend {
	return c.backend.backend()
}

// Prepare materializes the accepted exposure plan through the active
// backend. The coordinator creates the durable ownership state and the
// transient runtime directory before the backend creates its first
// kernel-side resource, so every crash window leaves provable ownership.
//
// Failure contract (single terminal classification for the caller):
//
//   - the returned error is a *workloadMACRetainedError exactly when
//     partial MAC state could not be rolled back and remains on the host;
//     the caller must retain the dependent source pins and the
//     workspace-use lease and let startup reconciliation finish;
//   - any other error means the MAC state was fully rolled back and the
//     caller must release the dependent resources as usual.
func (c *workloadMACCoordinator) Prepare(p workloadPreparation) (*preparedWorkloadMAC, error) {
	if err := ensureWorkloadStateRoot(c.stateRoot); err != nil {
		return nil, err
	}
	if err := ensureWorkloadStateRoot(c.runtimeRoot); err != nil {
		return nil, err
	}
	stateDir := filepath.Join(c.stateRoot, p.OperationID)
	runtimeDir := filepath.Join(c.runtimeRoot, p.OperationID)
	if err := os.Mkdir(stateDir, workloadMACStateDirPerm); err != nil {
		if os.IsExist(err) {
			return nil, fmt.Errorf("workload MAC state already exists for operation %s", p.OperationID)
		}
		return nil, fmt.Errorf("cannot create workload MAC state directory: %w", err)
	}
	if err := os.Mkdir(runtimeDir, workloadMACStateDirPerm); err != nil {
		removeWorkloadMACStateDir(c.stateRoot, p.OperationID)
		return nil, fmt.Errorf("cannot create workload MAC runtime directory: %w", err)
	}

	// Crash-safety: the durable ownership record is committed before the
	// backend creates its first kernel-side resource, so any crash leaves
	// startup reconciliation able to prove ownership.
	p.StateDir = stateDir
	p.RuntimeDir = runtimeDir
	rec := workloadMACRecord{
		Schema:      workloadMACStateSchema,
		OperationID: p.OperationID,
		SessionID:   p.SessionID,
		Backend:     string(c.backend.backend()),
		CreatedAt:   time.Now().UTC().Format(time.RFC3339),
	}
	// The rollback path below cleans through the same resolved paths the
	// backend prepared from; they are never serialized.
	rec.StateDir = stateDir
	rec.RuntimeDir = runtimeDir
	if err := writeWorkloadMACRecord(stateDir, rec); err != nil {
		_ = removeWorkloadMACStateDir(c.stateRoot, p.OperationID)
		_ = removeWorkloadMACStateDir(c.runtimeRoot, p.OperationID)
		return nil, err
	}

	prepared, err := c.backend.prepare(p)
	if err != nil {
		// Fail closed on the dependent resources: when the partial MAC
		// state cannot be rolled back, the pins and lease that the
		// projections depend on must remain until reconciliation.
		if cleanupErr := c.backend.cleanupOwnedState(rec); cleanupErr != nil {
			logRetainedWorkloadState(context.Background(), p.OperationID, "prepare_rollback", cleanupErr)
			return nil, &workloadMACRetainedError{err: err}
		}
		if stateErr := c.removeWorkloadMACState(p.OperationID); stateErr != nil {
			logRetainedWorkloadState(context.Background(), p.OperationID, "prepare_rollback_state_removal", stateErr)
			return nil, &workloadMACRetainedError{err: err}
		}
		return nil, err
	}
	return prepared, nil
}

// removeWorkloadMACState removes both the durable and the transient state
// directories of one operation; absence is success.
func (c *workloadMACCoordinator) removeWorkloadMACState(operationID string) error {
	stateErr := removeWorkloadMACStateDir(c.stateRoot, operationID)
	runtimeErr := removeWorkloadMACStateDir(c.runtimeRoot, operationID)
	return errors.Join(stateErr, runtimeErr)
}

// ReconcileStartup scans only positively identified helper-owned workload
// MAC state and cleans what the correlated container provenance proves is
// safe. Ambiguous, foreign, malformed, or unverifiable state is retained
// with an actionable diagnostic; nothing is deleted on a guess.
//
// It must run before the daemon accepts new HTTP requests.
func (c *workloadMACCoordinator) ReconcileStartup(ctx context.Context) error {
	entries, err := os.ReadDir(c.stateRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("cannot scan workload MAC state: %w", err)
	}
	// Deterministic order for reproducible reconciliation.
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)

	for _, name := range names {
		rec, err := c.parseReconcileEntry(name)
		if err != nil {
			logRetainedWorkloadState(ctx, name, "ownership_validation", err)
			continue
		}
		if err := c.reconcileOne(ctx, *rec); err != nil {
			logRetainedWorkloadState(ctx, rec.OperationID, "reconcile", err)
		}
	}
	return nil
}

// parseReconcileEntry validates that a state-root entry is exactly a
// positively identified helper-owned workload state directory. Any deviation
// — symlink, unsafe name, missing/unreadable/garbled record — makes the
// entry unowned: the caller retains it untouched.
func (c *workloadMACCoordinator) parseReconcileEntry(name string) (*workloadMACRecord, error) {
	if !isOperationIDSafe(name) {
		return nil, fmt.Errorf("state entry name is not a safe operation ID: %q", name)
	}
	dir := filepath.Join(c.stateRoot, name)
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, fmt.Errorf("cannot stat state entry: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("state entry is not a helper-owned directory")
	}
	rec, err := readWorkloadMACRecord(dir)
	if err != nil {
		return nil, fmt.Errorf("ownership record is not provable: %w", err)
	}
	if rec.OperationID != name {
		return nil, fmt.Errorf("ownership record names a different operation")
	}
	rec.StateDir = dir
	rec.RuntimeDir = filepath.Join(c.runtimeRoot, name)
	return &rec, nil
}

// reconcileOne handles one positively identified owned state directory.
// Every outcome is container-absence-driven and fail closed: state is
// removed only after Docker proves no correlated container remains.
func (c *workloadMACCoordinator) reconcileOne(ctx context.Context, rec workloadMACRecord) error {
	if rec.Schema != workloadMACStateSchema {
		return fmt.Errorf("unsupported ownership record schema %d", rec.Schema)
	}
	if rec.Backend != string(c.backend.backend()) {
		return fmt.Errorf("ownership record backend %q does not match active backend %q", rec.Backend, c.backend.backend())
	}
	if err := c.backend.validateOwnedState(rec); err != nil {
		return fmt.Errorf("owned state does not validate: %w", err)
	}

	queryCtx, cancel := context.WithTimeout(ctx, workloadReconcileScanTimeout)
	defer cancel()
	containers, err := c.inspectContainers(queryCtx, rec.OperationID, rec.SessionID)
	if err != nil {
		return fmt.Errorf("correlated container state is ambiguous: %w", err)
	}
	switch {
	case len(containers) > 1:
		return fmt.Errorf("%d correlated containers claim one operation; refusing to guess", len(containers))
	case len(containers) == 1:
		container := containers[0]
		if classifyHelperContainerState(container.State) == helperStateUnknown {
			return fmt.Errorf("correlated container state %q is unclassifiable; refusing removal", container.State)
		}
		// The operation supervisor never adopts containers across a daemon
		// restart, so one proven-owned correlated container is a stale run
		// workload. Force-remove it through the Docker cleanup mechanism and
		// verify absence before touching MAC state.
		if err := c.removeContainer(queryCtx, container.ID); err != nil {
			return fmt.Errorf("cannot remove proven-owned stale container: %w", err)
		}
		after, err := c.inspectContainers(queryCtx, rec.OperationID, rec.SessionID)
		if err != nil {
			return fmt.Errorf("cannot verify stale container removal: %w", err)
		}
		if len(after) != 0 {
			return fmt.Errorf("stale container removal could not be verified")
		}
	}

	// Container proven absent: release backend state, then dependent pin
	// residue, then the durable record. The durable record is removed only
	// after every earlier stage is positively proven gone; a failed stage
	// leaves the record as the reconciliation retry marker.
	if err := c.backend.cleanupOwnedState(rec); err != nil {
		return fmt.Errorf("backend workload state cleanup failed: %w", err)
	}
	if err := c.cleanupStalePins(rec.OperationID); err != nil {
		return fmt.Errorf("stale pin cleanup failed: %w", err)
	}
	if err := c.removeWorkloadMACState(rec.OperationID); err != nil {
		return fmt.Errorf("cannot remove owned workload state: %w", err)
	}
	return nil
}

// cleanupStalePins removes leftover inode pins of one proven-gone
// operation from the deterministic pin layout under the runtime directory.
// The pins were created by the mount-pin owner; after the container is
// proven absent and the projections that depended on them are released,
// they are pure residue. Every failure is returned so the caller retains
// the durable ownership record as the retry marker.
func (c *workloadMACCoordinator) cleanupStalePinsIn(operationID string) error {
	pinsDir := filepath.Join(filepath.Dir(c.runtimeRoot), "mounts", operationID)
	info, err := os.Lstat(pinsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("cannot inspect stale pin directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("stale pin directory %s is not a helper-owned directory", pinsDir)
	}
	entries, err := os.ReadDir(pinsDir)
	if err != nil {
		return fmt.Errorf("cannot scan stale mount pins: %w", err)
	}
	for _, entry := range entries {
		if err := validateStalePinEntry(pinsDir, entry); err != nil {
			return err
		}
		path := filepath.Join(pinsDir, entry.Name())
		mounted, err := procMountinfoContains(path)
		if err != nil {
			return fmt.Errorf("cannot inventory stale pin %s: %w", path, err)
		}
		if mounted {
			if err := unmountOwnedStalePin(path); err != nil {
				return err
			}
			stillMounted, err := procMountinfoContains(path)
			if err != nil {
				return fmt.Errorf("cannot verify stale pin unmount %s: %w", path, err)
			}
			if stillMounted {
				return fmt.Errorf("stale pin %s remained mounted after unmount", path)
			}
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("cannot remove stale pin %s: %w", path, err)
		}
	}
	if err := os.Remove(pinsDir); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("cannot remove stale pin directory %s: %w", pinsDir, err)
	}
	return nil
}

// validateStalePinEntry proves one pin-layout entry is exactly a
// deterministic helper-owned pin destination: a canonical decimal index
// naming a real directory or regular file. Anything else — symlink,
// foreign name, unexpected node — fails closed so the caller retains the
// owned state instead of unmounting or removing an unproven object.
func validateStalePinEntry(pinsDir string, entry os.DirEntry) error {
	if !isCanonicalDecimalIndex(entry.Name()) {
		return fmt.Errorf("unexpected pin layout entry %q; refusing cleanup", entry.Name())
	}
	info, err := os.Lstat(filepath.Join(pinsDir, entry.Name()))
	if err != nil {
		return fmt.Errorf("cannot inspect stale pin %q: %w", entry.Name(), err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("stale pin %q is not a helper-owned mount destination", entry.Name())
	}
	if !info.IsDir() && !info.Mode().IsRegular() {
		return fmt.Errorf("stale pin %q is neither a directory nor a regular file", entry.Name())
	}
	return nil
}

// isCanonicalDecimalIndex reports whether name is the canonical decimal
// spelling of a non-negative index: digits only with no leading zeros.
func isCanonicalDecimalIndex(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		if r < '0' || r > '9' {
			return false
		}
	}
	if len(name) > 1 && name[0] == '0' {
		return false
	}
	return true
}

// writeWorkloadMACRecord writes the durable ownership record atomically
// (temp file + rename) so a crash never exposes a half-written record.
func writeWorkloadMACRecord(stateDir string, rec workloadMACRecord) error {
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return fmt.Errorf("cannot encode workload ownership record: %w", err)
	}
	tmp := filepath.Join(stateDir, "ownership.tmp")
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("cannot write ownership record: %w", err)
	}
	if err := os.Rename(tmp, filepath.Join(stateDir, "ownership")); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("cannot commit ownership record: %w", err)
	}
	return nil
}

// readWorkloadMACRecord reads and validates the durable ownership record of
// one state directory. The decoder is exact: the record must be exactly one
// JSON value carrying exactly the current-owner fields, the schema must be
// the current schema, the operation ID must be safe, the session ID must
// carry the canonical shape, and the backend must be an exact known enum
// value. Anything unreadable, schema-incompatible, or malformed is an error
// so the caller retains the directory instead of guessing. Malformed state
// is never normalized.
func readWorkloadMACRecord(stateDir string) (workloadMACRecord, error) {
	var rec workloadMACRecord
	data, err := os.ReadFile(filepath.Join(stateDir, "ownership"))
	if err != nil {
		return rec, fmt.Errorf("cannot read ownership record: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rec); err != nil {
		return rec, fmt.Errorf("ownership record is malformed: %w", err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return rec, fmt.Errorf("ownership record must contain exactly one JSON value")
	}
	if rec.Schema != workloadMACStateSchema {
		return rec, fmt.Errorf("unsupported ownership record schema %d", rec.Schema)
	}
	if !isOperationIDSafe(rec.OperationID) {
		return rec, fmt.Errorf("ownership record names an unsafe operation ID")
	}
	if !isSessionIDShape(rec.SessionID) {
		return rec, fmt.Errorf("ownership record names an invalid session ID")
	}
	if rec.Backend != string(LSMAppArmor) && rec.Backend != string(LSMSELinux) {
		return rec, fmt.Errorf("ownership record names an unknown backend %q", rec.Backend)
	}
	return rec, nil
}

// isSessionIDShape reports whether value carries the canonical Session ID
// shape issued by the session owner: `dhs_` + lowercase hex characters.
func isSessionIDShape(value string) bool {
	const sessionIDPrefix = "dhs_"
	if !strings.HasPrefix(value, sessionIDPrefix) {
		return false
	}
	rest := value[len(sessionIDPrefix):]
	if rest == "" {
		return false
	}
	for _, r := range rest {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// removeWorkloadMACStateDir removes one operation directory under a state
// root; a missing directory is success.
func removeWorkloadMACStateDir(root, operationID string) error {
	dir := filepath.Join(root, operationID)
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("cannot remove workload state %s: %w", dir, err)
	}
	return nil
}

// logRetainedWorkloadState records one fail-closed reconciliation outcome
// with actionable internal correlation (no secrets).
func logRetainedWorkloadState(ctx context.Context, operationID, stage string, err error) {
	if err != nil {
		opLog(ctx).Error("workload MAC state retained — reconciliation did not remove owned state",
			slog.String("operation", "workload_mac_reconcile"),
			slog.String("operation_id", operationID),
			slog.String("stage", stage),
			slog.String("error", err.Error()),
		)
		return
	}
	opLog(ctx).Error("workload MAC state retained — reconciliation did not remove owned state",
		slog.String("operation", "workload_mac_reconcile"),
		slog.String("operation_id", operationID),
		slog.String("stage", stage),
	)
}

// workloadReadOnlyTargets returns the container targets of the accepted
// exposure plan whose caller-requested mode is read-only. The
// caller-requested mode — never the snapshot access alone — is the frozen
// workload exposure mode: an application-level narrowing (snapshot
// read_write requested read-only) is still read-only to the MAC layer, and
// an accepted read-write request was already proven writable by the
// application layer.
func workloadReadOnlyTargets(exposures []sessionFilesystemExposure) []string {
	var targets []string
	for _, e := range exposures {
		if e.RequestedReadOnly {
			targets = append(targets, e.Target)
		}
	}
	return targets
}

// fileExists reports whether the path exists as a readable file or directory.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// atomicWriteFile writes data through a temp file plus rename so a crash
// never exposes a partially written helper-owned file.
func atomicWriteFile(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
