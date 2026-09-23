package main

// build_driver.go implements the Release-2.4 build execution driver: the
// single build-completion owner that replaces the 2.3 rootful
// `docker build` child with the sandboxed sequence
//
//	manager START -> BuildKit socket validation -> buildctl ->
//	manager STOP -> docker load -> verify internal tag ->
//	docker tag commit -> bounded internal-tag cleanup
//
// behind the existing public build contract. It adds no second lifecycle:
// termination, capacity, MAC lease, staging, logs, audit, and result
// semantics stay with the existing owners (operation.go, supervisor,
// staging). The P2 manager client remains the single RPC ambiguity owner;
// the driver never speaks the manager protocol directly.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"syscall"
	"time"
)

// Fixed backend constants (implementation constants from the reviewed
// plan; no config, no public surface).

// buildctlBinary is the pinned bundled buildctl client.
const buildctlBinary = "/usr/libexec/docker-helper/buildkit/buildctl"

// buildInternalTagRepository is the server-owned internal image namespace
// of one build operation. Exactly one tag per operation:
// docker-helper-build/<op_id>.
const buildInternalTagRepository = "docker-helper-build"

// buildExportTarName is the export artifact name inside the existing
// operation-scoped staging tree ($RUNTIME_DIR/builds/<op_id>/).
const buildExportTarName = "export.tar"

// buildCleanupContextTimeout bounds every fresh server-owned build-driver
// context: manager STOP convergence, the internal-tag verification stage,
// and internal-tag rmi cleanup. Implementation constant, not config.
const buildCleanupContextTimeout = 30 * time.Second

// buildInternalTag derives the one internal image tag of one build
// operation: docker-helper-build/<op_id>.
func buildInternalTag(opID string) string {
	return buildInternalTagRepository + "/" + opID
}

// buildExportTarPath derives the export tar path inside the operation's
// existing staging tree: $RUNTIME_DIR/builds/<op_id>/export.tar. The
// path owner is the staged context's cleanupPath; it is derived, never
// caller-supplied.
func buildExportTarPath(staged *stagedBuildContext) string {
	return filepath.Join(staged.cleanupPath, buildExportTarName)
}

// buildDriver owns ONE build operation's execution stages and terminal
// transition. It is build-specific (no generic workflow machinery): the
// stages and their order are the frozen P3 sequence.
type buildDriver struct {
	a   *App
	op  *operation
	req buildDriverRequest

	// builderStarted flips true once manager START may have succeeded;
	// every terminal path after that performs the mandatory STOP cleanup.
	builderStarted bool
}

func newBuildDriver(a *App, op *operation, req buildDriverRequest) *buildDriver {
	return &buildDriver{a: a, op: op, req: req}
}

// run is the single build completion owner. One goroutine; no hidden
// asynchronous continuation after the terminal transition.
func (d *buildDriver) run() {
	result := d.runStages()
	d.finish(result)
}

// runStages executes the frozen P3 sequence and returns its one result.
// Every stage transition re-checks the permanent termination latch under
// the existing owner.
func (d *buildDriver) runStages() buildStageResult {
	// A. manager START (cancellable no-child control stage; the P2 client
	// owns all ambiguity convergence).
	startRes := d.managerStartStage()
	if startRes.Terminated {
		return buildStageResult{ResultCode: d.terminationResultCode(), Message: "build cancelled"}
	}
	if startRes.Err != nil {
		// The cancellation race is classified by the LATCH, not by the
		// underlying error kind: a cancel that lands during the START
		// round-trip surfaces as a dial-context-canceled unreachable error
		// while the latch is already set. Termination keeps priority over
		// failure (the same rule runChildStage applies).
		if d.latchObserved() {
			return buildStageResult{ResultCode: d.terminationResultCode(), Message: "build cancelled"}
		}
		return buildStageResult{ResultCode: "docker_build_failed", Message: "builder manager start failed"}
	}

	// B. validate the expected BuildKit socket (root-side, independent of
	// manager readiness claims).
	if err := d.validateSocket(); err != nil {
		d.logStage("builder_socket_validation_failed", err)
		d.builderStopCleanup()
		return buildStageResult{ResultCode: "docker_build_failed", Message: "builder socket validation failed"}
	}

	// C. buildctl (normal P1 child stage through the existing seam).
	buildctlRes := d.buildctlStage()
	if buildctlRes.Terminated {
		// Manager STOP is still mandatory cleanup after a cancelled
		// buildctl (fresh server-owned context).
		d.builderStopCleanup()
		return buildStageResult{ExitCode: buildctlRes.ExitCode, ResultCode: d.terminationResultCode(), Message: "build cancelled"}
	}
	if buildctlRes.Err != nil {
		d.builderStopCleanup()
		return buildStageResult{ExitCode: buildctlRes.ExitCode, ResultCode: "docker_build_failed", Message: "build failed"}
	}

	// D. manager STOP: mandatory cleanup owner; the untrusted builder is
	// gone before the trusted Engine import begins.
	if err := d.builderStopCleanup(); err != nil {
		// A STOP that cannot be proven converged must not hand an export
		// tar produced by a possibly-live builder to the Engine.
		return buildStageResult{ResultCode: "docker_build_failed", Message: "builder stop failed"}
	}

	// E. docker load into the internal tag (normal P1 child stage).
	loadRes := d.loadStage()
	if loadRes.Terminated {
		// Best-effort exact internal-tag cleanup, then the cancelled result.
		d.internalTagCleanupBestEffort()
		return buildStageResult{ExitCode: loadRes.ExitCode, ResultCode: d.terminationResultCode(), Message: "build cancelled"}
	}
	if loadRes.Err != nil {
		d.internalTagCleanupBestEffort()
		return buildStageResult{ExitCode: loadRes.ExitCode, ResultCode: "docker_build_failed", Message: "docker load failed"}
	}

	// F. verify the imported internal tag resolves in the local Engine
	// (cancellable child stage: a latched termination refuses admission so
	// no inspect process starts; a termination during the stage signals the
	// admitted child).
	verifyRes := d.verifyInternalTag()
	if verifyRes.Terminated {
		d.internalTagCleanupBestEffort()
		return buildStageResult{ExitCode: verifyRes.ExitCode, ResultCode: d.terminationResultCode(), Message: "build cancelled"}
	}
	if verifyRes.Err != nil {
		d.internalTagCleanupBestEffort()
		return buildStageResult{ExitCode: verifyRes.ExitCode, ResultCode: "docker_build_failed", Message: "docker load failed"}
	}

	// G. commit: docker tag <internal> <requested> through the one
	// linearized commit-stage primitive.
	commitRes := d.commitStage()
	if commitRes.Terminated {
		// The commit stage was REFUSED by the termination latch: the
		// requested image is untouched; clean up the imported internal tag.
		d.internalTagCleanupBestEffort()
		return buildStageResult{ResultCode: d.terminationResultCode(), Message: "build cancelled"}
	}
	if commitRes.Err != nil {
		// The commit child failed or was killed: result follows the commit
		// outcome, never cancelled (§17).
		d.internalTagCleanupBestEffort()
		return buildStageResult{ExitCode: commitRes.ExitCode, ResultCode: "docker_build_failed", Message: "docker tag failed"}
	}

	// docker tag exited 0: BUILD SUCCEEDED irrevocably. Everything below is
	// bounded cleanup that cannot downgrade the result.

	// Post-commit internal-tag cleanup: fresh bounded server-owned context,
	// NOT a cancellable operation stage (§19).
	d.internalTagCleanupBestEffort()

	return buildStageResult{ResultCode: "succeeded", CommitSucceeded: true}
}

// finish is the ONE terminal-transition owner after cleanup: staging
// cleanup, then (only on staging success) the MAC lease release, then the
// terminal operation transition through the existing succeed/fail owners
// (capacity release rides on them).
func (d *buildDriver) finish(result buildStageResult) {
	op := d.op

	op.mu.Lock()
	started := time.Time{}
	if op.StartedAt != nil {
		started = *op.StartedAt
	}
	op.mu.Unlock()
	// A build whose first stage never started a child reports the handler
	// creation time as its duration anchor.
	if started.IsZero() {
		started = op.CreatedAt
	}
	duration := time.Since(started).Round(time.Millisecond).String()

	// Staging cleanup: removes the staged context AND the export tar
	// (both live under the one operation-scoped staging tree).
	cleanupErr := error(nil)
	if op.stagedCtx != nil {
		cleanupErr = op.stagedCtx.Cleanup()
		if cleanupErr != nil {
			ctx := withSessionID(context.Background(), op.SessionID)
			opLog(ctx).Error("staging cleanup failed — MAC lease intentionally retained because workspace-dependent cleanup did not complete",
				slog.String("operation", "build"),
				slog.String("operation_id", op.ID),
				slog.String("error", cleanupErr.Error()),
			)
		}
	}

	// Release session-use lease only if staging cleanup succeeded (§27).
	if cleanupErr == nil && op.macLeaseRelease != nil {
		op.macLeaseRelease()
	}

	if result.ResultCode == "succeeded" {
		op.succeed(&duration)
		return
	}
	if result.ResultCode == resultCancelled {
		op.fail(resultCancelled, result.Message, result.ExitCode, &duration)
		return
	}
	op.fail(result.ResultCode, result.Message, result.ExitCode, &duration)
}

// terminationResultCode resolves the public result code of a latched
// termination BEFORE commit-stage admission: explicit cancel is cancelled;
// shutdown keeps the current kind-specific failure code (no public
// shutdown result code exists).
func (d *buildDriver) terminationResultCode() string {
	op := d.op
	op.mu.Lock()
	reason := op.reason
	op.mu.Unlock()
	if reason == terminationCancelled {
		return resultCancelled
	}
	return "docker_build_failed"
}

// terminationResultCodeAfterCommitAdmission resolves the result code when
// termination arrived after the commit stage was admitted: the commit
// outcome owns the result; cancellation can no longer downgrade it (§17).
func (d *buildDriver) terminationResultCodeAfterCommitAdmission(commitOK bool) string {
	if commitOK {
		return "succeeded"
	}
	return "docker_build_failed"
}

// latchObserved reports whether the permanent termination latch is set
// under op.mu.
func (d *buildDriver) latchObserved() bool {
	op := d.op
	op.mu.Lock()
	defer op.mu.Unlock()
	return op.terminationRequested
}

// logStage emits one bounded internal operational diagnostic for a build
// stage. Internal logging may name the stage vocabulary; it never exposes
// credential values, Docker config contents, or internal paths as
// caller-facing errors.
func (d *buildDriver) logStage(stage string, err error) {
	ctx := withSessionID(context.Background(), d.op.SessionID)
	if err != nil {
		opLog(ctx).Error("build stage failed",
			slog.String("operation", "build"),
			slog.String("operation_id", d.op.ID),
			slog.String("stage", stage),
			slog.String("error", err.Error()),
		)
		return
	}
	opLog(ctx).Info("build stage",
		slog.String("operation", "build"),
		slog.String("operation_id", d.op.ID),
		slog.String("stage", stage),
	)
}

// validateSocket runs the configured socket-validation owner (production:
// validateBuildKitSocket; narrow test seam on the App).
func (d *buildDriver) validateSocket() error {
	if d.a.validateBuildKitSocketFn != nil {
		return d.a.validateBuildKitSocketFn(d.op.ID)
	}
	return validateBuildKitSocket(d.op.ID)
}

// managerStartStage runs the manager START round-trip through the
// cancellable no-child control stage and the P2 client.
func (d *buildDriver) managerStartStage() buildStageResult {
	client := d.builderClient()
	var startErr error
	res := runOperationControlStage(d.op, func(ctx context.Context) error {
		startErr = client.Start(ctx, d.op.ID)
		return startErr
	})
	if res.Terminated {
		return buildStageResult{Terminated: true}
	}
	if res.Err != nil {
		d.logStage("builder_start", startErr)
		return buildStageResult{Err: startErr}
	}
	d.builderStarted = true
	d.logStage("builder_start", nil)
	return buildStageResult{}
}

// builderClient returns the P2 manager client (the single RPC owner).
func (d *buildDriver) builderClient() *builderManagerClient {
	if d.a.builderClientFn != nil {
		return d.a.builderClientFn()
	}
	return &builderManagerClient{}
}

// builderStopCleanup performs the mandatory manager STOP cleanup on a
// fresh bounded server-owned context (never the cancelled operation
// context). Ambiguity retry stays inside the P2 client.
func (d *buildDriver) builderStopCleanup() error {
	ctx, cancel := context.WithTimeout(context.Background(), buildCleanupContextTimeout)
	defer cancel()
	if err := d.builderClient().Stop(ctx, d.op.ID); err != nil {
		d.logStage("builder_stop", err)
		return err
	}
	d.logStage("builder_stop", nil)
	return nil
}

// buildctlStage assembles the exact server-owned buildctl invocation and
// runs it as a normal P1 child stage.
func (d *buildDriver) buildctlStage() buildStageResult {
	staged := d.op.stagedCtx
	if staged == nil {
		return buildStageResult{Err: errors.New("staged build context missing")}
	}
	args := buildctlArgs(buildctlArgsInput{
		OperationID:   d.op.ID,
		ContextPath:   staged.ContextPath,
		DockerfileRel: d.stagedDockerfileRel(),
		BuildArgKeys:  d.req.BuildArgKeys,
		BuildArgs:     d.req.BuildArgs,
		InternalTag:   buildInternalTag(d.op.ID),
		ExportPath:    buildExportTarPath(staged),
	})
	cmd := d.newChild(context.Background(), buildctlBinary, args...)
	cmd.Env = []string{"DOCKER_CONFIG=" + d.req.DockerDir}
	return d.runChildStage(cmd, "buildctl")
}

// stagedDockerfileRel derives the staged Dockerfile path relative to the
// staged context root. The staging owner copied the Dockerfile at exactly
// the validated relative path inside the staged context, so the relative
// derivation is mechanical: strip the staged context prefix.
func (d *buildDriver) stagedDockerfileRel() string {
	staged := d.op.stagedCtx
	rel, err := filepath.Rel(staged.ContextPath, staged.DockerfilePath)
	if err != nil || rel == "." {
		// Unreachable for a valid staging result (the staging owner
		// guarantees the layout); fail closed.
		return ""
	}
	return rel
}

// loadStage runs `docker load --input <export.tar>` through the existing
// trusted Docker CLI owner as a normal P1 child stage.
func (d *buildDriver) loadStage() buildStageResult {
	staged := d.op.stagedCtx
	if staged == nil {
		return buildStageResult{Err: errors.New("staged build context missing")}
	}
	exportPath := buildExportTarPath(staged)
	cmd := d.newChild(context.Background(), "docker", "load", "--input", exportPath)
	return d.runChildStage(cmd, "image_import")
}

// verifyInternalTag proves the exact internal tag resolves in the local
// Engine through the existing Docker CLI owner. It is a normal P1 child
// stage: admitted through startOperationStage, waited through the single
// Wait owner waitCurrentStage, and classified against the termination
// latch by the shared runChildStage owner — a latched termination refuses
// admission (no inspect process starts) and a termination during the
// stage signals the admitted child. The 30s bound is the existing
// server-owned bounded-context constant.
func (d *buildDriver) verifyInternalTag() buildStageResult {
	ctx, cancel := context.WithTimeout(context.Background(), buildCleanupContextTimeout)
	defer cancel()
	cmd := d.newChild(ctx, "docker", "image", "inspect", buildInternalTag(d.op.ID))
	return d.runChildStage(cmd, "image_import_verification")
}

// commitStage runs the ONE linearized commit-stage primitive with the
// docker tag command.
func (d *buildDriver) commitStage() buildStageResult {
	op := d.op
	cmd := d.newChild(context.Background(), "docker", "tag", buildInternalTag(op.ID), d.req.Image)
	return startOperationCommitStage(op, cmd)
}

// newChild creates a child process through the existing command seam.
func (d *buildDriver) newChild(ctx context.Context, name string, args ...string) *exec.Cmd {
	return d.a.newDockerCommand(ctx, name, args...)
}

// runChildStage is the shared child-stage runner: admit through the P1
// owner, wait through the single Wait owner, and classify the outcome
// against the termination latch.
func (d *buildDriver) runChildStage(cmd *exec.Cmd, stage string) buildStageResult {
	result := startOperationStage(cmd, d.op)
	if result.Terminated {
		return buildStageResult{Terminated: true}
	}
	if result.Err != nil {
		d.logStage(stage, result.Err)
		return buildStageResult{Err: result.Err}
	}
	waitErr := d.op.waitCurrentStage()

	// Classification: a termination that arrived during the stage may
	// signal the child, but the LATCH vs the child outcome decides. A
	// cancelled child (Wait error after termination) is the cancelled
	// result; a child that exited nonzero without termination is the
	// stage failure; a clean child exit is success.
	if waitErr != nil {
		if d.latchObserved() {
			return buildStageResult{ExitCode: extractExitCode(waitErr), Terminated: true}
		}
		d.logStage(stage, waitErr)
		return buildStageResult{ExitCode: extractExitCode(waitErr), Err: waitErr}
	}
	d.logStage(stage, nil)
	return buildStageResult{}
}

// internalTagCleanupBestEffort removes the exact internal tag with a fresh
// bounded server-owned context. It is NOT a cancellable operation stage:
// it must also run after a successful commit (an already-latched
// cancellation must not suppress cleanup) and its failure never downgrades
// a committed build. One attempt; already-absent is success.
func (d *buildDriver) internalTagCleanupBestEffort() {
	ctx, cancel := context.WithTimeout(context.Background(), buildCleanupContextTimeout)
	defer cancel()
	cmd := d.newChild(ctx, "docker", "rmi", buildInternalTag(d.op.ID))
	if err := cmd.Run(); err != nil {
		d.logStage("cleanup", err)
		return
	}
	d.logStage("cleanup", nil)
}

// startOperationCommitStage is the ONE commit-stage admission primitive
// (§16). Under ONE op.mu critical section it: refuses when the termination
// latch is set; asserts no current execution stage; installs the commit
// command in the current-child slot; marks commitClaimed; and starts the
// child while still holding the lock. The irreversible success point
// remains `docker tag` exit 0, owned by the driver's Wait.
func startOperationCommitStage(op *operation, cmd *exec.Cmd) buildStageResult {
	op.mu.Lock()
	if op.terminationRequested {
		op.mu.Unlock()
		return buildStageResult{Terminated: true}
	}
	if op.currentCmd != nil || op.currentCancel != nil {
		op.mu.Unlock()
		return buildStageResult{Err: errors.New("operation already owns an active execution stage")}
	}
	cmd.Stdout = op.LogBuffer
	cmd.Stderr = op.LogBuffer
	op.currentCmd = cmd
	op.commitClaimed = true
	err := cmd.Start()
	if err != nil {
		op.currentCmd = nil
		op.mu.Unlock()
		return buildStageResult{Err: err}
	}
	op.mu.Unlock()

	waitErr := op.waitCurrentStage()
	if waitErr != nil {
		// The commit child failed or was killed after admission. The result
		// follows the commit outcome (docker_build_failed), never
		// cancelled (§17) — even when a termination raced in.
		return buildStageResult{ExitCode: extractExitCode(waitErr), Err: waitErr}
	}
	return buildStageResult{CommitSucceeded: true}
}

// buildctlArgsInput is the exact input of the buildctl argv mapping.
type buildctlArgsInput struct {
	OperationID   string
	ContextPath   string // staged context root
	DockerfileRel string // staged-relative dockerfile path ("" = root Dockerfile)
	BuildArgKeys  []string
	BuildArgs     map[string]string
	InternalTag   string
	ExportPath    string
}

// buildctlArgs is the ONE owner of the server-owned buildctl argv (§8):
// fixed frontend, fixed progress, staged paths only, fixed exporter with
// the internal tag, sorted build args, no caller-controlled socket,
// frontend, network, entitlements, cache, or output.
func buildctlArgs(in buildctlArgsInput) []string {
	socketAddr := "unix://" + opSocketPath(in.OperationID)

	// Dockerfile local context: the directory containing the Dockerfile
	// inside the STAGED context (never the original workspace path).
	dockerfileDir := in.ContextPath
	if in.DockerfileRel != "" {
		dockerfileDir = filepath.Join(in.ContextPath, filepath.Dir(in.DockerfileRel))
	}

	args := []string{
		"--addr", socketAddr,
		"build",
		"--progress=plain",
		"--frontend=dockerfile.v0",
		"--local", "context=" + in.ContextPath,
		"--local", "dockerfile=" + dockerfileDir,
		"--opt", "filename=" + filepath.Base(in.DockerfileRel),
	}

	// Build args in sorted key order (§8).
	keys := in.BuildArgKeys
	if keys == nil {
		keys = make([]string, 0, len(in.BuildArgs))
		for k := range in.BuildArgs {
			keys = append(keys, k)
		}
		sort.Strings(keys)
	}
	for _, key := range keys {
		args = append(args, "--opt", "build-arg:"+key+"="+in.BuildArgs[key])
	}

	// Exporter: docker tar with the one server-owned internal tag.
	args = append(args,
		"--output", "type=docker,name="+in.InternalTag+",dest="+in.ExportPath,
	)
	return args
}

// validateBuildKitSocket is the root-side independent validation of the
// deterministic BuildKit endpoint (§6): exists, no symlink, a Unix socket,
// owned by the builder UID, private mode. It uses the ONE shared path
// owner from P2 (opSocketPath).
func validateBuildKitSocket(opID string) error {
	return validateBuildKitSocketPath(opSocketPath(opID), builderClientManagerUID)
}

// validateBuildKitSocketPath is the path-parameterized body of the root-side
// BuildKit endpoint validation: one call site owns the deterministic
// opSocketPath derivation; the expected-owner resolver is the P2 seam
// (production: builderClientManagerUID; tests: a fixed test identity).
func validateBuildKitSocketPath(socketPath string, expectedUID func() (int, int, error)) error {
	info, err := os.Lstat(socketPath)
	if err != nil {
		return fmt.Errorf("buildkit socket missing: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("buildkit socket is a symlink")
	}
	if info.Mode()&os.ModeSocket == 0 {
		return errors.New("buildkit socket is not a socket")
	}
	uid, _, err := expectedUID()
	if err != nil {
		return err
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat != nil {
		if stat.Uid != uint32(uid) {
			return errors.New("buildkit socket is not owned by the builder identity")
		}
	}
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("buildkit socket is not private")
	}
	return nil
}

// exportDiagnosticsSummary captures bounded internal load diagnostics: the
// `docker load` child stage writes into the operation LogBuffer like every
// other stage (the existing explicitly chosen build-log policy), and no
// additional public exposure exists.
func exportDiagnosticsSummary(op *operation) string {
	data, _, _ := op.LogBuffer.Range(0, logResponseChunkBytes)
	return string(data)
}
