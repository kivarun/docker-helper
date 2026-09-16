package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// H8 liveness suite (SC2 — bounded MAC-command liveness).
//
// Every coordination test in this file is RED/GREEN evidence: a seam-parked
// external MAC one-shot command parks shared lifecycle coordination, and the
// fixed Release-2.2 MAC transition budget terminates the parked command and
// releases the coordination. On the pre-fix release line each test fails at
// its bounded observation window (the coordination never progresses); after
// the fix it passes with the parked command killed at the budget.
//
// No sleeps-as-proof: the bounded observation window is the instrument that
// proves non-arrival; the parked seams are channels the test controls. The
// kill/reap proof uses a short real process bounded by the test budget —
// never a permanently hung host process.

// macLivenessObservationWindow is the bounded window during which a parked
// coordination must NOT progress (pre-fix defect) and during which a
// budgeted coordination MUST have progressed (post-fix). Generous for -race
// and CI scheduling.
const macLivenessObservationWindow = 750 * time.Millisecond

// macLivenessCompletionSlop is the scheduling slop added to the deadline for
// post-fix "progressed within the proven bound" wall-clock assertions.
const macLivenessCompletionSlop = 5 * time.Second

// macLivenessBudgetOverride is the test-narrow MAC transition budget. The
// production budget stays the fixed security constant; liveness tests narrow
// it deterministically through this package seam (never in parallel tests).
const macLivenessBudgetOverride = 300 * time.Millisecond

// macLivenessQueueBudgetOverride is the queue-proof budget. It must stay
// large against scheduling jitter (the queue arithmetic is wall-clock) and
// small enough to keep the pre-fix failure fast.
const macLivenessQueueBudgetOverride = 2 * time.Second

// macLivenessQueueDisableSlop is the scheduling slop on top of ONE budget
// for the queue-proof disable deadline. Pre-fix the disable waits behind
// every queued create's own fresh budget (queuedCreates+1 budgets total),
// far beyond this bound; post-fix it waits only behind the one in-flight
// transition.
const macLivenessQueueDisableSlop = 2 * time.Second

// h8QueueBudgetCount is the number of additional Session creates the queue
// proof issues while the first create holds the lifecycle coordination.
const h8QueueBudgetCount = 4

// h8BudgetOverride narrows the fixed MAC transition budget to a
// deterministic test value for the duration of a test and restores it.
func h8BudgetOverride(t *testing.T) {
	t.Helper()
	origBudget := macTransitionBudget
	macTransitionBudget = macLivenessBudgetOverride
	t.Cleanup(func() { macTransitionBudget = origBudget })
}

// h8QueueBudgetOverride narrows the fixed MAC transition budget to the
// queue-proof value for the duration of a test and restores it.
func h8QueueBudgetOverride(t *testing.T) {
	t.Helper()
	origBudget := macTransitionBudget
	macTransitionBudget = macLivenessQueueBudgetOverride
	t.Cleanup(func() { macTransitionBudget = origBudget })
}

// h8ParkedCommand parks one command execution until release is closed or the
// transition context expires (the budget kills the parked command, exactly
// like a real hung process under the bounded runner), signaling the entry on
// entered exactly once.
func h8ParkedCommand(ctx context.Context, entered chan<- struct{}, release <-chan struct{}) error {
	var once sync.Once
	once.Do(func() { entered <- struct{}{} })
	select {
	case <-release:
		return nil
	case <-ctx.Done():
		return macCommandError(ctx, "parked", context.DeadlineExceeded)
	}
}

// setupH8AppArmorParkedCoordinator builds an App whose session MAC
// coordinator runs the REAL AppArmor workspace driver over test-isolated
// state, with the parser runner parked deterministically.
func setupH8AppArmorParkedCoordinator(t *testing.T) (*App, <-chan struct{}, chan struct{}) {
	t.Helper()
	mockAppArmorActive(t, true)
	mockSELinuxInactive(t)
	savedEffectiveUID := EffectiveUID
	EffectiveUID = func() int { return 0 }
	t.Cleanup(func() { EffectiveUID = savedEffectiveUID })

	entered := make(chan struct{}, 8)
	release := make(chan struct{})
	_, mgr := setupAppArmorTestWithRunner(t, func(ctx context.Context, _ string, _ []string) error {
		return h8ParkedCommand(ctx, entered, release)
	})

	driver := &appArmorMACDriver{
		addManagedBoundary:    mgr.addManagedBoundary,
		removeManagedBoundary: mgr.removeManagedBoundary,
		listManagedBoundaries: mgr.listManagedBoundaries,
	}

	db, err := openDatabase(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("openDatabase: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initializeDatabase: %v", err)
	}
	if _, err := migrateSessionFilesystemSnapshots(db); err != nil {
		t.Fatalf("migrateSessionFilesystemSnapshots: %v", err)
	}

	allowedRoot := testAllowedRootDir(t)
	runtimeDir := t.TempDir()
	cfg := &Config{
		AllowedRoots:          []AllowedRootEntry{allowedRootEntry(allowedRoot)},
		SessionTTL:            24 * time.Hour,
		SocketPath:            filepath.Join(runtimeDir, "test.sock"),
		StateDir:              runtimeDir,
		RuntimeDir:            runtimeDir,
		DatabasePath:          filepath.Join(runtimeDir, "db"),
		AdminTokenPath:        filepath.Join(runtimeDir, "admin.token"),
		ShutdownTimeout:       30 * time.Second,
		OperationRetentionTTL: 10 * time.Minute,
		OperationMaxCompleted: 200,
		OperationLogMaxBytes:  4 * 1024 * 1024,
		Mode:                  ModeUser,
	}
	app := &App{Config: cfg, DB: db, MACCoordinator: newSessionMACCoordinator(db, driver)}
	home := filepath.Join(allowedRoot, "daemon-home")
	if err := os.MkdirAll(home, 0700); err != nil {
		t.Fatalf("cannot create daemon home: %v", err)
	}
	app.userModeDefault = provisionTestOwner(t, db, allowedRoot, home, os.Getuid(), os.Getgid())
	return app, entered, release
}

// setupH8SELinuxParkedCoordinator builds an App whose session MAC coordinator
// runs the REAL SELinux fcontext manager mechanics with the external command
// seam parked deterministically (the semanage fcontext listing that opens
// every workspace preparation). The allowed root lives outside /home so the
// workspace preparation actually reaches the fcontext mechanics (home-path
// workspaces are deliberately exempt from fcontext management).
func setupH8SELinuxParkedCoordinator(t *testing.T) (*App, <-chan struct{}, chan struct{}) {
	t.Helper()

	entered := make(chan struct{}, 8)
	release := make(chan struct{})

	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.semanagePath = semanagePath
	mgr.restoreconPath = restoreconPath
	mgr.runCommand = func(ctx context.Context, _ string, _ ...string) ([]byte, error) {
		if err := h8ParkedCommand(ctx, entered, release); err != nil {
			return nil, err
		}
		return []byte{}, nil
	}
	mgr.readPathCon = func(string) (string, error) { return selinuxWorkspaceType, nil }
	driver := &selinuxMACDriver{mgr: mgr, treeKind: macBoundaryKindFor}

	db, err := openDatabase(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("openDatabase: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initializeDatabase: %v", err)
	}
	if _, err := migrateSessionFilesystemSnapshots(db); err != nil {
		t.Fatalf("migrateSessionFilesystemSnapshots: %v", err)
	}

	allowedRoot := t.TempDir()
	runtimeDir := t.TempDir()
	cfg := &Config{
		AllowedRoots:          []AllowedRootEntry{allowedRootEntry(allowedRoot)},
		SessionTTL:            24 * time.Hour,
		SocketPath:            filepath.Join(runtimeDir, "test.sock"),
		StateDir:              runtimeDir,
		RuntimeDir:            runtimeDir,
		DatabasePath:          filepath.Join(runtimeDir, "db"),
		AdminTokenPath:        filepath.Join(runtimeDir, "admin.token"),
		ShutdownTimeout:       30 * time.Second,
		OperationRetentionTTL: 10 * time.Minute,
		OperationMaxCompleted: 200,
		OperationLogMaxBytes:  4 * 1024 * 1024,
		Mode:                  ModeUser,
	}
	app := &App{Config: cfg, DB: db, MACCoordinator: newSessionMACCoordinator(db, driver)}
	home := filepath.Join(allowedRoot, "daemon-home")
	if err := os.MkdirAll(home, 0700); err != nil {
		t.Fatalf("cannot create daemon home: %v", err)
	}
	app.userModeDefault = provisionTestOwner(t, db, allowedRoot, home, os.Getuid(), os.Getgid())
	return app, entered, release
}

// setupH8DisableTarget wires the operation supervisor and provisions a
// non-reserved Principal + Launcher to disable, returning the launcher ID and
// the principal username.
func setupH8DisableTarget(t *testing.T, app *App) (string, string) {
	t.Helper()
	app.OperationSupervisor = newOperationSupervisor()
	allowedRoot := app.Config.AllowedRoots[0].Path
	_, home := setupPrincipalForLauncherTest(t, app.DB, []string{allowedRoot}, "h8victim")
	_ = home
	l, _, _, err := createLauncher(app.DB, principalIDByName(t, app.DB, "h8victim"), "h8launcher", LauncherScopeInherit, nil, []string{allowedRoot}, false)
	if err != nil {
		t.Fatalf("createLauncher: %v", err)
	}
	return l.ID, "h8victim"
}

// h8RunConcurrentDisables requests a Launcher disable and a Principal disable
// concurrently and returns their completion channels.
func h8RunConcurrentDisables(app *App, launcherID, username string) (chan error, chan error) {
	disableLauncherDone := make(chan error, 1)
	go func() {
		disabled := false
		_, _, err := app.updateLauncherWithLifecycle(launcherID, nil, &disabled)
		disableLauncherDone <- err
	}()
	disablePrincipalDone := make(chan error, 1)
	go func() {
		_, err := app.disablePrincipalLaunchers(username)
		disablePrincipalDone <- err
	}()
	return disableLauncherDone, disablePrincipalDone
}

// h8AwaitDisables waits for both disables to reach their authoritative
// transitions within the deadline. Pre-fix this fails at the deadline with
// the H8 defect message; post-fix it passes.
func h8AwaitDisables(t *testing.T, disableLauncherDone, disablePrincipalDone chan error) {
	t.Helper()
	deadline := time.After(macLivenessObservationWindow + macLivenessCompletionSlop)
	launcherCommitted := false
	principalCommitted := false
	for !launcherCommitted || !principalCommitted {
		select {
		case err := <-disableLauncherDone:
			if err != nil {
				t.Fatalf("launcher disable failed: %v", err)
			}
			launcherCommitted = true
		case err := <-disablePrincipalDone:
			if err != nil {
				t.Fatalf("principal disable failed: %v", err)
			}
			principalCommitted = true
		case <-deadline:
			t.Fatal("administrative disable did not reach its authoritative transition within the bounded window: the parked MAC command holds lifecycle coordination without any bound (H8 defect)")
		}
	}
}

// h8AwaitCreateFailure waits for the parked create to terminate and asserts
// it failed as MAC preparation through the typed budget error (never a false
// success).
func h8AwaitCreateFailure(t *testing.T, createErr chan error) {
	t.Helper()
	select {
	case err := <-createErr:
		if err == nil {
			t.Fatal("a Session create whose MAC preparation exceeded the budget must fail, not succeed")
		}
		if !errors.Is(err, ErrMACPreparation) {
			t.Fatalf("create error = %v, want ErrMACPreparation in the failure chain", err)
		}
		if !errors.Is(err, ErrMACTransitionBudgetExceeded) {
			t.Fatalf("create error = %v, want ErrMACTransitionBudgetExceeded in the failure chain", err)
		}
	case <-time.After(macLivenessCompletionSlop):
		t.Fatal("the parked create did not terminate after the MAC budget expired")
	}
}

// h8DisabledStates asserts both disable targets are durably disabled.
func h8DisabledStates(t *testing.T, app *App, launcherID, username string) {
	t.Helper()
	var enabled int
	if err := app.DB.QueryRow(`SELECT enabled FROM launchers WHERE id = ?`, launcherID).Scan(&enabled); err != nil {
		t.Fatalf("read launcher enabled: %v", err)
	}
	if enabled != 0 {
		t.Error("launcher must be durably disabled after the disable transition")
	}
	if err := app.DB.QueryRow(`SELECT enabled FROM principals WHERE username = ?`, username).Scan(&enabled); err != nil {
		t.Fatalf("read principal enabled: %v", err)
	}
	if enabled != 0 {
		t.Error("principal must be durably disabled after the disable transition")
	}
}

// h8NoSessionCommitted asserts the create committed no session for its
// launcher and the disabled launcher carries none.
func h8NoSessionCommitted(t *testing.T, app *App, ownerLauncherID, disabledLauncherID string) {
	t.Helper()
	for _, id := range []string{ownerLauncherID, disabledLauncherID} {
		if got := h8SessionCount(t, app, id); got != 0 {
			t.Errorf("launcher %s carries %d sessions, want 0", id, got)
		}
	}
}

// h8SessionCount counts live sessions of one launcher.
func h8SessionCount(t *testing.T, app *App, launcherID string) int {
	t.Helper()
	var n int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM sessions WHERE launcher_id = ?`, launcherID).Scan(&n); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	return n
}

// h8AdmissionClosed asserts operation admission is closed for the disabled
// launcher as required.
func h8AdmissionClosed(t *testing.T, app *App, launcherID string) {
	t.Helper()
	if _, decision := app.OperationSupervisor.reserve("dhs_h8admission", launcherID, operationKindRun); decision != admissionRefusedQuiesced {
		t.Errorf("operation admission after disable = %v, want admissionRefusedQuiesced", decision)
	}
}

// TestH8HungAppArmorParserParksSessionCreateAndBlocksDisable proves RED case
// 1: a hung apparmor_parser keeps a Session create holding lifecycleMu (the
// create's MAC preparation runs inside the lifecycle create linearization
// boundary), so concurrent Launcher and Principal disables cannot reach their
// authoritative transitions today.
//
// Post-fix, the parked parser is terminated by the fixed MAC transition
// budget: the create fails, both disables reach their linearization points
// within the proven bound, no Session is committed, operation admission is
// closed, no coordination lock stays stranded, and the next ordinary MAC
// transition succeeds.
func TestH8HungAppArmorParserParksSessionCreateAndBlocksDisable(t *testing.T) {
	h8BudgetOverride(t)

	app, entered, release := setupH8AppArmorParkedCoordinator(t)
	launcherID, username := setupH8DisableTarget(t, app)
	allowedRoot := app.Config.AllowedRoots[0].Path
	workspace := testWorkspaceDir(t, allowedRoot)

	createErr := make(chan error, 1)
	go func() {
		_, err := createDefaultAdminSessionForTest(app, workspace)
		createErr <- err
	}()

	select {
	case <-entered:
	case <-time.After(macLivenessObservationWindow):
		t.Fatal("the parked create never reached the AppArmor parser command")
	}

	disableLauncherDone, disablePrincipalDone := h8RunConcurrentDisables(app, launcherID, username)
	h8AwaitDisables(t, disableLauncherDone, disablePrincipalDone)

	h8AwaitCreateFailure(t, createErr)
	h8DisabledStates(t, app, launcherID, username)
	h8NoSessionCommitted(t, app, app.userModeDefault.launcherID, launcherID)
	h8AdmissionClosed(t, app, launcherID)

	// No coordination lock stays stranded: after the hostile condition is
	// removed, the next ordinary MAC transition succeeds.
	close(release)
	secondWorkspace := testWorkspaceDir(t, allowedRoot)
	second, err := createDefaultAdminSessionForTest(app, secondWorkspace)
	if err != nil {
		t.Fatalf("the next ordinary session create after the hostile condition must succeed: %v", err)
	}
	app.MACCoordinator.ReleaseSessionBinding(second.Session.ID)
}

// h8RunQueuedCreatesDisableProof is the deterministic queue liveness proof
// shared by both MAC backends. The first Session create enters a parked
// backend MAC command and holds the lifecycle coordination; four further
// Session creates are issued while it holds the boundary; only then is the
// Launcher/Principal disable requested.
//
// The single bounded window anchored at the in-flight create's budget
// start proves the H8 queue closure: every queued create must receive its
// refusal within the window (it must never queue behind the coordination
// and execute its own later MAC transition), and the disable must reach its
// authoritative transition within ONE in-flight transition budget — its
// delay must not grow with the queued create count. On the pre-fix line the
// queued creates block on the held lifecycleMu and each one, once served,
// obtains its own fresh whole-transition budget, so the disable completes
// only after (queuedCreates+1) budgets and the window expires with the
// defect message.
func h8RunQueuedCreatesDisableProof(t *testing.T, app *App, entered <-chan struct{}, release chan struct{}) {
	t.Helper()
	launcherID, username := setupH8DisableTarget(t, app)
	allowedRoot := app.Config.AllowedRoots[0].Path

	// 1. The in-flight create parks in the backend MAC command and holds
	//    the lifecycle coordination.
	createErrs := make([]chan error, h8QueueBudgetCount+1)
	parkWorkspace := testWorkspaceDir(t, allowedRoot)
	createErrs[0] = make(chan error, 1)
	go func() {
		_, err := createDefaultAdminSessionForTest(app, parkWorkspace)
		createErrs[0] <- err
	}()

	select {
	case <-entered:
	case <-time.After(macLivenessObservationWindow):
		t.Fatal("the parked create never reached the backend MAC command")
	}

	// 2. The queued creates are issued while the boundary is held.
	for i := 1; i <= h8QueueBudgetCount; i++ {
		queuedWorkspace := testWorkspaceDir(t, allowedRoot)
		queuedErr := make(chan error, 1)
		createErrs[i] = queuedErr
		go func() {
			_, err := createDefaultAdminSessionForTest(app, queuedWorkspace)
			queuedErr <- err
		}()
	}

	// 3. The emergency disable is requested after the queued creates.
	disableLauncherDone, disablePrincipalDone := h8RunConcurrentDisables(app, launcherID, username)

	// 4. One bounded window: the queued creates must be refused and the
	//    disable must commit within one in-flight transition budget plus
	//    slop, whatever the queued create count.
	deadline := time.After(macLivenessQueueBudgetOverride + macLivenessQueueDisableSlop)
	refusalErrs := make([]error, h8QueueBudgetCount)
	refusals := 0
	disableLauncherCommitted := false
	disablePrincipalCommitted := false
	inFlightErr := false
	for refusals < h8QueueBudgetCount || !disableLauncherCommitted || !disablePrincipalCommitted || !inFlightErr {
		select {
		case err := <-createErrs[0]:
			if err == nil {
				t.Fatal("the in-flight create whose MAC preparation exceeded the budget must fail, not succeed")
			}
			inFlightErr = true
		case err := <-createErrs[1]:
			refusalErrs[0] = err
			refusals++
		case err := <-createErrs[2]:
			refusalErrs[1] = err
			refusals++
		case err := <-createErrs[3]:
			refusalErrs[2] = err
			refusals++
		case err := <-createErrs[4]:
			refusalErrs[3] = err
			refusals++
		case err := <-disableLauncherDone:
			if err != nil {
				t.Fatalf("launcher disable failed: %v", err)
			}
			disableLauncherCommitted = true
		case err := <-disablePrincipalDone:
			if err != nil {
				t.Fatalf("principal disable failed: %v", err)
			}
			disablePrincipalCommitted = true
		case <-deadline:
			t.Fatalf("the queued creates and the disable did not settle within one in-flight transition budget plus slop: queued Session creates queue behind the held lifecycle coordination and each one obtains its own fresh whole-transition MAC budget, so the emergency disable's delay grows with the queued create count (H8 queue defect)")
		}
	}

	// 5. Every queued create must have been refused, never executed later:
	//    a refusal is an error, never a committed Session.
	for i, err := range refusalErrs {
		if err == nil {
			t.Fatalf("queued create %d committed a Session instead of being refused", i+1)
		}
	}

	// 6. The in-flight create keeps the existing whole-transition MAC
	//    budget: its parked command was terminated at the budget and the
	//    failure carries the typed budget error inside the MAC preparation
	//    chain — never a false success.
	if err := <-createErrs[0]; err != nil {
		if !errors.Is(err, ErrMACPreparation) {
			t.Fatalf("in-flight create error = %v, want ErrMACPreparation in the failure chain", err)
		}
		if !errors.Is(err, ErrMACTransitionBudgetExceeded) {
			t.Fatalf("in-flight create error = %v, want ErrMACTransitionBudgetExceeded in the failure chain", err)
		}
	}

	// 7. Post-disable state: both disable targets are durably disabled, no
	//    Session was committed by any create, and operation admission is
	//    closed for the disabled launcher.
	h8DisabledStates(t, app, launcherID, username)
	h8NoSessionCommitted(t, app, app.userModeDefault.launcherID, launcherID)
	h8AdmissionClosed(t, app, launcherID)

	// 8. No coordination is stranded: after the hostile condition is
	//    removed, the next ordinary MAC transition succeeds.
	close(release)
	afterWorkspace := testWorkspaceDir(t, allowedRoot)
	after, err := createDefaultAdminSessionForTest(app, afterWorkspace)
	if err != nil {
		t.Fatalf("the next ordinary session create after the hostile condition must succeed: %v", err)
	}
	app.MACCoordinator.ReleaseSessionBinding(after.Session.ID)
}

// TestH8QueuedAppArmorSessionCreatesDoNotDelayDisable proves the H8 queue
// closure on the AppArmor backend: Session creates issued while one parked
// create holds the lifecycle coordination are refused without queueing, and
// the concurrent Launcher/Principal disable is delayed by at most the one
// in-flight transition budget — never by the queued create count.
func TestH8QueuedAppArmorSessionCreatesDoNotDelayDisable(t *testing.T) {
	h8QueueBudgetOverride(t)

	app, entered, release := setupH8AppArmorParkedCoordinator(t)
	h8RunQueuedCreatesDisableProof(t, app, entered, release)
}

// TestH8QueuedSELinuxSessionCreatesDoNotDelayDisable proves the same H8
// queue closure on the SELinux backend: the parked fcontext one-shot holds
// the lifecycle coordination, queued creates are refused without queueing,
// and the concurrent disable is delayed by at most one transition budget.
func TestH8QueuedSELinuxSessionCreatesDoNotDelayDisable(t *testing.T) {
	h8QueueBudgetOverride(t)

	app, entered, release := setupH8SELinuxParkedCoordinator(t)
	h8RunQueuedCreatesDisableProof(t, app, entered, release)
}

// TestH8HungSELinuxFcontextParksSessionCreateAndBlocksDisable proves RED case
// 2: a hung SELinux one-shot command (the semanage fcontext listing that
// opens every workspace preparation) parks a Session create inside the same
// lifecycle linearization boundary, so a concurrent administrative disable
// cannot proceed.
func TestH8HungSELinuxFcontextParksSessionCreateAndBlocksDisable(t *testing.T) {
	h8BudgetOverride(t)

	app, entered, release := setupH8SELinuxParkedCoordinator(t)
	launcherID, username := setupH8DisableTarget(t, app)
	allowedRoot := app.Config.AllowedRoots[0].Path
	workspace := testWorkspaceDir(t, allowedRoot)

	createErr := make(chan error, 1)
	go func() {
		_, err := createDefaultAdminSessionForTest(app, workspace)
		createErr <- err
	}()

	select {
	case <-entered:
	case <-time.After(macLivenessObservationWindow):
		t.Fatal("the parked create never reached the SELinux fcontext command")
	}

	disableLauncherDone, disablePrincipalDone := h8RunConcurrentDisables(app, launcherID, username)
	h8AwaitDisables(t, disableLauncherDone, disablePrincipalDone)

	h8AwaitCreateFailure(t, createErr)
	h8DisabledStates(t, app, launcherID, username)
	h8NoSessionCommitted(t, app, app.userModeDefault.launcherID, launcherID)
	h8AdmissionClosed(t, app, launcherID)

	close(release)
	secondWorkspace := testWorkspaceDir(t, allowedRoot)
	second, err := createDefaultAdminSessionForTest(app, secondWorkspace)
	if err != nil {
		t.Fatalf("the next ordinary session create after the hostile condition must succeed: %v", err)
	}
	app.MACCoordinator.ReleaseSessionBinding(second.Session.ID)
}

// TestH8SELinuxFcontextLockContentionFailsClosed proves RED case 3: the
// global SELinux fcontext flock is an unbounded blocking LOCK_EX pre-command
// wait. While the lock is held, the production acquisition does not fail
// closed within the observation window (pre-fix defect).
//
// Post-fix, the acquisition is fail-closed/non-waiting (LOCK_NB, consistent
// with the existing AppArmor lock) and returns the contention refusal
// immediately.
func TestH8SELinuxFcontextLockContentionFailsClosed(t *testing.T) {
	// Hold the global SELinux workspace flock in this process first.
	holder, err := os.OpenFile(selinuxFcontextLockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		if os.IsPermission(err) {
			t.Skip("cannot exercise the real /run/lock flock without write access to /run/lock")
		}
		t.Fatalf("cannot open the SELinux workspace lock path: %v", err)
	}
	defer holder.Close()
	if err := syscall.Flock(int(holder.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Skipf("cannot hold the real /run/lock flock in this environment: %v", err)
	}
	defer func() { _ = syscall.Flock(int(holder.Fd()), syscall.LOCK_UN) }()

	acquired := make(chan error, 1)
	go func() {
		release, err := acquireSELinuxFcontextLock()
		if err == nil {
			defer release()
		}
		acquired <- err
	}()

	select {
	case err := <-acquired:
		if err == nil {
			t.Fatal("a second acquisition of the held SELinux flock must fail closed, not succeed")
		}
		if !strings.Contains(err.Error(), "another SELinux fcontext operation is in progress") {
			t.Fatalf("lock contention error = %v, want the fail-closed contention refusal", err)
		}
	case <-time.After(macLivenessObservationWindow):
		t.Fatal("the SELinux fcontext lock acquisition did not fail closed under contention: the blocking LOCK_EX wait has no bound (H8 defect)")
	}
}

// TestH8ReloadHungTrustedCARestoreconKeepsPreviousConfig proves RED case 4:
// the trusted-CA restorecon inside configuration preparation runs while the
// reload holds lifecycleMu, so a hung restorecon parks the whole lifecycle
// coordination. Post-fix, the fixed MAC transition budget terminates the
// restorecon, the reload fails closed as an invalid configuration, the
// previous effective config stays active, and the lifecycle coordination is
// released within the bound.
func TestH8ReloadHungTrustedCARestoreconKeepsPreviousConfig(t *testing.T) {
	h8BudgetOverride(t)

	configPath, _, socketPath, _, cleanup := setupReloadTestEnv(t)
	defer cleanup()
	_ = socketPath

	origSEL := selinuxEnabled
	origRestorecon := trustedCARestorecon
	defer func() {
		selinuxEnabled = origSEL
		trustedCARestorecon = origRestorecon
	}()
	selinuxEnabled = func() (bool, bool, error) { return true, true, nil }

	entered := make(chan struct{}, 8)
	release := make(chan struct{})
	park := false
	var parkMu sync.Mutex
	trustedCARestorecon = func(ctx context.Context, _ ...string) ([]byte, error) {
		parkMu.Lock()
		parking := park
		parkMu.Unlock()
		if !parking {
			return []byte{}, nil
		}
		if err := h8ParkedCommand(ctx, entered, release); err != nil {
			return nil, err
		}
		return []byte{}, nil
	}

	opBuf := &bytes.Buffer{}
	initLoggers(opBuf, io.Discard, slog.LevelInfo, false)
	defer logging.reset()

	// 1. Load the initial valid config and create the App in the environment
	//    user mode (the DB and admin token live under the env-resolved dirs).
	cfg, err := loadAndPrepareRuntimeConfig()
	if err != nil {
		t.Fatalf("initial loadAndPrepareRuntimeConfig: %v", err)
	}
	adminHash, err := loadAdminToken(cfg.AdminTokenPath)
	if err != nil {
		t.Fatal(err)
	}
	db, err := openDatabase(cfg.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := initializeDatabase(db); err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	app := &App{Config: cfg, DB: db, AdminTokenHash: adminHash}
	launcherID, username := setupH8DisableTarget(t, app)

	// 2. Snapshot the previous effective config.
	previousRoot := app.getConfig().AllowedRoots[0].Path

	// 3. Arm the system-mode configuration preparation environment for the
	//    reload: the trusted-CA restorecon runs against this runtime dir.
	savedEffectiveUID := EffectiveUID
	EffectiveUID = func() int { return 0 }
	defer func() { EffectiveUID = savedEffectiveUID }()
	origRuntimeDir := getRuntimeDirFunc
	getRuntimeDirFunc = func() (string, error) {
		return filepath.Join(filepath.Dir(configPath), "xdg_runtime", "docker-helper"), nil
	}
	defer func() { getRuntimeDirFunc = origRuntimeDir }()

	// 4. Switch the on-disk config to trusted-CA injection with a narrowed
	//    allowed root, so the reload must run the trusted-CA restorecon.
	caFile := filepath.Join(filepath.Dir(configPath), "h8-ca.pem")
	generateTestCAPEM(t, caFile)
	otherRoot, err := os.MkdirTemp(previousRoot, "h8-other-root-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(otherRoot)
	newCfg := map[string]any{
		"allowed_root":         otherRoot,
		"session_ttl":          "12h",
		"log_level":            "info",
		"trusted_ca_injection": "auto",
		"trusted_ca_path":      caFile,
	}
	raw, err := json.MarshalIndent(newCfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, raw, 0600); err != nil {
		t.Fatal(err)
	}

	// 5. Arm the hostile restorecon and run the reload.
	parkMu.Lock()
	park = true
	parkMu.Unlock()

	reloadDone := make(chan int, 1)
	go func() {
		req := httptest.NewRequest(http.MethodPost, "/reload", nil)
		req.Header.Set("Authorization", "Bearer test-admin-token")
		w := httptest.NewRecorder()
		app.handleReload(w, req)
		reloadDone <- w.Code
	}()

	select {
	case <-entered:
	case <-time.After(macLivenessObservationWindow):
		t.Fatal("the parked reload never reached the trusted-CA restorecon")
	}

	// 6. Concurrent lifecycle mutation while the reload holds lifecycleMu.
	disableLauncherDone, disablePrincipalDone := h8RunConcurrentDisables(app, launcherID, username)
	deadline := time.After(macLivenessObservationWindow + macLivenessCompletionSlop)
	launcherCommitted := false
	principalCommitted := false
	reloadSet := false
	var reloadCode int
	for !launcherCommitted || !principalCommitted || !reloadSet {
		select {
		case err := <-disableLauncherDone:
			if err != nil {
				t.Fatalf("launcher disable failed: %v", err)
			}
			launcherCommitted = true
		case err := <-disablePrincipalDone:
			if err != nil {
				t.Fatalf("principal disable failed: %v", err)
			}
			principalCommitted = true
		case code := <-reloadDone:
			reloadCode = code
			reloadSet = true
		case <-deadline:
			t.Fatal("lifecycle coordination did not release within the bounded window: the hung trusted-CA restorecon holds lifecycleMu without any bound (H8 defect)")
		}
	}

	// 7. Post-fix assertions: the reload failed closed, the previous config
	//    stays effective, and the disables committed.
	if reloadCode != http.StatusBadRequest {
		t.Errorf("a reload whose trusted-CA restorecon exceeded the budget must fail closed with invalid_config, got status %d", reloadCode)
	}
	h8DisabledStates(t, app, launcherID, username)
	if got := app.getConfig().AllowedRoots[0].Path; got != previousRoot {
		t.Errorf("failed reload must keep the previous effective config: got root %q, want %q", got, previousRoot)
	}

	// 8. No stranded coordination: after the hostile condition is removed,
	//    the next reload succeeds and adopts the new config.
	close(release)
	req := httptest.NewRequest(http.MethodPost, "/reload", nil)
	req.Header.Set("Authorization", "Bearer test-admin-token")
	w := httptest.NewRecorder()
	app.handleReload(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("next ordinary reload after the hostile condition must succeed: status %d body %s", w.Code, w.Body.String())
	}
	if got := app.getConfig().AllowedRoots[0].Path; got != otherRoot {
		t.Errorf("successful reload must adopt the new config root: got %q, want %q", got, otherRoot)
	}
}

// TestH8WorkloadAppArmorCleanupTimeoutRetainsOwnership proves RED case 5: the
// workload AppArmor parser cleanup one-shot can outlive the intended
// cleanup/shutdown bound — a parked parser keeps the run completion path from
// ever reaching its terminal transition. Post-fix, the cleanup fails bounded,
// the generated profile file (ownership evidence) is retained, and the
// cleanup path returns within the budget so the operation terminal
// transition and shutdown are no longer hostage.
func TestH8WorkloadAppArmorCleanupTimeoutRetainsOwnership(t *testing.T) {
	h8BudgetOverride(t)

	stateDir := t.TempDir()
	profilePath := filepath.Join(stateDir, appArmorWorkloadProfileFileName)
	profileName := workloadAppArmorProfileName("op_h8cleanup")
	if err := os.WriteFile(profilePath, []byte("profile "+profileName+" {}\n"), 0600); err != nil {
		t.Fatal(err)
	}

	entered := make(chan struct{}, 8)
	release := make(chan struct{})
	backend := newWorkloadAppArmorBackend()
	backend.parserPath = filepath.Join(t.TempDir(), "apparmor_parser")
	if err := os.WriteFile(backend.parserPath, []byte("fake"), 0755); err != nil {
		t.Fatal(err)
	}
	backend.runParser = func(context.Context, string, []string) error { return nil }
	backend.loadedProfiles = func() ([]string, error) { return []string{profileName}, nil }

	// Build the prepared workload through the real production prepare path so
	// the exercised cleanup is the real budgeted cleanup closure.
	preparation := workloadPreparation{
		OperationID: "op_h8cleanup",
		SessionID:   "dhs_h8cleanup",
		StateDir:    stateDir,
		RuntimeDir:  t.TempDir(),
	}
	prepared, err := backend.prepare(context.Background(), preparation)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}

	// Arm the hostile hung parser for the cleanup pass.
	backend.runParser = func(ctx context.Context, _ string, _ []string) error {
		return h8ParkedCommand(ctx, entered, release)
	}

	started := time.Now()
	cleanupDone := make(chan error, 1)
	go func() {
		cleanupDone <- prepared.Cleanup()
	}()

	select {
	case <-entered:
	case <-time.After(macLivenessObservationWindow):
		t.Fatal("the parked cleanup never reached the workload AppArmor parser command")
	}

	var cleanupErr error
	select {
	case cleanupErr = <-cleanupDone:
	case <-time.After(macLivenessObservationWindow + macLivenessCompletionSlop):
		t.Fatal("workload AppArmor parser cleanup did not return within the bounded window: the parked parser outlives the intended cleanup bound (H8 defect)")
	}
	if cleanupErr == nil {
		t.Fatal("a cleanup whose parser exceeded the MAC budget must fail, not succeed")
	}
	if elapsed := time.Since(started); elapsed > macLivenessObservationWindow+macLivenessCompletionSlop {
		t.Errorf("cleanup returned after %v, want within the bounded window", elapsed)
	}

	// Fail-closed ownership: the cleanup failed before removing the generated
	// profile, so the durable state stays behind for reconciliation.
	if _, err := os.Stat(profilePath); err != nil {
		t.Fatalf("the generated profile must be retained for reconciliation after a failed cleanup: %v", err)
	}
}

// TestH8MACCommandKilledAndReapedAtBudget proves the kill/reap guarantee of
// the bounded execution owners with a REAL external process: a genuinely
// hung command started through the production parser runner is terminated at
// the fixed MAC transition budget, the execution returns the typed budget
// error within the budget, the child is reaped (no zombie), and no MAC child
// process is left behind. The command is a short-lived sleep bounded by the
// test budget — never a permanently hung host process.
func TestH8MACCommandKilledAndReapedAtBudget(t *testing.T) {
	h8BudgetOverride(t)

	runner := newProductionParserRunner()
	const sleepyArg = "793d"
	started := time.Now()
	ctx, cancel := newMACTransitionContext()
	defer cancel()
	err := runner(ctx, "/bin/sleep", []string{sleepyArg})
	if err == nil {
		t.Fatal("a hung MAC command must fail at the budget, not succeed")
	}
	if !errors.Is(err, ErrMACTransitionBudgetExceeded) {
		t.Fatalf("hung command error = %v, want the typed budget error", err)
	}
	if elapsed := time.Since(started); elapsed > macLivenessBudgetOverride+2*time.Second {
		t.Errorf("the hung command was terminated after %v, want at the budget %v", elapsed, macLivenessBudgetOverride)
	}

	// The child was reaped: no process with the unique command line remains.
	if h8ProcWithCmdline("sleep", sleepyArg) {
		t.Fatal("the hung MAC command child is still present after the budget: a MAC child process was left behind")
	}
}

// h8ProcWithCmdline reports whether a process whose cmdline starts with the
// given binary and contains the given argument is running.
func h8ProcWithCmdline(binary, arg string) bool {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		if err != nil {
			continue
		}
		parts := strings.Split(strings.TrimRight(string(data), "\x00"), "\x00")
		if len(parts) == 0 || filepath.Base(parts[0]) != binary {
			continue
		}
		for _, part := range parts[1:] {
			if part == arg {
				return true
			}
		}
	}
	return false
}

// TestH8RunCleanupSequenceBoundedUnderHungWorkloadCleanup proves the
// shutdown-relevant liveness property at the run-cleanup owner: the workload
// MAC cleanup stage failing at the fixed budget lets the cleanup sequence
// finish (the retained outcome is recorded) instead of parking the run
// completion goroutine — so the operation terminal transition and the
// bounded shutdown drain are no longer hostage to a hung parser process.
func TestH8RunCleanupSequenceBoundedUnderHungWorkloadCleanup(t *testing.T) {
	h8BudgetOverride(t)

	entered := make(chan struct{}, 8)
	release := make(chan struct{})
	backend := newWorkloadAppArmorBackend()
	backend.runParser = func(ctx context.Context, _ string, _ []string) error {
		return h8ParkedCommand(ctx, entered, release)
	}
	backend.loadedProfiles = func() ([]string, error) { return []string{"workload_docker_helper_op_h8drain"}, nil }

	prepared := &preparedWorkloadMAC{
		Backend: LSMAppArmor,
		cleanup: func() error {
			cleanupCtx, cancel := newMACTransitionContext()
			defer cancel()
			return backend.cleanupPrepared(cleanupCtx, t.TempDir(), "workload_docker_helper_op_h8drain")
		},
	}

	started := time.Now()
	outcomeDone := make(chan runCleanupOutcome, 1)
	go func() {
		outcomeDone <- newRunCleanupSequence(
			cleanupStage{name: cleanupStageWorkloadMAC, run: prepared.Cleanup},
		).run()
	}()

	select {
	case <-entered:
	case <-time.After(macLivenessObservationWindow):
		t.Fatal("the hung cleanup never reached the workload parser command")
	}

	var outcome runCleanupOutcome
	select {
	case outcome = <-outcomeDone:
	case <-time.After(macLivenessObservationWindow + macLivenessBudgetOverride + macLivenessCompletionSlop):
		t.Fatal("the run cleanup sequence did not finish within the MAC budget: the hung parser holds the run completion path without bound (H8 defect)")
	}
	if outcome.completed {
		t.Fatal("a budget-expired workload cleanup must retain state, never report completion")
	}
	if outcome.retainedStage != cleanupStageWorkloadMAC {
		t.Errorf("retained stage = %q, want %q", outcome.retainedStage, cleanupStageWorkloadMAC)
	}
	if !errors.Is(outcome.err, ErrMACTransitionBudgetExceeded) {
		t.Errorf("retained error = %v, want the typed budget error", outcome.err)
	}
	if elapsed := time.Since(started); elapsed > macLivenessBudgetOverride+macLivenessCompletionSlop {
		t.Errorf("cleanup sequence finished after %v, want within budget %v + slop", elapsed, macLivenessBudgetOverride)
	}

	// Release the hostile condition for deterministic test teardown.
	close(release)
}

// TestH8StartupReconciliationBoundedUnderHungRepair proves the startup
// reconciliation's repair pass is bounded: a hung backend repair command
// fails the session reconciliation within the fixed MAC transition budget
// (one budget per session), so daemon startup cannot be held hostage by a
// single session's backend commands.
func TestH8StartupReconciliationBoundedUnderHungRepair(t *testing.T) {
	h8BudgetOverride(t)

	entered := make(chan struct{}, 8)
	release := make(chan struct{})

	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.semanagePath = semanagePath
	mgr.restoreconPath = restoreconPath
	mgr.runCommand = func(ctx context.Context, _ string, _ ...string) ([]byte, error) {
		if err := h8ParkedCommand(ctx, entered, release); err != nil {
			return nil, err
		}
		return []byte{}, nil
	}
	mgr.readPathCon = func(string) (string, error) { return selinuxWorkspaceType, nil }
	driver := &selinuxMACDriver{mgr: mgr, treeKind: macBoundaryKindFor}

	db, err := openDatabase(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("openDatabase: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initializeDatabase: %v", err)
	}
	if _, err := migrateSessionFilesystemSnapshots(db); err != nil {
		t.Fatalf("migrateSessionFilesystemSnapshots: %v", err)
	}

	// Seed a live session whose persisted snapshot carries one external
	// (non-home) issued tree, so the reconciliation reaches the backend
	// verification/repair path for it.
	allowedRoot := t.TempDir()
	issuedTree := filepath.Join(allowedRoot, "h8-reconcile-tree")
	if err := os.MkdirAll(issuedTree, 0700); err != nil {
		t.Fatal(err)
	}
	ownerLauncherID := testMACLauncherID(t, db)
	if err := insertTestSessionTx(db, ownerLauncherID, "dhs_h8reconcile", issuedTree); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	mac := newSessionMACCoordinator(db, driver)
	started := time.Now()
	reconcileDone := make(chan error, 1)
	go func() {
		reconcileDone <- mac.ReconcileLiveSessions()
	}()

	select {
	case <-entered:
	case <-time.After(macLivenessObservationWindow):
		t.Fatal("the hung reconciliation never reached the backend repair command")
	}

	select {
	case err := <-reconcileDone:
		if err == nil {
			t.Fatal("a reconciliation whose backend repair exceeded the budget must fail, not succeed")
		}
		if !errors.Is(err, ErrMACTransitionBudgetExceeded) {
			t.Errorf("reconciliation error = %v, want the typed budget error", err)
		}
	case <-time.After(macLivenessObservationWindow + macLivenessBudgetOverride + macLivenessCompletionSlop):
		t.Fatal("startup reconciliation did not return within the MAC budget: a hung repair command holds the startup coordination without bound (H8 defect)")
	}
	if elapsed := time.Since(started); elapsed > macLivenessBudgetOverride+macLivenessCompletionSlop {
		t.Errorf("reconciliation returned after %v, want within budget %v + slop", elapsed, macLivenessBudgetOverride)
	}

	// The coordinator lock is not stranded: the next ordinary transition
	// (a create on the same coordinator) proceeds after the hostile
	// condition is removed.
	close(release)
	secondWorkspace := filepath.Join(allowedRoot, "h8-after-tree")
	if err := os.MkdirAll(secondWorkspace, 0700); err != nil {
		t.Fatal(err)
	}
	mgr.runCommand = func(context.Context, string, ...string) ([]byte, error) { return []byte{}, nil }
	second, err := mac.CreateSessionBinding("dhs_h8after", []string{secondWorkspace}, func([]sessionMACCoverage) error {
		return insertTestSessionTx(db, ownerLauncherID, "dhs_h8after", secondWorkspace)
	})
	if err != nil {
		t.Fatalf("the next ordinary MAC transition after the hostile condition must succeed: %v", err)
	}
	if len(second) == 0 {
		t.Fatal("the next ordinary transition must resolve coverage")
	}
}

// TestH8CreateMACBudgetFailureHTTPClass proves the HTTP boundary of the
// budget-expired create: a Session create whose MAC preparation was
// terminated at the fixed transition budget answers the documented
// mac_preparation_failed error class (HTTP 500) through the real route
// handler — the same class the audit record carries — never the generic
// internal_error fallback, and commits no Session.
func TestH8CreateMACBudgetFailureHTTPClass(t *testing.T) {
	h8BudgetOverride(t)

	app, _, release := setupH8AppArmorParkedCoordinator(t)
	_ = release
	adminHash := sha256.Sum256([]byte(testAdminToken))
	app.AdminTokenHash = adminHash

	workspace := testWorkspaceDir(t, app.Config.AllowedRoots[0].Path)
	body, err := json.Marshal(map[string]string{"workspace": workspace})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(body))
	withAdminToken(req)
	w := httptest.NewRecorder()

	mux := http.NewServeMux()
	mux.HandleFunc("POST /sessions", withRequestID(app.handleCreateSession))
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("budget-expired create: status = %d, want 500: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("cannot decode error response: %v", err)
	}
	if resp.Code != "mac_preparation_failed" {
		t.Errorf("error code = %q, want mac_preparation_failed", resp.Code)
	}
	if got := h8SessionCount(t, app, app.userModeDefault.launcherID); got != 0 {
		t.Errorf("budget-expired create committed %d sessions, want 0", got)
	}
}

// --- local helpers ---
