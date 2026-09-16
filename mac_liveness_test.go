package main

import (
	"bytes"
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

// H8 defect demonstrations (SC2 — bounded MAC-command liveness).
//
// Every test in this file is RED evidence against the pre-fix release line:
// a seam-parked external MAC one-shot command holds shared lifecycle
// coordination with no bound at all. Each test fails on the pre-fix code at
// its bounded observation window (the coordination never progresses) and
// passes after the fix, when the fixed Release-2.2 MAC transition budget
// kills the parked command and releases the lifecycle.
//
// No sleeps-as-proof: the bounded observation window is the instrument that
// proves non-arrival; the parked seams are channels closed by the test
// itself. No real permanently hung host process is ever started (the parked
// command is an injected seam; the kill/reap proof uses a short real process
// bounded by the budget — added with the fix).

// macLivenessObservationWindow is the bounded window during which a parked
// coordination must NOT progress (pre-fix defect) and during which a
// budgeted coordination MUST have progressed (post-fix). Generous for -race
// and CI scheduling.
const macLivenessObservationWindow = 750 * time.Millisecond

// macLivenessCompletionSlop is the scheduling slop added to the deadline for
// post-fix "progressed within the proven bound" wall-clock assertions.
const macLivenessCompletionSlop = 5 * time.Second

// h8ParkedCommand parks one command execution until release is closed,
// signaling the entry on entered exactly once. The fix commit turns this
// into a context-aware park so the budget terminates the parked command; the
// pre-fix signature has no context, which is itself part of the defect.
func h8ParkedCommand(entered chan<- struct{}, release <-chan struct{}) func() error {
	var once sync.Once
	return func() error {
		once.Do(func() { entered <- struct{}{} })
		<-release
		return nil
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
	parked := h8ParkedCommand(entered, release)
	_, mgr := setupAppArmorTestWithRunner(t, func(exe string, args []string) error {
		return parked()
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
	parked := h8ParkedCommand(entered, release)

	mgr := newTestManager(func() (bool, bool, error) { return true, true, nil })
	mgr.semanagePath = semanagePath
	mgr.restoreconPath = restoreconPath
	mgr.runCommand = func(cmd string, args ...string) ([]byte, error) {
		if err := parked(); err != nil {
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
// it failed as MAC preparation (never a false success).
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
		var n int
		if err := app.DB.QueryRow(`SELECT COUNT(*) FROM sessions WHERE launcher_id = ?`, id).Scan(&n); err != nil {
			t.Fatalf("count sessions: %v", err)
		}
		if n != 0 {
			t.Errorf("launcher %s carries %d sessions, want 0", id, n)
		}
	}
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

// TestH8HungSELinuxFcontextParksSessionCreateAndBlocksDisable proves RED case
// 2: a hung SELinux one-shot command (the semanage fcontext listing that
// opens every workspace preparation) parks a Session create inside the same
// lifecycle linearization boundary, so a concurrent administrative disable
// cannot proceed.
func TestH8HungSELinuxFcontextParksSessionCreateAndBlocksDisable(t *testing.T) {
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
	parked := h8ParkedCommand(entered, release)
	park := false
	var parkMu sync.Mutex
	trustedCARestorecon = func(args ...string) ([]byte, error) {
		parkMu.Lock()
		parking := park
		parkMu.Unlock()
		if !parking {
			return []byte{}, nil
		}
		if err := parked(); err != nil {
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
	stateDir := t.TempDir()
	profilePath := filepath.Join(stateDir, appArmorWorkloadProfileFileName)
	profileName := workloadAppArmorProfileName("op_h8cleanup")
	if err := os.WriteFile(profilePath, []byte("profile "+profileName+" {}\n"), 0600); err != nil {
		t.Fatal(err)
	}

	entered := make(chan struct{}, 8)
	release := make(chan struct{})
	parked := h8ParkedCommand(entered, release)
	backend := newWorkloadAppArmorBackend()
	backend.runParser = func(_ string, _ []string) error {
		return parked()
	}
	backend.loadedProfiles = func() ([]string, error) { return []string{profileName}, nil }

	started := time.Now()
	cleanupDone := make(chan error, 1)
	go func() {
		cleanupDone <- backend.cleanupPrepared(stateDir, profileName)
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

// --- local helpers ---
