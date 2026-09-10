package main

// Coherent Session-filesystem-authority read tests: the Session bearer
// authentication and the persisted snapshot load must read one database
// generation, issued snapshots survive real parent-policy mutations, and a
// legacy migrated Session keeps the 2.1 writable workspace behavior. The
// parked-query harness pins reads at deterministic synchronization points;
// no sleeps, no lifecycleMu.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// legacySessionToken is the bearer token of the directly seeded legacy
// Session; its hash is written by insertLegacySessionRow.
const legacySessionToken = "dht-legacy-session-token"

// insertLegacySessionRow inserts a pre-2.2 Session row the way pre-2.2
// production code created Sessions: no snapshot rows exist anywhere.
func insertLegacySessionRow(t *testing.T, db *sql.DB, sessionID, workspace, launcherID string) error {
	t.Helper()
	tokenHash := sha256.Sum256([]byte(legacySessionToken))
	_, err := db.Exec(`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at, launcher_id) VALUES (?, ?, ?, ?, ?, ?)`,
		sessionID, hex.EncodeToString(tokenHash[:]), workspace, time.Now().Unix(), time.Now().Add(24*time.Hour).Unix(), launcherID)
	return err
}

// legacyRunEnforcementApp wraps an already-open migrated database in a
// system-mode App with stubbed MAC detection for legacy-session run tests.
func legacyRunEnforcementApp(t *testing.T, dir, dbPath string, db *sql.DB, allowedRoot string, mac *sessionMACCoordinator) *App {
	t.Helper()
	mockDetectLSM(t, LSMAppArmor, nil)

	runtimeDir := filepath.Join(dir, "runtime")
	if err := os.MkdirAll(runtimeDir, 0700); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{
		AllowedRoots:          []AllowedRootEntry{allowedRootEntry(allowedRoot)},
		SessionTTL:            24 * time.Hour,
		SocketPath:            filepath.Join(dir, "test.sock"),
		StateDir:              dir,
		RuntimeDir:            runtimeDir,
		DatabasePath:          dbPath,
		AdminTokenPath:        filepath.Join(dir, "admin.token"),
		ShutdownTimeout:       30 * time.Second,
		OperationRetentionTTL: 10 * time.Minute,
		OperationMaxCompleted: 200,
		OperationLogMaxBytes:  4 * 1024 * 1024,
		Mode:                  ModeSystem,
	}
	return &App{
		Config:              cfg,
		DB:                  db,
		MACCoordinator:      mac,
		OperationSupervisor: newOperationSupervisor(),
	}
}

// TestRaceRunAuthorityReadCoherentUnderSessionDelete proves the coherent
// filesystem authority read: the Session auth query and the snapshot load are
// one read transaction, so a concurrent Session deletion cannot produce the
// illegal split outcome (authenticated Session, cascaded-away snapshot, false
// 500 corruption). The run is parked between the two reads inside the
// authority read; the concurrent delete can only commit after the read
// transaction ends, and the in-flight request still completes with the
// captured immutable authority.
func TestRaceRunAuthorityReadCoherentUnderSessionDelete(t *testing.T) {
	app, _ := newRunEnforcementApp(t)

	created := createRunEnforcementSession(t, app, nil)
	subdir := filepath.Join(created.Session.Workspace, "sub")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatal(err)
	}

	// Park the snapshot load: at this point the Session auth query has
	// already run inside the open authority read transaction.
	snapshotPoint := newParkedQueryPoint("FROM session_filesystem_snapshot_entries")
	parked := openParkedQueryDB(t, app.Config.DatabasePath, snapshotPoint)
	app.DB.Close()
	app.DB = parked

	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		w, _ := postRunRequest(app, created.Token,
			`{"image":"alpine:3.24","mounts":[{"source":"sub","target":"/data"}],"command":["true"]}`)
		done <- w
	}()

	select {
	case <-snapshotPoint.parked:
	case <-time.After(5 * time.Second):
		t.Fatal("snapshot load was never parked")
	}

	// Concurrent Session deletion, linearizing between the two reads from
	// the outside. The read transaction holds the shared lock, so this
	// delete can only commit after the authority read transaction ends.
	deleteErr := make(chan error, 1)
	go func() {
		_, err := app.DB.Exec(`DELETE FROM sessions WHERE id = ?`, created.Session.ID)
		deleteErr <- err
	}()

	close(snapshotPoint.release)

	var w *httptest.ResponseRecorder
	select {
	case w = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("run request never completed")
	}
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 from the captured pre-delete authority, got %d: %s", w.Code, w.Body.String())
	}

	if err := <-deleteErr; err != nil {
		t.Fatalf("concurrent delete failed: %v", err)
	}
	var count int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM sessions WHERE id = ?`, created.Session.ID).Scan(&count); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if count != 0 {
		t.Fatalf("delete did not linearize: session still present")
	}
}

// TestRunAuthorityReadDeleteFirstUnauthorized proves the delete-first
// linearization: when the concurrent Session deletion commits before the
// authority read transaction's Session auth query runs, the lookup sees no
// valid Session and fails closed with 401.
func TestRunAuthorityReadDeleteFirstUnauthorized(t *testing.T) {
	app, _ := newRunEnforcementApp(t)

	created := createRunEnforcementSession(t, app, nil)

	// Park the Session bearer-auth query itself (the delete statement does
	// not contain this projection predicate): the delete runs while the auth
	// read is parked, so by the time the auth query resumes the Session row
	// (and its cascaded snapshot) is already gone.
	authPoint := newParkedQueryPoint("s.token_hash = ?")
	parked := openParkedQueryDB(t, app.Config.DatabasePath, authPoint)
	app.DB.Close()
	app.DB = parked

	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		w, _ := postRunRequest(app, created.Token,
			`{"image":"alpine:3.24","command":["true"]}`)
		done <- w
	}()

	select {
	case <-authPoint.parked:
	case <-time.After(5 * time.Second):
		t.Fatal("session auth read was never parked")
	}

	if _, err := app.DB.Exec(`DELETE FROM sessions WHERE id = ?`, created.Session.ID); err != nil {
		t.Fatalf("delete session: %v", err)
	}
	close(authPoint.release)

	select {
	case w := <-done:
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 after delete-first linearization, got %d: %s", w.Code, w.Body.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run request never completed")
	}
}

// TestRunOldSessionKeepsIssuedSnapshotUnderParentPolicyChange proves the
// issued snapshot survives a real parent-policy mutation: a Session created
// under policy A keeps following snapshot A on the data plane after the
// parent policy is narrowed, while a Session created after the change follows
// the new policy B.
func TestRunOldSessionKeepsIssuedSnapshotUnderParentPolicyChange(t *testing.T) {
	app, capture := newRunEnforcementApp(t)

	root := app.Config.AllowedRoots[0].Path
	home := filepath.Join(root, "home", "policyshifter")
	workspace := filepath.Join(home, "work")
	inputs := filepath.Join(workspace, "inputs")
	for _, d := range []string{inputs} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}
	installOSUserMock(t, map[string]string{"policyshifter": home})
	if _, err := createPrincipal(app.DB, "policyshifter", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal(policyshifter): %v", err)
	}
	_, credentialToken, err := createPrincipalCredential(app.DB, "policyshifter", "oc")
	if err != nil {
		t.Fatalf("createPrincipalCredential(policyshifter): %v", err)
	}

	// Policy A: nested read_only transition on the workspace inputs.
	if _, _, err := addPrincipalAllowedRoot(app.DB, "policyshifter", inputs, AllowedRootAccessReadOnly, allowedRootPaths(app.getConfig().AllowedRoots)); err != nil {
		t.Fatalf("addPrincipalAllowedRoot(inputs): %v", err)
	}
	oldSession := createSessionThroughMux(app, credentialToken, workspace)
	if oldSession.Code != http.StatusCreated {
		t.Fatalf("create old session: %d %s", oldSession.Code, oldSession.Body.String())
	}
	oldToken := decodeCreateSessionToken(t, oldSession.Body.String())

	// Real parent-policy mutation to policy B: remove the nested read_only
	// root through the production mutation owner.
	if _, _, err := removePrincipalAllowedRoot(app.DB, "policyshifter", inputs); err != nil {
		t.Fatalf("removePrincipalAllowedRoot(inputs): %v", err)
	}

	// The old Session still follows the issued snapshot A: the writable
	// request for the inputs subtree is refused by the stored authority.
	w, _ := postRunRequest(app, oldToken, fmt.Sprintf(
		`{"image":"alpine:3.24","mounts":[{"source":"inputs","target":"/data"}],"command":["true"]}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("old session: expected 400, got %d: %s", w.Code, w.Body.String())
	}
	if code := readRootResponseCode(t, w.Body.String()); code != "read_only_root" {
		t.Fatalf("old session: expected read_only_root, got %q", code)
	}
	if specs := dockerMountSpecs(capture()); len(specs) != 0 {
		t.Errorf("old session must not mount the refused source, got %v", specs)
	}

	// A new Session under the same Principal follows the new policy B: the
	// same writable request is accepted because the issued snapshot has no
	// nested read_only transition.
	newSession := createSessionThroughMux(app, credentialToken, workspace)
	if newSession.Code != http.StatusCreated {
		t.Fatalf("create new session: %d %s", newSession.Code, newSession.Body.String())
	}
	newToken := decodeCreateSessionToken(t, newSession.Body.String())

	w2, _ := postRunRequest(app, newToken, fmt.Sprintf(
		`{"image":"alpine:3.24","mounts":[{"source":"inputs","target":"/data"}],"command":["true"]}`))
	if w2.Code != http.StatusCreated {
		t.Fatalf("new session: expected 201, got %d: %s", w2.Code, w2.Body.String())
	}
	spec := singleMountSpec(t, capture())
	wantSpec := fmt.Sprintf("type=bind,source=%s,target=/data", inputs)
	if spec != wantSpec {
		t.Fatalf("new session mount spec = %q, want %q", spec, wantSpec)
	}
}

// TestRunLegacyMigratedSessionKeepsWritableBehavior proves the 2.2 upgrade
// compatibility contract end-to-end: a Session migrated by the real startup
// owner (single-entry workspace-read_write backfill) behaves exactly like a
// 2.1 Session — the workspace and every subpath inherit the writable
// authority because the issued snapshot has no read_only transition.
func TestRunLegacyMigratedSessionKeepsWritableBehavior(t *testing.T) {
	auditBuf, opBuf := setupTestLogging(t)
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	db, err := openDatabase(dbPath)
	if err != nil {
		t.Fatalf("openDatabase: %v", err)
	}
	defer db.Close()

	// Pre-2.2 schema: sessions exist without any snapshot table yet.
	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initializeDatabase: %v", err)
	}

	root := testAllowedRootDir(t)
	workspace := filepath.Join(root, "legacy", "workspace")
	if err := os.MkdirAll(filepath.Join(workspace, "sub"), 0755); err != nil {
		t.Fatal(err)
	}
	launcherID := testMACLauncherID(t, db)
	// The legacy Session's MAC binding is provisioned the way the real
	// Session creation lifecycle does: the binding wraps the Session row
	// insert. (The daemon-owner Launcher's workspace MAC coverage is
	// driver-recorded state; the run request below only needs the
	// workspace-use lease from the binding table.)
	mac := newSessionMACCoordinator(db, newTestWorkspaceMACDriver(LSMBackend("test")))
	if _, err := mac.CreateSessionBinding(workspace, "legacy-sess", func(cov workspaceMACCoverage) error {
		return insertLegacySessionRow(t, db, "legacy-sess", workspace, launcherID)
	}); err != nil {
		t.Fatal(err)
	}

	// The real startup migration owner backfills the legacy Session's issued
	// snapshot from sessions.workspace alone.
	if _, err := migrateSessionFilesystemSnapshots(db); err != nil {
		t.Fatalf("migrateSessionFilesystemSnapshots: %v", err)
	}
	var entries int
	if err := db.QueryRow(`SELECT COUNT(*) FROM session_filesystem_snapshot_entries WHERE session_id = ?`, "legacy-sess").Scan(&entries); err != nil {
		t.Fatalf("count snapshot entries: %v", err)
	}
	if entries != 1 {
		t.Fatalf("legacy backfill produced %d entries, want 1", entries)
	}
	_ = auditBuf

	app := legacyRunEnforcementApp(t, dir, dbPath, db, root, mac)
	var capturedArgs []string
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		capturedArgs = args
		return exec.CommandContext(ctx, "/bin/true")
	}
	app.PinWorkspaceMountSourceFn = func(workspace, sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
		return &pinnedMount{PinnedPath: sourcePath, cleanup: func() error { return nil }}, nil
	}

	w, _ := postRunRequest(app, legacySessionToken,
		`{"image":"alpine:3.24","mounts":[{"source":"sub","target":"/data"}],"command":["true"]}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 from legacy migrated session, got %d: %s\nop log: %s", w.Code, w.Body.String(), opBuf.String())
	}
	spec := singleMountSpec(t, capturedArgs)
	wantSpec := fmt.Sprintf("type=bind,source=%s,target=/data", filepath.Join(workspace, "sub"))
	if spec != wantSpec {
		t.Fatalf("legacy mount spec = %q, want %q", spec, wantSpec)
	}

	// Subpaths inherit the workspace read_write authority: no nested
	// read_only transition exists in the migrated snapshot.
	var access string
	if err := app.DB.QueryRow(`SELECT access FROM session_filesystem_snapshot_entries WHERE session_id = ? AND path = ?`, "legacy-sess", workspace).Scan(&access); err != nil {
		t.Fatalf("query snapshot entry: %v", err)
	}
	if access != string(AllowedRootAccessReadWrite) {
		t.Fatalf("legacy snapshot access = %q, want read_write", access)
	}
}

// decodeCreateSessionToken extracts the bearer token from a 201 create
// response.
func decodeCreateSessionToken(t *testing.T, body string) string {
	t.Helper()
	var parsed struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		t.Fatalf("decode create response: %v (body=%s)", err, body)
	}
	if parsed.Token == "" {
		t.Fatalf("create response carries no token: %s", body)
	}
	return parsed.Token
}
