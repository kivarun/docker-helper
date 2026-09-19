package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type failingCredentialRotationWriter struct {
	header http.Header
	status int
}

func (w *failingCredentialRotationWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *failingCredentialRotationWriter) WriteHeader(status int) {
	w.status = status
}

func (w *failingCredentialRotationWriter) Write([]byte) (int, error) {
	return 0, errors.New("forced credential rotation response write failure")
}

type flushFailingCredentialRotationWriter struct {
	header http.Header
	status int
	wrote  int
}

func (w *flushFailingCredentialRotationWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *flushFailingCredentialRotationWriter) WriteHeader(status int) {
	w.status = status
}

func (w *flushFailingCredentialRotationWriter) Write(p []byte) (int, error) {
	w.wrote += len(p)
	return len(p), nil
}

func (w *flushFailingCredentialRotationWriter) FlushError() error {
	return errors.New("forced credential rotation response flush failure")
}

func serveCredentialRotationWithWriter(
	t *testing.T,
	app *App,
	method string,
	path string,
	bearer string,
	w http.ResponseWriter,
) {
	t.Helper()
	mux := http.NewServeMux()
	registerRoutes(mux, app)
	req := httptest.NewRequest(method, path, strings.NewReader(""))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	mux.ServeHTTP(w, req)
}

func installCredentialRotationBarrier(t *testing.T, count int) (func(), func()) {
	t.Helper()
	entered := make(chan struct{}, count)
	release := make(chan struct{})
	credentialRotationBeforeTransactionGate = func() {
		entered <- struct{}{}
		<-release
	}
	t.Cleanup(func() {
		credentialRotationBeforeTransactionGate = nil
	})
	wait := func() {
		for i := 0; i < count; i++ {
			<-entered
		}
	}
	unblock := func() {
		close(release)
	}
	return wait, unblock
}

func TestLauncherCredentialRotationWriteFailureRollsBack(t *testing.T) {
	app, _, oldBearer, l := launcherAuditApp(t, "rotwritefail")

	w := &failingCredentialRotationWriter{}
	serveCredentialRotationWithWriter(
		t,
		app,
		http.MethodPost,
		"/principals/rotwritefail/launchers/"+l.ID+"/credential/rotate",
		oldBearer,
		w,
	)

	if w.status != http.StatusOK {
		t.Fatalf("response status before forced write failure = %d, want 200", w.status)
	}
	auth, err := authenticateCredential(app.DB, oldBearer)
	if err != nil {
		t.Fatalf("old Launcher bearer must remain valid after response write failure: %v", err)
	}
	if auth.Launcher == nil || auth.Launcher.LauncherID != l.ID {
		t.Fatalf("old bearer authority after rollback = %+v, want Launcher %s", auth, l.ID)
	}
}

func TestPrincipalCredentialRotationWriteFailureRollsBack(t *testing.T) {
	app, oldBearer, _ := principalCredentialApp(t, "principalwritefail")

	w := &failingCredentialRotationWriter{}
	serveCredentialRotationWithWriter(
		t,
		app,
		http.MethodPost,
		"/principals/principalwritefail/credentials/caller/rotate",
		oldBearer,
		w,
	)

	if w.status != http.StatusOK {
		t.Fatalf("response status before forced write failure = %d, want 200", w.status)
	}
	auth, err := authenticateCredential(app.DB, oldBearer)
	if err != nil {
		t.Fatalf("old Principal bearer must remain valid after response write failure: %v", err)
	}
	if auth.Principal == nil || auth.Principal.PrincipalName != "principalwritefail" {
		t.Fatalf("old bearer authority after rollback = %+v, want principalwritefail", auth)
	}
}

func TestLauncherCredentialRotationFlushFailureRollsBack(t *testing.T) {
	app, _, oldBearer, l := launcherAuditApp(t, "rotflushfail")

	w := &flushFailingCredentialRotationWriter{}
	serveCredentialRotationWithWriter(
		t,
		app,
		http.MethodPost,
		"/principals/rotflushfail/launchers/"+l.ID+"/credential/rotate",
		oldBearer,
		w,
	)

	if w.status != http.StatusOK || w.wrote == 0 {
		t.Fatalf("pre-flush response state = status %d, wrote %d; want status 200 with full body write", w.status, w.wrote)
	}
	auth, err := authenticateCredential(app.DB, oldBearer)
	if err != nil {
		t.Fatalf("old Launcher bearer must remain valid after response flush failure: %v", err)
	}
	if auth.Launcher == nil || auth.Launcher.LauncherID != l.ID {
		t.Fatalf("old bearer authority after flush rollback = %+v, want Launcher %s", auth, l.ID)
	}
}

func TestPrincipalCredentialRotationFlushFailureRollsBack(t *testing.T) {
	app, oldBearer, _ := principalCredentialApp(t, "principalflushfail")

	w := &flushFailingCredentialRotationWriter{}
	serveCredentialRotationWithWriter(
		t,
		app,
		http.MethodPost,
		"/principals/principalflushfail/credentials/caller/rotate",
		oldBearer,
		w,
	)

	if w.status != http.StatusOK || w.wrote == 0 {
		t.Fatalf("pre-flush response state = status %d, wrote %d; want status 200 with full body write", w.status, w.wrote)
	}
	auth, err := authenticateCredential(app.DB, oldBearer)
	if err != nil {
		t.Fatalf("old Principal bearer must remain valid after response flush failure: %v", err)
	}
	if auth.Principal == nil || auth.Principal.PrincipalName != "principalflushfail" {
		t.Fatalf("old bearer authority after flush rollback = %+v, want principalflushfail", auth)
	}
}

func TestDeliveryBoundedWriterPropagatesFlushError(t *testing.T) {
	underlying := &flushFailingCredentialRotationWriter{}
	w := &deliveryBoundedWriter{ResponseWriter: underlying}

	if err := http.NewResponseController(w).Flush(); err == nil ||
		!strings.Contains(err.Error(), "forced credential rotation response flush failure") {
		t.Fatalf("Flush() error = %v, want underlying flush failure", err)
	}
}

func TestStatusResponseWriterTransparentToResponseControllerFlush(t *testing.T) {
	underlying := &flushFailingCredentialRotationWriter{}
	w := &statusResponseWriter{ResponseWriter: underlying, status: http.StatusOK}

	err := http.NewResponseController(w).Flush()
	if err == nil || !strings.Contains(err.Error(), "forced credential rotation response flush failure") {
		t.Fatalf("Flush() through statusResponseWriter = %v, want underlying flush failure", err)
	}
}

// newProductionChainServer serves the app's route table through the exact
// production middleware construction of the daemon wiring (main.go's
// newHTTPServer path):
//
//	boundResponseDelivery(
//	    withRequestID(
//	        withLogging(routeTable),
//	    ),
//	)
//
// It reuses the production construction functions unchanged, so handlers
// observe the same writer chain as in the real daemon: statusResponseWriter
// over deliveryBoundedWriter over the real connection writer, with the
// production response-delivery window.
func newProductionChainServer(t *testing.T, app *App) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	registerRoutes(mux, app)
	srv := httptest.NewServer(boundResponseDelivery(
		withRequestID(withLogging(http.HandlerFunc(mux.ServeHTTP))),
		productionServerTimeouts().responseDelivery,
	))
	t.Cleanup(srv.Close)
	return srv
}

// rotateThroughProductionChain posts a credential rotate request through the
// production middleware chain and returns the HTTP response; the caller owns
// closing the body.
func rotateThroughProductionChain(t *testing.T, srv *httptest.Server, path, bearer string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("rotate through production chain: %v", err)
	}
	return res
}

// authThroughProductionChain requests GET /auth through the production
// middleware chain and returns the status code; the caller owns closing the
// body.
func authThroughProductionChain(t *testing.T, srv *httptest.Server, bearer string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/auth", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("auth through production chain: %v", err)
	}
	defer res.Body.Close()
	return res.StatusCode
}

func TestLauncherCredentialRotateThroughProductionMiddlewareChain(t *testing.T) {
	app, _, oldBearer, l := launcherAuditApp(t, "rotprodchain")
	srv := newProductionChainServer(t, app)

	res := rotateThroughProductionChain(t, srv,
		"/principals/rotprodchain/launchers/"+l.ID+"/credential/rotate", oldBearer)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("rotate through production chain: expected 200, got %d", res.StatusCode)
	}
	var rotated launcherCredentialResponse
	if err := json.NewDecoder(res.Body).Decode(&rotated); err != nil {
		t.Fatal(err)
	}
	if rotated.Credential == nil || rotated.Token == "" {
		t.Fatal("rotate response must carry the rotated credential and the replacement bearer")
	}
	if rotated.Credential.ID == "" {
		t.Error("rotate response must preserve the credential ID")
	}

	if status := authThroughProductionChain(t, srv, oldBearer); status != http.StatusUnauthorized {
		t.Errorf("old bearer after committed rotation: expected 401, got %d", status)
	}
	if status := authThroughProductionChain(t, srv, rotated.Token); status != http.StatusOK {
		t.Fatalf("replacement bearer must authenticate through the production chain: got %d", status)
	}

	var credLauncherID string
	if err := app.DB.QueryRow(`SELECT launcher_id FROM credentials WHERE id = ?`, rotated.Credential.ID).
		Scan(&credLauncherID); err != nil {
		t.Fatalf("rotated credential lookup: %v", err)
	}
	if credLauncherID != l.ID {
		t.Errorf("rotated credential launcher_id = %q, want %q", credLauncherID, l.ID)
	}
}

func TestPrincipalCredentialRotateThroughProductionMiddlewareChain(t *testing.T) {
	app, oldBearer, _ := principalCredentialApp(t, "rotprodprincipal")
	srv := newProductionChainServer(t, app)

	res := rotateThroughProductionChain(t, srv,
		"/principals/rotprodprincipal/credentials/caller/rotate", oldBearer)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("rotate through production chain: expected 200, got %d", res.StatusCode)
	}
	var rotated principalCredentialTokenResponse
	if err := json.NewDecoder(res.Body).Decode(&rotated); err != nil {
		t.Fatal(err)
	}
	if rotated.Token == "" || rotated.Credential.ID == "" {
		t.Fatal("rotate response must carry the replacement bearer and the stable credential identity")
	}
	if rotated.Credential.Principal != "rotprodprincipal" {
		t.Errorf("credential principal = %q, want rotprodprincipal", rotated.Credential.Principal)
	}

	if status := authThroughProductionChain(t, srv, oldBearer); status != http.StatusUnauthorized {
		t.Errorf("old bearer after committed rotation: expected 401, got %d", status)
	}
	if status := authThroughProductionChain(t, srv, rotated.Token); status != http.StatusOK {
		t.Fatalf("replacement bearer must authenticate through the production chain: got %d", status)
	}

	var credPrincipal string
	if err := app.DB.QueryRow(
		`SELECT p.username FROM credentials c JOIN principals p ON p.id = c.principal_id WHERE c.id = ?`,
		rotated.Credential.ID,
	).Scan(&credPrincipal); err != nil {
		t.Fatalf("rotated credential lookup: %v", err)
	}
	if credPrincipal != "rotprodprincipal" {
		t.Errorf("rotated credential principal = %q, want rotprodprincipal", credPrincipal)
	}
}

func TestLauncherCredentialSelfRotationConcurrentSameBearerOneWinner(t *testing.T) {
	app, _, oldBearer, l := launcherAuditApp(t, "launcherrace")
	waitForBoth, releaseBoth := installCredentialRotationBarrier(t, 2)

	results := make(chan *httptest.ResponseRecorder, 2)
	go func() {
		results <- rotateThroughMux(t, app, "launcherrace", l.ID, oldBearer)
	}()
	go func() {
		results <- rotateThroughMux(t, app, "launcherrace", l.ID, oldBearer)
	}()

	waitForBoth()
	releaseBoth()

	first := <-results
	second := <-results
	responses := []*httptest.ResponseRecorder{first, second}
	var winner launcherCredentialResponse
	successes := 0
	conflicts := 0
	for _, w := range responses {
		switch w.Code {
		case http.StatusOK:
			successes++
			if err := json.Unmarshal(w.Body.Bytes(), &winner); err != nil {
				t.Fatal(err)
			}
		case http.StatusConflict:
			conflicts++
			apiErr := decodeAPIError(t, w.Body.Bytes())
			if apiErr.Code != "credential_rotation_conflict" {
				t.Errorf("loser code = %q, want credential_rotation_conflict", apiErr.Code)
			}
		default:
			t.Errorf("concurrent self-rotate status = %d body=%s", w.Code, w.Body.String())
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent self-rotate results: success=%d conflict=%d, want 1/1", successes, conflicts)
	}
	if winner.Token == "" {
		t.Fatal("winning rotation returned no bearer")
	}

	if _, err := authenticateCredential(app.DB, oldBearer); err == nil {
		t.Fatal("old Launcher bearer must be invalid after the winning commit")
	}
	auth, err := authenticateCredential(app.DB, winner.Token)
	if err != nil {
		t.Fatalf("winning Launcher bearer must authenticate: %v", err)
	}
	if auth.Launcher == nil || auth.Launcher.LauncherID != l.ID {
		t.Fatalf("winning bearer authority = %+v, want Launcher %s", auth, l.ID)
	}
}

func TestPrincipalCredentialSelfRotationConcurrentSameBearerOneWinner(t *testing.T) {
	app, oldBearer, _ := principalCredentialApp(t, "principalrace")
	waitForBoth, releaseBoth := installCredentialRotationBarrier(t, 2)

	results := make(chan *httptest.ResponseRecorder, 2)
	path := "/principals/principalrace/credentials/caller/rotate"
	go func() {
		results <- launcherRequest(t, app, http.MethodPost, path, oldBearer, "")
	}()
	go func() {
		results <- launcherRequest(t, app, http.MethodPost, path, oldBearer, "")
	}()

	waitForBoth()
	releaseBoth()

	first := <-results
	second := <-results
	responses := []*httptest.ResponseRecorder{first, second}
	var winner principalCredentialTokenResponse
	successes := 0
	conflicts := 0
	for _, w := range responses {
		switch w.Code {
		case http.StatusOK:
			successes++
			if err := json.Unmarshal(w.Body.Bytes(), &winner); err != nil {
				t.Fatal(err)
			}
		case http.StatusConflict:
			conflicts++
			apiErr := decodeAPIError(t, w.Body.Bytes())
			if apiErr.Code != "credential_rotation_conflict" {
				t.Errorf("loser code = %q, want credential_rotation_conflict", apiErr.Code)
			}
		default:
			t.Errorf("concurrent Principal self-rotate status = %d body=%s", w.Code, w.Body.String())
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent Principal self-rotate results: success=%d conflict=%d, want 1/1", successes, conflicts)
	}
	if winner.Token == "" {
		t.Fatal("winning Principal rotation returned no bearer")
	}

	if _, err := authenticateCredential(app.DB, oldBearer); err == nil {
		t.Fatal("old Principal bearer must be invalid after the winning commit")
	}
	auth, err := authenticateCredential(app.DB, winner.Token)
	if err != nil {
		t.Fatalf("winning Principal bearer must authenticate: %v", err)
	}
	if auth.Principal == nil || auth.Principal.PrincipalName != "principalrace" {
		t.Fatalf("winning bearer authority = %+v, want principalrace", auth)
	}
}

func TestCredentialRotationCommitErrorAfterWriteIsNotRetried(t *testing.T) {
	app, _, oldBearer, l := launcherAuditApp(t, "rotcommitfail")

	originalCommit := credentialRotationCommitFn
	commitCalls := 0
	credentialRotationCommitFn = func(*sql.Tx) error {
		commitCalls++
		return errors.New("forced commit failure after response write")
	}
	t.Cleanup(func() {
		credentialRotationCommitFn = originalCommit
	})

	w := rotateThroughMux(t, app, "rotcommitfail", l.ID, oldBearer)
	if w.Code != http.StatusOK {
		t.Fatalf("response already written before forced commit failure: got %d body=%s", w.Code, w.Body.String())
	}
	if commitCalls != 1 {
		t.Fatalf("commit attempts = %d, want exactly 1 (no automatic retry)", commitCalls)
	}

	var resp launcherCredentialResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Token == "" {
		t.Fatal("pre-commit response must contain the generated replacement bearer")
	}

	// The injected seam fails before committing, so this deterministic test
	// observes the rollback side of the intentionally ambiguous production
	// boundary: the old bearer remains valid and the already-returned new
	// bearer is not authoritative.
	if _, err := authenticateCredential(app.DB, oldBearer); err != nil {
		t.Fatalf("old bearer should remain valid in the forced rollback outcome: %v", err)
	}
	if _, err := authenticateCredential(app.DB, resp.Token); err == nil {
		t.Fatal("uncommitted replacement bearer must not authenticate")
	}
}
