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
