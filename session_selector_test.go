package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestCreateSessionSelectorMatrix verifies the Session create selector contract:
// true request-field presence distinguishes omitted from explicitly-supplied
// empty, malformed selector values (null / non-string) are rejected as invalid
// selectors (not silently treated as omitted), and structural conflict takes
// precedence over value/lookup validation.
func TestCreateSessionSelectorMatrix(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	ws := testWorkspaceDir(t, app.Config.AllowedRoots[0])

	mux := http.NewServeMux()
	mux.HandleFunc("POST /sessions", app.handleCreateSession)

	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/sessions", strings.NewReader(body))
		withAdminToken(req)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		return w
	}

	cases := []struct {
		name string
		body string
		want int
		code string
	}{
		{name: "omitted", body: `{"workspace":"` + ws + `"}`, want: http.StatusCreated, code: ""},
		{name: "empty launcher_id", body: `{"workspace":"` + ws + `","launcher_id":""}`, want: http.StatusBadRequest, code: "invalid_selector"},
		{name: "empty principal", body: `{"workspace":"` + ws + `","principal":""}`, want: http.StatusBadRequest, code: "invalid_selector"},
		{name: "null launcher_id", body: `{"workspace":"` + ws + `","launcher_id":null}`, want: http.StatusBadRequest, code: "invalid_selector"},
		{name: "null principal", body: `{"workspace":"` + ws + `","principal":null}`, want: http.StatusBadRequest, code: "invalid_selector"},
		{name: "non-string launcher_id", body: `{"workspace":"` + ws + `","launcher_id":123}`, want: http.StatusBadRequest, code: "invalid_selector"},
		{name: "non-string principal", body: `{"workspace":"` + ws + `","principal":123}`, want: http.StatusBadRequest, code: "invalid_selector"},
		{name: "both supplied valid", body: `{"workspace":"` + ws + `","launcher_id":"l","principal":"p"}`, want: http.StatusBadRequest, code: "conflicting_selectors"},
		{name: "both supplied one empty", body: `{"workspace":"` + ws + `","launcher_id":"l","principal":""}`, want: http.StatusBadRequest, code: "conflicting_selectors"},
		{name: "both supplied both empty", body: `{"workspace":"` + ws + `","launcher_id":"","principal":""}`, want: http.StatusBadRequest, code: "conflicting_selectors"},
		{name: "both supplied one null", body: `{"workspace":"` + ws + `","launcher_id":null,"principal":"p"}`, want: http.StatusBadRequest, code: "invalid_selector"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := post(tc.body)
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d; body %s", w.Code, tc.want, w.Body.String())
			}
			if tc.code != "" && !bytes.Contains(w.Body.Bytes(), []byte(tc.code)) {
				t.Fatalf("code %q not in body: %s", tc.code, w.Body.String())
			}
		})
	}
}
