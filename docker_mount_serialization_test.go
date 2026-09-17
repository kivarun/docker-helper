package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// parseDockerMountSpec is a semantic mirror of the exact MountOpt.Set
// validation subset the serializer contract depends on (docker/cli
// opts/mount.go): the whole --mount value is trimmed first, ONE CSV record
// is read, and every key=value field must carry a key and a value that
// survive Docker's whitespace validation unchanged — an empty value or a
// value with leading/trailing whitespace is rejected ("value is empty" /
// "value should not have whitespace"), unknown keys and unknown boolean
// flags are rejected, and later duplicate keys overwrite earlier ones.
// This mirror never runs in production; its only role is to prove the
// serializer contract against the authoritative grammar.
type dockerMountGrammar struct {
	Type     string
	Source   string
	Target   string
	ReadOnly bool
	Keys     []string
}

func parseDockerMountSpec(t *testing.T, spec string) dockerMountGrammar {
	t.Helper()
	value := strings.TrimSpace(spec)
	if value == "" {
		t.Fatal("Docker CLI grammar rejects the empty mount value")
	}
	fields, err := csv.NewReader(strings.NewReader(value)).Read()
	if err != nil {
		t.Fatalf("Docker CLI grammar cannot parse the mount value %q: %v", spec, err)
	}
	m := dockerMountGrammar{}
	for _, field := range fields {
		key, val, hasValue := strings.Cut(field, "=")
		if k := strings.TrimSpace(key); k != key {
			t.Fatalf("Docker CLI grammar rejects the whitespace-padded option %q of %q", field, spec)
		}
		if hasValue {
			v := strings.TrimSpace(val)
			if v == "" {
				t.Fatalf("Docker CLI grammar rejects the empty value of %q in %q", field, spec)
			}
			if v != val {
				t.Fatalf("Docker CLI grammar rejects the whitespace-padded value of %q in %q", field, spec)
			}
		}
		key = strings.ToLower(key)
		m.Keys = append(m.Keys, key)
		if !hasValue {
			switch key {
			case "readonly", "ro":
				m.ReadOnly = true
				continue
			default:
				t.Fatalf("Docker CLI grammar rejects the field %q of %q", field, spec)
			}
		}
		switch key {
		case "type":
			m.Type = strings.ToLower(val)
		case "source", "src":
			m.Source = val
		case "target", "dst", "destination":
			m.Target = val
		case "readonly", "ro":
			b, err := strconv.ParseBool(val)
			if err != nil {
				t.Fatalf("Docker CLI grammar rejects the %s value of %q: %v", key, spec, err)
			}
			m.ReadOnly = b
		default:
			t.Fatalf("Docker CLI grammar rejects the unexpected key %q of %q", key, spec)
		}
	}
	return m
}

// dockerMountValues returns the values of every --mount flag in one captured
// docker argv.
func dockerMountValues(t *testing.T, args []string) []string {
	t.Helper()
	var values []string
	for i, arg := range args {
		if arg == "--mount" {
			if i+1 >= len(args) {
				t.Fatal("docker argv carries a --mount flag without a value")
			}
			values = append(values, args[i+1])
		}
	}
	return values
}

// TestRunHostileTargetKeepsIntendedBindMountThroughDockerGrammar proves the
// bind-mount serialization security property through the real production run path: a crafted
// target/source must reach the Docker CLI as exactly ONE CSV field, so the
// CLI parses exactly the intended source, target, and readonly semantics —
// the crafted data cannot truncate the record, flip the consumption mode,
// or add a second logical field (the historical failure class: an unquoted
// control character in the target ends the CSV record the CLI parses, the
// trailing readonly flag is silently dropped, and the workspace mounts
// WRITABLE at a different target).
func TestRunHostileTargetKeepsIntendedBindMountThroughDockerGrammar(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	app.Config.Mode = ModeUser
	app.OperationSupervisor = newOperationSupervisor()
	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0].Path))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	var dockerArgs []string
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		dockerArgs = append([]string(nil), args...)
		return exec.CommandContext(ctx, "/bin/true")
	}

	for _, tc := range []struct {
		name   string
		target string
		// representable reports whether the mount representability
		// contract can represent the crafted value faithfully: the CSV
		// reader normalizes the literal CRLF pair to LF inside quoted
		// fields, and the Docker MountOpt.Set value validation rejects
		// empty or whitespace-padded values, so such values must be
		// refused before any Docker state exists.
		representable bool
	}{
		{name: "newline target", target: "/mnt\nfoo", representable: true},
		{name: "CRLF target", target: "/mnt\r\nfoo", representable: false},
		{name: "quote target", target: `/mnt"foo`, representable: true},
		{name: "comma option target", target: "/data,readonly", representable: true},
		{name: "trailing space target", target: "/mnt/sp ", representable: false},
	} {
		body := fmt.Sprintf(`{"image":"alpine","mounts":[{"source":".","target":%q,"read_only":true}]}`, tc.target)
		req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader([]byte(body)))
		req.Header.Set("Authorization", "Bearer "+result.Token)
		w := httptest.NewRecorder()
		app.handleRun(w, req)

		if !tc.representable {
			// The grammar cannot represent the value faithfully: the run is
			// refused invalid_mount before any Docker state exists.
			if w.Code != http.StatusBadRequest {
				t.Fatalf("%s: expected 400, got %d (body=%s)", tc.name, w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), "invalid_mount") {
				t.Fatalf("%s: expected invalid_mount, got %s", tc.name, w.Body.String())
			}
			if dockerArgs != nil {
				t.Fatalf("%s: Docker was invoked for an unrepresentable mount", tc.name)
			}
			continue
		}

		if w.Code != http.StatusCreated {
			t.Fatalf("%s: expected 201, got %d (body=%s)", tc.name, w.Code, w.Body.String())
		}
		specs := dockerMountValues(t, dockerArgs)
		dockerArgs = nil
		if len(specs) != 1 {
			t.Fatalf("%s: expected exactly one --mount value, got %q", tc.name, specs)
		}
		m := parseDockerMountSpec(t, specs[0])
		if m.Type != "bind" {
			t.Fatalf("%s: Docker parsed type %q, want bind", tc.name, m.Type)
		}
		if m.Source != result.Session.Workspace {
			t.Fatalf("%s: Docker parsed source %q, want the workspace %q", tc.name, m.Source, result.Session.Workspace)
		}
		if m.Target != tc.target {
			t.Fatalf("%s: Docker parsed target %q, want the intended target %q", tc.name, m.Target, tc.target)
		}
		if !m.ReadOnly {
			t.Fatalf("%s: Docker lost the intended readonly — the mount is writable", tc.name)
		}
		for _, key := range m.Keys {
			switch key {
			case "type", "source", "target", "readonly":
			default:
				t.Fatalf("%s: Docker parsed the extra mount option %q from crafted data", tc.name, key)
			}
		}
	}
}

// TestDockerBindMountSpecContract proves the canonical serializer's
// representability and semantic round-trip: for every accepted fact set the
// serialized value parses back through the authoritative Docker CLI grammar
// to exactly the intended source, target, and readonly semantics with no
// extra logical field, and a value the grammar cannot represent faithfully
// fails closed instead of being encoded approximately.
func TestDockerBindMountSpecContract(t *testing.T) {
	cases := []struct {
		name string
		in   dockerBindMount
		// wantErr marks values the mount representability contract cannot
		// represent faithfully: the encoding/csv record normalization, the
		// Docker MountOpt.Set value validation (empty or
		// whitespace-padded), or the exec argv limit (NUL), plus
		// structural empties.
		wantErr bool
	}{
		{name: "ordinary", in: dockerBindMount{Source: "/srv/data", Target: "/mnt/data"}},
		{name: "readonly true", in: dockerBindMount{Source: "/srv/data", Target: "/mnt/data", ReadOnly: true}},
		{name: "readonly false", in: dockerBindMount{Source: "/srv/data", Target: "/mnt/data", ReadOnly: false}},
		{name: "comma in source and target", in: dockerBindMount{Source: "/srv/a,b", Target: "/mnt/c,d"}},
		{name: "newline in source and target", in: dockerBindMount{Source: "/srv/a\nb", Target: "/mnt/c\nd"}},
		{name: "quotes in source and target", in: dockerBindMount{Source: `/srv/a"b`, Target: `/mnt/c"d`}},
		{name: "equals in source and target", in: dockerBindMount{Source: "/srv/a=b", Target: "/mnt/c=d"}},
		{name: "backslash in source and target", in: dockerBindMount{Source: `/srv/a\b`, Target: `/mnt/c\d`}},
		{name: "lone carriage return", in: dockerBindMount{Source: "/srv/a\rb", Target: "/mnt/c\rd"}},
		{name: "internal whitespace in source and target", in: dockerBindMount{Source: "/srv/a b", Target: "/mnt/c d"}},
		{name: "hostile delimiter combination", in: dockerBindMount{Source: `/srv/a,b"c`, Target: "/mnt/d=e\nf,g\"h"}},
		{name: "trailing ASCII space in target", in: dockerBindMount{Source: "/srv/data", Target: "/mnt/sp "}, wantErr: true},
		{name: "trailing tab in target", in: dockerBindMount{Source: "/srv/data", Target: "/mnt/tab\t"}, wantErr: true},
		{name: "trailing LF in target", in: dockerBindMount{Source: "/srv/data", Target: "/mnt/lf\n"}, wantErr: true},
		{name: "trailing lone CR in target", in: dockerBindMount{Source: "/srv/data", Target: "/mnt/cr\r"}, wantErr: true},
		{name: "leading space in target", in: dockerBindMount{Source: "/srv/data", Target: " /mnt/lead"}, wantErr: true},
		{name: "trailing Unicode NBSP in target", in: dockerBindMount{Source: "/srv/data", Target: "/mnt/nbsp\u00a0"}, wantErr: true},
		{name: "trailing Unicode ideographic space in target", in: dockerBindMount{Source: "/srv/data", Target: "/mnt/ideo\u3000"}, wantErr: true},
		{name: "leading and trailing whitespace in source and target", in: dockerBindMount{Source: "/srv/ a ", Target: "/mnt/ c "}, wantErr: true},
		{name: "trailing whitespace in source", in: dockerBindMount{Source: "/srv/tail ", Target: "/mnt/data"}, wantErr: true},
		{name: "leading whitespace in source", in: dockerBindMount{Source: " /srv/lead", Target: "/mnt/data"}, wantErr: true},
		{name: "NUL byte in source", in: dockerBindMount{Source: "/srv/a\x00b", Target: "/mnt/data"}, wantErr: true},
		{name: "NUL byte in target", in: dockerBindMount{Source: "/srv/data", Target: "/mnt/a\x00b"}, wantErr: true},
		{name: "CRLF in source", in: dockerBindMount{Source: "/srv/a\r\nb", Target: "/mnt/data"}, wantErr: true},
		{name: "CRLF in target", in: dockerBindMount{Source: "/srv/data", Target: "/mnt/c\r\nd"}, wantErr: true},
		{name: "empty source", in: dockerBindMount{Target: "/mnt/data"}, wantErr: true},
		{name: "empty target", in: dockerBindMount{Source: "/srv/data"}, wantErr: true},
	}
	for _, tc := range cases {
		spec, err := dockerBindMountSpec(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("%s: expected a fail-closed refusal, got spec %q", tc.name, spec)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: unexpected refusal: %v", tc.name, err)
		}
		if strings.Contains(spec, "\n") && !strings.Contains(tc.in.Source, "\n") && !strings.Contains(tc.in.Target, "\n") {
			t.Fatalf("%s: spec %q spans multiple records without any newline fact", tc.name, spec)
		}
		m := parseDockerMountSpec(t, spec)
		if m.Type != "bind" {
			t.Fatalf("%s: parsed type %q, want bind", tc.name, m.Type)
		}
		if m.Source != tc.in.Source {
			t.Fatalf("%s: parsed source %q, want the intended source %q", tc.name, m.Source, tc.in.Source)
		}
		if m.Target != tc.in.Target {
			t.Fatalf("%s: parsed target %q, want the intended target %q", tc.name, m.Target, tc.in.Target)
		}
		if m.ReadOnly != tc.in.ReadOnly {
			t.Fatalf("%s: parsed readonly %v, want the intended %v", tc.name, m.ReadOnly, tc.in.ReadOnly)
		}
		wantKeys := []string{"type", "source", "target"}
		if tc.in.ReadOnly {
			wantKeys = append(wantKeys, "readonly")
		}
		if strings.Join(m.Keys, ",") != strings.Join(wantKeys, ",") {
			t.Fatalf("%s: parsed keys %q, want exactly %q", tc.name, m.Keys, wantKeys)
		}
	}
}

// TestRunSerializerFailureBeforeAdmissionLeavesNoOperation proves the
// admission-order property through the real production run path: the Docker
// argv is built and serialized after the pins and the workload MAC state are
// prepared — when every actual bind source is known — but BEFORE the
// operation admission and the run.start audit. A serializer failure on a
// daemon-owned value must therefore answer internal_error with no admitted
// Operation left running in the supervisor, no run.start audit event, and no
// Docker process.
func TestRunSerializerFailureBeforeAdmissionLeavesNoOperation(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	app.Config.Mode = ModeUser
	app.OperationSupervisor = newOperationSupervisor()
	auditBuf, _ := setupTestLogging(t)
	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0].Path))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	// The daemon-owned trusted CA prepared directory carries an
	// unrepresentable sequence: the CRLF pair cannot survive the encoding/csv
	// record faithfully, so the serializer must refuse it. The value is
	// daemon-owned — the caller cannot influence it — so the correct answer
	// is an internal server error, not invalid_mount.
	preparedDir := filepath.Join(app.Config.RuntimeDir, "trusted-ca\r\nevil", "snapshot")
	app.Config.TrustedCAInjection = "auto"
	app.Config.TrustedCAPreparedDir = preparedDir

	var dockerCalled bool
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		dockerCalled = true
		return exec.CommandContext(ctx, "/bin/true")
	}

	req := newRunRequest(map[string]any{
		"image":   "alpine:3.24",
		"command": []string{"echo", "hello"},
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected %d for a daemon-owned serialization failure, got %d (body=%s)",
			http.StatusInternalServerError, w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "internal_error") {
		t.Fatalf("expected internal_error, got %s", w.Body.String())
	}
	if dockerCalled {
		t.Fatal("Docker must not be invoked when the argv cannot be serialized")
	}
	if len(app.OperationSupervisor.ops) != 0 {
		t.Fatalf("supervisor retains %d admitted operation(s) after the serializer failure — a running zombie Operation", len(app.OperationSupervisor.ops))
	}
	if strings.Contains(auditBuf.String(), "run.start") {
		t.Fatal("run.start audit event recorded without a valid started operation")
	}
}
