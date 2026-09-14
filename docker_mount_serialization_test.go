package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// parseDockerMountSpec parses one Docker --mount value with the
// authoritative docker/cli grammar (opts/mount.go, MountOpt.Set): the value
// is ONE Go CSV record — docker/cli reads exactly one record — and every
// field is a key=value pair (first '=' splits) or a boolean flag; later
// duplicate keys overwrite earlier ones. This mirror is the semantic
// reference the serializer contract tests are proved against; it never runs
// in production.
type dockerMountGrammar struct {
	Type     string
	Source   string
	Target   string
	ReadOnly bool
	Keys     []string
}

func parseDockerMountSpec(t *testing.T, spec string) dockerMountGrammar {
	t.Helper()
	fields, err := csv.NewReader(strings.NewReader(spec)).Read()
	if err != nil {
		t.Fatalf("Docker CLI grammar cannot parse the mount value %q: %v", spec, err)
	}
	m := dockerMountGrammar{}
	for _, field := range fields {
		key, val, ok := strings.Cut(field, "=")
		key = strings.ToLower(key)
		m.Keys = append(m.Keys, key)
		if !ok {
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
// M13 security property through the real production run path: a crafted
// target/source must reach the Docker CLI as exactly ONE CSV field, so the
// CLI parses exactly the intended source, target, and readonly semantics —
// the crafted data cannot truncate the record, flip the consumption mode,
// or add a second logical field (the historical M13 class: an unquoted
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
		// representable reports whether the Docker mount grammar can
		// represent the crafted value faithfully: the CSV reader normalizes
		// the literal CRLF pair to LF inside quoted fields, so a CRLF value
		// must be refused before any Docker state exists.
		representable bool
	}{
		{name: "newline target", target: "/mnt\nfoo", representable: true},
		{name: "CRLF target", target: "/mnt\r\nfoo", representable: false},
		{name: "quote target", target: `/mnt"foo`, representable: true},
		{name: "comma option target", target: "/data,readonly", representable: true},
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
		// wantErr marks values the Docker mount grammar cannot represent
		// faithfully (the CRLF normalization) or structural empties.
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
		{name: "leading and trailing whitespace", in: dockerBindMount{Source: "/srv/ a ", Target: "/mnt/ c "}},
		{name: "hostile delimiter combination", in: dockerBindMount{Source: `/srv/a,b"c`, Target: "/mnt/d=e\nf,g\"h"}},
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
