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
	}{
		{name: "newline target", target: "/mnt\nfoo"},
		{name: "CRLF target", target: "/mnt\r\nfoo"},
		{name: "quote target", target: `/mnt"foo`},
		{name: "comma option target", target: "/data,readonly"},
	} {
		body := fmt.Sprintf(`{"image":"alpine","mounts":[{"source":".","target":%q,"read_only":true}]}`, tc.target)
		req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader([]byte(body)))
		req.Header.Set("Authorization", "Bearer "+result.Token)
		w := httptest.NewRecorder()
		app.handleRun(w, req)
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
