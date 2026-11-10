//go:build linux

package main

// wrapper_runtime_linux_test.go proves the uninvoked wrapper runtime
// dispatch against the accepted R4-P1/C1/C2 contracts: the pinned argv
// grammar and dispatch matrix, the /dev spec rewrite with structural
// preservation, the commit-point semantics (pre-commit refusals leave
// the original byte-unchanged with no residue; the post-commit exec
// failure leaves the committed rewrite), byte-identical pass-through,
// and the fail-closed D-2 runtime-path boundary. The run fixtures use
// the REAL production preparer (via the R4-P0 helper) for the prepared
// tree and REAL files for the bundle/spec.

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

const wrapperTestRuntimePath = "/usr/libexec/docker-helper/buildkit/real-buildkit-runc"

// wrapperExecRecord records the exec seam calls.
type wrapperExecRecord struct {
	calls int
	path  string
	argv  []string
	env   []string
	err   error
}

// withWrapperRuntimeSeams swaps the runtime-path value, the exec seam
// (recording, optionally failing), and the commit rename (optionally
// failing). Package-global seams; restored via t.Cleanup; never used
// with t.Parallel.
func withWrapperRuntimeSeams(t *testing.T, execErr error, renameErr error) *wrapperExecRecord {
	t.Helper()
	rec := &wrapperExecRecord{err: execErr}
	origPath, origExec, origRename := wrapperRealRuntimePath, wrapperExecRuntime, wrapperCommitRename
	wrapperRealRuntimePath = wrapperTestRuntimePath
	wrapperExecRuntime = func(path string, argv []string, env []string) error {
		rec.calls++
		rec.path, rec.argv, rec.env = path, append([]string(nil), argv...), env
		return rec.err
	}
	wrapperCommitRename = func(tempPath, targetPath string) error {
		if renameErr != nil {
			return renameErr
		}
		return origRename(tempPath, targetPath)
	}
	t.Cleanup(func() {
		wrapperRealRuntimePath, wrapperExecRuntime, wrapperCommitRename = origPath, origExec, origRename
	})
	return rec
}

// withWrapperCreateTemp swaps the exclusive temporary-file creation seam
// (C4 deterministic fault injection). Package-global; restored via
// t.Cleanup; never used with t.Parallel.
func withWrapperCreateTemp(t *testing.T, fn func(dir string) (*os.File, error)) {
	t.Helper()
	orig := wrapperCreateTemp
	wrapperCreateTemp = fn
	t.Cleanup(func() { wrapperCreateTemp = orig })
}

// withWrapperBundleTree repoints the builderStateRoot owner at a real
// temporary tree and creates the canonical executor bundle directory for
// the test operation/bundle. Returns the bundle directory.
func withWrapperBundleTree(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	origRoot := builderStateRoot
	builderStateRoot = tmp
	t.Cleanup(func() { builderStateRoot = origRoot })
	bundleDir := filepath.Join(tmp, "ops", wrapperTestOpID, "root", "runc-native", "executor", wrapperTestBundleID)
	if err := os.MkdirAll(bundleDir, 0o755); err != nil {
		t.Fatalf("bundle dir: %v", err)
	}
	return bundleDir
}

// wrapperSpecFixture renders the predicted incumbent OCI spec: the
// containerd default mount list with buildkit's /run removal, plus
// representative unaffected fields including an exact integer (the
// UseNumber fidelity case).
func wrapperSpecFixture() []byte {
	spec := map[string]any{
		"process": map[string]any{
			"cwd":     "/",
			"args":    []any{"/bin/sh"},
			"rlimits": []any{map[string]any{"type": "RLIMIT_NOFILE", "hard": json.Number("1024"), "soft": json.Number("1024")}},
		},
		"root": map[string]any{"path": "rootfs", "readonly": false},
		"mounts": []any{
			map[string]any{"destination": "/proc", "type": "proc", "source": "proc", "options": []any{"nosuid", "noexec", "nodev"}},
			map[string]any{"destination": "/dev", "type": "tmpfs", "source": "tmpfs", "options": []any{"nosuid", "strictatime", "mode=755", "size=65536k"}},
			map[string]any{"destination": "/dev/pts", "type": "devpts", "source": "devpts", "options": []any{"nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620", "gid=5"}},
			map[string]any{"destination": "/dev/shm", "type": "tmpfs", "source": "shm", "options": []any{"nosuid", "noexec", "nodev", "mode=1777", "size=65536k"}},
			map[string]any{"destination": "/dev/mqueue", "type": "mqueue", "source": "mqueue", "options": []any{"nosuid", "noexec", "nodev"}},
			map[string]any{"destination": "/sys", "type": "sysfs", "source": "sysfs", "options": []any{"nosuid", "noexec", "nodev", "ro"}},
		},
	}
	data, err := json.Marshal(spec)
	if err != nil {
		panic(err)
	}
	return data
}

// wrapperDecodeSpec decodes a spec document with the production decode
// semantics (UseNumber) for structural comparison.
func wrapperDecodeSpec(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var doc map[string]any
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("spec decode: %v", err)
	}
	return doc
}

// wrapperRunArgv renders the pinned run invocation for the fixture
// bundle.
func wrapperRunArgv(bundleDir string) []string {
	logPath := filepath.Join(filepath.Dir(bundleDir), wrapperLogFileName)
	return []string{"buildkit-runc", "--log", logPath, "--log-format", "json",
		"run", "--bundle", bundleDir, "--keep", wrapperTestBundleID}
}

// wrapperPassthroughArgv renders one pinned pass-through invocation.
func wrapperPassthroughArgv(kind string) []string {
	logPath := filepath.Join(builderStateRoot, "ops", wrapperTestOpID, "root", "runc-native", "executor", wrapperLogFileName)
	switch kind {
	case "delete":
		return []string{"buildkit-runc", "--log", logPath, "--log-format", "json", "delete", wrapperTestBundleID}
	case "state":
		return []string{"buildkit-runc", "--log", logPath, "--log-format", "json", "state", wrapperTestBundleID}
	case "kill":
		return []string{"buildkit-runc", "--log", logPath, "--log-format", "json", "kill", wrapperTestBundleID, "9"}
	case "exec":
		return []string{"buildkit-runc", "--log", logPath, "--log-format", "json",
			"exec", "--process", "/run/docker-helper-builder/ops/op_x/runc-process1", "--pid-file", "/tmp/runc1/pidfile", wrapperTestBundleID}
	}
	return nil
}

// wrapperRunFixture assembles the full happy-path fixture: real bundle
// dir with the predicted spec, a real prepared tree on the fake
// filesystem, the kernel-derived own context, and the runtime seams.
func wrapperRunFixture(t *testing.T) (string, *fakeDevPrepFS, *wrapperExecRecord) {
	t.Helper()
	bundleDir := withWrapperBundleTree(t)
	if err := os.WriteFile(filepath.Join(bundleDir, "config.json"), wrapperSpecFixture(), 0o644); err != nil {
		t.Fatalf("fixture spec: %v", err)
	}
	fs := wrapperPrepareFixture(t, wrapperTestOpID, 7, false)
	rec := withWrapperRuntimeSeams(t, nil, nil)
	return bundleDir, fs, rec
}

// TestWrapperDispatchMatrix proves the complete dispatch matrix: the
// pinned run and pass-through forms reach their intended classes, and
// every other invocation shape — create in every form, unknown
// commands, malformed globals and arguments — is a typed refusal with
// the real runtime never invoked.
func TestWrapperDispatchMatrix(t *testing.T) {
	bundleDir := withWrapperBundleTree(t)
	if err := os.WriteFile(filepath.Join(bundleDir, "config.json"), wrapperSpecFixture(), 0o644); err != nil {
		t.Fatalf("fixture spec: %v", err)
	}
	fs := wrapperPrepareFixture(t, wrapperTestOpID, 7, false)
	reader := fakeWrapperOwnContext{raw: wrapperOwnContextRaw(7, "\n")}

	t.Run("accepted forms", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			argv []string
		}{
			{name: "run", argv: wrapperRunArgv(bundleDir)},
			{name: "delete", argv: wrapperPassthroughArgv("delete")},
			{name: "state", argv: wrapperPassthroughArgv("state")},
			{name: "kill", argv: wrapperPassthroughArgv("kill")},
			{name: "exec", argv: wrapperPassthroughArgv("exec")},
		} {
			t.Run(tc.name, func(t *testing.T) {
				rec := withWrapperRuntimeSeams(t, nil, nil)
				if err := wrapperMainWithSeams(tc.argv, nil, reader, fs); err != nil {
					t.Fatalf("the pinned %s form must be accepted: %v", tc.name, err)
				}
				if rec.calls != 1 {
					t.Fatalf("exec seam calls = %d, want exactly 1", rec.calls)
				}
				if rec.path != wrapperTestRuntimePath {
					t.Fatalf("exec path = %q, want the fixed runtime path", rec.path)
				}
				if !reflect.DeepEqual(rec.argv, tc.argv) {
					t.Fatalf("forwarded argv altered:\n got %v\nwant %v", rec.argv, tc.argv)
				}
			})
		}
	})

	t.Run("refused forms", func(t *testing.T) {
		logPath := filepath.Join(filepath.Dir(bundleDir), wrapperLogFileName)
		bundlePath := wrapperBundlePath(wrapperTestOpID, wrapperTestBundleID)
		for _, tc := range []struct {
			name string
			argv []string
		}{
			{name: "create with bundle", argv: []string{"buildkit-runc", "--log", logPath, "--log-format", "json", "create", "--bundle", bundlePath, "--keep", wrapperTestBundleID}},
			{name: "bare create", argv: []string{"buildkit-runc", "--log", logPath, "--log-format", "json", "create", wrapperTestBundleID}},
			{name: "unknown command", argv: []string{"buildkit-runc", "--log", logPath, "--log-format", "json", "list"}},
			{name: "no subcommand", argv: []string{"buildkit-runc", "--log", logPath, "--log-format", "json"}},
			{name: "too short", argv: []string{"buildkit-runc", "--log", logPath}},
			{name: "missing log-format", argv: []string{"buildkit-runc", "--log", logPath, "run", "--bundle", bundlePath, "--keep", wrapperTestBundleID}},
			{name: "text log-format", argv: []string{"buildkit-runc", "--log", logPath, "--log-format", "text", "run", "--bundle", bundlePath, "--keep", wrapperTestBundleID}},
			{name: "extra global flag", argv: []string{"buildkit-runc", "--log", logPath, "--log-format", "json", "--root", "/run/runc", "run", "--bundle", bundlePath, "--keep", wrapperTestBundleID}},
			{name: "reordered globals", argv: []string{"buildkit-runc", "--log-format", "json", "--log", logPath, "run", "--bundle", bundlePath, "--keep", wrapperTestBundleID}},
			{name: "noncanonical log path", argv: []string{"buildkit-runc", "--log", "/tmp/runc-log.json", "--log-format", "json", "delete", wrapperTestBundleID}},
			{name: "run without bundle", argv: []string{"buildkit-runc", "--log", logPath, "--log-format", "json", "run", "--keep", wrapperTestBundleID}},
			{name: "run extra flag", argv: []string{"buildkit-runc", "--log", logPath, "--log-format", "json", "run", "--bundle", bundlePath, "--keep", "--no-pivot", wrapperTestBundleID}},
			{name: "run noncanonical bundle", argv: []string{"buildkit-runc", "--log", logPath, "--log-format", "json", "run", "--bundle", "/tmp/elsewhere", "--keep", wrapperTestBundleID}},
			{name: "run foreign log operation", argv: []string{"buildkit-runc", "--log", filepath.Join(builderStateRoot, "ops", "op_fedcba9876543210fedcba9876543210", "root", "runc-native", "executor", wrapperLogFileName), "--log-format", "json", "run", "--bundle", bundlePath, "--keep", wrapperTestBundleID}},
			{name: "run id mismatch", argv: []string{"buildkit-runc", "--log", logPath, "--log-format", "json", "run", "--bundle", bundlePath, "--keep", "m1n2o3p4q5r6s7t8u9v0w1x2a"}},
			{name: "delete extra id", argv: []string{"buildkit-runc", "--log", logPath, "--log-format", "json", "delete", wrapperTestBundleID, wrapperTestBundleID}},
			{name: "delete flag", argv: []string{"buildkit-runc", "--log", logPath, "--log-format", "json", "delete", "--force", wrapperTestBundleID}},
			{name: "state flag", argv: []string{"buildkit-runc", "--log", logPath, "--log-format", "json", "state", "--all", wrapperTestBundleID}},
			{name: "kill wrong signal", argv: []string{"buildkit-runc", "--log", logPath, "--log-format", "json", "kill", wrapperTestBundleID, "15"}},
			{name: "kill missing signal", argv: []string{"buildkit-runc", "--log", logPath, "--log-format", "json", "kill", wrapperTestBundleID}},
			{name: "exec missing pid-file", argv: []string{"buildkit-runc", "--log", logPath, "--log-format", "json", "exec", "--process", "/tmp/p", wrapperTestBundleID}},
			{name: "exec reordered flags", argv: []string{"buildkit-runc", "--log", logPath, "--log-format", "json", "exec", "--pid-file", "/tmp/p", "--process", "/tmp/pr", wrapperTestBundleID}},
			{name: "noncanonical id", argv: []string{"buildkit-runc", "--log", logPath, "--log-format", "json", "delete", "UPPERCASE-ID"}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				rec := withWrapperRuntimeSeams(t, nil, nil)
				err := wrapperMainWithSeams(tc.argv, nil, reader, fs)
				var refuse *wrapperRefuseError
				if !errors.As(err, &refuse) {
					t.Fatalf("want a typed refusal, got %v", err)
				}
				if rec.calls != 0 {
					t.Fatalf("the real runtime must never be invoked on refusal (calls=%d)", rec.calls)
				}
			})
		}
	})

	t.Run("D-2 fail-closed runtime path", func(t *testing.T) {
		origPath, origExec := wrapperRealRuntimePath, wrapperExecRuntime
		wrapperRealRuntimePath = ""
		calls := 0
		wrapperExecRuntime = func(string, []string, []string) error {
			calls++
			return nil
		}
		t.Cleanup(func() { wrapperRealRuntimePath, wrapperExecRuntime = origPath, origExec })
		for _, argv := range [][]string{wrapperRunArgv(bundleDir), wrapperPassthroughArgv("delete")} {
			err := wrapperMainWithSeams(argv, nil, reader, fs)
			var refuse *wrapperRefuseError
			if !errors.As(err, &refuse) || !strings.Contains(err.Error(), "not established") {
				t.Fatalf("the unestablished runtime path must refuse, got %v", err)
			}
			if calls != 0 {
				t.Fatalf("no execution without an established runtime path (calls=%d)", calls)
			}
		}
	})
}

// TestWrapperNoExecutableSearch proves the fixed-path invariant: the
// wrapper runtime resolves NO executable through any search mechanism —
// the only exec surface is wrapperExecRuntime at the fixed D-2 constant,
// and the sources carry no LookPath/os/exec usage at all.
func TestWrapperNoExecutableSearch(t *testing.T) {
	for _, f := range []string{"wrapper_runtime_linux.go", "wrapper_inspection_linux.go", "main.go"} {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		content := string(data)
		if strings.Contains(content, "LookPath") {
			t.Errorf("%s must not perform any executable PATH search", f)
		}
	}
	// The runtime file itself never imports os/exec: the only exec surface
	// is the unix.Exec seam at the fixed D-2 path.
	data, err := os.ReadFile("wrapper_runtime_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "os/exec") {
		t.Error("the wrapper runtime must not import os/exec (no second executable selection path)")
	}
}

// TestWrapperRunRewritesSpec proves the happy run path end to end: the
// prepared tree is inspected through the R4-P0 owner, exactly the /dev
// entry is replaced by the prepared-tree bind at its original position,
// every unaffected field is structurally preserved (including exact
// integers), the original file mode is preserved, and the exec seam
// receives the unchanged argv at the fixed path.
func TestWrapperRunRewritesSpec(t *testing.T) {
	bundleDir, fs, rec := wrapperRunFixture(t)
	reader := fakeWrapperOwnContext{raw: wrapperOwnContextRaw(7, "\n")}
	specPath := filepath.Join(bundleDir, "config.json")
	original, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	origInfo, err := os.Stat(specPath)
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}

	if err := wrapperMainWithSeams(wrapperRunArgv(bundleDir), []string{"PATH=/nonexistent"}, reader, fs); err != nil {
		t.Fatalf("the ready run invocation must be accepted: %v", err)
	}
	rewritten, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatalf("rewritten spec: %v", err)
	}
	// Structural expectation: the original document with exactly the
	// /dev mount replaced in place.
	expected := wrapperDecodeSpec(t, original)
	mounts := expected["mounts"].([]any)
	for i, m := range mounts {
		if m.(map[string]any)["destination"] == "/dev" {
			mounts[i] = map[string]any{
				"destination": "/dev",
				"type":        "bind",
				"source":      devPrepOpDir(wrapperTestOpID),
				"options":     []any{"bind", "nosuid"},
			}
		}
	}
	if got := wrapperDecodeSpec(t, rewritten); !reflect.DeepEqual(got, expected) {
		t.Fatalf("rewritten spec diverges beyond the /dev replacement:\n got %v\nwant %v", got, expected)
	}
	// The commit must be the only write: exactly one rename, no residue.
	if entries, err := os.ReadDir(bundleDir); err != nil {
		t.Fatalf("bundle dir: %v", err)
	} else if len(entries) != 1 || entries[0].Name() != "config.json" {
		t.Fatalf("bundle dir must hold only config.json, got %v", entries)
	}
	info, err := os.Stat(specPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != origInfo.Mode().Perm() {
		t.Fatalf("spec mode = %#o, want the preserved %#o", info.Mode().Perm(), origInfo.Mode().Perm())
	}
	if rec.calls != 1 || rec.path != wrapperTestRuntimePath || !reflect.DeepEqual(rec.argv, wrapperRunArgv(bundleDir)) {
		t.Fatalf("exec handoff mismatch: calls=%d path=%q argv=%v", rec.calls, rec.path, rec.argv)
	}
	if len(rec.env) != 1 || rec.env[0] != "PATH=/nonexistent" {
		t.Fatalf("env must be forwarded verbatim, got %v", rec.env)
	}
}

// TestWrapperSpecRewriteRefusals proves the spec-level fail-closed
// contract: missing, malformed, null, trailing-data, mounts-less,
// zero-/dev, duplicate-/dev (literal and normalized aliases), noncanonical
// /dev spellings, foreign-shaped, already-rewritten, deviant incumbent
// options, missing options, extra mount fields, and malformed-entry specs
// are all refused with the original spec byte-unchanged and no temporary
// residue.
func TestWrapperSpecRewriteRefusals(t *testing.T) {
	base := wrapperSpecFixture()
	mutations := []struct {
		name     string
		mutate   func(t *testing.T, dir string)
		wantText string
	}{
		{name: "missing config.json", wantText: "cannot read the OCI spec", mutate: func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, "config.json")); err != nil {
				t.Fatalf("fixture: %v", err)
			}
		}},
		{name: "malformed json", wantText: "not a JSON object", mutate: func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte("{not json"), 0o644); err != nil {
				t.Fatalf("fixture: %v", err)
			}
		}},
		{name: "null spec", wantText: "no mounts array", mutate: func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte("null"), 0o644); err != nil {
				t.Fatalf("fixture: %v", err)
			}
		}},
		{name: "trailing data", wantText: "trailing data", mutate: func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "config.json"), append(append([]byte(nil), base...), []byte("{}")...), 0o644); err != nil {
				t.Fatalf("fixture: %v", err)
			}
		}},
		{name: "no mounts field", wantText: "no mounts array", mutate: func(t *testing.T, dir string) {
			doc := wrapperDecodeSpec(t, base)
			delete(doc, "mounts")
			writeSpec(t, dir, doc)
		}},
		{name: "mounts not an array", wantText: "no mounts array", mutate: func(t *testing.T, dir string) {
			doc := wrapperDecodeSpec(t, base)
			doc["mounts"] = "not-an-array"
			writeSpec(t, dir, doc)
		}},
		{name: "non-object mount entry", wantText: "non-object mount entry", mutate: func(t *testing.T, dir string) {
			doc := wrapperDecodeSpec(t, base)
			doc["mounts"] = append(doc["mounts"].([]any), "stray")
			writeSpec(t, dir, doc)
		}},
		{name: "zero /dev mounts", wantText: "no /dev mount", mutate: func(t *testing.T, dir string) {
			doc := wrapperDecodeSpec(t, base)
			var kept []any
			for _, m := range doc["mounts"].([]any) {
				if m.(map[string]any)["destination"] != "/dev" {
					kept = append(kept, m)
				}
			}
			doc["mounts"] = kept
			writeSpec(t, dir, doc)
		}},
		{name: "duplicate /dev mounts", wantText: "2 /dev mounts", mutate: func(t *testing.T, dir string) {
			doc := wrapperDecodeSpec(t, base)
			doc["mounts"] = append(doc["mounts"].([]any), map[string]any{"destination": "/dev", "type": "tmpfs", "source": "tmpfs"})
			writeSpec(t, dir, doc)
		}},
		{name: "alias /dev after canonical", wantText: "2 /dev mounts", mutate: func(t *testing.T, dir string) {
			doc := wrapperDecodeSpec(t, base)
			doc["mounts"] = append(doc["mounts"].([]any), map[string]any{
				"destination": "/dev/.", "type": "tmpfs", "source": "tmpfs",
				"options": []any{"nosuid", "strictatime", "mode=755", "size=65536k"},
			})
			writeSpec(t, dir, doc)
		}},
		{name: "parent-alias /dev after canonical", wantText: "2 /dev mounts", mutate: func(t *testing.T, dir string) {
			doc := wrapperDecodeSpec(t, base)
			doc["mounts"] = append(doc["mounts"].([]any), map[string]any{
				"destination": "/dev/../dev", "type": "tmpfs", "source": "tmpfs",
				"options": []any{"nosuid", "strictatime", "mode=755", "size=65536k"},
			})
			writeSpec(t, dir, doc)
		}},
		{name: "noncanonical sole /dev spelling", wantText: "noncanonical destination", mutate: func(t *testing.T, dir string) {
			doc := wrapperDecodeSpec(t, base)
			for _, m := range doc["mounts"].([]any) {
				if m.(map[string]any)["destination"] == "/dev" {
					m.(map[string]any)["destination"] = "/dev/."
				}
			}
			writeSpec(t, dir, doc)
		}},
		{name: "incumbent options reordered", wantText: "pinned provisional incumbent options", mutate: func(t *testing.T, dir string) {
			doc := wrapperDecodeSpec(t, base)
			for _, m := range doc["mounts"].([]any) {
				if m.(map[string]any)["destination"] == "/dev" {
					m.(map[string]any)["options"] = []any{"strictatime", "nosuid", "mode=755", "size=65536k"}
				}
			}
			writeSpec(t, dir, doc)
		}},
		{name: "incumbent option modified", wantText: "pinned provisional incumbent options", mutate: func(t *testing.T, dir string) {
			doc := wrapperDecodeSpec(t, base)
			for _, m := range doc["mounts"].([]any) {
				if m.(map[string]any)["destination"] == "/dev" {
					m.(map[string]any)["options"] = []any{"nosuid", "strictatime", "mode=755", "size=131072k"}
				}
			}
			writeSpec(t, dir, doc)
		}},
		{name: "incumbent option removed", wantText: "pinned provisional incumbent options", mutate: func(t *testing.T, dir string) {
			doc := wrapperDecodeSpec(t, base)
			for _, m := range doc["mounts"].([]any) {
				if m.(map[string]any)["destination"] == "/dev" {
					m.(map[string]any)["options"] = []any{"nosuid", "strictatime", "mode=755"}
				}
			}
			writeSpec(t, dir, doc)
		}},
		{name: "incumbent extra option", wantText: "pinned provisional incumbent options", mutate: func(t *testing.T, dir string) {
			doc := wrapperDecodeSpec(t, base)
			for _, m := range doc["mounts"].([]any) {
				if m.(map[string]any)["destination"] == "/dev" {
					m.(map[string]any)["options"] = []any{"nosuid", "strictatime", "mode=755", "size=65536k", "nodev"}
				}
			}
			writeSpec(t, dir, doc)
		}},
		{name: "incumbent options missing", wantText: "no options array", mutate: func(t *testing.T, dir string) {
			doc := wrapperDecodeSpec(t, base)
			for _, m := range doc["mounts"].([]any) {
				if m.(map[string]any)["destination"] == "/dev" {
					delete(m.(map[string]any), "options")
				}
			}
			writeSpec(t, dir, doc)
		}},
		{name: "incumbent extra mount field", wantText: "unexpected fields", mutate: func(t *testing.T, dir string) {
			doc := wrapperDecodeSpec(t, base)
			for _, m := range doc["mounts"].([]any) {
				if m.(map[string]any)["destination"] == "/dev" {
					m.(map[string]any)["propagation"] = "private"
				}
			}
			writeSpec(t, dir, doc)
		}},
		{name: "foreign /dev shape", wantText: "unexpected shape", mutate: func(t *testing.T, dir string) {
			doc := wrapperDecodeSpec(t, base)
			for _, m := range doc["mounts"].([]any) {
				if m.(map[string]any)["destination"] == "/dev" {
					m.(map[string]any)["type"] = "devtmpfs"
				}
			}
			writeSpec(t, dir, doc)
		}},
		{name: "already rewritten bind type", wantText: "already a bind", mutate: func(t *testing.T, dir string) {
			doc := wrapperDecodeSpec(t, base)
			for _, m := range doc["mounts"].([]any) {
				if m.(map[string]any)["destination"] == "/dev" {
					m.(map[string]any)["type"] = "bind"
					m.(map[string]any)["source"] = devPrepOpDir(wrapperTestOpID)
				}
			}
			writeSpec(t, dir, doc)
		}},
		{name: "already rewritten bind option", wantText: "already a bind", mutate: func(t *testing.T, dir string) {
			doc := wrapperDecodeSpec(t, base)
			for _, m := range doc["mounts"].([]any) {
				if m.(map[string]any)["destination"] == "/dev" {
					m.(map[string]any)["options"] = []any{"rbind", "nosuid"}
				}
			}
			writeSpec(t, dir, doc)
		}},
		{name: "non-string mount option", wantText: "non-string /dev mount option", mutate: func(t *testing.T, dir string) {
			doc := wrapperDecodeSpec(t, base)
			for _, m := range doc["mounts"].([]any) {
				if m.(map[string]any)["destination"] == "/dev" {
					m.(map[string]any)["options"] = []any{"nosuid", 65536}
				}
			}
			writeSpec(t, dir, doc)
		}},
	}
	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			bundleDir, _, rec := wrapperRunFixture(t)
			tc.mutate(t, bundleDir)
			before, err := os.ReadFile(filepath.Join(bundleDir, "config.json"))
			if err != nil {
				before = nil
			}
			err = wrapperRewriteSpecDevBind(bundleDir, wrapperTestOpID)
			if err == nil {
				t.Fatalf("the mutated spec must be refused")
			}
			if !strings.Contains(err.Error(), tc.wantText) {
				t.Fatalf("refusal %q must name %q", err, tc.wantText)
			}
			after, readErr := os.ReadFile(filepath.Join(bundleDir, "config.json"))
			if tc.name == "missing config.json" {
				if !os.IsNotExist(readErr) {
					t.Fatal("a missing spec must stay missing")
				}
			} else if string(after) != string(before) {
				t.Fatal("the original spec must remain byte-unchanged")
			}
			if entries, err := os.ReadDir(bundleDir); err != nil {
				t.Fatalf("bundle dir: %v", err)
			} else if len(entries) > 1 {
				t.Fatalf("temporary residue must not remain: %v", entries)
			}
			if rec.calls != 0 {
				t.Fatal("the real runtime must never be invoked on a spec refusal")
			}
		})
	}
}

func writeSpec(t *testing.T, dir string, doc map[string]any) {
	t.Helper()
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), data, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// TestWrapperCommitSemantics proves the accepted commit contract: a
// pre-commit create failure, write failure, and rename failure all leave
// the original spec byte-unchanged, remove the wrapper-owned temporary
// residue, and never invoke the real runtime; the post-commit exec
// failure leaves the committed rewrite in place with no rollback. The
// create/write failures use deterministic seam injection (valid under
// root, unlike a read-only bundle directory).
func TestWrapperCommitSemantics(t *testing.T) {
	reader := fakeWrapperOwnContext{raw: wrapperOwnContextRaw(7, "\n")}

	t.Run("pre-commit create failure", func(t *testing.T) {
		bundleDir, fs, rec := wrapperRunFixture(t)
		specPath := filepath.Join(bundleDir, "config.json")
		before, err := os.ReadFile(specPath)
		if err != nil {
			t.Fatalf("fixture: %v", err)
		}
		withWrapperCreateTemp(t, func(dir string) (*os.File, error) {
			if dir != bundleDir {
				t.Errorf("create seam reached with dir %q, want the bundle directory", dir)
			}
			return nil, errors.New("injected create failure")
		})
		err = wrapperMainWithSeams(wrapperRunArgv(bundleDir), nil, reader, fs)
		var refuse *wrapperRefuseError
		if !errors.As(err, &refuse) || !strings.Contains(err.Error(), "cannot create the rewritten OCI spec temporary file") {
			t.Fatalf("want the typed create refusal, got %v", err)
		}
		after, err := os.ReadFile(specPath)
		if err != nil || string(after) != string(before) {
			t.Fatal("the original spec must remain byte-unchanged")
		}
		if entries, _ := os.ReadDir(bundleDir); len(entries) != 1 {
			t.Fatalf("no residue may remain, got %v", entries)
		}
		if rec.calls != 0 {
			t.Fatal("the real runtime must never be invoked pre-commit")
		}
	})

	t.Run("pre-commit write failure", func(t *testing.T) {
		bundleDir, fs, rec := wrapperRunFixture(t)
		specPath := filepath.Join(bundleDir, "config.json")
		before, err := os.ReadFile(specPath)
		if err != nil {
			t.Fatalf("fixture: %v", err)
		}
		// Fault injection at the exact write boundary (deterministic
		// under root, unlike a read-only directory): the creation seam
		// returns an already-closed handle, so the production Write call
		// fails with os.ErrClosed while everything else is the real
		// production path.
		closed, err := os.CreateTemp(t.TempDir(), "closed-temp")
		if err != nil {
			t.Fatalf("closed handle: %v", err)
		}
		if err := closed.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
		withWrapperCreateTemp(t, func(dir string) (*os.File, error) {
			if dir != bundleDir {
				t.Errorf("create seam reached with dir %q, want the bundle directory", dir)
			}
			return closed, nil
		})
		err = wrapperMainWithSeams(wrapperRunArgv(bundleDir), nil, reader, fs)
		var refuse *wrapperRefuseError
		if !errors.As(err, &refuse) || !strings.Contains(err.Error(), "cannot write the rewritten OCI spec") {
			t.Fatalf("want the typed write refusal, got %v", err)
		}
		after, err := os.ReadFile(specPath)
		if err != nil || string(after) != string(before) {
			t.Fatal("the original spec must remain byte-unchanged")
		}
		if entries, _ := os.ReadDir(bundleDir); len(entries) != 1 {
			t.Fatalf("no residue may remain, got %v", entries)
		}
		if rec.calls != 0 {
			t.Fatal("the real runtime must never be invoked pre-commit")
		}
	})

	t.Run("pre-commit rename failure", func(t *testing.T) {
		bundleDir, fs, rec := wrapperRunFixture(t)
		specPath := filepath.Join(bundleDir, "config.json")
		before, err := os.ReadFile(specPath)
		if err != nil {
			t.Fatalf("fixture: %v", err)
		}
		// Re-arm the rename seam with an injected failure (the commit
		// point itself; the fixture's seam remains for restoration).
		origRename := wrapperCommitRename
		wrapperCommitRename = func(tempPath, targetPath string) error {
			return errors.New("injected rename failure")
		}
		t.Cleanup(func() { wrapperCommitRename = origRename })
		err = wrapperMainWithSeams(wrapperRunArgv(bundleDir), nil, reader, fs)
		var refuse *wrapperRefuseError
		if !errors.As(err, &refuse) || !strings.Contains(err.Error(), "cannot commit the rewritten OCI spec") {
			t.Fatalf("want the typed commit refusal, got %v", err)
		}
		after, err := os.ReadFile(specPath)
		if err != nil || string(after) != string(before) {
			t.Fatal("the original spec must remain byte-unchanged")
		}
		if entries, _ := os.ReadDir(bundleDir); len(entries) != 1 {
			t.Fatalf("the temporary residue must be removed, got %v", entries)
		}
		if rec.calls != 0 {
			t.Fatal("the real runtime must never be invoked pre-commit")
		}
	})

	t.Run("post-commit exec failure keeps the rewrite", func(t *testing.T) {
		bundleDir, fs, _ := wrapperRunFixture(t)
		specPath := filepath.Join(bundleDir, "config.json")
		original, err := os.ReadFile(specPath)
		if err != nil {
			t.Fatalf("fixture: %v", err)
		}
		rec := withWrapperRuntimeSeams(t, errors.New("injected exec failure"), nil)
		err = wrapperMainWithSeams(wrapperRunArgv(bundleDir), nil, reader, fs)
		var refuse *wrapperRefuseError
		if !errors.As(err, &refuse) || !strings.Contains(err.Error(), "post-commit") {
			t.Fatalf("want the typed post-commit failure, got %v", err)
		}
		rewritten, err := os.ReadFile(specPath)
		if err != nil {
			t.Fatalf("rewritten spec: %v", err)
		}
		expected := wrapperDecodeSpec(t, original)
		mounts := expected["mounts"].([]any)
		for i, m := range mounts {
			if m.(map[string]any)["destination"] == "/dev" {
				mounts[i] = map[string]any{
					"destination": "/dev",
					"type":        "bind",
					"source":      devPrepOpDir(wrapperTestOpID),
					"options":     []any{"bind", "nosuid"},
				}
			}
		}
		if got := wrapperDecodeSpec(t, rewritten); !reflect.DeepEqual(got, expected) {
			t.Fatal("the committed rewrite must remain in place")
		}
		if rec.calls != 1 {
			t.Fatalf("exec seam calls = %d, want exactly 1 (no retry)", rec.calls)
		}
		if entries, _ := os.ReadDir(bundleDir); len(entries) != 1 {
			t.Fatalf("no residue may remain after the commit, got %v", entries)
		}
	})
}

// TestWrapperPreexistingTempPath proves the exclusive-ownership contract
// of the rewritten-spec temporary file: a pre-existing symlink or regular
// file at the wrapper's temporary-path prefix is never followed, adopted,
// written through, or removed by the rewrite — the invocation owns only
// the file it creates, so no foreign path can cause premature spec
// mutation or violate the commit contract.
func TestWrapperPreexistingTempPath(t *testing.T) {
	reader := fakeWrapperOwnContext{raw: wrapperOwnContextRaw(7, "\n")}

	t.Run("temporary-path symlink is never followed", func(t *testing.T) {
		bundleDir, fs, rec := wrapperRunFixture(t)
		specPath := filepath.Join(bundleDir, "config.json")
		decoyPath := filepath.Join(bundleDir, "decoy")
		decoy := []byte("decoy payload\n")
		if err := os.WriteFile(decoyPath, decoy, 0o644); err != nil {
			t.Fatalf("decoy: %v", err)
		}
		// A symlink at the temporary path pointing at a writable foreign
		// file: any adoption would write the spec bytes through it and
		// mutate the decoy before the declared commit point.
		tempLink := filepath.Join(bundleDir, wrapperSpecTempName)
		if err := os.Symlink("decoy", tempLink); err != nil {
			t.Fatalf("symlink: %v", err)
		}
		if err := wrapperMainWithSeams(wrapperRunArgv(bundleDir), nil, reader, fs); err != nil {
			t.Fatalf("the run must commit despite the planted symlink: %v", err)
		}
		if got, err := os.ReadFile(decoyPath); err != nil || string(got) != string(decoy) {
			t.Fatalf("the planted symlink must never be written through (decoy = %q, %v)", got, err)
		}
		info, err := os.Lstat(tempLink)
		if err != nil || info.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("the planted symlink must remain untouched (lstat: %v, mode %v)", err, info)
		}
		if target, err := os.Readlink(tempLink); err != nil || target != "decoy" {
			t.Fatalf("symlink target = %q (%v), want the planted decoy", target, err)
		}
		doc := wrapperDecodeSpec(t, mustReadFile(t, specPath))
		var dev map[string]any
		for _, m := range doc["mounts"].([]any) {
			if m.(map[string]any)["destination"] == "/dev" {
				dev = m.(map[string]any)
			}
		}
		if dev == nil || dev["type"] != "bind" || dev["source"] != devPrepOpDir(wrapperTestOpID) {
			t.Fatalf("the committed spec must carry the prepared-tree bind, got %v", dev)
		}
		entries, err := os.ReadDir(bundleDir)
		if err != nil {
			t.Fatalf("bundle dir: %v", err)
		}
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		sort.Strings(names)
		if !reflect.DeepEqual(names, []string{"config.json", wrapperSpecTempName, "decoy"}) {
			t.Fatalf("bundle dir contents = %v, want only the spec, the decoy, and the planted symlink", names)
		}
		if rec.calls != 1 {
			t.Fatalf("exec seam calls = %d, want exactly 1", rec.calls)
		}
	})

	t.Run("temporary-path regular file is never adopted or deleted", func(t *testing.T) {
		bundleDir, fs, rec := wrapperRunFixture(t)
		specPath := filepath.Join(bundleDir, "config.json")
		before, err := os.ReadFile(specPath)
		if err != nil {
			t.Fatalf("fixture: %v", err)
		}
		// A pre-existing regular file at the temporary-path prefix: an
		// adopted write would mutate it, and a non-ownership-aware
		// cleanup would delete it — both are foreign-file violations.
		plantedPath := filepath.Join(bundleDir, wrapperSpecTempName)
		planted := []byte("planted foreign file\n")
		if err := os.WriteFile(plantedPath, planted, 0o644); err != nil {
			t.Fatalf("planted file: %v", err)
		}
		origRename := wrapperCommitRename
		wrapperCommitRename = func(tempPath, targetPath string) error {
			return errors.New("injected rename failure")
		}
		t.Cleanup(func() { wrapperCommitRename = origRename })
		err = wrapperMainWithSeams(wrapperRunArgv(bundleDir), nil, reader, fs)
		var refuse *wrapperRefuseError
		if !errors.As(err, &refuse) || !strings.Contains(err.Error(), "cannot commit the rewritten OCI spec") {
			t.Fatalf("want the typed commit refusal, got %v", err)
		}
		after, err := os.ReadFile(specPath)
		if err != nil || string(after) != string(before) {
			t.Fatal("the original spec must remain byte-unchanged")
		}
		if got, err := os.ReadFile(plantedPath); err != nil || string(got) != string(planted) {
			t.Fatalf("the planted regular file must survive untouched (got %q, %v)", got, err)
		}
		if rec.calls != 0 {
			t.Fatal("the real runtime must never be invoked pre-commit")
		}
	})
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}

// TestWrapperPassthroughIsolation proves the accepted pass-through
// contract: validated forms reach the real runtime byte-identically
// with ZERO prepared-tree or spec operations; malformed forms are
// refused without any access at all.
func TestWrapperPassthroughIsolation(t *testing.T) {
	bundleDir, fs, _ := wrapperRunFixture(t)
	specPath := filepath.Join(bundleDir, "config.json")
	specBefore, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	reader := fakeWrapperOwnContext{raw: wrapperOwnContextRaw(7, "\n")}

	for _, kind := range []string{"delete", "state", "kill", "exec"} {
		t.Run("accepted "+kind, func(t *testing.T) {
			rec := withWrapperRuntimeSeams(t, nil, nil)
			before := len(fs.log)
			if err := wrapperMainWithSeams(wrapperPassthroughArgv(kind), nil, reader, fs); err != nil {
				t.Fatalf("the pinned %s form must pass through: %v", kind, err)
			}
			if len(fs.log) != before {
				t.Fatalf("pass-through must not touch the prepared tree:\n%s", strings.Join(fs.log[before:], "\n"))
			}
			specAfter, err := os.ReadFile(specPath)
			if err != nil || string(specAfter) != string(specBefore) {
				t.Fatal("pass-through must not touch the OCI spec")
			}
			if !reflect.DeepEqual(rec.argv, wrapperPassthroughArgv(kind)) {
				t.Fatal("the forwarded argv must be byte-identical")
			}
		})
	}

	t.Run("refusals never access anything", func(t *testing.T) {
		logPath := filepath.Join(builderStateRoot, "ops", wrapperTestOpID, "root", "runc-native", "executor", wrapperLogFileName)
		del := wrapperPassthroughArgv("delete")
		mutations := []struct {
			name string
			argv []string
		}{
			{name: "kill signal 15", argv: []string{"buildkit-runc", "--log", logPath, "--log-format", "json", "kill", wrapperTestBundleID, "15"}},
			{name: "delete with flag", argv: append(del[:len(del)-1], "--force", del[len(del)-1])},
			{name: "noncanonical id", argv: []string{"buildkit-runc", "--log", logPath, "--log-format", "json", "state", "shortid"}},
		}
		for _, tc := range mutations {
			t.Run(tc.name, func(t *testing.T) {
				rec := withWrapperRuntimeSeams(t, nil, nil)
				before := len(fs.log)
				err := wrapperMainWithSeams(tc.argv, nil, reader, fs)
				var refuse *wrapperRefuseError
				if !errors.As(err, &refuse) {
					t.Fatalf("want a typed refusal, got %v", err)
				}
				if len(fs.log) != before {
					t.Fatal("a refused pass-through must not touch the prepared tree")
				}
				if rec.calls != 0 {
					t.Fatal("a refused pass-through must not invoke the real runtime")
				}
			})
		}
	})
}

// TestWrapperRunInspectionRefusalGatesExec proves the enforced sequence
// order: a category-inconsistent or absent prepared tree refuses BEFORE
// the spec is touched and the real runtime is never invoked.
func TestWrapperRunInspectionRefusalGatesExec(t *testing.T) {
	for _, tc := range []struct {
		name     string
		category builderCategory
		reader   fakeWrapperOwnContext
		absent   bool
		wantText string
	}{
		// The tree is always prepared for category 7; the "foreign"
		// case derives category 9 from the own context.
		{name: "foreign category", category: 7, reader: fakeWrapperOwnContext{raw: wrapperOwnContextRaw(9, "\n")}, wantText: "category-inconsistent"},
		{name: "absent tree", category: 7, reader: fakeWrapperOwnContext{raw: wrapperOwnContextRaw(7, "\n")}, absent: true, wantText: "is absent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bundleDir := withWrapperBundleTree(t)
			if err := os.WriteFile(filepath.Join(bundleDir, "config.json"), wrapperSpecFixture(), 0o644); err != nil {
				t.Fatalf("fixture: %v", err)
			}
			var fs *fakeDevPrepFS
			if tc.absent {
				withDevPrepSeams(t, true, devPrepTestBuilderUID)
				fs = newFakeDevPrepFS()
			} else {
				fs = wrapperPrepareFixture(t, wrapperTestOpID, tc.category, false)
			}
			rec := withWrapperRuntimeSeams(t, nil, nil)
			err := wrapperMainWithSeams(wrapperRunArgv(bundleDir), nil, tc.reader, fs)
			var refuse *wrapperRefuseError
			if !errors.As(err, &refuse) || !strings.Contains(err.Error(), tc.wantText) {
				t.Fatalf("want the typed inspection refusal (%s), got %v", tc.wantText, err)
			}
			specAfter, err := os.ReadFile(filepath.Join(bundleDir, "config.json"))
			if err != nil || string(specAfter) != string(wrapperSpecFixture()) {
				t.Fatal("the spec must remain untouched when the inspection refuses")
			}
			if rec.calls != 0 {
				t.Fatal("the real runtime must never be invoked past a refused inspection")
			}
		})
	}
}

// TestWrapperExecPathIndependentOfPATH proves the fixed absolute-path
// contract: the exec handoff uses the established runtime path exactly,
// regardless of the environment's PATH contents.
func TestWrapperExecPathIndependentOfPATH(t *testing.T) {
	bundleDir, fs, rec := wrapperRunFixture(t)
	reader := fakeWrapperOwnContext{raw: wrapperOwnContextRaw(7, "\n")}
	env := []string{"PATH=/attacker/controlled/path", "HOME=/x"}
	if err := wrapperMainWithSeams(wrapperRunArgv(bundleDir), env, reader, fs); err != nil {
		t.Fatalf("run: %v", err)
	}
	if rec.path != wrapperTestRuntimePath {
		t.Fatalf("exec path = %q, want the fixed runtime path regardless of PATH", rec.path)
	}
	if !reflect.DeepEqual(rec.env, env) {
		t.Fatalf("env must be forwarded verbatim, got %v", rec.env)
	}
}
