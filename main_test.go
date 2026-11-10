package main

// main_test.go proves the single production entry dispatch (the accepted
// R4-P3-P0 D-2 wiring): an execution whose argv[0] basename is the payload
// name runs the wrapper role (refusal = stderr + nonzero exit; the real
// runtime is reached only through the wrapper's own execve handoff), and
// every other invocation keeps the existing CLI routing unchanged. The
// wrapper entry is a seam; the CLI path runs the real command tree.

import (
	"bytes"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// wrapperEntryCall records one wrapper-role entry invocation.
type wrapperEntryCall struct {
	argv []string
	env  []string
}

// withWrapperEntry swaps the wrapper-role entry seam. Package-global;
// restored via t.Cleanup; never used with t.Parallel.
func withWrapperEntry(t *testing.T, fn func([]string, []string) error) *[]wrapperEntryCall {
	t.Helper()
	orig := wrapperEntry
	calls := &[]wrapperEntryCall{}
	wrapperEntry = func(argv []string, env []string) error {
		*calls = append(*calls, wrapperEntryCall{argv: append([]string(nil), argv...), env: env})
		return fn(argv, env)
	}
	t.Cleanup(func() { wrapperEntry = orig })
	return calls
}

func wrapperRoleArgv(dir string) []string {
	return []string{filepath.Join(dir, wrapperPayloadName),
		"--log", filepath.Join(dir, "runc-log.json"), "--log-format", "json",
		"delete", "m1n2o3p4q5r6s7t8u9v0w1x2a"}
}

func TestMainDispatchWrapperRole(t *testing.T) {
	dir := t.TempDir()
	argv := wrapperRoleArgv(dir)
	env := []string{"PATH=/irrelevant", "HOME=/x"}

	t.Run("basename routes to the wrapper entry", func(t *testing.T) {
		calls := withWrapperEntry(t, func([]string, []string) error { return nil })
		var out, errBuf bytes.Buffer
		if code := runMain(argv, env, &out, &errBuf); code != 0 {
			t.Fatalf("exit code = %d, want 0", code)
		}
		if len(*calls) != 1 {
			t.Fatalf("wrapper entry calls = %d, want exactly 1", len(*calls))
		}
		if got := (*calls)[0]; !reflect.DeepEqual(got.argv, argv) {
			t.Fatalf("argv altered:\n got %v\nwant %v", got.argv, argv)
		}
		if !reflect.DeepEqual((*calls)[0].env, env) {
			t.Fatalf("env altered: got %v, want %v", (*calls)[0].env, env)
		}
		if out.Len() != 0 || errBuf.Len() != 0 {
			t.Fatalf("the wrapper role must not write to the CLI streams (out=%q err=%q)", out.String(), errBuf.String())
		}
	})

	t.Run("dispatch key is the exact basename", func(t *testing.T) {
		for _, name := range []string{"not-buildkit-runc", "buildkit-runc2", "runc", "docker-helper"} {
			t.Run(name, func(t *testing.T) {
				calls := withWrapperEntry(t, func([]string, []string) error { return nil })
				var out, errBuf bytes.Buffer
				argv := []string{filepath.Join(dir, name), "version"}
				if code := runMain(argv, env, &out, &errBuf); code != 0 {
					t.Fatalf("%s: exit code = %d, want 0 (the CLI version command)", name, code)
				}
				if len(*calls) != 0 {
					t.Fatalf("%s must not route to the wrapper role", name)
				}
				if !strings.Contains(out.String(), version) {
					t.Fatalf("%s must reach the CLI (version output), got %q", name, out.String())
				}
				if errBuf.Len() != 0 {
					t.Fatalf("%s: unexpected stderr %q", name, errBuf.String())
				}
			})
		}
	})

	t.Run("refusal prints to stderr and exits nonzero", func(t *testing.T) {
		calls := withWrapperEntry(t, func([]string, []string) error {
			return errors.New("the command \"create\" is not a supported wrapper invocation")
		})
		var out, errBuf bytes.Buffer
		code := runMain(argv, env, &out, &errBuf)
		if code != 1 {
			t.Fatalf("exit code = %d, want 1", code)
		}
		if len(*calls) != 1 {
			t.Fatalf("the refused wrapper invocation must reach the wrapper entry (calls=%d)", len(*calls))
		}
		if want := "error: the command \"create\" is not a supported wrapper invocation\n"; errBuf.String() != want {
			t.Fatalf("stderr = %q, want %q", errBuf.String(), want)
		}
		if out.Len() != 0 {
			t.Fatalf("refusals must not write to stdout, got %q", out.String())
		}
	})

	t.Run("empty argv routes to the CLI without touching the wrapper", func(t *testing.T) {
		calls := withWrapperEntry(t, func([]string, []string) error { return nil })
		var out, errBuf bytes.Buffer
		runMain(nil, env, &out, &errBuf)
		if len(*calls) != 0 {
			t.Fatal("an empty argv must never route to the wrapper role")
		}
	})
}

func TestMainDispatchCLIUnchanged(t *testing.T) {
	calls := withWrapperEntry(t, func([]string, []string) error { return nil })
	var out, errBuf bytes.Buffer
	code := runMain([]string{"/usr/bin/docker-helper", "definitely-not-a-command"}, nil, &out, &errBuf)
	if code == 0 {
		t.Fatal("an unknown command must fail")
	}
	if !strings.Contains(errBuf.String(), "error: unknown command") {
		t.Fatalf("the CLI routing contract must be unchanged (stderr=%q)", errBuf.String())
	}
	if len(*calls) != 0 {
		t.Fatal("CLI invocations must never reach the wrapper role")
	}
}

func TestWrapperRealRuntimePathEstablished(t *testing.T) {
	// D-2 (R4-P3-P0 §1.2): the fixed, product-owned absolute path of the
	// relocated pinned upstream runc. Established at the integration
	// wiring; the exact value is the packaging contract (the .fc row and
	// the package manifests pin the same path).
	const want = "/usr/libexec/docker-helper/buildkit/runtime/buildkit-runc"
	if wrapperRealRuntimePath != want {
		t.Fatalf("wrapperRealRuntimePath = %q, want the fixed D-2 path %q", wrapperRealRuntimePath, want)
	}
	if !filepath.IsAbs(wrapperRealRuntimePath) {
		t.Fatal("the real-runtime path must be absolute (never PATH-resolved)")
	}
	// The handoff can never resolve back to the wrapper: the relocated
	// runtime keeps its upstream basename but lives in its own fixed
	// directory — a different inode from the wrapper payload path (the
	// packaging tests prove the byte provenance of each).
	if wrapperRealRuntimePath == "/usr/libexec/docker-helper/buildkit/buildkit-runc" {
		t.Fatal("the real-runtime path must not be the wrapper payload path")
	}
	if filepath.Dir(wrapperRealRuntimePath) != "/usr/libexec/docker-helper/buildkit/runtime" {
		t.Fatal("the real runtime must live in the dedicated runtime subdirectory")
	}
}
