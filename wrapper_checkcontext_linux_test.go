//go:build linux

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// TestWorkloadContextCheckTypedRefusals proves the typed refusal shapes
// of the context-validation transaction against the kernel behavior
// measured through the MNB39a matrix rows: an absent interface is its
// own class, a denied open or write is the missing check_context grant
// (a policy question never rendered as an invalid context), EINVAL is
// the loaded policy's context rejection, short transfers and unlocatable
// read-backs refuse, and a canonical response that differs from the
// composed context is broken — never an allowance.
func TestWorkloadContextCheckTypedRefusals(t *testing.T) {
	label := wrapperTestWorkloadLabel()
	cases := []struct {
		name     string
		openErr  error
		writeErr error
		writeN   int
		readBack string
		kind     string
		wantText string
	}{
		{name: "absent node", openErr: unix.ENOENT, kind: checkContextUnavailable.kind, wantText: "does not exist"},
		{name: "open denied", openErr: unix.EACCES, kind: checkContextPermission.kind, wantText: "grants no context-check permission"},
		{name: "open denied EPERM", openErr: unix.EPERM, kind: checkContextPermission.kind, wantText: "grants no context-check permission"},
		{name: "write denied", writeErr: unix.EACCES, kind: checkContextPermission.kind, wantText: "grants no context-check permission"},
		{name: "policy rejects the context", writeErr: unix.EINVAL, kind: checkContextInvalid.kind, wantText: "rejects the composed workload context"},
		{name: "short write", writeN: 5, kind: checkContextShortIO.kind, wantText: "transferred 5 of"},
		{name: "canonical mismatch", readBack: "system_u:system_r:" + wrapperWorkloadDomain + ":s0", kind: checkContextBroken.kind, wantText: "does not match the composed workload context"},
		{name: "empty read-back", readBack: "", kind: checkContextShortIO.kind, wantText: "the canonical response is empty"},
		{name: "foreign node shape", openErr: unix.ENXIO, kind: checkContextBroken.kind, wantText: "cannot be trusted"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			origOpen := wrapperContextNodeOpen
			origWrite := wrapperContextNodeWrite
			origRead := wrapperContextNodeRead
			origClose := wrapperContextNodeClose
			t.Cleanup(func() {
				wrapperContextNodeOpen = origOpen
				wrapperContextNodeWrite = origWrite
				wrapperContextNodeRead = origRead
				wrapperContextNodeClose = origClose
			})
			wrapperContextNodeOpen = func(path string, flags int, perm uint32) (int, error) {
				if path != selinuxContextValidationNode {
					t.Errorf("the transaction opens %q, got %q", selinuxContextValidationNode, path)
				}
				if flags&unix.O_RDWR != unix.O_RDWR {
					t.Errorf("the transaction opens the node O_RDWR, got flags %#x", flags)
				}
				if tc.openErr != nil {
					return 0, tc.openErr
				}
				return 7, nil
			}
			wrapperContextNodeWrite = func(fd int, buf []byte) (int, error) {
				if fd != 7 || tc.openErr != nil {
					t.Fatal("write must never be reached past a failed open")
				}
				if got := string(buf); got != label+"\x00" {
					t.Errorf("the write must be the NUL-terminated composed context, got %q", got)
				}
				if tc.writeErr != nil {
					return 0, tc.writeErr
				}
				if tc.writeN != 0 {
					return tc.writeN, nil
				}
				return len(buf), nil
			}
			wrapperContextNodeRead = func(fd int, buf []byte) (int, error) {
				if tc.writeErr != nil || tc.writeN != 0 {
					t.Fatal("read must never follow a failed or short write")
				}
				copy(buf, tc.readBack)
				return len(tc.readBack), nil
			}
			err := wrapperWorkloadContextCheck(label)
			var fail *checkContextFailure
			if !errors.As(err, &fail) || fail.kind != tc.kind {
				t.Fatalf("want the typed %q refusal, got %v", tc.kind, err)
			}
			if !strings.Contains(err.Error(), tc.wantText) {
				t.Fatalf("refusal %q must name %q", err, tc.wantText)
			}
		})
	}
}

// TestWorkloadContextCheckExactCanonicalAccept proves the accept path:
// the composed context written NUL-terminated is answered by a canonical
// read-back equal byte for byte, and the check passes.
func TestWorkloadContextCheckExactCanonicalAccept(t *testing.T) {
	label := wrapperTestWorkloadLabel()
	origOpen := wrapperContextNodeOpen
	origWrite := wrapperContextNodeWrite
	origRead := wrapperContextNodeRead
	origClose := wrapperContextNodeClose
	t.Cleanup(func() {
		wrapperContextNodeOpen = origOpen
		wrapperContextNodeWrite = origWrite
		wrapperContextNodeRead = origRead
		wrapperContextNodeClose = origClose
	})
	var wrote []byte
	var readBuf []byte
	var closed int
	wrapperContextNodeOpen = func(path string, flags int, perm uint32) (int, error) { return 3, nil }
	wrapperContextNodeWrite = func(fd int, buf []byte) (int, error) {
		wrote = append(wrote, buf...)
		return len(buf), nil
	}
	wrapperContextNodeRead = func(fd int, buf []byte) (int, error) {
		copy(buf, label)
		readBuf = buf[:len(label)]
		return len(label), nil
	}
	wrapperContextNodeClose = func(fd int) error { closed++; return nil }
	if err := wrapperWorkloadContextCheck(label); err != nil {
		t.Fatalf("the canonical accept must pass: %v", err)
	}
	if string(wrote) != label+"\x00" {
		t.Fatalf("the write must be the NUL-terminated composed context, got %q", wrote)
	}
	if string(readBuf) != label {
		t.Fatalf("the read-back comparison must be byte-exact against %q, got %q", label, readBuf)
	}
	if closed != 1 {
		t.Fatalf("the transaction descriptor must close exactly once, closed %d times", closed)
	}
}

// TestWorkloadContextCheckGateRefusesBeforeCommit proves the context
// validation is a pre-commit refusal in the REAL run pipeline: a refused
// validation aborts the run before any spec rewrite/commit and before
// the real runtime is exec'd, with the original spec untouched.
func TestWorkloadContextCheckGateRefusesBeforeCommit(t *testing.T) {
	bundleDir := withWrapperBundleTree(t)
	if err := os.WriteFile(filepath.Join(bundleDir, "config.json"), wrapperSpecFixture(), 0o644); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	fs := wrapperPrepareFixture(t, wrapperTestOpID, 7, false)
	rec := withWrapperRuntimeSeams(t, nil, nil)
	origCheck := wrapperWorkloadContextCheck
	t.Cleanup(func() { wrapperWorkloadContextCheck = origCheck })
	wrapperWorkloadContextCheck = func(label string) error {
		if label != wrapperTestWorkloadLabel() {
			t.Errorf("the pipeline must validate the composed workload context, got %q", label)
		}
		return &checkContextFailure{
			kind: checkContextInvalid.kind,
			err:  errors.New("the loaded policy rejects the composed workload context"),
		}
	}
	err := wrapperMainWithSeams(wrapperRunArgv(bundleDir), nil, fakeWrapperOwnContext{raw: wrapperOwnContextRaw(7, "\n")}, fs)
	var refuse *wrapperRefuseError
	if !errors.As(err, &refuse) || !strings.Contains(err.Error(), "workload context validation refused") {
		t.Fatalf("want the typed context refusal, got %v", err)
	}
	if !wrappersSpecUntouched(t, bundleDir) {
		t.Fatal("the spec must remain untouched when the context validation refuses")
	}
	if rec.calls != 0 {
		t.Fatal("the real runtime must never be invoked past a refused context validation")
	}
}

// wrappersSpecUntouched compares the bundle's config.json byte for byte
// against the undeformed fixture.
func wrappersSpecUntouched(t *testing.T, bundleDir string) bool {
	t.Helper()
	specAfter, err := os.ReadFile(filepath.Join(bundleDir, "config.json"))
	if err != nil || string(specAfter) != string(wrapperSpecFixture()) {
		return false
	}
	return true
}
