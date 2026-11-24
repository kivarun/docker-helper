//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWrapperFifoConstraintVerdict proves the fail-closed constraint
// classification over one trusted seinfo --constrain output: an absent or
// foreign constraint statement is a refusal naming the remediation, and
// only the exact canonical loaded-policy statement allows the run. The
// trusted-query failure half of the gate (an absent tool or a tooling
// error is never an allowance) is exercised through the resolution test
// below against the same production check.
func TestWrapperFifoConstraintVerdict(t *testing.T) {
	cases := []struct {
		name string
		out  []byte
		want string
	}{
		{name: "absent statement", out: []byte("Constraints: 23\n"), want: "does not carry the shipped"},
		{
			name: "foreign read-only confinement only",
			out:  []byte("Constraints: 23\n   mlsconstrain fifo_file { read } (h1 dom h2);\n"),
			want: "does not carry the shipped",
		},
		{name: "indented canonical statement", out: []byte("Constraints: 24\n   " + wrapperFifoConstraintStatement + "\n"), want: ""},
		{name: "exact statement, no wrapper decoration", out: []byte(wrapperFifoConstraintStatement + "\n"), want: ""},
		{name: "truncated statement", out: []byte("   mlsconstrain fifo_file { read write } (h1 dom h2)\n"), want: "does not carry the shipped"},
		{name: "empty output", out: nil, want: "does not carry the shipped"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := wrapperFifoConstraintVerdict(tc.out)
			if tc.want == "" && err != nil {
				t.Fatalf("want allowance, got %v", err)
			}
			if tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("want refusal naming %q, got %v", tc.want, err)
			}
			if err != nil && !strings.Contains(err.Error(), wrapperFifoConstraintRemediation) {
				t.Fatalf("the refusal must name the exact operator repair, got %v", err)
			}
		})
	}
}

// TestWrapperFifoConstraintResolutionThroughCandidates proves the
// production gate resolves seinfo through the shared candidate order
// exactly like the role check: the first answering candidate's output
// decides the verdict, and a refused pipeline shape (absent tool) is a
// typed trusted-query refusal, never an allowance.
func TestWrapperFifoConstraintResolutionThroughCandidates(t *testing.T) {
	binDir := t.TempDir()
	writeFake := func(t *testing.T, path string, lines []string) {
		t.Helper()
		script := "#!/bin/sh\n"
		for _, line := range lines {
			script += "echo '" + line + "'\n"
		}
		if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	absoluteFake := filepath.Join(t.TempDir(), "fake-absolute-seinfo")
	writeFake(t, absoluteFake, []string{
		"Constraints: 24",
		"   " + wrapperFifoConstraintStatement,
	})

	origCandidates := wrapperSeinfoCandidates
	t.Cleanup(func() { wrapperSeinfoCandidates = origCandidates })
	t.Setenv("PATH", "/nonexistent-restricted-path")

	// The absolute fallback resolves and its exact-statement output
	// allows the run.
	wrapperSeinfoCandidates = []string{"seinfo", absoluteFake}
	if err := wrapperFifoConstraintCheck(); err != nil {
		t.Fatalf("the absolute fallback must allow the exact statement: %v", err)
	}

	// A PATH fake that answers with a foreign policy shape refuses closed:
	// the answering (first-success) candidate decides the verdict, not the
	// resolution order.
	pathFake := binDir + "/fake-path-seinfo"
	writeFake(t, pathFake, []string{"Constraints: 23", "   mlsconstrain fifo_file { read } (h1 dom h2);"})
	wrapperSeinfoCandidates = []string{"fake-path-seinfo", absoluteFake}
	t.Setenv("PATH", binDir)
	err := wrapperFifoConstraintCheck()
	if err == nil || !strings.Contains(err.Error(), "does not carry the shipped") {
		t.Fatalf("the answering foreign constraint must refuse, got %v", err)
	}

	// An absent tool everywhere is a trusted-query refusal (fail closed),
	// not an allowance.
	wrapperSeinfoCandidates = []string{"absent-fake-seinfo"}
	err = wrapperFifoConstraintCheck()
	if err == nil || !strings.Contains(err.Error(), "cannot be trusted") {
		t.Fatalf("an unresolvable query tool must refuse as untrusted, got %v", err)
	}
}
