package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestR7P21E3AuditWindowSelftest runs the p21e3 guest harness's own
// boundary battery: the REAL audit-window functions
// (probe_lastbyte_code/audit_boundary_open/audit_window_identity/
// audit_window_drain) against synthetic audit sources. The regression this
// battery pins (R4-P3-P3-R1): the old opener classified its last byte
// through a shell string comparison, under which bash command substitution
// strips trailing newlines — a nonempty newline-terminated audit log took
// the empty-log branch and the window opened at offset 0 over the
// HISTORICAL records. Required behavior: a nonempty newline-terminated
// source starts the window at its exact current size (history excluded),
// a genuinely empty source starts at 0, a mid-record boundary is refused,
// and a rotated/replaced source is fail-closed at the close-time identity
// check.
func TestR7P21E3AuditWindowSelftest(t *testing.T) {
	dir := t.TempDir()
	out, err := exec.Command("bash", "scripts/release-2.4-r7-p21e3-guest.sh",
		"--audit-window-selftest", dir).CombinedOutput()
	if err != nil {
		t.Fatalf("audit-window selftest failed to run: %v\n%s", err, out)
	}

	results := func(name string) map[string]string {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(dir, "results", name))
		if err != nil {
			t.Fatalf("selftest result %s missing: %v\n%s", name, err, out)
		}
		m := make(map[string]string)
		for _, l := range strings.Split(string(raw), "\n") {
			if k, v, ok := strings.Cut(l, "="); ok && k != "" {
				m[k] = v
			}
		}
		return m
	}

	// 1. History-green: the boundary sits at the exact end of the three
	//    historical records (size==start, numeric lastbyte 10), and the
	//    drained window holds EXACTLY the two appended current-window
	//    records — history excluded, new records exactly once.
	ownLog := filepath.Join(dir, "audit-history.log")
	raw, err := os.ReadFile(ownLog)
	if err != nil {
		t.Fatal(err)
	}
	b := results("history-green.boundary")
	if b["lastbyte"] != "10" {
		t.Errorf("history-green: lastbyte = %q, want the numeric newline code 10", b["lastbyte"])
	}
	if b["start"] != b["size"] || b["start"] == "" {
		t.Errorf("history-green: start (%q) must equal size (%q): the whole newline-terminated log is history", b["start"], b["size"])
	}
	thirdNewline := 0
	for i, c := range raw {
		if c == '\n' {
			thirdNewline++
			if thirdNewline == 3 {
				thirdNewline = i + 1
				break
			}
		}
	}
	if got := b["start"]; fmtInt(thirdNewline) != got {
		t.Errorf("history-green: start = %q, want %d (the byte offset after the 3rd complete record)", got, thirdNewline)
	}
	windowRaw, err := os.ReadFile(filepath.Join(dir, "results", "history-green.window"))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(windowRaw),
		"type=SYNTH msg=audit(1000000.000:4): synthetic record 4\n"+
			"type=SYNTH msg=audit(1000000.000:5): synthetic record 5\n"; got != want {
		t.Errorf("history-green window must hold exactly the 2 new records: got %q", got)
	}
	if bytes.Contains(windowRaw, []byte("synthetic record 1")) ||
		bytes.Contains(windowRaw, []byte("synthetic record 2")) ||
		bytes.Contains(windowRaw, []byte("synthetic record 3")) {
		t.Error("history-green window must exclude ALL historical records")
	}
	if d := results("history-green.drain"); d["torn"] != "complete" {
		t.Errorf("history-green: torn = %q, want complete (every current-window record was complete)", d["torn"])
	}

	// 2. Torn-trailing: a final incomplete record is dropped; the complete
	//    records of the same window are kept exactly once.
	if d := results("torn-trailing.drain"); d["torn"] != "dropped" {
		t.Errorf("torn-trailing: torn = %q, want dropped", d["torn"])
	}
	windowRaw, err = os.ReadFile(filepath.Join(dir, "results", "torn-trailing.window"))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(windowRaw),
		"type=SYNTH msg=audit(1000000.000:8): synthetic record 8\n"+
			"type=SYNTH msg=audit(1000000.000:9): synthetic record 9\n"; got != want {
		t.Errorf("torn-trailing window must hold exactly the 2 complete records: got %q", got)
	}
	if bytes.Contains(windowRaw, []byte("torn")) {
		t.Error("torn-trailing window must not carry any torn bytes")
	}

	// 3. Empty: a genuinely zero-length source starts the window at 0.
	if b := results("empty.boundary"); b["start"] != "0" || b["lastbyte"] != "none" {
		t.Errorf("empty: boundary = %v, want start=0 lastbyte=none", b)
	}

	// 4. Partial-trailing: the boundary is refused, never approximated.
	if b := results("partial-trailing.boundary"); b["boundary"] != "refused" {
		t.Errorf("partial-trailing: boundary = %q, want refused", b["boundary"])
	}
	if b := results("partial-trailing.boundary"); b["size-lastbyte"] == "" || strings.HasPrefix(b["size-lastbyte"], "10,") {
		t.Errorf("partial-trailing: recorded lastbyte %q must be present and not the newline code", b["size-lastbyte"])
	}

	// 5. Rotated: a replaced source must decide broken at the identity
	//    check (fail-closed, never attributed to the new inode).
	id, err := os.ReadFile(filepath.Join(dir, "results", "rotated.identity"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(id), "broken(") {
		t.Errorf("rotated: identity = %q, want broken(...)", string(id))
	}
}

// TestR7P21E3GuestHarnessContract pins the corrective contracts in the
// guest harness itself: the numeric boundary probe (and the ABSENCE of the
// newline string comparison it replaces), the pre-POST sampler
// confirmation, the bounded builder-manager journal, and the hard
// pre-build identity/label gates.
func TestR7P21E3GuestHarnessContract(t *testing.T) {
	raw, err := os.ReadFile("scripts/release-2.4-r7-p21e3-guest.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(raw)
	for _, want := range []string{
		"probe_lastbyte_code",
		"audit_boundary_open",
		"audit_window_identity",
		"--audit-window-selftest",
		"SAMPLER-START",
		"p21e3-builder-journal.log",
		"R7-P21E3-BLOCKED-REASON=",
		"LABEL-GATE: FAIL",
		"NOT-OBSERVED-BY-SAMPLER",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("the p21e3 guest harness must carry %q", want)
		}
	}
	// The boundary bug this round corrects must not survive in any form:
	// no last-byte comparison against a (potentially newline-stripped)
	// shell string.
	if strings.Contains(script, `= "$(printf '\n')"`) {
		t.Error("the p21e3 guest harness must decide the boundary by numeric byte inspection, not a newline string comparison")
	}
	// The identity gate must carry the explicit reason vocabulary.
	if !strings.Contains(script, "GATE_REASON=identity") || !strings.Contains(script, "GATE_REASON=label-obl4") {
		t.Error("the p21e3 guest harness must record explicit identity and label (OBL-4) gate reasons")
	}
}

func fmtInt(n int) string {
	b := []byte{}
	if n == 0 {
		return "0"
	}
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
