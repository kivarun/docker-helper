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

// TestR7P21E3GuestSecretHygiene pins the secret-output corrections: the
// generated admin token never reaches the guest console or the evidence
// set, the Session bearer response never lands in the evidence set (the
// R1 round published it as session-response.json), and the image prewarm
// runs through the intended session-token mechanism with an explicitly
// recorded success/failure result.
func TestR7P21E3GuestSecretHygiene(t *testing.T) {
	raw, err := os.ReadFile("scripts/release-2.4-r7-p21e3-guest.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(raw)
	if strings.Contains(script, `RESP="$EVIDENCE_DIR/session-response.json"`) {
		t.Error("the Session bearer response must never be written into the evidence set")
	}
	if !strings.Contains(script, `RESP="$STATE_DIR/session-response.json"`) ||
		!strings.Contains(script, `rm -f "$RESP"`) {
		t.Error("the Session bearer response must live outside the evidence set and be removed after the token is extracted")
	}
	if !strings.Contains(script, "[REDACTED-TOKEN]") {
		t.Error("redaction of any dht_ token shape must remain in the harness before any captured output is recorded")
	}
	if !strings.Contains(script, `DOCKER_HELPER_SESSION_TOKEN="$TOKEN" docker-helper pull`) {
		t.Error("the image prewarm must run through the intended DOCKER_HELPER_SESSION_TOKEN mechanism")
	}
	if !strings.Contains(script, `prewarm=%s`) {
		t.Error("the harness must record the prewarm result explicitly, never treating a swallowed error as a warmup")
	}
	// The R4-P3-P4-R1 secret corrections: raw pull diagnostics live
	// OUTSIDE the published evidence tree and only a token-verified
	// sanitized copy is published; the Session failure path reports a
	// token-free status and never reads the removed response body.
	for _, want := range []string{
		`>"$PULL_RAW" 2>&1`,
		`"$PULL_RAW" >"$EVIDENCE_DIR/pull.log"`,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("the raw pull diagnostics must be captured outside the evidence tree and sanitized into it (%q)", want)
		}
	}
	if !strings.Contains(script, `PULL_RAW="$STATE_DIR/pull.raw.log"`) {
		t.Error("the raw pull diagnostics must be captured in the unpublished state dir")
	}
	for _, want := range []string{
		`grep -aqF -- "$TOKEN" "$EVIDENCE_DIR/pull.log"`,
		`grep -aqF -- "$ADMIN_TOKEN" "$EVIDENCE_DIR/pull.log"`,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("the sanitized pull log must be verified absent both live tokens (%q)", want)
		}
	}
	sidIdx := strings.Index(script, `rm -f "$RESP"`)
	failIdx := strings.Index(script, "session create failed (HTTP")
	if sidIdx < 0 || failIdx < 0 || sidIdx > failIdx {
		t.Error("the Session failure path must report a token-free status after the response is removed, without reading it afterward")
	}
	// The C2 corrective: the response BODY is never printed on any path —
	// no redacting sed over $RESP survives, and the refusal record carries
	// only the HTTP status and a token-free classification. The raw
	// response lives exclusively in the unpublished state dir.
	if strings.Contains(script, `sed -e 's/dht_[A-Za-z0-9]*/[REDACTED-TOKEN]/g' "$RESP"`) {
		t.Error("the Session failure path must not print the response body in any redacted form")
	}
	for _, want := range []string{
		"session-create refused: http_status=",
		"REFUSAL_CLASS=request-refused",
		"REFUSAL_CLASS=server-error",
		"REFUSAL_CLASS=transport-unreachable",
		"session-refusal.log",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("the Session refusal record must carry the token-free classification (%q)", want)
		}
	}
}

// TestR7P21E3PolicySemanticsSelftest runs the p21e3 guest harness's REAL
// fail-closed sesearch classifier (classify_sesearch_query, the exact
// function the section-3 gate calls) over the eight deterministic
// scenarios. The invariant (R4-P3-P4-R1-C1): only a successful,
// well-formed response decides PRESERVED or the exact three-permission
// shape; any nonzero exit — including timeout 124, which is NEVER an
// authoritative empty result — or malformed output is UNTRUSTED and must
// BLOCK before POST /build.
func TestR7P21E3PolicySemanticsSelftest(t *testing.T) {
	dir := t.TempDir()
	out, err := exec.Command("bash", "scripts/release-2.4-r7-p21e3-guest.sh",
		"--policy-semantics-selftest", dir).CombinedOutput()
	if err != nil {
		t.Fatalf("policy-semantics selftest failed to run: %v\n%s", err, out)
	}
	verdict := func(name string) string {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(dir, "results", name))
		if err != nil {
			t.Fatalf("selftest result %s missing: %v\n%s", name, err, out)
		}
		return strings.TrimSuffix(string(raw), "\n")
	}
	for _, tc := range []struct{ name, want string }{
		// The R2 live conditional grammar: a conditional suffix is
		// metadata, never a permission token.
		{"live-conditional-active.classify",
			"trusted:perms=map|cond-active=domain_can_mmap_files=True|cond-inactive=none"},
		{"live-conditional-inactive.classify",
			"trusted:perms=|cond-active=none|cond-inactive=example_boolean=False"},
		// An unknown conditional form is neither an effective grant nor an
		// authoritative absence: UNTRUSTED (BLOCKED).
		{"conditional-unknown-form.classify",
			"untrusted:malformed-line(allow docker_helper_rootlesskit_t bin_t:file execute; [ example_boolean ]:MAYBE)"},
		// The accepted exact three-permission check (conditional-free).
		{"valid-three.classify",
			"trusted:perms=net_admin sys_admin sys_ptrace|cond-active=none|cond-inactive=none"},
		// A trusted response with the required net_admin member missing is
		// a DECIDED wrong shape (not untrusted): the gate still blocks, but
		// with the shape reason, not the query-untrusted reason.
		{"missing-netadmin.classify",
			"trusted:perms=sys_admin sys_ptrace|cond-active=none|cond-inactive=none"},
		{"quarantine-present.classify", "trusted:perms=execute|cond-active=none|cond-inactive=none"},
		{"quarantine-absent.classify", "trusted:perms=|cond-active=none|cond-inactive=none"},
		{"quarantine-read-only.classify", "trusted:perms=getattr read|cond-active=none|cond-inactive=none"},
		{"exec-error.classify", "untrusted:nonzero-exit-1"},
		{"timeout.classify", "untrusted:nonzero-exit-124"},
		{"malformed.classify", "untrusted:malformed-line(error: cannot open /sys/fs/selinux/policy: No such file)"},
	} {
		if got := verdict(tc.name); got != tc.want {
			t.Errorf("%s verdict = %q, want %q", tc.name, got, tc.want)
		}
	}
	// The extraction-stage classifier: the four required outcomes (every
	// failure class blocks).
	for _, tc := range []struct{ name, want string }{
		{"extract-member-found.classify", "member-found"},
		{"extract-member-missing.classify", "blocked:member-missing"},
		{"extract-cpio-failed.classify", "blocked:cpio-extraction-failed(rc=2)"},
		{"extract-conversion-failed.classify", "blocked:rpm-conversion-failed(rc=1)"},
		{"extract-conversion-rc1-member-found.classify", "member-found"},
		{"extract-conversion-rc1-cpio-failed.classify", "blocked:cpio-extraction-failed(rc=2)"},
		{"extract-conversion-timeout.classify", "blocked:rpm-conversion-failed(rc=124)"},
	} {
		if got := verdict(tc.name); got != tc.want {
			t.Errorf("%s verdict = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestR7P21E3PolicySemanticsGate pins the section-3 gate's decision wiring
// around the classifier: the exact three-permission acceptance, the shape
// and untrusted refusal branches, and the quarantine decision (execute
// token in a trusted set VIOLATES; genuinely absent PRESERVES; untrusted
// BLOCKS) — each must reach the same BLOCKED gate, and the gate fires
// before the build with an explicit reason.
func TestR7P21E3PolicySemanticsGate(t *testing.T) {
	raw, err := os.ReadFile("scripts/release-2.4-r7-p21e3-guest.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(raw)
	for _, want := range []string{
		"p21e3-policy-semantics.log",
		"rpm2cpio",
		"rpm==installed: MATCH",
		"classify_sesearch_query \"$SLIRP_RC\" \"$SLIRP_CAPS\"",
		"classify_sesearch_query \"$QUAR_RC\" \"$QUAR_CAPS\"",
		"trusted:perms=net_admin sys_admin sys_ptrace|cond-active=none|cond-inactive=none",
		"QUERY-UNTRUSTED",
		"rootlesskit bin_t quarantine: PRESERVED",
		"rootlesskit bin_t quarantine: VIOLATED",
		"GATE_REASON=policy-semantics",
		"POLICY-GATE: FAIL",
		// The staged extraction gate: separate rpm2cpio/cpio exit statuses
		// and a stage-classified outcome (no --quiet cpio flag; no
		// stderr-swallowing on the extraction pipeline).
		"classify_pp_extraction",
		"extraction verdict: $EXTRACT_VERDICT",
		"for stage in rpm2cpio cpio",
		"$stage stderr (tail; no tokens)",
		`2>"$work/rpm2cpio.err"`,
		`2>"$work/cpio.err"`,
		`cpio -id --no-absolute-filenames`,
		`/usr/bin/docker-helper usr/bin/docker-helper ./usr/bin/docker-helper`,
		`/usr/share/selinux/docker_helper.pp usr/share/selinux/docker_helper.pp`,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("the p21e3 guest harness must gate the loaded-policy semantics %q", want)
		}
	}
	if strings.Contains(script, "cpio -id --quiet") {
		t.Error("the extraction must not depend on the guest cpio implementation accepting --quiet")
	}
	if strings.Contains(script, `'usr/share/selinux/docker_helper.pp' 2>/dev/null)`) {
		t.Error("the extraction gate must not swallow its pipeline stderr")
	}
}

// TestR7P21E3PPExtractSelftest runs the harness's own
// --pp-extract-selftest with the cpio-stage fixtures: the member must
// extract and hash to the fixture content's digest, a member-less payload
// must extract nothing (blocked), and a truncated archive must not yield
// the member (blocked). With rpm2cpio and a real RPM provided
// (R7_P21E3_TEST_RPM), the full gate path runs on the actual artifact.
func TestR7P21E3PPExtractSelftest(t *testing.T) {
	if _, err := exec.LookPath("cpio"); err != nil && os.Getenv("R7_P21E3_TEST_RPM") == "" {
		t.Skip("cpio is required for the archive fixtures")
	}
	dir := t.TempDir()
	out, err := exec.Command("bash", "scripts/release-2.4-r7-p21e3-guest.sh",
		"--pp-extract-selftest", dir).CombinedOutput()
	if err != nil {
		t.Fatalf("pp-extract selftest failed to run: %v\n%s", err, out)
	}
	shaRaw, err := os.ReadFile(filepath.Join(dir, "results", "fixture.member-found.sha256"))
	if err != nil {
		t.Fatalf("fixture result missing: %v\n%s", err, out)
	}
	got := strings.Fields(strings.TrimSpace(string(shaRaw)))
	if len(got) != 2 || got[0] != "8bc5b882c687041c292cc12457db6f016a9489947215c420306f4a6152a65c4d" {
		t.Fatalf("fixture member digest = %q, want the fixture content sha256 8bc5b882…", strings.TrimSpace(string(shaRaw)))
	}
	content, err := os.ReadFile(filepath.Join(dir, "results", "fixture.member.pp"))
	if err != nil || !strings.HasPrefix(string(content), "fixture-module-content") {
		t.Errorf("the extracted fixture member must be the source bytes: %v %q", err, content)
	}
	missRaw, err := os.ReadFile(filepath.Join(dir, "results", "fixture.member-missing.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(missRaw), "confirmed absent") {
		t.Errorf("the member-less fixture must confirm the member absent (and stay blocked), got %q", missRaw)
	}
	toolsRaw, err := os.ReadFile(filepath.Join(dir, "results", "tools.ident"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(toolsRaw), "rpm2cpio=") || !strings.Contains(string(toolsRaw), "cpio=") {
		t.Errorf("the toolchain identity must be recorded explicitly: %q", toolsRaw)
	}
	if rpm := os.Getenv("R7_P21E3_TEST_RPM"); rpm != "" {
		dir2 := t.TempDir()
		out2, err := exec.Command("bash", "scripts/release-2.4-r7-p21e3-guest.sh",
			"--pp-extract-selftest", dir2, rpm).CombinedOutput()
		if err != nil {
			stages, _ := os.ReadFile(filepath.Join(dir2, "results", "extract.stages"))
			t.Fatalf("pp-extract selftest (real RPM) failed: %v\n%s\n%s", err, out2, stages)
		}
		digestRaw, err := os.ReadFile(filepath.Join(dir2, "results", "member.pp.sha256"))
		if err != nil {
			t.Fatalf("real-RPM policy member digest missing: %v\n%s", err, out2)
		}
		binaryDigest, err := os.ReadFile(filepath.Join(dir2, "results", "member.binary.sha256"))
		if err != nil || len(strings.Fields(string(binaryDigest))) != 2 {
			t.Fatalf("real-RPM binary member digest missing or malformed: %v %q", err, binaryDigest)
		}
		t.Logf("real-RPM full-gate binary digest: %s", binaryDigest)
		t.Logf("real-RPM full-gate member digest: %s", digestRaw)
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

// TestR7P21E3InspectionDiagnosticsContract pins the R4-P3-P5 diagnostic
// machinery: the corrected strace filter (newfstatat/statx — the
// lstat-family coverage whose absence left R2-C1's wrapper rung syscall
// unobserved), the wrapper-credential capture in the sampler, the
// prepared-tree event watcher, the terminal DAC-state captures, and the
// dontaudit toggle with its guaranteed-and-verified restoration on every
// path.
func TestR7P21E3InspectionDiagnosticsContract(t *testing.T) {
	raw, err := os.ReadFile("scripts/release-2.4-r7-p21e3-guest.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(raw)
	for _, want := range []string{
		// Lstat-family syscall coverage in the buildkitd trace.
		"read,newfstatat,statx,statfs,getxattr",
		// The wrapper-credential capture (uid_map/gid_map/status) in the
		// sampler, keyed on the wrapper/real-runtime exe.
		"PROCDETAIL",
		"uid_map",
		// The prepared-tree event watcher and its read-only discipline.
		"p21e3_devprep_watcher",
		"WATCHER-START",
		"DEPEVENT",
		"inotify_add_watch",
		"p21e3-devprep-events.log",
		// R4-P3-P5-R1 watcher repair: the watch starts on the EXISTING
		// state root (the traverse chain's first hop), not on the not-
		// yet-existing dev-prep directory.
		`/var/lib/docker-helper "$WATCHER_STOP"`,
		// Watch-attachment success is reported distinctly from
		// watcher-start success.
		"WATCHER-ATTACH",
		// Read-only snapshots: the decoded access ACL and the SELinux
		// label, plus the explicit overflow/limitation markers.
		"DEVSNAP",
		"acl=v2",
		"system.posix_acl_access",
		"WATCHER-OVERFLOW",
		"p21e3-watcher-triage.log",
		"MISSED-LIFECYCLE",
		// DAC-state captures (labels remain read-only).
		"p21e3-dac-state.log",
		"getfacl -p --absolute-names",
		"p21e3-devprep-terminal-state.log",
		// R4-P3-P6/M3: the dev-prep lifecycle diagnostics come from the
		// daemon's own operational journal (dev_prep, dev_prep_cleanup),
		// and the exact prepared-tree path is probed at the terminal.
		"p21e3-daemon-journal.log",
		"p21e3-devprep-terminal-probe.log",
		"dev_prep_cleanup",
		// R4-P3-P6-MNB mountinfo snapshots: per-context raw mountinfo,
		// context/ns identities, and the readonly lookups.
		"p21e3_procns_snap",
		"p21e3-procns.log",
		"p21e3-procns-host.log",
		"RPNS-MOUNT",
		// R4-P3-P5-R1: the state root is captured once more AFTER the
		// build terminal, alongside the per-op teardown race capture.
		"post-terminal traverse-chain state",
		// R4-P3-P5-R1 sampler: the near-wrapper traverse-chain snapshot
		// (root sampler, same sweep as the wrapper observation), the
		// namespace identities, and the deduped buildkitd credentials.
		"WRAPPER-SNAP",
		"/var/lib/docker-helper/dev-prep/%s",
		"ns_user=",
		"ns_mnt=",
		"PROCDETAIL-BUILDKITD",
		// The dontaudit diagnostic visibility toggle with verified restore.
		"semodule -DB",
		"semodule -B",
		"R7-P21E3-DONTAUDIT-RESTORED=verified",
		"policy sha restored",
		// The toolchain gains the ACL interrogation tool.
		"zypper --non-interactive install -y gcc strace acl",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("the p21e3 guest harness must carry the inspection diagnostic %q", want)
		}
	}
	// Restoration discipline: the policy identity must be recorded BEFORE
	// the toggle, and the EXIT trap must pair the restoration with the
	// abandonment handler.
	dbIdx := strings.Index(script, "SE_POLICY_SHA_PRE=")
	restoreIdx := strings.Index(script, "p21e3_dontaudit_restore() {")
	trapIdx := strings.Index(script, "trap 'p21e3_dontaudit_restore; measure_abandon' EXIT")
	if dbIdx < 0 || restoreIdx < 0 || dbIdx > restoreIdx {
		t.Error("the dontaudit toggle must record the policy identity BEFORE the restore-mechanism definition")
	}
	if trapIdx < 0 {
		t.Error("the EXIT trap must pair the dontaudit restoration with the abandonment handler")
	}
	// The P5 regression must not return: the watcher must never be started
	// on the not-yet-existing dev-prep directory again.
	if strings.Contains(script, `/var/lib/docker-helper/dev-prep "$WATCHER_STOP"`) {
		t.Error("the watcher must start on the existing state root, not on the not-yet-existing dev-prep directory")
	}
}

// TestR7P21E3HostGateDetectsVerdict pins the host-side verdict detection
// regression observed on the first p21e3 dispatch (run 43031588124): the
// gate fabricated its verdict string with `tail -2 | tr '\n' ' '`, which
// produced "R7-P21E3-BUILD=failed R7-P21E3-VERDICT=MEASURED" — prefixed by
// the BUILD line, so the R7-P21E3-VERDICT=* case never matched and the
// job retried over a valid MEASURED verdict. The detection must select the
// VERDICT line alone.
func TestR7P21E3HostGateDetectsVerdict(t *testing.T) {
	raw, err := os.ReadFile("scripts/release-2.4-r7-diag-tw-selinux-vm.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(raw)
	if strings.Contains(script, `R7-P21E3-(VERDICT|BUILD)`) {
		t.Error("the p21e3 host gate must not select VERDICT and BUILD with one grep (the joined string is BUILD-prefixed and never matches R7-P21E3-VERDICT=*)")
	}
	if !strings.Contains(script, "grep -aoE 'R7-P21E3-VERDICT=") {
		t.Error("the p21e3 host gate must match the VERDICT line alone")
	}
}
