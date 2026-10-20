package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// R7 B′ gate evaluator regression fixtures (§4 of the B′ hardening task):
// synthetic evidence directories prove the fail-closed classification and
// the ten-check gate without a VM. The evaluator is the single authority
// for the machine-readable verdict; these tests pin its identity
// classification, its deduplication, and every fail-closed branch.

const bprimeMemfdHex = "2F6D656D66643A72756E635F636C6F6E65643A2F70726F632F73656C662F657865202864656C6574656429"

const bprimeNewtype = "docker_helper_runc_memfd_t"

func bprimeAVC(serial, ts, pid, comm, perms, dev, ino, sctx, tctx, pathOrName string) string {
	rec := "type=AVC msg=audit(" + ts + ":" + serial + "): avc:  denied  { " + perms +
		" } for  pid=" + pid + " comm=\"" + comm + "\" "
	switch {
	case strings.HasPrefix(pathOrName, "2F"):
		rec += "path=" + pathOrName
	case pathOrName != "":
		rec += "name=\"" + pathOrName + "\""
	}
	rec += " dev=\"" + dev + "\" ino=" + ino +
		" scontext=" + sctx + " tcontext=" + tctx + " tclass=file permissive=0"
	return rec
}

const (
	bprimeRuncC1 = "system_u:system_r:docker_helper_buildkitd_t:s0:c1"
	bprimeRuncC2 = "system_u:system_r:docker_helper_buildkitd_t:s0:c2"
	bprimeUnconf = "unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023"
)

func bprimeNewtypeTctx() string {
	return "system_u:object_r:" + bprimeNewtype + ":s0"
}

func bprimeTmpfsTctx() string {
	return "system_u:object_r:tmpfs_t:s0"
}

// bprimeGreenFiles returns the complete evidence set of a PASSING B′ run:
// live memfd re-labeling (c1 and second-build windows, with strace
// getattr records that precede the runc write records — the two-pass
// anchor order), duplicate audit records across overlapping windows, the
// deny-all type facts, the matrices, and the byte-identical rollback.
func bprimeGreenFiles() map[string]string {
	runcWrite := func(serial, ino string) string {
		return bprimeAVC(serial, "1792485500.069", "3215", "buildkit-runc", "write",
			"tmpfs", ino, bprimeRuncC1, bprimeNewtypeTctx(), bprimeMemfdHex)
	}
	straceGetattr := func(serial, pid, ino string) string {
		return bprimeAVC(serial, "1792485502.555", pid, "strace", "getattr",
			"tmpfs", ino, bprimeUnconf, bprimeNewtypeTctx(), bprimeMemfdHex)
	}
	fifoAVC := bprimeAVC("1161", "1792485500.069", "3215", "buildkit-runc", "unlink",
		"tmpfs", "2076", bprimeRuncC1,
		"system_u:object_r:docker_helper_builder_runtime_t:s0:c1", "exec.fifo")
	memfdCreate := "3215  08:38:20.070321 memfd_create(\"runc_cloned:/proc/self/exe\", " +
		"MFD_CLOEXEC|MFD_ALLOW_SEALING|MFD_EXEC) = 23</memfd:runc_cloned:/proc/self/exe (deleted)>"

	before := []string{
		"CREATE system_u:system_r:docker_helper_buildkitd_t:s0:c1 x system_u:object_r:tmpfs_t:s0 x file -> system_u:object_r:tmpfs_t:s0",
		"CREATE system_u:system_r:docker_helper_buildkitd_t:s0:c2 x system_u:object_r:tmpfs_t:s0 x file -> system_u:object_r:tmpfs_t:s0",
		"CREATE unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 x system_u:object_r:tmpfs_t:s0 x file -> unconfined_u:object_r:user_tmp_t:s0",
		"CREATE system_u:system_r:docker_helper_buildkitd_t:s0:c1 x system_u:object_r:docker_helper_builder_runtime_t:s0:c1 x file -> system_u:object_r:docker_helper_builder_runtime_t:s0:c1",
		"CREATE system_u:system_r:docker_helper_buildkitd_t:s0:c1 x system_u:object_r:tmpfs_t:s0 x dir -> system_u:object_r:tmpfs_t:s0",
		"CREATE system_u:system_r:docker_helper_buildkitd_t:s0:c1 x system_u:object_r:tmpfs_t:s0 x fifo_file -> system_u:object_r:tmpfs_t:s0",
	}
	after := make([]string, 0, len(before))
	for _, line := range before {
		if strings.Contains(line, "buildkitd_t:s0:c1 x system_u:object_r:tmpfs_t:s0 x file") ||
			strings.Contains(line, "buildkitd_t:s0:c2 x system_u:object_r:tmpfs_t:s0 x file") {
			line = strings.Replace(line, " -> system_u:object_r:tmpfs_t:s0",
				" -> system_u:object_r:"+bprimeNewtype+":s0", 1)
		}
		after = append(after, line)
	}

	avMatrix := "== " + bprimeRuncC1 + " -> system_u:object_r:" + bprimeNewtype + ":s0 (class file)\n" +
		"  write    DENY (allowed=0x0 decided=0xffffffff)\n" +
		"  execute  DENY (allowed=0x0 decided=0xffffffff)\n" +
		"== " + bprimeRuncC2 + " -> system_u:object_r:" + bprimeNewtype + ":s0 (class file)\n" +
		"  write    DENY (allowed=0x0 decided=0xffffffff)\n"

	return map[string]string{
		// Overlapping windows repeat records verbatim (ausearch + raw tail):
		// the c1 log carries serial 1158 twice; the evaluator must dedup.
		"bprime-avc-c1.log": strings.Join([]string{
			runcWrite("1158", "67"), runcWrite("1158", "67"), fifoAVC, runcWrite("1160", "67"),
			"\n",
		}, "\n"),
		"bprime-avc-c2.log": strings.Join([]string{
			straceGetattr("1771", "3332", "68"), straceGetattr("1772", "3332", "68"),
			runcWrite("1774", "68"), straceGetattr("1775", "3332", "68"),
			"\n",
		}, "\n"),
		"bprime-avc-probe.log": "(no new-type records beyond the windows above)\n",
		"bprime-strace-c1.log": memfdCreate + "\n",
		"bprime-strace-c2.log": memfdCreate + "\n",
		"loaded-transition.log": "type_transition docker_helper_buildkitd_t tmpfs_t:file " +
			bprimeNewtype + ";\ntype_transition docker_helper_buildkitd_t tmpfs_t:file ica_tmpfs_t icastats_0;\n",
		"newtype-allows.log":            "# sesearch -A -t " + bprimeNewtype + " (empty = deny-all)\n",
		"newtype-attrs.log":             "Types: 1\n   type " + bprimeNewtype + "\n",
		"create-matrix-before.log":      strings.Join(before, "\n") + "\n",
		"create-matrix-after.log":       strings.Join(after, "\n") + "\n",
		"av-matrix-loaded.log":          avMatrix,
		"policy-sha-before.log":         "0b8cf58af85d8cbb73252c72402f9230bb8e20927961ddcf55e7d5137de4082c\n",
		"policy-sha-after-rollback.log": "0b8cf58af85d8cbb73252c72402f9230bb8e20927961ddcf55e7d5137de4082c\n",
		"rollback-module-list.log":      "module-removed\n",
		"rollback-transition.log":       "# sesearch -T -s docker_helper_buildkitd_t -t tmpfs_t -c file (empty = transition removed)\n",
		"create-matrix-rollback.log":    strings.Join(before, "\n") + "\n",
		"bprime-rollback-avc.log": bprimeAVC("2388", "1792485513.890", "3497", "buildkit-runc", "write",
			"tmpfs", "69", bprimeRuncC1, bprimeTmpfsTctx(), bprimeMemfdHex) + "\n",
	}
}

func runBPrimeVerdict(t *testing.T, files map[string]string) (string, int) {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatalf("write fixture %s: %v", name, err)
		}
	}
	cmd := exec.Command("bash", "scripts/release-2.4-r7-bprime-verdict.sh", dir)
	out, err := cmd.CombinedOutput()
	line := ""
	for _, l := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(l, "R7-BPRIME-VERDICT=") {
			line = l
		}
	}
	if line == "" {
		t.Fatalf("no verdict line in output: %s", out)
	}
	code := 0
	if exit, ok := err.(*exec.ExitError); ok {
		code = exit.ExitCode()
	} else if err != nil {
		t.Fatalf("run evaluator: %v", err)
	}
	return line, code
}

func bprimeDecision(line string) string {
	line = strings.TrimPrefix(line, "R7-BPRIME-VERDICT=")
	for _, part := range strings.Split(line, ";") {
		if strings.HasPrefix(part, "DECISION=") {
			return strings.TrimPrefix(part, "DECISION=")
		}
	}
	return ""
}

func bprimeFieldValue(line, key string) string {
	for _, part := range strings.Split(line, ";") {
		if strings.HasPrefix(part, key+"=") {
			return strings.TrimPrefix(part, key+"=")
		}
	}
	return ""
}

// The green evidence set reaches BPRIME-VIABLE: the expected runc memfd
// AVCs (including the strace getattr observations of the same inode) do
// NOT trigger OTHER-RELABEL, duplicates are deduplicated, and the distro's
// unrelated ica_tmpfs_t transition does not falsely fail the check.
func TestBPrimeGateGreenEvidenceIsViable(t *testing.T) {
	line, code := runBPrimeVerdict(t, bprimeGreenFiles())
	if code != 0 || bprimeDecision(line) != "BPRIME-VIABLE" {
		t.Fatalf("expected BPRIME-VIABLE exit 0, got %s (%d): %s", bprimeDecision(line), code, line)
	}
	if got := bprimeFieldValue(line, "OTHER-RELABEL"); got != "none" {
		t.Fatalf("OTHER-RELABEL = %q, want none", got)
	}
	if got := bprimeFieldValue(line, "LIVE-LABEL"); got != "proven" {
		t.Fatalf("LIVE-LABEL = %q, want proven", got)
	}
	if got := bprimeFieldValue(line, "MEMFD-CREATE-TRACE"); got != "present" {
		t.Fatalf("MEMFD-CREATE-TRACE = %q, want present", got)
	}
	// Dedup: the fixture repeats serial 1158 once; raw must exceed deduped.
	class := bprimeFieldValue(line, "CLASSIFICATION")
	if !strings.Contains(class, "expected=") {
		t.Fatalf("CLASSIFICATION missing: %s", class)
	}
	dedup := bprimeFieldValue(line, "AUDIT-DEDUP")
	var raw, deduped int
	if _, err := fmt.Sscanf(dedup, "raw=%d,deduped=%d", &raw, &deduped); err != nil {
		t.Fatalf("AUDIT-DEDUP unparsable: %q (%v)", dedup, err)
	}
	if raw <= deduped {
		t.Fatalf("dedup not observed: %s", dedup)
	}
}

// The distro's unrelated named ica_tmpfs_t transition on the same pair is
// tolerated: its presence or absence must not change the verdict.
func TestBPrimeGateDistroTransitionTolerated(t *testing.T) {
	files := bprimeGreenFiles()
	files["loaded-transition.log"] = "type_transition docker_helper_buildkitd_t tmpfs_t:file " +
		bprimeNewtype + ";\n"
	line, code := runBPrimeVerdict(t, files)
	if code != 0 || bprimeDecision(line) != "BPRIME-VIABLE" {
		t.Fatalf("expected VIABLE without the ica line too, got %s (%d)", bprimeDecision(line), code)
	}
}

// An unrelated inode carrying the new type (a /memfd:-shaped object with
// no runc write anchor) fails closed: BLOCKED, never VIABLE.
func TestBPrimeGateUnmatchedMemfdInodeBlocks(t *testing.T) {
	files := bprimeGreenFiles()
	files["bprime-avc-probe.log"] = bprimeAVC("3001", "1792485520.000", "4000", "strace",
		"getattr", "tmpfs", "999", bprimeUnconf, bprimeNewtypeTctx(), bprimeMemfdHex) + "\n"
	line, _ := runBPrimeVerdict(t, files)
	if bprimeDecision(line) != "BPRIME-BLOCKED" {
		t.Fatalf("expected BPRIME-BLOCKED, got %s: %s", bprimeDecision(line), line)
	}
	if !strings.Contains(line, "unmatched=1") {
		t.Fatalf("unmatched inode not classified: %s", line)
	}
}

// A foreign pathname object carrying the new type is other-object
// relabeling: FAIL, never VIABLE.
func TestBPrimeGateForeignPathnameFails(t *testing.T) {
	files := bprimeGreenFiles()
	files["bprime-avc-probe.log"] = bprimeAVC("3002", "1792485520.100", "4001", "someproc",
		"write", "tmpfs", "1000", bprimeRuncC1, bprimeNewtypeTctx(), "bprime-probe") + "\n"
	line, code := runBPrimeVerdict(t, files)
	if code != 1 || bprimeDecision(line) != "BPRIME-FAIL" {
		t.Fatalf("expected BPRIME-FAIL exit 1, got %s (%d)", bprimeDecision(line), code)
	}
	if got := bprimeFieldValue(line, "OTHER-RELABEL"); !strings.HasPrefix(got, "yes:") {
		t.Fatalf("OTHER-RELABEL = %q, want yes:...", got)
	}
}

// A memfd-shaped record whose inode identity cannot be anchored (the write
// anchor is missing for that dev/ino) is unmatched: BLOCKED, not PASS.
func TestBPrimeGateUnknownInodeFailsClosed(t *testing.T) {
	files := bprimeGreenFiles()
	// Remove the runc write anchors: only unanchored getattr records remain.
	files["bprime-avc-c1.log"] = ""
	files["bprime-avc-c2.log"] = bprimeAVC("1771", "1792485502.555", "3332", "strace",
		"getattr", "tmpfs", "68", bprimeUnconf, bprimeNewtypeTctx(), bprimeMemfdHex) + "\n"
	line, code := runBPrimeVerdict(t, files)
	if code == 0 || bprimeDecision(line) == "BPRIME-VIABLE" {
		t.Fatalf("unanchored inode must not pass: %s", line)
	}
}

// Duplicate audit records across overlapping windows are deduplicated:
// the classification counts distinct serials, not raw lines.
func TestBPrimeGateDeduplicatesAuditWindows(t *testing.T) {
	line, _ := runBPrimeVerdict(t, bprimeGreenFiles())
	dedup := bprimeFieldValue(line, "AUDIT-DEDUP")
	var raw, deduped int
	if _, err := fmt.Sscanf(dedup, "raw=%d,deduped=%d", &raw, &deduped); err != nil {
		t.Fatalf("AUDIT-DEDUP unparsable: %q (%v)", dedup, err)
	}
	// The green fixtures carry 6 raw records (one duplicate) -> 5 distinct.
	if raw != 8 || deduped != 7 {
		t.Fatalf("raw=%d deduped=%d, want 8/7", raw, deduped)
	}
}

// A missing memfd creation trace cannot silently PASS: the live-label
// check degrades to BLOCKED.
func TestBPrimeGateMissingMemfdCreateTraceBlocks(t *testing.T) {
	files := bprimeGreenFiles()
	delete(files, "bprime-strace-c1.log")
	delete(files, "bprime-strace-c2.log")
	line, code := runBPrimeVerdict(t, files)
	if code != 2 || bprimeDecision(line) != "BPRIME-BLOCKED" {
		t.Fatalf("expected BPRIME-BLOCKED exit 2, got %s (%d)", bprimeDecision(line), code)
	}
	if got := bprimeFieldValue(line, "MEMFD-CREATE-TRACE"); got != "missing" {
		t.Fatalf("MEMFD-CREATE-TRACE = %q, want missing", got)
	}
}

// A rollback SHA mismatch blocks acceptance: FAIL, never VIABLE.
func TestBPrimeGateRollbackSHAMismatchFails(t *testing.T) {
	files := bprimeGreenFiles()
	files["policy-sha-after-rollback.log"] = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\n"
	line, code := runBPrimeVerdict(t, files)
	if code != 1 || bprimeDecision(line) != "BPRIME-FAIL" {
		t.Fatalf("expected BPRIME-FAIL exit 1, got %s (%d)", bprimeDecision(line), code)
	}
	if !strings.Contains(bprimeFieldValue(line, "CHECKS"), "8=fail") {
		t.Fatalf("check 8 not failed: %s", line)
	}
}

// A post-rollback create-matrix mismatch blocks acceptance: FAIL.
func TestBPrimeGateRollbackMatrixMismatchFails(t *testing.T) {
	files := bprimeGreenFiles()
	files["create-matrix-rollback.log"] = strings.Replace(
		files["create-matrix-rollback.log"], " -> system_u:object_r:tmpfs_t:s0",
		" -> system_u:object_r:"+bprimeNewtype+":s0", 1)
	line, code := runBPrimeVerdict(t, files)
	if code != 1 || bprimeDecision(line) != "BPRIME-FAIL" {
		t.Fatalf("expected BPRIME-FAIL exit 1, got %s (%d)", bprimeDecision(line), code)
	}
	if !strings.Contains(bprimeFieldValue(line, "CHECKS"), "9=fail") {
		t.Fatalf("check 9 not failed: %s", line)
	}
}

// A remaining experimental transition after rollback blocks acceptance: FAIL.
func TestBPrimeGateRemainingTransitionFails(t *testing.T) {
	files := bprimeGreenFiles()
	files["rollback-transition.log"] = "# sesearch -T -s docker_helper_buildkitd_t -t tmpfs_t -c file\n" +
		"type_transition docker_helper_buildkitd_t tmpfs_t:file " + bprimeNewtype + ";\n"
	line, code := runBPrimeVerdict(t, files)
	if code != 1 || bprimeDecision(line) != "BPRIME-FAIL" {
		t.Fatalf("expected BPRIME-FAIL exit 1, got %s (%d)", bprimeDecision(line), code)
	}
	if !strings.Contains(bprimeFieldValue(line, "CHECKS"), "7=fail") {
		t.Fatalf("check 7 not failed: %s", line)
	}
}

// A live label that did NOT move (the memfd write denial still carries
// tmpfs_t while the experiment is loaded) is the mechanism disproven: FAIL.
func TestBPrimeGateLabelNoMoveFails(t *testing.T) {
	files := bprimeGreenFiles()
	files["bprime-avc-c1.log"] = bprimeAVC("1158", "1792485500.069", "3215", "buildkit-runc",
		"write", "tmpfs", "67", bprimeRuncC1, bprimeTmpfsTctx(), bprimeMemfdHex) + "\n"
	line, code := runBPrimeVerdict(t, files)
	if code != 1 || bprimeDecision(line) != "BPRIME-FAIL" {
		t.Fatalf("expected BPRIME-FAIL exit 1, got %s (%d)", bprimeDecision(line), code)
	}
	if got := bprimeFieldValue(line, "LIVE-LABEL"); got != "no-move" {
		t.Fatalf("LIVE-LABEL = %q, want no-move", got)
	}
}

// Missing required evidence is BLOCKED, never silently VIABLE.
func TestBPrimeGateMissingEvidenceBlocks(t *testing.T) {
	for _, missing := range []string{
		"loaded-transition.log", "newtype-allows.log", "newtype-attrs.log",
		"create-matrix-before.log", "create-matrix-after.log",
		"av-matrix-loaded.log", "policy-sha-before.log",
		"policy-sha-after-rollback.log", "rollback-module-list.log",
		"rollback-transition.log", "create-matrix-rollback.log",
		"bprime-rollback-avc.log", "bprime-avc-c1.log",
	} {
		files := bprimeGreenFiles()
		delete(files, missing)
		line, code := runBPrimeVerdict(t, files)
		if code == 0 || bprimeDecision(line) == "BPRIME-VIABLE" {
			t.Fatalf("missing %s must not be VIABLE: %s", missing, line)
		}
	}
}

// The gate subcommand: a BLOCKED (or FAIL) result cannot produce a
// successful gate status; only BPRIME-VIABLE exits zero.
func TestBPrimeGateSubcommandFailsClosed(t *testing.T) {
	cases := map[string]int{
		"R7-BPRIME-VERDICT=DECISION=BPRIME-VIABLE;CHECKS=1=pass":     0,
		"R7-BPRIME-VERDICT=DECISION=BPRIME-BLOCKED;CHECKS=3=blocked": 1,
		"R7-BPRIME-VERDICT=DECISION=BPRIME-FAIL;CHECKS=4=fail":       1,
		"":                                       1,
		"R7-BPRIME-VERDICT=DECISION=UNPARSEABLE": 1,
	}
	for line, want := range cases {
		cmd := exec.Command("bash", "scripts/release-2.4-r7-bprime-verdict.sh", "--gate", line)
		err := cmd.Run()
		code := 0
		if exit, ok := err.(*exec.ExitError); ok {
			code = exit.ExitCode()
		} else if err != nil {
			t.Fatalf("gate %q: %v", line, err)
		}
		if code != want {
			t.Fatalf("gate %q: exit %d, want %d", line, code, want)
		}
	}
}
