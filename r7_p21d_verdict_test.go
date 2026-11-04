package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// R7 P21-C gate evaluator regression fixtures, revision 3 (the
// r7-p21d-corrective-2 task): on top of the revision-2 per-operation
// runtime-window attribution, the audit CAPTURE itself is part of the
// proof. The producer reads every window through ONE pinned read
// descriptor on the audit source and records the identity checkpoints
// around every drain, the drain outcomes, and a MEASURED accounting
// (before/after/expected/actual, actual = the extracted file's own line
// count); the evaluator accepts MEASURED only when every checkpoint is
// proven, the accounting is internally consistent, and the RAW window
// artifacts independently corroborate the section (same line count,
// every cited record present verbatim, every raw runc:[2:INIT] record
// accounted for, no regression-control shape in the raw bytes). The
// fail-closed branches are proven for every falsification the review
// identified, including the producer-side scenarios driven through the
// REAL guest capture functions (the --capture-selftest battery). The
// evaluator (scripts/release-2.4-r7-p21d-verdict.sh) is the single
// authority for the machine-readable verdict; the P21-B evaluator stays
// untouched as the historical instrument, and no test reimplements its
// semantics.

const (
	p21dC1      = "system_u:system_r:docker_helper_buildkitd_t:s0:c1"
	p21dC2      = "system_u:system_r:docker_helper_buildkitd_t:s0:c2"
	p21dUnconf  = "unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023"
	p21dTmpfs   = "system_u:object_r:tmpfs_t:s0"
	p21dDevnode = "system_u:object_r:docker_helper_devnode_t:s0"
	p21dMemfd   = "system_u:object_r:docker_helper_runc_memfd_t:s0"
	p21dUserTmp = "unconfined_u:object_r:user_tmp_t:s0"
)

// The two independently measured operations of enforcing run 41817339781
// (the REAL operation ids and their recorded per-operation paths).
const (
	p21dOp1ID     = "71b1c2d3e4f5061728394a5b6c7d8e9f"
	p21dOp2ID     = "82c2d3e4f5a6071829304a5b6c7d8e9f"
	p21dSession1  = "dhs_aaa1111111111111111111111111111"
	p21dSession2  = "dhs_bbb2222222222222222222222222222"
	p21dOp1Rootfs = "/var/lib/docker-helper-builder/ops/op_71b1c2d3e4f5061728394a5b6c7d8e9f/root/runc-native/executor/m1n2o3p4q5r6s7t8u9v0w1x2/rootfs/dev/null"
	p21dOp2Rootfs = "/var/lib/docker-helper-builder/ops/op_82c2d3e4f5a6071829304a5b6c7d8e9f/root/runc-native/executor/n2o3p4q5r6s7t8u9v0w1x2y3/rootfs/dev/null"
)

// p21dDevnodeBasenames is the exact six-basename list the policy diverts
// (runc v1.4.3 AllowedDevices placeholders) — unchanged by P21-C.
var p21dDevnodeBasenames = []string{"null", "zero", "full", "random", "urandom", "tty"}

func p21dCreateRow(src, name, result string) string {
	return "CREATE " + src + " x " + p21dTmpfs + " x file [" + name + "] -> " + result
}

// p21dGreenMatrix returns the required create-decision rows (the P21-B
// transition surface is UNCHANGED by P21-C; the rows use the real probe
// grammar of run 41623047086).
func p21dGreenMatrix() []string {
	var rows []string
	for _, name := range p21dDevnodeBasenames {
		rows = append(rows, p21dCreateRow(p21dC1, name, p21dDevnode))
	}
	for _, name := range p21dDevnodeBasenames {
		rows = append(rows, p21dCreateRow(p21dC2, name, p21dDevnode))
	}
	rows = append(rows,
		p21dCreateRow(p21dC1, "someothername", p21dMemfd),
		p21dCreateRow(p21dC1, "-", p21dMemfd),
		p21dCreateRow(p21dC2, "someothername", p21dMemfd),
		p21dCreateRow(p21dC2, "-", p21dMemfd),
		p21dCreateRow(p21dUnconf, "null", p21dUserTmp),
		p21dCreateRow(p21dUnconf, "-", p21dUserTmp),
	)
	return rows
}

// p21dAVFilePerm is one kernel-AV matrix row in the probe's exact format.
func p21dAVFilePerm(perm, verdict, allowed string) string {
	return "  " + perm + " " + verdict + " (allowed=" + allowed + " decided=0xffffffff)"
}

// p21dGreenAV returns the kernel-AV rows the P21-D candidate policy must
// produce: for BOTH operation categories the devnode_t:file surface is
// create=ALLOW plus the ONE { read open } open-completion pair plus the
// ONE P21-D bind-mount mounton singleton, with every other permission
// DENIED; unconfined stays all-DENY (mounton included); the three
// associate rows are unchanged from P21-B.
func p21dGreenAV() []string {
	granted := []string{"write", "append", "setattr", "execute", "execute_no_trans", "map", "getattr", "unlink", "rename", "link", "ioctl", "lock"}
	var out []string
	out = append(out, "== buildkitd_t:s0:c1 -> docker_helper_devnode_t:s0 ==")
	out = append(out,
		p21dAVFilePerm("create", "ALLOW", "0x8000a"),
		p21dAVFilePerm("open", "ALLOW", "0x8000a"),
		p21dAVFilePerm("read", "ALLOW", "0x8000a"),
		p21dAVFilePerm("mounton", "ALLOW", "0x8000a"))
	for _, perm := range granted {
		out = append(out, p21dAVFilePerm(perm, "DENY", "0x8000a"))
	}
	out = append(out, "== CROSS-OP: buildkitd_t:s0:c2 -> docker_helper_devnode_t:s0 ==")
	out = append(out,
		p21dAVFilePerm("create", "ALLOW", "0x8000a"),
		p21dAVFilePerm("open", "ALLOW", "0x8000a"),
		p21dAVFilePerm("read", "ALLOW", "0x8000a"),
		p21dAVFilePerm("mounton", "ALLOW", "0x8000a"))
	for _, perm := range granted {
		out = append(out, p21dAVFilePerm(perm, "DENY", "0x8000a"))
	}
	out = append(out, "== unconfined_t -> docker_helper_devnode_t:s0 ==")
	for _, perm := range []string{"create", "write", "append", "setattr", "execute", "execute_no_trans", "map", "mounton", "open", "read", "getattr", "unlink", "rename", "link", "ioctl", "lock"} {
		out = append(out, p21dAVFilePerm(perm, "DENY", "0x0"))
	}
	out = append(out,
		"== FILESYSTEM ASSOCIATE rows ==",
		"-- devnode_t -> tmpfs_t (the granted singleton) --",
		"  associate ALLOW (allowed=0x80 decided=0xffffffff)",
		"-- runc_memfd_t -> tmpfs_t (must stay denied) --",
		"  associate DENY (allowed=0x0 decided=0xffffffff)",
		"-- tmpfs_t -> tmpfs_t (control) --",
		"  associate ALLOW (allowed=0x80 decided=0xffffffff)",
	)
	return out
}

// The measured pre-boundary cap_userns self-denials (the P21-B/C window
// shape) and the observed next terminals of run 41817339781 (both windows
// carry the buildkitd_t:s0:c1 source — the same MCS category; attribution
// NEVER rests on the category).
const (
	p21dSetuid1      = `type=AVC msg=audit(1793899120.001:3101): avc:  denied  { setuid } for  pid=5353 comm="runc:[2:INIT]" capability=7  scontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tcontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tclass=cap_userns permissive=0`
	p21dSetgid1      = `type=AVC msg=audit(1793899120.002:3102): avc:  denied  { setgid } for  pid=5353 comm="runc:[2:INIT]" capability=6  scontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tcontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tclass=cap_userns permissive=0`
	p21dNewTerminal1 = `type=AVC msg=audit(1793899120.003:3103): avc:  denied  { read open } for  pid=5353 comm="runc:[2:INIT]" path="` + p21dOp1Rootfs + `" dev="tmpfs" ino=5 scontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tcontext=system_u:object_r:device_t:s0 tclass=chr_file permissive=0`
	p21dSetuid2      = `type=AVC msg=audit(1793899122.001:4101): avc:  denied  { setuid } for  pid=5517 comm="runc:[2:INIT]" capability=7  scontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tcontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tclass=cap_userns permissive=0`
	p21dSetgid2      = `type=AVC msg=audit(1793899122.002:4102): avc:  denied  { setgid } for  pid=5517 comm="runc:[2:INIT]" capability=6  scontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tcontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tclass=cap_userns permissive=0`
	p21dNewTerminal2 = `type=AVC msg=audit(1793899122.003:4103): avc:  denied  { read open } for  pid=5517 comm="runc:[2:INIT]" path="` + p21dOp2Rootfs + `" dev="tmpfs" ino=5 scontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tcontext=system_u:object_r:device_t:s0 tclass=chr_file permissive=0`
	p21dOldMounton1  = `type=AVC msg=audit(1793899120.004:3104): avc:  denied  { mounton } for  pid=5353 comm="runc:[2:INIT]" path="` + p21dOp1Rootfs + `" dev="tmpfs" ino=5 scontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tcontext=system_u:object_r:docker_helper_devnode_t:s0 tclass=file permissive=0`
	p21dOldMounton2  = `type=AVC msg=audit(1793899122.004:4104): avc:  denied  { mounton } for  pid=5517 comm="runc:[2:INIT]" path="` + p21dOp2Rootfs + `" dev="tmpfs" ino=5 scontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tcontext=system_u:object_r:docker_helper_devnode_t:s0 tclass=file permissive=0`
)

// p21dNewTerminal1/2 are the fixtures' observed P21-D next terminals: the
// first access THROUGH a bound host device — the post-bind check against
// the MOUNTED source inode's own label and class (device_t:chr_file), a
// surface the P21-D grant deliberately does NOT touch. The exact next
// terminal of the real run is OBSERVED, never pre-granted; the evaluator
// accepts any real new-flow record.
const p21dNewTerminalNote = "the post-bind device access (device_t:chr_file)"

// p21dOldTerminal is the ELIMINATED P21-B shape (the P21-B measured
// terminal of run 41623047086): the exact "denied  { read open }" pair on
// the devnode_t file object, permissive=0, with a per-operation path.
const p21dOldTerminal = `type=AVC msg=audit(1793889070.816:2190): avc:  denied  { read open } for  pid=5288 comm="runc:[2:INIT]" path="` + p21dOp1Rootfs + `" dev="tmpfs" ino=5 scontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tcontext=system_u:object_r:docker_helper_devnode_t:s0 tclass=file permissive=0`

// p21dAssociateDenial is the associate-denial shape the raw-window
// regression controls must catch (the singleton is granted; any associate
// denial on the loaded candidate policy is a positive violation).
const p21dAssociateDenial = `type=AVC msg=audit(1793789899.004:2003): avc:  denied  { associate } for  pid=5517 comm="runc:[2:INIT]" path="/dev/shm/x" dev="tmpfs" ino=9 scontext=system_u:object_r:docker_helper_devnode_t:s0 tcontext=system_u:object_r:tmpfs_t:s0 tclass=filesystem permissive=0`

// p21dWindow1/p21dWindow2 are the green raw windows: EXACTLY the bytes the
// producer drained through the pinned descriptor for each operation.
var (
	p21dWindow1 = p21dNewTerminal1 + "\n" + p21dSetuid1 + "\n" + p21dSetgid1 + "\n"
	p21dWindow2 = p21dNewTerminal2 + "\n" + p21dSetuid2 + "\n" + p21dSetgid2 + "\n"
)

// p21dWindowLines counts the non-empty record lines of a raw window
// fixture — the same measurement the producer records as `actual` (the
// extracted file's own line count, never the boundary arithmetic).
func p21dWindowLines(records string) int {
	n := 0
	for _, l := range strings.Split(records, "\n") {
		if strings.TrimSpace(l) != "" {
			n++
		}
	}
	return n
}

// p21dOpSection composes one per-operation evidence section in the
// corrected grammar: header (tag + daemon operation id + session id), the
// pinned-source capture-integrity accounting (identity checkpoints, drain
// outcomes, measured before/after/expected/actual), the operation result,
// the attributed runtime records partitioned by attribution quality, the
// whole-window regression-control sections, and the raw window records the
// capture claims to have extracted.
func p21dOpSection(tag, opid, session string, before, after int, opAttributed, pidCorrelated, misattributed, unattributed, p21bTerminal, p21cTerminal, windowRecords, opResult string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "== operation %s op_%s session %s ==\n", tag, opid, session)
	b.WriteString("-- window boundaries (pinned-source capture integrity) --\n")
	b.WriteString("identity-begin-pre=proven\n")
	b.WriteString("pre-drain=ok\n")
	b.WriteString("identity-begin-post=proven\n")
	fmt.Fprintf(&b, "before=%d\n", before)
	b.WriteString("identity-extract-pre=proven\n")
	b.WriteString("window-drain=ok\n")
	b.WriteString("identity-extract-post=proven\n")
	fmt.Fprintf(&b, "after=%d\n", after)
	fmt.Fprintf(&b, "expected=%d\n", after-before)
	fmt.Fprintf(&b, "actual=%d\n", p21dWindowLines(windowRecords))
	b.WriteString("source=proven\n")
	b.WriteString("-- operation result --\n")
	if opResult == "succeeded" {
		b.WriteString(`"status": "succeeded" "result_code": "docker_build_succeeded" "exit_code": 0` + "\n")
	} else {
		b.WriteString(`"status": "failed" "result_code": "docker_build_failed" "exit_code": 1` + "\n")
	}
	b.WriteString("-- op-attributed runc-init records --\n")
	b.WriteString(opAttributed)
	b.WriteString("-- pid-correlated runc-init records --\n")
	b.WriteString(pidCorrelated)
	b.WriteString("-- misattributed records (a path carries a DIFFERENT operation id) --\n")
	b.WriteString(misattributed)
	b.WriteString("-- unattributed runc-init records --\n")
	b.WriteString(unattributed)
	b.WriteString("-- regression controls (the WHOLE window; must be EMPTY) --\n")
	b.WriteString("-- P20 terminal (runc_memfd_t:file create) --\n")
	b.WriteString("-- pre-B terminal (tmpfs_t:file write) --\n")
	b.WriteString("-- associate denials (must be EMPTY — the singleton is granted) --\n")
	b.WriteString("-- P21-B terminal (devnode_t:file { read open }; the ELIMINATED shape) --\n")
	b.WriteString(p21bTerminal)
	b.WriteString("-- P21-C terminal (devnode_t:file mounton; the ELIMINATED shape) --\n")
	b.WriteString(p21cTerminal)
	return b.String()
}

// p21dInterSection composes the inter-window region section: the records
// drained between the two operations (attributable to NEITHER operation;
// host audit noise is expected there), with the same capture-integrity
// accounting as the operation windows.
func p21dInterSection(gapAfter, gapBefore int, records string) string {
	var b strings.Builder
	b.WriteString("== inter-window records (attributable to NEITHER operation) ==\n")
	b.WriteString("-- window boundaries (pinned-source capture integrity) --\n")
	b.WriteString("identity-gap-pre=proven\n")
	b.WriteString("identity-gap-post=proven\n")
	b.WriteString("inter-drain=ok\n")
	fmt.Fprintf(&b, "gap-after=%d\n", gapAfter)
	fmt.Fprintf(&b, "gap-before=%d\n", gapBefore)
	fmt.Fprintf(&b, "expected=%d\n", gapBefore-gapAfter)
	fmt.Fprintf(&b, "actual=%d\n", p21dWindowLines(records))
	b.WriteString("source=proven\n")
	b.WriteString("-- records --\n")
	b.WriteString(records)
	return b.String()
}

// p21dGreenTerminals returns the green live-flow fixture: two DISTINCT
// operations (distinct operation ids, distinct session ids), each with its
// own bounded non-overlapping audit window, its own attributed runtime
// records (op-path terminal + pid-correlated pre-boundary self-denials),
// its own observed next terminal, EMPTY control sections, and an empty
// inter-window region. BOTH windows carry the buildkitd_t:s0:c1 source
// context — the same MCS category — because attribution never rests on
// the category.
func p21dGreenTerminals() string {
	return p21dOpSection("c1", p21dOp1ID, p21dSession1, 100, 103, p21dNewTerminal1+"\n", p21dSetuid1+"\n"+p21dSetgid1+"\n", "", "", "", "", p21dWindow1, "failed") +
		p21dOpSection("c2", p21dOp2ID, p21dSession2, 103, 106, p21dNewTerminal2+"\n", p21dSetuid2+"\n"+p21dSetgid2+"\n", "", "", "", "", p21dWindow2, "failed") +
		p21dInterSection(103, 103, "")
}

// p21dGreenRawWindows returns the raw window artifacts of the green
// fixture: the exact drained bytes per operation plus the empty
// inter-window artifact.
func p21dGreenRawWindows() map[string]string {
	return map[string]string{"c1": p21dWindow1, "c2": p21dWindow2, "inter": ""}
}

func p21dWriteEvidence(t *testing.T, matrix, av, terminals string, raw map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("create-matrix-before.log", matrix)
	write("av-matrix-before.log", av)
	write("p21d-terminals.log", terminals)
	write("avc-window-c1.log", raw["c1"])
	write("avc-window-c2.log", raw["c2"])
	write("inter-window.log", raw["inter"])
	return dir
}

func p21dRunEvaluator(t *testing.T, dir string) (string, int) {
	t.Helper()
	out, err := exec.Command("bash", "scripts/release-2.4-r7-p21d-verdict.sh", dir).CombinedOutput()
	line := ""
	for _, l := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(l, "R7-P21D-VERDICT=") {
			line = l
		}
	}
	rc := 0
	if err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("evaluator failed to run: %v\n%s", err, out)
		}
		rc = exitErr.ExitCode()
	}
	if line == "" || rc != 0 {
		if class, err := os.ReadFile(filepath.Join(dir, "p21d-classification.log")); err == nil {
			_ = os.WriteFile("/tmp/opencode/last-classification.log", class, 0o644)
		}
	}
	if line == "" {
		t.Fatalf("evaluator produced no verdict line (rc=%d):\n%s", rc, out)
	}
	if rc != 0 {
		if class, err := os.ReadFile(filepath.Join(dir, "p21d-classification.log")); err == nil {
			_ = os.WriteFile("/tmp/opencode/last-classification.log", class, 0o644)
		}
	}
	return line, rc
}

func p21dField(t *testing.T, verdict, key string) string {
	t.Helper()
	for _, part := range strings.Split(strings.TrimPrefix(verdict, "R7-P21D-VERDICT="), ";") {
		if strings.HasPrefix(part, key+"=") {
			return strings.TrimPrefix(part, key+"=")
		}
	}
	t.Fatalf("verdict %q carries no %s field", verdict, key)
	return ""
}

func p21dGreenDir(t *testing.T) string {
	return p21dWriteEvidence(t,
		strings.Join(p21dGreenMatrix(), "\n")+"\n",
		strings.Join(p21dGreenAV(), "\n")+"\n",
		p21dGreenTerminals(), p21dGreenRawWindows())
}

// TestR7P21DVerdictGreenEvidenceIsMeasured proves the evaluator decides
// P21D-MEASURED when BOTH operations independently prove their own
// advancement, with every summary field at its expected value.
func TestR7P21DVerdictGreenEvidenceIsMeasured(t *testing.T) {
	line, rc := p21dRunEvaluator(t, p21dGreenDir(t))
	if rc != 0 {
		t.Fatalf("green evidence must decide P21D-MEASURED (rc=0), got rc=%d: %s", rc, line)
	}
	if !strings.Contains(line, "DECISION=P21D-MEASURED") {
		t.Errorf("green evidence must carry DECISION=P21D-MEASURED: %s", line)
	}
	if got := p21dField(t, line, "SCOPE"); got != "six-names-ok" {
		t.Errorf("SCOPE must be six-names-ok, got %q", got)
	}
	if got := p21dField(t, line, "OPEN-COMPLETION"); got != "eliminated" {
		t.Errorf("OPEN-COMPLETION must be eliminated, got %q", got)
	}
	if got := p21dField(t, line, "MEMFD"); got != "intact" {
		t.Errorf("MEMFD must be intact, got %q", got)
	}
	if got := p21dField(t, line, "CROSSOP-CONTENT"); got != "closed" {
		t.Errorf("CROSSOP-CONTENT must be closed, got %q", got)
	}
	if got := p21dField(t, line, "NEXT-TERMINAL"); !strings.Contains(got, p21dOp1ID) || !strings.Contains(got, "tclass=chr_file") {
		t.Errorf("NEXT-TERMINAL must be the FIRST operation's own attributed record, got %q", got)
	}
}

// TestR7P21DVerdictSingleWindowCannotMeasure is THE corrected defect: the
// revision-1 evaluator could decide MEASURED from one merged record set.
// A single window (the second section missing) can never measure, and a
// second window that merely COPIES the first is a positive attribution
// violation, never evidence.
func TestR7P21DVerdictSingleWindowCannotMeasure(t *testing.T) {
	green := p21dGreenTerminals()
	secondStart := strings.Index(green, "== operation c2 ")
	if secondStart < 0 {
		t.Fatal("fixture must contain a second operation section")
	}
	firstOnly := green[:secondStart]
	copied := firstOnly + strings.Replace(firstOnly, "operation c1", "operation c2", 1)
	for name, terminals := range map[string]struct {
		want string
		text string
		raw  map[string]string
	}{
		"second window missing entirely": {"P21D-BLOCKED", firstOnly,
			map[string]string{"c1": p21dWindow1, "c2": "", "inter": ""}},
		"second window is a copy of the first (the first op's paths inside it)": {"P21D-FAIL", copied,
			map[string]string{"c1": p21dWindow1, "c2": p21dWindow1, "inter": ""}},
	} {
		dir := p21dWriteEvidence(t, strings.Join(p21dGreenMatrix(), "\n")+"\n",
			strings.Join(p21dGreenAV(), "\n")+"\n", terminals.text, terminals.raw)
		line, rc := p21dRunEvaluator(t, dir)
		if rc == 0 || !strings.Contains(line, "DECISION="+terminals.want) {
			t.Errorf("%s must decide %s, got rc=%d: %s", name, terminals.want, rc, line)
		}
	}
}

// TestR7P21DVerdictSecondOperationFailsBeforeInitBlocks proves a second
// operation that never reached runc:[2:INIT] can never ride the first
// operation's evidence: the second section carries no attributed runtime
// record, so the verdict is BLOCKED (not MEASURED, not FAIL-by-proxy).
func TestR7P21DVerdictSecondOperationFailsBeforeInitBlocks(t *testing.T) {
	terminals := p21dOpSection("c1", p21dOp1ID, p21dSession1, 100, 103, p21dNewTerminal1+"\n", p21dSetuid1+"\n"+p21dSetgid1+"\n", "", "", "", "", p21dWindow1, "failed") +
		p21dOpSection("c2", p21dOp2ID, p21dSession2, 103, 104, "", "", "", "", "", "", "host noise record\n", "failed") +
		p21dInterSection(103, 103, "")
	dir := p21dWriteEvidence(t, strings.Join(p21dGreenMatrix(), "\n")+"\n",
		strings.Join(p21dGreenAV(), "\n")+"\n", terminals,
		map[string]string{"c1": p21dWindow1, "c2": "host noise record\n", "inter": ""})
	line, rc := p21dRunEvaluator(t, dir)
	if rc == 0 || !strings.Contains(line, "DECISION=P21D-BLOCKED") {
		t.Errorf("a second operation with no attributed runtime record must decide BLOCKED, got rc=%d: %s", rc, line)
	}
	if got := p21dField(t, line, "OPEN-COMPLETION"); got != "eliminated" {
		t.Errorf("the FIRST window was still fully evaluated (OPEN-COMPLETION=eliminated), got %q", got)
	}
}

// TestR7P21DVerdictCategoryOnlyAttributionBlocks proves the attribution
// never rests on the MCS category: two windows whose records are
// distinguishable ONLY by category labels (no per-operation path, no
// pid proven by an op-attributed record) are AMBIGUOUS evidence — BLOCKED.
// TestR7P21DVerdictWindowScopedAttribution proves the P21-D attribution
// grammar for PATHLESS runtime records (the post-rung flow: the observed
// terminals of the device-bind stage carry name=/pathless shapes, no
// operation path): attribution rests on the PROVEN window and the
// container-init pid singleton — NEVER on the MCS category. Pathless
// records of distinct container-init pids in distinct proven windows
// attribute cleanly and measure; the SAME pid appearing in BOTH windows
// is a positive violation (one container init can never serve two
// operations, no matter what the category labels claim).
func TestR7P21DVerdictWindowScopedAttribution(t *testing.T) {
	// Distinct pids, distinct proven windows, pathless records only: the
	// records are window-scoped, the category label (c1 in BOTH windows)
	// is irrelevant, and each window's own terminal decides its
	// operation's advancement.
	pathlessSetuid1 := `type=AVC msg=audit(1793899120.001:3101): avc:  denied  { setuid } for  pid=5353 comm="runc:[2:INIT]" capability=7  scontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tcontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tclass=cap_userns permissive=0`
	pathlessTerminal1 := `type=AVC msg=audit(1793899120.005:3110): avc:  denied  { create } for  pid=5353 comm="runc:[2:INIT]" name="ptmx" scontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tcontext=system_u:object_r:tmpfs_t:s0 tclass=lnk_file permissive=0`
	pathlessSetuid2 := `type=AVC msg=audit(1793899122.001:4101): avc:  denied  { setuid } for  pid=5517 comm="runc:[2:INIT]" capability=7  scontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tcontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tclass=cap_userns permissive=0`
	pathlessTerminal2 := `type=AVC msg=audit(1793899122.005:4110): avc:  denied  { create } for  pid=5517 comm="runc:[2:INIT]" name="ptmx" scontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tcontext=system_u:object_r:tmpfs_t:s0 tclass=lnk_file permissive=0`
	terminals := p21dOpSection("c1", p21dOp1ID, p21dSession1, 100, 102, "", "",
		"", pathlessSetuid1+"\n"+pathlessTerminal1+"\n", "", "",
		pathlessSetuid1+"\n"+pathlessTerminal1+"\n", "failed") +
		p21dOpSection("c2", p21dOp2ID, p21dSession2, 102, 104, "", "",
			"", pathlessSetuid2+"\n"+pathlessTerminal2+"\n", "", "",
			pathlessSetuid2+"\n"+pathlessTerminal2+"\n", "failed") +
		p21dInterSection(102, 102, "")
	dir := p21dWriteEvidence(t, strings.Join(p21dGreenMatrix(), "\n")+"\n",
		strings.Join(p21dGreenAV(), "\n")+"\n", terminals,
		map[string]string{"c1": pathlessSetuid1 + "\n" + pathlessTerminal1 + "\n",
			"c2": pathlessSetuid2 + "\n" + pathlessTerminal2 + "\n", "inter": ""})
	line, rc := p21dRunEvaluator(t, dir)
	if rc != 0 || !strings.Contains(line, "DECISION=P21D-MEASURED") {
		t.Errorf("window-scoped pathless records with distinct container-init pids must measure (the category is never the key), got rc=%d: %s", rc, line)
	}
	// The SAME container-init pid in BOTH windows: one runc:[2:INIT]
	// process can never serve two operations — FAIL.
	samePidTerminals := p21dOpSection("c1", p21dOp1ID, p21dSession1, 100, 102, "", "",
		"", pathlessSetuid1+"\n"+pathlessTerminal1+"\n", "", "",
		pathlessSetuid1+"\n"+pathlessTerminal1+"\n", "failed") +
		p21dOpSection("c2", p21dOp2ID, p21dSession2, 102, 104, "", "",
			"", pathlessSetuid1+"\n"+pathlessTerminal1+"\n", "", "",
			pathlessSetuid1+"\n"+pathlessTerminal1+"\n", "failed") +
		p21dInterSection(102, 102, "")
	dir = p21dWriteEvidence(t, strings.Join(p21dGreenMatrix(), "\n")+"\n",
		strings.Join(p21dGreenAV(), "\n")+"\n", samePidTerminals,
		map[string]string{"c1": pathlessSetuid1 + "\n" + pathlessTerminal1 + "\n",
			"c2": pathlessSetuid1 + "\n" + pathlessTerminal1 + "\n", "inter": ""})
	line, rc = p21dRunEvaluator(t, dir)
	if rc == 0 || !strings.Contains(line, "DECISION=P21D-FAIL") {
		t.Errorf("the same container-init pid in both windows must decide FAIL, got rc=%d: %s", rc, line)
	}
}

// TestR7P21DVerdictMisattributedAndUnattributedFailClosed proves the
// attribution-quality branches: a first-window record placed into the
// second window is a positive violation (FAIL), an unattributed
// runc:[2:INIT] record is ambiguous evidence (BLOCKED).
func TestR7P21DVerdictMisattributedAndUnattributedFailClosed(t *testing.T) {
	// A pathless runc-init record whose pid is NOT proven by any
	// op-attributed record of its window.
	stray := `type=AVC msg=audit(1793789899.002:2001): avc:  denied  { getattr } for  pid=4242 comm="runc:[2:INIT]" path="/tmp/x" dev="vda3" ino=1 scontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tcontext=system_u:object_r:tmp_t:s0 tclass=file permissive=0`
	for name, terminals := range map[string]struct {
		want string
		text string
		raw  map[string]string
	}{
		"first op's terminal record placed into the second window": {"P21D-FAIL",
			p21dOpSection("c1", p21dOp1ID, p21dSession1, 100, 103, p21dNewTerminal1+"\n", p21dSetuid1+"\n"+p21dSetgid1+"\n", "", "", "", "", p21dWindow1, "failed") +
				p21dOpSection("c2", p21dOp2ID, p21dSession2, 103, 107, p21dNewTerminal1+"\n"+p21dNewTerminal2+"\n", p21dSetuid2+"\n"+p21dSetgid2+"\n", "", "", "", "", p21dNewTerminal1+"\n"+p21dNewTerminal2+"\n"+p21dSetuid2+"\n"+p21dSetgid2+"\n", "failed"),
			map[string]string{
				"c1":    p21dWindow1,
				"c2":    p21dNewTerminal1 + "\n" + p21dNewTerminal2 + "\n" + p21dSetuid2 + "\n" + p21dSetgid2 + "\n",
				"inter": "",
			}},
		"unattributed runc-init record in the first window": {"P21D-BLOCKED",
			p21dOpSection("c1", p21dOp1ID, p21dSession1, 100, 104, p21dNewTerminal1+"\n", p21dSetuid1+"\n"+p21dSetgid1+"\n", "", stray+"\n", "", "", p21dWindow1+stray+"\n", "failed") +
				p21dOpSection("c2", p21dOp2ID, p21dSession2, 104, 107, p21dNewTerminal2+"\n", p21dSetuid2+"\n"+p21dSetgid2+"\n", "", "", "", "", p21dWindow2, "failed"),
			map[string]string{"c1": p21dWindow1 + stray + "\n", "c2": p21dWindow2, "inter": ""}},
	} {
		dir := p21dWriteEvidence(t, strings.Join(p21dGreenMatrix(), "\n")+"\n",
			strings.Join(p21dGreenAV(), "\n")+"\n", terminals.text, terminals.raw)
		line, rc := p21dRunEvaluator(t, dir)
		if rc == 0 || !strings.Contains(line, "DECISION="+terminals.want) {
			t.Errorf("%s must decide %s, got rc=%d: %s", name, terminals.want, rc, line)
		}
	}
}

// TestR7P21DVerdictWindowBoundaryFailClosed proves the exact-boundary
// contract: a truncated/rotated capture (inconsistent boundary) decides
// BLOCKED, an overlapping second window decides FAIL, a gap between the
// windows decides BLOCKED.
func TestR7P21DVerdictWindowBoundaryFailClosed(t *testing.T) {
	greenC1 := p21dOpSection("c1", p21dOp1ID, p21dSession1, 100, 103, p21dNewTerminal1+"\n", p21dSetuid1+"\n"+p21dSetgid1+"\n", "", "", "", "", p21dWindow1, "failed")
	_ = os.WriteFile("/tmp/opencode/greenc1.txt", []byte(greenC1+"\n@@\n"+p21dWindow1), 0o644)
	greenInter := p21dInterSection(103, 103, "")
	c2 := func() string {
		return p21dOpSection("c2", p21dOp2ID, p21dSession2, 103, 106, p21dNewTerminal2+"\n", p21dSetuid2+"\n"+p21dSetgid2+"\n", "", "", "", "", p21dWindow2, "failed")
	}
	shiftC2 := func(before, after string) string {
		out := strings.Replace(c2(), "before=103\n", "before="+before+"\n", 1)
		return strings.Replace(out, "after=106\n", "after="+after+"\n", 1)
	}
	truncated := greenC1 + strings.Replace(c2(), "actual=3", "actual=2", 1) + greenInter
	overlapping := greenC1 + shiftC2("102", "105") + greenInter
	unaccountedGap := greenC1 + shiftC2("110", "113") + greenInter
	// A capture gap WITH a faithful inter-window section (host noise only)
	// is sound evidence: the gap region is accounted — seven real records
	// captured, all of them host noise — and carries no ambiguous runtime
	// record.
	accountedGap := greenC1 + shiftC2("110", "113") +
		p21dInterSection(103, 110,
			"host noise 1\nhost noise 2\nhost noise 3\nhost noise 4\nhost noise 5\nhost noise 6\nhost noise 7\n")
	unproven := greenC1 +
		strings.Replace(c2(), "identity-extract-post=proven", "identity-extract-post=unproven:path-replaced(pinned=95:1,path=95:2)", 1) +
		greenInter
	ambiguousGap := greenC1 + c2() + p21dInterSection(103, 110, p21dNewTerminal2+"\n")
	for name, terminals := range map[string]struct {
		want string
		text string
	}{
		"truncated capture (actual does not match the boundary arithmetic)": {"P21D-BLOCKED", truncated},
		"second window overlaps the first":                                  {"P21D-FAIL", overlapping},
		"capture gap between the windows is unaccounted":                    {"P21D-BLOCKED", unaccountedGap},
		"a runc-init record inside the inter-window region":                 {"P21D-BLOCKED", ambiguousGap},
		"capture not proven at the extraction boundary":                     {"P21D-BLOCKED", unproven},
	} {
		dir := p21dWriteEvidence(t, strings.Join(p21dGreenMatrix(), "\n")+"\n",
			strings.Join(p21dGreenAV(), "\n")+"\n", terminals.text, p21dGreenRawWindows())
		line, rc := p21dRunEvaluator(t, dir)
		if rc == 0 || !strings.Contains(line, "DECISION="+terminals.want) {
			t.Errorf("%s must decide %s, got rc=%d: %s", name, terminals.want, rc, line)
		}
	}
	// The accounted-gap control: with a faithful inter-window section the
	// same gapped capture measures.
	dir := p21dWriteEvidence(t, strings.Join(p21dGreenMatrix(), "\n")+"\n",
		strings.Join(p21dGreenAV(), "\n")+"\n", accountedGap,
		map[string]string{"c1": p21dWindow1, "c2": p21dWindow2,
			"inter": "host noise 1\nhost noise 2\nhost noise 3\nhost noise 4\nhost noise 5\nhost noise 6\nhost noise 7\n"})
	line, rc := p21dRunEvaluator(t, dir)
	if rc != 0 || !strings.Contains(line, "DECISION=P21D-MEASURED") {
		t.Errorf("a capture gap WITH a faithful inter-window section must decide MEASURED, got rc=%d: %s", rc, line)
	}
}

// TestR7P21DVerdictDuplicateIdentityFailsClosed proves the identity
// branches: the SAME operation id in both windows (one window serving both
// operations) decides FAIL, the SAME session id decides FAIL, and the
// SAME AVC record cited as both operations' terminal decides FAIL.
func TestR7P21DVerdictDuplicateIdentityFailsClosed(t *testing.T) {
	sameOp := p21dOpSection("c1", p21dOp1ID, p21dSession1, 100, 103, p21dNewTerminal1+"\n", p21dSetuid1+"\n"+p21dSetgid1+"\n", "", "", "", "", p21dWindow1, "failed") +
		p21dOpSection("c2", p21dOp1ID, p21dSession2, 103, 106, p21dNewTerminal2+"\n", p21dSetuid2+"\n"+p21dSetgid2+"\n", "", "", "", "", p21dWindow2, "failed")
	sameSession := p21dOpSection("c1", p21dOp1ID, p21dSession1, 100, 103, p21dNewTerminal1+"\n", p21dSetuid1+"\n"+p21dSetgid1+"\n", "", "", "", "", p21dWindow1, "failed") +
		p21dOpSection("c2", p21dOp2ID, p21dSession1, 103, 106, p21dNewTerminal2+"\n", p21dSetuid2+"\n"+p21dSetgid2+"\n", "", "", "", "", p21dWindow2, "failed")
	sameTerminal := p21dOpSection("c1", p21dOp1ID, p21dSession1, 100, 103, p21dNewTerminal1+"\n", p21dSetuid1+"\n"+p21dSetgid1+"\n", "", "", "", "", p21dWindow1, "failed") +
		p21dOpSection("c2", p21dOp2ID, p21dSession2, 103, 106, p21dNewTerminal1+"\n", p21dSetuid2+"\n"+p21dSetgid2+"\n", "", "", "", "", p21dNewTerminal1+"\n"+p21dSetuid2+"\n"+p21dSetgid2+"\n", "failed")
	for name, terminals := range map[string]string{
		"same operation id in both windows":                       sameOp,
		"same session id in both windows":                         sameSession,
		"the same AVC record for both terminals (misattribution)": sameTerminal,
	} {
		dir := p21dWriteEvidence(t, strings.Join(p21dGreenMatrix(), "\n")+"\n",
			strings.Join(p21dGreenAV(), "\n")+"\n", terminals, p21dGreenRawWindows())
		line, rc := p21dRunEvaluator(t, dir)
		if rc == 0 || !strings.Contains(line, "DECISION=P21D-FAIL") {
			t.Errorf("%s must decide FAIL, got rc=%d: %s", name, rc, line)
		}
	}
}

// TestR7P21DVerdictEliminatedShapeConfinedToSecondWindowFails proves the
// eliminated-shape check is PER OPERATION: the P21-B { read open } shape
// present ONLY in the second operation's window (both as an attributed
// record and via the whole-window control section) decides FAIL with
// OPEN-COMPLETION=live.
func TestR7P21DVerdictEliminatedShapeConfinedToSecondWindowFails(t *testing.T) {
	window2WithOld := p21dWindow2 + p21dOldTerminal + "\n"
	op2WithOld := strings.Replace(p21dOpSection("c2", p21dOp2ID, p21dSession2, 103, 107, p21dNewTerminal2+"\n", p21dSetuid2+"\n"+p21dSetgid2+"\n", "", "", "", "", window2WithOld, "failed"),
		"-- P21-B terminal (devnode_t:file { read open }; the ELIMINATED shape) --\n",
		"-- P21-B terminal (devnode_t:file { read open }; the ELIMINATED shape) --\n"+p21dOldTerminal+"\n", 1)
	terminals := p21dOpSection("c1", p21dOp1ID, p21dSession1, 100, 103, p21dNewTerminal1+"\n", p21dSetuid1+"\n"+p21dSetgid1+"\n", "", "", "", "", p21dWindow1, "failed") + op2WithOld
	dir := p21dWriteEvidence(t, strings.Join(p21dGreenMatrix(), "\n")+"\n",
		strings.Join(p21dGreenAV(), "\n")+"\n", terminals,
		map[string]string{"c1": p21dWindow1, "c2": window2WithOld, "inter": ""})
	line, rc := p21dRunEvaluator(t, dir)
	if rc == 0 || !strings.Contains(line, "DECISION=P21D-FAIL") {
		t.Errorf("the eliminated shape confined to the second window must decide FAIL, got rc=%d: %s", rc, line)
	}
	if got := p21dField(t, line, "OPEN-COMPLETION"); got != "live" {
		t.Errorf("OPEN-COMPLETION must be live, got %q", got)
	}
}

// TestR7P21DVerdictEliminatedMountonShapeFails proves the P21-C mounton
// terminal is an ELIMINATED shape of the P21-D stage: with the singleton
// granted, its reappearance in EITHER operation's window — attributed or
// via the whole-window control section — decides FAIL
// (MOUNTON-TERMINAL-LIVE, OPEN-COMPLETION=live).
func TestR7P21DVerdictEliminatedMountonShapeFails(t *testing.T) {
	window1WithOld := p21dWindow1 + p21dOldMounton1 + "\n"
	op1WithOld := strings.Replace(p21dOpSection("c1", p21dOp1ID, p21dSession1, 100, 104, p21dNewTerminal1+"\n", p21dSetuid1+"\n"+p21dSetgid1+"\n", "", "", "", "", window1WithOld, "failed"),
		"-- P21-C terminal (devnode_t:file mounton; the ELIMINATED shape) --\n",
		"-- P21-C terminal (devnode_t:file mounton; the ELIMINATED shape) --\n"+p21dOldMounton1+"\n", 1)
	terminals := op1WithOld + p21dOpSection("c2", p21dOp2ID, p21dSession2, 104, 107, p21dNewTerminal2+"\n", p21dSetuid2+"\n"+p21dSetgid2+"\n", "", "", "", "", p21dWindow2, "failed")
	dir := p21dWriteEvidence(t, strings.Join(p21dGreenMatrix(), "\n")+"\n",
		strings.Join(p21dGreenAV(), "\n")+"\n", terminals,
		map[string]string{"c1": window1WithOld, "c2": p21dWindow2, "inter": ""})
	line, rc := p21dRunEvaluator(t, dir)
	if rc == 0 || !strings.Contains(line, "DECISION=P21D-FAIL") {
		t.Errorf("the eliminated P21-C mounton shape must decide FAIL, got rc=%d: %s", rc, line)
	}
	if got := p21dField(t, line, "OPEN-COMPLETION"); got != "live" {
		t.Errorf("OPEN-COMPLETION must be live, got %q", got)
	}
}

// TestR7P21DVerdictZeroNewlineGrepArtifactFailsClosed pins the fail-closed
// behavior on the degenerate matrix shapes the P21-B corrective round
// documented (the "0\n0" grep artifact, an empty file, garbage).
func TestR7P21DVerdictZeroNewlineGrepArtifactFailsClosed(t *testing.T) {
	for name, matrix := range map[string]string{
		"the 0-newline-0 grep artifact": "0\n0\n",
		"empty file":                    "",
		"garbage only":                  "grep: no matches\n",
	} {
		dir := p21dWriteEvidence(t, matrix, strings.Join(p21dGreenAV(), "\n")+"\n", p21dGreenTerminals(), p21dGreenRawWindows())
		line, rc := p21dRunEvaluator(t, dir)
		if rc == 0 || strings.Contains(line, "DECISION=P21D-MEASURED") || strings.Contains(line, "SCOPE=six-names-ok") {
			t.Errorf("mutation %q must fail closed (no MEASURED, no six-names-ok), got rc=%d: %s", name, rc, line)
		}
	}
}

// TestR7P21DVerdictMatrixMutationsFailClosed proves every matrix
// irregularity fails closed (never MEASURED).
func TestR7P21DVerdictMatrixMutationsFailClosed(t *testing.T) {
	rows := p21dGreenMatrix()
	find := func(name, src string) int {
		for i, r := range rows {
			if strings.Contains(r, "x file ["+name+"] ->") && strings.Contains(r, src) {
				return i
			}
		}
		return -1
	}
	mutations := []struct {
		name   string
		mutate func([]string) []string
	}{
		{"missing c2/tty row", func(r []string) []string {
			i := find("tty", p21dC2)
			return append(r[:i:i], r[i+1:]...)
		}},
		{"duplicated c1/zero row", func(r []string) []string {
			i := find("zero", p21dC1)
			return append(append(r[:i:i], r[i]), r[i:]...)
		}},
		{"wrong result: c1/null keeps runc_memfd_t", func(r []string) []string {
			i := find("null", p21dC1)
			out := append([]string(nil), r...)
			out[i] = p21dCreateRow(p21dC1, "null", p21dMemfd)
			return out
		}},
		{"arbitrary name diverted to devnode_t", func(r []string) []string {
			i := find("someothername", p21dC1)
			out := append([]string(nil), r...)
			out[i] = p21dCreateRow(p21dC1, "someothername", p21dDevnode)
			return out
		}},
		{"unparseable line injected", func(r []string) []string {
			return append(r, "CREATE broken matrix line")
		}},
	}
	for _, mut := range mutations {
		mutated := mut.mutate(append([]string(nil), rows...))
		dir := p21dWriteEvidence(t, strings.Join(mutated, "\n")+"\n",
			strings.Join(p21dGreenAV(), "\n")+"\n", p21dGreenTerminals(), p21dGreenRawWindows())
		line, rc := p21dRunEvaluator(t, dir)
		if rc == 0 || strings.Contains(line, "DECISION=P21D-MEASURED") {
			t.Errorf("mutation %q must fail closed, got rc=%d: %s", mut.name, rc, line)
		}
	}
}

// TestR7P21DVerdictAVMutationsFailClosed proves the AV-matrix branches for
// the P21-C shape: the { read open } pair must be EXACTLY granted for both
// operation categories, every other permission must stay DENIED, the
// unconfined surface must stay all-DENY, the associate rows must stay
// unchanged, and missing/duplicated/unparseable rows fail closed.
func TestR7P21DVerdictAVMutationsFailClosed(t *testing.T) {
	green := strings.Join(p21dGreenAV(), "\n") + "\n"
	mutations := []struct {
		name   string
		mutate func(string) string
	}{
		{"c1 pair member read DENIED", func(p string) string {
			return strings.Replace(p, p21dAVFilePerm("read", "ALLOW", "0x8000a"), p21dAVFilePerm("read", "DENY", "0x80008"), 1)
		}},
		{"c2 pair member open DENIED", func(p string) string {
			return strings.Replace(p, p21dAVFilePerm("open", "ALLOW", "0x8000a"), p21dAVFilePerm("open", "DENY", "0xa"), 1)
		}},
		{"c1 mounton DENIED (the P21-D rung missing from the loaded policy)", func(p string) string {
			return strings.Replace(p, p21dAVFilePerm("mounton", "ALLOW", "0x8000a"), p21dAVFilePerm("mounton", "DENY", "0x8000a"), 1)
		}},
		{"c1 write ALLOW (the rejected content authority)", func(p string) string {
			return strings.Replace(p, p21dAVFilePerm("write", "DENY", "0x8000a"), p21dAVFilePerm("write", "ALLOW", "0x8000a"), 1)
		}},
		{"c2 setattr ALLOW", func(p string) string {
			return strings.Replace(p, p21dAVFilePerm("setattr", "DENY", "0x8000a"), p21dAVFilePerm("setattr", "ALLOW", "0x8000a"), 1)
		}},
		{"unconfined read ALLOW", func(p string) string {
			return strings.Replace(p, p21dAVFilePerm("read", "DENY", "0x0"), p21dAVFilePerm("read", "ALLOW", "0x2"), 1)
		}},
		{"runc_memfd associate flipped to ALLOW", func(p string) string {
			return strings.Replace(p, "  associate DENY (allowed=0x0 decided=0xffffffff)",
				"  associate ALLOW (allowed=0x80 decided=0xffffffff)", 1)
		}},
		{"devnode associate flipped to DENY", func(p string) string {
			return strings.Replace(p, "  associate ALLOW (allowed=0x80 decided=0xffffffff)",
				"  associate DENY (allowed=0x0 decided=0xffffffff)", 1)
		}},
		{"missing c2/lock row", func(p string) string {
			return strings.Replace(p, p21dAVFilePerm("lock", "DENY", "0x8000a"), "", 1)
		}},
		{"duplicated c1/create row", func(p string) string {
			needle := p21dAVFilePerm("create", "ALLOW", "0x8000a")
			return strings.Replace(p, needle, needle+"\n"+needle, 1)
		}},
		{"unparseable AV row injected", func(p string) string {
			return p + "  write MAYBE\n"
		}},
	}
	for _, mut := range mutations {
		dir := p21dWriteEvidence(t, strings.Join(p21dGreenMatrix(), "\n")+"\n", mut.mutate(green), p21dGreenTerminals(), p21dGreenRawWindows())
		line, rc := p21dRunEvaluator(t, dir)
		if rc == 0 || strings.Contains(line, "DECISION=P21D-MEASURED") {
			t.Errorf("mutation %q must fail closed, got rc=%d: %s", mut.name, rc, line)
		}
	}
}

// TestR7P21DVerdictNextTerminalMutationsFailClosed proves the strict
// next-terminal matcher per operation: a corrupted terminal record in
// EITHER window (permissive=1, unconfined source, foreign comm, the
// granted shape, a cap_userns downgrade) removes that operation's proof
// and decides BLOCKED; the whole-flow failure shape decides FAIL.
func TestR7P21DVerdictNextTerminalMutationsFailClosed(t *testing.T) {
	mutations := []struct {
		name         string
		corrupt      func(string) string
		wantDECISION string
	}{
		{"terminal records corrupted to permissive=1", func(p string) string {
			return strings.ReplaceAll(p, " permissive=0", " permissive=1")
		}, "P21D-BLOCKED"},
		{"the second operation's terminal record removed (only the first proves its own)", func(p string) string {
			return strings.ReplaceAll(p, p21dNewTerminal2+"\n", "")
		}, "P21D-BLOCKED"},
		{"terminal records corrupted to the eliminated P21-B shape", func(p string) string {
			return strings.ReplaceAll(p,
				"tcontext=system_u:object_r:device_t:s0 tclass=chr_file",
				"tcontext=system_u:object_r:docker_helper_devnode_t:s0 tclass=file")
		}, "P21D-FAIL"},
		{"terminal records corrupted to the eliminated P21-C mounton shape", func(p string) string {
			out := strings.ReplaceAll(p,
				"tcontext=system_u:object_r:device_t:s0 tclass=chr_file",
				"tcontext=system_u:object_r:docker_helper_devnode_t:s0 tclass=file")
			return strings.ReplaceAll(out, "denied  { read open }", "denied  { mounton }")
		}, "P21D-FAIL"},
		{"terminal records downgraded to cap_userns", func(p string) string {
			out := strings.ReplaceAll(p, "denied  { read open }", "denied  { setuid }")
			return strings.ReplaceAll(out,
				"tcontext=system_u:object_r:device_t:s0 tclass=chr_file",
				"tcontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tclass=cap_userns")
		}, "P21D-BLOCKED"},
		{"terminal records corrupted to a foreign comm", func(p string) string {
			return strings.ReplaceAll(p, `comm="runc:[2:INIT]" path="/var/lib`, `comm="buildkit-runc" path="/var/lib`)
		}, "P21D-BLOCKED"},
	}
	for _, mut := range mutations {
		mutated := mut.corrupt(p21dGreenTerminals())
		if mutated == p21dGreenTerminals() {
			t.Fatalf("mutation %q must corrupt at least one record", mut.name)
		}
		// The corruption is applied to the raw window artifacts too, so the
		// evidence stays internally consistent and the next-terminal
		// matcher itself is what must fail closed.
		raw := p21dGreenRawWindows()
		for tag, content := range raw {
			raw[tag] = mut.corrupt(content)
			if tag == "inter" && raw[tag] != "" && content == "" {
				t.Fatalf("mutation %q must not fabricate inter-window records", mut.name)
			}
		}
		dir := p21dWriteEvidence(t, strings.Join(p21dGreenMatrix(), "\n")+"\n",
			strings.Join(p21dGreenAV(), "\n")+"\n", mutated, raw)
		line, rc := p21dRunEvaluator(t, dir)
		if rc == 0 || !strings.Contains(line, "DECISION="+mut.wantDECISION) {
			t.Errorf("mutation %q must decide %s, got rc=%d: %s", mut.name, mut.wantDECISION, rc, line)
		}
	}
}

// TestR7P21DVerdictSectionHeaderIntegrityFailClosed proves the header
// recognition is whole-line and per-operation: a missing operation header
// decides BLOCKED, a duplicated operation header decides FAIL, a missing
// control header inside ONE section decides BLOCKED, a corrupted (not
// whole-line) header decides BLOCKED.
func TestR7P21DVerdictSectionHeaderIntegrityFailClosed(t *testing.T) {
	green := p21dGreenTerminals()
	missingOp2 := green[:strings.Index(green, "== operation c2 ")]
	dir := p21dWriteEvidence(t, strings.Join(p21dGreenMatrix(), "\n")+"\n",
		strings.Join(p21dGreenAV(), "\n")+"\n", missingOp2, p21dGreenRawWindows())
	line, rc := p21dRunEvaluator(t, dir)
	if rc == 0 || !strings.Contains(line, "DECISION=P21D-BLOCKED") {
		t.Errorf("a missing second operation header must decide BLOCKED, got rc=%d: %s", rc, line)
	}
	duplicatedOp1 := green + "== operation c1 op_" + p21dOp1ID + " session " + p21dSession1 + " ==\n"
	dir = p21dWriteEvidence(t, strings.Join(p21dGreenMatrix(), "\n")+"\n",
		strings.Join(p21dGreenAV(), "\n")+"\n", duplicatedOp1, p21dGreenRawWindows())
	line, rc = p21dRunEvaluator(t, dir)
	if rc == 0 || !strings.Contains(line, "DECISION=P21D-FAIL") {
		t.Errorf("a duplicated operation header must decide FAIL, got rc=%d: %s", rc, line)
	}
	missingControl := strings.Replace(green,
		"-- P20 terminal (runc_memfd_t:file create) --\n", "", 1)
	dir = p21dWriteEvidence(t, strings.Join(p21dGreenMatrix(), "\n")+"\n",
		strings.Join(p21dGreenAV(), "\n")+"\n", missingControl, p21dGreenRawWindows())
	line, rc = p21dRunEvaluator(t, dir)
	if rc == 0 || !strings.Contains(line, "DECISION=P21D-BLOCKED") {
		t.Errorf("a missing control header (both sections) must decide BLOCKED, got rc=%d: %s", rc, line)
	}
	corruptedHeader := strings.Replace(green,
		"== operation c1 op_"+p21dOp1ID+" session "+p21dSession1+" ==\n",
		"X== operation c1 op_"+p21dOp1ID+" session "+p21dSession1+" ==\n", 1)
	dir = p21dWriteEvidence(t, strings.Join(p21dGreenMatrix(), "\n")+"\n",
		strings.Join(p21dGreenAV(), "\n")+"\n", corruptedHeader, p21dGreenRawWindows())
	line, rc = p21dRunEvaluator(t, dir)
	if rc == 0 || !strings.Contains(line, "DECISION=P21D-BLOCKED") {
		t.Errorf("a corrupted (not whole-line) operation header must decide BLOCKED, got rc=%d: %s", rc, line)
	}
}

// TestR7P21DVerdictMissingEvidenceFilesBlock pins the file-level
// fail-closed branch, including the raw capture artifacts.
func TestR7P21DVerdictMissingEvidenceFilesBlock(t *testing.T) {
	for _, name := range []string{
		"create-matrix-before.log", "av-matrix-before.log", "p21d-terminals.log",
		"avc-window-c1.log", "avc-window-c2.log", "inter-window.log",
	} {
		broken := p21dGreenDir(t)
		if err := os.Remove(filepath.Join(broken, name)); err != nil {
			t.Fatal(err)
		}
		line, rc := p21dRunEvaluator(t, broken)
		if rc == 0 || !strings.Contains(line, "DECISION=P21D-BLOCKED") {
			t.Errorf("missing %q must decide BLOCKED, got rc=%d: %s", name, rc, line)
		}
	}
	line, rc := p21dRunEvaluator(t, t.TempDir())
	if rc == 0 || !strings.Contains(line, "DECISION=P21D-BLOCKED") {
		t.Errorf("an empty evidence directory must decide BLOCKED, got rc=%d: %s", rc, line)
	}
}

// TestR7P21DVerdictCaptureIntegrityFailClosed proves the revision-3
// capture-integrity branches: an unproven identity checkpoint or drain
// outcome, an actual/expected mismatch, a raw window artifact that does
// not corroborate the section (wrong line count, missing cited record,
// an unaccounted runc-init record, a hidden misattribution, the
// eliminated shape) can never decide MEASURED.
func TestR7P21DVerdictCaptureIntegrityFailClosed(t *testing.T) {
	stray2 := `type=AVC msg=audit(1793789899.003:2002): avc:  denied  { getattr } for  pid=4243 comm="runc:[2:INIT]" path="/tmp/y" dev="vda3" ino=2 scontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tcontext=system_u:object_r:tmp_t:s0 tclass=file permissive=0`
	greenC1 := p21dOpSection("c1", p21dOp1ID, p21dSession1, 100, 103, p21dNewTerminal1+"\n", p21dSetuid1+"\n"+p21dSetgid1+"\n", "", "", "", "", p21dWindow1, "failed")
	greenInter := p21dInterSection(103, 103, "")
	c2 := func() string {
		return p21dOpSection("c2", p21dOp2ID, p21dSession2, 103, 106, p21dNewTerminal2+"\n", p21dSetuid2+"\n"+p21dSetgid2+"\n", "", "", "", "", p21dWindow2, "failed")
	}
	c2Window4 := func(extra string) string {
		// A c2 section consistent with a FOUR-record raw window: the
		// boundary accounting is shifted to match the fabricated bytes.
		out := strings.Replace(c2(), "after=106\n", "after=107\n", 1)
		out = strings.Replace(out, "expected=3\n", "expected=4\n", 1)
		return strings.Replace(out, "actual=3\n", "actual=4\n", 1) + extra
	}
	mutations := []struct {
		name string
		text string
		raw  map[string]string
		want string
	}{
		{"actual does not match the boundary arithmetic",
			greenC1 + strings.Replace(c2(), "actual=3", "actual=2", 1) + greenInter,
			p21dGreenRawWindows(), "P21D-BLOCKED"},
		{"capture source state not proven",
			greenC1 + strings.Replace(c2(), "source=proven", "source=unproven", 1) + greenInter,
			p21dGreenRawWindows(), "P21D-BLOCKED"},
		{"identity checkpoint not proven",
			greenC1 + strings.Replace(c2(), "identity-extract-pre=proven", "identity-extract-pre=unproven:path-replaced(pinned=95:1,path=95:2)", 1) + greenInter,
			p21dGreenRawWindows(), "P21D-BLOCKED"},
		{"window drain not ok",
			greenC1 + strings.Replace(c2(), "window-drain=ok", "window-drain=failed:read-error", 1) + greenInter,
			p21dGreenRawWindows(), "P21D-BLOCKED"},
		{"raw window holds fewer lines than the claimed capture",
			greenC1 + c2() + greenInter,
			map[string]string{"c1": p21dWindow1, "c2": p21dNewTerminal2 + "\n" + p21dSetuid2 + "\n", "inter": ""},
			"P21D-BLOCKED"},
		{"a cited record is absent from the raw window",
			greenC1 + c2() + greenInter,
			map[string]string{"c1": p21dWindow1, "c2": p21dNewTerminal2 + "\n" + p21dSetgid2 + "\nhost noise\n", "inter": ""},
			"P21D-BLOCKED"},
		{"the raw window carries an unaccounted runc-init record",
			greenC1 + c2Window4("") + greenInter,
			map[string]string{"c1": p21dWindow1, "c2": p21dWindow2 + stray2 + "\n", "inter": ""},
			"P21D-BLOCKED"},
		{"the raw window carries a hidden misattribution",
			greenC1 + c2Window4("") + greenInter,
			map[string]string{"c1": p21dWindow1, "c2": p21dWindow2 + p21dOldMounton1 + "\n", "inter": ""},
			"P21D-FAIL"},
		{"the raw window carries the eliminated P21-B shape",
			greenC1 + c2Window4("") + greenInter,
			map[string]string{"c1": p21dWindow1, "c2": p21dWindow2 + p21dOldTerminal + "\n", "inter": ""},
			"P21D-FAIL"},
		{"the raw window carries the eliminated P21-C mounton shape",
			greenC1 + c2Window4("") + greenInter,
			map[string]string{"c1": p21dWindow1, "c2": p21dWindow2 + p21dOldMounton1 + "\n", "inter": ""},
			"P21D-FAIL"},
		{"the raw window carries an associate denial",
			greenC1 + c2Window4("") + greenInter,
			map[string]string{"c1": p21dWindow1, "c2": p21dWindow2 + p21dAssociateDenial + "\n", "inter": ""},
			"P21D-FAIL"},
	}
	for _, mut := range mutations {
		dir := p21dWriteEvidence(t, strings.Join(p21dGreenMatrix(), "\n")+"\n",
			strings.Join(p21dGreenAV(), "\n")+"\n", mut.text, mut.raw)
		line, rc := p21dRunEvaluator(t, dir)
		if rc == 0 || !strings.Contains(line, "DECISION="+mut.want) {
			t.Errorf("mutation %q must decide %s, got rc=%d: %s", mut.name, mut.want, rc, line)
		}
	}
	// A missing raw artifact decides BLOCKED.
	broken := p21dGreenDir(t)
	if err := os.Remove(filepath.Join(broken, "avc-window-c2.log")); err != nil {
		t.Fatal(err)
	}
	line, rc := p21dRunEvaluator(t, broken)
	if rc == 0 || !strings.Contains(line, "DECISION=P21D-BLOCKED") {
		t.Errorf("a missing raw window artifact must decide BLOCKED, got rc=%d: %s", rc, line)
	}
}

// TestR7P21DVerdictInterWindowCaptureIntegrityFailClosed proves the
// inter-window capture is held to the SAME integrity contract: an
// unproven checkpoint, an actual/expected mismatch, or a raw artifact
// that does not corroborate the section decides BLOCKED; a faithful
// inter-window capture with real host-noise records still measures.
func TestR7P21DVerdictInterWindowCaptureIntegrityFailClosed(t *testing.T) {
	noise := "host noise record one\nhost noise record two\nhost noise record three\n"
	c1 := p21dOpSection("c1", p21dOp1ID, p21dSession1, 100, 103, p21dNewTerminal1+"\n", p21dSetuid1+"\n"+p21dSetgid1+"\n", "", "", "", "", p21dWindow1, "failed")
	c2 := p21dOpSection("c2", p21dOp2ID, p21dSession2, 106, 109, p21dNewTerminal2+"\n", p21dSetuid2+"\n"+p21dSetgid2+"\n", "", "", "", "", p21dWindow2, "failed")
	// Positive control: a proven inter-window capture with three real
	// host-noise records, fully accounted, still measures.
	interGreen := p21dInterSection(103, 106, noise)
	green := c1 + c2 + interGreen
	dir := p21dWriteEvidence(t, strings.Join(p21dGreenMatrix(), "\n")+"\n",
		strings.Join(p21dGreenAV(), "\n")+"\n", green,
		map[string]string{"c1": p21dWindow1, "c2": p21dWindow2, "inter": noise})
	if line, rc := p21dRunEvaluator(t, dir); rc != 0 || !strings.Contains(line, "DECISION=P21D-MEASURED") {
		t.Fatalf("a proven inter-window capture with accounted noise must decide MEASURED, got rc=%d: %s", rc, line)
	}
	mutations := []struct {
		name string
		text string
		raw  map[string]string
		want string
	}{
		{"inter capture not proven", c1 + c2 + strings.Replace(interGreen, "source=proven", "source=unproven", 1),
			map[string]string{"c1": p21dWindow1, "c2": p21dWindow2, "inter": ""}, "P21D-BLOCKED"},
		{"inter identity checkpoint not proven", c1 + c2 + strings.Replace(interGreen, "identity-gap-pre=proven", "identity-gap-pre=unproven:path-replaced(pinned=95:1,path=95:2)", 1),
			map[string]string{"c1": p21dWindow1, "c2": p21dWindow2, "inter": noise}, "P21D-BLOCKED"},
		{"inter actual does not match expected", c1 + c2 + strings.Replace(interGreen, "actual=3\n", "actual=2\n", 1),
			map[string]string{"c1": p21dWindow1, "c2": p21dWindow2, "inter": noise}, "P21D-BLOCKED"},
		{"raw inter artifact holds fewer lines than claimed", green,
			map[string]string{"c1": p21dWindow1, "c2": p21dWindow2, "inter": "host noise record one\n"}, "P21D-BLOCKED"},
	}
	for _, mut := range mutations {
		dir = p21dWriteEvidence(t, strings.Join(p21dGreenMatrix(), "\n")+"\n",
			strings.Join(p21dGreenAV(), "\n")+"\n", mut.text, mut.raw)
		line, rc := p21dRunEvaluator(t, dir)
		if rc == 0 || !strings.Contains(line, "DECISION="+mut.want) {
			t.Errorf("%s must decide %s, got rc=%d: %s", mut.name, mut.want, rc, line)
		}
	}
	// A missing raw inter artifact decides BLOCKED.
	broken := p21dGreenDir(t)
	if err := os.Remove(filepath.Join(broken, "inter-window.log")); err != nil {
		t.Fatal(err)
	}
	line, rc := p21dRunEvaluator(t, broken)
	if rc == 0 || !strings.Contains(line, "DECISION=P21D-BLOCKED") {
		t.Errorf("a missing raw inter-window artifact must decide BLOCKED, got rc=%d: %s", rc, line)
	}
}

// TestR7P21DGuestCaptureSelftest runs the guest harness's own capture
// battery: the REAL production capture functions
// (audit_open/audit_identity/audit_drain/capture_begin/capture_end)
// against synthetic audit sources, covering the review's RED/GREEN
// scenarios on the actual evidence-production path — append-only growth
// stays valid, while torn records, read errors, same-inode truncation,
// and rename/replacement (fewer, equal, or more lines, including between
// the extraction checkpoints) are all fail-closed, for the operation
// windows AND the inter-window capture.
func TestR7P21DGuestCaptureSelftest(t *testing.T) {
	dir := t.TempDir()
	out, err := exec.Command("bash", "scripts/release-2.4-r7-p21d-guest.sh",
		"--capture-selftest", dir).CombinedOutput()
	if err != nil {
		t.Fatalf("capture selftest failed to run: %v\n%s", err, out)
	}
	kv := func(name string) map[string]string {
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
	expect := func(name string, want map[string]string) {
		t.Helper()
		got := kv(name)
		for k, v := range want {
			if strings.HasPrefix(v, "~") {
				if !strings.Contains(got[k], strings.TrimPrefix(v, "~")) {
					t.Errorf("%s: %s = %q, want it to contain %q", name, k, got[k], strings.TrimPrefix(v, "~"))
				}
				continue
			}
			if got[k] != v {
				t.Errorf("%s: %s = %q, want %q (full result: %v)", name, k, got[k], v, got)
			}
		}
	}
	// 1. Normal append-only growth: proven, and actual is measured from
	//    the extracted file (5 records), not the arithmetic alone.
	expect("append-only-green.boundaries", map[string]string{
		"identity-begin-pre": "proven", "identity-begin-post": "proven",
		"identity-extract-pre": "proven", "identity-extract-post": "proven",
		"pre-drain": "ok", "window-drain": "ok",
		"before": "3", "after": "8", "expected": "5", "actual": "5",
		"source": "proven",
	})
	if window, err := os.ReadFile(filepath.Join(dir, "evidence-s1", "avc-window-s1.log")); err != nil {
		t.Fatal(err)
	} else if n := p21dWindowLines(string(window)); n != 5 {
		t.Errorf("the green window artifact must hold the 5 drained records, got %d lines", n)
	}
	// 1b. The inter-window capture on the SAME pinned flow: proven.
	expect("inter-window-green.inter", map[string]string{
		"identity-gap-pre": "proven", "identity-gap-post": "proven",
		"inter-drain": "ok", "gap-after": "8", "gap-before": "12",
		"expected": "4", "actual": "4", "source": "proven",
	})
	// 2. Torn record: the capture fails closed.
	expect("torn-record.boundaries", map[string]string{
		"source": "unproven", "window-drain": "failed:partial-record",
	})
	// 3. Read error through the descriptor: the capture fails closed.
	expect("read-error.boundaries", map[string]string{
		"source": "unproven", "pre-drain": "failed:read-error",
	})
	// 4. Truncate WITHOUT an inode change: detected by the consumed-cursor
	//    size check.
	expect("truncate-same-inode.boundaries", map[string]string{
		"source": "unproven", "identity-extract-pre": "~unproven:truncated",
	})
	// 5/6/7. Rename/replacement with FEWER, EQUAL, or MORE lines: the
	//        inode mismatch decides, never the line count. The replacement
	//        fixtures themselves are verified BEFORE the replacement:
	//        1, 8, and 12 records respectively, newline-terminated.
	for scenario, count := range map[string]string{
		"replace-fewer": "1", "replace-same": "8", "replace-more": "12",
	} {
		fixture := kv(scenario + ".fixture")
		if fixture["replacement-records"] != count {
			t.Errorf("%s: the replacement fixture must carry %s records before the replacement, got %q", scenario, count, fixture["replacement-records"])
		}
		if fixture["replacement-newline-terminated"] != "yes" {
			t.Errorf("%s: the replacement fixture must be newline-terminated, got %q", scenario, fixture["replacement-newline-terminated"])
		}
		expect(scenario+".boundaries", map[string]string{
			"identity-begin-pre":   "proven",
			"identity-extract-pre": "~unproven:path-replaced",
			"source":               "unproven",
		})
	}
	// 8. Replacement DURING the extraction (between the extraction
	//    checkpoints): the pinned descriptor still delivers the drained
	//    bytes, but the capture cannot be proven afterwards.
	expect("replace-during-extract.steps", map[string]string{
		"identity-extract-pre":  "proven",
		"window-drain":          "ok",
		"identity-extract-post": "~unproven:path-replaced",
	})
	// 10. An incomplete inter-window capture: fails closed.
	expect("inter-window-unsound.inter", map[string]string{
		"source": "unproven", "identity-gap-pre": "~unproven:path-replaced",
	})
}

// TestR7P21DGuestEarlyAVCOrdering proves the window opens BEFORE the build
// is admitted: an AVC raised after POST /build is sent but before the HTTP
// 201 response exists must land in THIS operation's raw window artifact —
// never in the pre-build drain, never in the inter-window region — and the
// evidence the mock run produced must be decisive in the evaluator: with
// the eliminated { read open } shape it decides FAIL (OPEN-COMPLETION=
// live), with a normal next terminal and no regressions it decides
// MEASURED. The transport is a controlled mock curl seam inside the guest
// harness's selftest battery (deterministic, no sleeps); capture_begin,
// capture_end, classify_window, and the terminals composition are the
// production path verbatim. The P21-D evaluator treats BOTH eliminated
// devnode shapes ({ read open } and { mounton }) as live terminals and a
// non-eliminated shape as the observed next terminal.
func TestR7P21DGuestEarlyAVCOrdering(t *testing.T) {
	dir := t.TempDir()
	out, err := exec.Command("bash", "scripts/release-2.4-r7-p21d-guest.sh",
		"--capture-selftest", dir).CombinedOutput()
	if err != nil {
		t.Fatalf("capture selftest failed to run: %v\n%s", err, out)
	}
	kv := func(path string) map[string]string {
		t.Helper()
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("file %s missing: %v\n%s", path, err, out)
		}
		m := make(map[string]string)
		for _, l := range strings.Split(string(raw), "\n") {
			if k, v, ok := strings.Cut(l, "="); ok && k != "" {
				m[k] = v
			}
		}
		return m
	}
	for name, want := range map[string]struct{ decision, openCompletion string }{
		"early-avc-old":  {"P21D-FAIL", "live"},
		"early-avc-next": {"P21D-MEASURED", "eliminated"},
	} {
		t.Run(name, func(t *testing.T) {
			ev := filepath.Join(dir, "evidence-"+name)
			summary := kv(filepath.Join(dir, "results", name+".summary"))
			op1 := summary["op1"]
			if op1 == "" {
				t.Fatal("the selftest summary carries no op1 id")
			}
			// The producer's own evidence is fed to the evaluator verbatim;
			// only the two policy matrices come from the green fixtures
			// (the mock run does not run sesearch — it exercises capture
			// and ordering, not the policy inventory).
			if err := os.WriteFile(filepath.Join(ev, "create-matrix-before.log"),
				[]byte(strings.Join(p21dGreenMatrix(), "\n")+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(ev, "av-matrix-before.log"),
				[]byte(strings.Join(p21dGreenAV(), "\n")+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			// The early AVC (a runc-init record carrying THIS operation's
			// op path) is present in BOTH operation windows...
			for _, pair := range []struct{ tag, opid string }{{"c1", op1}, {"c2", summary["op2"]}} {
				raw, err := os.ReadFile(filepath.Join(ev, "avc-window-"+pair.tag+".log"))
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(string(raw), `comm="runc:[2:INIT]"`) ||
					!strings.Contains(string(raw), "ops/op_"+pair.opid+"/") {
					t.Fatalf("the early AVC must be captured in avc-window-%s.log, got: %q", pair.tag, string(raw))
				}
			}
			// ...and absent from the pre-build drain and the inter-window
			// region (the accounting there must never absorb it).
			for _, file := range []string{"pre-drain-c1.log", "inter-window.log"} {
				raw, err := os.ReadFile(filepath.Join(ev, file))
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(raw), `comm="runc:[2:INIT]"`) {
					t.Errorf("%s must not carry the early AVC (a runc-init record), got: %q", file, string(raw))
				}
			}
			// Both captures are proven with the early AVC counted.
			for _, tag := range []string{"c1", "c2"} {
				b := kv(filepath.Join(ev, "window-boundaries-"+tag+".log"))
				if b["source"] != "proven" || b["actual"] != "1" || b["expected"] != "1" {
					t.Errorf("%s window accounting must be proven with actual=expected=1, got %v", tag, b)
				}
			}
			// The recorded HTTP admission status.
			httpRaw, err := os.ReadFile(filepath.Join(ev, "build-start-c1.http.log"))
			if err != nil {
				t.Fatal(err)
			}
			if strings.TrimSpace(string(httpRaw)) != "201" {
				t.Errorf("the mock admission must record HTTP 201, got %q", string(httpRaw))
			}
			line, rc := p21dRunEvaluator(t, ev)
			if want.decision == "P21D-MEASURED" && rc != 0 {
				t.Fatalf("%s must decide %s (exit 0), got rc=%d: %s", name, want.decision, rc, line)
			}
			if want.decision != "P21D-MEASURED" && rc == 0 {
				t.Fatalf("%s must NOT exit 0 (want %s), got: %s", name, want.decision, line)
			}
			if !strings.Contains(line, "DECISION="+want.decision) {
				t.Fatalf("%s must decide %s, got: %s", name, want.decision, line)
			}
			if got := p21dField(t, line, "OPEN-COMPLETION"); got != want.openCompletion {
				t.Errorf("%s: OPEN-COMPLETION must be %s, got %q", name, want.openCompletion, got)
			}
		})
	}
}

// TestR7P21DVerdictCompletionEvidenceIsMeasured proves the P21-D
// completion alternative: when the singleton lets runc COMPLETE the device
// binds, an operation may run to its own terminal state with no further
// denial — the proven non-overlapping window then IS the attribution for
// the pathless pre-boundary records, and TWO independently proven
// completions decide P21D-MEASURED with the explicit NEXT-TERMINAL=none
// form (admissible ONLY when both operations completed).
func TestR7P21DVerdictCompletionEvidenceIsMeasured(t *testing.T) {
	// Both windows carry ONLY pathless cap_userns self-denials: with no
	// op-path record and no anchorable pid the per-record attribution
	// would be ambiguous — but the operation result proves completion, so
	// the records are window-scoped, not assumed.
	window1Only := p21dSetuid1 + "\n" + p21dSetgid1 + "\n"
	window2Only := p21dSetuid2 + "\n" + p21dSetgid2 + "\n"
	terminals := p21dOpSection("c1", p21dOp1ID, p21dSession1, 100, 102, "", "", "", p21dSetuid1+"\n"+p21dSetgid1+"\n", "", "", window1Only, "succeeded") +
		p21dOpSection("c2", p21dOp2ID, p21dSession2, 102, 104, "", "", "", p21dSetuid2+"\n"+p21dSetgid2+"\n", "", "", window2Only, "succeeded") +
		p21dInterSection(102, 102, "")
	dir := p21dWriteEvidence(t, strings.Join(p21dGreenMatrix(), "\n")+"\n",
		strings.Join(p21dGreenAV(), "\n")+"\n", terminals,
		map[string]string{"c1": window1Only, "c2": window2Only, "inter": ""})
	line, rc := p21dRunEvaluator(t, dir)
	if rc != 0 || !strings.Contains(line, "DECISION=P21D-MEASURED") {
		t.Fatalf("two proven completions must decide P21D-MEASURED, got rc=%d: %s", rc, line)
	}
	if got := p21dField(t, line, "NEXT-TERMINAL"); got != "none" {
		t.Errorf("NEXT-TERMINAL must be the explicit none form, got %q", got)
	}
	if got := p21dField(t, line, "OP1-RESULT"); got != "completed" {
		t.Errorf("OP1-RESULT must be completed, got %q", got)
	}
	if got := p21dField(t, line, "OP2-RESULT"); got != "completed" {
		t.Errorf("OP2-RESULT must be completed, got %q", got)
	}
	// The same shape with a FAILED operation result: no terminal and no
	// completion — BLOCKED (absence of AVCs alone is never a passing
	// outcome).
	terminals = p21dOpSection("c1", p21dOp1ID, p21dSession1, 100, 102, "", "", "", p21dSetuid1+"\n"+p21dSetgid1+"\n", "", "", window1Only, "failed") +
		p21dOpSection("c2", p21dOp2ID, p21dSession2, 102, 104, p21dNewTerminal2+"\n", p21dSetuid2+"\n"+p21dSetgid2+"\n", "", "", "", "", window2Only, "failed") +
		p21dInterSection(102, 102, "")
	dir = p21dWriteEvidence(t, strings.Join(p21dGreenMatrix(), "\n")+"\n",
		strings.Join(p21dGreenAV(), "\n")+"\n", terminals,
		map[string]string{"c1": window1Only, "c2": p21dWindow2, "inter": ""})
	line, rc = p21dRunEvaluator(t, dir)
	if rc == 0 || !strings.Contains(line, "DECISION=P21D-BLOCKED") {
		t.Errorf("a failed operation with no terminal and no completion must decide BLOCKED, got rc=%d: %s", rc, line)
	}
	// A misattributed record stays a positive violation even under a
	// proven completion.
	terminals = p21dOpSection("c1", p21dOp1ID, p21dSession1, 100, 102, "", "", "", p21dSetuid1+"\n"+p21dSetgid1+"\n", "", "", window1Only, "succeeded") +
		p21dOpSection("c2", p21dOp2ID, p21dSession2, 102, 105, "", "", p21dNewTerminal1+"\n", p21dSetuid2+"\n"+p21dSetgid2+"\n", "", "", window2Only+p21dNewTerminal1+"\n", "succeeded") +
		p21dInterSection(102, 102, "")
	dir = p21dWriteEvidence(t, strings.Join(p21dGreenMatrix(), "\n")+"\n",
		strings.Join(p21dGreenAV(), "\n")+"\n", terminals,
		map[string]string{"c1": window1Only, "c2": window2Only + p21dNewTerminal1 + "\n", "inter": ""})
	line, rc = p21dRunEvaluator(t, dir)
	if rc == 0 || !strings.Contains(line, "DECISION=P21D-FAIL") {
		t.Errorf("a misattributed record must decide FAIL even under a proven completion, got rc=%d: %s", rc, line)
	}
}

// TestR7P21DVerdictGateMode pins the driver-side gate: exit 0 iff the
// argument is EXACTLY ONE correctly formed R7-P21D-VERDICT line whose
// first field is the single DECISION=P21D-MEASURED.
func TestR7P21DVerdictGateMode(t *testing.T) {
	gate := func(line string) error {
		return exec.Command("bash", "scripts/release-2.4-r7-p21d-verdict.sh", "--gate", line).Run()
	}
	accepted := "R7-P21D-VERDICT=DECISION=P21D-MEASURED;SCOPE=six-names-ok;OPEN-COMPLETION=eliminated;MEMFD=intact;CROSSOP-CONTENT=closed;NEXT-TERMINAL=<" + p21dNewTerminal1 + ">;OP1-RESULT=terminal;OP2-RESULT=terminal"
	if err := gate(accepted); err != nil {
		t.Errorf("--gate must accept a correctly formed MEASURED verdict line: %v", err)
	}
	completedBoth := "R7-P21D-VERDICT=DECISION=P21D-MEASURED;SCOPE=six-names-ok;OPEN-COMPLETION=eliminated;MEMFD=intact;CROSSOP-CONTENT=closed;NEXT-TERMINAL=none;OP1-RESULT=completed;OP2-RESULT=completed"
	if err := gate(completedBoth); err != nil {
		t.Errorf("--gate must accept the both-completed none form: %v", err)
	}
	for _, bad := range []string{
		"R7-P21D-VERDICT=DECISION=P21D-FAIL;NOTE=DECISION=P21D-MEASURED",
		"R7-P21D-VERDICT=DECISION=P21D-BLOCKED;DECISION=P21D-MEASURED",
		"R7-P21D-VERDICT=DECISION=P21D-MEASURED;DECISION=P21D-FAIL",
		"R7-P21D-VERDICT=DECISION=P21D-BLOCKED;REASON=no-evidence-dir",
		"R7-P21D-VERDICT=SCOPE=six-names-ok",
		"XR7-P21D-VERDICT=DECISION=P21D-MEASURED;SCOPE=six-names-ok",
		"R7-P21D-VERDICTX=DECISION=P21D-MEASURED;SCOPE=six-names-ok",
		"R7-P21D-VERDICT=DECISION=P21D-MEAS",
		"R7-P21D-VERDICT=DECISION=P21D-MEASURED",
		"R7-P21D-VERDICT=DECISION=P21D-MEASURED;SCOPE=six-names-ok",
		"R7-P21D-VERDICT=DECISION=P21D-MEASURED;SCOPE=six-names-ok;;",
		"R7-P21D-VERDICT=DECISION=P21D-MEASURED;SCOPE=six-names-ok;",
		"R7-P21D-VERDICT=DECISION=P21D-MEASURED;SCOPE=six-names-ok;JUNK",
		"R7-P21D-VERDICT=DECISION=P21D-MEASURED;SCOPE=six-names-ok;UNEXPECTED-FIELD=1",
		"R7-P21D-VERDICT=DECISION=P21D-MEASURED;SCOPE=not-established;OPEN-COMPLETION=eliminated;MEMFD=intact;CROSSOP-CONTENT=closed;NEXT-TERMINAL=<type=AVC msg=audit(1.0:1190)>;OP1-RESULT=terminal;OP2-RESULT=terminal",
		"R7-P21D-VERDICT=DECISION=P21D-MEASURED;SCOPE=six-names-ok;OPEN-COMPLETION=live;MEMFD=intact;CROSSOP-CONTENT=closed;NEXT-TERMINAL=<type=AVC msg=audit(1.0:1190)>;OP1-RESULT=terminal;OP2-RESULT=terminal",
		"R7-P21D-VERDICT=DECISION=P21D-MEASURED;SCOPE=six-names-ok;OPEN-COMPLETION=not-established;MEMFD=intact;CROSSOP-CONTENT=closed;NEXT-TERMINAL=<type=AVC msg=audit(1.0:1190)>;OP1-RESULT=terminal;OP2-RESULT=terminal",
		"R7-P21D-VERDICT=DECISION=P21D-MEASURED;SCOPE=six-names-ok;OPEN-COMPLETION=eliminated;MEMFD=regressed;CROSSOP-CONTENT=closed;NEXT-TERMINAL=<type=AVC msg=audit(1.0:1190)>;OP1-RESULT=terminal;OP2-RESULT=terminal",
		"R7-P21D-VERDICT=DECISION=P21D-MEASURED;SCOPE=six-names-ok;OPEN-COMPLETION=eliminated;MEMFD=intact;CROSSOP-CONTENT=open;NEXT-TERMINAL=<type=AVC msg=audit(1.0:1190)>;OP1-RESULT=terminal;OP2-RESULT=terminal",
		"R7-P21D-VERDICT=DECISION=P21D-MEASURED;NEXT-TERMINAL=<(none)>",
		"R7-P21D-VERDICT=DECISION=P21D-MEASURED;NEXT-TERMINAL=<type=AVC line;broken=field>",
		"R7-P21D-VERDICT=DECISION=P21D-MEASURED;SCOPE=six-names-ok;OPEN-COMPLETION=eliminated;MEMFD=intact;CROSSOP-CONTENT=closed",
		// the none form is admissible ONLY when BOTH operations completed
		"R7-P21D-VERDICT=DECISION=P21D-MEASURED;SCOPE=six-names-ok;OPEN-COMPLETION=eliminated;MEMFD=intact;CROSSOP-CONTENT=closed;NEXT-TERMINAL=none;OP1-RESULT=terminal;OP2-RESULT=completed",
		"R7-P21D-VERDICT=DECISION=P21D-MEASURED;SCOPE=six-names-ok;OPEN-COMPLETION=eliminated;MEMFD=intact;CROSSOP-CONTENT=closed;NEXT-TERMINAL=none;OP1-RESULT=completed;OP2-RESULT=terminal",
		"R7-P21D-VERDICT=DECISION=P21D-MEASURED;SCOPE=six-names-ok;OPEN-COMPLETION=eliminated;MEMFD=intact;CROSSOP-CONTENT=closed;NEXT-TERMINAL=none;OP1-RESULT=failed;OP2-RESULT=failed",
		"R7-P21D-VERDICT=DECISION=P21D-MEASURED;SCOPE=six-names-ok;OPEN-COMPLETION=eliminated;MEMFD=intact;CROSSOP-CONTENT=closed;NEXT-TERMINAL=<" + p21dNewTerminal1 + ">;OP1-RESULT=terminal",
		"R7-P21D-VERDICT=DECISION=P21D-MEASURED;SCOPE=six-names-ok;OPEN-COMPLETION=eliminated;MEMFD=intact;CROSSOP-CONTENT=closed;NEXT-TERMINAL=<" + p21dNewTerminal1 + ">;OP1-RESULT=terminal;OP2-RESULT=terminal;OP3-RESULT=terminal",
	} {
		if err := gate(bad); err == nil {
			t.Errorf("--gate must reject %q", bad)
		}
	}
}
