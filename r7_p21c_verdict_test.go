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
// r7-p21c-corrective-2 task): on top of the revision-2 per-operation
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
// evaluator (scripts/release-2.4-r7-p21c-verdict.sh) is the single
// authority for the machine-readable verdict; the P21-B evaluator stays
// untouched as the historical instrument, and no test reimplements its
// semantics.

const (
	p21cC1      = "system_u:system_r:docker_helper_buildkitd_t:s0:c1"
	p21cC2      = "system_u:system_r:docker_helper_buildkitd_t:s0:c2"
	p21cUnconf  = "unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023"
	p21cTmpfs   = "system_u:object_r:tmpfs_t:s0"
	p21cDevnode = "system_u:object_r:docker_helper_devnode_t:s0"
	p21cMemfd   = "system_u:object_r:docker_helper_runc_memfd_t:s0"
	p21cUserTmp = "unconfined_u:object_r:user_tmp_t:s0"
)

// The two independently measured operations of enforcing run 41817339781
// (the REAL operation ids and their recorded per-operation paths).
const (
	p21cOp1ID     = "0fa70c22a486dbbb176540db9115467c"
	p21cOp2ID     = "d298110c0575df75e08e7c479eecf843"
	p21cSession1  = "dhs_1111111111111111111111111111111"
	p21cSession2  = "dhs_2222222222222222222222222222222"
	p21cOp1Rootfs = "/var/lib/docker-helper-builder/ops/op_0fa70c22a486dbbb176540db9115467c/root/runc-native/executor/9ljpl8zdbqwrbx85v3okf4y83/rootfs/dev/null"
	p21cOp2Rootfs = "/var/lib/docker-helper-builder/ops/op_d298110c0575df75e08e7c479eecf843/root/runc-native/executor/p8s0i4imq0adpx6apco1pl9ft/rootfs/dev/null"
)

// p21cDevnodeBasenames is the exact six-basename list the policy diverts
// (runc v1.4.3 AllowedDevices placeholders) — unchanged by P21-C.
var p21cDevnodeBasenames = []string{"null", "zero", "full", "random", "urandom", "tty"}

func p21cCreateRow(src, name, result string) string {
	return "CREATE " + src + " x " + p21cTmpfs + " x file [" + name + "] -> " + result
}

// p21cGreenMatrix returns the required create-decision rows (the P21-B
// transition surface is UNCHANGED by P21-C; the rows use the real probe
// grammar of run 41623047086).
func p21cGreenMatrix() []string {
	var rows []string
	for _, name := range p21cDevnodeBasenames {
		rows = append(rows, p21cCreateRow(p21cC1, name, p21cDevnode))
	}
	for _, name := range p21cDevnodeBasenames {
		rows = append(rows, p21cCreateRow(p21cC2, name, p21cDevnode))
	}
	rows = append(rows,
		p21cCreateRow(p21cC1, "someothername", p21cMemfd),
		p21cCreateRow(p21cC1, "-", p21cMemfd),
		p21cCreateRow(p21cC2, "someothername", p21cMemfd),
		p21cCreateRow(p21cC2, "-", p21cMemfd),
		p21cCreateRow(p21cUnconf, "null", p21cUserTmp),
		p21cCreateRow(p21cUnconf, "-", p21cUserTmp),
	)
	return rows
}

// p21cAVFilePerm is one kernel-AV matrix row in the probe's exact format.
func p21cAVFilePerm(perm, verdict, allowed string) string {
	return "  " + perm + " " + verdict + " (allowed=" + allowed + " decided=0xffffffff)"
}

// p21cGreenAV returns the kernel-AV rows the P21-C candidate policy must
// produce: for BOTH operation categories the devnode_t:file surface is
// create=ALLOW plus the ONE { read open } open-completion pair with every
// other permission DENIED; unconfined stays all-DENY; the three associate
// rows are unchanged from P21-B.
func p21cGreenAV() []string {
	granted := []string{"write", "append", "setattr", "execute", "execute_no_trans", "map", "getattr", "unlink", "rename", "link", "ioctl", "lock"}
	var out []string
	out = append(out, "== buildkitd_t:s0:c1 -> docker_helper_devnode_t:s0 ==")
	out = append(out,
		p21cAVFilePerm("create", "ALLOW", "0x8000a"),
		p21cAVFilePerm("open", "ALLOW", "0x8000a"),
		p21cAVFilePerm("read", "ALLOW", "0x8000a"))
	for _, perm := range granted {
		out = append(out, p21cAVFilePerm(perm, "DENY", "0x8000a"))
	}
	out = append(out, "== CROSS-OP: buildkitd_t:s0:c2 -> docker_helper_devnode_t:s0 ==")
	out = append(out,
		p21cAVFilePerm("create", "ALLOW", "0x8000a"),
		p21cAVFilePerm("open", "ALLOW", "0x8000a"),
		p21cAVFilePerm("read", "ALLOW", "0x8000a"))
	for _, perm := range granted {
		out = append(out, p21cAVFilePerm(perm, "DENY", "0x8000a"))
	}
	out = append(out, "== unconfined_t -> docker_helper_devnode_t:s0 ==")
	for _, perm := range []string{"create", "write", "append", "setattr", "execute", "execute_no_trans", "map", "open", "read", "getattr", "unlink", "rename", "link", "ioctl", "lock"} {
		out = append(out, p21cAVFilePerm(perm, "DENY", "0x0"))
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
	p21cSetuid1  = `type=AVC msg=audit(1793789849.894:1190): avc:  denied  { setuid } for  pid=3353 comm="runc:[2:INIT]" capability=7  scontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tcontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tclass=cap_userns permissive=0`
	p21cSetgid1  = `type=AVC msg=audit(1793789849.894:1191): avc:  denied  { setgid } for  pid=3353 comm="runc:[2:INIT]" capability=6  scontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tcontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tclass=cap_userns permissive=0`
	p21cMounton1 = `type=AVC msg=audit(1793789849.898:1192): avc:  denied  { mounton } for  pid=3353 comm="runc:[2:INIT]" path="` + p21cOp1Rootfs + `" dev="tmpfs" ino=5 scontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tcontext=system_u:object_r:docker_helper_devnode_t:s0 tclass=file permissive=0`
	p21cSetuid2  = `type=AVC msg=audit(1793789851.301:1817): avc:  denied  { setuid } for  pid=3517 comm="runc:[2:INIT]" capability=7  scontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tcontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tclass=cap_userns permissive=0`
	p21cSetgid2  = `type=AVC msg=audit(1793789851.301:1818): avc:  denied  { setgid } for  pid=3517 comm="runc:[2:INIT]" capability=6  scontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tcontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tclass=cap_userns permissive=0`
	p21cMounton2 = `type=AVC msg=audit(1793789851.305:1819): avc:  denied  { mounton } for  pid=3517 comm="runc:[2:INIT]" path="` + p21cOp2Rootfs + `" dev="tmpfs" ino=5 scontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tcontext=system_u:object_r:docker_helper_devnode_t:s0 tclass=file permissive=0`
)

// p21cOldTerminal is the ELIMINATED P21-B shape (the P21-B measured
// terminal of run 41623047086): the exact "denied  { read open }" pair on
// the devnode_t file object, permissive=0, with a per-operation path.
const p21cOldTerminal = `type=AVC msg=audit(1793714070.816:1190): avc:  denied  { read open } for  pid=3288 comm="runc:[2:INIT]" path="` + p21cOp1Rootfs + `" dev="tmpfs" ino=5 scontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tcontext=system_u:object_r:docker_helper_devnode_t:s0 tclass=file permissive=0`

// p21cWindow1/p21cWindow2 are the green raw windows: EXACTLY the bytes the
// producer drained through the pinned descriptor for each operation.
var (
	p21cWindow1 = p21cMounton1 + "\n" + p21cSetuid1 + "\n" + p21cSetgid1 + "\n"
	p21cWindow2 = p21cMounton2 + "\n" + p21cSetuid2 + "\n" + p21cSetgid2 + "\n"
)

// p21cWindowLines counts the non-empty record lines of a raw window
// fixture — the same measurement the producer records as `actual` (the
// extracted file's own line count, never the boundary arithmetic).
func p21cWindowLines(records string) int {
	n := 0
	for _, l := range strings.Split(records, "\n") {
		if strings.TrimSpace(l) != "" {
			n++
		}
	}
	return n
}

// p21cOpSection composes one per-operation evidence section in the
// corrected grammar: header (tag + daemon operation id + session id), the
// pinned-source capture-integrity accounting (identity checkpoints, drain
// outcomes, measured before/after/expected/actual), the operation result,
// the attributed runtime records partitioned by attribution quality, the
// whole-window regression-control sections, and the raw window records the
// capture claims to have extracted.
func p21cOpSection(tag, opid, session string, before, after int, opAttributed, pidCorrelated, misattributed, unattributed, p21bTerminal, windowRecords string) string {
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
	fmt.Fprintf(&b, "actual=%d\n", p21cWindowLines(windowRecords))
	b.WriteString("source=proven\n")
	b.WriteString("-- operation result --\n")
	b.WriteString(`"status": "failed" "result_code": "docker_build_failed" "exit_code": 1` + "\n")
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
	return b.String()
}

// p21cInterSection composes the inter-window region section: the records
// drained between the two operations (attributable to NEITHER operation;
// host audit noise is expected there), with the same capture-integrity
// accounting as the operation windows.
func p21cInterSection(gapAfter, gapBefore int, records string) string {
	var b strings.Builder
	b.WriteString("== inter-window records (attributable to NEITHER operation) ==\n")
	b.WriteString("-- window boundaries (pinned-source capture integrity) --\n")
	b.WriteString("identity-gap-pre=proven\n")
	b.WriteString("identity-gap-post=proven\n")
	b.WriteString("inter-drain=ok\n")
	fmt.Fprintf(&b, "gap-after=%d\n", gapAfter)
	fmt.Fprintf(&b, "gap-before=%d\n", gapBefore)
	fmt.Fprintf(&b, "expected=%d\n", gapBefore-gapAfter)
	fmt.Fprintf(&b, "actual=%d\n", p21cWindowLines(records))
	b.WriteString("source=proven\n")
	b.WriteString("-- records --\n")
	b.WriteString(records)
	return b.String()
}

// p21cGreenTerminals returns the green live-flow fixture: two DISTINCT
// operations (distinct operation ids, distinct session ids), each with its
// own bounded non-overlapping audit window, its own attributed runtime
// records (op-path terminal + pid-correlated pre-boundary self-denials),
// its own observed next terminal, EMPTY control sections, and an empty
// inter-window region. BOTH windows carry the buildkitd_t:s0:c1 source
// context — the same MCS category — because attribution never rests on
// the category.
func p21cGreenTerminals() string {
	return p21cOpSection("c1", p21cOp1ID, p21cSession1, 100, 103,
		p21cMounton1+"\n",
		p21cSetuid1+"\n"+p21cSetgid1+"\n",
		"", "", "", p21cWindow1) +
		p21cOpSection("c2", p21cOp2ID, p21cSession2, 103, 106,
			p21cMounton2+"\n",
			p21cSetuid2+"\n"+p21cSetgid2+"\n",
			"", "", "", p21cWindow2) +
		p21cInterSection(103, 103, "")
}

// p21cGreenRawWindows returns the raw window artifacts of the green
// fixture: the exact drained bytes per operation plus the empty
// inter-window artifact.
func p21cGreenRawWindows() map[string]string {
	return map[string]string{"c1": p21cWindow1, "c2": p21cWindow2, "inter": ""}
}

func p21cWriteEvidence(t *testing.T, matrix, av, terminals string, raw map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("create-matrix-before.log", matrix)
	write("av-matrix-before.log", av)
	write("p21c-terminals.log", terminals)
	write("avc-window-c1.log", raw["c1"])
	write("avc-window-c2.log", raw["c2"])
	write("inter-window.log", raw["inter"])
	return dir
}

func p21cRunEvaluator(t *testing.T, dir string) (string, int) {
	t.Helper()
	out, err := exec.Command("bash", "scripts/release-2.4-r7-p21c-verdict.sh", dir).CombinedOutput()
	line := ""
	for _, l := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(l, "R7-P21C-VERDICT=") {
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
	if line == "" {
		t.Fatalf("evaluator produced no verdict line (rc=%d):\n%s", rc, out)
	}
	return line, rc
}

func p21cField(t *testing.T, verdict, key string) string {
	t.Helper()
	for _, part := range strings.Split(strings.TrimPrefix(verdict, "R7-P21C-VERDICT="), ";") {
		if strings.HasPrefix(part, key+"=") {
			return strings.TrimPrefix(part, key+"=")
		}
	}
	t.Fatalf("verdict %q carries no %s field", verdict, key)
	return ""
}

func p21cGreenDir(t *testing.T) string {
	return p21cWriteEvidence(t,
		strings.Join(p21cGreenMatrix(), "\n")+"\n",
		strings.Join(p21cGreenAV(), "\n")+"\n",
		p21cGreenTerminals(), p21cGreenRawWindows())
}

// TestR7P21CVerdictGreenEvidenceIsMeasured proves the evaluator decides
// P21C-MEASURED when BOTH operations independently prove their own
// advancement, with every summary field at its expected value.
func TestR7P21CVerdictGreenEvidenceIsMeasured(t *testing.T) {
	line, rc := p21cRunEvaluator(t, p21cGreenDir(t))
	if rc != 0 {
		t.Fatalf("green evidence must decide P21C-MEASURED (rc=0), got rc=%d: %s", rc, line)
	}
	if !strings.Contains(line, "DECISION=P21C-MEASURED") {
		t.Errorf("green evidence must carry DECISION=P21C-MEASURED: %s", line)
	}
	if got := p21cField(t, line, "SCOPE"); got != "six-names-ok" {
		t.Errorf("SCOPE must be six-names-ok, got %q", got)
	}
	if got := p21cField(t, line, "OPEN-COMPLETION"); got != "eliminated" {
		t.Errorf("OPEN-COMPLETION must be eliminated, got %q", got)
	}
	if got := p21cField(t, line, "MEMFD"); got != "intact" {
		t.Errorf("MEMFD must be intact, got %q", got)
	}
	if got := p21cField(t, line, "CROSSOP-CONTENT"); got != "closed" {
		t.Errorf("CROSSOP-CONTENT must be closed, got %q", got)
	}
	if got := p21cField(t, line, "NEXT-TERMINAL"); !strings.Contains(got, p21cOp1ID) || !strings.Contains(got, "denied  { mounton }") {
		t.Errorf("NEXT-TERMINAL must be the FIRST operation's own attributed record, got %q", got)
	}
}

// TestR7P21CVerdictSingleWindowCannotMeasure is THE corrected defect: the
// revision-1 evaluator could decide MEASURED from one merged record set.
// A single window (the second section missing) can never measure, and a
// second window that merely COPIES the first is a positive attribution
// violation, never evidence.
func TestR7P21CVerdictSingleWindowCannotMeasure(t *testing.T) {
	green := p21cGreenTerminals()
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
		"second window missing entirely": {"P21C-BLOCKED", firstOnly,
			map[string]string{"c1": p21cWindow1, "c2": "", "inter": ""}},
		"second window is a copy of the first (the first op's paths inside it)": {"P21C-FAIL", copied,
			map[string]string{"c1": p21cWindow1, "c2": p21cWindow1, "inter": ""}},
	} {
		dir := p21cWriteEvidence(t, strings.Join(p21cGreenMatrix(), "\n")+"\n",
			strings.Join(p21cGreenAV(), "\n")+"\n", terminals.text, terminals.raw)
		line, rc := p21cRunEvaluator(t, dir)
		if rc == 0 || !strings.Contains(line, "DECISION="+terminals.want) {
			t.Errorf("%s must decide %s, got rc=%d: %s", name, terminals.want, rc, line)
		}
	}
}

// TestR7P21CVerdictSecondOperationFailsBeforeInitBlocks proves a second
// operation that never reached runc:[2:INIT] can never ride the first
// operation's evidence: the second section carries no attributed runtime
// record, so the verdict is BLOCKED (not MEASURED, not FAIL-by-proxy).
func TestR7P21CVerdictSecondOperationFailsBeforeInitBlocks(t *testing.T) {
	terminals := p21cOpSection("c1", p21cOp1ID, p21cSession1, 100, 103,
		p21cMounton1+"\n",
		p21cSetuid1+"\n"+p21cSetgid1+"\n",
		"", "", "", p21cWindow1) +
		p21cOpSection("c2", p21cOp2ID, p21cSession2, 103, 104,
			"", "", "", "", "", "host noise record\n") +
		p21cInterSection(103, 103, "")
	dir := p21cWriteEvidence(t, strings.Join(p21cGreenMatrix(), "\n")+"\n",
		strings.Join(p21cGreenAV(), "\n")+"\n", terminals,
		map[string]string{"c1": p21cWindow1, "c2": "host noise record\n", "inter": ""})
	line, rc := p21cRunEvaluator(t, dir)
	if rc == 0 || !strings.Contains(line, "DECISION=P21C-BLOCKED") {
		t.Errorf("a second operation with no attributed runtime record must decide BLOCKED, got rc=%d: %s", rc, line)
	}
	if got := p21cField(t, line, "OPEN-COMPLETION"); got != "eliminated" {
		t.Errorf("the FIRST window was still fully evaluated (OPEN-COMPLETION=eliminated), got %q", got)
	}
}

// TestR7P21CVerdictCategoryOnlyAttributionBlocks proves the attribution
// never rests on the MCS category: two windows whose records are
// distinguishable ONLY by category labels (no per-operation path, no
// pid proven by an op-attributed record) are AMBIGUOUS evidence — BLOCKED.
func TestR7P21CVerdictCategoryOnlyAttributionBlocks(t *testing.T) {
	// Pathless records only: nothing anchors them to an operation. Both
	// carry the SAME c1 category label — the category is never the key.
	pathlessSetuid := `type=AVC msg=audit(1793789899.001:1999): avc:  denied  { setuid } for  pid=3999 comm="runc:[2:INIT]" capability=7  scontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tcontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tclass=cap_userns permissive=0`
	pathlessMounton := `type=AVC msg=audit(1793789899.002:2000): avc:  denied  { mounton } for  pid=3999 comm="runc:[2:INIT]" dev="tmpfs" ino=5 scontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tcontext=system_u:object_r:docker_helper_devnode_t:s0 tclass=file permissive=0`
	terminals := p21cOpSection("c1", p21cOp1ID, p21cSession1, 100, 101,
		"", "", "", pathlessSetuid+"\n", "", pathlessSetuid+"\n") +
		p21cOpSection("c2", p21cOp2ID, p21cSession2, 104, 105,
			"", "", "", pathlessMounton+"\n", "", pathlessMounton+"\n") +
		p21cInterSection(101, 104, "")
	dir := p21cWriteEvidence(t, strings.Join(p21cGreenMatrix(), "\n")+"\n",
		strings.Join(p21cGreenAV(), "\n")+"\n", terminals,
		map[string]string{"c1": pathlessSetuid + "\n", "c2": pathlessMounton + "\n", "inter": ""})
	line, rc := p21cRunEvaluator(t, dir)
	if rc == 0 || !strings.Contains(line, "DECISION=P21C-BLOCKED") {
		t.Errorf("category-only distinguishable records must decide BLOCKED (attribution never rests on the category), got rc=%d: %s", rc, line)
	}
}

// TestR7P21CVerdictMisattributedAndUnattributedFailClosed proves the
// attribution-quality branches: a first-window record placed into the
// second window is a positive violation (FAIL), an unattributed
// runc:[2:INIT] record is ambiguous evidence (BLOCKED).
func TestR7P21CVerdictMisattributedAndUnattributedFailClosed(t *testing.T) {
	// A pathless runc-init record whose pid is NOT proven by any
	// op-attributed record of its window.
	stray := `type=AVC msg=audit(1793789899.002:2001): avc:  denied  { getattr } for  pid=4242 comm="runc:[2:INIT]" path="/tmp/x" dev="vda3" ino=1 scontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tcontext=system_u:object_r:tmp_t:s0 tclass=file permissive=0`
	for name, terminals := range map[string]struct {
		want string
		text string
		raw  map[string]string
	}{
		"first op's terminal record placed into the second window": {"P21C-FAIL",
			p21cOpSection("c1", p21cOp1ID, p21cSession1, 100, 103,
				p21cMounton1+"\n",
				p21cSetuid1+"\n"+p21cSetgid1+"\n",
				"", "", "", p21cWindow1) +
				p21cOpSection("c2", p21cOp2ID, p21cSession2, 103, 107,
					p21cMounton1+"\n"+p21cMounton2+"\n",
					p21cSetuid2+"\n"+p21cSetgid2+"\n",
					"", "", "",
					p21cMounton1+"\n"+p21cMounton2+"\n"+p21cSetuid2+"\n"+p21cSetgid2+"\n"),
			map[string]string{
				"c1":    p21cWindow1,
				"c2":    p21cMounton1 + "\n" + p21cMounton2 + "\n" + p21cSetuid2 + "\n" + p21cSetgid2 + "\n",
				"inter": "",
			}},
		"unattributed runc-init record in the first window": {"P21C-BLOCKED",
			p21cOpSection("c1", p21cOp1ID, p21cSession1, 100, 104,
				p21cMounton1+"\n",
				p21cSetuid1+"\n"+p21cSetgid1+"\n",
				"", stray+"\n", "",
				p21cWindow1+stray+"\n") +
				p21cOpSection("c2", p21cOp2ID, p21cSession2, 104, 107,
					p21cMounton2+"\n",
					p21cSetuid2+"\n"+p21cSetgid2+"\n",
					"", "", "", p21cWindow2),
			map[string]string{"c1": p21cWindow1 + stray + "\n", "c2": p21cWindow2, "inter": ""}},
	} {
		dir := p21cWriteEvidence(t, strings.Join(p21cGreenMatrix(), "\n")+"\n",
			strings.Join(p21cGreenAV(), "\n")+"\n", terminals.text, terminals.raw)
		line, rc := p21cRunEvaluator(t, dir)
		if rc == 0 || !strings.Contains(line, "DECISION="+terminals.want) {
			t.Errorf("%s must decide %s, got rc=%d: %s", name, terminals.want, rc, line)
		}
	}
}

// TestR7P21CVerdictWindowBoundaryFailClosed proves the exact-boundary
// contract: a truncated/rotated capture (inconsistent boundary) decides
// BLOCKED, an overlapping second window decides FAIL, a gap between the
// windows decides BLOCKED.
func TestR7P21CVerdictWindowBoundaryFailClosed(t *testing.T) {
	greenC1 := p21cOpSection("c1", p21cOp1ID, p21cSession1, 100, 103,
		p21cMounton1+"\n",
		p21cSetuid1+"\n"+p21cSetgid1+"\n",
		"", "", "", p21cWindow1)
	greenInter := p21cInterSection(103, 103, "")
	c2 := func() string {
		return p21cOpSection("c2", p21cOp2ID, p21cSession2, 103, 106,
			p21cMounton2+"\n",
			p21cSetuid2+"\n"+p21cSetgid2+"\n",
			"", "", "", p21cWindow2)
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
		p21cInterSection(103, 110,
			"host noise 1\nhost noise 2\nhost noise 3\nhost noise 4\nhost noise 5\nhost noise 6\nhost noise 7\n")
	unproven := greenC1 +
		strings.Replace(c2(), "identity-extract-post=proven", "identity-extract-post=unproven:path-replaced(pinned=95:1,path=95:2)", 1) +
		greenInter
	ambiguousGap := greenC1 + c2() + p21cInterSection(103, 110, p21cMounton2+"\n")
	for name, terminals := range map[string]struct {
		want string
		text string
	}{
		"truncated capture (actual does not match the boundary arithmetic)": {"P21C-BLOCKED", truncated},
		"second window overlaps the first":                                  {"P21C-FAIL", overlapping},
		"capture gap between the windows is unaccounted":                    {"P21C-BLOCKED", unaccountedGap},
		"a runc-init record inside the inter-window region":                 {"P21C-BLOCKED", ambiguousGap},
		"capture not proven at the extraction boundary":                     {"P21C-BLOCKED", unproven},
	} {
		dir := p21cWriteEvidence(t, strings.Join(p21cGreenMatrix(), "\n")+"\n",
			strings.Join(p21cGreenAV(), "\n")+"\n", terminals.text, p21cGreenRawWindows())
		line, rc := p21cRunEvaluator(t, dir)
		if rc == 0 || !strings.Contains(line, "DECISION="+terminals.want) {
			t.Errorf("%s must decide %s, got rc=%d: %s", name, terminals.want, rc, line)
		}
	}
	// The accounted-gap control: with a faithful inter-window section the
	// same gapped capture measures.
	dir := p21cWriteEvidence(t, strings.Join(p21cGreenMatrix(), "\n")+"\n",
		strings.Join(p21cGreenAV(), "\n")+"\n", accountedGap,
		map[string]string{"c1": p21cWindow1, "c2": p21cWindow2,
			"inter": "host noise 1\nhost noise 2\nhost noise 3\nhost noise 4\nhost noise 5\nhost noise 6\nhost noise 7\n"})
	line, rc := p21cRunEvaluator(t, dir)
	if rc != 0 || !strings.Contains(line, "DECISION=P21C-MEASURED") {
		t.Errorf("a capture gap WITH a faithful inter-window section must decide MEASURED, got rc=%d: %s", rc, line)
	}
}

// TestR7P21CVerdictDuplicateIdentityFailsClosed proves the identity
// branches: the SAME operation id in both windows (one window serving both
// operations) decides FAIL, the SAME session id decides FAIL, and the
// SAME AVC record cited as both operations' terminal decides FAIL.
func TestR7P21CVerdictDuplicateIdentityFailsClosed(t *testing.T) {
	sameOp := p21cOpSection("c1", p21cOp1ID, p21cSession1, 100, 103,
		p21cMounton1+"\n",
		p21cSetuid1+"\n"+p21cSetgid1+"\n",
		"", "", "", p21cWindow1) +
		p21cOpSection("c2", p21cOp1ID, p21cSession2, 103, 106,
			p21cMounton2+"\n",
			p21cSetuid2+"\n"+p21cSetgid2+"\n",
			"", "", "", p21cWindow2)
	sameSession := p21cOpSection("c1", p21cOp1ID, p21cSession1, 100, 103,
		p21cMounton1+"\n",
		p21cSetuid1+"\n"+p21cSetgid1+"\n",
		"", "", "", p21cWindow1) +
		p21cOpSection("c2", p21cOp2ID, p21cSession1, 103, 106,
			p21cMounton2+"\n",
			p21cSetuid2+"\n"+p21cSetgid2+"\n",
			"", "", "", p21cWindow2)
	sameTerminal := p21cOpSection("c1", p21cOp1ID, p21cSession1, 100, 103,
		p21cMounton1+"\n",
		p21cSetuid1+"\n"+p21cSetgid1+"\n",
		"", "", "", p21cWindow1) +
		p21cOpSection("c2", p21cOp2ID, p21cSession2, 103, 106,
			p21cMounton1+"\n",
			p21cSetuid2+"\n"+p21cSetgid2+"\n",
			"", "", "",
			p21cMounton1+"\n"+p21cSetuid2+"\n"+p21cSetgid2+"\n")
	for name, terminals := range map[string]string{
		"same operation id in both windows":                       sameOp,
		"same session id in both windows":                         sameSession,
		"the same AVC record for both terminals (misattribution)": sameTerminal,
	} {
		dir := p21cWriteEvidence(t, strings.Join(p21cGreenMatrix(), "\n")+"\n",
			strings.Join(p21cGreenAV(), "\n")+"\n", terminals, p21cGreenRawWindows())
		line, rc := p21cRunEvaluator(t, dir)
		if rc == 0 || !strings.Contains(line, "DECISION=P21C-FAIL") {
			t.Errorf("%s must decide FAIL, got rc=%d: %s", name, rc, line)
		}
	}
}

// TestR7P21CVerdictEliminatedShapeConfinedToSecondWindowFails proves the
// eliminated-shape check is PER OPERATION: the P21-B { read open } shape
// present ONLY in the second operation's window (both as an attributed
// record and via the whole-window control section) decides FAIL with
// OPEN-COMPLETION=live.
func TestR7P21CVerdictEliminatedShapeConfinedToSecondWindowFails(t *testing.T) {
	window2WithOld := p21cWindow2 + p21cOldTerminal + "\n"
	op2WithOld := strings.Replace(p21cOpSection("c2", p21cOp2ID, p21cSession2, 103, 107,
		p21cMounton2+"\n",
		p21cSetuid2+"\n"+p21cSetgid2+"\n",
		"", "", "", window2WithOld),
		"-- P21-B terminal (devnode_t:file { read open }; the ELIMINATED shape) --\n",
		"-- P21-B terminal (devnode_t:file { read open }; the ELIMINATED shape) --\n"+p21cOldTerminal+"\n", 1)
	terminals := p21cOpSection("c1", p21cOp1ID, p21cSession1, 100, 103,
		p21cMounton1+"\n",
		p21cSetuid1+"\n"+p21cSetgid1+"\n",
		"", "", "", p21cWindow1) + op2WithOld
	dir := p21cWriteEvidence(t, strings.Join(p21cGreenMatrix(), "\n")+"\n",
		strings.Join(p21cGreenAV(), "\n")+"\n", terminals,
		map[string]string{"c1": p21cWindow1, "c2": window2WithOld, "inter": ""})
	line, rc := p21cRunEvaluator(t, dir)
	if rc == 0 || !strings.Contains(line, "DECISION=P21C-FAIL") {
		t.Errorf("the eliminated shape confined to the second window must decide FAIL, got rc=%d: %s", rc, line)
	}
	if got := p21cField(t, line, "OPEN-COMPLETION"); got != "live" {
		t.Errorf("OPEN-COMPLETION must be live, got %q", got)
	}
}

// TestR7P21CVerdictZeroNewlineGrepArtifactFailsClosed pins the fail-closed
// behavior on the degenerate matrix shapes the P21-B corrective round
// documented (the "0\n0" grep artifact, an empty file, garbage).
func TestR7P21CVerdictZeroNewlineGrepArtifactFailsClosed(t *testing.T) {
	for name, matrix := range map[string]string{
		"the 0-newline-0 grep artifact": "0\n0\n",
		"empty file":                    "",
		"garbage only":                  "grep: no matches\n",
	} {
		dir := p21cWriteEvidence(t, matrix, strings.Join(p21cGreenAV(), "\n")+"\n", p21cGreenTerminals(), p21cGreenRawWindows())
		line, rc := p21cRunEvaluator(t, dir)
		if rc == 0 || strings.Contains(line, "DECISION=P21C-MEASURED") || strings.Contains(line, "SCOPE=six-names-ok") {
			t.Errorf("mutation %q must fail closed (no MEASURED, no six-names-ok), got rc=%d: %s", name, rc, line)
		}
	}
}

// TestR7P21CVerdictMatrixMutationsFailClosed proves every matrix
// irregularity fails closed (never MEASURED).
func TestR7P21CVerdictMatrixMutationsFailClosed(t *testing.T) {
	rows := p21cGreenMatrix()
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
			i := find("tty", p21cC2)
			return append(r[:i:i], r[i+1:]...)
		}},
		{"duplicated c1/zero row", func(r []string) []string {
			i := find("zero", p21cC1)
			return append(append(r[:i:i], r[i]), r[i:]...)
		}},
		{"wrong result: c1/null keeps runc_memfd_t", func(r []string) []string {
			i := find("null", p21cC1)
			out := append([]string(nil), r...)
			out[i] = p21cCreateRow(p21cC1, "null", p21cMemfd)
			return out
		}},
		{"arbitrary name diverted to devnode_t", func(r []string) []string {
			i := find("someothername", p21cC1)
			out := append([]string(nil), r...)
			out[i] = p21cCreateRow(p21cC1, "someothername", p21cDevnode)
			return out
		}},
		{"unparseable line injected", func(r []string) []string {
			return append(r, "CREATE broken matrix line")
		}},
	}
	for _, mut := range mutations {
		mutated := mut.mutate(append([]string(nil), rows...))
		dir := p21cWriteEvidence(t, strings.Join(mutated, "\n")+"\n",
			strings.Join(p21cGreenAV(), "\n")+"\n", p21cGreenTerminals(), p21cGreenRawWindows())
		line, rc := p21cRunEvaluator(t, dir)
		if rc == 0 || strings.Contains(line, "DECISION=P21C-MEASURED") {
			t.Errorf("mutation %q must fail closed, got rc=%d: %s", mut.name, rc, line)
		}
	}
}

// TestR7P21CVerdictAVMutationsFailClosed proves the AV-matrix branches for
// the P21-C shape: the { read open } pair must be EXACTLY granted for both
// operation categories, every other permission must stay DENIED, the
// unconfined surface must stay all-DENY, the associate rows must stay
// unchanged, and missing/duplicated/unparseable rows fail closed.
func TestR7P21CVerdictAVMutationsFailClosed(t *testing.T) {
	green := strings.Join(p21cGreenAV(), "\n") + "\n"
	mutations := []struct {
		name   string
		mutate func(string) string
	}{
		{"c1 pair member read DENIED", func(p string) string {
			return strings.Replace(p, p21cAVFilePerm("read", "ALLOW", "0x8000a"), p21cAVFilePerm("read", "DENY", "0x80008"), 1)
		}},
		{"c2 pair member open DENIED", func(p string) string {
			return strings.Replace(p, p21cAVFilePerm("open", "ALLOW", "0x8000a"), p21cAVFilePerm("open", "DENY", "0xa"), 1)
		}},
		{"c1 write ALLOW (the rejected content authority)", func(p string) string {
			return strings.Replace(p, p21cAVFilePerm("write", "DENY", "0x8000a"), p21cAVFilePerm("write", "ALLOW", "0x8000a"), 1)
		}},
		{"c2 setattr ALLOW", func(p string) string {
			return strings.Replace(p, p21cAVFilePerm("setattr", "DENY", "0x8000a"), p21cAVFilePerm("setattr", "ALLOW", "0x8000a"), 1)
		}},
		{"unconfined read ALLOW", func(p string) string {
			return strings.Replace(p, p21cAVFilePerm("read", "DENY", "0x0"), p21cAVFilePerm("read", "ALLOW", "0x2"), 1)
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
			return strings.Replace(p, p21cAVFilePerm("lock", "DENY", "0x8000a"), "", 1)
		}},
		{"duplicated c1/create row", func(p string) string {
			needle := p21cAVFilePerm("create", "ALLOW", "0x8000a")
			return strings.Replace(p, needle, needle+"\n"+needle, 1)
		}},
		{"unparseable AV row injected", func(p string) string {
			return p + "  write MAYBE\n"
		}},
	}
	for _, mut := range mutations {
		dir := p21cWriteEvidence(t, strings.Join(p21cGreenMatrix(), "\n")+"\n", mut.mutate(green), p21cGreenTerminals(), p21cGreenRawWindows())
		line, rc := p21cRunEvaluator(t, dir)
		if rc == 0 || strings.Contains(line, "DECISION=P21C-MEASURED") {
			t.Errorf("mutation %q must fail closed, got rc=%d: %s", mut.name, rc, line)
		}
	}
}

// TestR7P21CVerdictNextTerminalMutationsFailClosed proves the strict
// next-terminal matcher per operation: a corrupted terminal record in
// EITHER window (permissive=1, unconfined source, foreign comm, the
// granted shape, a cap_userns downgrade) removes that operation's proof
// and decides BLOCKED; the whole-flow failure shape decides FAIL.
func TestR7P21CVerdictNextTerminalMutationsFailClosed(t *testing.T) {
	mutations := []struct {
		name         string
		corrupt      func(string) string
		wantDECISION string
	}{
		{"terminal records corrupted to permissive=1", func(p string) string {
			return strings.ReplaceAll(p, "tclass=file permissive=0", "tclass=file permissive=1")
		}, "P21C-BLOCKED"},
		{"the second operation's terminal record removed (only the first proves its own)", func(p string) string {
			return strings.ReplaceAll(p, p21cMounton2+"\n", "")
		}, "P21C-BLOCKED"},
		{"terminal records corrupted to the granted shape", func(p string) string {
			return strings.ReplaceAll(p, "denied  { mounton }", "denied  { read open }")
		}, "P21C-FAIL"},
		{"terminal records downgraded to cap_userns", func(p string) string {
			out := strings.ReplaceAll(p, "denied  { mounton }", "denied  { setuid }")
			return strings.ReplaceAll(out,
				"tcontext=system_u:object_r:docker_helper_devnode_t:s0 tclass=file",
				"tcontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tclass=cap_userns")
		}, "P21C-BLOCKED"},
		{"terminal records corrupted to a foreign comm", func(p string) string {
			return strings.ReplaceAll(p, `comm="runc:[2:INIT]" path="/var/lib`, `comm="buildkit-runc" path="/var/lib`)
		}, "P21C-BLOCKED"},
	}
	for _, mut := range mutations {
		mutated := mut.corrupt(p21cGreenTerminals())
		if mutated == p21cGreenTerminals() {
			t.Fatalf("mutation %q must corrupt at least one record", mut.name)
		}
		// The corruption is applied to the raw window artifacts too, so the
		// evidence stays internally consistent and the next-terminal
		// matcher itself is what must fail closed.
		raw := p21cGreenRawWindows()
		for tag, content := range raw {
			raw[tag] = mut.corrupt(content)
			if tag == "inter" && raw[tag] != "" && content == "" {
				t.Fatalf("mutation %q must not fabricate inter-window records", mut.name)
			}
		}
		dir := p21cWriteEvidence(t, strings.Join(p21cGreenMatrix(), "\n")+"\n",
			strings.Join(p21cGreenAV(), "\n")+"\n", mutated, raw)
		line, rc := p21cRunEvaluator(t, dir)
		if rc == 0 || !strings.Contains(line, "DECISION="+mut.wantDECISION) {
			t.Errorf("mutation %q must decide %s, got rc=%d: %s", mut.name, mut.wantDECISION, rc, line)
		}
	}
}

// TestR7P21CVerdictSectionHeaderIntegrityFailClosed proves the header
// recognition is whole-line and per-operation: a missing operation header
// decides BLOCKED, a duplicated operation header decides FAIL, a missing
// control header inside ONE section decides BLOCKED, a corrupted (not
// whole-line) header decides BLOCKED.
func TestR7P21CVerdictSectionHeaderIntegrityFailClosed(t *testing.T) {
	green := p21cGreenTerminals()
	missingOp2 := green[:strings.Index(green, "== operation c2 ")]
	dir := p21cWriteEvidence(t, strings.Join(p21cGreenMatrix(), "\n")+"\n",
		strings.Join(p21cGreenAV(), "\n")+"\n", missingOp2, p21cGreenRawWindows())
	line, rc := p21cRunEvaluator(t, dir)
	if rc == 0 || !strings.Contains(line, "DECISION=P21C-BLOCKED") {
		t.Errorf("a missing second operation header must decide BLOCKED, got rc=%d: %s", rc, line)
	}
	duplicatedOp1 := green + "== operation c1 op_" + p21cOp1ID + " session " + p21cSession1 + " ==\n"
	dir = p21cWriteEvidence(t, strings.Join(p21cGreenMatrix(), "\n")+"\n",
		strings.Join(p21cGreenAV(), "\n")+"\n", duplicatedOp1, p21cGreenRawWindows())
	line, rc = p21cRunEvaluator(t, dir)
	if rc == 0 || !strings.Contains(line, "DECISION=P21C-FAIL") {
		t.Errorf("a duplicated operation header must decide FAIL, got rc=%d: %s", rc, line)
	}
	missingControl := strings.Replace(green,
		"-- P20 terminal (runc_memfd_t:file create) --\n", "", 1)
	dir = p21cWriteEvidence(t, strings.Join(p21cGreenMatrix(), "\n")+"\n",
		strings.Join(p21cGreenAV(), "\n")+"\n", missingControl, p21cGreenRawWindows())
	line, rc = p21cRunEvaluator(t, dir)
	if rc == 0 || !strings.Contains(line, "DECISION=P21C-BLOCKED") {
		t.Errorf("a missing control header (both sections) must decide BLOCKED, got rc=%d: %s", rc, line)
	}
	corruptedHeader := strings.Replace(green,
		"== operation c1 op_"+p21cOp1ID+" session "+p21cSession1+" ==\n",
		"X== operation c1 op_"+p21cOp1ID+" session "+p21cSession1+" ==\n", 1)
	dir = p21cWriteEvidence(t, strings.Join(p21cGreenMatrix(), "\n")+"\n",
		strings.Join(p21cGreenAV(), "\n")+"\n", corruptedHeader, p21cGreenRawWindows())
	line, rc = p21cRunEvaluator(t, dir)
	if rc == 0 || !strings.Contains(line, "DECISION=P21C-BLOCKED") {
		t.Errorf("a corrupted (not whole-line) operation header must decide BLOCKED, got rc=%d: %s", rc, line)
	}
}

// TestR7P21CVerdictMissingEvidenceFilesBlock pins the file-level
// fail-closed branch, including the raw capture artifacts.
func TestR7P21CVerdictMissingEvidenceFilesBlock(t *testing.T) {
	for _, name := range []string{
		"create-matrix-before.log", "av-matrix-before.log", "p21c-terminals.log",
		"avc-window-c1.log", "avc-window-c2.log", "inter-window.log",
	} {
		broken := p21cGreenDir(t)
		if err := os.Remove(filepath.Join(broken, name)); err != nil {
			t.Fatal(err)
		}
		line, rc := p21cRunEvaluator(t, broken)
		if rc == 0 || !strings.Contains(line, "DECISION=P21C-BLOCKED") {
			t.Errorf("missing %q must decide BLOCKED, got rc=%d: %s", name, rc, line)
		}
	}
	line, rc := p21cRunEvaluator(t, t.TempDir())
	if rc == 0 || !strings.Contains(line, "DECISION=P21C-BLOCKED") {
		t.Errorf("an empty evidence directory must decide BLOCKED, got rc=%d: %s", rc, line)
	}
}

// TestR7P21CVerdictCaptureIntegrityFailClosed proves the revision-3
// capture-integrity branches: an unproven identity checkpoint or drain
// outcome, an actual/expected mismatch, a raw window artifact that does
// not corroborate the section (wrong line count, missing cited record,
// an unaccounted runc-init record, a hidden misattribution, the
// eliminated shape) can never decide MEASURED.
func TestR7P21CVerdictCaptureIntegrityFailClosed(t *testing.T) {
	stray2 := `type=AVC msg=audit(1793789899.003:2002): avc:  denied  { getattr } for  pid=4243 comm="runc:[2:INIT]" path="/tmp/y" dev="vda3" ino=2 scontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tcontext=system_u:object_r:tmp_t:s0 tclass=file permissive=0`
	greenC1 := p21cOpSection("c1", p21cOp1ID, p21cSession1, 100, 103,
		p21cMounton1+"\n",
		p21cSetuid1+"\n"+p21cSetgid1+"\n",
		"", "", "", p21cWindow1)
	greenInter := p21cInterSection(103, 103, "")
	c2 := func() string {
		return p21cOpSection("c2", p21cOp2ID, p21cSession2, 103, 106,
			p21cMounton2+"\n",
			p21cSetuid2+"\n"+p21cSetgid2+"\n",
			"", "", "", p21cWindow2)
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
			p21cGreenRawWindows(), "P21C-BLOCKED"},
		{"capture source state not proven",
			greenC1 + strings.Replace(c2(), "source=proven", "source=unproven", 1) + greenInter,
			p21cGreenRawWindows(), "P21C-BLOCKED"},
		{"identity checkpoint not proven",
			greenC1 + strings.Replace(c2(), "identity-extract-pre=proven", "identity-extract-pre=unproven:path-replaced(pinned=95:1,path=95:2)", 1) + greenInter,
			p21cGreenRawWindows(), "P21C-BLOCKED"},
		{"window drain not ok",
			greenC1 + strings.Replace(c2(), "window-drain=ok", "window-drain=failed:read-error", 1) + greenInter,
			p21cGreenRawWindows(), "P21C-BLOCKED"},
		{"raw window holds fewer lines than the claimed capture",
			greenC1 + c2() + greenInter,
			map[string]string{"c1": p21cWindow1, "c2": p21cMounton2 + "\n" + p21cSetuid2 + "\n", "inter": ""},
			"P21C-BLOCKED"},
		{"a cited record is absent from the raw window",
			greenC1 + c2() + greenInter,
			map[string]string{"c1": p21cWindow1, "c2": p21cMounton2 + "\n" + p21cSetgid2 + "\nhost noise\n", "inter": ""},
			"P21C-BLOCKED"},
		{"the raw window carries an unaccounted runc-init record",
			greenC1 + c2Window4("") + greenInter,
			map[string]string{"c1": p21cWindow1, "c2": p21cWindow2 + stray2 + "\n", "inter": ""},
			"P21C-BLOCKED"},
		{"the raw window carries a hidden misattribution",
			greenC1 + c2Window4("") + greenInter,
			map[string]string{"c1": p21cWindow1, "c2": p21cWindow2 + p21cMounton1 + "\n", "inter": ""},
			"P21C-FAIL"},
		{"the raw window carries the eliminated shape",
			greenC1 + c2Window4("") + greenInter,
			map[string]string{"c1": p21cWindow1, "c2": p21cWindow2 + p21cOldTerminal + "\n", "inter": ""},
			"P21C-FAIL"},
	}
	for _, mut := range mutations {
		dir := p21cWriteEvidence(t, strings.Join(p21cGreenMatrix(), "\n")+"\n",
			strings.Join(p21cGreenAV(), "\n")+"\n", mut.text, mut.raw)
		line, rc := p21cRunEvaluator(t, dir)
		if rc == 0 || !strings.Contains(line, "DECISION="+mut.want) {
			t.Errorf("mutation %q must decide %s, got rc=%d: %s", mut.name, mut.want, rc, line)
		}
	}
	// A missing raw artifact decides BLOCKED.
	broken := p21cGreenDir(t)
	if err := os.Remove(filepath.Join(broken, "avc-window-c2.log")); err != nil {
		t.Fatal(err)
	}
	line, rc := p21cRunEvaluator(t, broken)
	if rc == 0 || !strings.Contains(line, "DECISION=P21C-BLOCKED") {
		t.Errorf("a missing raw window artifact must decide BLOCKED, got rc=%d: %s", rc, line)
	}
}

// TestR7P21CVerdictInterWindowCaptureIntegrityFailClosed proves the
// inter-window capture is held to the SAME integrity contract: an
// unproven checkpoint, an actual/expected mismatch, or a raw artifact
// that does not corroborate the section decides BLOCKED; a faithful
// inter-window capture with real host-noise records still measures.
func TestR7P21CVerdictInterWindowCaptureIntegrityFailClosed(t *testing.T) {
	noise := "host noise record one\nhost noise record two\nhost noise record three\n"
	c1 := p21cOpSection("c1", p21cOp1ID, p21cSession1, 100, 103,
		p21cMounton1+"\n",
		p21cSetuid1+"\n"+p21cSetgid1+"\n",
		"", "", "", p21cWindow1)
	c2 := p21cOpSection("c2", p21cOp2ID, p21cSession2, 106, 109,
		p21cMounton2+"\n",
		p21cSetuid2+"\n"+p21cSetgid2+"\n",
		"", "", "", p21cWindow2)
	// Positive control: a proven inter-window capture with three real
	// host-noise records, fully accounted, still measures.
	interGreen := p21cInterSection(103, 106, noise)
	green := c1 + c2 + interGreen
	dir := p21cWriteEvidence(t, strings.Join(p21cGreenMatrix(), "\n")+"\n",
		strings.Join(p21cGreenAV(), "\n")+"\n", green,
		map[string]string{"c1": p21cWindow1, "c2": p21cWindow2, "inter": noise})
	if line, rc := p21cRunEvaluator(t, dir); rc != 0 || !strings.Contains(line, "DECISION=P21C-MEASURED") {
		t.Fatalf("a proven inter-window capture with accounted noise must decide MEASURED, got rc=%d: %s", rc, line)
	}
	mutations := []struct {
		name string
		text string
		raw  map[string]string
		want string
	}{
		{"inter capture not proven", c1 + c2 + strings.Replace(interGreen, "source=proven", "source=unproven", 1),
			map[string]string{"c1": p21cWindow1, "c2": p21cWindow2, "inter": ""}, "P21C-BLOCKED"},
		{"inter identity checkpoint not proven", c1 + c2 + strings.Replace(interGreen, "identity-gap-pre=proven", "identity-gap-pre=unproven:path-replaced(pinned=95:1,path=95:2)", 1),
			map[string]string{"c1": p21cWindow1, "c2": p21cWindow2, "inter": noise}, "P21C-BLOCKED"},
		{"inter actual does not match expected", c1 + c2 + strings.Replace(interGreen, "actual=3\n", "actual=2\n", 1),
			map[string]string{"c1": p21cWindow1, "c2": p21cWindow2, "inter": noise}, "P21C-BLOCKED"},
		{"raw inter artifact holds fewer lines than claimed", green,
			map[string]string{"c1": p21cWindow1, "c2": p21cWindow2, "inter": "host noise record one\n"}, "P21C-BLOCKED"},
	}
	for _, mut := range mutations {
		dir = p21cWriteEvidence(t, strings.Join(p21cGreenMatrix(), "\n")+"\n",
			strings.Join(p21cGreenAV(), "\n")+"\n", mut.text, mut.raw)
		line, rc := p21cRunEvaluator(t, dir)
		if rc == 0 || !strings.Contains(line, "DECISION="+mut.want) {
			t.Errorf("%s must decide %s, got rc=%d: %s", mut.name, mut.want, rc, line)
		}
	}
	// A missing raw inter artifact decides BLOCKED.
	broken := p21cGreenDir(t)
	if err := os.Remove(filepath.Join(broken, "inter-window.log")); err != nil {
		t.Fatal(err)
	}
	line, rc := p21cRunEvaluator(t, broken)
	if rc == 0 || !strings.Contains(line, "DECISION=P21C-BLOCKED") {
		t.Errorf("a missing raw inter-window artifact must decide BLOCKED, got rc=%d: %s", rc, line)
	}
}

// TestR7P21CGuestCaptureSelftest runs the guest harness's own capture
// battery: the REAL production capture functions
// (audit_open/audit_identity/audit_drain/capture_begin/capture_end)
// against synthetic audit sources, covering the review's RED/GREEN
// scenarios on the actual evidence-production path — append-only growth
// stays valid, while torn records, read errors, same-inode truncation,
// and rename/replacement (fewer, equal, or more lines, including between
// the extraction checkpoints) are all fail-closed, for the operation
// windows AND the inter-window capture.
func TestR7P21CGuestCaptureSelftest(t *testing.T) {
	dir := t.TempDir()
	out, err := exec.Command("bash", "scripts/release-2.4-r7-p21c-guest.sh",
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
	} else if n := p21cWindowLines(string(window)); n != 5 {
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
	//        inode mismatch decides, never the line count.
	for _, name := range []string{"replace-fewer", "replace-same", "replace-more"} {
		expect(name+".boundaries", map[string]string{
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

// TestR7P21CVerdictGateMode pins the driver-side gate: exit 0 iff the
// argument is EXACTLY ONE correctly formed R7-P21C-VERDICT line whose
// first field is the single DECISION=P21C-MEASURED.
func TestR7P21CVerdictGateMode(t *testing.T) {
	accepted := "R7-P21C-VERDICT=DECISION=P21C-MEASURED;SCOPE=six-names-ok;OPEN-COMPLETION=eliminated;MEMFD=intact;CROSSOP-CONTENT=closed;NEXT-TERMINAL=<" + p21cMounton1 + ">"
	if rc := exec.Command("bash", "scripts/release-2.4-r7-p21c-verdict.sh", "--gate", accepted).Run(); rc != nil {
		t.Errorf("--gate must accept a correctly formed MEASURED verdict line: %v", rc)
	}
	for _, bad := range []string{
		"R7-P21C-VERDICT=DECISION=P21C-FAIL;NOTE=DECISION=P21C-MEASURED",
		"R7-P21C-VERDICT=DECISION=P21C-BLOCKED;DECISION=P21C-MEASURED",
		"R7-P21C-VERDICT=DECISION=P21C-MEASURED;DECISION=P21C-FAIL",
		"R7-P21C-VERDICT=DECISION=P21C-BLOCKED;REASON=no-evidence-dir",
		"R7-P21C-VERDICT=SCOPE=six-names-ok",
		"XR7-P21C-VERDICT=DECISION=P21C-MEASURED;SCOPE=six-names-ok",
		"R7-P21C-VERDICTX=DECISION=P21C-MEASURED;SCOPE=six-names-ok",
		"R7-P21C-VERDICT=DECISION=P21C-MEAS",
		"R7-P21C-VERDICT=DECISION=P21C-MEASURED",
		"R7-P21C-VERDICT=DECISION=P21C-MEASURED;SCOPE=six-names-ok",
		"R7-P21C-VERDICT=DECISION=P21C-MEASURED;SCOPE=six-names-ok;;",
		"R7-P21C-VERDICT=DECISION=P21C-MEASURED;SCOPE=six-names-ok;",
		"R7-P21C-VERDICT=DECISION=P21C-MEASURED;SCOPE=six-names-ok;JUNK",
		"R7-P21C-VERDICT=DECISION=P21C-MEASURED;SCOPE=six-names-ok;UNEXPECTED-FIELD=1",
		"R7-P21C-VERDICT=DECISION=P21C-MEASURED;SCOPE=not-established;OPEN-COMPLETION=eliminated;MEMFD=intact;CROSSOP-CONTENT=closed;NEXT-TERMINAL=<type=AVC msg=audit(1.0:1190)>",
		"R7-P21C-VERDICT=DECISION=P21C-MEASURED;SCOPE=six-names-ok;OPEN-COMPLETION=live;MEMFD=intact;CROSSOP-CONTENT=closed;NEXT-TERMINAL=<type=AVC msg=audit(1.0:1190)>",
		"R7-P21C-VERDICT=DECISION=P21C-MEASURED;SCOPE=six-names-ok;OPEN-COMPLETION=not-established;MEMFD=intact;CROSSOP-CONTENT=closed;NEXT-TERMINAL=<type=AVC msg=audit(1.0:1190)>",
		"R7-P21C-VERDICT=DECISION=P21C-MEASURED;SCOPE=six-names-ok;OPEN-COMPLETION=eliminated;MEMFD=regressed;CROSSOP-CONTENT=closed;NEXT-TERMINAL=<type=AVC msg=audit(1.0:1190)>",
		"R7-P21C-VERDICT=DECISION=P21C-MEASURED;SCOPE=six-names-ok;OPEN-COMPLETION=eliminated;MEMFD=intact;CROSSOP-CONTENT=open;NEXT-TERMINAL=<type=AVC msg=audit(1.0:1190)>",
		"R7-P21C-VERDICT=DECISION=P21C-MEASURED;NEXT-TERMINAL=<(none)>",
		"R7-P21C-VERDICT=DECISION=P21C-MEASURED;NEXT-TERMINAL=<type=AVC line;broken=field>",
		"R7-P21C-VERDICT=DECISION=P21C-MEASURED;SCOPE=six-names-ok;OPEN-COMPLETION=eliminated;MEMFD=intact;CROSSOP-CONTENT=closed",
	} {
		if rc := exec.Command("bash", "scripts/release-2.4-r7-p21c-verdict.sh", "--gate", bad).Run(); rc == nil {
			t.Errorf("--gate must reject %q", bad)
		}
	}
}
