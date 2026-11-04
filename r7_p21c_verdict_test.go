package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// R7 P21-C gate evaluator regression fixtures, revision 2 (the
// r7-p21c-corrective-1 task): the fail-closed classification now requires
// TWO INDEPENDENTLY ATTRIBUTED per-operation runtime windows. The evidence
// grammar is the corrected per-operation section shape (distinct daemon
// operation id and session id per section, exact audit.log line-offset
// window boundaries, op-path/pid attribution with MCS category never an
// attribution key). The fail-closed branches are proven for every
// falsification the review identified: a missing second window, a copied
// window, a second operation that failed before runc:[2:INIT], records
// distinguishable only by MCS category, a first-window record placed into
// the second window, truncated/overlapping/gapped captures, a duplicated
// operation id, and the eliminated { read open } shape confined to the
// second window. The evaluator (scripts/release-2.4-r7-p21c-verdict.sh) is
// the single authority for the machine-readable verdict; the P21-B
// evaluator stays untouched as the historical instrument, and no test
// reimplements its semantics.

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

// p21cOpSection composes one per-operation evidence section in the
// corrected grammar: header (tag + daemon operation id + session id),
// exact window boundaries, the operation result, the attributed runtime
// records partitioned by attribution quality, and the whole-window
// regression-control sections.
func p21cOpSection(tag, opid, session string, before, after int, opAttributed, pidCorrelated, misattributed, unattributed, p21bTerminal string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "== operation %s op_%s session %s ==\n", tag, opid, session)
	b.WriteString("-- window boundaries (audit.log line offsets) --\n")
	fmt.Fprintf(&b, "before=%d after=%d captured=%d\n", before, after, after-before)
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
// appended between the two operations' capture boundaries, attributable to
// NEITHER operation (host audit noise is expected there).
func p21cInterSection(gapAfter, gapBefore int, records string) string {
	var b strings.Builder
	b.WriteString("== inter-window records (attributable to NEITHER operation) ==\n")
	b.WriteString("-- window boundaries (audit.log line offsets) --\n")
	fmt.Fprintf(&b, "gap-after=%d gap-before=%d captured=%d\n", gapAfter, gapBefore, gapBefore-gapAfter)
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
		"", "", "") +
		p21cOpSection("c2", p21cOp2ID, p21cSession2, 103, 106,
			p21cMounton2+"\n",
			p21cSetuid2+"\n"+p21cSetgid2+"\n",
			"", "", "") +
		p21cInterSection(103, 103, "")
}

func p21cWriteEvidence(t *testing.T, matrix, av, terminals string) string {
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
		p21cGreenTerminals())
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
	}{
		"second window missing entirely":                                        {"P21C-BLOCKED", firstOnly},
		"second window is a copy of the first (the first op's paths inside it)": {"P21C-FAIL", copied},
	} {
		dir := p21cWriteEvidence(t, strings.Join(p21cGreenMatrix(), "\n")+"\n",
			strings.Join(p21cGreenAV(), "\n")+"\n", terminals.text)
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
		"", "", "") +
		p21cOpSection("c2", p21cOp2ID, p21cSession2, 103, 106,
			"", "", "", "", "")
	dir := p21cWriteEvidence(t, strings.Join(p21cGreenMatrix(), "\n")+"\n",
		strings.Join(p21cGreenAV(), "\n")+"\n", terminals)
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
	onlyCategory := `type=AVC msg=audit(1793789899.001:1999): avc:  denied  { mounton } for  pid=3999 comm="runc:[2:INIT]" path="` + p21cOp1Rootfs + `" dev="tmpfs" ino=5 scontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tcontext=system_u:object_r:docker_helper_devnode_t:s0 tclass=file permissive=0`
	// Pathless records only: nothing anchors them to an operation.
	pathless := `type=AVC msg=audit(1793789899.001:1999): avc:  denied  { mounton } for  pid=3999 comm="runc:[2:INIT]" capability=7  scontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tcontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tclass=cap_userns permissive=0`
	terminals := p21cOpSection("c1", p21cOp1ID, p21cSession1, 100, 103,
		"", "", "", pathless+"\n", "") +
		p21cOpSection("c2", p21cOp2ID, p21cSession2, 103, 106,
			"", "", "", onlyCategory+"\n", "")
	dir := p21cWriteEvidence(t, strings.Join(p21cGreenMatrix(), "\n")+"\n",
		strings.Join(p21cGreenAV(), "\n")+"\n", terminals)
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
	}{
		"first op's terminal record placed into the second window": {"P21C-FAIL",
			p21cOpSection("c1", p21cOp1ID, p21cSession1, 100, 103,
				p21cMounton1+"\n",
				p21cSetuid1+"\n"+p21cSetgid1+"\n",
				"", "", "") +
				p21cOpSection("c2", p21cOp2ID, p21cSession2, 103, 106,
					p21cMounton1+"\n"+p21cMounton2+"\n",
					p21cSetuid2+"\n"+p21cSetgid2+"\n",
					"", "", "")},
		"unattributed runc-init record in the first window": {"P21C-BLOCKED",
			p21cOpSection("c1", p21cOp1ID, p21cSession1, 100, 103,
				p21cMounton1+"\n",
				p21cSetuid1+"\n"+p21cSetgid1+"\n",
				"", stray+"\n", "") +
				p21cOpSection("c2", p21cOp2ID, p21cSession2, 103, 106,
					p21cMounton2+"\n",
					p21cSetuid2+"\n"+p21cSetgid2+"\n",
					"", "", "")},
	} {
		dir := p21cWriteEvidence(t, strings.Join(p21cGreenMatrix(), "\n")+"\n",
			strings.Join(p21cGreenAV(), "\n")+"\n", terminals.text)
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
	truncated := p21cOpSection("c1", p21cOp1ID, p21cSession1, 100, 103,
		p21cMounton1+"\n",
		p21cSetuid1+"\n"+p21cSetgid1+"\n",
		"", "", "") +
		strings.Replace(p21cOpSection("c2", p21cOp2ID, p21cSession2, 103, 106,
			p21cMounton2+"\n",
			p21cSetuid2+"\n"+p21cSetgid2+"\n",
			"", "", ""), "before=103 after=106 captured=3", "before=103 after=106 captured=2", 1) +
		p21cInterSection(103, 103, "")
	overlapping := p21cOpSection("c1", p21cOp1ID, p21cSession1, 100, 103,
		p21cMounton1+"\n",
		p21cSetuid1+"\n"+p21cSetgid1+"\n",
		"", "", "") +
		strings.Replace(p21cOpSection("c2", p21cOp2ID, p21cSession2, 103, 106,
			p21cMounton2+"\n",
			p21cSetuid2+"\n"+p21cSetgid2+"\n",
			"", "", ""), "before=103 after=106 captured=3", "before=102 after=105 captured=3", 1) +
		p21cInterSection(103, 103, "")
	unaccountedGap := p21cOpSection("c1", p21cOp1ID, p21cSession1, 100, 103,
		p21cMounton1+"\n",
		p21cSetuid1+"\n"+p21cSetgid1+"\n",
		"", "", "") +
		strings.Replace(p21cOpSection("c2", p21cOp2ID, p21cSession2, 103, 106,
			p21cMounton2+"\n",
			p21cSetuid2+"\n"+p21cSetgid2+"\n",
			"", "", ""), "before=103 after=106 captured=3", "before=110 after=113 captured=3", 1) +
		p21cInterSection(103, 103, "")
	// A capture gap WITH a faithful inter-window section (host noise only)
	// is sound evidence: the gap region is accounted and carries no
	// ambiguous runtime record.
	accountedGap := p21cOpSection("c1", p21cOp1ID, p21cSession1, 100, 103,
		p21cMounton1+"\n",
		p21cSetuid1+"\n"+p21cSetgid1+"\n",
		"", "", "") +
		strings.Replace(p21cOpSection("c2", p21cOp2ID, p21cSession2, 103, 106,
			p21cMounton2+"\n",
			p21cSetuid2+"\n"+p21cSetgid2+"\n",
			"", "", ""), "before=103 after=106 captured=3", "before=110 after=113 captured=3", 1) +
		p21cInterSection(103, 110, "")
	unbounded := p21cOpSection("c1", p21cOp1ID, p21cSession1, 100, 103,
		p21cMounton1+"\n",
		p21cSetuid1+"\n"+p21cSetgid1+"\n",
		"", "", "") +
		strings.Replace(p21cOpSection("c2", p21cOp2ID, p21cSession2, 103, 106,
			p21cMounton2+"\n",
			p21cSetuid2+"\n"+p21cSetgid2+"\n",
			"", "", ""), "before=103 after=106 captured=3", "before=103 after=105 captured=ROTATED", 1) +
		p21cInterSection(103, 103, "")
	ambiguousGap := p21cOpSection("c1", p21cOp1ID, p21cSession1, 100, 103,
		p21cMounton1+"\n",
		p21cSetuid1+"\n"+p21cSetgid1+"\n",
		"", "", "") +
		p21cOpSection("c2", p21cOp2ID, p21cSession2, 103, 106,
			p21cMounton2+"\n",
			p21cSetuid2+"\n"+p21cSetgid2+"\n",
			"", "", "") +
		p21cInterSection(103, 110, p21cMounton2+"\n")
	for name, terminals := range map[string]struct {
		want string
		text string
	}{
		"truncated capture (boundary inconsistent)":           {"P21C-BLOCKED", truncated},
		"second window overlaps the first":                    {"P21C-FAIL", overlapping},
		"capture gap between the windows is unaccounted":      {"P21C-BLOCKED", unaccountedGap},
		"a runc-init record inside the inter-window region":   {"P21C-BLOCKED", ambiguousGap},
		"rotated capture (capture-unavailable boundary mark)": {"P21C-BLOCKED", unbounded},
	} {
		dir := p21cWriteEvidence(t, strings.Join(p21cGreenMatrix(), "\n")+"\n",
			strings.Join(p21cGreenAV(), "\n")+"\n", terminals.text)
		line, rc := p21cRunEvaluator(t, dir)
		if rc == 0 || !strings.Contains(line, "DECISION="+terminals.want) {
			t.Errorf("%s must decide %s, got rc=%d: %s", name, terminals.want, rc, line)
		}
	}
	// The accounted-gap control: with a faithful inter-window section the
	// same gapped capture measures.
	dir := p21cWriteEvidence(t, strings.Join(p21cGreenMatrix(), "\n")+"\n",
		strings.Join(p21cGreenAV(), "\n")+"\n", accountedGap)
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
		"", "", "") +
		p21cOpSection("c2", p21cOp1ID, p21cSession2, 103, 106,
			p21cMounton2+"\n",
			p21cSetuid2+"\n"+p21cSetgid2+"\n",
			"", "", "")
	sameSession := p21cOpSection("c1", p21cOp1ID, p21cSession1, 100, 103,
		p21cMounton1+"\n",
		p21cSetuid1+"\n"+p21cSetgid1+"\n",
		"", "", "") +
		p21cOpSection("c2", p21cOp2ID, p21cSession1, 103, 106,
			p21cMounton2+"\n",
			p21cSetuid2+"\n"+p21cSetgid2+"\n",
			"", "", "")
	sameTerminal := p21cOpSection("c1", p21cOp1ID, p21cSession1, 100, 103,
		p21cMounton1+"\n",
		p21cSetuid1+"\n"+p21cSetgid1+"\n",
		"", "", "") +
		p21cOpSection("c2", p21cOp2ID, p21cSession2, 103, 106,
			p21cMounton1+"\n",
			p21cSetuid2+"\n"+p21cSetgid2+"\n",
			"", "", "")
	for name, terminals := range map[string]string{
		"same operation id in both windows":                       sameOp,
		"same session id in both windows":                         sameSession,
		"the same AVC record for both terminals (misattribution)": sameTerminal,
	} {
		dir := p21cWriteEvidence(t, strings.Join(p21cGreenMatrix(), "\n")+"\n",
			strings.Join(p21cGreenAV(), "\n")+"\n", terminals)
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
	op2WithOld := strings.Replace(p21cOpSection("c2", p21cOp2ID, p21cSession2, 103, 106,
		p21cMounton2+"\n",
		p21cSetuid2+"\n"+p21cSetgid2+"\n",
		"", "", ""),
		"-- P21-B terminal (devnode_t:file { read open }; the ELIMINATED shape) --\n",
		"-- P21-B terminal (devnode_t:file { read open }; the ELIMINATED shape) --\n"+p21cOldTerminal+"\n", 1)
	terminals := p21cOpSection("c1", p21cOp1ID, p21cSession1, 100, 103,
		p21cMounton1+"\n",
		p21cSetuid1+"\n"+p21cSetgid1+"\n",
		"", "", "") + op2WithOld
	dir := p21cWriteEvidence(t, strings.Join(p21cGreenMatrix(), "\n")+"\n",
		strings.Join(p21cGreenAV(), "\n")+"\n", terminals)
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
		dir := p21cWriteEvidence(t, matrix, strings.Join(p21cGreenAV(), "\n")+"\n", p21cGreenTerminals())
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
			strings.Join(p21cGreenAV(), "\n")+"\n", p21cGreenTerminals())
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
		dir := p21cWriteEvidence(t, strings.Join(p21cGreenMatrix(), "\n")+"\n", mut.mutate(green), p21cGreenTerminals())
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
		dir := p21cWriteEvidence(t, strings.Join(p21cGreenMatrix(), "\n")+"\n",
			strings.Join(p21cGreenAV(), "\n")+"\n", mutated)
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
	if rc := (func() bool { return false })(); rc {
		t.Fatal("unreachable")
	}
	dir := p21cWriteEvidence(t, strings.Join(p21cGreenMatrix(), "\n")+"\n",
		strings.Join(p21cGreenAV(), "\n")+"\n", missingOp2)
	line, rc := p21cRunEvaluator(t, dir)
	if rc == 0 || !strings.Contains(line, "DECISION=P21C-BLOCKED") {
		t.Errorf("a missing second operation header must decide BLOCKED, got rc=%d: %s", rc, line)
	}
	duplicatedOp1 := green + "== operation c1 op_" + p21cOp1ID + " session " + p21cSession1 + " ==\n"
	dir = p21cWriteEvidence(t, strings.Join(p21cGreenMatrix(), "\n")+"\n",
		strings.Join(p21cGreenAV(), "\n")+"\n", duplicatedOp1)
	line, rc = p21cRunEvaluator(t, dir)
	if rc == 0 || !strings.Contains(line, "DECISION=P21C-FAIL") {
		t.Errorf("a duplicated operation header must decide FAIL, got rc=%d: %s", rc, line)
	}
	missingControl := strings.Replace(green,
		"-- P20 terminal (runc_memfd_t:file create) --\n", "", 1)
	dir = p21cWriteEvidence(t, strings.Join(p21cGreenMatrix(), "\n")+"\n",
		strings.Join(p21cGreenAV(), "\n")+"\n", missingControl)
	line, rc = p21cRunEvaluator(t, dir)
	if rc == 0 || !strings.Contains(line, "DECISION=P21C-BLOCKED") {
		t.Errorf("a missing control header (both sections) must decide BLOCKED, got rc=%d: %s", rc, line)
	}
	corruptedHeader := strings.Replace(green,
		"== operation c1 op_"+p21cOp1ID+" session "+p21cSession1+" ==\n",
		"X== operation c1 op_"+p21cOp1ID+" session "+p21cSession1+" ==\n", 1)
	dir = p21cWriteEvidence(t, strings.Join(p21cGreenMatrix(), "\n")+"\n",
		strings.Join(p21cGreenAV(), "\n")+"\n", corruptedHeader)
	line, rc = p21cRunEvaluator(t, dir)
	if rc == 0 || !strings.Contains(line, "DECISION=P21C-BLOCKED") {
		t.Errorf("a corrupted (not whole-line) operation header must decide BLOCKED, got rc=%d: %s", rc, line)
	}
}

// TestR7P21CVerdictMissingEvidenceFilesBlock pins the file-level
// fail-closed branch.
func TestR7P21CVerdictMissingEvidenceFilesBlock(t *testing.T) {
	for _, name := range []string{"create-matrix-before.log", "av-matrix-before.log", "p21c-terminals.log"} {
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
