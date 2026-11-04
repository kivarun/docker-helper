package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// R7 P21-C gate evaluator regression fixtures (the r7-p21c-devnode-open
// task): the fail-closed classification is proven against the REAL
// diagnostic output shapes captured by enforcing run 41623047086 (the
// create-decision matrix and the kernel-AV matrix grammar — the P21-C
// candidate policy changes only the devnode content-permission rows) and
// the P21-B terminal-window record format (whose cap_userns pre-boundary
// records and per-op dev paths the P21-C windows carry unchanged), plus
// synthetic mutations for every fail-closed branch. The evaluator
// (scripts/release-2.4-r7-p21c-verdict.sh) is the single authority for the
// machine-readable verdict; the P21-B evaluator stays untouched as the
// historical instrument, and no test reimplements its semantics.

const (
	p21cC1      = "system_u:system_r:docker_helper_buildkitd_t:s0:c1"
	p21cC2      = "system_u:system_r:docker_helper_buildkitd_t:s0:c2"
	p21cUnconf  = "unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023"
	p21cTmpfs   = "system_u:object_r:tmpfs_t:s0"
	p21cDevnode = "system_u:object_r:docker_helper_devnode_t:s0"
	p21cMemfd   = "system_u:object_r:docker_helper_runc_memfd_t:s0"
	p21cUserTmp = "unconfined_u:object_r:user_tmp_t:s0"
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
// create=ALLOW plus the ONE { read open } open-completion pair (the
// granted mask 0x4000a = create|read|open) with every other permission
// DENIED — the pair must never ride a wider grant; unconfined stays
// all-DENY; the three associate rows are unchanged from P21-B.
func p21cGreenAV() []string {
	granted := []string{"write", "append", "setattr", "execute", "execute_no_trans", "map", "getattr", "unlink", "rename", "link", "ioctl", "lock"}
	var out []string
	out = append(out, "== buildkitd_t:s0:c1 -> docker_helper_devnode_t:s0 ==")
	out = append(out,
		p21cAVFilePerm("create", "ALLOW", "0x4000a"),
		p21cAVFilePerm("open", "ALLOW", "0x4000a"),
		p21cAVFilePerm("read", "ALLOW", "0x4000a"))
	for _, perm := range granted {
		out = append(out, p21cAVFilePerm(perm, "DENY", "0x4000a"))
	}
	out = append(out, "== CROSS-OP: buildkitd_t:s0:c2 -> docker_helper_devnode_t:s0 ==")
	out = append(out,
		p21cAVFilePerm("create", "ALLOW", "0x4000a"),
		p21cAVFilePerm("open", "ALLOW", "0x4000a"),
		p21cAVFilePerm("read", "ALLOW", "0x4000a"))
	for _, perm := range granted {
		out = append(out, p21cAVFilePerm(perm, "DENY", "0x4000a"))
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

// p21cNextTerminalRecord is the fixture's observed next-terminal record: a
// full-structure denied AVC from the same runc:[2:INIT] runtime stage that
// is NOT the granted devnode { read open } shape. The fixture uses the
// file-class mounton of the host device node over the placeholder — the
// predicted follow-on hook the P21-B provenance recorded as its own future
// evidenced rung — purely as a well-formed specimen; the evaluator accepts
// any real new-flow record and pre-classifies nothing.
const p21cNextTerminalRecord = `type=AVC msg=audit(1793714090.100:1201): avc:  denied  { mounton } for  pid=3288 comm="runc:[2:INIT]" path="/var/lib/docker-helper-builder/ops/op_557f5cc38c677ba14475b5dd2f88dbaa/root/runc-native/executor/6jinf8i9db2cl6rsdw8zcony9/rootfs/dev/null" dev="tmpfs" ino=5 scontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tcontext=system_u:object_r:docker_helper_devnode_t:s0 tclass=file permissive=0`

const p21cSetuidRecord = `type=AVC msg=audit(1793714090.090:1199): avc:  denied  { setuid } for  pid=3288 comm="runc:[2:INIT]" capability=7  scontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tcontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tclass=cap_userns permissive=0`

const p21cSetgidRecord = `type=AVC msg=audit(1793714090.091:1200): avc:  denied  { setgid } for  pid=3288 comm="runc:[2:INIT]" capability=6  scontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tcontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tclass=cap_userns permissive=0`

// p21cC2Records is the second window's variant of the same record set (the
// distinct pid, serials, and per-operation path of the P21-B windows; both
// real windows carried the buildkitd_t:s0:c1 source context).
var p21cC2Records = strings.NewReplacer(
	"pid=3288", "pid=3424",
	":1199)", ":1815)",
	":1200)", ":1816)",
	":1201)", ":1817)",
	"op_557f5cc38c677ba14475b5dd2f88dbaa", "op_349ddf17ce6f9448f30d8c2ffad0c32f",
	"6jinf8i9db2cl6rsdw8zcony9", "ygn48dtxodtbs22evtqnhhktx",
).Replace(p21cSetuidRecord + "\n" + p21cSetgidRecord + "\n" + p21cNextTerminalRecord)

// p21cGreenTerminals returns the green live-flow fixture: BOTH windows
// carry the P21-B window's pre-boundary non-fatal cap_userns self-denials
// and the new observed terminal, the granted devnode { read open } shape
// is ABSENT (the rung eliminated it), and the three regression-control
// sections are empty.
func p21cGreenTerminals() string {
	return `== devnode-terminal runc-init AVCs (both windows) ==` + "\n" +
		p21cSetuidRecord + "\n" + p21cSetgidRecord + "\n" + p21cNextTerminalRecord + "\n" +
		p21cC2Records + "\n" +
		`== next-terminal runc-init AVCs (both windows) ==` + "\n" +
		p21cSetuidRecord + "\n" + p21cSetgidRecord + "\n" + p21cNextTerminalRecord + "\n" +
		p21cC2Records + "\n" +
		`== regression controls (must be EMPTY) ==` + "\n" +
		`-- P20 terminal (runc_memfd_t:file create) --` + "\n" +
		`-- pre-B terminal (tmpfs_t:file write) --` + "\n" +
		`-- associate denials (must be EMPTY — the singleton is granted) --` + "\n"
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
// P21C-MEASURED on the green fixture shape with every field at its
// expected value: the transition scope unchanged, the open-completion
// pair eliminated from the windows, the memfd plane intact, the
// cross-operation content channel closed, and a real next-terminal record.
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
	if got := p21cField(t, line, "NEXT-TERMINAL"); !strings.Contains(got, "denied  { mounton }") || strings.Contains(got, "(none)") {
		t.Errorf("NEXT-TERMINAL must be the observed new-flow record, got %q", got)
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
// irregularity — a missing required row, a duplicated row, a wrong result,
// an unexpected row, and an unparseable line — fails closed (never
// MEASURED), with a positive violation taking FAIL over the
// missing-evidence BLOCKED.
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
		{"missing c1/null row", func(r []string) []string {
			i := find("null", p21cC1)
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
		{"wrong result: c2/tty keeps runc_memfd_t", func(r []string) []string {
			i := find("tty", p21cC2)
			out := append([]string(nil), r...)
			out[i] = p21cCreateRow(p21cC2, "tty", p21cMemfd)
			return out
		}},
		{"arbitrary name diverted to devnode_t", func(r []string) []string {
			i := find("someothername", p21cC1)
			out := append([]string(nil), r...)
			out[i] = p21cCreateRow(p21cC1, "someothername", p21cDevnode)
			return out
		}},
		{"name=NULL diverted to devnode_t", func(r []string) []string {
			i := find("-", p21cC1)
			out := append([]string(nil), r...)
			out[i] = p21cCreateRow(p21cC1, "-", p21cDevnode)
			return out
		}},
		{"unconfined control diverted", func(r []string) []string {
			i := find("null", p21cUnconf)
			out := append([]string(nil), r...)
			out[i] = p21cCreateRow(p21cUnconf, "null", p21cDevnode)
			return out
		}},
		{"unexpected seventh basename row", func(r []string) []string {
			return append(r, p21cCreateRow(p21cC1, "stdin", p21cDevnode))
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
		if mut.name == "missing c2/tty row" && !strings.Contains(line, "DECISION=P21C-BLOCKED") {
			t.Errorf("a purely missing row must decide BLOCKED (fail-closed), got: %s", line)
		}
	}
}

// TestR7P21CVerdictMatrixStructureMutationsFailClosed proves the FULL row
// structure is part of the requirement: a row whose RESULT alone would
// look right is still rejected when its parent (target) context, class,
// source context, or name is wrong — no partial-structure acceptance.
func TestR7P21CVerdictMatrixStructureMutationsFailClosed(t *testing.T) {
	mutations := []struct {
		name    string
		corrupt func(string) string
	}{
		{"wrong parent context, result still devnode_t", func(r string) string {
			return strings.Replace(r,
				"CREATE "+p21cC1+" x "+p21cTmpfs+" x file [null] -> "+p21cDevnode,
				"CREATE "+p21cC1+" x system_u:object_r:builder_runtime_t:s0 x file [null] -> "+p21cDevnode, 1)
		}},
		{"wrong class, result still devnode_t", func(r string) string {
			return strings.Replace(r,
				"CREATE "+p21cC1+" x "+p21cTmpfs+" x file [null] -> "+p21cDevnode,
				"CREATE "+p21cC1+" x "+p21cTmpfs+" x dir [null] -> "+p21cDevnode, 1)
		}},
		{"wrong source context, right name and result", func(r string) string {
			return strings.Replace(r,
				"CREATE "+p21cC1+" x "+p21cTmpfs+" x file [null] -> "+p21cDevnode,
				"CREATE system_u:system_r:docker_helper_t:s0:c1 x "+p21cTmpfs+" x file [null] -> "+p21cDevnode, 1)
		}},
		{"wrong name, right result", func(r string) string {
			return strings.Replace(r,
				"CREATE "+p21cC1+" x "+p21cTmpfs+" x file [null] -> "+p21cDevnode,
				"CREATE "+p21cC1+" x "+p21cTmpfs+" x file [nul] -> "+p21cDevnode, 1)
		}},
		{"wrong result", func(r string) string {
			return strings.Replace(r,
				"CREATE "+p21cC1+" x "+p21cTmpfs+" x file [null] -> "+p21cDevnode,
				"CREATE "+p21cC1+" x "+p21cTmpfs+" x file [null] -> "+p21cMemfd, 1)
		}},
	}
	for _, mut := range mutations {
		dir := p21cWriteEvidence(t, mut.corrupt(strings.Join(p21cGreenMatrix(), "\n")+"\n"),
			strings.Join(p21cGreenAV(), "\n")+"\n", p21cGreenTerminals())
		line, rc := p21cRunEvaluator(t, dir)
		if rc == 0 || strings.Contains(line, "DECISION=P21C-MEASURED") {
			t.Errorf("mutation %q must fail closed, got rc=%d: %s", mut.name, rc, line)
		}
	}
}

// TestR7P21CVerdictAVMutationsFailClosed proves the AV-matrix branches for
// the P21-C shape: the { read open } pair must be EXACTLY granted for both
// operation categories (a DENIED pair member is a wrong verdict — the rung
// did not take effect), every other permission must stay DENIED, the
// unconfined surface must stay all-DENY, the associate rows must stay
// unchanged, and missing/duplicated/unparseable rows fail closed.
func TestR7P21CVerdictAVMutationsFailClosed(t *testing.T) {
	green := strings.Join(p21cGreenAV(), "\n") + "\n"
	mutations := []struct {
		name   string
		mutate func(string) string
	}{
		{"c1 pair member read DENIED", func(p string) string {
			return strings.Replace(p, p21cAVFilePerm("read", "ALLOW", "0x4000a"), p21cAVFilePerm("read", "DENY", "0x40008"), 1)
		}},
		{"c1 pair member open DENIED", func(p string) string {
			return strings.Replace(p, p21cAVFilePerm("open", "ALLOW", "0x4000a"), p21cAVFilePerm("open", "DENY", "0xa"), 1)
		}},
		{"c2 pair member read DENIED", func(p string) string {
			return strings.Replace(p, p21cAVFilePerm("read", "ALLOW", "0x4000a"), p21cAVFilePerm("read", "DENY", "0x4000a"), 1)
		}},
		{"c1 write ALLOW (the rejected content authority)", func(p string) string {
			return strings.Replace(p, p21cAVFilePerm("write", "DENY", "0x4000a"), p21cAVFilePerm("write", "ALLOW", "0x4000a"), 1)
		}},
		{"c2 write ALLOW", func(p string) string {
			return strings.Replace(p, p21cAVFilePerm("write", "DENY", "0x4000a"), p21cAVFilePerm("write", "ALLOW", "0x4000a"), 1)
		}},
		{"c1 setattr ALLOW", func(p string) string {
			return strings.Replace(p, p21cAVFilePerm("setattr", "DENY", "0x4000a"), p21cAVFilePerm("setattr", "ALLOW", "0x4000a"), 1)
		}},
		{"c1 map ALLOW", func(p string) string {
			return strings.Replace(p, p21cAVFilePerm("map", "DENY", "0x4000a"), p21cAVFilePerm("map", "ALLOW", "0x4000a"), 1)
		}},
		{"c1 execute ALLOW", func(p string) string {
			return strings.Replace(p, p21cAVFilePerm("execute", "DENY", "0x4000a"), p21cAVFilePerm("execute", "ALLOW", "0x4000a"), 1)
		}},
		{"unconfined read ALLOW", func(p string) string {
			return strings.Replace(p, p21cAVFilePerm("read", "DENY", "0x0"), p21cAVFilePerm("read", "ALLOW", "0x2"), 1)
		}},
		{"unconfined create ALLOW", func(p string) string {
			return strings.Replace(p, p21cAVFilePerm("create", "DENY", "0x0"), p21cAVFilePerm("create", "ALLOW", "0x8"), 1)
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
			return strings.Replace(p, p21cAVFilePerm("lock", "DENY", "0x4000a"), "", 1)
		}},
		{"duplicated c1/create row", func(p string) string {
			needle := p21cAVFilePerm("create", "ALLOW", "0x4000a")
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

// TestR7P21CVerdictTerminalMutationsFailClosed proves the live-flow
// branches: the P21-B measured terminal reappearing decides FAIL with
// OPEN-COMPLETION=live, a reappeared regression-control record decides
// FAIL (MEMFD=regressed for the P20 shape), a window with no further
// new-flow record decides BLOCKED (absence of AVCs alone is never a
// passing outcome), and the cap_userns pre-boundary self-denials can never
// be selected as the next terminal.
func TestR7P21CVerdictTerminalMutationsFailClosed(t *testing.T) {
	green := p21cGreenTerminals()
	oldTerminal := `type=AVC msg=audit(1793714070.816:1190): avc:  denied  { read open } for  pid=3288 comm="runc:[2:INIT]" path="/var/lib/docker-helper-builder/ops/op_557f5cc38c677ba14475b5dd2f88dbaa/root/runc-native/executor/6jinf8i9db2cl6rsdw8zcony9/rootfs/dev/null" dev="tmpfs" ino=5 scontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tcontext=system_u:object_r:docker_helper_devnode_t:s0 tclass=file permissive=0`
	mutations := []struct {
		name             string
		mutate           func(string) string
		wantDECISION     string
		wantOPENCOMPLETE string
		wantMEMFD        string
	}{
		{"P21-B devnode { read open } terminal reappeared", func(p string) string {
			return strings.Replace(p,
				"== devnode-terminal runc-init AVCs (both windows) ==\n",
				"== devnode-terminal runc-init AVCs (both windows) ==\n"+oldTerminal+"\n", 1)
		}, "P21C-FAIL", "live", "intact"},
		{"P20 runc_memfd create denial reappeared", func(p string) string {
			return strings.Replace(p,
				"-- P20 terminal (runc_memfd_t:file create) --",
				"-- P20 terminal (runc_memfd_t:file create) --\n"+
					`type=AVC msg=audit(1793703417.986:9999): avc:  denied  { create } for  pid=3261 comm="runc:[2:INIT]" name="null" scontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tcontext=system_u:object_r:docker_helper_runc_memfd_t:s0 tclass=file permissive=0`, 1)
		}, "P21C-FAIL", "eliminated", "regressed"},
		{"pre-B tmpfs_t:file write denial reappeared", func(p string) string {
			return strings.Replace(p,
				"-- pre-B terminal (tmpfs_t:file write) --",
				"-- pre-B terminal (tmpfs_t:file write) --\n"+
					`type=AVC msg=audit(1793703417.986:9998): avc:  denied  { write } for  pid=3261 comm="buildkit-runc" path=2F6D656D66643A scontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tcontext=system_u:object_r:tmpfs_t:s0 tclass=file permissive=0`, 1)
		}, "P21C-FAIL", "eliminated", "intact"},
		{"associate denial reappeared", func(p string) string {
			return strings.Replace(p,
				"-- associate denials (must be EMPTY — the singleton is granted) --",
				"-- associate denials (must be EMPTY — the singleton is granted) --\n"+
					`type=AVC msg=audit(1793703417.986:9997): avc:  denied  { associate } for  pid=3261 comm="runc:[2:INIT]" name="null" scontext=system_u:object_r:docker_helper_devnode_t:s0 tcontext=system_u:object_r:tmpfs_t:s0 tclass=filesystem permissive=0`, 1)
		}, "P21C-FAIL", "eliminated", "intact"},
		{"only the pre-boundary cap_userns records (no new-flow record)", func(p string) string {
			var kept []string
			for _, l := range strings.Split(p, "\n") {
				if strings.Contains(l, "denied  { mounton }") {
					continue
				}
				kept = append(kept, l)
			}
			return strings.Join(kept, "\n")
		}, "P21C-BLOCKED", "eliminated", "intact"},
		{"no runc-init records at all (absence of AVC is never a pass)", func(p string) string {
			var kept []string
			for _, l := range strings.Split(p, "\n") {
				if strings.Contains(l, `comm="runc:[2:INIT]"`) {
					continue
				}
				kept = append(kept, l)
			}
			return strings.Join(kept, "\n")
		}, "P21C-BLOCKED", "eliminated", "intact"},
		{"devnode-terminal header missing (nothing established about the pair)", func(p string) string {
			return strings.Replace(p,
				"== devnode-terminal runc-init AVCs (both windows) ==\n", "", 1)
		}, "P21C-BLOCKED", "not-established", "intact"},
	}
	for _, mut := range mutations {
		dir := p21cWriteEvidence(t, strings.Join(p21cGreenMatrix(), "\n")+"\n",
			strings.Join(p21cGreenAV(), "\n")+"\n", mut.mutate(green))
		line, rc := p21cRunEvaluator(t, dir)
		if !strings.Contains(line, "DECISION="+mut.wantDECISION) || rc == 0 {
			t.Errorf("mutation %q must decide %s, got rc=%d: %s", mut.name, mut.wantDECISION, rc, line)
		}
		if got := p21cField(t, line, "OPEN-COMPLETION"); got != mut.wantOPENCOMPLETE {
			t.Errorf("mutation %q must report OPEN-COMPLETION=%s, got %q", mut.name, mut.wantOPENCOMPLETE, got)
		}
		if got := p21cField(t, line, "MEMFD"); got != mut.wantMEMFD {
			t.Errorf("mutation %q must report MEMFD=%s, got %q", mut.name, mut.wantMEMFD, got)
		}
	}
}

// TestR7P21CVerdictNextTerminalRecordMutationsFailClosed proves the strict
// next-terminal matcher: an arbitrary AVC carrying the granted shape or
// the pre-boundary cap_userns self-denials is never accepted as the new
// terminal. Each mutation leaves a window whose only runc-init records are
// NOT acceptable next-terminal evidence; the evaluator must decide
// BLOCKED, never MEASURED.
func TestR7P21CVerdictNextTerminalRecordMutationsFailClosed(t *testing.T) {
	mutations := []struct {
		name         string
		corrupt      func(string) string
		wantDECISION string
	}{
		{"next-terminal record corrupted to permissive=1", func(p string) string {
			return strings.ReplaceAll(p, "tclass=file permissive=0", "tclass=file permissive=1")
		}, "P21C-BLOCKED"},
		{"next-terminal record corrupted to unconfined source", func(p string) string {
			return strings.ReplaceAll(p, "scontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tcontext=system_u:object_r:docker_helper_devnode_t:s0 tclass=file",
				"scontext=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 tcontext=system_u:object_r:docker_helper_devnode_t:s0 tclass=file")
		}, "P21C-BLOCKED"},
		{"next-terminal record corrupted to a foreign comm", func(p string) string {
			return strings.ReplaceAll(p, `comm="runc:[2:INIT]" path="/var/lib`, `comm="buildkit-runc" path="/var/lib`)
		}, "P21C-BLOCKED"},
		{"next-terminal record corrupted to the granted shape", func(p string) string {
			return strings.ReplaceAll(p, "denied  { mounton }", "denied  { read open }")
		}, "P21C-FAIL"},
		{"next-terminal record downgraded to cap_userns", func(p string) string {
			out := strings.ReplaceAll(p, "denied  { mounton }", "denied  { setuid }")
			return strings.ReplaceAll(out,
				"tcontext=system_u:object_r:docker_helper_devnode_t:s0 tclass=file",
				"tcontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tclass=cap_userns")
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

// TestR7P21CVerdictRegressionSectionHeadersFailClosed proves the section
// headers are mandatory evidence: a missing header decides BLOCKED
// (damaged or truncated evidence can never be MEASURED) and a duplicated
// control header decides FAIL (ambiguous evidence).
func TestR7P21CVerdictRegressionSectionHeadersFailClosed(t *testing.T) {
	headers := []string{
		"== devnode-terminal runc-init AVCs (both windows) ==",
		"== next-terminal runc-init AVCs (both windows) ==",
		"== regression controls (must be EMPTY) ==",
		"-- P20 terminal (runc_memfd_t:file create) --",
		"-- pre-B terminal (tmpfs_t:file write) --",
		"-- associate denials (must be EMPTY — the singleton is granted) --",
	}
	for _, header := range headers {
		missing := strings.Replace(p21cGreenTerminals(), header+"\n", "", 1)
		dir := p21cWriteEvidence(t, strings.Join(p21cGreenMatrix(), "\n")+"\n",
			strings.Join(p21cGreenAV(), "\n")+"\n", missing)
		line, rc := p21cRunEvaluator(t, dir)
		if rc == 0 || !strings.Contains(line, "DECISION=P21C-BLOCKED") {
			t.Errorf("missing header %q must decide BLOCKED, got rc=%d: %s", header, rc, line)
		}
	}
	for _, header := range headers[2:] {
		duplicated := strings.Replace(p21cGreenTerminals(), header+"\n", header+"\n"+header+"\n", 1)
		dir := p21cWriteEvidence(t, strings.Join(p21cGreenMatrix(), "\n")+"\n",
			strings.Join(p21cGreenAV(), "\n")+"\n", duplicated)
		line, rc := p21cRunEvaluator(t, dir)
		if rc == 0 || !strings.Contains(line, "DECISION=P21C-FAIL") {
			t.Errorf("duplicated header %q must decide FAIL, got rc=%d: %s", header, rc, line)
		}
	}
}

// TestR7P21CVerdictHeaderIntegrityFailClosed proves header recognition is
// whole-line and consistent with the AWK section anchoring: a header that
// appears only as a substring of a corrupted line (prefixed, suffixed, or
// trailing-whitespace variant) is a MISSING header (BLOCKED — damaged or
// truncated evidence can never be MEASURED).
func TestR7P21CVerdictHeaderIntegrityFailClosed(t *testing.T) {
	headers := []string{
		"== devnode-terminal runc-init AVCs (both windows) ==",
		"== next-terminal runc-init AVCs (both windows) ==",
		"== regression controls (must be EMPTY) ==",
		"-- P20 terminal (runc_memfd_t:file create) --",
		"-- pre-B terminal (tmpfs_t:file write) --",
		"-- associate denials (must be EMPTY — the singleton is granted) --",
	}
	corruptions := map[string]func(string) string{
		"prefixed":       func(h string) string { return "X" + h },
		"suffixed":       func(h string) string { return h + "X" },
		"trailing space": func(h string) string { return h + " " },
	}
	for _, header := range headers {
		for cname, corrupt := range corruptions {
			mutated := strings.Replace(p21cGreenTerminals(), header+"\n", corrupt(header)+"\n", 1)
			dir := p21cWriteEvidence(t, strings.Join(p21cGreenMatrix(), "\n")+"\n",
				strings.Join(p21cGreenAV(), "\n")+"\n", mutated)
			line, rc := p21cRunEvaluator(t, dir)
			if rc == 0 || !strings.Contains(line, "DECISION=P21C-BLOCKED") {
				t.Errorf("header %q with %q corruption must decide BLOCKED (the header is not a whole line), got rc=%d: %s", header, cname, rc, line)
			}
		}
	}
}

// TestR7P21CVerdictMissingEvidenceFilesBlock pins the file-level
// fail-closed branch: a missing or empty required evidence file can never
// produce a passing decision, and a missing evaluator input directory is
// BLOCKED.
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
// first field is the single DECISION=P21C-MEASURED — a verdict whose
// DECISION is not P21C-MEASURED, a second DECISION field, the MEASURED
// literal as a substring of another field's value, a malformed prefix, a
// truncated line, an empty/trailing field, an unknown field, or a
// missing/placeholder/corrupted NEXT-TERMINAL is rejected.
func TestR7P21CVerdictGateMode(t *testing.T) {
	accepted := "R7-P21C-VERDICT=DECISION=P21C-MEASURED;SCOPE=six-names-ok;OPEN-COMPLETION=eliminated;MEMFD=intact;CROSSOP-CONTENT=closed;NEXT-TERMINAL=<" + p21cNextTerminalRecord + ">"
	if rc := exec.Command("bash", "scripts/release-2.4-r7-p21c-verdict.sh", "--gate", accepted).Run(); rc != nil {
		t.Errorf("--gate must accept a correctly formed MEASURED verdict line: %v", rc)
	}
	for _, bad := range []string{
		"R7-P21C-VERDICT=DECISION=P21C-FAIL;NOTE=DECISION=P21C-MEASURED",
		"R7-P21C-VERDICT=DECISION=P21C-BLOCKED;DECISION=P21C-MEASURED",
		"R7-P21C-VERDICT=DECISION=P21C-MEASURED;DECISION=P21C-FAIL",
		"R7-P21C-VERDICT=DECISION=P21C-FAIL;SCOPE=not-established",
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
