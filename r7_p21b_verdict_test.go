package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// R7 P21-B gate evaluator regression fixtures (the r7-p21b-corrective
// tasks): the fail-closed classification is proven against the REAL
// diagnostic output lines captured by enforcing run 41623047086 (the
// create-decision matrix and the kernel-AV matrix of the accepted E1
// candidate) and run 41648049864 (the live-flow terminal records, whose
// exact format defines the evaluator's strict terminal matcher), plus
// synthetic mutations for every fail-closed branch — including the
// "0\n0" grep-artifact shape that defeated the replaced count-based
// classifier. The evaluator (scripts/release-2.4-r7-p21b-verdict.sh) is
// the single authority for the machine-readable verdict; no test
// reimplements its semantics.

const (
	p21bC1      = "system_u:system_r:docker_helper_buildkitd_t:s0:c1"
	p21bC2      = "system_u:system_r:docker_helper_buildkitd_t:s0:c2"
	p21bUnconf  = "unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023"
	p21bTmpfs   = "system_u:object_r:tmpfs_t:s0"
	p21bDevnode = "system_u:object_r:docker_helper_devnode_t:s0"
	p21bMemfd   = "system_u:object_r:docker_helper_runc_memfd_t:s0"
	p21bUserTmp = "unconfined_u:object_r:user_tmp_t:s0"
)

// p21bDevnodeBasenames is the exact six-basename list the P21-B policy
// diverts (runc v1.4.3 AllowedDevices placeholders).
var p21bDevnodeBasenames = []string{"null", "zero", "full", "random", "urandom", "tty"}

func p21bCreateRow(src, name, result string) string {
	return "CREATE " + src + " x " + p21bTmpfs + " x file [" + name + "] -> " + result
}

// p21bGreenMatrix returns the real create-decision rows of run
// 41623047086 (the c1 diversion rows and the arbitrary-name/NULL controls
// are verbatim captures; the c2 rows use the identical probe grammar and
// are produced for real by the corrected matrix), plus the unconfined
// controls.
func p21bGreenMatrix() []string {
	var rows []string
	for _, name := range p21bDevnodeBasenames {
		rows = append(rows, p21bCreateRow(p21bC1, name, p21bDevnode))
	}
	for _, name := range p21bDevnodeBasenames {
		rows = append(rows, p21bCreateRow(p21bC2, name, p21bDevnode))
	}
	rows = append(rows,
		p21bCreateRow(p21bC1, "someothername", p21bMemfd),
		p21bCreateRow(p21bC1, "-", p21bMemfd),
		p21bCreateRow(p21bC2, "someothername", p21bMemfd),
		p21bCreateRow(p21bC2, "-", p21bMemfd),
		p21bCreateRow(p21bUnconf, "null", p21bUserTmp),
		p21bCreateRow(p21bUnconf, "-", p21bUserTmp),
	)
	return rows
}

// p21bAVFilePerm is one kernel-AV matrix row in the probe's exact format.
func p21bAVFilePerm(perm, verdict, allowed string) string {
	return "  " + perm + " " + verdict + " (allowed=" + allowed + " decided=0xffffffff)"
}

// p21bGreenAV returns the real kernel-AV rows of run 41623047086 (the
// devnode create=0x8 allow and the deny-all content surface for both
// operation categories, the unconfined deny-all section, and the three
// associate rows).
func p21bGreenAV() []string {
	var out []string
	out = append(out, "== buildkitd_t:s0:c1 -> docker_helper_devnode_t:s0 ==")
	out = append(out, p21bAVFilePerm("create", "ALLOW", "0x8"))
	for _, perm := range []string{"write", "append", "setattr", "execute", "execute_no_trans", "map", "open", "read", "getattr", "unlink", "rename", "link", "ioctl", "lock"} {
		out = append(out, p21bAVFilePerm(perm, "DENY", "0x8"))
	}
	out = append(out, "== CROSS-OP: buildkitd_t:s0:c2 -> docker_helper_devnode_t:s0 ==")
	out = append(out, p21bAVFilePerm("create", "ALLOW", "0x8"))
	for _, perm := range []string{"write", "append", "setattr", "execute", "execute_no_trans", "map", "open", "read", "getattr", "unlink", "rename", "link", "ioctl", "lock"} {
		out = append(out, p21bAVFilePerm(perm, "DENY", "0x8"))
	}
	out = append(out, "== unconfined_t -> docker_helper_devnode_t:s0 ==")
	for _, perm := range []string{"create", "write", "append", "setattr", "execute", "execute_no_trans", "map", "open", "read", "getattr", "unlink", "rename", "link", "ioctl", "lock"} {
		out = append(out, p21bAVFilePerm(perm, "DENY", "0x0"))
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

// p21bGreenTerminals returns the real live-flow window records of run
// 41648049864 (serials 1188-1190 and 1815-1817, verbatim): the recorded
// docker_helper_devnode_t:file { read open } next terminal for both
// windows, and the three EMPTY regression-control sections. These real
// records define the format the evaluator's strict terminal matcher must
// accept.
func p21bGreenTerminals() string {
	return `== devnode-terminal runc-init AVCs (both windows) ==
type=AVC msg=audit(1793714070.810:1188): avc:  denied  { setuid } for  pid=3288 comm="runc:[2:INIT]" capability=7  scontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tcontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tclass=cap_userns permissive=0
type=AVC msg=audit(1793714070.810:1189): avc:  denied  { setgid } for  pid=3288 comm="runc:[2:INIT]" capability=6  scontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tcontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tclass=cap_userns permissive=0
type=AVC msg=audit(1793714070.816:1190): avc:  denied  { read open } for  pid=3288 comm="runc:[2:INIT]" path="/var/lib/docker-helper-builder/ops/op_557f5cc38c677ba14475b5dd2f88dbaa/root/runc-native/executor/6jinf8i9db2cl6rsdw8zcony9/rootfs/dev/null" dev="tmpfs" ino=5 scontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tcontext=system_u:object_r:docker_helper_devnode_t:s0 tclass=file permissive=0
type=AVC msg=audit(1793714070.810:1188): avc:  denied  { setuid } for  pid=3288 comm="runc:[2:INIT]" capability=7  scontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tcontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tclass=cap_userns permissive=0
type=AVC msg=audit(1793714070.810:1189): avc:  denied  { setgid } for  pid=3288 comm="runc:[2:INIT]" capability=6  scontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tcontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tclass=cap_userns permissive=0
type=AVC msg=audit(1793714070.816:1190): avc:  denied  { read open } for  pid=3288 comm="runc:[2:INIT]" path="/var/lib/docker-helper-builder/ops/op_557f5cc38c677ba14475b5dd2f88dbaa/root/runc-native/executor/6jinf8i9db2cl6rsdw8zcony9/rootfs/dev/null" dev="tmpfs" ino=5 scontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tcontext=system_u:object_r:docker_helper_devnode_t:s0 tclass=file permissive=0
type=AVC msg=audit(1793714072.887:1815): avc:  denied  { setuid } for  pid=3424 comm="runc:[2:INIT]" capability=7  scontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tcontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tclass=cap_userns permissive=0
type=AVC msg=audit(1793714072.887:1816): avc:  denied  { setgid } for  pid=3424 comm="runc:[2:INIT]" capability=6  scontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tcontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tclass=cap_userns permissive=0
type=AVC msg=audit(1793714072.893:1817): avc:  denied  { read open } for  pid=3424 comm="runc:[2:INIT]" path="/var/lib/docker-helper-builder/ops/op_349ddf17ce6f9448f30d8c2ffad0c32f/root/runc-native/executor/ygn48dtxodtbs22evtqnhhktx/rootfs/dev/null" dev="tmpfs" ino=5 scontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tcontext=system_u:object_r:docker_helper_devnode_t:s0 tclass=file permissive=0
== regression controls (must be EMPTY) ==
-- P20 terminal (runc_memfd_t:file create) --
-- pre-B terminal (tmpfs_t:file write) --
-- associate denials (must be EMPTY — the singleton is granted) --
`
}

func p21bWriteEvidence(t *testing.T, matrix, av, terminals string) string {
	t.Helper()
	dir := t.TempDir()
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("create-matrix-before.log", matrix)
	write("av-matrix-before.log", av)
	write("p21b-terminals.log", terminals)
	return dir
}

func p21bRunEvaluator(t *testing.T, dir string) (string, int) {
	t.Helper()
	out, err := exec.Command("bash", "scripts/release-2.4-r7-p21b-verdict.sh", dir).CombinedOutput()
	line := ""
	for _, l := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(l, "R7-P21B-VERDICT=") {
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

func p21bField(t *testing.T, verdict, key string) string {
	t.Helper()
	for _, part := range strings.Split(strings.TrimPrefix(verdict, "R7-P21B-VERDICT="), ";") {
		if strings.HasPrefix(part, key+"=") {
			return strings.TrimPrefix(part, key+"=")
		}
	}
	t.Fatalf("verdict %q carries no %s field", verdict, key)
	return ""
}

func p21bGreenDir(t *testing.T) string {
	return p21bWriteEvidence(t,
		strings.Join(p21bGreenMatrix(), "\n")+"\n",
		strings.Join(p21bGreenAV(), "\n")+"\n",
		p21bGreenTerminals())
}

// TestR7P21BVerdictGreenEvidenceIsMeasured proves the evaluator decides
// P21B-MEASURED on the real run-41623047086 evidence shape with every
// field at its expected value.
func TestR7P21BVerdictGreenEvidenceIsMeasured(t *testing.T) {
	line, rc := p21bRunEvaluator(t, p21bGreenDir(t))
	if rc != 0 {
		t.Fatalf("green evidence must decide P21B-MEASURED (rc=0), got rc=%d: %s", rc, line)
	}
	if !strings.Contains(line, "DECISION=P21B-MEASURED") {
		t.Errorf("green evidence must carry DECISION=P21B-MEASURED: %s", line)
	}
	if got := p21bField(t, line, "SCOPE"); got != "six-names-ok" {
		t.Errorf("SCOPE must be six-names-ok, got %q", got)
	}
	if got := p21bField(t, line, "ARBITRARY-NAME-KEEPS-MEMFD"); got != "yes" {
		t.Errorf("ARBITRARY-NAME-KEEPS-MEMFD must be yes (the raw matrix proves it), got %q", got)
	}
	if got := p21bField(t, line, "MEMFD"); got != "intact" {
		t.Errorf("MEMFD must be intact, got %q", got)
	}
	if got := p21bField(t, line, "CROSSOP-CONTENT"); got != "closed" {
		t.Errorf("CROSSOP-CONTENT must be closed, got %q", got)
	}
	if got := p21bField(t, line, "NEXT-TERMINAL"); !strings.Contains(got, "docker_helper_devnode_t:s0 tclass=file") {
		t.Errorf("NEXT-TERMINAL must be the devnode { read open } record, got %q", got)
	}
}

// TestR7P21BVerdictZeroNewlineGrepArtifactFailsClosed pins the replaced
// classifier's concrete failure: the old code fed a "0\n0" blob (grep -c
// printing 0 with the || echo 0 second line) into a broken numeric
// comparison and kept SCOPE=six-names-ok. The evaluator must fail closed
// on that artifact and on every degenerate matrix shape.
func TestR7P21BVerdictZeroNewlineGrepArtifactFailsClosed(t *testing.T) {
	for name, matrix := range map[string]string{
		"the 0-newline-0 grep artifact": "0\n0\n",
		"empty file":                    "",
		"garbage only":                  "grep: no matches\n",
	} {
		dir := p21bWriteEvidence(t, matrix, strings.Join(p21bGreenAV(), "\n")+"\n", p21bGreenTerminals())
		line, rc := p21bRunEvaluator(t, dir)
		if rc == 0 || strings.Contains(line, "DECISION=P21B-MEASURED") || strings.Contains(line, "SCOPE=six-names-ok") {
			t.Errorf("mutation %q must fail closed (no MEASURED, no six-names-ok), got rc=%d: %s", name, rc, line)
		}
	}
}

// TestR7P21BVerdictMatrixMutationsFailClosed proves every matrix
// irregularity — a missing required row, a duplicated row, a corrupted
// row, a wrong result, an unexpected row, and an unparseable line — fails
// closed (never MEASURED), with a positive violation taking FAIL over the
// missing-evidence BLOCKED.
func TestR7P21BVerdictMatrixMutationsFailClosed(t *testing.T) {
	rows := p21bGreenMatrix()
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
			i := find("tty", p21bC2)
			return append(r[:i:i], r[i+1:]...)
		}},
		{"missing c1/null row", func(r []string) []string {
			i := find("null", p21bC1)
			return append(r[:i:i], r[i+1:]...)
		}},
		{"duplicated c1/zero row", func(r []string) []string {
			i := find("zero", p21bC1)
			return append(append(r[:i:i], r[i]), r[i:]...)
		}},
		{"corrupted ERR row replaces c1/full", func(r []string) []string {
			i := find("full", p21bC1)
			out := append([]string(nil), r...)
			out[i] = "CREATE " + p21bC1 + " x " + p21bTmpfs + " x file [full] -> ERR rc=-1 errno=22 (Invalid argument)"
			return out
		}},
		{"wrong result: c1/null keeps runc_memfd_t", func(r []string) []string {
			i := find("null", p21bC1)
			out := append([]string(nil), r...)
			out[i] = p21bCreateRow(p21bC1, "null", p21bMemfd)
			return out
		}},
		{"wrong result: c2/tty keeps runc_memfd_t", func(r []string) []string {
			i := find("tty", p21bC2)
			out := append([]string(nil), r...)
			out[i] = p21bCreateRow(p21bC2, "tty", p21bMemfd)
			return out
		}},
		{"arbitrary name diverted to devnode_t", func(r []string) []string {
			i := find("someothername", p21bC1)
			out := append([]string(nil), r...)
			out[i] = p21bCreateRow(p21bC1, "someothername", p21bDevnode)
			return out
		}},
		{"name=NULL diverted to devnode_t", func(r []string) []string {
			i := find("-", p21bC1)
			out := append([]string(nil), r...)
			out[i] = p21bCreateRow(p21bC1, "-", p21bDevnode)
			return out
		}},
		{"unconfined control diverted", func(r []string) []string {
			i := find("null", p21bUnconf)
			out := append([]string(nil), r...)
			out[i] = p21bCreateRow(p21bUnconf, "null", p21bDevnode)
			return out
		}},
		{"unexpected seventh basename row", func(r []string) []string {
			return append(r, p21bCreateRow(p21bC1, "stdin", p21bDevnode))
		}},
		{"unparseable line injected", func(r []string) []string {
			return append(r, "CREATE broken matrix line")
		}},
	}
	for _, mut := range mutations {
		mutated := mut.mutate(append([]string(nil), rows...))
		dir := p21bWriteEvidence(t, strings.Join(mutated, "\n")+"\n",
			strings.Join(p21bGreenAV(), "\n")+"\n", p21bGreenTerminals())
		line, rc := p21bRunEvaluator(t, dir)
		if rc == 0 || strings.Contains(line, "DECISION=P21B-MEASURED") {
			t.Errorf("mutation %q must fail closed, got rc=%d: %s", mut.name, rc, line)
		}
		if mut.name == "missing c2/tty row" && !strings.Contains(line, "DECISION=P21B-BLOCKED") {
			t.Errorf("a purely missing row must decide BLOCKED (fail-closed), got: %s", line)
		}
	}
}

// TestR7P21BVerdictMatrixStructureMutationsFailClosed proves the FULL row
// structure is part of the requirement: a row whose RESULT alone would
// look right is still rejected when its parent (target) context, class,
// source context, or name is wrong — no partial-structure acceptance.
func TestR7P21BVerdictMatrixStructureMutationsFailClosed(t *testing.T) {
	mutations := []struct {
		name    string
		corrupt func(string) string
	}{
		{"wrong parent context, result still devnode_t", func(r string) string {
			return strings.Replace(r,
				"CREATE "+p21bC1+" x "+p21bTmpfs+" x file [null] -> "+p21bDevnode,
				"CREATE "+p21bC1+" x system_u:object_r:builder_runtime_t:s0 x file [null] -> "+p21bDevnode, 1)
		}},
		{"wrong class, result still devnode_t", func(r string) string {
			return strings.Replace(r,
				"CREATE "+p21bC1+" x "+p21bTmpfs+" x file [null] -> "+p21bDevnode,
				"CREATE "+p21bC1+" x "+p21bTmpfs+" x dir [null] -> "+p21bDevnode, 1)
		}},
		{"wrong source context, right name and result", func(r string) string {
			return strings.Replace(r,
				"CREATE "+p21bC1+" x "+p21bTmpfs+" x file [null] -> "+p21bDevnode,
				"CREATE system_u:system_r:docker_helper_t:s0:c1 x "+p21bTmpfs+" x file [null] -> "+p21bDevnode, 1)
		}},
		{"wrong name, right result", func(r string) string {
			return strings.Replace(r,
				"CREATE "+p21bC1+" x "+p21bTmpfs+" x file [null] -> "+p21bDevnode,
				"CREATE "+p21bC1+" x "+p21bTmpfs+" x file [nul] -> "+p21bDevnode, 1)
		}},
		{"wrong result", func(r string) string {
			return strings.Replace(r,
				"CREATE "+p21bC1+" x "+p21bTmpfs+" x file [null] -> "+p21bDevnode,
				"CREATE "+p21bC1+" x "+p21bTmpfs+" x file [null] -> "+p21bMemfd, 1)
		}},
	}
	for _, mut := range mutations {
		dir := p21bWriteEvidence(t, mut.corrupt(strings.Join(p21bGreenMatrix(), "\n")+"\n"),
			strings.Join(p21bGreenAV(), "\n")+"\n", p21bGreenTerminals())
		line, rc := p21bRunEvaluator(t, dir)
		if rc == 0 || strings.Contains(line, "DECISION=P21B-MEASURED") {
			t.Errorf("mutation %q must fail closed, got rc=%d: %s", mut.name, rc, line)
		}
	}
}

// TestR7P21BVerdictAVMutationsFailClosed proves the AV-matrix branches:
// any content permission ALLOW for either operation category, any missing
// or duplicated row, an associate flip, and an unparseable row fail closed.
func TestR7P21BVerdictAVMutationsFailClosed(t *testing.T) {
	green := strings.Join(p21bGreenAV(), "\n") + "\n"
	mutations := []struct {
		name   string
		mutate func(string) string
	}{
		{"c2 write ALLOW (the rejected P21-A authority shape)", func(p string) string {
			needle := p21bAVFilePerm("write", "DENY", "0x8")
			return strings.Replace(p, needle, p21bAVFilePerm("write", "ALLOW", "0x8"), 1)
		}},
		{"c1 execute ALLOW", func(p string) string {
			needle := p21bAVFilePerm("execute", "DENY", "0x8")
			return strings.Replace(p, needle, p21bAVFilePerm("execute", "ALLOW", "0x8"), 1)
		}},
		{"c1 open ALLOW", func(p string) string {
			needle := p21bAVFilePerm("open", "DENY", "0x8")
			return strings.Replace(p, needle, p21bAVFilePerm("open", "ALLOW", "0x8"), 1)
		}},
		{"unconfined create ALLOW", func(p string) string {
			needle := p21bAVFilePerm("create", "DENY", "0x0")
			return strings.Replace(p, needle, p21bAVFilePerm("create", "ALLOW", "0x0"), 1)
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
			return strings.Replace(p, p21bAVFilePerm("lock", "DENY", "0x8"), "", 1)
		}},
		{"duplicated c1/create row", func(p string) string {
			needle := p21bAVFilePerm("create", "ALLOW", "0x8")
			return strings.Replace(p, needle, needle+"\n"+needle, 1)
		}},
		{"unparseable AV row injected", func(p string) string {
			return p + "  write MAYBE\n"
		}},
	}
	for _, mut := range mutations {
		dir := p21bWriteEvidence(t, strings.Join(p21bGreenMatrix(), "\n")+"\n", mut.mutate(green), p21bGreenTerminals())
		line, rc := p21bRunEvaluator(t, dir)
		if rc == 0 || strings.Contains(line, "DECISION=P21B-MEASURED") {
			t.Errorf("mutation %q must fail closed, got rc=%d: %s", mut.name, rc, line)
		}
	}
}

// TestR7P21BVerdictTerminalMutationsFailClosed proves the live-flow
// branches: a reappeared regression-control record decides FAIL with
// MEMFD=regressed, a missing devnode terminal decides BLOCKED, and a
// tampered NEXT-TERMINAL can never pass.
func TestR7P21BVerdictTerminalMutationsFailClosed(t *testing.T) {
	green := p21bGreenTerminals()
	mutations := []struct {
		name         string
		mutate       func(string) string
		wantMEMFD    string
		wantDECISION string
	}{
		{"P20 runc_memfd create denial reappeared", func(p string) string {
			return strings.Replace(p,
				"-- P20 terminal (runc_memfd_t:file create) --",
				"-- P20 terminal (runc_memfd_t:file create) --\n"+
					`type=AVC msg=audit(1793703417.986:9999): avc:  denied  { create } for  pid=3261 comm="runc:[2:INIT]" name="null" scontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tcontext=system_u:object_r:docker_helper_runc_memfd_t:s0 tclass=file permissive=0`, 1)
		}, "regressed", "P21B-FAIL"},
		{"pre-B tmpfs_t:file write denial reappeared", func(p string) string {
			return strings.Replace(p,
				"-- pre-B terminal (tmpfs_t:file write) --",
				"-- pre-B terminal (tmpfs_t:file write) --\n"+
					`type=AVC msg=audit(1793703417.986:9998): avc:  denied  { write } for  pid=3261 comm="buildkit-runc" path=2F6D656D66643A scontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tcontext=system_u:object_r:tmpfs_t:s0 tclass=file permissive=0`, 1)
		}, "intact", "P21B-FAIL"},
		{"associate denial reappeared", func(p string) string {
			return strings.Replace(p,
				"-- associate denials (must be EMPTY — the singleton is granted) --",
				"-- associate denials (must be EMPTY — the singleton is granted) --\n"+
					`type=AVC msg=audit(1793703417.986:9997): avc:  denied  { associate } for  pid=3261 comm="runc:[2:INIT]" name="null" scontext=system_u:object_r:docker_helper_devnode_t:s0 tcontext=system_u:object_r:tmpfs_t:s0 tclass=filesystem permissive=0`, 1)
		}, "intact", "P21B-FAIL"},
		{"devnode terminal record missing", func(p string) string {
			lines := strings.Split(p, "\n")
			var kept []string
			for _, l := range lines {
				if strings.Contains(l, "docker_helper_devnode_t") {
					continue
				}
				kept = append(kept, l)
			}
			return strings.Join(kept, "\n")
		}, "intact", "P21B-BLOCKED"},
	}
	for _, mut := range mutations {
		dir := p21bWriteEvidence(t, strings.Join(p21bGreenMatrix(), "\n")+"\n",
			strings.Join(p21bGreenAV(), "\n")+"\n", mut.mutate(green))
		line, rc := p21bRunEvaluator(t, dir)
		if !strings.Contains(line, "DECISION="+mut.wantDECISION) || rc == 0 {
			t.Errorf("mutation %q must decide %s, got rc=%d: %s", mut.name, mut.wantDECISION, rc, line)
		}
		if got := p21bField(t, line, "MEMFD"); got != mut.wantMEMFD {
			t.Errorf("mutation %q must report MEMFD=%s, got %q", mut.name, mut.wantMEMFD, got)
		}
	}
}

// TestR7P21BVerdictTerminalRecordMutationsFailClosed proves the strict
// terminal matcher: an arbitrary AVC carrying the same type is NOT
// accepted as the required terminal. Each mutation corrupts EVERY terminal
// record (both windows) of the real run-41648049864 shape; the flow then
// has no correctly formed terminal record and must decide BLOCKED, never
// MEASURED.
func TestR7P21BVerdictTerminalRecordMutationsFailClosed(t *testing.T) {
	realTerminal := `type=AVC msg=audit(1793714070.816:1190): avc:  denied  { read open } for  pid=3288 comm="runc:[2:INIT]" path="/var/lib/docker-helper-builder/ops/op_557f5cc38c677ba14475b5dd2f88dbaa/root/runc-native/executor/6jinf8i9db2cl6rsdw8zcony9/rootfs/dev/null" dev="tmpfs" ino=5 scontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tcontext=system_u:object_r:docker_helper_devnode_t:s0 tclass=file permissive=0`
	mutations := []struct {
		name    string
		corrupt func(string) string
	}{
		{"extra permission in the pair", func(p string) string {
			return strings.ReplaceAll(p, "denied  { read open }", "denied  { read open map }")
		}},
		{"permissive=1", func(p string) string {
			return strings.ReplaceAll(p, "tclass=file permissive=0", "tclass=file permissive=1")
		}},
		{"unconfined source context", func(p string) string {
			return strings.ReplaceAll(p, "scontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tcontext=",
				"scontext=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 tcontext=")
		}},
		{"runc_memfd_t target context", func(p string) string {
			return strings.ReplaceAll(p, "tcontext=system_u:object_r:docker_helper_devnode_t:s0 tclass=",
				"tcontext=system_u:object_r:docker_helper_runc_memfd_t:s0 tclass=")
		}},
		{"wrong class", func(p string) string {
			return strings.ReplaceAll(p, "tclass=file permissive", "tclass=chr_file permissive")
		}},
		{"path outside the per-operation tree", func(p string) string {
			return strings.ReplaceAll(p, "/rootfs/dev/null", "/tmp/dev/null")
		}},
		{"only the read permission of the pair", func(p string) string {
			return strings.ReplaceAll(p, "denied  { read open }", "denied  { read }")
		}},
	}
	for _, mut := range mutations {
		mutated := mut.corrupt(p21bGreenTerminals())
		if mutated == p21bGreenTerminals() {
			t.Fatalf("mutation %q must corrupt at least one terminal record", mut.name)
		}
		if strings.Contains(mut.corrupt(realTerminal), realTerminal) && mut.name != "only the read permission of the pair" {
			t.Fatalf("mutation %q must corrupt the canonical real terminal record", mut.name)
		}
		dir := p21bWriteEvidence(t, strings.Join(p21bGreenMatrix(), "\n")+"\n",
			strings.Join(p21bGreenAV(), "\n")+"\n", mutated)
		line, rc := p21bRunEvaluator(t, dir)
		if rc == 0 || !strings.Contains(line, "DECISION=P21B-BLOCKED") {
			t.Errorf("mutation %q must decide BLOCKED (no correctly formed terminal record), got rc=%d: %s", mut.name, rc, line)
		}
	}
}

// TestR7P21BVerdictRegressionSectionHeadersFailClosed proves the
// regression-control sections are mandatory evidence: a missing section
// header decides BLOCKED (damaged or truncated evidence can never be
// MEASURED), a duplicated header decides FAIL (ambiguous evidence), and a
// missing devnode-terminal section header also decides BLOCKED.
func TestR7P21BVerdictRegressionSectionHeadersFailClosed(t *testing.T) {
	headers := []string{
		"-- P20 terminal (runc_memfd_t:file create) --",
		"-- pre-B terminal (tmpfs_t:file write) --",
		"-- associate denials (must be EMPTY — the singleton is granted) --",
		"== devnode-terminal runc-init AVCs (both windows) ==",
	}
	for _, header := range headers {
		missing := strings.Replace(p21bGreenTerminals(), header+"\n", "", 1)
		dir := p21bWriteEvidence(t, strings.Join(p21bGreenMatrix(), "\n")+"\n",
			strings.Join(p21bGreenAV(), "\n")+"\n", missing)
		line, rc := p21bRunEvaluator(t, dir)
		if rc == 0 || !strings.Contains(line, "DECISION=P21B-BLOCKED") {
			t.Errorf("missing header %q must decide BLOCKED, got rc=%d: %s", header, rc, line)
		}
	}
	for _, header := range headers[:3] {
		duplicated := strings.Replace(p21bGreenTerminals(), header+"\n", header+"\n"+header+"\n", 1)
		dir := p21bWriteEvidence(t, strings.Join(p21bGreenMatrix(), "\n")+"\n",
			strings.Join(p21bGreenAV(), "\n")+"\n", duplicated)
		line, rc := p21bRunEvaluator(t, dir)
		if rc == 0 || !strings.Contains(line, "DECISION=P21B-FAIL") {
			t.Errorf("duplicated header %q must decide FAIL, got rc=%d: %s", header, rc, line)
		}
	}
}

// TestR7P21BVerdictMissingEvidenceFilesBlock pins the file-level fail-closed
// branch: a missing or empty required evidence file can never produce a
// passing decision, and a missing evaluator input directory is BLOCKED.
func TestR7P21BVerdictMissingEvidenceFilesBlock(t *testing.T) {
	dir := p21bGreenDir(t)
	for _, name := range []string{"create-matrix-before.log", "av-matrix-before.log", "p21b-terminals.log"} {
		broken := p21bGreenDir(t)
		if err := os.Remove(filepath.Join(broken, name)); err != nil {
			t.Fatal(err)
		}
		line, rc := p21bRunEvaluator(t, broken)
		if rc == 0 || !strings.Contains(line, "DECISION=P21B-BLOCKED") {
			t.Errorf("missing %q must decide BLOCKED, got rc=%d: %s", name, rc, line)
		}
	}
	_ = dir
	line, rc := p21bRunEvaluator(t, t.TempDir())
	if rc == 0 || !strings.Contains(line, "DECISION=P21B-BLOCKED") {
		t.Errorf("an empty evidence directory must decide BLOCKED, got rc=%d: %s", rc, line)
	}
}

// TestR7P21BVerdictGateMode pins the driver-side gate: exit 0 iff the
// argument is EXACTLY ONE correctly formed R7-P21B-VERDICT line whose
// first field is the single DECISION=P21B-MEASURED — a verdict whose
// DECISION is not P21B-MEASURED, a second DECISION field, the MEASURED
// literal as a substring of another field's value, a malformed prefix, a
// truncated line, an empty/trailing field, an unknown field, or a
// missing/placeholder/corrupted NEXT-TERMINAL is rejected.
func TestR7P21BVerdictGateMode(t *testing.T) {
	accepted := "R7-P21B-VERDICT=DECISION=P21B-MEASURED;SCOPE=six-names-ok;ARBITRARY-NAME-KEEPS-MEMFD=yes;MEMFD=intact;CROSSOP-CONTENT=closed;NEXT-TERMINAL=<type=AVC msg=audit(1793714070.816:1190): avc:  denied  { read open } for  pid=3288 comm=\"runc:[2:INIT]\" path=\"/var/lib/docker-helper-builder/ops/op_557f5cc38c677ba14475b5dd2f88dbaa/root/runc-native/executor/6jinf8i9db2cl6rsdw8zcony9/rootfs/dev/null\" scontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tcontext=system_u:object_r:docker_helper_devnode_t:s0 tclass=file permissive=0>"
	if rc := exec.Command("bash", "scripts/release-2.4-r7-p21b-verdict.sh", "--gate", accepted).Run(); rc != nil {
		t.Errorf("--gate must accept a correctly formed MEASURED verdict line: %v", rc)
	}
	for _, bad := range []string{
		"R7-P21B-VERDICT=DECISION=P21B-FAIL;NOTE=DECISION=P21B-MEASURED",
		"R7-P21B-VERDICT=DECISION=P21B-BLOCKED;DECISION=P21B-MEASURED",
		"R7-P21B-VERDICT=DECISION=P21B-MEASURED;DECISION=P21B-FAIL",
		"R7-P21B-VERDICT=DECISION=P21B-FAIL;SCOPE=not-established",
		"R7-P21B-VERDICT=DECISION=P21B-BLOCKED;REASON=no-evidence-dir",
		"R7-P21B-VERDICT=SCOPE=six-names-ok",
		"XR7-P21B-VERDICT=DECISION=P21B-MEASURED;SCOPE=six-names-ok",
		"R7-P21B-VERDICTX=DECISION=P21B-MEASURED;SCOPE=six-names-ok",
		"R7-P21B-VERDICT=DECISION=P21B-MEAS",
		"R7-P21B-VERDICT=DECISION=P21B-MEASURED",
		"R7-P21B-VERDICT=DECISION=P21B-MEASURED;SCOPE=six-names-ok",
		"R7-P21B-VERDICT=DECISION=P21B-MEASURED;SCOPE=six-names-ok;;",
		"R7-P21B-VERDICT=DECISION=P21B-MEASURED;SCOPE=six-names-ok;",
		"R7-P21B-VERDICT=DECISION=P21B-MEASURED;SCOPE=six-names-ok;JUNK",
		"R7-P21B-VERDICT=DECISION=P21B-MEASURED;SCOPE=six-names-ok;UNEXPECTED-FIELD=1",
		"R7-P21B-VERDICT=DECISION=P21B-MEASURED;NEXT-TERMINAL=<(none)>",
		"R7-P21B-VERDICT=DECISION=P21B-MEASURED;NEXT-TERMINAL=<type=AVC line;broken=field>",
		"R7-P21B-VERDICT=DECISION=P21B-MEASURED;SCOPE=six-names-ok;ARBITRARY-NAME-KEEPS-MEMFD=yes;MEMFD=intact;CROSSOP-CONTENT=closed",
	} {
		if rc := exec.Command("bash", "scripts/release-2.4-r7-p21b-verdict.sh", "--gate", bad).Run(); rc == nil {
			t.Errorf("--gate must reject %q", bad)
		}
	}
}
