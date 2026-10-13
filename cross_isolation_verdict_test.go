package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// The 4C-37V first-boundary verdict is the harness's own production
// function: the test extracts cross_first_boundary_eval verbatim from
// scripts/release-2.4-p5s2-phase4b-launcher-tw.sh and drives it through
// bash with fixture verdict globals, so every accepted/rejected shape is
// the real code path, never a reimplementation. The positive fixture is
// the canonical 4C-91 run 38304565815's own live record (A bound 53475
// c1, the vehicle's first A-targeted step openat("/proc/53475/ns/net")
// stopped at slirp4netns_t:s0:c2 -> buildkitd_t:s0:c1 dir:search
// EACCES, A alive, no attack TUNSETIFF success, both downstream legs
// absent).

const crossFirstBoundaryFuncName = "cross_first_boundary_eval() {"

func crossFirstBoundaryFunc(t *testing.T) string {
	t.Helper()
	src, err := os.ReadFile("scripts/release-2.4-p5s2-phase4b-launcher-tw.sh")
	if err != nil {
		t.Fatalf("read harness: %v", err)
	}
	s := string(src)
	start := strings.Index(s, crossFirstBoundaryFuncName)
	if start < 0 {
		t.Fatalf("the %s function is missing from the harness", crossFirstBoundaryFuncName)
	}
	body := s[start:]
	end := strings.Index(body, "\n}\n")
	if end < 0 {
		t.Fatalf("the %s function's closing brace is missing", crossFirstBoundaryFuncName)
	}
	return body[:end+len("\n}\n")]
}

type crossFirstBoundaryCase struct {
	name    string
	env     map[string]string
	want    string   // CROSS_ISOLATION_MODE
	wantHas []string // additional required KEY=VALUE lines
	wantNot []string // forbidden KEY=VALUE lines
	seq     string   // CROSS_ATTACK_SEQ (unescaped)
	lastE   string   // CROSS_ATTACK_LAST_ENTER
}

const crossBoundaryEnter = `     slirp4netns-55663   [001] .n...   341.068305: sys_openat(dfd: 4294967196, filename: 140727032729536 "/proc/53475/ns/net", flags: O_RDONLY)`
const crossBoundaryRecord = `     slirp4netns-55663   [001] .n...   341.068338: selinux_audited: requested=0x20000000 denied=0x20000000 audited=0x20000000 result=-13 scontext=system_u:system_r:docker_helper_slirp4netns_t:s0:c2 tcontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tclass=dir`
const crossBoundaryExit = `     slirp4netns-55663   [001] .n...   341.068409: sys_openat -> 0xfffffffffffffff3`

func crossBoundarySeq() string {
	return strings.Join([]string{crossBoundaryEnter, crossBoundaryRecord, crossBoundaryExit}, "\n")
}

func crossBoundaryBaseEnv() map[string]string {
	return map[string]string{
		"OP_ID":                     "op_545dc50177bbcd6655b740b37934ce02",
		"CROSS_OP_ID":               "op_2a9a9ec2032eb96f4c8fca6a3724717b",
		"CROSS_A_PID":               "53475",
		"CROSS_A_DOMAIN":            "docker_helper_buildkitd_t",
		"CROSS_A_CATEGORY":          "c1",
		"CROSS_A_ALIVE":             "YES",
		"CROSS_CONTROL_RET":         "0x0",
		"CROSS_ATTACK_TUNSETIFF_OK": "",
		"CROSS_ATTACK_SOCK_PAIR":    "",
		"CROSS_ATTACK_STATE_PAIR":   "",
		"CROSS_ATTACK_LAST_ENTER":   crossBoundaryEnter,
	}
}

func TestCrossIsolationFirstBoundaryVerdict(t *testing.T) {
	fn := crossFirstBoundaryFunc(t)
	cases := []crossFirstBoundaryCase{
		{
			name: "the canonical 4C-91 live shape proves isolation",
			env:  crossBoundaryBaseEnv(),
			seq:  crossBoundarySeq(),
			want: "FIRST_A_TARGETED_BOUNDARY",
			wantHas: []string{
				"FIRST_A_TARGETED_BOUNDARY=YES",
				"FIRST_A_TARGETED_BOUNDARY_IS_SELINUX=YES",
				"FIRST_A_TARGETED_BOUNDARY_CLASS=dir",
				"FIRST_A_TARGETED_BOUNDARY_PERMS=search",
				"FIRST_A_TARGETED_BOUNDARY_ERRNO=EACCES",
				"FIRST_A_TARGETED_BOUNDARY_SCONTEXT=system_u:system_r:docker_helper_slirp4netns_t:s0:c2",
				"FIRST_A_TARGETED_BOUNDARY_TCONTEXT=system_u:system_r:docker_helper_buildkitd_t:s0:c1",
				"FIRST_A_TARGETED_BOUNDARY_TARGET=/proc/53475/ns/net",
				"FIRST_A_TARGETED_BOUNDARY_TARGET_IS_A=YES",
				"A_IDENTITY_BOUND=YES",
				"A_BOUND_PID=53475",
				"A_BOUND_CATEGORY=c1",
				"B_ATTACK_CATEGORY=c2",
				"A_ALIVE_AFTER_ATTACK=YES",
				"DOWNSTREAM_LEGS_SKIPPED_REASON=STOPPED_AT_FIRST_POLICY_BOUNDARY",
			},
			wantNot: []string{"CFB_FAIL="},
		},
		{
			// Negative 1: A not bound.
			name: "A not bound is NOT_PROVEN",
			env: func() map[string]string {
				e := crossBoundaryBaseEnv()
				e["CROSS_A_PID"] = ""
				return e
			}(),
			seq:     crossBoundarySeq(),
			want:    "NOT_PROVEN",
			wantHas: []string{"CFB_FAIL=A_NOT_BOUND"},
		},
		{
			// Negative 2: A bound but dead by verdict time.
			name: "A dead by verdict time is NOT_PROVEN",
			env: func() map[string]string {
				e := crossBoundaryBaseEnv()
				e["CROSS_A_ALIVE"] = "NO"
				return e
			}(),
			seq:     crossBoundarySeq(),
			want:    "NOT_PROVEN",
			wantHas: []string{"CFB_FAIL=A_DEAD_BY_VERDICT_TIME"},
		},
		{
			// Negative 3: B's category equals A's category.
			name: "same-category denial is NOT_PROVEN",
			env:  crossBoundaryBaseEnv(),
			seq: strings.Join([]string{
				crossBoundaryEnter,
				`     slirp4netns-55663   [001] .n...   341.068338: selinux_audited: requested=0x20000000 denied=0x20000000 audited=0x20000000 result=-13 scontext=system_u:system_r:docker_helper_slirp4netns_t:s0:c1 tcontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tclass=dir`,
				crossBoundaryExit,
			}, "\n"),
			want:    "NOT_PROVEN",
			wantHas: []string{"CFB_FAIL=CATEGORIES_NOT_DISTINCT"},
		},
		{
			// Negative 4: the stop is ENOENT (a tool/fs outcome, not SELinux).
			name: "ENOENT stop is NOT_PROVEN",
			env:  crossBoundaryBaseEnv(),
			seq: strings.Join([]string{
				crossBoundaryEnter,
				`     slirp4netns-55663   [001] .n...   341.068409: sys_openat -> 0xfffffffffffffffe`,
			}, "\n"),
			want:    "NOT_PROVEN",
			wantHas: []string{"CFB_FAIL=BOUNDARY_NOT_SELINUX_ERRNO"},
		},
		{
			// Negative 5: the failure targets B's own/other object, not A.
			name: "target outside A's identity is NOT_PROVEN",
			env: func() map[string]string {
				e := crossBoundaryBaseEnv()
				e["CROSS_ATTACK_LAST_ENTER"] = `     slirp4netns-55663   [001] .n...   341.068305: sys_openat(dfd: 4294967196, filename: 140727032729536 "/proc/99999/ns/net", flags: O_RDONLY)`
				return e
			}(),
			seq: strings.Join([]string{
				`     slirp4netns-55663   [001] .n...   341.068305: sys_openat(dfd: 4294967196, filename: 140727032729536 "/proc/99999/ns/net", flags: O_RDONLY)`,
				crossBoundaryRecord,
				crossBoundaryExit,
			}, "\n"),
			want:    "NOT_PROVEN",
			wantHas: []string{"CFB_FAIL=TARGET_NOT_A_IDENTITY"},
		},
		{
			// Negative 6: only the shared-root pre-boundary, no A-targeted
			// step.
			name: "shared-root-only denial is NOT_PROVEN",
			env: func() map[string]string {
				e := crossBoundaryBaseEnv()
				e["CROSS_ATTACK_LAST_ENTER"] = `     slirp4netns-55663   [001] .n...   341.068038: sys_openat(dfd: 4294967196, filename: 140727032729536 "/run/docker-helper-builder", flags: O_RDONLY|O_DIRECTORY)`
				return e
			}(),
			seq: strings.Join([]string{
				`     slirp4netns-55663   [001] .n...   341.068038: sys_openat(dfd: 4294967196, filename: 140727032729536 "/run/docker-helper-builder", flags: O_RDONLY|O_DIRECTORY)`,
				`     slirp4netns-55663   [001] .n...   341.068058: selinux_audited: requested=0x20000000 denied=0x20000000 audited=0x20000000 result=-13 scontext=system_u:system_r:docker_helper_slirp4netns_t:s0:c2 tcontext=system_u:object_r:docker_helper_builder_runtime_root_t:s0 tclass=dir`,
				`     slirp4netns-55663   [001] .n...   341.068079: sys_openat -> 0xfffffffffffffff3`,
			}, "\n"),
			want:    "NOT_PROVEN",
			wantHas: []string{"CFB_FAIL=TARGET_NOT_A_IDENTITY"},
		},
		{
			// Negative 7: the attack TUNSETIFF succeeded (BROKEN, never
			// relabeled).
			name: "attack TUNSETIFF success is FAIL",
			env: func() map[string]string {
				e := crossBoundaryBaseEnv()
				e["CROSS_ATTACK_TUNSETIFF_OK"] = "     slirp4netns-55663   [001] .....   341.070000: sys_ioctl -> 0x0"
				return e
			}(),
			seq:  crossBoundarySeq(),
			want: "FAIL",
			wantHas: []string{
				"CFB_FAIL=ATTACK_TUNSETIFF_SUCCEEDED",
			},
			wantNot: []string{"CROSS_ISOLATION_MODE=FIRST_A_TARGETED_BOUNDARY"},
		},
		{
			// Negative 8: the ENXIO compromise semantic is reached.
			name: "ENXIO stop is NOT_PROVEN (never isolation success)",
			env:  crossBoundaryBaseEnv(),
			seq: strings.Join([]string{
				`     slirp4netns-55663   [001] .n...   341.068305: sys_openat(dfd: 4294967196, filename: 140727032729536 "/proc/53475/ns/net", flags: O_RDONLY)`,
				`     slirp4netns-55663   [001] .n...   341.068409: sys_openat -> 0xfffffffffffffffa`,
			}, "\n"),
			want:    "NOT_PROVEN",
			wantHas: []string{"CFB_FAIL=BOUNDARY_NOT_SELINUX_ERRNO"},
		},
		{
			// Negative 9: the downstream legs are absent for a non-policy
			// reason — the attack seq is empty (a parser/script crash).
			name: "empty attack seq (crash-shaped absence) is NOT_PROVEN",
			env:  crossBoundaryBaseEnv(),
			seq:  "",
			want: "NOT_PROVEN",
			wantHas: []string{
				"CFB_FAIL=NO_A_TARGETED_ATTEMPT",
				"CROSS_ISOLATION_MODE=NOT_PROVEN",
			},
		},
		{
			// Negative 10: the vehicle never attempted an A-targeted
			// syscall (a non-empty seq with no A-targeted enter).
			name: "no A-targeted attempt in the seq is NOT_PROVEN",
			env: func() map[string]string {
				e := crossBoundaryBaseEnv()
				e["CROSS_ATTACK_LAST_ENTER"] = ""
				return e
			}(),
			seq:     `     slirp4netns-55663   [001] .....   341.060000: sys_write(fd: 2, "unrelated", 0x9) = 9`,
			want:    "NOT_PROVEN",
			wantHas: []string{"CFB_FAIL=NO_A_TARGETED_ATTEMPT"},
		},
		{
			// Negative 11: the AVC belongs to A's own cleanup, not to the
			// vehicle's attack leg (the actor check).
			name: "non-vehicle AVC actor is NOT_PROVEN",
			env:  crossBoundaryBaseEnv(),
			seq: strings.Join([]string{
				crossBoundaryEnter,
				`     buildkitd-53475   [001] .n...   341.068338: selinux_audited: requested=0x20000000 denied=0x20000000 audited=0x20000000 result=-13 scontext=system_u:system_r:docker_helper_buildkitd_t:s0:c1 tcontext=system_u:object_r:docker_helper_builder_state_t:s0:c1 tclass=dir`,
				crossBoundaryExit,
			}, "\n"),
			want:    "NOT_PROVEN",
			wantHas: []string{"CFB_FAIL=ACTOR_NOT_B_VEHICLE"},
		},
		{
			// The boundary is not the FIRST A-targeted step (an earlier
			// A-targeted step exists — the legs-ran shape, the leg gates'
			// owner).
			name: "boundary not the first A-targeted step is NOT_PROVEN",
			env: func() map[string]string {
				e := crossBoundaryBaseEnv()
				e["CROSS_ATTACK_LAST_ENTER"] = crossBoundaryEnter
				return e
			}(),
			seq: strings.Join([]string{
				`     slirp4netns-55663   [001] .....   341.067000: sys_openat(dfd: 4294967196, filename: 140727032729536 "/proc/53475/ns/net", flags: O_RDONLY)`,
				`     slirp4netns-55663   [001] .....   341.067100: sys_openat -> 0x3`,
				crossBoundaryEnter,
				crossBoundaryRecord,
				crossBoundaryExit,
			}, "\n"),
			want:    "NOT_PROVEN",
			wantHas: []string{"CFB_FAIL=BOUNDARY_NOT_FIRST_A_TARGETED_STEP"},
		},
		{
			// A downstream leg DID run (its pair is present) — the leg
			// gates own the verdict, the mode declines.
			name: "downstream legs present is NOT_PROVEN (leg-gate owner)",
			env: func() map[string]string {
				e := crossBoundaryBaseEnv()
				e["CROSS_ATTACK_SOCK_PAIR"] = "     slirp4netns-55663   [001] .....   341.069000: sys_openat(dfd: 4294967196, filename: 140727032729536 \"/run/docker-helper-builder/ops/op_545dc50177bbcd6655b740b37934ce02/buildkitd.sock\", flags: O_RDONLY)"
				return e
			}(),
			seq:     crossBoundarySeq(),
			want:    "NOT_PROVEN",
			wantHas: []string{"CFB_FAIL=DOWNSTREAM_LEGS_PRESENT"},
		},
		{
			// The denied object's tcontext category is not A's category
			// (a cross-binding confusion).
			name: "tcontext category not A's category is NOT_PROVEN",
			env: func() map[string]string {
				e := crossBoundaryBaseEnv()
				e["CROSS_ATTACK_LAST_ENTER"] = `     slirp4netns-55663   [001] .n...   341.068305: sys_openat(dfd: 4294967196, filename: 140727032729536 "/var/lib/docker-helper-builder/ops/op_545dc50177bbcd6655b740b37934ce02/root", flags: O_RDONLY)`
				return e
			}(),
			seq: strings.Join([]string{
				`     slirp4netns-55663   [001] .n...   341.068305: sys_openat(dfd: 4294967196, filename: 140727032729536 "/var/lib/docker-helper-builder/ops/op_545dc50177bbcd6655b740b37934ce02/root", flags: O_RDONLY)`,
				`     slirp4netns-55663   [001] .n...   341.068338: selinux_audited: requested=0x2 denied=0x2 audited=0x2 result=-13 scontext=system_u:system_r:docker_helper_slirp4netns_t:s0:c2 tcontext=system_u:object_r:docker_helper_builder_state_t:s0:c2 tclass=file`,
				crossBoundaryExit,
			}, "\n"),
			want:    "NOT_PROVEN",
			wantHas: []string{"CFB_FAIL=TCONTEXT_CATEGORY_NOT_A"},
		},
		{
			// The control leg failed — the operation is not mechanically
			// capable even in its own context.
			name: "control leg not successful is NOT_PROVEN",
			env: func() map[string]string {
				e := crossBoundaryBaseEnv()
				e["CROSS_CONTROL_RET"] = "0xfffffffffffffff3"
				return e
			}(),
			seq:     crossBoundarySeq(),
			want:    "NOT_PROVEN",
			wantHas: []string{"CFB_FAIL=CONTROL_LEG_NOT_SUCCESSFUL"},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var b strings.Builder
			b.WriteString(fn)
			b.WriteString("\nOP_ID=$OP_ID\n") // silence set -u in exotic shells; the driver has no set -u
			b.WriteString("cross_first_boundary_eval\n")
			cmd := exec.Command("bash", "-c", b.String())
			env := os.Environ()
			for k, v := range tc.env {
				env = append(env, k+"="+v)
			}
			if tc.seq != "" || tc.env["CROSS_ATTACK_SEQ"] == "" {
				env = append(env, "CROSS_ATTACK_SEQ="+tc.seq)
			}
			cmd.Env = env
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("bash run: %v\noutput:\n%s", err, out)
			}
			got := string(out)
			if !strings.Contains(got, "CROSS_ISOLATION_MODE="+tc.want+"\n") {
				t.Fatalf("CROSS_ISOLATION_MODE must be %s, got output:\n%s", tc.want, got)
			}
			for _, want := range tc.wantHas {
				if !strings.Contains(got, want) {
					t.Errorf("output must contain %s, got:\n%s", want, got)
				}
			}
			for _, ban := range tc.wantNot {
				if strings.Contains(got, ban+"\n") {
					t.Errorf("output must NOT contain %s, got:\n%s", ban, got)
				}
			}
			if tc.want == "FIRST_A_TARGETED_BOUNDARY" {
				if !strings.Contains(got, "CROSS_ISOLATION_MODE=FIRST_A_TARGETED_BOUNDARY\n") {
					t.Errorf("mode line missing, got:\n%s", got)
				}
			}
		})
	}
}
