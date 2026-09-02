package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// cmdRecorder records external command invocations for read-only-contract and
// outcome assertions.
type cmdRecorder struct {
	cmds [][]string
	// respond emulates the external commands. Defaults to the happy path.
	respond func(string, ...string) ([]byte, error)
}

func (r *cmdRecorder) run(cmd string, args ...string) ([]byte, error) {
	r.cmds = append(r.cmds, append([]string{cmd}, args...))
	if r.respond != nil {
		return r.respond(cmd, args...)
	}
	return r.defaultResponse(cmd, args...)
}

// defaultResponse emulates the read-only SELinux tools for the happy path.
func (r *cmdRecorder) defaultResponse(cmd string, args ...string) ([]byte, error) {
	switch cmd {
	case "semodule":
		return []byte("docker_helper\t1.0.0\nbase\t1.0.0\n"), nil
	case "matchpathcon":
		return nil, nil
	}
	return nil, fmt.Errorf("unexpected command %s", cmd)
}

func newTestSELinuxCheckVerifier(rec *cmdRecorder) *selinuxCheckVerifier {
	return &selinuxCheckVerifier{
		runCommand: rec.run,
		detectLSM:  func() (LSMBackend, error) { return LSMSELinux, nil },
		pathExists: func(string) bool { return true },
	}
}

func TestSELinuxCheckNonRootFails(t *testing.T) {
	origUID := EffectiveUID
	EffectiveUID = func() int { return 1000 }
	defer func() { EffectiveUID = origUID }()

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"selinux", "check"}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected non-zero exit for non-root")
	}
	if stdout.String() != "" {
		t.Errorf("expected empty stdout, got: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "requires root") {
		t.Errorf("expected root diagnostic on stderr, got: %q", stderr.String())
	}
}

func TestSELinuxCheckLSMNoneFails(t *testing.T) {
	v := newTestSELinuxCheckVerifier(&cmdRecorder{})
	v.detectLSM = func() (LSMBackend, error) { return LSMNone, nil }
	if err := v.check(); err == nil {
		t.Fatal("expected failure when no MAC backend is active")
	}
}

func TestSELinuxCheckLSMAppArmorFails(t *testing.T) {
	v := newTestSELinuxCheckVerifier(&cmdRecorder{})
	v.detectLSM = func() (LSMBackend, error) { return LSMAppArmor, nil }
	err := v.check()
	if err == nil {
		t.Fatal("expected failure when AppArmor is the active backend")
	}
	if !strings.Contains(err.Error(), "AppArmor") {
		t.Errorf("expected AppArmor in diagnostic, got: %v", err)
	}
}

func TestSELinuxCheckLSMErrorPropagates(t *testing.T) {
	v := newTestSELinuxCheckVerifier(&cmdRecorder{})
	v.detectLSM = func() (LSMBackend, error) {
		return LSMNone, fmt.Errorf("SELinux is active but in permissive mode (system mode requires enforcing SELinux)")
	}
	err := v.check()
	if err == nil {
		t.Fatal("expected detection error to propagate")
	}
	if !strings.Contains(err.Error(), "permissive") {
		t.Errorf("expected permissive diagnostic, got: %v", err)
	}
}

func TestSELinuxCheckSemoduleUnavailable(t *testing.T) {
	v := newTestSELinuxCheckVerifier(&cmdRecorder{})
	v.runCommand = func(cmd string, args ...string) ([]byte, error) {
		if cmd == "semodule" {
			return nil, fmt.Errorf("executable file not found in $PATH")
		}
		return nil, nil
	}
	err := v.check()
	if err == nil {
		t.Fatal("expected failure when semodule is unavailable")
	}
	if !strings.Contains(err.Error(), "semodule -l") {
		t.Errorf("expected semodule diagnostic, got: %v", err)
	}
}

func TestSELinuxCheckModuleAbsent(t *testing.T) {
	rec := &cmdRecorder{}
	rec.respond = func(cmd string, args ...string) ([]byte, error) {
		if cmd == "semodule" {
			return []byte("base\t1.0.0\ncontainer\t1.0.0\n"), nil
		}
		return nil, nil
	}
	v := newTestSELinuxCheckVerifier(rec)
	err := v.check()
	if err == nil {
		t.Fatal("expected failure when docker_helper module is not loaded")
	}
	if !strings.Contains(err.Error(), "docker_helper") {
		t.Errorf("expected module name in diagnostic, got: %v", err)
	}
}

func TestSELinuxCheckModuleExactNameMatch(t *testing.T) {
	tests := []struct {
		name    string
		modules string
		wantErr bool
	}{
		{
			name:    "similarly named module does not match",
			modules: "base\t1.0.0\ndocker_helper_extra\t1.0.0\n",
			wantErr: true,
		},
		{
			name:    "exact module name matches despite similar names",
			modules: "base\t1.0.0\ndocker_helper_extra\t1.0.0\ndocker_helper\t1.0.0\n",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := &cmdRecorder{}
			rec.respond = func(cmd string, args ...string) ([]byte, error) {
				if cmd == "semodule" {
					return []byte(tt.modules), nil
				}
				return nil, nil
			}
			v := newTestSELinuxCheckVerifier(rec)
			err := v.check()
			if tt.wantErr && err == nil {
				t.Fatal("expected failure for non-exact module match")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("expected success for exact module match, got: %v", err)
			}
		})
	}
}

func TestSELinuxCheckExecutableContextFails(t *testing.T) {
	rec := &cmdRecorder{}
	rec.respond = func(cmd string, args ...string) ([]byte, error) {
		if cmd == "semodule" {
			return []byte("docker_helper\t1.0.0\n"), nil
		}
		if cmd == "matchpathcon" && args[0] == "-V" && args[1] == selinuxCheckExecutable {
			return []byte("verify failed on /usr/bin/docker-helper"), fmt.Errorf("exit status 1")
		}
		return nil, nil
	}
	v := newTestSELinuxCheckVerifier(rec)
	err := v.check()
	if err == nil {
		t.Fatal("expected failure when executable context mismatches")
	}
	if !strings.Contains(err.Error(), selinuxCheckExecutable) {
		t.Errorf("expected executable path in diagnostic, got: %v", err)
	}
}

func TestSELinuxCheckOptionalPathAbsentOK(t *testing.T) {
	rec := &cmdRecorder{}
	v := newTestSELinuxCheckVerifier(rec)
	v.pathExists = func(p string) bool { return p == selinuxCheckExecutable }
	if err := v.check(); err != nil {
		t.Fatalf("expected success when optional paths are absent, got: %v", err)
	}
	// Only the executable file context is verified when optional paths absent.
	for _, c := range rec.cmds {
		if c[0] == "matchpathcon" && c[1] == "-V" && c[2] != selinuxCheckExecutable {
			t.Errorf("must not verify absent optional path, got: %v", c)
		}
	}
}

func TestSELinuxCheckOptionalPathMismatchFails(t *testing.T) {
	rec := &cmdRecorder{}
	rec.respond = func(cmd string, args ...string) ([]byte, error) {
		if cmd == "semodule" {
			return []byte("docker_helper\t1.0.0\n"), nil
		}
		if cmd == "matchpathcon" && args[1] == "/etc/docker-helper" {
			return []byte("verify failed on /etc/docker-helper"), fmt.Errorf("exit status 1")
		}
		return nil, nil
	}
	v := newTestSELinuxCheckVerifier(rec)
	err := v.check()
	if err == nil {
		t.Fatal("expected failure when a present optional path mismatches")
	}
	if !strings.Contains(err.Error(), "/etc/docker-helper") {
		t.Errorf("expected optional path in diagnostic, got: %v", err)
	}
}

func TestSELinuxCheckValidState(t *testing.T) {
	origUID := EffectiveUID
	EffectiveUID = func() int { return 0 }
	defer func() { EffectiveUID = origUID }()

	rec := &cmdRecorder{}
	v := newTestSELinuxCheckVerifier(rec)

	var stdout, stderr bytes.Buffer
	code := runSELinuxCheckWithVerifier(v, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d: stderr=%q", code, stderr.String())
	}
	if stdout.String() != "SELinux policy valid\n" {
		t.Errorf("expected exactly 'SELinux policy valid', got: %q", stdout.String())
	}
	if stderr.String() != "" {
		t.Errorf("expected empty stderr, got: %q", stderr.String())
	}
}

// TestSELinuxCheckReadOnlyContract proves the successful path invokes only the
// expected read-only commands (semodule -l, matchpathcon -V) and that no
// mutation command is ever issued.
func TestSELinuxCheckReadOnlyContract(t *testing.T) {
	rec := &cmdRecorder{}
	v := newTestSELinuxCheckVerifier(rec)
	if err := v.check(); err != nil {
		t.Fatalf("expected success, got: %v", err)
	}

	want := [][]string{
		{"semodule", "-l"},
		{"matchpathcon", "-V", selinuxCheckExecutable},
		{"matchpathcon", "-V", "/etc/docker-helper"},
		{"matchpathcon", "-V", "/var/lib/docker-helper"},
		{"matchpathcon", "-V", "/run/docker-helper"},
		{"matchpathcon", "-V", "/run/docker-helper/trusted-ca"},
	}
	if len(rec.cmds) != len(want) {
		t.Fatalf("expected %d invocations, got %d: %v", len(want), len(rec.cmds), rec.cmds)
	}
	for i := range want {
		if strings.Join(rec.cmds[i], " ") != strings.Join(want[i], " ") {
			t.Errorf("invocation %d = %v, want %v", i, rec.cmds[i], want[i])
		}
	}

	// No mutation command may ever be issued.
	for _, c := range rec.cmds {
		for _, m := range []string{"semodule", "semanage", "restorecon", "chcon", "setenforce"} {
			if c[0] == m {
				if m == "semodule" && c[1] != "-l" {
					t.Errorf("semodule must only be called read-only (-l), got: %v", c)
				}
				if m != "semodule" {
					t.Errorf("mutation command %q must never be invoked, got: %v", m, c)
				}
			}
		}
	}
}

func TestSELinuxCheckHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runCommandWithWriters([]string{"--help"}, &stdout, &stderr); code != 0 {
		t.Fatalf("root --help: expected exit 0, got %d", code)
	}
	if !strings.Contains(stdout.String(), "selinux") {
		t.Error("root --help must include the selinux command")
	}

	stdout.Reset()
	stderr.Reset()
	if code := runCommandWithWriters([]string{"selinux", "--help"}, &stdout, &stderr); code != 0 {
		t.Fatalf("selinux --help: expected exit 0, got %d: stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "check") {
		t.Error("selinux --help must include the check subcommand")
	}

	stdout.Reset()
	stderr.Reset()
	if code := runCommandWithWriters([]string{"help", "selinux", "check"}, &stdout, &stderr); code != 0 {
		t.Fatalf("help selinux check: expected exit 0, got %d: stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "docker-helper selinux check") {
		t.Errorf("help selinux check must show the usage, got: %q", stdout.String())
	}
}

func TestSELinuxCheckRejectsPositionalArgs(t *testing.T) {
	origUID := EffectiveUID
	EffectiveUID = func() int { return 0 }
	defer func() { EffectiveUID = origUID }()

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"selinux", "check", "extra"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("expected exit 2 for positional args, got %d: stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "unexpected argument") {
		t.Errorf("expected unexpected-argument error, got: %q", stderr.String())
	}
}
