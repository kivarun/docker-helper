package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestSELinuxPolicyKeepsGenericBinTExecBounded pins the narrow exception used
// by the semanage Python interpreter. Generic bin_t may be executed for that
// transition, but docker-helper must never receive same-domain execute_no_trans
// over the whole bin_t class.
func TestSELinuxPolicyKeepsGenericBinTExecBounded(t *testing.T) {
	data, err := os.ReadFile("packaging/selinux/docker-helper.te")
	if err != nil {
		t.Fatal(err)
	}
	policy := strings.Join(strings.Fields(string(data)), " ")
	want := "allow docker_helper_t bin_t:file { execute read open getattr map };"
	if !strings.Contains(policy, want) {
		t.Fatalf("SELinux policy must retain only the bounded semanage-interpreter bin_t exec grant: %s", want)
	}
	if strings.Contains(policy, "allow docker_helper_t bin_t:file { execute read open getattr map execute_no_trans };") ||
		strings.Contains(policy, "allow docker_helper_t bin_t:file { execute_no_trans") {
		t.Fatal("SELinux policy must not grant generic bin_t execute_no_trans")
	}

	capGrant := "allow docker_helper_t self:capability { dac_read_search dac_override sys_admin };"
	if !strings.Contains(policy, "allow docker_helper_t self:capability fowner;") {
		t.Fatal("the restorecon relabel path must carry the evidence-backed fowner capability grant")
	}
	if got := strings.Count(policy, capGrant); got != 1 {
		t.Fatalf("daemon capability grant must have one canonical declaration, got %d", got)
	}
}

// TestSELinuxProjectionUnmountDoesNotExecFUSEHelper keeps workload cleanup on
// the kernel mount API. The system-mode backend already owns CAP_SYS_ADMIN and
// positively inventories the mount before and after unmount; executing a
// generic fusermount helper would only widen the daemon executable surface.
func TestSELinuxProjectionUnmountDoesNotExecFUSEHelper(t *testing.T) {
	data, err := os.ReadFile("workload_selinux.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, forbidden := range []string{"runFusermountUnmount", `LookPath("fusermount3")`, `LookPath("fusermount")`} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("SELinux projection cleanup must not execute external FUSE unmount helpers: found %q", forbidden)
		}
	}
}

// TestUATScratchIsIgnored prevents local UAT credentials and state from being
// added to the repository again.
func TestUATScratchIsIgnored(t *testing.T) {
	data, err := os.ReadFile(".gitignore")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "/.uat-scratch/\n") {
		t.Fatal(".gitignore must exclude the repository-local UAT scratch tree")
	}
}

// shippedBearerGuidanceFiles is the explicit shipped current-guidance set the
// bearer-argv regression scans: the operator quick start, the shipped agent
// skill, the agent-integration guide, and the man pages. Historical/plan/audit
// documents and internal test/UAT scripts are deliberately outside this set.
var shippedBearerGuidanceFiles = []string{
	"README.md",
	".claude/skills/docker-helper/SKILL.md",
	"docs/agent-integration.md",
	"docs/man/docker-helper.1",
	"docs/man/docker-helper-config.5",
}

// TestShippedDocsNeverExpandBearerIntoCurlArgv rejects the shell-expanded-bearer
// failure class in
// CURRENT shipped guidance: an Authorization Bearer header argument that
// shell-expands the bearer value ($VAR, ${VAR}, $(...), backticks) into a
// process argument. Conceptual protocol notation — "Authorization: Bearer
// <token>" — is not matched.
func TestShippedDocsNeverExpandBearerIntoCurlArgv(t *testing.T) {
	for _, file := range shippedBearerGuidanceFiles {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read shipped guidance %s: %v", file, err)
		}
		for i, line := range strings.Split(string(data), "\n") {
			for _, pattern := range []string{
				"Authorization: Bearer $",
				"Authorization: Bearer $(",
				"Authorization: Bearer `",
			} {
				if strings.Contains(line, pattern) {
					t.Fatalf("%s:%d teaches expanding the bearer into curl argv (%q); shipped examples must feed the bearer header via stdin/file-backed input (curl -H @-)", file, i+1, strings.TrimSpace(line))
				}
			}
		}
	}
}

// TestShippedHeaderProducersDeliverBearerWithoutArgvExpansion executes the
// shipped header-producer pattern with a SYNTHETIC bearer and proves, for the
// environment-held and file-backed forms:
//
//   - the exact Authorization header still reaches a local HTTP receiver;
//   - the live curl /proc/<pid>/cmdline carries the literal -H and @- argv
//     elements and never the bearer value;
//   - the held-curl inspection method itself is sensitive: the pre-fix
//     shell-expanded argv form IS detected leaking the bearer;
//   - the file-backed helper leaves no derived header file behind.
//
// The synthetic marker never appears in any helper process argument: it
// transits via the environment (env form), a file (file form), or a pipe, and
// the leak comparison runs in memory.
func TestShippedHeaderProducersDeliverBearerWithoutArgvExpansion(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skipf("bash unavailable: %v", err)
	}
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skipf("curl unavailable: %v", err)
	}

	fakeBearer := "dht_fake_m2_bearer_0123456789abcdef_0123456789abcdef"

	tokenDir := t.TempDir()
	tokenFile := filepath.Join(tokenDir, "fake.token")
	if err := os.WriteFile(tokenFile, []byte(fakeBearer+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	received := make(chan string, 4)
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		select {
		case received <- r.Header.Get("Authorization"):
		default:
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer receiver.Close()

	// inspectLiveArgv reads the live curl cmdline and asserts the argv
	// transport and bearer leak expectation.
	inspectLiveArgv := func(t *testing.T, curlPid int, wantLeak bool) {
		t.Helper()
		raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", curlPid))
		if err != nil {
			t.Fatalf("read live curl cmdline: %v", err)
		}
		args := strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00")
		hasH, hasAt, leaks := false, false, false
		for _, arg := range args {
			switch arg {
			case "-H":
				hasH = true
			case "@-":
				hasAt = true
			}
			if strings.Contains(arg, "Bearer "+fakeBearer) {
				leaks = true
			}
		}
		if leaks != wantLeak {
			t.Fatalf("live curl argv bearer leak = %v, want %v (argv elements withheld)", leaks, wantLeak)
		}
		if !wantLeak && (!hasH || !hasAt) {
			t.Fatalf("live curl argv must carry the literal -H and @- header transport (hasH=%v hasAt=%v)", hasH, hasAt)
		}
	}

	// runPipeline starts the header producer and curl over the pipe, runs the
	// bounded hold/inspect window when requested, and returns once curl has
	// exited (killed on the hold path, completed otherwise).
	runPipeline := func(t *testing.T, producerScript string, wantLeak bool) {
		t.Helper()
		pr, pw, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer pr.Close()
		defer pw.Close()

		producer := exec.Command("bash", "-c", producerScript)
		producer.Stdout = pw
		producer.Stderr = os.Stderr
		producer.Env = append(os.Environ(),
			"DOCKER_HELPER_SESSION_TOKEN="+fakeBearer,
			"TOKEN_FILE="+tokenFile,
		)
		if err := producer.Start(); err != nil {
			t.Fatalf("start producer: %v", err)
		}
		// The producer owns the pipe's write end from here on.
		if err := pw.Close(); err != nil {
			t.Fatalf("close pipe writer: %v", err)
		}

		var curlCmd *exec.Cmd
		if wantLeak {
			// The pre-fix form: the SHELL expands the bearer into curl's argv
			// (the script text itself carries only the variable name; curl is
			// held by reading its request body from the never-closed stdin).
			curlCmd = exec.Command("bash", "-c", `exec curl --silent --max-time 4 -o /dev/null -H "Authorization: Bearer $DOCKER_HELPER_SESSION_TOKEN" -d @- `+receiver.URL)
			curlCmd.Stdin = pr
		} else {
			curlCmd = exec.Command("curl", "--silent", "--max-time", "4", "-o", "/dev/null",
				"-H", "@-", "-H", "Content-Type: application/json", "-d", `{"k":"v"}`, receiver.URL)
			curlCmd.Stdin = pr
		}
		curlCmd.Stdout = os.Stderr
		curlCmd.Stderr = os.Stderr
		curlCmd.Env = append(os.Environ(),
			"DOCKER_HELPER_SESSION_TOKEN="+fakeBearer,
			"TOKEN_FILE="+tokenFile,
		)
		if err := curlCmd.Start(); err != nil {
			_ = producer.Process.Kill()
			_ = producer.Wait()
			t.Fatalf("start curl: %v", err)
		}

		if wantLeak || producerContainsSleep(producerScript) {
			// The producer keeps the pipe open (sleep in the script), so curl
			// blocks reading its stdin before any request is sent: a
			// deterministic bounded inspection window.
			time.Sleep(500 * time.Millisecond)
			inspectLiveArgv(t, curlCmd.Process.Pid, wantLeak)
			_ = curlCmd.Process.Kill()
		}

		_ = curlCmd.Wait()
		_ = producer.Process.Kill()
		_ = producer.Wait()
	}

	envHelper := `docker_helper_session_header() {
    printf '%s' 'Authorization: Bearer '
    printf '%s' "$DOCKER_HELPER_SESSION_TOKEN"
    printf '\n'
}
`
	fileHelper := `docker_helper_header_from_file() {
    printf '%s' 'Authorization: Bearer '
    tr -d '\r\n' < "$1"
    printf '\n'
}
`

	t.Run("environment-backed session header delivers the exact header", func(t *testing.T) {
		runPipeline(t, envHelper+"docker_helper_session_header\n", false)
		select {
		case got := <-received:
			if got != "Bearer "+fakeBearer {
				t.Fatalf("receiver Authorization = %q, want the exact environment-held bearer header", got)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("receiver never observed the Authorization header")
		}
	})

	t.Run("environment-backed session header keeps the bearer out of live curl argv", func(t *testing.T) {
		runPipeline(t, envHelper+"docker_helper_session_header\nsleep 4\n", false)
	})

	t.Run("file-backed admin/credential header delivers the exact header", func(t *testing.T) {
		runPipeline(t, fileHelper+"docker_helper_header_from_file \"$TOKEN_FILE\"\n", false)
		select {
		case got := <-received:
			if got != "Bearer "+fakeBearer {
				t.Fatalf("receiver Authorization = %q, want the exact file-backed bearer header", got)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("receiver never observed the Authorization header")
		}
	})

	t.Run("file-backed admin/credential header keeps the bearer out of live curl argv", func(t *testing.T) {
		runPipeline(t, fileHelper+"docker_helper_header_from_file \"$TOKEN_FILE\"\nsleep 4\n", false)
	})

	t.Run("file-backed helper leaves no derived header file", func(t *testing.T) {
		runPipeline(t, fileHelper+"docker_helper_header_from_file \"$TOKEN_FILE\"\n", false)
		entries, err := os.ReadDir(tokenDir)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 1 || entries[0].Name() != "fake.token" {
			t.Fatalf("token directory residue: %v", entries)
		}
	})

	t.Run("pre-fix shell-expanded argv form leaks the bearer (detector sensitivity)", func(t *testing.T) {
		runPipeline(t, "sleep 4\n", true)
	})
}

// producerContainsSleep reports whether the producer script holds the pipe
// open after emitting the header (the deterministic curl-inspection hold).
func producerContainsSleep(script string) bool {
	return strings.Contains(script, "\nsleep ")
}
