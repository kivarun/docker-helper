package main

import (
	"errors"
	"strings"
	"testing"
)

// newKindAwareTestManager builds a real selinuxFcontextManager with a
// stateful fcontext world: rules added by ensure appear in the listing, and
// every semanage/restorecon invocation is recorded.
type kindAwareManager struct {
	*selinuxFcontextManager
	rules          *[]string
	semanageCalls  *[]string
	restoreconArgs *[]string
}

func newKindAwareTestManager(t *testing.T, active bool, enforcing bool) kindAwareManager {
	t.Helper()
	rules := []string{}
	semanageCalls := []string{}
	restoreconArgs := []string{}
	mgr := newTestManager(func() (bool, bool, error) { return active, enforcing, nil })
	mgr.semanagePath = semanagePath
	mgr.restoreconPath = restoreconPath
	mgr.runCommand = func(cmd string, args ...string) ([]byte, error) {
		switch {
		case strings.HasSuffix(cmd, "semanage"):
			joined := strings.Join(args, " ")
			semanageCalls = append(semanageCalls, joined)
			switch args[1] {
			case "-l":
				// The listing renders the full record line per stored pattern.
				out := ""
				for _, rule := range rules {
					out += rule + "  gen_context(system_u:object_r:" + selinuxWorkspaceType + ":s0)\n"
				}
				return []byte(out), nil
			case "-a":
				// args: fcontext -a -t TYPE PATTERN
				rules = append(rules, args[len(args)-1])
				return []byte{}, nil
			case "-d":
				// args: fcontext -d PATTERN
				pattern := args[len(args)-1]
				kept := rules[:0]
				for _, rule := range rules {
					if rule != pattern {
						kept = append(kept, rule)
					}
				}
				rules = kept
				return []byte{}, nil
			}
			return []byte{}, nil
		case strings.HasSuffix(cmd, "restorecon"):
			restoreconArgs = append(restoreconArgs, strings.Join(args, " "))
			return []byte{}, nil
		}
		return []byte{}, nil
	}
	mgr.readPathCon = func(path string) (string, error) { return selinuxWorkspaceType, nil }
	return kindAwareManager{selinuxFcontextManager: mgr, rules: &rules, semanageCalls: &semanageCalls, restoreconArgs: &restoreconArgs}
}

// TestSELinuxDriverExternalDirectoryCoverage proves an external issued
// directory creates, verifies, and removes the helper-owned recursive
// fcontext coverage — and that a policy ceiling alone never does.
func TestSELinuxDriverExternalDirectoryCoverage(t *testing.T) {
	world := newKindAwareTestManager(t, true, true)
	world.readMountinfo = func() ([]byte, error) { return []byte(""), nil }
	world.treeKind = func(string) (selinuxTreeKind, error) { return selinuxTreeDirectory, nil }
	driver := &selinuxWorkspaceMACDriver{mgr: world.selinuxFcontextManager, treeKind: world.treeKind}

	coverage, created, err := driver.ensureCoverage("/opt/michael/cache")
	if err != nil {
		t.Fatalf("ensureCoverage: %v", err)
	}
	if !created || coverage.Boundary != "/opt/michael/cache" || !coverage.HelperOwned {
		t.Fatalf("coverage = %+v created=%v, want the helper-owned exact boundary", coverage, created)
	}
	found := false
	for _, call := range *world.semanageCalls {
		if strings.Contains(call, "fcontext -a -t docker_helper_workspace_t /opt/michael/cache(/.*)?") {
			found = true
		}
	}
	if !found {
		t.Errorf("the directory boundary must create the recursive fcontext rule, semanage calls: %v", *world.semanageCalls)
	}
	for _, arg := range *world.restoreconArgs {
		if !strings.Contains(arg, "-R") {
			t.Errorf("a directory boundary must use the recursive restorecon, got %q", arg)
		}
	}
	if len(*world.restoreconArgs) != 1 {
		t.Errorf("restorecon calls = %d, want exactly one (ensure)", len(*world.restoreconArgs))
	}

	// Idempotent second ensure: the exact rule exists, no new rule.
	_, createdAgain, err := driver.ensureCoverage("/opt/michael/cache")
	if err != nil {
		t.Fatalf("second ensureCoverage: %v", err)
	}
	if createdAgain {
		t.Error("the second ensure must not report a newly created boundary")
	}

	// Removal: the recursive rule is removed and the tree is restored.
	if err := driver.removeBoundary("/opt/michael/cache"); err != nil {
		t.Fatalf("removeBoundary: %v", err)
	}
	if len(*world.rules) != 0 {
		t.Errorf("rules after removal = %v, want empty", *world.rules)
	}
}

// TestSELinuxDriverRegularFileCoverage proves a regular-file issued root
// creates the exact-path fcontext rule (no descendant suffix) and uses the
// plain restorecon form.
func TestSELinuxDriverRegularFileCoverage(t *testing.T) {
	world := newKindAwareTestManager(t, true, true)
	world.readMountinfo = func() ([]byte, error) { return []byte(""), nil }
	world.treeKind = func(string) (selinuxTreeKind, error) { return selinuxTreeRegularFile, nil }
	driver := &selinuxWorkspaceMACDriver{mgr: world.selinuxFcontextManager, treeKind: world.treeKind}

	coverage, created, err := driver.ensureCoverage("/opt/michael/secrets/token.pem")
	if err != nil {
		t.Fatalf("ensureCoverage: %v", err)
	}
	if !created || coverage.Boundary != "/opt/michael/secrets/token.pem" {
		t.Fatalf("coverage = %+v created=%v, want the exact file boundary", coverage, created)
	}
	found := false
	wantPattern := fcontextPatternFor("/opt/michael/secrets/token.pem", selinuxTreeRegularFile)
	for _, call := range *world.semanageCalls {
		if strings.Contains(call, "fcontext -a -t docker_helper_workspace_t "+wantPattern) &&
			!strings.Contains(call, "(/.*)?") {
			found = true
		}
	}
	if !found {
		t.Errorf("a regular-file boundary must map exactly the file (no descendant suffix), semanage calls: %v", *world.semanageCalls)
	}
	for _, arg := range *world.restoreconArgs {
		if strings.Contains(arg, "-R") {
			t.Errorf("a regular-file boundary must not use the recursive restorecon, got %q", arg)
		}
	}

	// Removal: the exact-file rule is found by stem and removed.
	if err := driver.removeBoundary("/opt/michael/secrets/token.pem"); err != nil {
		t.Fatalf("removeBoundary: %v", err)
	}
	if len(*world.rules) != 0 {
		t.Errorf("rules after removal = %v, want empty", *world.rules)
	}
}

// TestSELinuxDriverOperatorRuleNeverClaimedOrDeleted proves an
// operator-owned compatible rule is used as coverage but is never claimed as
// helper-owned and never removed through the session lifecycle.
func TestSELinuxDriverOperatorRuleNeverClaimedOrDeleted(t *testing.T) {
	world := newKindAwareTestManager(t, true, true)
	world.readMountinfo = func() ([]byte, error) { return []byte(""), nil }
	world.treeKind = func(string) (selinuxTreeKind, error) { return selinuxTreeDirectory, nil }
	// Operator-local compatible rule.
	*world.rules = append(*world.rules, "/opt/michael(/.*)?  gen_context(system_u:object_r:docker_helper_workspace_t:s0)")
	driver := &selinuxWorkspaceMACDriver{mgr: world.selinuxFcontextManager, treeKind: world.treeKind}

	coverage, created, err := driver.ensureCoverage("/opt/michael/cache")
	if err != nil {
		t.Fatalf("ensureCoverage: %v", err)
	}
	if created {
		t.Error("an existing compatible boundary must not be recreated")
	}
	if coverage.Boundary != "/opt/michael" || coverage.HelperOwned {
		t.Errorf("coverage = %+v, want the operator boundary, never helper-owned", coverage)
	}
	for _, call := range *world.semanageCalls {
		if strings.Contains(call, "fcontext -a") || strings.Contains(call, "fcontext -d") {
			t.Errorf("an operator-owned rule must never be mutated through the session lifecycle: %q", call)
		}
	}
}

// TestSELinuxDriverCeilingNeverTriggersRelabel proves that merely
// authorizing a ceiling does not touch MAC state: the driver refuses /opt as
// a NEW boundary (the exact /opt namespace guard), and ensureCoverage is
// only ever invoked for issued trees — structurally, no policy path calls
// the driver at all.
func TestSELinuxDriverCeilingNeverTriggersRelabel(t *testing.T) {
	world := newKindAwareTestManager(t, true, true)
	world.readMountinfo = func() ([]byte, error) { return []byte(""), nil }
	world.treeKind = func(string) (selinuxTreeKind, error) { return selinuxTreeDirectory, nil }
	driver := &selinuxWorkspaceMACDriver{mgr: world.selinuxFcontextManager, treeKind: world.treeKind}

	_, _, err := driver.ensureCoverage("/opt")
	if err == nil {
		t.Fatal("ensureCoverage(/opt) must fail: the exact /opt namespace is not a permitted boundary")
	}
	for _, call := range *world.semanageCalls {
		if strings.Contains(call, "fcontext -a") {
			t.Errorf("no fcontext rule may be added for the ceiling itself: %q", call)
		}
	}
}

// TestSELinuxDriverMissingTreeFailsClosed proves a missing issued tree fails
// closed instead of creating coverage for a nonexistent path.
func TestSELinuxDriverMissingTreeFailsClosed(t *testing.T) {
	world := newKindAwareTestManager(t, true, true)
	world.readMountinfo = func() ([]byte, error) { return []byte(""), nil }
	world.treeKind = func(string) (selinuxTreeKind, error) {
		return 0, errors.New("cannot stat issued tree /gone: no such file")
	}
	driver := &selinuxWorkspaceMACDriver{mgr: world.selinuxFcontextManager, treeKind: world.treeKind}

	if _, _, err := driver.ensureCoverage("/gone"); err == nil {
		t.Fatal("a missing issued tree must fail closed")
	}
	if len(*world.semanageCalls) != 0 {
		t.Errorf("no semanage call may happen for a missing tree: %v", *world.semanageCalls)
	}
}

// TestSELinuxFcontextStemExactPattern proves the stem classifier handles the
// exact-file form and still fails closed on unclassifiable patterns.
func TestSELinuxFcontextStemExactPattern(t *testing.T) {
	cases := []struct {
		pattern string
		want    string
	}{
		{"/data(/.*)?", "/data"},
		{"/data", "/data"},
		// The exact-file rule is stored in the escaped form (escapeFcontextPath).
		{"/opt/michael/secrets/token\\.pem", "/opt/michael/secrets/token.pem"},
		// A raw dotted path is not a classifiable literal pattern: '.' is a
		// regex metacharacter, so an unescaped exact rule fails closed.
		{"/opt/michael/secrets/token.pem", ""},
		{"/data\\.test", "/data.test"},
		{"something_else", ""},
		{"/usr/share/.*\\.so", ""},
	}
	for _, tc := range cases {
		if got := fcontextStem(tc.pattern); got != tc.want {
			t.Errorf("fcontextStem(%q) = %q, want %q", tc.pattern, got, tc.want)
		}
	}
}
