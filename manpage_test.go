package main

import (
	"flag"
	"os"
	"regexp"
	"strings"
	"testing"
)

// roffBlockDirectives are the structural roff macros that must always begin on
// their own source line. Concatenating one to the end of prose (for example
// "target daemon:.IP \(bu 4") silently corrupts the rendered man page.
var roffBlockDirectives = []string{
	".TH",
	".SH",
	".SS",
	".PP",
	".P",
	".IP",
	".TP",
	".RS",
	".RE",
}

// TestManpageRoffDirectivesOwnLine verifies that known block roff directives in
// docs/man/docker-helper.1 are never concatenated to prose on the same line.
// This guards the regression where ".IP \(bu 4" was appended to the end of the
// OPERATOR ENDPOINT SELECTION intro text.
func TestManpageRoffDirectivesOwnLine(t *testing.T) {
	data, err := os.ReadFile("docs/man/docker-helper.1")
	if err != nil {
		t.Fatalf("cannot read manpage source: %v", err)
	}

	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		for _, dir := range roffBlockDirectives {
			// A block directive is only valid when it starts the line.
			if strings.HasPrefix(trimmed, dir) {
				continue
			}
			// If the directive appears anywhere else in the line, it has been
			// concatenated to prose or mid-line text.
			if strings.Contains(line, dir) {
				t.Errorf("docs/man/docker-helper.1:%d: roff directive %q must start on its own line, got: %q", i+1, dir, line)
			}
		}
	}
}

// TestManpageNoLegacyAdminPath verifies the man pages document the admin token
// via the root-level admin-token command and contain no reference to the
// legacy `admin token rotate` CLI path.
func TestManpageNoLegacyAdminPath(t *testing.T) {
	man1, err := os.ReadFile("docs/man/docker-helper.1")
	if err != nil {
		t.Fatalf("cannot read docs/man/docker-helper.1: %v", err)
	}
	content := string(man1)

	if !strings.Contains(content, "docker-helper admin-token rotate") {
		t.Error("man page must document docker-helper admin-token rotate")
	}
	for _, legacy := range []string{"docker-helper admin token rotate", ".SS Admin Commands", "admin token rotate commands"} {
		if strings.Contains(content, legacy) {
			t.Errorf("man page must not contain legacy CLI path %q", legacy)
		}
	}
}

// TestDocsNoLegacyAdminPath verifies operator-facing docs and help sources
// contain no reference to the legacy `admin token rotate` CLI path.
func TestDocsNoLegacyAdminPath(t *testing.T) {
	files := []string{
		"README.md",
		"docs/architecture.md",
	}
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("cannot read %s: %v", path, err)
		}
		if strings.Contains(string(data), "admin token rotate") {
			t.Errorf("%s must not contain the legacy 'admin token rotate' CLI path", path)
		}
	}
}

// TestSecurityContractDocumented pins the fixed workload runtime privilege
// floor and the credential-hash coverage in the operator-facing security
// documentation: the exact runtime protections the implementation emits
// (`--cap-drop ALL`, `no-new-privileges:true`), the SUID/SGID staging strip,
// and Launcher credentials inside the SHA-256 hashing description. Without
// these statements the operator docs could read as if the UID:GID execution
// identity were the only runtime protection. Wording is pinned at the level
// of the exact runtime flags and stable mechanism phrases, not full
// sentences, to avoid brittle sentence matching.
func TestSecurityContractDocumented(t *testing.T) {
	cases := []struct {
		path     string
		contains []string
	}{
		{
			path: "README.md",
			contains: []string{
				"--cap-drop ALL",
				"--security-opt no-new-privileges:true",
				"no request field can disable or weaken them",
				"strips the SUID/SGID",
				"Principal credentials, Launcher\n  credentials, and session tokens use SHA-256 hashes",
			},
		},
		{
			path: "docs/man/docker-helper.1",
			contains: []string{
				"\\-\\-cap\\-drop ALL",
				"no\\-new\\-privileges:true",
				"strips\nthe SUID/SGID privilege bits",
				"capabilities\u2014protect them accordingly. They are stored as SHA-256 hashes",
			},
		},
	}
	for _, tc := range cases {
		data, err := os.ReadFile(tc.path)
		if err != nil {
			t.Fatalf("cannot read %s: %v", tc.path, err)
		}
		content := string(data)
		for _, want := range tc.contains {
			if !strings.Contains(content, want) {
				t.Errorf("%s must document the security contract, missing %q", tc.path, want)
			}
		}
	}
}

// TestManpageSynopsesMatchParser proves the man-page command synopses stay
// bidirectionally aligned with the parser tree:
//
//   - every registered leaf command (one with a NewInvocation) has a man
//     synopsis (a documented command missing from the man page fails);
//   - every `.B docker-helper <path>` synopsis line resolves to a
//     registered command path (a stale command name such as a retired verb
//     fails this);
//   - for every synopsis with a resolvable leaf command, the synopsis flag
//     set and the parser flag set match in both directions: every parser
//     flag appears in the synopsis and every synopsis flag exists on the
//     parser command (a flag documented in the man page that the parser
//     does not define — such as the retired --system — fails this).
//
// It is a line-level smoke check, not a roff parser: only lines that start
// with the `.B docker-helper` synopsis macro are considered, and synopsis
// flags are the `--flag` tokens of the line (roff-escaped dashes and
// synopsis brackets are normalized before matching). The implicit -h/--help
// flags are excluded from both directions.
func TestManpageSynopsesMatchParser(t *testing.T) {
	data, err := os.ReadFile("docs/man/docker-helper.1")
	if err != nil {
		t.Fatalf("cannot read manpage source: %v", err)
	}

	leaves := map[string]bool{}
	for _, p := range walkCommandPaths(rootCommand, nil) {
		cmd, _ := rootCommand.resolveCommandPath(p)
		if cmd != nil && cmd.NewInvocation != nil {
			leaves[strings.Join(p, " ")] = true
		}
	}
	// The walker must be complete enough for the bidirectional check to be
	// meaningful: guard against a partial tree producing vacuous passes.
	if len(leaves) < 50 {
		t.Fatalf("only %d leaf commands walked; tree walk is incomplete", len(leaves))
	}

	synopsisFlags := func(line string) []string {
		// Normalize roff escapes first, then harvest `--flag` tokens: from
		// bracket-group contents (the synopsis flag lists) and from the raw
		// tokens (required flags such as build's --dockerfile are not
		// bracketed). Trimming brackets keeps tokens like `[--access`
		// comparable.
		normalized := strings.ReplaceAll(line, `\`, "")
		var flags []string
		addTokens := func(s string) {
			for _, tok := range strings.Fields(s) {
				tok = strings.Trim(tok, "[],")
				if strings.HasPrefix(tok, "--") && len(tok) > 2 {
					flags = append(flags, tok)
				}
			}
		}
		for _, m := range regexp.MustCompile(`\[([^\]]*)\]`).FindAllStringSubmatch(normalized, -1) {
			addTokens(m[1])
		}
		addTokens(normalized)
		return flags
	}

	synopses := map[string]bool{}
	for i, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, ".B docker-helper ") {
			continue
		}
		var path []string
		for _, tok := range strings.Fields(trimmed)[2:] {
			// Stop at the first flag/bracket/roff escape or uppercase
			// positional placeholder: everything after the command path is
			// synopsis arguments, not path components.
			if strings.HasPrefix(tok, "-") || strings.HasPrefix(tok, "[") || strings.HasPrefix(tok, `\`) ||
				strings.ContainsAny(tok, "AZERTYUIOPQSDFGHJKLMWXCVBN&|<") {
				break
			}
			path = append(path, tok)
		}
		if len(path) == 0 {
			continue
		}
		joined := strings.Join(path, " ")
		synopses[joined] = true
		if !leaves[joined] {
			if cmd, _ := rootCommand.resolveCommandPath(path); cmd == nil {
				t.Errorf("docs/man/docker-helper.1:%d: synopsis names unknown command %q", i+1, joined)
			}
			continue
		}
		cmd, _ := rootCommand.resolveCommandPath(path)
		if cmd == nil || cmd.NewInvocation == nil {
			continue
		}
		syncFS := flag.NewFlagSet("man-sync", flag.ContinueOnError)
		cmd.NewInvocation(syncFS)
		parserFlags := map[string]bool{}
		syncFS.VisitAll(func(f *flag.Flag) {
			if f.Name == "h" || f.Name == "help" {
				return
			}
			parserFlags[f.Name] = true
		})
		lineFlags := synopsisFlags(trimmed)
		seen := map[string]bool{}
		for _, f := range lineFlags {
			name := strings.TrimPrefix(f, "--")
			if seen[name] {
				continue
			}
			seen[name] = true
			if name == "h" || name == "help" {
				continue
			}
			if !parserFlags[name] {
				t.Errorf("docs/man/docker-helper.1:%d: synopsis for %q documents flag %s which the parser does not define", i+1, joined, f)
			}
		}
		for name := range parserFlags {
			if !seen[name] {
				t.Errorf("docs/man/docker-helper.1:%d: parser command %q defines flag --%s missing from its synopsis", i+1, joined, name)
			}
		}
	}

	for path := range leaves {
		if !synopses[path] {
			t.Errorf("registered command %q has no man synopsis", path)
		}
	}
}

// TestManpageNoSystemFlag rejects the retired Release 2.2 dual-mode
// endpoint-selection flag everywhere in the current man page. After the
// system-only cutover there is exactly one daemon deployment and the
// parser defines no --system flag (it fails as an undefined flag), so
// documenting it would teach an invocable lie. Both the roff-escaped
// synopsis form (\-\-system) and a plain prose form must fail this: roff
// escapes split the dashes, so the backslashes are normalized away before
// matching.
func TestManpageNoSystemFlag(t *testing.T) {
	data, err := os.ReadFile("docs/man/docker-helper.1")
	if err != nil {
		t.Fatalf("cannot read manpage source: %v", err)
	}
	normalized := strings.ReplaceAll(string(data), `\`, "")
	if strings.Contains(normalized, "--system") {
		t.Error("docs/man/docker-helper.1 must not document the retired --system dual-mode flag")
	}
}

// TestConfigManpageTmpPolicyMatchesProduction ties the shipped config man
// page's namespace classification to the production workspace-path policy:
// /tmp is a wide namespace whose exact root alone is too broad while
// descendants are permitted — it must never be listed among the forbidden
// root-and-descendants system trees.
func TestConfigManpageTmpPolicyMatchesProduction(t *testing.T) {
	data, err := os.ReadFile("docs/man/docker-helper-config.5")
	if err != nil {
		t.Fatalf("cannot read docs/man/docker-helper-config.5: %v", err)
	}
	man := string(data)

	forbidden := strings.Join(forbiddenSystemTrees, " ")
	if !strings.Contains(man, forbidden) {
		t.Errorf("config man must list the forbidden root-and-descendants trees exactly as production does: %q", forbidden)
	}
	forbiddenWithTmp := strings.Join(append(append([]string{}, forbiddenSystemTrees...), "/tmp"), " ")
	if strings.Contains(man, forbiddenWithTmp) {
		t.Error("config man must not list /tmp among the forbidden root-and-descendants namespaces")
	}

	permitted := strings.Join(forbiddenWideNamespaces, " ")
	if !strings.Contains(man, permitted) {
		t.Errorf("config man must list the wide namespaces (root too broad, descendants permitted) exactly as production does: %q", permitted)
	}
}

// TestManagedAppArmorBoundaryVocabulary guards the canonical term for the
// generalized AppArmor MAC boundary state in the shipped operator docs: the
// boundary state file holds managed AppArmor MAC boundaries for concrete
// issued trees, not "managed workspace boundaries".
func TestManagedAppArmorBoundaryVocabulary(t *testing.T) {
	for _, path := range []string{"docs/man/docker-helper-config.5", "README.md"} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("cannot read %s: %v", path, err)
		}
		content := string(data)
		if strings.Contains(content, "managed workspace boundaries") {
			t.Errorf("%s uses the stale 'managed workspace boundaries' vocabulary", path)
		}
		if !strings.Contains(content, "managed AppArmor MAC boundaries") {
			t.Errorf("%s must name the boundary state with the canonical term 'managed AppArmor MAC boundaries'", path)
		}
	}
}

// TestH10CapabilitySemanticsDocumented guards the accepted
// filesystem-capability boundary in every operator-facing doc that describes the
// filesystem policy: an allowed root and the issued Session filesystem
// snapshot are an explicitly granted helper-mediated filesystem capability,
// NOT a path ceiling layered over the Principal's Unix DAC — and `read_only`
// is a workload-facing access/integrity mode, not a confidentiality
// boundary against the daemon. Removing or contradicting this statement in
// the shipped docs would silently reverse the accepted Release 2.2 contract.
func TestH10CapabilitySemanticsDocumented(t *testing.T) {
	cases := []struct {
		path     string
		contains []string
	}{
		{
			path: "docs/architecture.md",
			contains: []string{
				"filesystem **capability**",
				"not a path ceiling layered over the Principal's Unix DAC",
				"not a\n  confidentiality boundary against the helper",
				"evaluated by kernel DAC,\n  including POSIX ACLs, against the credentials actually supplied to the\n  container",
				"not a reproduction of the Principal's host login credential set",
				"host\n  supplementary groups are not propagated",
			},
		},
		{
			path: "README.md",
			contains: []string{
				"helper-mediated filesystem capability",
				"not a path ceiling layered over the Principal's Unix DAC",
				"not a confidentiality boundary against the daemon",
				"with POSIX ACLs\n  evaluated against those actual credentials",
			},
		},
		{
			path: "docs/man/docker-helper.1",
			contains: []string{
				"helper-mediated filesystem capability, not a path ceiling over the",
				"it is not a\nconfidentiality boundary against the daemon",
				"with POSIX ACLs\nevaluated against those actual credentials",
			},
		},
	}
	for _, tc := range cases {
		data, err := os.ReadFile(tc.path)
		if err != nil {
			t.Fatalf("cannot read %s: %v", tc.path, err)
		}
		content := string(data)
		for _, want := range tc.contains {
			if !strings.Contains(content, want) {
				t.Errorf("%s must carry the accepted filesystem-capability semantics, missing %q", tc.path, want)
			}
		}
	}
}

// TestM1DaemonSideArgvResidualDocumented guards the accepted daemon-side
// argv residual boundary in every operator-facing doc that documents
// run environment values or build args: the residual is the daemon-side
// legacy Docker CLI argv (observable through /proc/<pid>/cmdline while the
// child runs, where host procfs policy permits), build args are explicitly
// not a secret transport, and no alternative secret transport is introduced
// in Release 2.2. Removing or contradicting this statement in the shipped
// docs would silently reverse the accepted Release 2.2 contract or imply a
// secret-safety the CLI transport does not provide.
func TestM1DaemonSideArgvResidualDocumented(t *testing.T) {
	cases := []struct {
		path     string
		contains []string
	}{
		{
			path: "docs/architecture.md",
			contains: []string{
				"residual of the daemon-side legacy Docker CLI argv, not a missed check",
				"residual as run environment values",
				"explicitly NOT a secret transport",
				"not disappear when the CLI argv exposure is later removed",
			},
		},
		{
			path: "README.md",
			contains: []string{
				"accepted Release 2.2 residual of the daemon-side legacy Docker CLI argv",
				"not a secret transport",
			},
		},
		{
			path: "docs/man/docker-helper.1",
			contains: []string{
				"accepted Release 2.2 residual",
				"Build arguments are not a secret transport",
			},
		},
		{
			path: ".claude/skills/docker-helper/SKILL.md",
			contains: []string{
				"not a mechanism for passing secrets",
				"accepted Release 2.2 residual",
			},
		},
	}
	for _, tc := range cases {
		data, err := os.ReadFile(tc.path)
		if err != nil {
			t.Fatalf("cannot read %s: %v", tc.path, err)
		}
		content := string(data)
		for _, want := range tc.contains {
			if !strings.Contains(content, want) {
				t.Errorf("%s must carry the accepted daemon-side argv residual wording, missing %q", tc.path, want)
			}
		}
	}
}
