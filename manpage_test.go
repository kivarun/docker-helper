package main

import (
	"os"
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
