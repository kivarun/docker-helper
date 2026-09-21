package main

import "testing"

// TestGenerateOperationIDShape proves the generator emits the canonical
// grammar and that isOperationID accepts exactly that shape.
func TestGenerateOperationIDShape(t *testing.T) {
	id := generateOperationID()
	if !isOperationID(id) {
		t.Fatalf("generated operation ID %q does not satisfy the canonical grammar", id)
	}
	if len(id) != len(operationIDPrefix)+operationIDHexLength {
		t.Fatalf("generated operation ID length %d, want %d", len(id), len(operationIDPrefix)+operationIDHexLength)
	}
}

// TestIsOperationIDGrammar is the exact grammar table for the canonical
// issued Operation ID: op_ + exactly 32 lowercase hex characters.
func TestIsOperationIDGrammar(t *testing.T) {
	validHex := "0123456789abcdef0123456789abcdef"
	if len(validHex) != 32 {
		t.Fatal("test fixture hex length wrong")
	}
	issued := operationIDPrefix + validHex

	tests := []struct {
		name string
		id   string
		want bool
	}{
		{"issued ID", issued, true},
		{"uppercase hex invalid", operationIDPrefix + "0123456789ABCDEF0123456789ABCDEF", false},
		{"wrong prefix", "opx_" + validHex, false},
		{"empty prefix", validHex, false},
		{"31 hex invalid", operationIDPrefix + validHex[:31], false},
		{"33 hex invalid", operationIDPrefix + validHex + "0", false},
		{"non-hex invalid", operationIDPrefix + "zz23456789abcdef0123456789abcdef", false},
		{"traversal slash invalid", operationIDPrefix + validHex[:20] + "/../../etc", false},
		{"traversal backslash invalid", operationIDPrefix + validHex[:20] + "\\", false},
		{"dot form invalid", "." + issued, false},
		{"empty", "", false},
	}

	for _, tc := range tests {
		if got := isOperationID(tc.id); got != tc.want {
			t.Errorf("isOperationID(%q) = %v, want %v (%s)", tc.id, got, tc.want, tc.name)
		}
	}
}
