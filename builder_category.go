package main

// builder_category.go owns the per-operation MCS category representation
// (G32 r3 §4.1): one canonical internal type, one parser/formatter pair,
// and the fixed production pool. Categories are bound to instance records
// at START admission under the manager lock (the manager map is the single
// occupancy source) and release exactly when the terminal convergence
// removes the record — there is no separate allocator object, lock, or
// free-list.

import "strconv"

// builderCategory is one MCS category of the per-operation isolation pool.
// The canonical textual form is c<N>; the internal representation is the
// numeric N. The type is not a free string: only the parser below mints
// categories, and only from the canonical spelling.
type builderCategory int

const (
	// builderCategoryPoolMin/Max are the fixed production pool bounds
	// (G32 r3 §4.1). c0 is never issued — the bare s0 range is the only
	// "uncategorized" state — and the pool never widens at runtime.
	builderCategoryPoolMin builderCategory = 1
	builderCategoryPoolMax builderCategory = 1023
)

// String renders the canonical textual form c<N>. It is the single
// formatter; no production code composes the spelling from parts.
func (c builderCategory) String() string {
	return "c" + strconv.Itoa(int(c))
}

// parseBuilderCategory is the single parser of the canonical category
// token: exactly c followed by decimal digits, no leading zero, within
// the production pool. Everything else is invalid and rejected — c0 (the
// reserved/invalid bare-s0 category), out-of-pool values, negative or
// decorated numbers, alternate spellings (case, spacing, leading zeros,
// unicode digits), and composed forms such as category sets or ranges
// (c1,c2 / c1.c3). It never trims or normalizes input.
func parseBuilderCategory(text string) (builderCategory, bool) {
	if len(text) < 2 || text[0] != 'c' {
		return 0, false
	}
	digits := text[1:]
	if len(digits) > len("1023") {
		return 0, false
	}
	if len(digits) > 1 && digits[0] == '0' {
		return 0, false
	}
	for i := 0; i < len(digits); i++ {
		if digits[i] < '0' || digits[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(digits)
	if err != nil {
		return 0, false
	}
	c := builderCategory(n)
	if c < builderCategoryPoolMin || c > builderCategoryPoolMax {
		return 0, false
	}
	return c, true
}
