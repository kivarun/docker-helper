package main

import "testing"

func TestPathWithin(t *testing.T) {
	tests := []struct {
		name, root, path string
		want             bool
	}{
		{"equal", "/data", "/data", true},
		{"child", "/data", "/data/foo", true},
		{"deep child", "/data", "/data/foo/bar", true},
		{"sibling", "/data", "/data2", false},
		{"sibling child", "/data", "/other/foo", false},
		{"prefix trap", "/data", "/data2", false},
		{"prefix trap child", "/data", "/data2/foo", false},
		{"root slash", "/", "/data", true},
		{"root slash equal", "/", "/", true},
		{"nested", "/a/b/c", "/a/b/c/d", true},
		{"nested sibling", "/a/b/c", "/a/b/d", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := pathWithin(tc.root, tc.path); got != tc.want {
				t.Errorf("pathWithin(%q, %q) = %v, want %v", tc.root, tc.path, got, tc.want)
			}
		})
	}
}

func TestPathStrictlyWithin(t *testing.T) {
	tests := []struct {
		name, root, path string
		want             bool
	}{
		{"equal", "/data", "/data", false},
		{"child", "/data", "/data/foo", true},
		{"deep child", "/data", "/data/foo/bar", true},
		{"sibling", "/data", "/data2", false},
		{"sibling child", "/data", "/other/foo", false},
		{"prefix trap", "/data", "/data2", false},
		{"prefix trap child", "/data", "/data2/foo", false},
		{"root slash", "/", "/data", true},
		{"root slash equal", "/", "/", false},
		{"nested", "/a/b/c", "/a/b/c/d", true},
		{"nested sibling", "/a/b/c", "/a/b/d", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := pathStrictlyWithin(tc.root, tc.path); got != tc.want {
				t.Errorf("pathStrictlyWithin(%q, %q) = %v, want %v", tc.root, tc.path, got, tc.want)
			}
		})
	}
}
