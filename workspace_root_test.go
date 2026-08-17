package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsForbiddenWorkspaceRoot(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
		errSub  string
	}{
		// Filesystem root
		{"root slash", "/", true, "filesystem root"},

		// Forbidden system trees (exact match)
		{"system tree bin", "/bin", true, "forbidden system directory"},
		{"system tree boot", "/boot", true, "forbidden system directory"},
		{"system tree dev", "/dev", true, "forbidden system directory"},
		{"system tree etc", "/etc", true, "forbidden system directory"},
		{"system tree lib", "/lib", true, "forbidden system directory"},
		{"system tree lib32", "/lib32", true, "forbidden system directory"},
		{"system tree lib64", "/lib64", true, "forbidden system directory"},
		{"system tree libx32", "/libx32", true, "forbidden system directory"},
		{"system tree proc", "/proc", true, "forbidden system directory"},
		{"system tree root", "/root", true, "forbidden system directory"},
		{"system tree run", "/run", true, "forbidden system directory"},
		{"system tree sbin", "/sbin", true, "forbidden system directory"},
		{"system tree sys", "/sys", true, "forbidden system directory"},
		{"system tree usr", "/usr", true, "forbidden system directory"},
		{"system tree var", "/var", true, "forbidden system directory"},
		{"system tree tmp", "/tmp", true, "forbidden system directory"},

		// Under forbidden system trees
		{"under bin", "/bin/ls", true, "under forbidden system directory"},
		{"under etc", "/etc/passwd", true, "under forbidden system directory"},
		{"under var", "/var/lib/docker", true, "under forbidden system directory"},
		{"under usr", "/usr/local/bin", true, "under forbidden system directory"},
		{"under tmp", "/tmp/work", true, "under forbidden system directory"},
		{"under dev", "/dev/null", true, "under forbidden system directory"},
		{"under proc", "/proc/1", true, "under forbidden system directory"},
		{"under sys", "/sys/kernel", true, "under forbidden system directory"},

		// Forbidden wide namespaces (exact match only)
		{"wide namespace home", "/home", true, "too broad"},
		{"wide namespace opt", "/opt", true, "too broad"},
		{"wide namespace srv", "/srv", true, "too broad"},
		{"wide namespace mnt", "/mnt", true, "too broad"},
		{"wide namespace media", "/media", true, "too broad"},

		// Subdirectories of wide namespaces are allowed
		{"sub of home", "/home/user", false, ""},
		{"sub of home deep", "/home/user/workspaces", false, ""},
		{"sub of opt", "/opt/project", false, ""},
		{"sub of srv", "/srv/data", false, ""},
		{"sub of mnt", "/mnt/data", false, ""},
		{"sub of media", "/media/usb", false, ""},

		// Normal user paths
		{"user data", "/home/user/data", false, ""},
		{"user workspaces", "/home/user/workspaces", false, ""},
		{"arbitrary path", "/data/work", false, ""},
		{"arbitrary deep", "/data/work/deep", false, ""},
		{"single char", "/a", false, ""},
		{"single char sub", "/a/b", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := isForbiddenWorkspaceRoot(tt.path)
			if tt.wantErr && err == nil {
				t.Errorf("isForbiddenWorkspaceRoot(%q) = nil, want error", tt.path)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("isForbiddenWorkspaceRoot(%q) = %v, want nil", tt.path, err)
			}
			if tt.wantErr && tt.errSub != "" && err != nil {
				if !contains(err.Error(), tt.errSub) {
					t.Errorf("isForbiddenWorkspaceRoot(%q) error = %q, want contains %q", tt.path, err.Error(), tt.errSub)
				}
			}
		})
	}
}

func TestValidateWorkspaceRootPolicy(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"empty", "", true},
		{"relative path", "relative/path", true},
		{"relative path dot", "./path", true},
		{"valid abs", "/data/work", false},
		{"valid home subdir", "/home/user/work", false},
		{"forbidden root", "/", true},
		{"forbidden system", "/etc", true},
		{"forbidden under system", "/etc/passwd", true},
		{"forbidden wide ns", "/home", true},
		{"forbidden tmp", "/tmp", true},
		{"forbidden under tmp", "/tmp/work", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateWorkspaceRootPolicy(tt.path)
			if tt.wantErr && err == nil {
				t.Errorf("validateWorkspaceRootPolicy(%q) = nil, want error", tt.path)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("validateWorkspaceRootPolicy(%q) = %v, want nil", tt.path, err)
			}
		})
	}
}

func TestCanonicalizeWorkspaceRootForAdd(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"empty", "", true},
		{"nonexistent", "/nonexistent/path/xyz", true},
		{"file not dir", "/etc/hostname", true}, // may be a file
		{"valid dir", testAllowedRootDir(t), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := canonicalizeWorkspaceRootForAdd(tt.path)
			if tt.wantErr && err == nil {
				t.Errorf("canonicalizeWorkspaceRootForAdd(%q) = nil error, want error", tt.path)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("canonicalizeWorkspaceRootForAdd(%q) = %v, want nil", tt.path, err)
			}
		})
	}
}

func TestCanonicalizeWorkspaceRootSymlinkEscape(t *testing.T) {
	// Create a symlink in a non-forbidden location that points to a forbidden location
	linkParent := testAllowedRootDir(t)
	linkPath := filepath.Join(linkParent, "escape-link")
	if err := os.Symlink("/var", linkPath); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	defer os.Remove(linkPath)

	// The symlink should be resolved and rejected because /var is forbidden
	_, err := canonicalizeWorkspaceRootForAdd(linkPath)
	if err == nil {
		t.Error("expected error for symlink to /var, got nil")
	}
}

func TestCanonicalizeWorkspaceRootTildeExpansion(t *testing.T) {
	// Tilde expansion uses the real user home, so this test needs the home
	// itself to be a policy-legal workspace root. For root, the home is a
	// forbidden system tree and ~ expansion is rejected by the policy.
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("cannot determine home directory: %v", err)
	}
	canonicalHome, err := filepath.EvalSymlinks(home)
	if err != nil {
		t.Skipf("cannot canonicalize home: %v", err)
	}
	if err := isForbiddenWorkspaceRoot(canonicalHome); err != nil {
		t.Skipf("home %s is not a valid workspace root: %v", canonicalHome, err)
	}

	// Create a valid workspace root directly under home so it is addressable
	// with a ~/ spelling.
	testDir, err := os.MkdirTemp(canonicalHome, ".docker-helper-test-*")
	if err != nil {
		t.Fatalf("cannot create workspace root test dir: %v", err)
	}
	defer os.RemoveAll(testDir)

	rel, err := filepath.Rel(canonicalHome, testDir)
	if err != nil {
		t.Fatal(err)
	}
	tildePath := "~/" + rel

	canonical, err := canonicalizeWorkspaceRootForAdd(tildePath)
	if err != nil {
		t.Fatalf("canonicalizeWorkspaceRootForAdd(%q) = %v", tildePath, err)
	}
	expected, _ := filepath.EvalSymlinks(testDir)
	if canonical != expected {
		t.Errorf("canonicalizeWorkspaceRootForAdd(%q) = %q, want %q", tildePath, canonical, expected)
	}
}

// contains is a helper for checking if a string contains a substring.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && indexOf(s, substr) >= 0))
}

func indexOf(s, substr string) int {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
