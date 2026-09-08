package main

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// TestStagedBuildContextTarContext proves the prepared trusted context tar:
// regular files and subdirectories are streamed, a symlink entry is
// preserved as a symlink (never followed), and the walk stays inside the
// staged copy.
func TestStagedBuildContextTarContext(t *testing.T) {
	staged := newTestStagedContext(t, "Dockerfile", nil)
	if err := os.WriteFile(filepath.Join(staged.ContextPath, "app.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(staged.ContextPath, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staged.ContextPath, "sub", "data"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("..", "app.txt"), filepath.Join(staged.ContextPath, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staged.ContextPath, "Dockerfile"), []byte("FROM alpine"), 0o644); err != nil {
		t.Fatal(err)
	}

	reader, err := staged.tarContext(context.Background())
	if err != nil {
		t.Fatalf("tarContext: %v", err)
	}
	defer reader.Close()

	blob, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read tar: %v", err)
	}

	entries := make(map[string]tar.Header)
	var appBody []byte
	tr := tar.NewReader(bytes.NewReader(blob))
	for {
		hdr, err := tr.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			t.Fatalf("tar next: %v", err)
		}
		entries[hdr.Name] = *hdr
		if hdr.Name == "app.txt" {
			appBody, err = io.ReadAll(tr)
			if err != nil {
				t.Fatalf("read app.txt: %v", err)
			}
		}
	}

	if _, rootEntry := entries["Dockerfile/"]; rootEntry {
		t.Error("the context root must not be a tar entry")
	}
	if _, ok := entries["Dockerfile"]; !ok {
		t.Error("Dockerfile entry missing")
	}
	if _, ok := entries["sub/"]; !ok {
		t.Error("subdirectory entry missing")
	}
	if _, ok := entries["sub/data"]; !ok {
		t.Error("nested file entry missing")
	}
	symlink := entries["link"]
	if symlink.Typeflag != tar.TypeSymlink || symlink.Linkname != filepath.Join("..", "app.txt") {
		t.Errorf("symlink entry = %+v, want a preserved symlink entry", symlink)
	}
	if string(appBody) != "hello" {
		t.Errorf("app.txt body = %q", appBody)
	}
}

// TestStagedBuildContextTarContextCancellation proves the tar goroutine
// terminates on context cancellation instead of blocking on the pipe.
func TestStagedBuildContextTarContextCancellation(t *testing.T) {
	staged := newTestStagedContext(t, "Dockerfile", nil)
	for i := 0; i < 50; i++ {
		name := filepath.Join(staged.ContextPath, "file"+string(rune('a'+i%26))+string(rune('0'+i/26)))
		if err := os.WriteFile(name, make([]byte, 4096), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	reader, err := staged.tarContext(ctx)
	if err != nil {
		t.Fatalf("tarContext: %v", err)
	}
	defer reader.Close()

	cancel()
	// Closing the reader must release the tar goroutine.
	if err := reader.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}
