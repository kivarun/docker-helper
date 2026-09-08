package main

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
)

// stagedBuildContext represents a successfully staged build context.
type stagedBuildContext struct {
	ContextPath    string
	DockerfilePath string
	cleanupPath    string
	cleanupOnce    sync.Once
	cleanupErr     error
	// removeAll is an optional test seam for deterministic cleanup testing.
	// When nil, os.RemoveAll is used.
	removeAll func(string) error
}

// Cleanup removes the staging directory. It is idempotent and concurrency-safe.
// The first invocation performs the deletion; subsequent invocations return
// the same result (nil or the error from the first attempt).
func (s *stagedBuildContext) Cleanup() error {
	s.cleanupOnce.Do(func() {
		rm := s.removeAll
		if rm == nil {
			rm = os.RemoveAll
		}
		s.cleanupErr = rm(s.cleanupPath)
	})
	return s.cleanupErr
}

// tarContext streams the staged build context as a tar archive for the
// Engine ImageBuild request body. The staged copy is helper-owned — created
// by StageBuildContext under the runtime staging root with restricted
// traversal — so this traversal re-derives no workspace policy: it walks the
// staged directory without following symlinks, preserving symlink entries
// verbatim exactly as the docker CLI context tar did. The returned reader
// must be closed; closing it releases the tar goroutine.
func (s *stagedBuildContext) tarContext(ctx context.Context) (io.ReadCloser, error) {
	pr, pw := io.Pipe()
	go func() {
		err := tarWalk(ctx, s.ContextPath, pw)
		pw.CloseWithError(err)
	}()
	return pr, nil
}

// tarWalk writes one tar archive of root to w, streaming entries as they are
// walked. Directory order is the lexical order filepath.WalkDir guarantees.
func tarWalk(ctx context.Context, root string, w io.Writer) error {
	tw := tar.NewWriter(w)
	defer tw.Close()
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		name := filepath.ToSlash(rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case d.IsDir():
			hdr, err := tar.FileInfoHeader(info, "")
			if err != nil {
				return err
			}
			hdr.Name = name + "/"
			return tw.WriteHeader(hdr)
		case info.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			return tw.WriteHeader(&tar.Header{
				Typeflag: tar.TypeSymlink,
				Name:     name,
				Linkname: target,
				Mode:     int64(info.Mode() & fs.ModePerm),
			})
		case info.Mode().IsRegular():
			hdr, err := tar.FileInfoHeader(info, "")
			if err != nil {
				return err
			}
			hdr.Name = name
			if err := tw.WriteHeader(hdr); err != nil {
				return err
			}
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			defer file.Close()
			_, err = io.Copy(tw, file)
			return err
		default:
			// The staged copy cannot contain other entry types: staging
			// rejects FIFOs, sockets, and devices at copy time.
			return fmt.Errorf("unsupported staged context entry: %s", name)
		}
	})
}
