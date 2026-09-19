//go:build linux

package fs

import (
	"errors"
	iofs "io/fs"
	"os"
	"path/filepath"
	"testing"

	"common.queueb.org/keyring/internal/contract"

	"golang.org/x/sys/unix"
)

func TestPrepareDirectories(t *testing.T) {
	t.Parallel()

	rootPath := filepath.Join(t.TempDir(), "fallback")
	layout := newLayout("service")
	if err := prepareDirectories(rootPath, layout, uint32(os.Geteuid())); err != nil {
		t.Fatalf("prepare directories: %v", err)
	}
	if err := prepareDirectories(rootPath, layout, uint32(os.Geteuid())); err != nil {
		t.Fatalf("prepare existing directories: %v", err)
	}

	for _, path := range []string{
		rootPath,
		filepath.Join(rootPath, layoutVersion),
		filepath.Join(rootPath, layout.servicePath()),
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %q: %v", path, err)
		}
		if mode := info.Mode().Perm(); mode != directoryMode {
			t.Fatalf("unexpected mode for %q: %#o", path, mode)
		}
	}
}

func TestPrepareDirectoriesRejectsRootSymlink(t *testing.T) {
	t.Parallel()

	parent := t.TempDir()
	target := filepath.Join(parent, "target")
	if err := os.Mkdir(target, directoryMode); err != nil {
		t.Fatalf("create target: %v", err)
	}
	rootPath := filepath.Join(parent, "fallback")
	if err := os.Symlink(target, rootPath); err != nil {
		t.Fatalf("create root symlink: %v", err)
	}

	err := prepareDirectories(rootPath, newLayout("service"), uint32(os.Geteuid()))
	if !errors.Is(err, contract.ErrInsecureFallback) {
		t.Fatalf("expected insecure fallback error, got %v", err)
	}
}

func TestPrepareDirectoriesRejectsManagedSymlinks(t *testing.T) {
	t.Parallel()

	for _, target := range []string{"version", "service"} {
		t.Run(target, func(t *testing.T) {
			t.Parallel()

			rootPath := filepath.Join(t.TempDir(), "fallback")
			if err := os.Mkdir(rootPath, directoryMode); err != nil {
				t.Fatalf("create root: %v", err)
			}
			outside := filepath.Join(t.TempDir(), "outside")
			if err := os.Mkdir(outside, directoryMode); err != nil {
				t.Fatalf("create symlink target: %v", err)
			}

			layout := newLayout("service")
			symlink := filepath.Join(rootPath, layoutVersion)
			if target == "service" {
				if err := os.Mkdir(symlink, directoryMode); err != nil {
					t.Fatalf("create version directory: %v", err)
				}
				symlink = filepath.Join(symlink, layout.serviceID)
			}
			if err := os.Symlink(outside, symlink); err != nil {
				t.Fatalf("create %s symlink: %v", target, err)
			}

			err := prepareDirectories(rootPath, layout, uint32(os.Geteuid()))
			if !errors.Is(err, contract.ErrInsecureFallback) {
				t.Fatalf("expected insecure fallback error, got %v", err)
			}
		})
	}
}

func TestPrepareDirectoriesRejectsInsecureMode(t *testing.T) {
	t.Parallel()

	for _, target := range []string{"root", "version", "service"} {
		t.Run(target, func(t *testing.T) {
			t.Parallel()

			rootPath := filepath.Join(t.TempDir(), "fallback")
			layout := newLayout("service")
			servicePath := filepath.Join(rootPath, layout.servicePath())
			if err := os.MkdirAll(servicePath, directoryMode); err != nil {
				t.Fatalf("create layout: %v", err)
			}

			path := map[string]string{
				"root":    rootPath,
				"version": filepath.Join(rootPath, layoutVersion),
				"service": servicePath,
			}[target]
			if err := os.Chmod(path, 0o750); err != nil {
				t.Fatalf("change %s mode: %v", target, err)
			}

			err := prepareDirectories(rootPath, layout, uint32(os.Geteuid()))
			if !errors.Is(err, contract.ErrInsecureFallback) {
				t.Fatalf("expected insecure fallback error, got %v", err)
			}
		})
	}
}

func TestPrepareDirectoriesErrors(t *testing.T) {
	t.Parallel()

	t.Run("create root", func(t *testing.T) {
		t.Parallel()

		parent := t.TempDir()
		rootPath := filepath.Join(parent, "file", "fallback")
		if err := os.WriteFile(filepath.Join(parent, "file"), nil, 0o600); err != nil {
			t.Fatalf("create parent file: %v", err)
		}
		if err := prepareDirectories(rootPath, newLayout("service"), uint32(os.Geteuid())); err == nil {
			t.Fatal("expected root creation error")
		}
	})

	t.Run("create managed directory", func(t *testing.T) {
		t.Parallel()

		rootPath := filepath.Join(t.TempDir(), "fallback")
		if err := os.Mkdir(rootPath, 0o500); err != nil {
			t.Fatalf("create read-only root: %v", err)
		}
		err := prepareDirectories(rootPath, newLayout("service"), uint32(os.Geteuid()))
		if !errors.Is(err, contract.ErrPermissionDenied) {
			t.Fatalf("expected permission error, got %v", err)
		}
	})
}

func TestValidateDirectory(t *testing.T) {
	t.Parallel()

	t.Run("inspect error", func(t *testing.T) {
		t.Parallel()

		if err := validateDirectory(-1, uint32(os.Geteuid())); !errors.Is(err, contract.ErrBackendFailure) {
			t.Fatalf("expected backend failure, got %v", err)
		}
	})

	t.Run("not directory", func(t *testing.T) {
		t.Parallel()

		file, err := os.CreateTemp(t.TempDir(), "file")
		if err != nil {
			t.Fatalf("create file: %v", err)
		}
		defer file.Close()
		if err := validateDirectory(int(file.Fd()), uint32(os.Geteuid())); !errors.Is(err, contract.ErrInsecureFallback) {
			t.Fatalf("expected insecure fallback error, got %v", err)
		}
	})

	t.Run("wrong owner", func(t *testing.T) {
		t.Parallel()

		directory, err := unix.Open(t.TempDir(), unix.O_RDONLY|unix.O_DIRECTORY, 0)
		if err != nil {
			t.Fatalf("open directory: %v", err)
		}
		defer unix.Close(directory)
		if err := validateDirectory(directory, uint32(os.Geteuid())+1); !errors.Is(err, contract.ErrInsecureFallback) {
			t.Fatalf("expected insecure fallback error, got %v", err)
		}
	})
}

func TestDirectoryError(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name     string
		err      error
		expected error
	}{
		{name: "missing", err: iofs.ErrNotExist, expected: iofs.ErrNotExist},
		{name: "permission", err: iofs.ErrPermission, expected: contract.ErrPermissionDenied},
		{name: "exists", err: iofs.ErrExist, expected: contract.ErrInsecureFallback},
		{name: "symlink", err: unix.ELOOP, expected: contract.ErrInsecureFallback},
		{name: "not directory", err: unix.ENOTDIR, expected: contract.ErrInsecureFallback},
		{name: "other", err: unix.EIO, expected: contract.ErrBackendFailure},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := directoryError("test", test.err)
			if !errors.Is(err, test.expected) {
				t.Fatalf("expected %v, got %v", test.expected, err)
			}
			if !errors.Is(err, test.err) {
				t.Fatalf("expected original cause %v, got %v", test.err, err)
			}
		})
	}
}
