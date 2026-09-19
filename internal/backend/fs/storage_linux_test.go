//go:build linux

package fs

import (
	"bytes"
	"context"
	"errors"
	"io"
	iofs "io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"common.queueb.org/keyring/internal/contract"
	tests "common.queueb.org/tests"

	"golang.org/x/sys/unix"
)

func TestFilesystemKeyringCRUD(t *testing.T) {
	t.Parallel()

	rootPath := filepath.Join(t.TempDir(), "fallback")
	keyring, err := Open(rootPath, "service")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	ctx := context.Background()
	if _, err := keyring.Get(ctx, "key"); !errors.Is(err, contract.ErrNotFound) {
		t.Fatalf("initial Get: got %v, want %v", err, contract.ErrNotFound)
	}
	if err := keyring.Delete(ctx, "key"); !errors.Is(err, contract.ErrNotFound) {
		t.Fatalf("initial Delete: got %v, want %v", err, contract.ErrNotFound)
	}

	if err := keyring.Set(ctx, "key", []byte("old value")); err != nil {
		t.Fatalf("initial Set: %v", err)
	}
	if err := keyring.Set(ctx, "key", []byte("new value")); err != nil {
		t.Fatalf("replacement Set: %v", err)
	}
	value, err := keyring.Get(ctx, "key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(value) != "new value" {
		t.Fatalf("Get returned %q", value)
	}

	layout := newLayout("service")
	credentialPath := filepath.Join(rootPath, layout.keyPath("key"))
	info, err := os.Stat(credentialPath)
	if err != nil {
		t.Fatalf("stat credential: %v", err)
	}
	if mode := info.Mode().Perm(); mode != secretMode {
		t.Fatalf("credential mode = %#o, want %#o", mode, secretMode)
	}
	entries, err := os.ReadDir(filepath.Dir(credentialPath))
	if err != nil {
		t.Fatalf("read service directory: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(credentialPath) {
		t.Fatalf("unexpected service directory entries: %+v", entries)
	}

	if err := keyring.Delete(ctx, "key"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := keyring.Get(ctx, "key"); !errors.Is(err, contract.ErrNotFound) {
		t.Fatalf("final Get: got %v, want %v", err, contract.ErrNotFound)
	}
}

func TestFilesystemKeyringRejectsUnsafeCredentials(t *testing.T) {
	t.Parallel()

	for _, target := range []string{"symlink", "directory", "fifo", "mode"} {
		t.Run(target, func(t *testing.T) {
			t.Parallel()

			rootPath := filepath.Join(t.TempDir(), "fallback")
			keyring, err := Open(rootPath, "service")
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			credentialPath := filepath.Join(rootPath, newLayout("service").keyPath("key"))
			switch target {
			case "symlink":
				outside := filepath.Join(t.TempDir(), "outside")
				tests.WithWriteFile(t, outside, []byte("outside"))
				if err := os.Symlink(outside, credentialPath); err != nil {
					t.Fatalf("create credential symlink: %v", err)
				}
			case "directory":
				if err := os.Mkdir(credentialPath, secretMode); err != nil {
					t.Fatalf("create credential directory: %v", err)
				}
			case "fifo":
				if err := unix.Mkfifo(credentialPath, secretMode); err != nil {
					t.Fatalf("create credential fifo: %v", err)
				}
			case "mode":
				tests.WithWriteFile(t, credentialPath, []byte("value"))
				if err := os.Chmod(credentialPath, 0o640); err != nil {
					t.Fatalf("set credential mode: %v", err)
				}
			}

			if _, err := keyring.Get(context.Background(), "key"); !errors.Is(err, contract.ErrInsecureFallback) {
				t.Fatalf("Get: got %v, want %v", err, contract.ErrInsecureFallback)
			}
			if err := keyring.Set(context.Background(), "key", []byte("value")); !errors.Is(err, contract.ErrInsecureFallback) {
				t.Fatalf("Set: got %v, want %v", err, contract.ErrInsecureFallback)
			}
			if err := keyring.Delete(context.Background(), "key"); !errors.Is(err, contract.ErrInsecureFallback) {
				t.Fatalf("Delete: got %v, want %v", err, contract.ErrInsecureFallback)
			}
		})
	}
}

func TestFilesystemKeyringAtomicFailureState(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name          string
		system        func(linuxSystem, error) linuxSystem
		expectedValue string
	}{
		{
			name: "before rename",
			system: func(system linuxSystem, err error) linuxSystem {
				return failingRenameSystem{linuxSystem: system, err: err}
			},
			expectedValue: "old value",
		},
		{
			name: "after rename",
			system: func(system linuxSystem, err error) linuxSystem {
				return &failingDirectorySyncSystem{linuxSystem: system, err: err}
			},
			expectedValue: "new value",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			keyring, err := Open(filepath.Join(t.TempDir(), "fallback"), "service")
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			ctx := context.Background()
			if err := keyring.Set(ctx, "key", []byte("old value")); err != nil {
				t.Fatalf("initial Set: %v", err)
			}

			backend := keyring.storage.(*linuxStorage)
			originalSystem := backend.system
			sentinel := errors.New("injected failure")
			backend.system = test.system(originalSystem, sentinel)
			if err := keyring.Set(ctx, "key", []byte("new value")); !errors.Is(err, sentinel) {
				t.Fatalf("replacement Set: got %v, want %v", err, sentinel)
			}
			backend.system = originalSystem

			value, err := keyring.Get(ctx, "key")
			if err != nil {
				t.Fatalf("Get after failed Set: %v", err)
			}
			if string(value) != test.expectedValue {
				t.Fatalf("Get after failed Set = %q, want %q", value, test.expectedValue)
			}
			servicePath := filepath.Join(backend.rootPath, backend.layout.servicePath())
			entries, err := os.ReadDir(servicePath)
			if err != nil {
				t.Fatalf("read service directory: %v", err)
			}
			if len(entries) != 1 || entries[0].Name() != identifier(keyDomain, "key") {
				t.Fatalf("unexpected service directory entries: %+v", entries)
			}
		})
	}
}

func TestOpenLinuxStorageErrors(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("sentinel")
	for _, test := range []struct {
		name   string
		system *fakeLinuxSystem
	}{
		{name: "mount", system: &fakeLinuxSystem{mountErr: sentinel}},
		{name: "directories", system: &fakeLinuxSystem{prepareErr: sentinel}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if _, err := openLinuxStorage("root", newLayout("service"), 1000, test.system, strings.NewReader("")); !errors.Is(err, sentinel) {
				t.Fatalf("expected %v, got %v", sentinel, err)
			}
		})
	}

	system := newFakeLinuxSystem()
	storage, err := openLinuxStorage("root", newLayout("service"), 1000, system, strings.NewReader(""))
	if err != nil {
		t.Fatalf("open storage: %v", err)
	}
	if storage == nil {
		t.Fatal("open storage returned nil")
	}
}

func TestLinuxStorageOpenServiceDirectoryErrors(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("sentinel")
	for _, test := range []struct {
		name   string
		create bool
		setup  func(*fakeLinuxSystem)
	}{
		{name: "mount", setup: func(system *fakeLinuxSystem) { system.mountErr = sentinel }},
		{name: "prepare", create: true, setup: func(system *fakeLinuxSystem) { system.prepareErr = sentinel }},
		{name: "root", setup: func(system *fakeLinuxSystem) { system.openDirectoryErr = sentinel }},
		{name: "version", setup: func(system *fakeLinuxSystem) { system.openDirectoryAtErrors = map[int]error{1: sentinel} }},
		{name: "service", setup: func(system *fakeLinuxSystem) { system.openDirectoryAtErrors = map[int]error{2: sentinel} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			system := newFakeLinuxSystem()
			test.setup(system)
			storage := newTestLinuxStorage(system)
			if _, err := storage.openServiceDirectory(test.create); !errors.Is(err, sentinel) {
				t.Fatalf("expected %v, got %v", sentinel, err)
			}
		})
	}
}

func TestLinuxStorageCredentialValidation(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("sentinel")
	for _, test := range []struct {
		name     string
		setup    func(*fakeLinuxSystem)
		expected error
	}{
		{name: "open", setup: func(system *fakeLinuxSystem) { system.credentialOpenErr = sentinel }, expected: sentinel},
		{name: "stat", setup: func(system *fakeLinuxSystem) { system.fstatErr = sentinel }, expected: sentinel},
		{name: "type", setup: func(system *fakeLinuxSystem) { system.status.Mode = unix.S_IFIFO | secretMode }, expected: contract.ErrInsecureFallback},
		{name: "owner", setup: func(system *fakeLinuxSystem) { system.status.Uid++ }, expected: contract.ErrInsecureFallback},
		{name: "mode", setup: func(system *fakeLinuxSystem) { system.status.Mode = unix.S_IFREG | 0o640 }, expected: contract.ErrInsecureFallback},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			system := newFakeLinuxSystem()
			test.setup(system)
			storage := newTestLinuxStorage(system)
			if _, err := storage.openCredential(12, "credential"); !errors.Is(err, test.expected) {
				t.Fatalf("expected %v, got %v", test.expected, err)
			}
		})
	}
}

func TestLinuxStorageValidateExistingCredential(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("sentinel")
	for _, test := range []struct {
		name     string
		setup    func(*fakeLinuxSystem)
		expected error
	}{
		{name: "missing", setup: func(system *fakeLinuxSystem) { system.credentialOpenErr = iofs.ErrNotExist }},
		{name: "open", setup: func(system *fakeLinuxSystem) { system.credentialOpenErr = sentinel }, expected: sentinel},
		{name: "close", setup: func(system *fakeLinuxSystem) { system.closeErrors[20] = sentinel }, expected: sentinel},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			system := newFakeLinuxSystem()
			test.setup(system)
			storage := newTestLinuxStorage(system)
			err := storage.validateExistingCredential(12, "credential")
			if !errors.Is(err, test.expected) {
				t.Fatalf("expected %v, got %v", test.expected, err)
			}
		})
	}
}

func TestLinuxStorageGetErrors(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("sentinel")
	for _, test := range []struct {
		name  string
		setup func(*fakeLinuxSystem)
	}{
		{name: "service", setup: func(system *fakeLinuxSystem) { system.mountErr = sentinel }},
		{name: "credential", setup: func(system *fakeLinuxSystem) { system.credentialOpenErr = sentinel }},
		{name: "read", setup: func(system *fakeLinuxSystem) { system.readErr = sentinel }},
		{name: "close", setup: func(system *fakeLinuxSystem) { system.closeErrors[20] = sentinel }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			system := newFakeLinuxSystem()
			test.setup(system)
			if _, err := newTestLinuxStorage(system).get("key"); !errors.Is(err, sentinel) {
				t.Fatalf("expected %v, got %v", sentinel, err)
			}
		})
	}
}

func TestLinuxStorageSetServiceError(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("sentinel")
	system := newFakeLinuxSystem()
	system.mountErr = sentinel
	if err := newTestLinuxStorage(system).set("key", []byte("value")); !errors.Is(err, sentinel) {
		t.Fatalf("expected %v, got %v", sentinel, err)
	}
}

func TestLinuxStorageDeleteErrors(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("sentinel")
	for _, test := range []struct {
		name  string
		setup func(*fakeLinuxSystem)
	}{
		{name: "service", setup: func(system *fakeLinuxSystem) { system.mountErr = sentinel }},
		{name: "credential", setup: func(system *fakeLinuxSystem) { system.credentialOpenErr = sentinel }},
		{name: "close", setup: func(system *fakeLinuxSystem) { system.closeErrors[20] = sentinel }},
		{name: "unlink", setup: func(system *fakeLinuxSystem) { system.unlinkErr = sentinel }},
		{name: "directory sync", setup: func(system *fakeLinuxSystem) { system.fsyncErrors[12] = sentinel }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			system := newFakeLinuxSystem()
			test.setup(system)
			if err := newTestLinuxStorage(system).delete("key"); !errors.Is(err, sentinel) {
				t.Fatalf("expected %v, got %v", sentinel, err)
			}
		})
	}
}

func TestLinuxStorageWriteAtomic(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		system := newFakeLinuxSystem()
		storage := newTestLinuxStorage(system)
		if err := storage.writeAtomic(12, "credential", []byte("value")); err != nil {
			t.Fatalf("write atomic: %v", err)
		}
		if string(system.written) != "value" || !system.renamed || system.unlinked {
			t.Fatalf("unexpected atomic write state: %+v", system)
		}
	})

	sentinel := errors.New("sentinel")
	for _, test := range []struct {
		name  string
		setup func(*fakeLinuxSystem)
	}{
		{name: "temporary", setup: func(system *fakeLinuxSystem) { system.temporaryOpenErrors = []error{sentinel} }},
		{name: "chmod", setup: func(system *fakeLinuxSystem) { system.fchmodErr = sentinel }},
		{name: "write", setup: func(system *fakeLinuxSystem) { system.writeErr = sentinel }},
		{name: "file sync", setup: func(system *fakeLinuxSystem) { system.fsyncErrors[30] = sentinel }},
		{name: "close", setup: func(system *fakeLinuxSystem) { system.closeErrors[30] = sentinel }},
		{name: "rename", setup: func(system *fakeLinuxSystem) { system.renameErr = sentinel }},
		{name: "directory sync", setup: func(system *fakeLinuxSystem) { system.fsyncErrors[12] = sentinel }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			system := newFakeLinuxSystem()
			test.setup(system)
			err := newTestLinuxStorage(system).writeAtomic(12, "credential", []byte("value"))
			if !errors.Is(err, sentinel) {
				t.Fatalf("expected %v, got %v", sentinel, err)
			}
			if test.name == "directory sync" {
				if system.unlinked {
					t.Fatal("renamed credential must not be removed after directory sync failure")
				}
			} else if test.name != "temporary" && !system.unlinked {
				t.Fatal("temporary credential was not cleaned up")
			}
		})
	}

	t.Run("cleanup errors", func(t *testing.T) {
		t.Parallel()

		operationErr := errors.New("operation")
		closeErr := errors.New("close")
		cleanupErr := errors.New("cleanup")
		system := newFakeLinuxSystem()
		system.fchmodErr = operationErr
		system.closeErrors[30] = closeErr
		system.unlinkErr = cleanupErr
		err := newTestLinuxStorage(system).writeAtomic(12, "credential", nil)
		for _, expected := range []error{operationErr, closeErr, cleanupErr} {
			if !errors.Is(err, expected) {
				t.Fatalf("expected joined error %v, got %v", expected, err)
			}
		}
	})

	t.Run("missing temporary during cleanup", func(t *testing.T) {
		t.Parallel()

		system := newFakeLinuxSystem()
		system.fchmodErr = sentinel
		system.unlinkErr = iofs.ErrNotExist
		if err := newTestLinuxStorage(system).writeAtomic(12, "credential", nil); !errors.Is(err, sentinel) {
			t.Fatalf("expected %v, got %v", sentinel, err)
		}
	})
}

func TestLinuxStorageCreateTemporary(t *testing.T) {
	t.Parallel()

	t.Run("random", func(t *testing.T) {
		t.Parallel()

		storage := newTestLinuxStorage(newFakeLinuxSystem())
		storage.random = errorReader{}
		if _, _, err := storage.createTemporary(12); err == nil {
			t.Fatal("expected random error")
		}
	})

	t.Run("collision", func(t *testing.T) {
		t.Parallel()

		system := newFakeLinuxSystem()
		system.temporaryOpenErrors = []error{iofs.ErrExist, nil}
		storage := newTestLinuxStorage(system)
		storage.random = bytes.NewReader(make([]byte, 2*temporaryRandomBytes))
		name, descriptor, err := storage.createTemporary(12)
		if err != nil {
			t.Fatalf("create temporary: %v", err)
		}
		if name != ".tmp-"+strings.Repeat("0", 2*temporaryRandomBytes) || descriptor != 30 {
			t.Fatalf("unexpected temporary result: name=%q descriptor=%d", name, descriptor)
		}
	})

	t.Run("exhausted", func(t *testing.T) {
		t.Parallel()

		system := newFakeLinuxSystem()
		system.defaultTemporaryOpenErr = iofs.ErrExist
		storage := newTestLinuxStorage(system)
		storage.random = bytes.NewReader(make([]byte, temporaryCreateAttempts*temporaryRandomBytes))
		if _, _, err := storage.createTemporary(12); err == nil {
			t.Fatal("expected collision exhaustion error")
		}
	})
}

func TestWriteAll(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("sentinel")
	for _, test := range []struct {
		name     string
		contents []byte
		setup    func(*fakeLinuxSystem)
		expected error
	}{
		{name: "empty"},
		{name: "partial", contents: []byte("value"), setup: func(system *fakeLinuxSystem) { system.maximumWrite = 2 }},
		{name: "error", contents: []byte("value"), setup: func(system *fakeLinuxSystem) { system.writeErr = sentinel }, expected: sentinel},
		{name: "zero", contents: []byte("value"), setup: func(system *fakeLinuxSystem) { system.zeroWrite = true }, expected: io.ErrShortWrite},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			system := newFakeLinuxSystem()
			if test.setup != nil {
				test.setup(system)
			}
			err := writeAll(system, 30, test.contents)
			if !errors.Is(err, test.expected) {
				t.Fatalf("expected %v, got %v", test.expected, err)
			}
			if err == nil && !bytes.Equal(system.written, test.contents) {
				t.Fatalf("written %q, want %q", system.written, test.contents)
			}
		})
	}
}

func TestOperationError(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name     string
		err      error
		missing  bool
		expected error
	}{
		{name: "nil"},
		{name: "missing", err: iofs.ErrNotExist, missing: true, expected: contract.ErrNotFound},
		{name: "missing during Set", err: iofs.ErrNotExist, expected: contract.ErrBackendFailure},
		{name: "permission", err: iofs.ErrPermission, expected: contract.ErrPermissionDenied},
		{name: "symlink", err: unix.ELOOP, expected: contract.ErrInsecureFallback},
		{name: "not directory", err: unix.ENOTDIR, expected: contract.ErrInsecureFallback},
		{name: "directory", err: unix.EISDIR, expected: contract.ErrInsecureFallback},
		{name: "categorized", err: contract.ErrInsecureFallback, expected: contract.ErrInsecureFallback},
		{name: "invalid", err: contract.ErrInvalidArgument, expected: contract.ErrInvalidArgument},
		{name: "denied", err: contract.ErrPermissionDenied, expected: contract.ErrPermissionDenied},
		{name: "unavailable", err: contract.ErrBackendUnavailable, expected: contract.ErrBackendUnavailable},
		{name: "unsupported", err: contract.ErrUnsupported, expected: contract.ErrUnsupported},
		{name: "backend", err: contract.ErrBackendFailure, expected: contract.ErrBackendFailure},
		{name: "other", err: errors.New("other"), expected: contract.ErrBackendFailure},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := operationError("test", test.missing, test.err)
			if !errors.Is(err, test.expected) {
				t.Fatalf("expected %v, got %v", test.expected, err)
			}
			if test.name == "missing" && errors.Is(err, contract.ErrBackendFailure) {
				t.Fatalf("missing credential also matched backend failure: %v", err)
			}
		})
	}
}

func newTestLinuxStorage(system *fakeLinuxSystem) *linuxStorage {
	return &linuxStorage{
		rootPath:     "root",
		layout:       newLayout("service"),
		effectiveUID: 1000,
		system:       system,
		random:       bytes.NewReader(make([]byte, temporaryRandomBytes)),
	}
}

type fakeLinuxSystem struct {
	mountErr                error
	prepareErr              error
	openDirectoryErr        error
	openDirectoryAtCalls    int
	openDirectoryAtErrors   map[int]error
	credentialOpenErr       error
	temporaryOpenErrors     []error
	defaultTemporaryOpenErr error
	status                  unix.Stat_t
	fstatErr                error
	fchmodErr               error
	readContents            []byte
	readErr                 error
	written                 []byte
	writeErr                error
	maximumWrite            int
	zeroWrite               bool
	fsyncErrors             map[int]error
	closeErrors             map[int]error
	renameErr               error
	unlinkErr               error
	renamed                 bool
	unlinked                bool
}

type failingRenameSystem struct {
	linuxSystem
	err error
}

func (s failingRenameSystem) renameAt(int, string, int, string) error {
	return s.err
}

type failingDirectorySyncSystem struct {
	linuxSystem
	err       error
	syncCalls int
}

func (s *failingDirectorySyncSystem) fsync(descriptor int) error {
	s.syncCalls++
	if s.syncCalls == 2 {
		return s.err
	}
	return s.linuxSystem.fsync(descriptor)
}

func newFakeLinuxSystem() *fakeLinuxSystem {
	return &fakeLinuxSystem{
		status: unix.Stat_t{
			Mode: unix.S_IFREG | secretMode,
			Uid:  1000,
		},
		readContents: []byte("value"),
		fsyncErrors:  make(map[int]error),
		closeErrors:  make(map[int]error),
	}
}

func (s *fakeLinuxSystem) validateMount(string) error {
	return s.mountErr
}

func (s *fakeLinuxSystem) prepareDirectories(string, layout, uint32) error {
	return s.prepareErr
}

func (s *fakeLinuxSystem) openDirectory(string, uint32) (int, error) {
	return 10, s.openDirectoryErr
}

func (s *fakeLinuxSystem) openDirectoryAt(int, string, uint32) (int, error) {
	s.openDirectoryAtCalls++
	if err := s.openDirectoryAtErrors[s.openDirectoryAtCalls]; err != nil {
		return -1, err
	}
	return 10 + s.openDirectoryAtCalls, nil
}

func (s *fakeLinuxSystem) openFileAt(_ int, _ string, flags int, _ uint32) (int, error) {
	if flags&unix.O_CREAT == 0 {
		return 20, s.credentialOpenErr
	}
	if len(s.temporaryOpenErrors) != 0 {
		err := s.temporaryOpenErrors[0]
		s.temporaryOpenErrors = s.temporaryOpenErrors[1:]
		if err != nil {
			return -1, err
		}
	}
	if s.defaultTemporaryOpenErr != nil {
		return -1, s.defaultTemporaryOpenErr
	}
	return 30, nil
}

func (s *fakeLinuxSystem) fstat(_ int, status *unix.Stat_t) error {
	*status = s.status
	return s.fstatErr
}

func (s *fakeLinuxSystem) fchmod(int, uint32) error {
	return s.fchmodErr
}

func (s *fakeLinuxSystem) read(_ int, contents []byte) (int, error) {
	read := copy(contents, s.readContents)
	s.readContents = s.readContents[read:]
	return read, s.readErr
}

func (s *fakeLinuxSystem) write(_ int, contents []byte) (int, error) {
	if s.zeroWrite {
		return 0, nil
	}
	written := len(contents)
	if s.maximumWrite != 0 && written > s.maximumWrite {
		written = s.maximumWrite
	}
	s.written = append(s.written, contents[:written]...)
	return written, s.writeErr
}

func (s *fakeLinuxSystem) fsync(descriptor int) error {
	return s.fsyncErrors[descriptor]
}

func (s *fakeLinuxSystem) close(descriptor int) error {
	return s.closeErrors[descriptor]
}

func (s *fakeLinuxSystem) renameAt(int, string, int, string) error {
	s.renamed = true
	return s.renameErr
}

func (s *fakeLinuxSystem) unlinkAt(int, string, int) error {
	s.unlinked = true
	return s.unlinkErr
}
