package fs

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"

	"common.queueb.org/keyring/internal/contract"
)

func TestOpenValidation(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("sentinel")
	for _, test := range []struct {
		name     string
		rootDir  string
		service  string
		absolute absolutePathFunc
		opener   storageOpener
		expected error
	}{
		{
			name:     "empty root",
			service:  "service",
			absolute: unchangedPath,
			opener:   successfulStorageOpen,
			expected: contract.ErrInvalidArgument,
		},
		{
			name:     "empty service",
			rootDir:  "root",
			absolute: unchangedPath,
			opener:   successfulStorageOpen,
			expected: contract.ErrInvalidArgument,
		},
		{
			name:    "absolute path",
			rootDir: "root",
			service: "service",
			absolute: func(string) (string, error) {
				return "", sentinel
			},
			opener:   successfulStorageOpen,
			expected: sentinel,
		},
		{
			name:     "storage",
			rootDir:  "root",
			service:  "service",
			absolute: unchangedPath,
			opener: func(string, layout) (storage, error) {
				return nil, sentinel
			},
			expected: sentinel,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			keyring, err := openKeyring(
				test.rootDir,
				test.service,
				test.absolute,
				test.opener,
			)
			if keyring != nil {
				t.Fatalf("unexpected keyring: %#v", keyring)
			}
			if !errors.Is(err, test.expected) {
				t.Fatalf("expected %v, got %v", test.expected, err)
			}
		})
	}
}

func TestOpenUsesAbsoluteRootAndServiceLayout(t *testing.T) {
	t.Parallel()

	backend := &testStorage{}
	keyring, err := openKeyring(
		"relative",
		"service",
		func(path string) (string, error) {
			if path != "relative" {
				t.Fatalf("unexpected path: %q", path)
			}
			return "/absolute", nil
		},
		func(rootDir string, layout layout) (storage, error) {
			if rootDir != "/absolute" {
				t.Fatalf("unexpected root: %q", rootDir)
			}
			if layout != newLayout("service") {
				t.Fatalf("unexpected layout: %+v", layout)
			}
			return backend, nil
		},
	)
	if err != nil {
		t.Fatalf("open keyring: %v", err)
	}
	if keyring.storage != backend {
		t.Fatal("Open returned a keyring with a different storage")
	}
}

func TestKeyringOperations(t *testing.T) {
	t.Parallel()

	backend := &testStorage{value: []byte("value")}
	keyring := &Keyring{storage: backend}
	value, err := keyring.Get(context.Background(), "key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(value) != "value" || backend.key != "key" {
		t.Fatalf("unexpected Get result: value=%q key=%q", value, backend.key)
	}

	if err := keyring.Set(context.Background(), "key", []byte("new")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if string(backend.value) != "new" || backend.key != "key" {
		t.Fatalf("unexpected Set input: value=%q key=%q", backend.value, backend.key)
	}

	if err := keyring.Delete(context.Background(), "key"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if backend.key != "key" || !backend.deleted {
		t.Fatalf("unexpected Delete input: key=%q deleted=%t", backend.key, backend.deleted)
	}
}

func TestKeyringOperationErrors(t *testing.T) {
	t.Parallel()

	backendErr := errors.New("backend failed")
	backend := &testStorage{err: backendErr}
	keyring := &Keyring{storage: backend}
	for _, test := range []struct {
		name      string
		operation func(context.Context, string) error
	}{
		{
			name: "Get",
			operation: func(ctx context.Context, key string) error {
				_, err := keyring.Get(ctx, key)
				return err
			},
		},
		{name: "Set", operation: func(ctx context.Context, key string) error {
			return keyring.Set(ctx, key, nil)
		}},
		{name: "Delete", operation: keyring.Delete},
	} {
		t.Run(test.name+" empty key", func(t *testing.T) {
			t.Parallel()

			if err := test.operation(context.Background(), ""); !errors.Is(err, contract.ErrInvalidArgument) {
				t.Fatalf("expected invalid argument, got %v", err)
			}
		})
		t.Run(test.name+" context", func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if err := test.operation(ctx, "key"); !errors.Is(err, context.Canceled) {
				t.Fatalf("expected context cancellation, got %v", err)
			}
		})
		t.Run(test.name+" backend", func(t *testing.T) {
			t.Parallel()

			if err := test.operation(context.Background(), "key"); !errors.Is(err, backendErr) {
				t.Fatalf("expected backend error, got %v", err)
			}
		})
	}
}

func TestMutationLock(t *testing.T) {
	t.Parallel()

	keyring := &Keyring{}
	digest := sha256.Sum256([]byte(keyDomain + "key"))
	expected := &keyring.locks[int(digest[0])%len(keyring.locks)]
	if keyring.mutationLock("key") != expected {
		t.Fatal("key uses an unexpected mutation lock")
	}
}

type testStorage struct {
	mu      sync.Mutex
	key     string
	value   []byte
	deleted bool
	err     error
}

func (s *testStorage) get(key string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.key = key
	return s.value, s.err
}

func (s *testStorage) set(key string, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.key = key
	s.value = value
	return s.err
}

func (s *testStorage) delete(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.key = key
	s.deleted = true
	return s.err
}

func unchangedPath(path string) (string, error) {
	return path, nil
}

func successfulStorageOpen(string, layout) (storage, error) {
	return &testStorage{}, nil
}
