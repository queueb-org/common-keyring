package keyring

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	backendfs "common.queueb.org/keyring/internal/backend/fs"
)

type testKeyringer struct{}

func (*testKeyringer) Get(context.Context, string) ([]byte, error) { return nil, nil }
func (*testKeyringer) Set(context.Context, string, []byte) error   { return nil }
func (*testKeyringer) Delete(context.Context, string) error        { return nil }

// WithNativeBackendProbe overrides native backend availability for one test
// and restores the original probe during test cleanup. It mutates package state
// and must not be used by parallel tests.
func WithNativeBackendProbe(t *testing.T, probe func(context.Context) error) {
	t.Helper()
	original := probeNativeBackend
	probeNativeBackend = probe
	t.Cleanup(func() { probeNativeBackend = original })
}

// WithNativeOperations overrides native credential operations for one test
// and restores them during cleanup. It mutates package state and must not be
// used by parallel tests.
func WithNativeOperations(
	t *testing.T,
	get func(context.Context, string, string) ([]byte, error),
	set func(context.Context, string, string, []byte) error,
	delete func(context.Context, string, string) error,
) {
	t.Helper()
	originalGet := nativeGet
	originalSet := nativeSet
	originalDelete := nativeDelete
	nativeGet = get
	nativeSet = set
	nativeDelete = delete
	t.Cleanup(func() {
		nativeGet = originalGet
		nativeSet = originalSet
		nativeDelete = originalDelete
	})
}

func TestOpen(t *testing.T) {
	ctx := context.Background()

	t.Run("injected", func(t *testing.T) {
		injected := &testKeyringer{}
		WithNativeBackendProbe(t, func(context.Context) error {
			t.Fatal("native probe was called")
			return nil
		})
		keyring, info, err := Open(ctx,
			&Option{Service: "first", Keyringer: injected},
			&Option{Service: "", Keyringer: nil},
		)
		if err != nil {
			t.Fatalf("Open() error = %v", err)
		}
		if keyring != injected {
			t.Fatalf("Open() keyring = %T", keyring)
		}
		want := Info{
			Backend:     BackendCustom,
			Persistence: PersistenceUnknown,
			Host:        HostUnknown,
			Interaction: InteractionUnknown,
		}
		if !reflect.DeepEqual(info, want) {
			t.Fatalf("Open() info = %#v, want %#v", info, want)
		}
	})

	t.Run("missing service", func(t *testing.T) {
		if _, _, err := Open(ctx); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("Open() error = %v, want %v", err, ErrInvalidArgument)
		}
	})

	t.Run("native", func(t *testing.T) {
		WithNativeBackendProbe(t, func(context.Context) error { return nil })
		keyring, info, err := Open(ctx, &Option{Service: "service"})
		if err != nil {
			t.Fatalf("Open() error = %v", err)
		}
		if _, ok := keyring.(*Keyring); !ok {
			t.Fatalf("Open() keyring = %T", keyring)
		}
		if !reflect.DeepEqual(info, nativeBackendInfo) {
			t.Fatalf("Open() info = %#v, want %#v", info, nativeBackendInfo)
		}
	})

	t.Run("unavailable", func(t *testing.T) {
		WithNativeBackendProbe(t, func(context.Context) error { return ErrBackendUnavailable })
		if _, _, err := Open(ctx, &Option{Service: "service"}); !errors.Is(err, ErrBackendUnavailable) {
			t.Fatalf("Open() error = %v, want %v", err, ErrBackendUnavailable)
		}
	})

	t.Run("filesystem fallback", func(t *testing.T) {
		WithNativeBackendProbe(t, func(context.Context) error { return ErrBackendUnavailable })
		keyring, info, err := Open(ctx,
			&Option{Service: "first", FallbackDir: "first"},
			&Option{Service: "service", FallbackDir: filepath.Join(t.TempDir(), "fallback")},
		)
		if err != nil {
			t.Fatalf("Open() error = %v", err)
		}
		if _, ok := keyring.(*backendfs.Keyring); !ok {
			t.Fatalf("Open() keyring = %T", keyring)
		}
		want := Info{
			Backend:     BackendFilesystem,
			Persistence: PersistencePersistent,
			Host:        HostCurrent,
			Interaction: InteractionNone,
			Fallback:    true,
		}
		if len(info.Rejected) != 1 ||
			info.Rejected[0].Backend != BackendSecretService ||
			!errors.Is(info.Rejected[0].Err, ErrBackendUnavailable) {
			t.Fatalf("Open() rejected = %#v", info.Rejected)
		}
		want.Rejected = info.Rejected
		if !reflect.DeepEqual(info, want) {
			t.Fatalf("Open() info = %#v, want %#v", info, want)
		}
	})

	t.Run("explicit backend order", func(t *testing.T) {
		WithNativeBackendProbe(t, func(context.Context) error {
			t.Fatal("native probe was called")
			return nil
		})
		keyring, info, err := Open(ctx,
			&Option{Service: "service", Backends: []Backend{BackendSecretService}},
			&Option{Backends: []Backend{BackendFilesystem}, FallbackDir: filepath.Join(t.TempDir(), "fallback")},
		)
		if err != nil {
			t.Fatalf("Open() error = %v", err)
		}
		if _, ok := keyring.(*backendfs.Keyring); !ok || !info.Fallback ||
			info.Backend != BackendFilesystem {
			t.Fatalf("Open() = %T, %#v", keyring, info)
		}
	})

	t.Run("filesystem configuration", func(t *testing.T) {
		_, _, err := Open(ctx, &Option{
			Service:  "service",
			Backends: []Backend{BackendFilesystem},
		})
		if !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("Open() error = %v, want %v", err, ErrInvalidArgument)
		}
	})

	t.Run("filesystem security", func(t *testing.T) {
		fallbackDir := t.TempDir()
		if err := os.Chmod(fallbackDir, 0o755); err != nil {
			t.Fatalf("chmod fallback directory: %v", err)
		}
		_, _, err := Open(ctx, &Option{
			Service:     "service",
			Backends:    []Backend{BackendFilesystem},
			FallbackDir: fallbackDir,
		})
		if !errors.Is(err, ErrInsecureFallback) {
			t.Fatalf("Open() error = %v, want %v", err, ErrInsecureFallback)
		}
	})

	t.Run("context", func(t *testing.T) {
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if _, _, err := Open(canceled); !errors.Is(err, context.Canceled) {
			t.Fatalf("Open() error = %v", err)
		}
	})
}

func TestKeyring(t *testing.T) {
	values := make(map[string][]byte)
	WithNativeOperations(t,
		func(ctx context.Context, service, key string) ([]byte, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			value, ok := values[service+"\x00"+key]
			if !ok {
				return nil, ErrNotFound
			}
			return append([]byte(nil), value...), nil
		},
		func(ctx context.Context, service, key string, value []byte) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			values[service+"\x00"+key] = append([]byte(nil), value...)
			return nil
		},
		func(ctx context.Context, service, key string) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			name := service + "\x00" + key
			if _, ok := values[name]; !ok {
				return ErrNotFound
			}
			delete(values, name)
			return nil
		},
	)
	ctx := context.Background()
	keyring := &Keyring{service: "test"}
	secret := []byte("secret\x00value")
	if err := keyring.Set(ctx, "account", secret); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	got, err := keyring.Get(ctx, "account")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("Get() = %q, want %q", got, secret)
	}
	if err := keyring.Delete(ctx, "account"); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, err := keyring.Get(ctx, "account"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get() error = %v, want %v", err, ErrNotFound)
	}
	if err := keyring.Delete(ctx, "account"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Delete() error = %v, want %v", err, ErrNotFound)
	}

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := keyring.Set(canceled, "account", nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("Set() context error = %v", err)
	}
	if _, err := keyring.Get(canceled, "account"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Get() context error = %v", err)
	}
	if err := keyring.Delete(canceled, "account"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Delete() context error = %v", err)
	}
}
