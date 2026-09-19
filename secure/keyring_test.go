package keyring

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"

	api "common.queueb.org/keyring"
)

type testKeyringer struct{}

func (*testKeyringer) Get(context.Context, string) ([]byte, error) { return nil, nil }
func (*testKeyringer) Set(context.Context, string, []byte) error   { return nil }
func (*testKeyringer) Delete(context.Context, string) error        { return nil }

type fakeGetter struct {
	Keyringer api.Keyringer
	Info      api.Info
	Err       error
	Option    Option
}

func (f *fakeGetter) Get(
	_ context.Context,
	option Option,
) (api.Keyringer, api.Info, error) {
	f.Option = option
	return f.Keyringer, f.Info, f.Err
}

// WithGetter overrides secure backend discovery for one test and restores the
// original initializer during cleanup. It mutates package state and must not be
// used by parallel tests.
func WithGetter(t *testing.T, override initializer) {
	t.Helper()
	original := getter
	getter = override
	t.Cleanup(func() { getter = original })
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

func TestDefaultGetter(t *testing.T) {
	keyring, info, err := (&defaultGetter{}).Get(context.Background(), Option{Service: "service"})
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got, ok := keyring.(*Keyring); !ok || got.service != "service" {
		t.Fatalf("Get() keyring = %#v", keyring)
	}
	if !reflect.DeepEqual(info, nativeBackendInfo) {
		t.Fatalf("Get() info = %#v, want %#v", info, nativeBackendInfo)
	}
}

func TestOpen(t *testing.T) {
	ctx := context.Background()

	t.Run("injected overlay", func(t *testing.T) {
		injected := &testKeyringer{}
		WithGetter(t, &fakeGetter{Err: errors.New("must not be called")})
		keyring, info, err := Open(ctx,
			&Option{Service: "first", Keyringer: injected},
			&Option{},
		)
		if err != nil {
			t.Fatalf("Open() error = %v", err)
		}
		if keyring != injected {
			t.Fatalf("Open() keyring = %T", keyring)
		}
		want := api.Info{
			Backend:     api.BackendCustom,
			Persistence: api.PersistenceUnknown,
			Host:        api.HostUnknown,
			Interaction: api.InteractionUnknown,
		}
		if !reflect.DeepEqual(info, want) {
			t.Fatalf("Open() info = %#v, want %#v", info, want)
		}
	})

	t.Run("missing service", func(t *testing.T) {
		if _, _, err := Open(ctx); !errors.Is(err, api.ErrInvalidArgument) {
			t.Fatalf("Open() error = %v, want %v", err, api.ErrInvalidArgument)
		}
	})

	t.Run("discovery", func(t *testing.T) {
		expectedKeyring := &testKeyringer{}
		expectedInfo := api.Info{Backend: api.BackendKernelKeyring}
		discovery := &fakeGetter{Keyringer: expectedKeyring, Info: expectedInfo}
		WithGetter(t, discovery)
		keyring, info, err := Open(ctx,
			&Option{Service: "first", Backends: []api.Backend{api.BackendSecretService}},
			&Option{Service: "last", Backends: []api.Backend{api.BackendKernelKeyring}},
		)
		if err != nil {
			t.Fatalf("Open() error = %v", err)
		}
		if discovery.Option.Service != "last" ||
			!reflect.DeepEqual(discovery.Option.Backends, []api.Backend{api.BackendKernelKeyring}) ||
			keyring != expectedKeyring || !reflect.DeepEqual(info, expectedInfo) {
			t.Fatalf("Open() = %#v, %T, %#v", discovery.Option, keyring, info)
		}
	})

	t.Run("discovery error", func(t *testing.T) {
		expected := errors.New("discovery")
		WithGetter(t, &fakeGetter{Err: expected})
		if _, _, err := Open(ctx, &Option{Service: "service"}); !errors.Is(err, expected) {
			t.Fatalf("Open() error = %v, want %v", err, expected)
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
				return nil, api.ErrNotFound
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
				return api.ErrNotFound
			}
			delete(values, name)
			return nil
		},
	)
	ctx := context.Background()
	keyring := NewKeyring("service")
	secret := []byte("secret\x00value")
	if err := keyring.Set(ctx, "account", secret); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	got, err := keyring.Get(ctx, "account")
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("Get() = %q, %v", got, err)
	}
	if err := keyring.Delete(ctx, "account"); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, err := keyring.Get(ctx, "account"); !errors.Is(err, api.ErrNotFound) {
		t.Fatalf("Get() error = %v, want %v", err, api.ErrNotFound)
	}
	if err := keyring.Delete(ctx, "account"); !errors.Is(err, api.ErrNotFound) {
		t.Fatalf("Delete() error = %v, want %v", err, api.ErrNotFound)
	}

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := keyring.Get(canceled, "account"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Get() context error = %v", err)
	}
	if err := keyring.Set(canceled, "account", nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("Set() context error = %v", err)
	}
	if err := keyring.Delete(canceled, "account"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Delete() context error = %v", err)
	}
}
