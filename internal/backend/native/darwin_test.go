//go:build darwin

package native

import (
	"bytes"
	"context"
	"testing"
)

// WithKeychainOperations overrides macOS Keychain operations for one test and
// restores them during cleanup. It mutates package state and must not be used
// by parallel tests.
func WithKeychainOperations(
	t *testing.T,
	get func(context.Context, string, string) ([]byte, error),
	set func(context.Context, string, string, []byte) error,
	delete func(context.Context, string, string) error,
) {
	t.Helper()
	originalGet := keychainGet
	originalSet := keychainSet
	originalDelete := keychainDelete
	keychainGet = get
	keychainSet = set
	keychainDelete = delete
	t.Cleanup(func() {
		keychainGet = originalGet
		keychainSet = originalSet
		keychainDelete = originalDelete
	})
}

func TestNativeKeychainOperations(t *testing.T) {
	ctx := context.Background()
	want := []byte("secret")
	WithKeychainOperations(t,
		func(gotCtx context.Context, service, key string) ([]byte, error) {
			if gotCtx != ctx || service != "service" || key != "key" {
				t.Fatalf("Get() = %v, %q, %q", gotCtx, service, key)
			}
			return want, nil
		},
		func(gotCtx context.Context, service, key string, value []byte) error {
			if gotCtx != ctx || service != "service" || key != "key" || !bytes.Equal(value, want) {
				t.Fatalf("Set() = %v, %q, %q, %q", gotCtx, service, key, value)
			}
			return nil
		},
		func(gotCtx context.Context, service, key string) error {
			if gotCtx != ctx || service != "service" || key != "key" {
				t.Fatalf("Delete() = %v, %q, %q", gotCtx, service, key)
			}
			return nil
		},
	)

	got, err := Get(ctx, "service", "key")
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("Get() = %q, %v", got, err)
	}
	if err := Set(ctx, "service", "key", want); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	if err := Delete(ctx, "service", "key"); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
}
