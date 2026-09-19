//go:build linux

package keyring

import (
	"context"
	"errors"
	"reflect"
	"testing"

	api "common.queueb.org/keyring"
	backendkeyctl "common.queueb.org/keyring/internal/backend/keyctl"
	"common.queueb.org/keyring/secure/wsl2"
)

// WithSecretServiceProbe overrides the Secret Service availability probe for
// one test and restores it during cleanup. It mutates package state and must
// not be used by parallel tests.
func WithSecretServiceProbe(t *testing.T, override secretServiceProbeFunc) {
	t.Helper()
	original := probeSecretService
	probeSecretService = override
	t.Cleanup(func() { probeSecretService = original })
}

// WithKernelKeyring overrides kernel keyring initialization for one test and
// restores it during cleanup. It mutates package state and must not be used by
// parallel tests.
func WithKernelKeyring(
	t *testing.T,
	override kernelKeyringOpener,
) {
	t.Helper()
	original := openKernelKeyring
	openKernelKeyring = override
	t.Cleanup(func() { openKernelKeyring = original })
}

// WithWSL2 overrides WSL2 detection and initialization for one test and
// restores both during cleanup. It mutates package state and must not be used
// by parallel tests.
func WithWSL2(t *testing.T, detected bool, initializer wsl2InitializerFunc) {
	t.Helper()
	originalDetector := wsl2.IsWSL2
	originalInitializer := initializeWSL2
	wsl2.IsWSL2 = func() bool { return detected }
	initializeWSL2 = initializer
	t.Cleanup(func() {
		wsl2.IsWSL2 = originalDetector
		initializeWSL2 = originalInitializer
	})
}

func TestLinuxGetter(t *testing.T) {
	ctx := context.Background()

	t.Run("WSL2 bridge", func(t *testing.T) {
		expected := &testKeyringer{}
		WithWSL2(t, true, func(_ context.Context, service string) (api.Keyringer, error) {
			if service != "service" {
				t.Fatalf("service = %q", service)
			}
			return expected, nil
		})
		WithSecretServiceProbe(t, func(context.Context) error {
			t.Fatal("D-Bus fallback was called")
			return nil
		})
		keyring, info, err := (&linuxGetter{}).Get(ctx, Option{Service: "service"})
		if err != nil || keyring != expected {
			t.Fatalf("Get() = %T, %#v, %v", keyring, info, err)
		}
		want := api.Info{
			Backend:     api.BackendWindowsCredentialManager,
			Persistence: api.PersistencePersistent,
			Host:        api.HostWindows,
			Interaction: api.InteractionNone,
		}
		if !reflect.DeepEqual(info, want) {
			t.Fatalf("Get() info = %#v, want %#v", info, want)
		}
	})

	t.Run("WSL2 helper missing falls back to D-Bus", func(t *testing.T) {
		WithWSL2(t, true, func(context.Context, string) (api.Keyringer, error) {
			return nil, errors.Join(api.ErrBackendUnavailable, wsl2.ErrHelperNotFound)
		})
		WithSecretServiceProbe(t, func(context.Context) error { return nil })
		keyring, info, err := (&linuxGetter{}).Get(ctx, Option{Service: "service"})
		if err != nil {
			t.Fatalf("Get() error = %v", err)
		}
		if _, ok := keyring.(*Keyring); !ok || !info.Fallback ||
			info.Backend != api.BackendSecretService {
			t.Fatalf("Get() = %T, %#v", keyring, info)
		}
		if len(info.Rejected) != 1 ||
			info.Rejected[0].Backend != api.BackendWindowsCredentialManager ||
			!errors.Is(info.Rejected[0].Err, wsl2.ErrHelperNotFound) {
			t.Fatalf("Get() rejected = %#v", info.Rejected)
		}
	})

	t.Run("WSL2 not applicable falls back to kernel", func(t *testing.T) {
		WithWSL2(t, true, func(context.Context, string) (api.Keyringer, error) {
			return nil, errors.Join(api.ErrUnsupported, wsl2.ErrNotWSL2)
		})
		WithSecretServiceProbe(t, func(context.Context) error { return api.ErrBackendUnavailable })
		WithKernelKeyring(t, func(service string) (*backendkeyctl.Keyring, error) {
			if service != "service" {
				t.Fatalf("service = %q", service)
			}
			return new(backendkeyctl.Keyring), nil
		})
		keyring, info, err := (&linuxGetter{}).Get(ctx, Option{Service: "service"})
		if err != nil {
			t.Fatalf("Get() error = %v", err)
		}
		if _, ok := keyring.(*backendkeyctl.Keyring); !ok || !info.Fallback ||
			info.Backend != api.BackendKernelKeyring {
			t.Fatalf("Get() = %T, %#v", keyring, info)
		}
		if len(info.Rejected) != 2 {
			t.Fatalf("Get() rejected = %#v", info.Rejected)
		}
	})

	t.Run("WSL2 stopper", func(t *testing.T) {
		WithWSL2(t, true, func(context.Context, string) (api.Keyringer, error) {
			return nil, wsl2.ErrTimeout
		})
		WithSecretServiceProbe(t, func(context.Context) error {
			t.Fatal("D-Bus fallback was called")
			return nil
		})
		_, _, err := (&linuxGetter{}).Get(ctx, Option{Service: "service"})
		if !errors.Is(err, wsl2.ErrTimeout) {
			t.Fatalf("Get() error = %v, want %v", err, wsl2.ErrTimeout)
		}
	})

	t.Run("native D-Bus", func(t *testing.T) {
		WithWSL2(t, false, nil)
		WithSecretServiceProbe(t, func(context.Context) error { return nil })
		keyring, info, err := (&linuxGetter{}).Get(ctx, Option{Service: "service"})
		if err != nil {
			t.Fatalf("Get() error = %v", err)
		}
		if _, ok := keyring.(*Keyring); !ok || info.Fallback ||
			info.Backend != api.BackendSecretService {
			t.Fatalf("Get() = %T, %#v", keyring, info)
		}
	})

	t.Run("native kernel fallback", func(t *testing.T) {
		WithWSL2(t, false, nil)
		WithSecretServiceProbe(t, func(context.Context) error { return api.ErrBackendUnavailable })
		WithKernelKeyring(t, func(string) (*backendkeyctl.Keyring, error) {
			return new(backendkeyctl.Keyring), nil
		})
		keyring, info, err := (&linuxGetter{}).Get(ctx, Option{Service: "service"})
		if err != nil {
			t.Fatalf("Get() error = %v", err)
		}
		if _, ok := keyring.(*backendkeyctl.Keyring); !ok || !info.Fallback ||
			info.Persistence != api.PersistenceSession {
			t.Fatalf("Get() = %T, %#v", keyring, info)
		}
	})

	t.Run("explicit kernel order", func(t *testing.T) {
		WithWSL2(t, true, func(context.Context, string) (api.Keyringer, error) {
			t.Fatal("WSL2 initializer was called")
			return nil, nil
		})
		WithSecretServiceProbe(t, func(context.Context) error {
			t.Fatal("D-Bus probe was called")
			return nil
		})
		WithKernelKeyring(t, func(string) (*backendkeyctl.Keyring, error) {
			return new(backendkeyctl.Keyring), nil
		})
		keyring, info, err := (&linuxGetter{}).Get(ctx, Option{
			Service:  "service",
			Backends: []api.Backend{api.BackendKernelKeyring},
		})
		if err != nil {
			t.Fatalf("Get() error = %v", err)
		}
		if _, ok := keyring.(*backendkeyctl.Keyring); !ok || info.Fallback || len(info.Rejected) != 0 {
			t.Fatalf("Get() = %T, %#v", keyring, info)
		}
	})

	t.Run("terminal D-Bus failure", func(t *testing.T) {
		WithWSL2(t, false, nil)
		WithSecretServiceProbe(t, func(context.Context) error { return api.ErrPermissionDenied })
		WithKernelKeyring(t, func(string) (*backendkeyctl.Keyring, error) {
			t.Fatal("kernel fallback was called")
			return nil, nil
		})
		_, _, err := (&linuxGetter{}).Get(ctx, Option{Service: "service"})
		var selection *api.SelectionError
		if !errors.As(err, &selection) || !errors.Is(err, api.ErrPermissionDenied) ||
			len(selection.Rejected) != 1 {
			t.Fatalf("Get() error = %#v", err)
		}
	})

	t.Run("unavailable", func(t *testing.T) {
		WithWSL2(t, false, nil)
		WithSecretServiceProbe(t, func(context.Context) error { return api.ErrBackendUnavailable })
		WithKernelKeyring(t, func(string) (*backendkeyctl.Keyring, error) {
			return nil, api.ErrBackendUnavailable
		})
		if _, _, err := (&linuxGetter{}).Get(ctx, Option{Service: "service"}); !errors.Is(err, api.ErrBackendUnavailable) {
			t.Fatalf("Get() error = %v, want %v", err, api.ErrBackendUnavailable)
		}
	})

	t.Run("context", func(t *testing.T) {
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if _, _, err := (&linuxGetter{}).Get(canceled, Option{Service: "service"}); !errors.Is(err, context.Canceled) {
			t.Fatalf("Get() error = %v", err)
		}
	})
}

func TestInitializeWSL2(t *testing.T) {
	originalDetector := wsl2.IsWSL2
	wsl2.IsWSL2 = func() bool { return false }
	t.Cleanup(func() { wsl2.IsWSL2 = originalDetector })
	if _, err := initializeWSL2(context.Background(), "service"); !errors.Is(err, wsl2.ErrNotWSL2) {
		t.Fatalf("initializeWSL2() error = %v, want %v", err, wsl2.ErrNotWSL2)
	}
}
