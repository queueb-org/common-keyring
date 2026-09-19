//go:build linux && integration

package keyring

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	api "common.queueb.org/keyring"
	"common.queueb.org/keyring/internal/backend/dbus"
	backendkeyctl "common.queueb.org/keyring/internal/backend/keyctl"
	"common.queueb.org/keyring/secure/wsl2"
)

func TestLinuxKeyringIntegration(t *testing.T) {
	expectedError := integrationExpectedKeyctlError(t)
	keyring, err := backendkeyctl.Open(strings.ToLower(t.Name()))
	if integrationKeyctlError(t, "Open", err, expectedError) {
		return
	}
	ctx := context.Background()
	account := "account"
	t.Cleanup(func() { _ = keyring.Delete(ctx, account) })

	if integrationKeyctlError(t, "Set", keyring.Set(ctx, account, []byte("secret")), expectedError) {
		return
	}
	got, err := keyring.Get(ctx, account)
	if integrationKeyctlError(t, "Get", err, expectedError) {
		return
	}
	if string(got) != "secret" {
		t.Fatalf("Get() = %q, want secret", got)
	}
	if integrationKeyctlError(t, "Delete", keyring.Delete(ctx, account), expectedError) {
		return
	}
	if expectedError != nil {
		t.Fatalf("keyctl operations succeeded, want %v", expectedError)
	}
}

func integrationExpectedKeyctlError(t *testing.T) error {
	t.Helper()
	switch value := os.Getenv("KEYRING_TEST_EXPECT_KEYCTL_ERROR"); value {
	case "":
		return nil
	case "permission":
		return api.ErrPermissionDenied
	case "unavailable":
		return api.ErrBackendUnavailable
	default:
		t.Fatalf("unknown KEYRING_TEST_EXPECT_KEYCTL_ERROR value %q", value)
		return nil
	}
}

func integrationKeyctlError(t *testing.T, operation string, err, expected error) bool {
	t.Helper()
	if err == nil {
		return false
	}
	if expected == nil || !errors.Is(err, expected) {
		t.Fatalf("%s() error = %v, want %v", operation, err, expected)
	}
	t.Logf("%s() returned expected %v: %v", operation, expected, err)
	return true
}

func TestLinuxBackendSelectionIntegration(t *testing.T) {
	ctx := context.Background()
	if err := dbus.Probe(ctx); err == nil {
		t.Skip("Secret Service is available in this session")
	} else if !errors.Is(err, api.ErrBackendUnavailable) {
		t.Fatalf("Secret Service probe error = %v", err)
	}

	keyring, info, err := Open(ctx, &Option{
		Service: strings.ToLower(t.Name()),
		Backends: []api.Backend{
			api.BackendSecretService,
			api.BackendKernelKeyring,
		},
	})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if info.Backend != api.BackendKernelKeyring || !info.Fallback ||
		info.Persistence != api.PersistenceSession || len(info.Rejected) != 1 ||
		info.Rejected[0].Backend != api.BackendSecretService ||
		!errors.Is(info.Rejected[0].Err, api.ErrBackendUnavailable) {
		t.Fatalf("Open() info = %#v", info)
	}

	key := "account"
	value := []byte("secret")
	t.Cleanup(func() { _ = keyring.Delete(ctx, key) })
	if err := keyring.Set(ctx, key, value); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	got, err := keyring.Get(ctx, key)
	if err != nil || string(got) != string(value) {
		t.Fatalf("Get() = %q, %v, want %q, nil", got, err, value)
	}
	if err := keyring.Delete(ctx, key); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, err := keyring.Get(ctx, key); !errors.Is(err, api.ErrNotFound) {
		t.Fatalf("Get() after Delete error = %v, want %v", err, api.ErrNotFound)
	}
}

func TestLinuxWSL2MissingHelperFallbackIntegration(t *testing.T) {
	if !wsl2.IsWSL2() {
		t.Skip("requires WSL2")
	}

	ctx := context.Background()
	if err := dbus.Probe(ctx); err == nil {
		t.Skip("requires an unavailable Secret Service provider")
	} else if !errors.Is(err, api.ErrBackendUnavailable) {
		t.Fatalf("Secret Service probe error = %v", err)
	}

	t.Setenv("PATH", t.TempDir())
	keyring, info, err := Open(ctx, &Option{Service: strings.ToLower(t.Name())})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if info.Backend != api.BackendKernelKeyring || !info.Fallback ||
		len(info.Rejected) != 2 ||
		info.Rejected[0].Backend != api.BackendWindowsCredentialManager ||
		!errors.Is(info.Rejected[0].Err, wsl2.ErrHelperNotFound) ||
		info.Rejected[1].Backend != api.BackendSecretService ||
		!errors.Is(info.Rejected[1].Err, api.ErrBackendUnavailable) {
		t.Fatalf("Open() info = %#v", info)
	}

	key := "account"
	value := []byte("secret")
	t.Cleanup(func() { _ = keyring.Delete(ctx, key) })
	if err := keyring.Set(ctx, key, value); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	got, err := keyring.Get(ctx, key)
	if err != nil || string(got) != string(value) {
		t.Fatalf("Get() = %q, %v, want %q, nil", got, err, value)
	}
	if err := keyring.Delete(ctx, key); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, err := keyring.Get(ctx, key); !errors.Is(err, api.ErrNotFound) {
		t.Fatalf("Get() after Delete error = %v, want %v", err, api.ErrNotFound)
	}
}

func TestLinuxWSL2UnexecutableHelperStopsIntegration(t *testing.T) {
	if !wsl2.IsWSL2() {
		t.Skip("requires WSL2")
	}

	dir := t.TempDir()
	helperPath := filepath.Join(dir, "keyring-winbridge.exe")
	if err := os.WriteFile(helperPath, []byte("not a Windows executable\n"), 0o700); err != nil {
		t.Fatalf("write helper fixture: %v", err)
	}
	t.Setenv("PATH", dir)

	keyring, info, err := Open(context.Background(), &Option{Service: strings.ToLower(t.Name())})
	if keyring != nil || !reflect.DeepEqual(info, api.Info{}) {
		t.Fatalf("Open() = %T, %#v, want nil keyring and empty info", keyring, info)
	}
	var selection *api.SelectionError
	if !errors.As(err, &selection) || !errors.Is(err, api.ErrBackendFailure) ||
		errors.Is(err, api.ErrBackendUnavailable) ||
		len(selection.Rejected) != 1 ||
		selection.Rejected[0].Backend != api.BackendWindowsCredentialManager ||
		!errors.Is(selection.Rejected[0].Err, wsl2.ErrBackendFailure) ||
		errors.Is(selection.Rejected[0].Err, wsl2.ErrHelperNotFound) {
		t.Fatalf("Open() error = %#v", err)
	}
}
