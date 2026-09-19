//go:build linux && integration

package wsl2

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"

	api "common.queueb.org/keyring"
)

func TestIntegrationProbe(t *testing.T) {
	keyring, err := New(context.Background(), "common.queueb.org/keyring/integration-test")
	if errors.Is(err, ErrNotWSL2) {
		t.Skip("not running inside WSL2")
	}
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if keyring == nil {
		t.Fatal("New() returned nil")
	}
}

func TestIntegrationCRUD(t *testing.T) {
	ctx := context.Background()
	keyring, err := New(ctx, "common.queueb.org/keyring/integration-test")
	if errors.Is(err, ErrNotWSL2) {
		t.Skip("not running inside WSL2")
	}
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	account := "test-" + integrationRandomHex(t, 8)
	password := "secret-" + integrationRandomHex(t, 32)
	t.Cleanup(func() {
		_ = keyring.Delete(ctx, account)
	})

	if _, err := keyring.Get(ctx, account); !errors.Is(err, api.ErrNotFound) {
		t.Fatalf("initial Get() error = %v, want %v", err, api.ErrNotFound)
	}
	if err := keyring.Set(ctx, account, []byte(password)); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	got, err := keyring.Get(ctx, account)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if string(got) != password {
		t.Fatal("Get() returned a different secret")
	}
	if err := keyring.Delete(ctx, account); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, err := keyring.Get(ctx, account); !errors.Is(err, api.ErrNotFound) {
		t.Fatalf("final Get() error = %v, want %v", err, api.ErrNotFound)
	}
}

func integrationRandomHex(t *testing.T, size int) string {
	t.Helper()
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		t.Fatalf("rand.Read() error = %v", err)
	}
	return hex.EncodeToString(value)
}
