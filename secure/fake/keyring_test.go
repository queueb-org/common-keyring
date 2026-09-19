package fake

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"

	api "common.queueb.org/keyring"
)

func TestKeyring(t *testing.T) {
	ctx := context.Background()

	t.Run("separates usernames", func(t *testing.T) {
		keyring := &Keyring{}
		if err := keyring.Set(ctx, "alice", []byte("alice-secret")); err != nil {
			t.Fatalf("Set(alice) error = %v", err)
		}
		if err := keyring.Set(ctx, "bob", []byte("bob-secret")); err != nil {
			t.Fatalf("Set(bob) error = %v", err)
		}
		for username, want := range map[string][]byte{
			"alice": []byte("alice-secret"),
			"bob":   []byte("bob-secret"),
		} {
			got, err := keyring.Get(ctx, username)
			if err != nil {
				t.Fatalf("Get(%q) error = %v", username, err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("Get(%q) = %q, want %q", username, got, want)
			}
		}
	})

	t.Run("separates services", func(t *testing.T) {
		keyring := &Keyring{Service: "first"}
		if err := keyring.Set(ctx, "account", []byte("first-secret")); err != nil {
			t.Fatalf("Set(first) error = %v", err)
		}
		keyring.Service = "second"
		if err := keyring.Set(ctx, "account", []byte("second-secret")); err != nil {
			t.Fatalf("Set(second) error = %v", err)
		}
		for service, want := range map[string][]byte{
			"first":  []byte("first-secret"),
			"second": []byte("second-secret"),
		} {
			keyring.Service = service
			got, err := keyring.Get(ctx, "account")
			if err != nil {
				t.Fatalf("Get(%q) error = %v", service, err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("Get(%q) = %q, want %q", service, got, want)
			}
		}
	})

	t.Run("overwrites and copies values", func(t *testing.T) {
		keyring := &Keyring{}
		value := []byte("old")
		if err := keyring.Set(ctx, "account", value); err != nil {
			t.Fatalf("Set(old) error = %v", err)
		}
		value[0] = 'X'
		if err := keyring.Set(ctx, "account", []byte("new")); err != nil {
			t.Fatalf("Set(new) error = %v", err)
		}
		got, err := keyring.Get(ctx, "account")
		if err != nil {
			t.Fatalf("Get() error = %v", err)
		}
		got[0] = 'X'
		again, err := keyring.Get(ctx, "account")
		if err != nil || string(again) != "new" {
			t.Fatalf("second Get() = %q, %v", again, err)
		}
	})

	t.Run("missing", func(t *testing.T) {
		keyring := &Keyring{}
		if _, err := keyring.Get(ctx, "missing"); !errors.Is(err, api.ErrNotFound) {
			t.Fatalf("Get() error = %v, want %v", err, api.ErrNotFound)
		}
		if err := keyring.Delete(ctx, "missing"); !errors.Is(err, api.ErrNotFound) {
			t.Fatalf("Delete() error = %v, want %v", err, api.ErrNotFound)
		}
	})

	t.Run("delete", func(t *testing.T) {
		keyring := &Keyring{}
		if err := keyring.Set(ctx, "account", []byte("secret")); err != nil {
			t.Fatalf("Set() error = %v", err)
		}
		if err := keyring.Delete(ctx, "account"); err != nil {
			t.Fatalf("Delete() error = %v", err)
		}
		if _, err := keyring.Get(ctx, "account"); !errors.Is(err, api.ErrNotFound) {
			t.Fatalf("Get() after Delete error = %v, want %v", err, api.ErrNotFound)
		}
	})

	t.Run("injected error does not mutate storage", func(t *testing.T) {
		injected := errors.New("injected")
		keyring := &Keyring{Err: injected}
		if err := keyring.Set(ctx, "account", []byte("secret")); !errors.Is(err, injected) {
			t.Fatalf("Set() error = %v, want %v", err, injected)
		}
		keyring.Err = nil
		if _, err := keyring.Get(ctx, "account"); !errors.Is(err, api.ErrNotFound) {
			t.Fatalf("Get() after failed Set error = %v", err)
		}
		if err := keyring.Set(ctx, "account", []byte("secret")); err != nil {
			t.Fatalf("Set() error = %v", err)
		}
		keyring.Err = injected
		if _, err := keyring.Get(ctx, "account"); !errors.Is(err, injected) {
			t.Fatalf("Get() error = %v, want %v", err, injected)
		}
		if err := keyring.Delete(ctx, "account"); !errors.Is(err, injected) {
			t.Fatalf("Delete() error = %v, want %v", err, injected)
		}
		keyring.Err = nil
		got, err := keyring.Get(ctx, "account")
		if err != nil || string(got) != "secret" {
			t.Fatalf("Get() after failed Delete = %q, %v", got, err)
		}
	})

	t.Run("context", func(t *testing.T) {
		keyring := &Keyring{}
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := keyring.Get(canceled, "account"); !errors.Is(err, context.Canceled) {
			t.Fatalf("Get() error = %v", err)
		}
		if err := keyring.Set(canceled, "account", nil); !errors.Is(err, context.Canceled) {
			t.Fatalf("Set() error = %v", err)
		}
		if err := keyring.Delete(canceled, "account"); !errors.Is(err, context.Canceled) {
			t.Fatalf("Delete() error = %v", err)
		}
	})
}

func TestKeyringConcurrent(t *testing.T) {
	keyring := &Keyring{}
	for index := range 16 {
		username := fmt.Sprintf("account-%d", index)
		t.Run(username, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			if err := keyring.Set(ctx, username, []byte("secret")); err != nil {
				t.Fatalf("Set() error = %v", err)
			}
			got, err := keyring.Get(ctx, username)
			if err != nil || string(got) != "secret" {
				t.Fatalf("Get() = %q, %v", got, err)
			}
			if err := keyring.Delete(ctx, username); err != nil {
				t.Fatalf("Delete() error = %v", err)
			}
		})
	}
}
