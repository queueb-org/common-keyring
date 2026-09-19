//go:build darwin

package native

import (
	"context"

	"common.queueb.org/keyring/internal/backend/darwin"
)

// Keep the Keychain operations behind variables intentionally: tests replace
// these functions to exercise the macOS adapter without accessing a live
// Keychain. Direct calls to darwin.Get, darwin.Set, and darwin.Delete would
// remove that test seam.
var (
	keychainGet    = darwin.Get
	keychainSet    = darwin.Set
	keychainDelete = darwin.Delete
)

// Get reads from macOS Keychain.
func Get(ctx context.Context, service, key string) ([]byte, error) {
	return keychainGet(ctx, service, key)
}

// Set writes to macOS Keychain.
func Set(ctx context.Context, service, key string, value []byte) error {
	return keychainSet(ctx, service, key, value)
}

// Delete removes a value from macOS Keychain.
func Delete(ctx context.Context, service, key string) error {
	return keychainDelete(ctx, service, key)
}
