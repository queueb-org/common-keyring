//go:build windows

package native

import (
	"context"

	windowsbackend "common.queueb.org/keyring/internal/backend/windows"
)

// Keep the Windows Credential Manager operations behind variables
// intentionally: tests replace these functions to exercise the Windows
// adapter without accessing the live credential store.
var (
	windowsGet    = windowsbackend.Get
	windowsSet    = windowsbackend.Set
	windowsDelete = windowsbackend.Delete
)

// Get reads from Windows Credential Manager.
func Get(ctx context.Context, service, key string) ([]byte, error) {
	return windowsGet(ctx, service, key)
}

// Set writes to Windows Credential Manager.
func Set(ctx context.Context, service, key string, value []byte) error {
	return windowsSet(ctx, service, key, value)
}

// Delete removes a value from Windows Credential Manager.
func Delete(ctx context.Context, service, key string) error {
	return windowsDelete(ctx, service, key)
}
