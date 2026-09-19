//go:build linux

package native

import (
	"context"

	"common.queueb.org/keyring/internal/backend/dbus"
)

// Keep the D-Bus operations behind variables intentionally: tests replace
// these functions to exercise the Linux adapter without accessing a live
// D-Bus session. Direct calls to dbus.Get, dbus.Set, and dbus.Delete would
// remove that test seam.
var (
	dbusGet    = dbus.Get
	dbusSet    = dbus.Set
	dbusDelete = dbus.Delete
)

// Get reads from Linux Secret Service.
func Get(ctx context.Context, service, key string) ([]byte, error) {
	return dbusGet(ctx, service, key)
}

// Set writes to Linux Secret Service.
func Set(ctx context.Context, service, key string, value []byte) error {
	return dbusSet(ctx, service, key, value)
}

// Delete removes a value from Linux Secret Service.
func Delete(ctx context.Context, service, key string) error {
	return dbusDelete(ctx, service, key)
}
