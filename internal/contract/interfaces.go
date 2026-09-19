package contract

import "context"

// Keyringer is the canonical interface for credential storage operations.
// Implementations are safe for concurrent use.
type Keyringer interface {
	// Get returns the value stored for key.
	// A missing key returns an error matching [ErrNotFound].
	Get(ctx context.Context, key string) ([]byte, error)
	// Set stores value for key, replacing an existing value.
	Set(ctx context.Context, key string, value []byte) error
	// Delete removes key.
	// A missing key returns an error matching [ErrNotFound].
	Delete(ctx context.Context, key string) error
}
