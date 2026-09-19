package fs

import (
	"context"

	keyring "common.queueb.org/keyring"
	backendfs "common.queueb.org/keyring/internal/backend/fs"
)

// Keyring stores secret values in a filesystem directory.
//
// Values are plaintext unless the underlying volume provides encryption.
// A Keyring is safe for concurrent use, but must not be copied after first use.
type Keyring struct {
	backend *backendfs.Keyring
}

var _ keyring.Keyringer = (*Keyring)(nil)

// Open validates rootDir and initializes filesystem storage for service.
// Missing managed directories are created with mode 0700. Existing managed
// directories must belong to the effective user, must not grant group or other
// access, and must not be symbolic links.
//
// Linux is the supported implementation for the initial release. Other
// platforms return errors matching both [keyring.ErrInsecureFallback] and
// [keyring.ErrUnsupported].
func Open(rootDir, service string) (*Keyring, error) {
	backend, err := backendfs.Open(rootDir, service)
	if err != nil {
		return nil, err
	}
	return &Keyring{backend: backend}, nil
}

// Get implements [keyring.Keyringer].
func (k *Keyring) Get(ctx context.Context, key string) ([]byte, error) {
	return k.backend.Get(ctx, key)
}

// Set implements [keyring.Keyringer].
func (k *Keyring) Set(ctx context.Context, key string, value []byte) error {
	return k.backend.Set(ctx, key, value)
}

// Delete implements [keyring.Keyringer].
func (k *Keyring) Delete(ctx context.Context, key string) error {
	return k.backend.Delete(ctx, key)
}
