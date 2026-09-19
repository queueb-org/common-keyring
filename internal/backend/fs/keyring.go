package fs

import (
	"context"
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"sync"

	"common.queueb.org/keyring/internal/contract"
)

const mutationLockCount = 64

type storage interface {
	get(string) ([]byte, error)
	set(string, []byte) error
	delete(string) error
}

// Keyring stores secret values in a filesystem directory.
//
// Values are plaintext unless the underlying volume provides encryption.
// A Keyring is safe for concurrent use, but must not be copied after first use.
type Keyring struct {
	storage storage
	locks   [mutationLockCount]sync.Mutex
}

var _ contract.Keyringer = (*Keyring)(nil)

type absolutePathFunc func(string) (string, error)
type storageOpener func(string, layout) (storage, error)

// Open validates rootDir and initializes filesystem storage for service.
// Missing managed directories are created with mode 0700. Existing managed
// directories must belong to the effective user, must not grant group or other
// access, and must not be symbolic links.
//
// Linux is the supported implementation for the initial release. Other
// platforms return errors matching both [contract.ErrInsecureFallback] and
// [contract.ErrUnsupported].
func Open(rootDir, service string) (*Keyring, error) {
	return openKeyring(rootDir, service, filepath.Abs, openStorage)
}

func openKeyring(
	rootDir string,
	service string,
	absolutePath absolutePathFunc,
	opener storageOpener,
) (*Keyring, error) {
	if rootDir == "" {
		return nil, fmt.Errorf("%w: root directory is empty", contract.ErrInvalidArgument)
	}
	if service == "" {
		return nil, fmt.Errorf("%w: service is empty", contract.ErrInvalidArgument)
	}

	rootDir, err := absolutePath(rootDir)
	if err != nil {
		return nil, fmt.Errorf("%w: resolve root directory: %w", contract.ErrInvalidArgument, err)
	}
	storage, err := opener(rootDir, newLayout(service))
	if err != nil {
		return nil, err
	}
	return &Keyring{storage: storage}, nil
}

// Get implements [contract.Keyringer].
func (k *Keyring) Get(ctx context.Context, key string) ([]byte, error) {
	if err := validateOperation(ctx, key); err != nil {
		return nil, err
	}
	return k.storage.get(key)
}

// Set implements [contract.Keyringer].
func (k *Keyring) Set(ctx context.Context, key string, value []byte) error {
	if err := validateOperation(ctx, key); err != nil {
		return err
	}
	lock := k.mutationLock(key)
	lock.Lock()
	defer lock.Unlock()
	return k.storage.set(key, value)
}

// Delete implements [contract.Keyringer].
func (k *Keyring) Delete(ctx context.Context, key string) error {
	if err := validateOperation(ctx, key); err != nil {
		return err
	}
	lock := k.mutationLock(key)
	lock.Lock()
	defer lock.Unlock()
	return k.storage.delete(key)
}

func validateOperation(ctx context.Context, key string) error {
	if err := contract.ContextError(ctx); err != nil {
		return err
	}
	if key == "" {
		return fmt.Errorf("%w: key is empty", contract.ErrInvalidArgument)
	}
	return nil
}

func (k *Keyring) mutationLock(key string) *sync.Mutex {
	digest := sha256.Sum256([]byte(keyDomain + key))
	return &k.locks[int(digest[0])%len(k.locks)]
}
