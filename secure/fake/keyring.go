package fake

import (
	"context"
	"sync"

	api "common.queueb.org/keyring"
	"common.queueb.org/keyring/internal/contract"
)

// Keyring implements [api.Keyringer] for testing purposes.
type Keyring struct {
	// Err forces operations to fail without mutating stored credentials.
	Err error
	// Service namespaces credentials. An empty value defaults to "fake".
	Service string
	storage map[entry][]byte

	mu sync.RWMutex
}

type entry struct {
	service  string
	username string
}

var _ api.Keyringer = (*Keyring)(nil)

func (k *Keyring) init() {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.storage == nil {
		k.storage = make(map[entry][]byte)
	}
	if k.Service == "" {
		k.Service = "fake"
	}
}

// key builds a unique service and username pair.
func (k *Keyring) key(username string) entry {
	return entry{service: k.Service, username: username}
}

// Get implements [api.Keyringer], gets password for the given username, if
// internal Err is set, returns it also.
func (k *Keyring) Get(ctx context.Context, username string) ([]byte, error) {
	if err := contract.ContextError(ctx); err != nil {
		return nil, err
	}
	k.init()
	k.mu.RLock()
	defer k.mu.RUnlock()

	if k.Err != nil {
		return nil, k.Err
	}

	password, ok := k.storage[k.key(username)]
	if !ok {
		return nil, api.ErrNotFound
	}
	return append([]byte(nil), password...), nil
}

// Set implements [api.Keyringer], sets password for the given username to the storage.
func (k *Keyring) Set(ctx context.Context, username string, password []byte) error {
	if err := contract.ContextError(ctx); err != nil {
		return err
	}
	k.init()
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.Err != nil {
		return k.Err
	}
	k.storage[k.key(username)] = append([]byte(nil), password...)
	return nil
}

// Delete implements [api.Keyringer].
func (k *Keyring) Delete(ctx context.Context, username string) error {
	if err := contract.ContextError(ctx); err != nil {
		return err
	}
	k.init()
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.Err != nil {
		return k.Err
	}
	if _, found := k.storage[k.key(username)]; !found {
		return api.ErrNotFound
	}
	delete(k.storage, k.key(username))
	return nil
}
