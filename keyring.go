package keyring

import (
	"context"
	"fmt"

	backendfs "common.queueb.org/keyring/internal/backend/fs"
	"common.queueb.org/keyring/internal/backend/native"
	"common.queueb.org/keyring/internal/contract"
	"common.queueb.org/keyring/internal/selection"
)

// Keyring delegates [Keyringer] operations to the current platform's native
// credential store.
type Keyring struct {
	service string
}

var _ Keyringer = (*Keyring)(nil)

var (
	nativeGet    = native.Get
	nativeSet    = native.Set
	nativeDelete = native.Delete
)

// Set implements [Keyringer].
func (k *Keyring) Set(ctx context.Context, key string, contents []byte) error {
	return nativeSet(ctx, k.service, key, contents)
}

// Get implements [Keyringer].
func (k *Keyring) Get(ctx context.Context, key string) ([]byte, error) {
	return nativeGet(ctx, k.service, key)
}

// Delete implements [Keyringer].
func (k *Keyring) Delete(ctx context.Context, key string) error {
	return nativeDelete(ctx, k.service, key)
}

// Open selects a credential backend according to options.
// Selection is not repeated automatically if that backend later becomes
// unavailable; operations return their error and the caller may call Open
// again to perform a new selection.
func Open(ctx context.Context, options ...*Option) (Keyringer, Info, error) {
	if err := contract.ContextError(ctx); err != nil {
		return nil, Info{}, err
	}
	option := mergeOptions(options...)
	if option.Keyringer != nil {
		return option.Keyringer, customInfo(), nil
	}
	if option.Service == "" {
		return nil, Info{}, fmt.Errorf("%w: service is empty", ErrInvalidArgument)
	}

	order := option.Backends
	if len(order) == 0 {
		if nativeBackendSupported {
			order = append(order, nativeBackendInfo.Backend)
		}
		if option.FallbackDir != "" {
			order = append(order, BackendFilesystem)
		}
	}

	registry := map[Backend]selection.BackendOpener{
		BackendFilesystem: func(context.Context) (Keyringer, Info, error) {
			if option.FallbackDir == "" {
				return nil, Info{}, fmt.Errorf(
					"%w: filesystem fallback directory is empty",
					ErrInvalidArgument,
				)
			}
			keyring, err := backendfs.Open(option.FallbackDir, option.Service)
			if err != nil {
				return nil, Info{}, err
			}
			return keyring, Info{
				Backend:     BackendFilesystem,
				Persistence: PersistencePersistent,
				Host:        HostCurrent,
				Interaction: InteractionNone,
				Fallback:    true,
			}, nil
		},
	}
	if nativeBackendSupported {
		registry[nativeBackendInfo.Backend] = func(ctx context.Context) (Keyringer, Info, error) {
			if err := probeNativeBackend(ctx); err != nil {
				return nil, Info{}, err
			}
			return &Keyring{service: option.Service}, nativeBackendInfo, nil
		}
	}
	return selection.SelectBackend(ctx, order, registry)
}

func customInfo() Info {
	return Info{
		Backend:     BackendCustom,
		Persistence: PersistenceUnknown,
		Host:        HostUnknown,
		Interaction: InteractionUnknown,
	}
}
