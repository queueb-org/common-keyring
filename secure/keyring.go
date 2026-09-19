package keyring

import (
	"context"
	"fmt"

	api "common.queueb.org/keyring"
	"common.queueb.org/keyring/internal/backend/native"
	"common.queueb.org/keyring/internal/contract"
	"common.queueb.org/keyring/internal/selection"
)

var getter initializer

func init() {
	getter = &defaultGetter{}
}

// Option configures one [Open] call.
type Option struct {
	// Service namespaces credentials during backend discovery.
	Service string
	// Keyringer bypasses backend discovery when non-nil.
	Keyringer api.Keyringer
	// Backends overrides the default backend order when non-empty.
	Backends []api.Backend
}

type initializer interface {
	Get(context.Context, Option) (api.Keyringer, api.Info, error)
}

type defaultGetter struct{}

func (g *defaultGetter) Get(
	ctx context.Context,
	option Option,
) (api.Keyringer, api.Info, error) {
	order := option.Backends
	if len(order) == 0 && nativeBackendSupported {
		order = []api.Backend{nativeBackendInfo.Backend}
	}
	registry := make(map[api.Backend]selection.BackendOpener)
	if nativeBackendSupported {
		registry[nativeBackendInfo.Backend] = func(context.Context) (api.Keyringer, api.Info, error) {
			return &Keyring{service: option.Service}, nativeBackendInfo, nil
		}
	}
	return selection.SelectBackend(ctx, order, registry)
}

// Keyring delegates [api.Keyringer] operations to the selected native backend.
type Keyring struct {
	service string
}

var _ api.Keyringer = (*Keyring)(nil)

var (
	nativeGet    = native.Get
	nativeSet    = native.Set
	nativeDelete = native.Delete
)

// NewKeyring initializes Keyring.
func NewKeyring(service string) *Keyring {
	return &Keyring{service: service}
}

// Get implements [api.Keyringer].
func (k *Keyring) Get(ctx context.Context, username string) ([]byte, error) {
	return nativeGet(ctx, k.service, username)
}

// Set implements [api.Keyringer].
func (k *Keyring) Set(ctx context.Context, username string, password []byte) error {
	return nativeSet(ctx, k.service, username, password)
}

// Delete implements [api.Keyringer].
func (k *Keyring) Delete(ctx context.Context, username string) error {
	return nativeDelete(ctx, k.service, username)
}

// Open selects a secure credential backend according to options.
// Selection is not repeated automatically if that backend later becomes
// unavailable; operations return their error and the caller may call Open
// again to perform a new selection.
func Open(ctx context.Context, options ...*Option) (api.Keyringer, api.Info, error) {
	if err := contract.ContextError(ctx); err != nil {
		return nil, api.Info{}, err
	}
	option := mergeOptions(options...)
	if option.Keyringer != nil {
		return option.Keyringer, customInfo(), nil
	}
	if option.Service == "" {
		return nil, api.Info{}, fmt.Errorf("%w: service is empty", api.ErrInvalidArgument)
	}
	return getter.Get(ctx, option)
}

func mergeOptions(options ...*Option) Option {
	var merged Option
	for _, option := range options {
		if option.Service != "" {
			merged.Service = option.Service
		}
		if option.Keyringer != nil {
			merged.Keyringer = option.Keyringer
		}
		if len(option.Backends) != 0 {
			merged.Backends = option.Backends
		}
	}
	return merged
}

func customInfo() api.Info {
	return api.Info{
		Backend:     api.BackendCustom,
		Persistence: api.PersistenceUnknown,
		Host:        api.HostUnknown,
		Interaction: api.InteractionUnknown,
	}
}
