//go:build linux

package keyring

import (
	"context"

	api "common.queueb.org/keyring"
	"common.queueb.org/keyring/internal/backend/dbus"
	backendkeyctl "common.queueb.org/keyring/internal/backend/keyctl"
	"common.queueb.org/keyring/internal/selection"
	"common.queueb.org/keyring/secure/wsl2"
)

func init() {
	getter = &linuxGetter{}
}

type linuxGetter struct{}

type secretServiceProbeFunc = func(context.Context) error
type kernelKeyringOpener = func(string) (*backendkeyctl.Keyring, error)

var (
	nativeBackendInfo = api.Info{
		Backend:     api.BackendSecretService,
		Persistence: api.PersistencePersistent,
		Host:        api.HostCurrent,
		Interaction: api.InteractionPossible,
	}
	probeSecretService = dbus.Probe
	openKernelKeyring  = backendkeyctl.Open
)

const nativeBackendSupported = true

type wsl2InitializerFunc = func(context.Context, string) (api.Keyringer, error)

var initializeWSL2 wsl2InitializerFunc = func(
	ctx context.Context,
	service string,
) (api.Keyringer, error) {
	return wsl2.New(ctx, service)
}

func (g *linuxGetter) Get(
	ctx context.Context,
	option Option,
) (api.Keyringer, api.Info, error) {
	order := option.Backends
	if len(order) == 0 {
		if wsl2.IsWSL2() {
			order = append(order, api.BackendWindowsCredentialManager)
		}
		order = append(order, api.BackendSecretService, api.BackendKernelKeyring)
	}

	registry := map[api.Backend]selection.BackendOpener{
		api.BackendWindowsCredentialManager: func(ctx context.Context) (api.Keyringer, api.Info, error) {
			keyring, err := initializeWSL2(ctx, option.Service)
			if err != nil {
				return nil, api.Info{}, err
			}
			return keyring, api.Info{
				Backend:     api.BackendWindowsCredentialManager,
				Persistence: api.PersistencePersistent,
				Host:        api.HostWindows,
				Interaction: api.InteractionNone,
			}, nil
		},
		api.BackendSecretService: func(ctx context.Context) (api.Keyringer, api.Info, error) {
			if err := probeSecretService(ctx); err != nil {
				return nil, api.Info{}, err
			}
			return &Keyring{service: option.Service}, api.Info{
				Backend:     api.BackendSecretService,
				Persistence: api.PersistencePersistent,
				Host:        api.HostCurrent,
				Interaction: api.InteractionPossible,
			}, nil
		},
		api.BackendKernelKeyring: func(context.Context) (api.Keyringer, api.Info, error) {
			keyring, err := openKernelKeyring(option.Service)
			if err != nil {
				return nil, api.Info{}, err
			}
			return keyring, api.Info{
				Backend:     api.BackendKernelKeyring,
				Persistence: api.PersistenceSession,
				Host:        api.HostCurrent,
				Interaction: api.InteractionNone,
			}, nil
		},
	}
	return selection.SelectBackend(ctx, order, registry)
}
