//go:build darwin

package keyring

import (
	"context"
)

var nativeBackendInfo = Info{
	Backend:     BackendKeychain,
	Persistence: PersistencePersistent,
	Host:        HostCurrent,
	Interaction: InteractionPossible,
}

const nativeBackendSupported = true

var probeNativeBackend = func(context.Context) error {
	return nil
}
