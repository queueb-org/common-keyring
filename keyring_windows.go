//go:build windows

package keyring

import (
	"context"
)

var nativeBackendInfo = Info{
	Backend:     BackendWindowsCredentialManager,
	Persistence: PersistencePersistent,
	Host:        HostCurrent,
	Interaction: InteractionNone,
}

const nativeBackendSupported = true

var probeNativeBackend = func(context.Context) error {
	return nil
}
