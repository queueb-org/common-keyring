//go:build unix && !darwin

package keyring

import (
	"common.queueb.org/keyring/internal/backend/dbus"
)

var nativeBackendInfo = Info{
	Backend:     BackendSecretService,
	Persistence: PersistencePersistent,
	Host:        HostCurrent,
	Interaction: InteractionPossible,
}

const nativeBackendSupported = true

var probeNativeBackend = dbus.Probe
