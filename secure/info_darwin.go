//go:build darwin

package keyring

import api "common.queueb.org/keyring"

var nativeBackendInfo = api.Info{
	Backend:     api.BackendKeychain,
	Persistence: api.PersistencePersistent,
	Host:        api.HostCurrent,
	Interaction: api.InteractionPossible,
}

const nativeBackendSupported = true
