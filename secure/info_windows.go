//go:build windows

package keyring

import api "common.queueb.org/keyring"

var nativeBackendInfo = api.Info{
	Backend:     api.BackendWindowsCredentialManager,
	Persistence: api.PersistencePersistent,
	Host:        api.HostCurrent,
	Interaction: api.InteractionNone,
}

const nativeBackendSupported = true
