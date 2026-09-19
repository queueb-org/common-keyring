//go:build !linux && !darwin && !windows

package keyring

import api "common.queueb.org/keyring"

var nativeBackendInfo = api.Info{
	Backend:     api.BackendCustom,
	Persistence: api.PersistenceUnknown,
	Host:        api.HostCurrent,
	Interaction: api.InteractionUnknown,
}

const nativeBackendSupported = false
