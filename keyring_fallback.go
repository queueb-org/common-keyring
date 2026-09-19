//go:build !windows && !unix

package keyring

import (
	"context"
	"fmt"
)

var nativeBackendInfo = Info{
	Backend:     BackendCustom,
	Persistence: PersistenceUnknown,
	Host:        HostCurrent,
	Interaction: InteractionUnknown,
}

const nativeBackendSupported = false

var probeNativeBackend = func(context.Context) error {
	return fmt.Errorf("%w: native credential backend", ErrUnsupported)
}
