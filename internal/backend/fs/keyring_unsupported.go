//go:build !linux

package fs

import (
	"fmt"

	"common.queueb.org/keyring/internal/contract"
)

func openStorage(string, layout) (storage, error) {
	return nil, fmt.Errorf(
		"%w: %w: required filesystem security checks are not implemented on this platform",
		contract.ErrInsecureFallback,
		contract.ErrUnsupported,
	)
}
