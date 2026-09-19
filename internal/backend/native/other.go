//go:build !linux && !darwin && !windows

package native

import (
	"context"
	"fmt"

	"common.queueb.org/keyring/internal/contract"
)

// Get reports that no native credential store is supported on this platform.
func Get(ctx context.Context, service, key string) ([]byte, error) {
	if err := contract.ContextError(ctx); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("%w: native credential store", contract.ErrUnsupported)
}

// Set reports that no native credential store is supported on this platform.
func Set(ctx context.Context, service, key string, value []byte) error {
	if err := contract.ContextError(ctx); err != nil {
		return err
	}
	return fmt.Errorf("%w: native credential store", contract.ErrUnsupported)
}

// Delete reports that no native credential store is supported on this platform.
func Delete(ctx context.Context, service, key string) error {
	if err := contract.ContextError(ctx); err != nil {
		return err
	}
	return fmt.Errorf("%w: native credential store", contract.ErrUnsupported)
}
