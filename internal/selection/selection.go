package selection

import (
	"context"
	"errors"
	"fmt"

	"common.queueb.org/keyring/internal/contract"
)

// BackendOpener initializes one backend after its cheap environment hints have
// been evaluated by the owning policy package.
type BackendOpener func(context.Context) (contract.Keyringer, contract.Info, error)

// SelectBackend tries registry entries in order and records every rejected
// candidate. Only unavailable and unsupported candidates permit fallback.
func SelectBackend(
	ctx context.Context,
	order []contract.Backend,
	registry map[contract.Backend]BackendOpener,
) (contract.Keyringer, contract.Info, error) {
	rejected := make([]contract.Rejection, 0, len(order))
	for _, backend := range order {
		if err := contract.ContextError(ctx); err != nil {
			return nil, contract.Info{}, selectionError(rejected, err)
		}

		opener, ok := registry[backend]
		if !ok {
			err := fmt.Errorf("%w: backend %q", contract.ErrUnsupported, backend)
			rejected = append(rejected, contract.Rejection{Backend: backend, Err: err})
			continue
		}

		keyring, info, err := opener(ctx)
		if err == nil {
			info.Fallback = info.Fallback || len(rejected) != 0
			info.Rejected = append([]contract.Rejection(nil), rejected...)
			return keyring, info, nil
		}

		rejected = append(rejected, contract.Rejection{Backend: backend, Err: err})
		if !errors.Is(err, contract.ErrBackendUnavailable) &&
			!errors.Is(err, contract.ErrUnsupported) {
			return nil, contract.Info{}, selectionError(rejected, err)
		}
	}

	return nil, contract.Info{}, selectionError(rejected, contract.ErrBackendUnavailable)
}

func selectionError(rejected []contract.Rejection, cause error) error {
	return &contract.SelectionError{
		Rejected: append([]contract.Rejection(nil), rejected...),
		Cause:    cause,
	}
}
