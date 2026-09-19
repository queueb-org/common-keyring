package selection

import (
	"context"
	"errors"
	"testing"

	"common.queueb.org/keyring/internal/contract"
)

type selectorKeyring struct{}

func (*selectorKeyring) Get(context.Context, string) ([]byte, error) { return nil, nil }
func (*selectorKeyring) Set(context.Context, string, []byte) error   { return nil }
func (*selectorKeyring) Delete(context.Context, string) error        { return nil }

func TestSelectBackend(t *testing.T) {
	ctx := context.Background()
	wantKeyring := &selectorKeyring{}
	unavailable := errors.New("unavailable")
	terminal := errors.New("terminal")

	t.Run("fallback success", func(t *testing.T) {
		order := []contract.Backend{contract.BackendSecretService, contract.BackendKernelKeyring}
		registry := map[contract.Backend]BackendOpener{
			contract.BackendSecretService: func(context.Context) (contract.Keyringer, contract.Info, error) {
				return nil, contract.Info{}, errors.Join(contract.ErrBackendUnavailable, unavailable)
			},
			contract.BackendKernelKeyring: func(got context.Context) (contract.Keyringer, contract.Info, error) {
				if got != ctx {
					t.Fatal("context was not forwarded")
				}
				return wantKeyring, contract.Info{Backend: contract.BackendKernelKeyring}, nil
			},
		}
		keyring, info, err := SelectBackend(ctx, order, registry)
		if err != nil || keyring != wantKeyring {
			t.Fatalf("SelectBackend() = %T, %#v, %v", keyring, info, err)
		}
		if !info.Fallback || len(info.Rejected) != 1 ||
			!errors.Is(info.Rejected[0].Err, unavailable) {
			t.Fatalf("SelectBackend() info = %#v", info)
		}
	})

	t.Run("first success", func(t *testing.T) {
		keyring, info, err := SelectBackend(ctx,
			[]contract.Backend{contract.BackendCustom},
			map[contract.Backend]BackendOpener{
				contract.BackendCustom: func(context.Context) (contract.Keyringer, contract.Info, error) {
					return wantKeyring, contract.Info{Backend: contract.BackendCustom}, nil
				},
			},
		)
		if err != nil || keyring != wantKeyring || info.Fallback || len(info.Rejected) != 0 {
			t.Fatalf("SelectBackend() = %T, %#v, %v", keyring, info, err)
		}
	})

	t.Run("intrinsic fallback", func(t *testing.T) {
		_, info, err := SelectBackend(ctx,
			[]contract.Backend{contract.BackendFilesystem},
			map[contract.Backend]BackendOpener{
				contract.BackendFilesystem: func(context.Context) (contract.Keyringer, contract.Info, error) {
					return wantKeyring, contract.Info{
						Backend:  contract.BackendFilesystem,
						Fallback: true,
					}, nil
				},
			},
		)
		if err != nil || !info.Fallback {
			t.Fatalf("SelectBackend() info = %#v, error = %v", info, err)
		}
	})

	t.Run("unsupported candidate", func(t *testing.T) {
		_, _, err := SelectBackend(ctx, []contract.Backend{"unknown"}, nil)
		var selection *contract.SelectionError
		if !errors.As(err, &selection) || !errors.Is(err, contract.ErrUnsupported) ||
			!errors.Is(err, contract.ErrBackendUnavailable) || len(selection.Rejected) != 1 {
			t.Fatalf("SelectBackend() error = %#v", err)
		}
	})

	t.Run("terminal failure", func(t *testing.T) {
		_, _, err := SelectBackend(ctx,
			[]contract.Backend{contract.BackendCustom},
			map[contract.Backend]BackendOpener{
				contract.BackendCustom: func(context.Context) (contract.Keyringer, contract.Info, error) {
					return nil, contract.Info{}, terminal
				},
			},
		)
		var selection *contract.SelectionError
		if !errors.As(err, &selection) || !errors.Is(err, terminal) ||
			errors.Is(err, contract.ErrBackendUnavailable) || len(selection.Rejected) != 1 {
			t.Fatalf("SelectBackend() error = %#v", err)
		}
	})

	t.Run("empty order", func(t *testing.T) {
		_, _, err := SelectBackend(ctx, nil, nil)
		if !errors.Is(err, contract.ErrBackendUnavailable) {
			t.Fatalf("SelectBackend() error = %v", err)
		}
	})

	t.Run("context", func(t *testing.T) {
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		_, _, err := SelectBackend(canceled, []contract.Backend{contract.BackendCustom}, nil)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("SelectBackend() error = %v", err)
		}
	})
}
