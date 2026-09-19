package dbus

import (
	"context"
	"errors"
	"fmt"

	"common.queueb.org/keyring/internal/contract"

	godbus "github.com/godbus/dbus/v5"
)

func contextError(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("%w: context is nil", contract.ErrInvalidArgument)
	}
	err := ctx.Err()
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%w: %w", contract.ErrTimeout, err)
	}
	return err
}

func backendError(ctx context.Context, operation string, err error) error {
	if contextErr := contextError(ctx); contextErr != nil {
		return contextErr
	}
	for _, category := range []error{
		contract.ErrNotFound,
		contract.ErrInvalidArgument,
		contract.ErrValueTooLarge,
		contract.ErrBackendUnavailable,
		contract.ErrBackendLocked,
		contract.ErrInteractionRequired,
		contract.ErrPermissionDenied,
		contract.ErrTimeout,
		contract.ErrUnsupported,
		contract.ErrBackendFailure,
	} {
		if errors.Is(err, category) {
			return fmt.Errorf("%s: %w", operation, err)
		}
	}

	category := contract.ErrBackendFailure
	var busErr godbus.Error
	if errors.As(err, &busErr) {
		switch busErr.Name {
		case "org.freedesktop.DBus.Error.ServiceUnknown",
			"org.freedesktop.DBus.Error.NameHasNoOwner":
			category = contract.ErrBackendUnavailable
		case "org.freedesktop.DBus.Error.AccessDenied",
			"org.freedesktop.DBus.Error.AuthFailed":
			category = contract.ErrPermissionDenied
		case "org.freedesktop.DBus.Error.NoReply",
			"org.freedesktop.DBus.Error.Timeout":
			category = contract.ErrTimeout
		case "org.freedesktop.Secret.Error.IsLocked":
			category = contract.ErrBackendLocked
		case "org.freedesktop.Secret.Error.NoSuchObject":
			category = contract.ErrNotFound
		case "org.freedesktop.DBus.Error.InteractiveAuthorizationRequired":
			category = contract.ErrInteractionRequired
		case "org.freedesktop.DBus.Error.LimitsExceeded":
			category = contract.ErrValueTooLarge
		}
	}
	return fmt.Errorf("%w: %s: %w", category, operation, err)
}
