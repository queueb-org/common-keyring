package windows

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"common.queueb.org/keyring/internal/contract"
)

const (
	maxCredentialBlobBytes = 5 * 512
	maxGenericTargetUnits  = 32767
	maxUsernameUnits       = 513
)

// Keep native operations behind variables intentionally so unit tests can
// exercise the adapter without accessing Windows Credential Manager.
var (
	readCredential   = nativeReadCredential
	writeCredential  = nativeWriteCredential
	deleteCredential = nativeDeleteCredential
)

// Get returns a value from Windows Credential Manager. The native call is
// synchronous and cannot be interrupted after it starts.
func Get(ctx context.Context, service, key string) ([]byte, error) {
	if err := contract.ContextError(ctx); err != nil {
		return nil, err
	}
	target, err := validatedTarget(service, key)
	if err != nil {
		return nil, err
	}

	value, err := readCredential(target)
	if err != nil {
		return nil, operationError("get credential", err)
	}
	return append([]byte(nil), value...), nil
}

// Set stores a value in Windows Credential Manager. The native call is
// synchronous and cannot be interrupted after it starts.
func Set(ctx context.Context, service, key string, value []byte) error {
	if err := contract.ContextError(ctx); err != nil {
		return err
	}
	target, err := validatedTarget(service, key)
	if err != nil {
		return err
	}
	if len(value) > maxCredentialBlobBytes {
		return fmt.Errorf(
			"%w: Windows credential blob exceeds %d bytes",
			contract.ErrValueTooLarge,
			maxCredentialBlobBytes,
		)
	}
	return operationError(
		"set credential",
		writeCredential(target, key, append([]byte(nil), value...)),
	)
}

// Delete removes a value from Windows Credential Manager. The native call is
// synchronous and cannot be interrupted after it starts.
func Delete(ctx context.Context, service, key string) error {
	if err := contract.ContextError(ctx); err != nil {
		return err
	}
	target, err := validatedTarget(service, key)
	if err != nil {
		return err
	}

	return operationError("delete credential", deleteCredential(target))
}

func validatedTarget(service, key string) (string, error) {
	if service == "" {
		return "", fmt.Errorf("%w: service is empty", contract.ErrInvalidArgument)
	}
	if key == "" {
		return "", fmt.Errorf("%w: key is empty", contract.ErrInvalidArgument)
	}
	if strings.IndexByte(service, 0) >= 0 || strings.IndexByte(key, 0) >= 0 {
		return "", fmt.Errorf("%w: service or key contains NUL", contract.ErrInvalidArgument)
	}
	if !utf8.ValidString(service) || !utf8.ValidString(key) {
		return "", fmt.Errorf("%w: service or key is not valid UTF-8", contract.ErrInvalidArgument)
	}
	if utf16Units(key) > maxUsernameUnits {
		return "", fmt.Errorf(
			"%w: Windows credential username exceeds %d UTF-16 code units",
			contract.ErrInvalidArgument,
			maxUsernameUnits,
		)
	}

	// This mapping is part of keyring-winbridge/v1alpha1 interoperability.
	target := service + ":" + key
	if utf16Units(target) > maxGenericTargetUnits {
		return "", fmt.Errorf(
			"%w: Windows credential target exceeds %d UTF-16 code units",
			contract.ErrInvalidArgument,
			maxGenericTargetUnits,
		)
	}
	return target, nil
}

func utf16Units(value string) int {
	return len(utf16.Encode([]rune(value)))
}

func operationError(operation string, err error) error {
	if err == nil {
		return nil
	}

	for _, category := range []error{
		contract.ErrNotFound,
		contract.ErrInvalidArgument,
		contract.ErrValueTooLarge,
		contract.ErrBackendUnavailable,
		contract.ErrPermissionDenied,
		contract.ErrUnsupported,
	} {
		if errors.Is(err, category) {
			return fmt.Errorf("%s: %w", operation, err)
		}
	}
	return fmt.Errorf("%w: %s: %w", contract.ErrBackendFailure, operation, err)
}
