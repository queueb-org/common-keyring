package darwin

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os/exec"
	"strings"

	"common.queueb.org/keyring/internal/contract"
)

func decodeValue(value string) ([]byte, error) {
	var (
		decoded []byte
		err     error
	)
	switch {
	case strings.HasPrefix(value, legacyEncodingPrefix):
		decoded, err = hex.DecodeString(value[len(legacyEncodingPrefix):])
	case strings.HasPrefix(value, base64Prefix):
		decoded, err = base64.StdEncoding.DecodeString(value[len(base64Prefix):])
	default:
		return []byte(value), nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: decode Keychain credential: %w", contract.ErrBackendFailure, err)
	}
	return decoded, nil
}

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

func keychainError(ctx context.Context, operation string, output []byte, err error) error {
	if err == nil {
		return nil
	}
	if contextErr := contextError(ctx); contextErr != nil {
		return contextErr
	}
	category := contract.ErrBackendFailure
	switch {
	case errors.Is(err, exec.ErrNotFound), errors.Is(err, fs.ErrNotExist):
		category = contract.ErrBackendUnavailable
	case strings.Contains(string(output), "could not be found"):
		category = contract.ErrNotFound
	}
	return fmt.Errorf("%w: %s: %w", category, operation, err)
}
