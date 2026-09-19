package contract

import (
	"context"
	"errors"
	"fmt"
)

// ContextError returns the current context failure in the portable error model.
func ContextError(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("%w: context is nil", ErrInvalidArgument)
	}
	err := ctx.Err()
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%w: %w", ErrTimeout, err)
	}
	return err
}
