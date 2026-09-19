package contract

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestContextError(t *testing.T) {
	if err := ContextError(context.Background()); err != nil {
		t.Fatalf("ContextError() = %v", err)
	}

	//lint:ignore SA1012, for test purposes
	if err := ContextError(nil); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("ContextError(nil) = %v, want %v", err, ErrInvalidArgument)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := ContextError(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("ContextError(canceled) = %v, want %v", err, context.Canceled)
	}

	expired, cancel := context.WithDeadline(context.Background(), time.Time{})
	defer cancel()
	err := ContextError(expired)
	if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, ErrTimeout) {
		t.Fatalf("ContextError(expired) = %v", err)
	}
}
