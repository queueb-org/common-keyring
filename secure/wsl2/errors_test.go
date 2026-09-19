//go:build linux

package wsl2

import (
	"errors"
	"testing"
)

func TestProtocolErrorCategories(t *testing.T) {
	tests := []struct {
		code string
		want error
	}{
		{code: errInvalidRequest, want: ErrInvalidRequest},
		{code: errUnsupportedProtocol, want: ErrUnsupportedProtocol},
		{code: errUnsupportedOperation, want: ErrUnsupportedOperation},
		{code: errInvalidArgument, want: ErrInvalidArgument},
		{code: errNotFound, want: ErrNotFound},
		{code: errAccessDenied, want: ErrAccessDenied},
		{code: errBackendUnavailable, want: ErrBackendUnavailable},
		{code: errBackendFailure, want: ErrBackendFailure},
		{code: errTimeout, want: ErrTimeout},
		{code: errInternal, want: ErrInternal},
	}

	for _, test := range tests {
		t.Run(test.code, func(t *testing.T) {
			err := &ProtocolError{Code: test.code, Message: "details"}
			if !errors.Is(err, test.want) {
				t.Fatalf("errors.Is(%v, %v) = false", err, test.want)
			}
		})
	}
}

func TestProtocolError(t *testing.T) {
	t.Run("message", func(t *testing.T) {
		err := &ProtocolError{Code: errInternal, Message: "details"}
		if got := err.Error(); got != "internal: details" {
			t.Fatalf("Error() = %q, want %q", got, "internal: details")
		}
	})

	t.Run("code only", func(t *testing.T) {
		err := &ProtocolError{Code: errInternal}
		if got := err.Error(); got != errInternal {
			t.Fatalf("Error() = %q, want %q", got, errInternal)
		}
	})

	t.Run("unknown code", func(t *testing.T) {
		err := &ProtocolError{Code: "future_error", Message: "details"}
		if unwrapped := errors.Unwrap(err); unwrapped != nil {
			t.Fatalf("errors.Unwrap() = %v, want nil", unwrapped)
		}
	})

	t.Run("nil", func(t *testing.T) {
		var err *ProtocolError
		if got := err.Error(); got != "" {
			t.Fatalf("Error() = %q, want empty string", got)
		}
		if unwrapped := err.Unwrap(); unwrapped != nil {
			t.Fatalf("Unwrap() = %v, want nil", unwrapped)
		}
	})
}

func TestErrHelperNotFound(t *testing.T) {
	if !errors.Is(ErrHelperNotFound, ErrBackendUnavailable) {
		t.Fatalf("errors.Is(%v, %v) = false", ErrHelperNotFound, ErrBackendUnavailable)
	}
}
