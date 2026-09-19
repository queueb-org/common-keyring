package contract

import (
	"errors"
	"testing"
)

func TestSelectionError(t *testing.T) {
	denied := errors.New("denied")
	err := &SelectionError{
		Rejected: []Rejection{
			{Backend: BackendSecretService, Err: ErrBackendUnavailable},
			{Backend: BackendKernelKeyring, Err: denied},
		},
		Cause: denied,
	}

	if got, want := err.Error(), "credential backend selection failed: secret-service: kernel-keyring"; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
	if !errors.Is(err, denied) || !errors.Is(err, ErrBackendUnavailable) {
		t.Fatalf("SelectionError does not preserve causes: %v", err)
	}
	if got := err.Unwrap(); len(got) != 2 {
		t.Fatalf("Unwrap() returned %d errors, want 2", len(got))
	}
}

func TestSelectionErrorEmpty(t *testing.T) {
	var err *SelectionError
	if got := err.Error(); got != "credential backend selection failed" {
		t.Fatalf("Error() = %q", got)
	}
	if got := err.Unwrap(); got != nil {
		t.Fatalf("Unwrap() = %#v", got)
	}

	err = &SelectionError{Rejected: []Rejection{{Backend: BackendCustom}}}
	if got := err.Unwrap(); len(got) != 0 {
		t.Fatalf("Unwrap() = %#v", got)
	}
}
