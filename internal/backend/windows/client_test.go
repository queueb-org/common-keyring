package windows

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"common.queueb.org/keyring/internal/contract"
)

// withCredentialOperations overrides native Windows credential operations for
// one test and restores them during cleanup. It mutates package state and must
// not be used by parallel tests.
func withCredentialOperations(
	t *testing.T,
	read func(string) ([]byte, error),
	write func(string, string, []byte) error,
	delete func(string) error,
) {
	t.Helper()
	originalRead := readCredential
	originalWrite := writeCredential
	originalDelete := deleteCredential
	readCredential = read
	writeCredential = write
	deleteCredential = delete
	t.Cleanup(func() {
		readCredential = originalRead
		writeCredential = originalWrite
		deleteCredential = originalDelete
	})
}

func TestOperations(t *testing.T) {
	ctx := context.Background()
	want := []byte{0, 1, 2, 255}
	withCredentialOperations(t,
		func(target string) ([]byte, error) {
			if target != "service:key" {
				t.Fatalf("read target = %q", target)
			}
			return want, nil
		},
		func(target, username string, value []byte) error {
			if target != "service:key" || username != "key" || !bytes.Equal(value, want) {
				t.Fatalf("write = %q, %q, %v", target, username, value)
			}
			value[0] = 9
			return nil
		},
		func(target string) error {
			if target != "service:key" {
				t.Fatalf("delete target = %q", target)
			}
			return nil
		},
	)

	got, err := Get(ctx, "service", "key")
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("Get() = %v, %v, want %v, nil", got, err, want)
	}
	got[0] = 8
	if want[0] != 0 {
		t.Fatal("Get() returned backend-owned storage")
	}
	if err := Set(ctx, "service", "key", want); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	if want[0] != 0 {
		t.Fatal("Set() passed caller-owned storage to the backend")
	}
	if err := Delete(ctx, "service", "key"); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
}

func TestOperationErrors(t *testing.T) {
	failure := errors.New("failure")
	withCredentialOperations(t,
		func(string) ([]byte, error) { return nil, contract.ErrNotFound },
		func(string, string, []byte) error { return contract.ErrPermissionDenied },
		func(string) error { return failure },
	)

	if _, err := Get(context.Background(), "service", "key"); !errors.Is(err, contract.ErrNotFound) {
		t.Fatalf("Get() error = %v, want %v", err, contract.ErrNotFound)
	}
	if err := Set(context.Background(), "service", "key", nil); !errors.Is(err, contract.ErrPermissionDenied) {
		t.Fatalf("Set() error = %v, want %v", err, contract.ErrPermissionDenied)
	}
	if err := Delete(context.Background(), "service", "key"); !errors.Is(err, failure) || !errors.Is(err, contract.ErrBackendFailure) {
		t.Fatalf("Delete() error = %v, want %v and %v", err, failure, contract.ErrBackendFailure)
	}
}

func TestValidatedTarget(t *testing.T) {
	tests := []struct {
		name    string
		service string
		key     string
		want    string
		err     error
	}{
		{name: "valid", service: "service", key: "key", want: "service:key"},
		{name: "unicode units", service: strings.Repeat("a", maxGenericTargetUnits-3), key: "🔑", want: strings.Repeat("a", maxGenericTargetUnits-3) + ":🔑"},
		{name: "empty service", key: "key", err: contract.ErrInvalidArgument},
		{name: "empty key", service: "service", err: contract.ErrInvalidArgument},
		{name: "service NUL", service: "service\x00", key: "key", err: contract.ErrInvalidArgument},
		{name: "key NUL", service: "service", key: "key\x00", err: contract.ErrInvalidArgument},
		{name: "service invalid UTF-8", service: "service\xff", key: "key", err: contract.ErrInvalidArgument},
		{name: "key invalid UTF-8", service: "service", key: "key\xff", err: contract.ErrInvalidArgument},
		{name: "username too long", service: "service", key: strings.Repeat("k", maxUsernameUnits+1), err: contract.ErrInvalidArgument},
		{name: "target too long", service: strings.Repeat("s", maxGenericTargetUnits), key: "k", err: contract.ErrInvalidArgument},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := validatedTarget(test.service, test.key)
			if got != test.want || !errors.Is(err, test.err) {
				t.Fatalf("validatedTarget() = %q, %v, want %q, %v", got, err, test.want, test.err)
			}
		})
	}
}

func TestOperationInputAndContextErrors(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, cancel := context.WithDeadline(context.Background(), time.Time{})
	defer cancel()

	tests := []struct {
		name string
		call func() error
		err  error
	}{
		{name: "get input", call: func() error {
			_, err := Get(context.Background(), "", "key")
			return err
		}, err: contract.ErrInvalidArgument},
		{name: "set value", call: func() error {
			return Set(context.Background(), "service", "key", make([]byte, maxCredentialBlobBytes+1))
		}, err: contract.ErrValueTooLarge},
		{name: "set input", call: func() error {
			return Set(context.Background(), "", "key", nil)
		}, err: contract.ErrInvalidArgument},
		{name: "delete input", call: func() error {
			return Delete(context.Background(), "service", "")
		}, err: contract.ErrInvalidArgument},
		{name: "get nil context", call: func() error {
			//lint:ignore SA1012, for test purposes
			_, err := Get(nil, "service", "key")
			return err
		}, err: contract.ErrInvalidArgument},
		{name: "set canceled", call: func() error {
			return Set(canceled, "service", "key", nil)
		}, err: context.Canceled},
		{name: "delete expired", call: func() error {
			return Delete(expired, "service", "key")
		}, err: contract.ErrTimeout},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.call(); !errors.Is(err, test.err) {
				t.Fatalf("operation error = %v, want %v", err, test.err)
			}
		})
	}
}

func TestOperationErrorCategories(t *testing.T) {
	for _, category := range []error{
		contract.ErrInvalidArgument,
		contract.ErrValueTooLarge,
		contract.ErrBackendUnavailable,
		contract.ErrUnsupported,
	} {
		if err := operationError("operation", category); !errors.Is(err, category) {
			t.Fatalf("operationError(%v) = %v", category, err)
		}
	}
}
