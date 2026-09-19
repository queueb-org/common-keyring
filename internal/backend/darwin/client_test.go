package darwin

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	"common.queueb.org/keyring/internal/contract"
)

// withCommand overrides macOS security-command execution for one test and
// restores the original function during cleanup. It mutates package state and
// must not be used by parallel tests.
func withCommand(t *testing.T, command commandFunc) {
	t.Helper()
	original := executeCommand
	executeCommand = command
	t.Cleanup(func() {
		executeCommand = original
	})
}

func TestGet(t *testing.T) {
	ctx := context.Background()
	want := []byte("secret")
	withCommand(t, func(
		gotCtx context.Context,
		input io.Reader,
		arguments ...string,
	) ([]byte, error) {
		if gotCtx != ctx || input != nil {
			t.Fatalf("executeCommand() context or input mismatch")
		}
		wantArguments := []string{"find-generic-password", "-s", "service", "-wa", "key"}
		if !reflect.DeepEqual(arguments, wantArguments) {
			t.Fatalf("executeCommand() arguments = %q, want %q", arguments, wantArguments)
		}
		return []byte(base64Prefix + "c2VjcmV0\n"), nil
	})

	got, err := Get(ctx, "service", "key")
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("Get() = %q, %v, want %q, nil", got, err, want)
	}
}

func TestGetError(t *testing.T) {
	want := errors.New("get failed")
	withCommand(t, func(context.Context, io.Reader, ...string) ([]byte, error) {
		return nil, want
	})

	_, err := Get(context.Background(), "service", "key")
	if !errors.Is(err, want) || !errors.Is(err, contract.ErrBackendFailure) {
		t.Fatalf("Get() error = %v, want %v and %v", err, want, contract.ErrBackendFailure)
	}
}

func TestSet(t *testing.T) {
	withCommand(t, func(
		_ context.Context,
		input io.Reader,
		arguments ...string,
	) ([]byte, error) {
		if !reflect.DeepEqual(arguments, []string{"-i"}) {
			t.Fatalf("executeCommand() arguments = %q, want [-i]", arguments)
		}
		command, err := io.ReadAll(input)
		if err != nil {
			t.Fatalf("ReadAll() error = %v", err)
		}
		want := "add-generic-password -U -s 'service name' -a key -w go-keyring-base64:c2VjcmV0\n"
		if string(command) != want {
			t.Fatalf("executeCommand() input = %q, want %q", command, want)
		}
		return nil, nil
	})

	if err := Set(context.Background(), "service name", "key", []byte("secret")); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
}

func TestSetValueTooLarge(t *testing.T) {
	err := Set(context.Background(), "service", "key", bytes.Repeat([]byte("x"), commandLimit))
	if !errors.Is(err, contract.ErrValueTooLarge) {
		t.Fatalf("Set() error = %v, want %v", err, contract.ErrValueTooLarge)
	}
}

func TestDelete(t *testing.T) {
	withCommand(t, func(
		_ context.Context,
		input io.Reader,
		arguments ...string,
	) ([]byte, error) {
		if input != nil {
			t.Fatalf("executeCommand() input is non-nil")
		}
		want := []string{"delete-generic-password", "-s", "service", "-a", "key"}
		if !reflect.DeepEqual(arguments, want) {
			t.Fatalf("executeCommand() arguments = %q, want %q", arguments, want)
		}
		return nil, nil
	})

	if err := Delete(context.Background(), "service", "key"); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
}

func TestOperationContextErrors(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, cancel := context.WithDeadline(context.Background(), time.Time{})
	defer cancel()

	tests := []struct {
		name string
		err  error
		call func() error
	}{
		{
			name: "nil",
			err:  contract.ErrInvalidArgument,
			call: func() error {
				//lint:ignore SA1012, for test purposes
				_, err := Get(nil, "service", "key")
				return err
			},
		},
		{
			name: "canceled",
			err:  context.Canceled,
			call: func() error {
				return Set(canceled, "service", "key", nil)
			},
		},
		{
			name: "expired",
			err:  contract.ErrTimeout,
			call: func() error {
				return Delete(expired, "service", "key")
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.call(); !errors.Is(err, test.err) {
				t.Fatalf("operation error = %v, want %v", err, test.err)
			}
		})
	}
}

func TestRunCommand(t *testing.T) {
	original := commandContext
	commandContext = func(ctx context.Context, name string, arguments ...string) *exec.Cmd {
		if name != securityPath || !reflect.DeepEqual(arguments, []string{"argument"}) {
			t.Fatalf("CommandContext() = %q, %q", name, arguments)
		}
		return exec.CommandContext(ctx, os.Args[0], "-test.run=^$")
	}
	t.Cleanup(func() {
		commandContext = original
	})

	if _, err := runCommand(context.Background(), strings.NewReader("input"), "argument"); err != nil {
		t.Fatalf("runCommand() error = %v", err)
	}
}

func TestDecodeValue(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  []byte
		err   error
	}{
		{name: "plain", value: "secret", want: []byte("secret")},
		{name: "legacy", value: legacyEncodingPrefix + "736563726574", want: []byte("secret")},
		{name: "base64", value: base64Prefix + "c2VjcmV0", want: []byte("secret")},
		{name: "invalid", value: base64Prefix + "%%%", err: contract.ErrBackendFailure},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := decodeValue(test.value)
			if !errors.Is(err, test.err) || !bytes.Equal(got, test.want) {
				t.Fatalf("decodeValue() = %q, %v, want %q, %v", got, err, test.want, test.err)
			}
		})
	}
}

func TestKeychainError(t *testing.T) {
	unknown := errors.New("unknown")
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	tests := []struct {
		name     string
		ctx      context.Context
		output   []byte
		err      error
		category error
	}{
		{name: "nil", ctx: context.Background()},
		{name: "canceled", ctx: canceled, err: unknown, category: context.Canceled},
		{name: "unavailable", ctx: context.Background(), err: exec.ErrNotFound, category: contract.ErrBackendUnavailable},
		{name: "not found", ctx: context.Background(), output: []byte("item could not be found"), err: unknown, category: contract.ErrNotFound},
		{name: "failure", ctx: context.Background(), err: unknown, category: contract.ErrBackendFailure},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := keychainError(test.ctx, "operation", test.output, test.err)
			if !errors.Is(err, test.category) {
				t.Fatalf("keychainError() = %v, want %v", err, test.category)
			}
			if test.err != nil && test.category != context.Canceled && !errors.Is(err, test.err) {
				t.Fatalf("keychainError() = %v, want cause %v", err, test.err)
			}
		})
	}
}
