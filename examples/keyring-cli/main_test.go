package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	api "common.queueb.org/keyring"
	keyring "common.queueb.org/keyring/secure"
)

type memoryKeyring struct {
	secrets map[string][]byte
	err     error
}

var _ api.Keyringer = (*memoryKeyring)(nil)

func (k *memoryKeyring) Get(_ context.Context, username string) ([]byte, error) {
	if k.err != nil {
		return nil, k.err
	}
	secret, found := k.secrets[username]
	if !found {
		return nil, api.ErrNotFound
	}
	return append([]byte(nil), secret...), nil
}

func (k *memoryKeyring) Set(_ context.Context, username string, password []byte) error {
	if k.err != nil {
		return k.err
	}
	k.secrets[username] = append([]byte(nil), password...)
	return nil
}

func (k *memoryKeyring) Delete(_ context.Context, username string) error {
	if k.err != nil {
		return k.err
	}
	if _, found := k.secrets[username]; !found {
		return api.ErrNotFound
	}
	delete(k.secrets, username)
	return nil
}

func TestCommands(t *testing.T) {
	storage := &memoryKeyring{secrets: make(map[string][]byte)}
	initialize := func(
		_ context.Context,
		options ...*keyring.Option,
	) (api.Keyringer, api.Info, error) {
		if len(options) != 1 || options[0].Service != "test-service" {
			t.Fatalf("options = %#v", options)
		}
		return storage, api.Info{Backend: api.BackendCustom}, nil
	}

	t.Run("create", func(t *testing.T) {
		output, err := execute(t, initialize, "secret", "--service", "test-service", "create", "api-token")
		if err != nil {
			t.Fatalf("Execute() error = %v", err)
		}
		if output != "secret created\n" {
			t.Fatalf("output = %q", output)
		}
		if string(storage.secrets["api-token"]) != "secret" {
			t.Fatalf("stored secret = %q", storage.secrets["api-token"])
		}
	})

	t.Run("get", func(t *testing.T) {
		output, err := execute(t, initialize, "", "--service", "test-service", "get", "api-token")
		if err != nil {
			t.Fatalf("Execute() error = %v", err)
		}
		if output != "secret" {
			t.Fatalf("output = %q, want secret", output)
		}
	})

	t.Run("delete", func(t *testing.T) {
		output, err := execute(t, initialize, "", "--service", "test-service", "delete", "api-token")
		if err != nil {
			t.Fatalf("Execute() error = %v", err)
		}
		if output != "secret deleted\n" {
			t.Fatalf("output = %q", output)
		}
	})

	t.Run("delete missing", func(t *testing.T) {
		_, err := execute(t, initialize, "", "--service", "test-service", "delete", "api-token")
		if err == nil {
			t.Fatal("Execute() error = nil")
		}
	})
}

func TestCommandErrors(t *testing.T) {
	want := errors.New("failure")

	t.Run("initialize", func(t *testing.T) {
		_, err := execute(t, func(context.Context, ...*keyring.Option) (api.Keyringer, api.Info, error) {
			return nil, api.Info{}, want
		}, "", "get", "api-token")
		if !errors.Is(err, want) {
			t.Fatalf("Execute() error = %v, want %v", err, want)
		}
	})

	t.Run("create", func(t *testing.T) {
		storage := &memoryKeyring{secrets: make(map[string][]byte), err: want}
		_, err := execute(t, fixedInitializer(storage), "secret", "create", "api-token")
		if !errors.Is(err, want) {
			t.Fatalf("Execute() error = %v, want %v", err, want)
		}
	})

	t.Run("read secret", func(t *testing.T) {
		storage := &memoryKeyring{secrets: make(map[string][]byte)}
		command := newRootCommand(fixedInitializer(storage))
		command.SetArgs([]string{"create", "api-token"})
		command.SetIn(errorReader{err: want})
		if err := command.Execute(); !errors.Is(err, want) {
			t.Fatalf("Execute() error = %v, want %v", err, want)
		}
	})

	t.Run("get", func(t *testing.T) {
		storage := &memoryKeyring{secrets: make(map[string][]byte), err: want}
		_, err := execute(t, fixedInitializer(storage), "", "get", "api-token")
		if !errors.Is(err, want) {
			t.Fatalf("Execute() error = %v, want %v", err, want)
		}
	})
}

func TestMain(t *testing.T) {
	originalArgs := os.Args
	originalStdout := os.Stdout
	originalStderr := os.Stderr
	originalExit := exitProcess

	output, err := os.Create(filepath.Join(t.TempDir(), "output"))
	if err != nil {
		t.Fatalf("create output: %v", err)
	}
	os.Stdout = output
	os.Stderr = output
	exitCode := 0
	exitProcess = func(code int) { exitCode = code }
	t.Cleanup(func() {
		os.Args = originalArgs
		os.Stdout = originalStdout
		os.Stderr = originalStderr
		exitProcess = originalExit
		_ = output.Close()
	})

	os.Args = []string{"keyring-example", "--help"}
	main()
	if exitCode != 0 {
		t.Fatalf("help exit code = %d, want 0", exitCode)
	}

	os.Args = []string{"keyring-example", "unknown"}
	main()
	if exitCode != 1 {
		t.Fatalf("error exit code = %d, want 1", exitCode)
	}
}

func execute(
	t *testing.T,
	initialize initializer,
	input string,
	args ...string,
) (string, error) {
	t.Helper()
	command := newRootCommand(initialize)
	var output bytes.Buffer
	command.SetArgs(args)
	command.SetIn(strings.NewReader(input))
	command.SetOut(&output)
	command.SetErr(&output)
	err := command.Execute()
	return output.String(), err
}

func fixedInitializer(storage api.Keyringer) initializer {
	return func(context.Context, ...*keyring.Option) (api.Keyringer, api.Info, error) {
		return storage, api.Info{Backend: api.BackendCustom}, nil
	}
}

type errorReader struct {
	err error
}

func (r errorReader) Read([]byte) (int, error) {
	return 0, r.err
}
