//go:build linux

package wsl2

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"

	api "common.queueb.org/keyring"
)

func TestIsKernelRelease(t *testing.T) {
	tests := []struct {
		name    string
		release string
		want    bool
	}{
		{name: "current WSL2", release: "6.6.87.2-microsoft-standard-WSL2", want: true},
		{name: "lowercase WSL2", release: "5.15.153.1-microsoft-standard-wsl2", want: true},
		{name: "whitespace", release: "  6.6.87.2-microsoft-standard-WSL2\n", want: true},
		{name: "native Linux", release: "6.12.12-generic", want: false},
		{name: "WSL1", release: "4.4.0-19041-Microsoft", want: false},
		{name: "empty", release: "", want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isKernelRelease([]byte(test.release)); got != test.want {
				t.Fatalf("isKernelRelease(%q) = %v, want %v", test.release, got, test.want)
			}
		})
	}
}

func TestIsWSL2(t *testing.T) {
	originalRead := readKernelRelease
	t.Cleanup(func() { readKernelRelease = originalRead })

	tests := []struct {
		name    string
		release string
		err     error
		want    bool
	}{
		{name: "WSL2", release: "6.6.87.2-microsoft-standard-WSL2", want: true},
		{name: "native Linux", release: "6.12.12-generic"},
		{name: "read failure", err: errors.New("read failed")},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			readKernelRelease = func() ([]byte, error) {
				return []byte(test.release), test.err
			}
			if got := isWSL2(); got != test.want {
				t.Fatalf("isWSL2() = %v, want %v", got, test.want)
			}
		})
	}

	readKernelRelease = originalRead
	_ = isWSL2()
}

func TestNew(t *testing.T) {
	originalIsWSL2 := IsWSL2
	originalLookPath := lookPath
	originalRun := runProcess
	t.Cleanup(func() {
		IsWSL2 = originalIsWSL2
		lookPath = originalLookPath
		runProcess = originalRun
	})

	t.Run("invalid service", func(t *testing.T) {
		for _, service := range []string{"", "invalid\x00service"} {
			if _, err := New(context.Background(), service); !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("New(%q) error = %v, want %v", service, err, ErrInvalidArgument)
			}
		}
	})

	t.Run("context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := New(ctx, "test"); !errors.Is(err, context.Canceled) {
			t.Fatalf("New() error = %v, want %v", err, context.Canceled)
		}
	})

	t.Run("not WSL2", func(t *testing.T) {
		IsWSL2 = func() bool { return false }
		if _, err := New(context.Background(), "test"); !errors.Is(err, ErrNotWSL2) {
			t.Fatalf("New() error = %v, want %v", err, ErrNotWSL2)
		}
	})

	t.Run("missing helper", func(t *testing.T) {
		IsWSL2 = func() bool { return true }
		lookPath = func(string) (string, error) {
			return "", exec.ErrNotFound
		}
		if _, err := New(context.Background(), "test"); !errors.Is(err, exec.ErrNotFound) ||
			!errors.Is(err, ErrHelperNotFound) ||
			!errors.Is(err, ErrBackendUnavailable) {
			t.Fatalf(
				"New() error = %v, want %v, %v and %v",
				err,
				exec.ErrNotFound,
				ErrHelperNotFound,
				ErrBackendUnavailable,
			)
		}
	})

	t.Run("helper discovery failure", func(t *testing.T) {
		want := errors.New("discovery failed")
		IsWSL2 = func() bool { return true }
		lookPath = func(string) (string, error) {
			return "", want
		}
		_, err := New(context.Background(), "test")
		if !errors.Is(err, ErrBackendFailure) ||
			!errors.Is(err, api.ErrBackendFailure) ||
			!errors.Is(err, want) {
			t.Fatalf("New() error = %v, want %v, %v and %v", err, ErrBackendFailure, api.ErrBackendFailure, want)
		}
		if errors.Is(err, ErrHelperNotFound) || errors.Is(err, api.ErrBackendUnavailable) {
			t.Fatalf("New() error = %v, must not permit fallback", err)
		}
	})

	t.Run("probe", func(t *testing.T) {
		IsWSL2 = func() bool { return true }
		lookPath = func(name string) (string, error) {
			if name != executableName {
				t.Fatalf("lookPath(%q), want %q", name, executableName)
			}
			return "/windows/keyring-winbridge.exe", nil
		}
		runProcess = successfulRunner(t)

		keyring, err := New(context.Background(), "test-service")
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		if keyring.service != "test-service" {
			t.Fatalf("service = %q, want test-service", keyring.service)
		}
		if keyring.helperPath != "/windows/keyring-winbridge.exe" {
			t.Fatalf("helperPath = %q", keyring.helperPath)
		}
	})

	t.Run("probe failure", func(t *testing.T) {
		want := errors.New("execution failed")
		IsWSL2 = func() bool { return true }
		lookPath = func(string) (string, error) {
			return "/windows/keyring-winbridge.exe", nil
		}
		runProcess = func(context.Context, string, []byte) processResult {
			return processResult{err: want}
		}
		_, err := New(context.Background(), "test")
		if !errors.Is(err, ErrBackendFailure) ||
			!errors.Is(err, api.ErrBackendFailure) ||
			!errors.Is(err, want) {
			t.Fatalf("New() error = %v, want %v, %v and %v", err, ErrBackendFailure, api.ErrBackendFailure, want)
		}
		if errors.Is(err, api.ErrBackendUnavailable) {
			t.Fatalf("New() error = %v, must not permit fallback", err)
		}
	})
}

func TestKeyringSuite(t *testing.T) {
	secrets := make(map[string]string)
	runner := func(_ context.Context, helperPath string, input []byte) processResult {
		if helperPath != "/windows/keyring-winbridge.exe" {
			t.Fatalf("helper path = %q", helperPath)
		}
		request := decodeTestRequest(t, input)
		if request.Protocol != protocolID {
			t.Fatalf("protocol = %q", request.Protocol)
		}

		response := response{
			Protocol:  request.Protocol,
			RequestID: request.RequestID,
			OK:        true,
			Result:    &result{},
		}
		exitCode := exitSuccess
		switch request.Operation {
		case operationProbe:
			response.Result = successfulProbeResult()
		case operationSet:
			secrets[request.Account] = *request.Secret
		case operationGet:
			secret, ok := secrets[request.Account]
			if !ok {
				response.OK = false
				response.Result = nil
				response.Error = &ProtocolError{
					Code:    errNotFound,
					Message: "credential was not found",
				}
				exitCode = exitOperationError
			} else {
				response.Result.Secret = &secret
			}
		case operationDelete:
			_, deleted := secrets[request.Account]
			delete(secrets, request.Account)
			response.Result.Deleted = &deleted
		default:
			t.Fatalf("operation = %q", request.Operation)
		}
		return encodedResponse(t, response, exitCode)
	}

	keyring := testKeyring(runner)
	ctx := context.Background()
	if err := keyring.probe(ctx); err != nil {
		t.Fatalf("probe() error = %v", err)
	}
	if err := keyring.Set(ctx, "account", []byte("secret\x00value")); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	password, err := keyring.Get(ctx, "account")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if string(password) != "secret\x00value" {
		t.Fatalf("Get() = %q", password)
	}
	if err := keyring.Delete(ctx, "account"); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if err := keyring.Delete(ctx, "account"); !errors.Is(err, api.ErrNotFound) {
		t.Fatalf("second Delete() error = %v, want %v", err, api.ErrNotFound)
	}
	if _, err := keyring.Get(ctx, "account"); !errors.Is(err, api.ErrNotFound) ||
		!errors.Is(err, ErrNotFound) {
		t.Fatalf("Get() error = %v, want %v and %v", err, api.ErrNotFound, ErrNotFound)
	}
}

func TestKeyringRejectsOversizedSecret(t *testing.T) {
	called := false
	keyring := testKeyring(func(context.Context, string, []byte) processResult {
		called = true
		return processResult{}
	})
	err := keyring.Set(context.Background(), "account", bytes.Repeat([]byte{'x'}, maxSecretBytes+1))
	if !errors.Is(err, ErrValueTooLarge) || !errors.Is(err, api.ErrValueTooLarge) {
		t.Fatalf("Set() error = %v, want %v and %v", err, ErrValueTooLarge, api.ErrValueTooLarge)
	}
	if called {
		t.Fatal("helper was called for an oversized secret")
	}
}

func TestPortableError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		category error
	}{
		{name: "nil"},
		{name: "canceled", err: context.Canceled, category: context.Canceled},
		{name: "deadline", err: context.DeadlineExceeded, category: api.ErrTimeout},
		{name: "timeout", err: ErrTimeout, category: api.ErrTimeout},
		{name: "not found", err: ErrNotFound, category: api.ErrNotFound},
		{name: "invalid argument", err: ErrInvalidArgument, category: api.ErrInvalidArgument},
		{name: "too large", err: ErrValueTooLarge, category: api.ErrValueTooLarge},
		{name: "unavailable", err: ErrBackendUnavailable, category: api.ErrBackendUnavailable},
		{name: "denied", err: ErrAccessDenied, category: api.ErrPermissionDenied},
		{name: "unsupported protocol", err: ErrUnsupportedProtocol, category: api.ErrUnsupported},
		{name: "unsupported operation", err: ErrUnsupportedOperation, category: api.ErrUnsupported},
		{name: "not WSL2", err: ErrNotWSL2, category: api.ErrUnsupported},
		{name: "protocol", err: ErrProtocol, category: api.ErrBackendFailure},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := portableError(test.err)
			if test.err == nil {
				if err != nil {
					t.Fatalf("portableError() = %v", err)
				}
				return
			}
			if !errors.Is(err, test.err) || !errors.Is(err, test.category) {
				t.Fatalf("portableError() = %v, want %v and %v", err, test.err, test.category)
			}
		})
	}
}

func TestInvokeErrors(t *testing.T) {
	t.Run("canceled before invocation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		keyring := testKeyring(successfulRunner(t))
		if _, err := keyring.invoke(ctx, operationGet, "account", nil); !errors.Is(err, context.Canceled) {
			t.Fatalf("invoke() error = %v, want %v", err, context.Canceled)
		}
	})

	t.Run("canceled during invocation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		keyring := testKeyring(func(runCtx context.Context, _ string, _ []byte) processResult {
			cancel()
			<-runCtx.Done()
			return processResult{}
		})
		if _, err := keyring.Get(ctx, "account"); !errors.Is(err, context.Canceled) {
			t.Fatalf("Get() error = %v, want %v", err, context.Canceled)
		}
	})

	t.Run("delete operation error", func(t *testing.T) {
		want := errors.New("execution failed")
		keyring := testKeyring(func(context.Context, string, []byte) processResult {
			return processResult{err: want}
		})
		err := keyring.Delete(context.Background(), "account")
		if !errors.Is(err, api.ErrBackendUnavailable) || !errors.Is(err, want) {
			t.Fatalf("Delete() error = %v, want %v and %v", err, api.ErrBackendUnavailable, want)
		}
	})

	t.Run("unconfigured", func(t *testing.T) {
		var keyring *Keyring
		if _, err := keyring.invoke(context.Background(), operationGet, "account", nil); !errors.Is(err, ErrInternal) {
			t.Fatalf("invoke() error = %v, want %v", err, ErrInternal)
		}
	})

	t.Run("invalid timeout", func(t *testing.T) {
		keyring := testKeyring(successfulRunner(t))
		keyring.timeout = 0
		if _, err := keyring.invoke(context.Background(), operationGet, "account", nil); !errors.Is(err, ErrInternal) {
			t.Fatalf("invoke() error = %v, want %v", err, ErrInternal)
		}
	})

	t.Run("request id failure", func(t *testing.T) {
		want := errors.New("random source failed")
		keyring := testKeyring(successfulRunner(t))
		keyring.requestID = func() (string, error) { return "", want }
		_, err := keyring.invoke(context.Background(), operationGet, "account", nil)
		if !errors.Is(err, ErrInternal) || !errors.Is(err, want) {
			t.Fatalf("invoke() error = %v, want %v and %v", err, ErrInternal, want)
		}
	})

	t.Run("empty request id", func(t *testing.T) {
		keyring := testKeyring(successfulRunner(t))
		keyring.requestID = func() (string, error) { return "", nil }
		if _, err := keyring.invoke(context.Background(), operationGet, "account", nil); !errors.Is(err, ErrInternal) {
			t.Fatalf("invoke() error = %v, want %v", err, ErrInternal)
		}
	})

	t.Run("request encoding failure", func(t *testing.T) {
		want := errors.New("encoding failed")
		keyring := testKeyring(successfulRunner(t))
		keyring.encode = func(request) ([]byte, error) { return nil, want }
		_, err := keyring.Get(context.Background(), "account")
		if !errors.Is(err, ErrInternal) || !errors.Is(err, want) {
			t.Fatalf("Get() error = %v, want %v and %v", err, ErrInternal, want)
		}
	})

	t.Run("invalid account", func(t *testing.T) {
		keyring := testKeyring(successfulRunner(t))
		if _, err := keyring.Get(context.Background(), ""); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("Get() error = %v, want %v", err, ErrInvalidArgument)
		}
	})

	t.Run("oversized request", func(t *testing.T) {
		keyring := testKeyring(successfulRunner(t))
		keyring.service = strings.Repeat("s", maxMessageBytes)
		if _, err := keyring.Get(context.Background(), "account"); !errors.Is(err, ErrValueTooLarge) {
			t.Fatalf("Get() error = %v, want %v", err, ErrValueTooLarge)
		}
	})

	t.Run("timeout", func(t *testing.T) {
		keyring := testKeyring(func(ctx context.Context, _ string, _ []byte) processResult {
			<-ctx.Done()
			return processResult{}
		})
		keyring.timeout = time.Millisecond
		_, err := keyring.Get(context.Background(), "account")
		if !errors.Is(err, ErrTimeout) || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Get() error = %v, want %v and %v", err, ErrTimeout, context.DeadlineExceeded)
		}
	})

	t.Run("process failure", func(t *testing.T) {
		want := errors.New("execution failed")
		keyring := testKeyring(func(context.Context, string, []byte) processResult {
			return processResult{err: want}
		})
		_, err := keyring.Get(context.Background(), "account")
		if !errors.Is(err, ErrBackendUnavailable) || !errors.Is(err, want) {
			t.Fatalf("Get() error = %v, want %v and %v", err, ErrBackendUnavailable, want)
		}
	})

	t.Run("process protocol failure", func(t *testing.T) {
		keyring := testKeyring(func(context.Context, string, []byte) processResult {
			return processResult{err: ErrProtocol}
		})
		_, err := keyring.Get(context.Background(), "account")
		if !errors.Is(err, ErrProtocol) || errors.Is(err, ErrBackendUnavailable) {
			t.Fatalf("Get() error = %v, want only %v", err, ErrProtocol)
		}
	})

	t.Run("operation error exit code", func(t *testing.T) {
		keyring := testKeyring(func(_ context.Context, _ string, input []byte) processResult {
			request := decodeTestRequest(t, input)
			return encodedResponse(t, response{
				Protocol:  request.Protocol,
				RequestID: request.RequestID,
				Error: &ProtocolError{
					Code:    errInternal,
					Message: "failed",
				},
			}, 2)
		})
		if _, err := keyring.Get(context.Background(), "account"); !errors.Is(err, ErrProtocol) {
			t.Fatalf("Get() error = %v, want %v", err, ErrProtocol)
		}
	})

}

func TestKeyringProtocolError(t *testing.T) {
	keyring := testKeyring(func(_ context.Context, _ string, input []byte) processResult {
		request := decodeTestRequest(t, input)
		return encodedResponse(t, response{
			Protocol:  request.Protocol,
			RequestID: request.RequestID,
			Error: &ProtocolError{
				Code:    errAccessDenied,
				Message: "credential access was denied",
			},
		}, exitOperationError)
	})

	_, err := keyring.Get(context.Background(), "account")
	var protocolErr *ProtocolError
	if !errors.As(err, &protocolErr) {
		t.Fatalf("Get() error type = %T, want *ProtocolError", err)
	}
	if protocolErr.Code != errAccessDenied {
		t.Fatalf("error code = %q", protocolErr.Code)
	}
	if !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("Get() error = %v, want %v", err, ErrAccessDenied)
	}
}

func testKeyring(runner runFunc) *Keyring {
	return &Keyring{
		service:    "test-service",
		helperPath: "/windows/keyring-winbridge.exe",
		timeout:    time.Second,
		run:        runner,
		requestID: func() (string, error) {
			return "test-request", nil
		},
		encode: encodeRequest,
	}
}

func successfulRunner(t *testing.T) runFunc {
	t.Helper()
	return func(_ context.Context, _ string, input []byte) processResult {
		request := decodeTestRequest(t, input)
		if request.Operation != operationProbe {
			t.Fatalf("operation = %q, want probe", request.Operation)
		}
		return encodedResponse(t, response{
			Protocol:  request.Protocol,
			RequestID: request.RequestID,
			OK:        true,
			Result:    successfulProbeResult(),
		}, exitSuccess)
	}
}

func successfulProbeResult() *result {
	return &result{
		HelperVersion:      "0.1.0",
		SupportedProtocols: []string{protocolID},
		Backend:            backendName,
	}
}

func decodeTestRequest(t *testing.T, contents []byte) request {
	t.Helper()
	var request request
	if err := json.Unmarshal(contents, &request); err != nil {
		t.Fatalf("decode request: %v", err)
	}
	return request
}

func encodedResponse(t *testing.T, response response, exitCode int) processResult {
	t.Helper()
	contents, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("encode response: %v", err)
	}
	return processResult{output: append(contents, '\n'), exitCode: exitCode}
}
