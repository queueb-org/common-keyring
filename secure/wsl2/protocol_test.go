//go:build linux

package wsl2

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestValidateRequest(t *testing.T) {
	secret := "c2VjcmV0"
	tests := []struct {
		name string
		req  request
		want error
	}{
		{name: "probe", req: request{Operation: operationProbe}},
		{name: "get", req: request{Operation: operationGet, Service: "service", Account: "account"}},
		{name: "delete", req: request{Operation: operationDelete, Service: "service", Account: "account"}},
		{name: "set", req: request{Operation: operationSet, Service: "service", Account: "account", Secret: &secret}},
		{name: "empty service", req: request{Operation: operationGet, Account: "account"}, want: ErrInvalidArgument},
		{name: "service NUL", req: request{Operation: operationGet, Service: "bad\x00service", Account: "account"}, want: ErrInvalidArgument},
		{name: "empty account", req: request{Operation: operationGet, Service: "service"}, want: ErrInvalidArgument},
		{name: "account NUL", req: request{Operation: operationGet, Service: "service", Account: "bad\x00account"}, want: ErrInvalidArgument},
		{name: "probe fields", req: request{Operation: operationProbe, Service: "service"}, want: ErrInternal},
		{name: "get secret", req: request{Operation: operationGet, Service: "service", Account: "account", Secret: &secret}, want: ErrInternal},
		{name: "delete secret", req: request{Operation: operationDelete, Service: "service", Account: "account", Secret: &secret}, want: ErrInternal},
		{name: "set without secret", req: request{Operation: operationSet, Service: "service", Account: "account"}, want: ErrInternal},
		{name: "unknown operation", req: request{Operation: "future", Service: "service", Account: "account"}, want: ErrInternal},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateRequest(test.req)
			if test.want == nil && err != nil {
				t.Fatalf("validateRequest() error = %v", err)
			}
			if test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("validateRequest() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestRejectsInvalidResponses(t *testing.T) {
	tests := []struct {
		name     string
		response func(request) ([]byte, int)
	}{
		{
			name: "empty response",
			response: func(request) ([]byte, int) {
				return nil, exitSuccess
			},
		},
		{
			name: "oversized response",
			response: func(request) ([]byte, int) {
				return make([]byte, maxMessageBytes+1), exitSuccess
			},
		},
		{
			name: "invalid JSON",
			response: func(request) ([]byte, int) {
				return []byte("not-json"), exitSuccess
			},
		},
		{
			name: "mismatched protocol",
			response: func(request request) ([]byte, int) {
				output, _ := json.Marshal(response{
					Protocol:  "different",
					RequestID: request.RequestID,
					OK:        true,
					Result:    &result{Secret: new("c2VjcmV0")},
				})
				return output, exitSuccess
			},
		},
		{
			name: "mismatched request id",
			response: func(request request) ([]byte, int) {
				output, _ := json.Marshal(response{
					Protocol:  request.Protocol,
					RequestID: "different",
					OK:        true,
					Result:    &result{Secret: new("c2VjcmV0")},
				})
				return output, exitSuccess
			},
		},
		{
			name: "success without result",
			response: func(request request) ([]byte, int) {
				return encodedJSON(t, response{
					Protocol:  request.Protocol,
					RequestID: request.RequestID,
					OK:        true,
				}), exitSuccess
			},
		},
		{
			name: "success with error",
			response: func(request request) ([]byte, int) {
				return encodedJSON(t, response{
					Protocol:  request.Protocol,
					RequestID: request.RequestID,
					OK:        true,
					Result:    &result{Secret: new("c2VjcmV0")},
					Error:     &ProtocolError{Code: errInternal, Message: "failure"},
				}), exitSuccess
			},
		},
		{
			name: "failure with result",
			response: func(request request) ([]byte, int) {
				return encodedJSON(t, response{
					Protocol:  request.Protocol,
					RequestID: request.RequestID,
					Result:    &result{},
					Error:     &ProtocolError{Code: errInternal, Message: "failure"},
				}), exitOperationError
			},
		},
		{
			name: "failure without error",
			response: func(request request) ([]byte, int) {
				return encodedJSON(t, response{
					Protocol:  request.Protocol,
					RequestID: request.RequestID,
				}), exitOperationError
			},
		},
		{
			name: "invalid get result",
			response: func(request request) ([]byte, int) {
				return encodedJSON(t, response{
					Protocol:  request.Protocol,
					RequestID: request.RequestID,
					OK:        true,
					Result:    &result{},
				}), exitSuccess
			},
		},
		{
			name: "success with operation exit",
			response: func(request request) ([]byte, int) {
				output, _ := json.Marshal(response{
					Protocol:  request.Protocol,
					RequestID: request.RequestID,
					OK:        true,
					Result:    &result{Secret: new("c2VjcmV0")},
				})
				return output, exitOperationError
			},
		},
		{
			name: "unknown error code",
			response: func(request request) ([]byte, int) {
				output, _ := json.Marshal(response{
					Protocol:  request.Protocol,
					RequestID: request.RequestID,
					Error: &ProtocolError{
						Code:    "future_error",
						Message: "future error",
					},
				})
				return output, exitOperationError
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			keyring := testKeyring(func(
				_ context.Context,
				_ string,
				input []byte,
			) processResult {
				request := decodeTestRequest(t, input)
				output, exitCode := test.response(request)
				return processResult{output: output, exitCode: exitCode}
			})
			if _, err := keyring.Get(context.Background(), "account"); !errors.Is(err, ErrProtocol) {
				t.Fatalf("Get() error = %v, want %v", err, ErrProtocol)
			}
		})
	}
}

func TestValidateResult(t *testing.T) {
	encodedSecret := base64.StdEncoding.EncodeToString([]byte("secret"))
	oversizedSecret := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", maxSecretBytes+1)))
	deleted := true
	tests := []struct {
		name      string
		operation string
		result    *result
		want      error
	}{
		{name: "probe", operation: operationProbe, result: successfulProbeResult()},
		{name: "invalid probe", operation: operationProbe, result: &result{}, want: ErrProtocol},
		{name: "get", operation: operationGet, result: &result{Secret: &encodedSecret}},
		{name: "get without secret", operation: operationGet, result: &result{}, want: ErrProtocol},
		{name: "get invalid base64", operation: operationGet, result: &result{Secret: new("!")}, want: ErrProtocol},
		{name: "get oversized", operation: operationGet, result: &result{Secret: &oversizedSecret}, want: ErrProtocol},
		{name: "set", operation: operationSet, result: &result{}},
		{name: "invalid set", operation: operationSet, result: &result{Secret: &encodedSecret}, want: ErrProtocol},
		{name: "delete", operation: operationDelete, result: &result{Deleted: &deleted}},
		{name: "invalid delete", operation: operationDelete, result: &result{}, want: ErrProtocol},
		{name: "unknown operation", operation: "future", result: &result{}, want: ErrInternal},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateResult(test.operation, test.result)
			if test.want == nil && err != nil {
				t.Fatalf("validateResult() error = %v", err)
			}
			if test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("validateResult() error = %v, want %v", err, test.want)
			}
			if test.name == "get" && string(test.result.secret) != "secret" {
				t.Fatalf("decoded secret = %q, want secret", test.result.secret)
			}
		})
	}
}

func TestValidateProtocolError(t *testing.T) {
	tests := []struct {
		name string
		err  *ProtocolError
		want error
	}{
		{name: "valid", err: &ProtocolError{Code: errInternal, Message: "failure"}},
		{name: "valid unsupported protocol", err: &ProtocolError{Code: errUnsupportedProtocol, Message: "unsupported", SupportedProtocols: []string{"future"}}},
		{name: "missing code", err: &ProtocolError{Message: "failure"}, want: ErrProtocol},
		{name: "missing message", err: &ProtocolError{Code: errInternal}, want: ErrProtocol},
		{name: "unknown code", err: &ProtocolError{Code: "future", Message: "failure"}, want: ErrProtocol},
		{name: "missing supported protocols", err: &ProtocolError{Code: errUnsupportedProtocol, Message: "unsupported"}, want: ErrProtocol},
		{name: "unexpected supported protocols", err: &ProtocolError{Code: errInternal, Message: "failure", SupportedProtocols: []string{protocolID}}, want: ErrProtocol},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateProtocolError(test.err)
			if test.want == nil && err != nil {
				t.Fatalf("validateProtocolError() error = %v", err)
			}
			if test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("validateProtocolError() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestNewRequestID(t *testing.T) {
	first, err := newRequestID(rand.Reader)
	if err != nil {
		t.Fatalf("newRequestID() error = %v", err)
	}
	second, err := newRequestID(rand.Reader)
	if err != nil {
		t.Fatalf("newRequestID() error = %v", err)
	}
	if len(first) != 32 || len(second) != 32 || first == second {
		t.Fatalf("request ids = %q and %q", first, second)
	}

	want := errors.New("random source failed")
	if _, err := newRequestID(errorReader{err: want}); !errors.Is(err, want) {
		t.Fatalf("newRequestID() error = %v, want %v", err, want)
	}
}

func encodedJSON(t *testing.T, value any) []byte {
	t.Helper()
	output, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("encode JSON: %v", err)
	}
	return output
}

type errorReader struct {
	err error
}

func (r errorReader) Read([]byte) (int, error) {
	return 0, r.err
}
