//go:build linux

package wsl2

import (
	"errors"
	"fmt"
)

var (
	// ErrNotWSL2 reports that the current Linux kernel is not a WSL2 kernel.
	ErrNotWSL2 = errors.New("not running inside WSL2")

	// ErrInvalidRequest reports that the helper rejected the request envelope.
	ErrInvalidRequest = errors.New("invalid request")
	// ErrUnsupportedProtocol reports that the helper does not support protocolID.
	ErrUnsupportedProtocol = errors.New("unsupported protocol")
	// ErrUnsupportedOperation reports that the helper does not support an operation.
	ErrUnsupportedOperation = errors.New("unsupported operation")
	// ErrInvalidArgument reports that a request argument is invalid.
	ErrInvalidArgument = errors.New("invalid argument")
	// ErrNotFound reports that the requested credential does not exist.
	ErrNotFound = errors.New("credential not found")
	// ErrAccessDenied reports that Windows denied access to the credential.
	ErrAccessDenied = errors.New("credential access denied")
	// ErrBackendUnavailable reports that Windows Credential Manager is unavailable.
	ErrBackendUnavailable = errors.New("credential backend unavailable")
	// ErrHelperNotFound reports that keyring-winbridge.exe was not found.
	// It also matches [ErrBackendUnavailable].
	ErrHelperNotFound = fmt.Errorf("%w: keyring-winbridge executable not found", ErrBackendUnavailable)
	// ErrBackendFailure reports an unexpected Windows Credential Manager failure.
	ErrBackendFailure = errors.New("credential backend failure")
	// ErrTimeout reports that an operation timed out.
	ErrTimeout = errors.New("credential operation timed out")
	// ErrInternal reports an unexpected helper failure.
	ErrInternal = errors.New("internal helper error")
	// ErrValueTooLarge reports that a request or secret exceeds a protocol limit.
	ErrValueTooLarge = errors.New("value too large")
	// ErrProtocol reports a malformed or inconsistent helper response.
	ErrProtocol = errors.New("invalid helper protocol response")
)

// ProtocolError is an operation error returned by keyring-winbridge.
//
// Use [errors.Is] to inspect its stable category and [errors.As] when the
// helper-provided message, retryability, or supported protocols are needed.
type ProtocolError struct {
	Code               string   `json:"code"`
	Message            string   `json:"message"`
	Retryable          bool     `json:"retryable"`
	SupportedProtocols []string `json:"supported_protocols,omitempty"`
}

func (e *ProtocolError) Error() string {
	if e == nil {
		return ""
	}
	if e.Message == "" {
		return e.Code
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap exposes the stable error category represented by Code.
func (e *ProtocolError) Unwrap() error {
	if e == nil {
		return nil
	}
	return sentinelForCode(e.Code)
}

func sentinelForCode(code string) error {
	switch code {
	case errInvalidRequest:
		return ErrInvalidRequest
	case errUnsupportedProtocol:
		return ErrUnsupportedProtocol
	case errUnsupportedOperation:
		return ErrUnsupportedOperation
	case errInvalidArgument:
		return ErrInvalidArgument
	case errNotFound:
		return ErrNotFound
	case errAccessDenied:
		return ErrAccessDenied
	case errBackendUnavailable:
		return ErrBackendUnavailable
	case errBackendFailure:
		return ErrBackendFailure
	case errTimeout:
		return ErrTimeout
	case errInternal:
		return ErrInternal
	default:
		return nil
	}
}
