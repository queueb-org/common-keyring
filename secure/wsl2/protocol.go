//go:build linux

package wsl2

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
)

const (
	protocolID  = "keyring-winbridge/v1alpha1"
	backendName = "windows-credential-manager"

	operationProbe  = "probe"
	operationGet    = "get"
	operationSet    = "set"
	operationDelete = "delete"

	errInvalidRequest       = "invalid_request"
	errUnsupportedProtocol  = "unsupported_protocol"
	errUnsupportedOperation = "unsupported_operation"
	errInvalidArgument      = "invalid_argument"
	errNotFound             = "not_found"
	errAccessDenied         = "access_denied"
	errBackendUnavailable   = "backend_unavailable"
	errBackendFailure       = "backend_failure"
	errTimeout              = "timeout"
	errInternal             = "internal"

	exitSuccess        = 0
	exitOperationError = 1

	maxMessageBytes = 1 << 20
	maxSecretBytes  = 5 * 512
)

type request struct {
	Protocol  string  `json:"protocol"`
	RequestID string  `json:"request_id"`
	Operation string  `json:"operation"`
	Service   string  `json:"service,omitempty"`
	Account   string  `json:"account,omitempty"`
	Secret    *string `json:"secret_b64,omitempty"`
}

type response struct {
	Protocol  string         `json:"protocol"`
	RequestID string         `json:"request_id,omitempty"`
	OK        bool           `json:"ok"`
	Result    *result        `json:"result,omitempty"`
	Error     *ProtocolError `json:"error,omitempty"`
}

type result struct {
	HelperVersion      string   `json:"helper_version,omitempty"`
	SupportedProtocols []string `json:"supported_protocols,omitempty"`
	Backend            string   `json:"backend,omitempty"`
	Secret             *string  `json:"secret_b64,omitempty"`
	Deleted            *bool    `json:"deleted,omitempty"`
	secret             []byte
}

func newRequestID(random io.Reader) (string, error) {
	var value [16]byte
	if _, err := io.ReadFull(random, value[:]); err != nil {
		return "", fmt.Errorf("generate request id: %w", err)
	}
	return hex.EncodeToString(value[:]), nil
}

func validateRequest(request request) error {
	if request.Service == "" && request.Operation != operationProbe {
		return fmt.Errorf("%w: service is empty", ErrInvalidArgument)
	}
	if strings.IndexByte(request.Service, 0) >= 0 {
		return fmt.Errorf("%w: service contains a NUL character", ErrInvalidArgument)
	}
	if request.Account == "" && request.Operation != operationProbe {
		return fmt.Errorf("%w: account is empty", ErrInvalidArgument)
	}
	if strings.IndexByte(request.Account, 0) >= 0 {
		return fmt.Errorf("%w: account contains a NUL character", ErrInvalidArgument)
	}

	switch request.Operation {
	case operationProbe:
		if request.Service != "" || request.Account != "" || request.Secret != nil {
			return fmt.Errorf("%w: probe contains credential fields", ErrInternal)
		}
	case operationGet, operationDelete:
		if request.Secret != nil {
			return fmt.Errorf("%w: %s request contains a secret", ErrInternal, request.Operation)
		}
	case operationSet:
		if request.Secret == nil {
			return fmt.Errorf("%w: set request secret is missing", ErrInternal)
		}
	default:
		return fmt.Errorf("%w: unsupported operation %q", ErrInternal, request.Operation)
	}
	return nil
}

func decodeResponse(output []byte, request request) (*response, error) {
	if len(output) == 0 {
		return nil, fmt.Errorf("%w: empty response", ErrProtocol)
	}
	if len(output) > maxMessageBytes {
		return nil, fmt.Errorf("%w: response exceeds %d bytes", ErrProtocol, maxMessageBytes)
	}

	var response response
	if err := json.Unmarshal(output, &response); err != nil {
		return nil, fmt.Errorf("%w: decode response: %w", ErrProtocol, err)
	}
	if response.Protocol != request.Protocol {
		return nil, fmt.Errorf("%w: response protocol does not match request", ErrProtocol)
	}
	if response.RequestID != request.RequestID {
		return nil, fmt.Errorf("%w: response request id does not match request", ErrProtocol)
	}
	if response.OK {
		if response.Result == nil || response.Error != nil {
			return nil, fmt.Errorf("%w: invalid successful response", ErrProtocol)
		}
		if err := validateResult(request.Operation, response.Result); err != nil {
			return nil, err
		}
		return &response, nil
	}
	if response.Result != nil || response.Error == nil {
		return nil, fmt.Errorf("%w: invalid failed response", ErrProtocol)
	}
	if err := validateProtocolError(response.Error); err != nil {
		return nil, err
	}
	return &response, nil
}

func validateResult(operation string, result *result) error {
	hasProbeFields := result.HelperVersion != "" ||
		result.SupportedProtocols != nil || result.Backend != ""

	switch operation {
	case operationProbe:
		if result.HelperVersion == "" || result.Backend != backendName ||
			!slices.Contains(result.SupportedProtocols, protocolID) ||
			result.Secret != nil || result.Deleted != nil {
			return fmt.Errorf("%w: invalid probe result", ErrProtocol)
		}
	case operationGet:
		if result.Secret == nil || result.Deleted != nil || hasProbeFields {
			return fmt.Errorf("%w: invalid get result", ErrProtocol)
		}
		secret, err := base64.StdEncoding.Strict().DecodeString(*result.Secret)
		if err != nil {
			return fmt.Errorf("%w: invalid secret encoding: %w", ErrProtocol, err)
		}
		if len(secret) > maxSecretBytes {
			return fmt.Errorf("%w: response secret exceeds %d bytes", ErrProtocol, maxSecretBytes)
		}
		result.secret = secret
	case operationSet:
		if result.Secret != nil || result.Deleted != nil || hasProbeFields {
			return fmt.Errorf("%w: invalid set result", ErrProtocol)
		}
	case operationDelete:
		if result.Deleted == nil || result.Secret != nil || hasProbeFields {
			return fmt.Errorf("%w: invalid delete result", ErrProtocol)
		}
	default:
		return fmt.Errorf("%w: unsupported response operation %q", ErrInternal, operation)
	}
	return nil
}

func validateProtocolError(protocolErr *ProtocolError) error {
	if protocolErr.Code == "" || protocolErr.Message == "" {
		return fmt.Errorf("%w: invalid operation error", ErrProtocol)
	}
	if !validErrorCode(protocolErr.Code) {
		return fmt.Errorf("%w: unknown error code %q", ErrProtocol, protocolErr.Code)
	}
	if protocolErr.Code == errUnsupportedProtocol {
		if len(protocolErr.SupportedProtocols) == 0 {
			return fmt.Errorf("%w: unsupported protocol response has no supported protocols", ErrProtocol)
		}
	} else if len(protocolErr.SupportedProtocols) != 0 {
		return fmt.Errorf("%w: unexpected supported protocols in operation error", ErrProtocol)
	}
	return nil
}

func validErrorCode(code string) bool {
	return sentinelForCode(code) != nil
}
