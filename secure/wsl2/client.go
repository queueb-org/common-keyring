//go:build linux

package wsl2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"common.queueb.org/keyring/internal/contract"
)

type encodeFunc func(request) ([]byte, error)

func encodeRequest(request request) ([]byte, error) {
	return json.Marshal(request)
}

func (k *Keyring) invoke(
	parent context.Context,
	operation string,
	account string,
	secret *string,
) (*result, error) {
	if err := contract.ContextError(parent); err != nil {
		return nil, err
	}
	if k == nil || k.run == nil || k.requestID == nil || k.encode == nil || k.helperPath == "" {
		return nil, fmt.Errorf("%w: client is not configured", ErrInternal)
	}
	if k.timeout <= 0 {
		return nil, fmt.Errorf("%w: timeout is not configured", ErrInternal)
	}

	requestID, err := k.requestID()
	if err != nil {
		return nil, fmt.Errorf("%w: generate request id: %w", ErrInternal, err)
	}
	if requestID == "" {
		return nil, fmt.Errorf("%w: request id is empty", ErrInternal)
	}

	request := request{
		Protocol:  protocolID,
		RequestID: requestID,
		Operation: operation,
		Secret:    secret,
	}
	if operation != operationProbe {
		request.Service = k.service
		request.Account = account
	}
	if err := validateRequest(request); err != nil {
		return nil, err
	}

	input, err := k.encode(request)
	if err != nil {
		return nil, fmt.Errorf("%w: encode request: %w", ErrInternal, err)
	}
	input = append(input, '\n')
	if len(input) > maxMessageBytes {
		return nil, fmt.Errorf("%w: request exceeds %d bytes", ErrValueTooLarge, maxMessageBytes)
	}

	ctx, cancel := context.WithTimeout(parent, k.timeout)
	defer cancel()
	process := k.run(ctx, k.helperPath, input)
	if ctxErr := ctx.Err(); ctxErr != nil {
		if errors.Is(ctxErr, context.Canceled) {
			return nil, ctxErr
		}
		return nil, fmt.Errorf("%w: run keyring-winbridge: %w", ErrTimeout, ctxErr)
	}
	if process.err != nil {
		if errors.Is(process.err, ErrProtocol) {
			return nil, process.err
		}
		if operation == operationProbe {
			return nil, fmt.Errorf("%w: run keyring-winbridge: %w", ErrBackendFailure, process.err)
		}
		return nil, fmt.Errorf("%w: run keyring-winbridge: %w", ErrBackendUnavailable, process.err)
	}

	response, err := decodeResponse(process.output, request)
	if err != nil {
		return nil, err
	}
	if response.OK {
		if process.exitCode != exitSuccess {
			return nil, fmt.Errorf(
				"%w: helper returned success with exit code %d",
				ErrProtocol,
				process.exitCode,
			)
		}
		return response.Result, nil
	}
	if process.exitCode != exitOperationError {
		return nil, fmt.Errorf(
			"%w: helper returned an operation error with exit code %d",
			ErrProtocol,
			process.exitCode,
		)
	}
	return nil, response.Error
}
