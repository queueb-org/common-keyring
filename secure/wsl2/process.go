//go:build linux

package wsl2

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"

	"common.queueb.org/keyring/internal/iox"
)

type processResult struct {
	output   []byte
	exitCode int
	err      error
}

type runFunc func(context.Context, string, []byte) processResult

func run(ctx context.Context, helperPath string, input []byte) processResult {
	command := exec.CommandContext(ctx, helperPath)
	command.Stdin = bytes.NewReader(input)
	command.Stderr = io.Discard

	output := iox.NewLimitedBuffer(maxMessageBytes)
	command.Stdout = output
	err := command.Run()
	if output.Overflow() {
		return processResult{
			exitCode: -1,
			err:      fmt.Errorf("%w: response exceeds %d bytes", ErrProtocol, maxMessageBytes),
		}
	}
	if err == nil {
		return processResult{output: output.Bytes(), exitCode: 0}
	}
	if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
		return processResult{output: output.Bytes(), exitCode: exitErr.ExitCode()}
	}
	return processResult{output: output.Bytes(), exitCode: -1, err: err}
}
