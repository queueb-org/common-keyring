package darwin

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"os/exec"
	"strings"

	"common.queueb.org/keyring/internal/contract"

	"github.com/alessio/shellescape"
)

const (
	securityPath         = "/usr/bin/security"
	legacyEncodingPrefix = "go-keyring-encoded:"
	base64Prefix         = "go-keyring-base64:"
	commandLimit         = 4096
)

type commandFunc func(context.Context, io.Reader, ...string) ([]byte, error)

// Keep command execution behind variables intentionally so unit tests can
// exercise the adapter without invoking the host's Keychain tooling.
var (
	executeCommand = commandFunc(runCommand)
	commandContext = exec.CommandContext
)

// Get returns a value from macOS Keychain and terminates the security process
// when ctx ends.
func Get(ctx context.Context, service, key string) ([]byte, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	output, err := executeCommand(
		ctx,
		nil,
		"find-generic-password",
		"-s", service,
		"-wa", key,
	)
	if err != nil {
		return nil, keychainError(ctx, "get credential", output, err)
	}
	return decodeValue(strings.TrimSpace(string(output)))
}

// Set stores a value in macOS Keychain and terminates the security process
// when ctx ends.
func Set(ctx context.Context, service, key string, value []byte) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	encoded := base64Prefix + base64.StdEncoding.EncodeToString(value)
	command := fmt.Sprintf(
		"add-generic-password -U -s %s -a %s -w %s\n",
		shellescape.Quote(service),
		shellescape.Quote(key),
		shellescape.Quote(encoded),
	)
	if len(command) > commandLimit {
		return fmt.Errorf("%w: macOS security command exceeds %d bytes", contract.ErrValueTooLarge, commandLimit)
	}

	output, err := executeCommand(ctx, strings.NewReader(command), "-i")
	return keychainError(ctx, "set credential", output, err)
}

// Delete removes a value from macOS Keychain and terminates the security
// process when ctx ends.
func Delete(ctx context.Context, service, key string) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	output, err := executeCommand(
		ctx,
		nil,
		"delete-generic-password",
		"-s", service,
		"-a", key,
	)
	return keychainError(ctx, "delete credential", output, err)
}

func runCommand(ctx context.Context, input io.Reader, arguments ...string) ([]byte, error) {
	cmd := commandContext(ctx, securityPath, arguments...)
	cmd.Stdin = input
	return cmd.CombinedOutput()
}
