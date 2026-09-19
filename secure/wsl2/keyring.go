//go:build linux

package wsl2

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	api "common.queueb.org/keyring"
	"common.queueb.org/keyring/internal/contract"
)

const (
	executableName = "keyring-winbridge.exe"
	defaultTimeout = 15 * time.Second
)

var (
	readKernelRelease = func() ([]byte, error) {
		return os.ReadFile("/proc/sys/kernel/osrelease")
	}
	lookPath           = exec.LookPath
	runProcess runFunc = run
)

// IsWSL2 reports whether the current system is running a WSL2 kernel.
// Its default implementation inspects the current Linux kernel release.
var IsWSL2 = isWSL2

// Keyring implements [api.Keyringer] through keyring-winbridge.exe.
type Keyring struct {
	service    string
	helperPath string
	timeout    time.Duration
	run        runFunc
	requestID  func() (string, error)
	encode     encodeFunc
}

var _ api.Keyringer = (*Keyring)(nil)

// New discovers and probes keyring-winbridge.exe inside WSL2.
func New(ctx context.Context, service string) (*Keyring, error) {
	if err := contract.ContextError(ctx); err != nil {
		return nil, err
	}
	if service == "" {
		return nil, portableError(fmt.Errorf("%w: service is empty", ErrInvalidArgument))
	}
	if strings.IndexByte(service, 0) >= 0 {
		return nil, portableError(fmt.Errorf("%w: service contains a NUL character", ErrInvalidArgument))
	}

	if !IsWSL2() {
		return nil, portableError(ErrNotWSL2)
	}

	helperPath, err := lookPath(executableName)
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return nil, portableError(fmt.Errorf("%w: find %s: %w", ErrHelperNotFound, executableName, err))
		}
		return nil, portableError(fmt.Errorf("%w: find %s: %w", ErrBackendFailure, executableName, err))
	}

	keyring := &Keyring{
		service:    service,
		helperPath: helperPath,
		timeout:    defaultTimeout,
		run:        runProcess,
		requestID: func() (string, error) {
			return newRequestID(rand.Reader)
		},
		encode: encodeRequest,
	}
	if err := keyring.probe(ctx); err != nil {
		return nil, portableError(fmt.Errorf("probe %s: %w", executableName, err))
	}
	return keyring, nil
}

// isWSL2 implements a check if we operate in WSL2 environment.
func isWSL2() bool {
	release, err := readKernelRelease()
	return err == nil && isKernelRelease(release)
}

// isKernelRelease reports whether release identifies a WSL2 kernel.
func isKernelRelease(release []byte) bool {
	normalized := strings.ToLower(string(bytes.TrimSpace(release)))
	return strings.Contains(normalized, "microsoft-standard-wsl2") ||
		strings.Contains(normalized, "wsl2")
}

func (k *Keyring) probe(ctx context.Context) error {
	_, err := k.invoke(ctx, operationProbe, "", nil)
	return err
}

// Get implements [api.Keyringer] through Windows Credential Manager.
func (k *Keyring) Get(ctx context.Context, username string) ([]byte, error) {
	result, err := k.invoke(ctx, operationGet, username, nil)
	if err != nil {
		return nil, portableError(err)
	}
	return result.secret, nil
}

// Set implements [api.Keyringer] through Windows Credential Manager.
func (k *Keyring) Set(ctx context.Context, username string, password []byte) error {
	if len(password) > maxSecretBytes {
		return portableError(fmt.Errorf("%w: secret exceeds %d bytes", ErrValueTooLarge, maxSecretBytes))
	}
	secret := base64.StdEncoding.EncodeToString(password)
	_, err := k.invoke(ctx, operationSet, username, &secret)
	return portableError(err)
}

// Delete implements [api.Keyringer] through Windows Credential Manager.
func (k *Keyring) Delete(ctx context.Context, username string) error {
	result, err := k.invoke(ctx, operationDelete, username, nil)
	if err != nil {
		return portableError(err)
	}
	if result.Deleted == nil || !*result.Deleted {
		return portableError(ErrNotFound)
	}
	return nil
}

func portableError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) {
		return err
	}
	var category error
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, ErrTimeout):
		category = api.ErrTimeout
	case errors.Is(err, ErrNotFound):
		category = api.ErrNotFound
	case errors.Is(err, ErrInvalidArgument):
		category = api.ErrInvalidArgument
	case errors.Is(err, ErrValueTooLarge):
		category = api.ErrValueTooLarge
	case errors.Is(err, ErrBackendUnavailable):
		category = api.ErrBackendUnavailable
	case errors.Is(err, ErrAccessDenied):
		category = api.ErrPermissionDenied
	case errors.Is(err, ErrUnsupportedProtocol),
		errors.Is(err, ErrUnsupportedOperation),
		errors.Is(err, ErrNotWSL2):
		category = api.ErrUnsupported
	default:
		category = api.ErrBackendFailure
	}
	return fmt.Errorf("%w: %w", category, err)
}
