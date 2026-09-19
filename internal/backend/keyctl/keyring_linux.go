//go:build linux

package keyctl

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"

	"common.queueb.org/keyring/internal/contract"

	"golang.org/x/sys/unix"
)

const userKeyPayloadLimit = 32767

var (
	getKeyringID   = unix.KeyctlGetKeyringID
	searchKey      = unix.KeyctlSearch
	addKey         = unix.AddKey
	keyctlBuffer   = unix.KeyctlBuffer
	keyctlInt      = unix.KeyctlInt
	getKeyContents = readKeyContents
)

// Keyring stores values in the Linux user-session keyring.
type Keyring struct {
	session int
	service string
}

var _ contract.Keyringer = (*Keyring)(nil)

// Open accesses the user-session keyring and returns a namespaced Keyring.
func Open(service string) (*Keyring, error) {
	session, err := getKeyringID(unix.KEY_SPEC_USER_SESSION_KEYRING, true)
	if err != nil {
		return nil, probeError(err)
	}
	return &Keyring{session: session, service: service}, nil
}

func (k *Keyring) key(key string) string {
	return keyName(k.service, key)
}

func keyName(service, key string) string {
	digest := sha256.New()
	_, _ = digest.Write([]byte("common.queueb.org/keyring:kernel:v1\x00service\x00"))
	_, _ = digest.Write([]byte(service))
	_, _ = digest.Write([]byte("\x00key\x00"))
	_, _ = digest.Write([]byte(key))
	return "keyring:v1:" + hex.EncodeToString(digest.Sum(nil))
}

func (k *Keyring) get(key string) (int, error) {
	return searchKey(k.session, "user", k.key(key), 0)
}

// Get implements [contract.Keyringer].
func (k *Keyring) Get(ctx context.Context, key string) ([]byte, error) {
	if err := contract.ContextError(ctx); err != nil {
		return nil, err
	}
	credential, err := k.get(key)
	if err != nil {
		return nil, operationError("find credential", err)
	}
	value, err := getKeyContents(credential)
	if err != nil {
		return nil, operationError("get credential", err)
	}
	return value, nil
}

// Set implements [contract.Keyringer].
func (k *Keyring) Set(ctx context.Context, key string, value []byte) error {
	if err := contract.ContextError(ctx); err != nil {
		return err
	}
	if len(value) > userKeyPayloadLimit {
		return fmt.Errorf(
			"%w: kernel key payload exceeds %d bytes",
			contract.ErrValueTooLarge,
			userKeyPayloadLimit,
		)
	}
	_, err := addKey("user", k.key(key), value, k.session)
	return operationError("set credential", err)
}

// Delete implements [contract.Keyringer].
func (k *Keyring) Delete(ctx context.Context, key string) error {
	if err := contract.ContextError(ctx); err != nil {
		return err
	}
	credential, err := k.get(key)
	if err != nil {
		return operationError("find credential", err)
	}
	_, err = keyctlInt(unix.KEYCTL_UNLINK, credential, k.session, 0, 0)
	return operationError("delete credential", err)
}

func readKeyContents(key int) ([]byte, error) {
	size, err := keyctlBuffer(unix.KEYCTL_READ, key, nil, 0)
	if err != nil {
		return nil, err
	}
	for {
		value := make([]byte, size)
		read, err := keyctlBuffer(unix.KEYCTL_READ, key, value, 0)
		if err != nil {
			return nil, err
		}
		if read <= len(value) {
			return value[:read], nil
		}
		size = read
	}
}

func probeError(err error) error {
	category := error(contract.ErrBackendFailure)
	switch {
	case errors.Is(err, fs.ErrPermission), errors.Is(err, unix.EPERM):
		category = contract.ErrPermissionDenied
	case errors.Is(err, unix.ENOKEY), errors.Is(err, unix.ENOSYS), errors.Is(err, unix.ENODEV):
		category = contract.ErrBackendUnavailable
	}
	return fmt.Errorf("%w: probe kernel keyring: %w", category, err)
}

func operationError(operation string, err error) error {
	if err == nil {
		return nil
	}
	category := error(contract.ErrBackendFailure)
	switch {
	case errors.Is(err, unix.ENOKEY), errors.Is(err, unix.EKEYEXPIRED), errors.Is(err, unix.EKEYREVOKED):
		category = contract.ErrNotFound
	case errors.Is(err, fs.ErrPermission), errors.Is(err, unix.EPERM):
		category = contract.ErrPermissionDenied
	case errors.Is(err, unix.ENOSYS), errors.Is(err, unix.ENODEV):
		category = contract.ErrBackendUnavailable
	}
	return fmt.Errorf("%w: %s: %w", category, operation, err)
}
