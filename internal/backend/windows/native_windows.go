//go:build windows

package windows

import (
	"errors"
	"fmt"

	"common.queueb.org/keyring/internal/contract"

	"github.com/danieljoos/wincred"
	winapi "golang.org/x/sys/windows"
)

func nativeReadCredential(target string) ([]byte, error) {
	credential, err := wincred.GetGenericCredential(target)
	if err != nil {
		return nil, windowsError(err)
	}
	return credential.CredentialBlob, nil
}

func nativeWriteCredential(target, username string, value []byte) error {
	credential := wincred.NewGenericCredential(target)
	credential.UserName = username
	credential.CredentialBlob = value
	return windowsError(credential.Write())
}

func nativeDeleteCredential(target string) error {
	return windowsError(wincred.NewGenericCredential(target).Delete())
}

func windowsError(err error) error {
	if err == nil {
		return nil
	}

	var category error
	switch {
	case errors.Is(err, wincred.ErrElementNotFound):
		category = contract.ErrNotFound
	case errors.Is(err, wincred.ErrInvalidParameter), errors.Is(err, wincred.ErrBadUsername):
		category = contract.ErrInvalidArgument
	case errors.Is(err, winapi.ERROR_ACCESS_DENIED):
		category = contract.ErrPermissionDenied
	case errors.Is(err, winapi.ERROR_NO_SUCH_LOGON_SESSION):
		category = contract.ErrBackendUnavailable
	default:
		return err
	}
	return fmt.Errorf("%w: %w", category, err)
}
