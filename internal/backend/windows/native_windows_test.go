//go:build windows

package windows

import (
	"errors"
	"testing"

	"common.queueb.org/keyring/internal/contract"

	"github.com/danieljoos/wincred"
	winapi "golang.org/x/sys/windows"
)

func TestWindowsError(t *testing.T) {
	unknown := errors.New("unknown")
	tests := []struct {
		name     string
		err      error
		category error
	}{
		{name: "nil"},
		{name: "not found", err: wincred.ErrElementNotFound, category: contract.ErrNotFound},
		{name: "invalid parameter", err: wincred.ErrInvalidParameter, category: contract.ErrInvalidArgument},
		{name: "bad username", err: wincred.ErrBadUsername, category: contract.ErrInvalidArgument},
		{name: "access denied", err: winapi.ERROR_ACCESS_DENIED, category: contract.ErrPermissionDenied},
		{name: "no logon session", err: winapi.ERROR_NO_SUCH_LOGON_SESSION, category: contract.ErrBackendUnavailable},
		{name: "unknown", err: unknown, category: unknown},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := windowsError(test.err)
			if !errors.Is(err, test.category) {
				t.Fatalf("windowsError() = %v, want %v", err, test.category)
			}
			if test.err != nil && !errors.Is(err, test.err) {
				t.Fatalf("windowsError() = %v, want cause %v", err, test.err)
			}
		})
	}
}
