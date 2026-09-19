//go:build linux

package fs

import (
	"errors"
	"fmt"
	iofs "io/fs"
	"os"

	"common.queueb.org/keyring/internal/contract"

	"golang.org/x/sys/unix"
)

const directoryMode = 0o700

func prepareDirectories(rootPath string, layout layout, effectiveUID uint32) error {
	if err := os.MkdirAll(rootPath, directoryMode); err != nil {
		return directoryError("create fallback root", err)
	}

	root, err := openDirectory(rootPath, effectiveUID)
	if err != nil {
		return fmt.Errorf("open fallback root: %w", err)
	}
	defer unix.Close(root)

	version, err := openOrCreateDirectory(root, layoutVersion, effectiveUID)
	if err != nil {
		return fmt.Errorf("open fallback layout: %w", err)
	}
	defer unix.Close(version)

	service, err := openOrCreateDirectory(version, layout.serviceID, effectiveUID)
	if err != nil {
		return fmt.Errorf("open fallback service: %w", err)
	}
	defer unix.Close(service)
	return nil
}

func openOrCreateDirectory(parent int, name string, effectiveUID uint32) (int, error) {
	directory, err := openDirectoryAt(parent, name, effectiveUID)
	if err == nil {
		return directory, nil
	}
	if !errors.Is(err, iofs.ErrNotExist) {
		return -1, err
	}

	if err := unix.Mkdirat(parent, name, directoryMode); err != nil && !errors.Is(err, iofs.ErrExist) {
		return -1, directoryError("create directory", err)
	}
	return openDirectoryAt(parent, name, effectiveUID)
}

func openDirectory(path string, effectiveUID uint32) (int, error) {
	directory, err := unix.Open(
		path,
		unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return -1, directoryError("open directory", err)
	}
	if err := validateDirectory(directory, effectiveUID); err != nil {
		_ = unix.Close(directory)
		return -1, err
	}
	return directory, nil
}

func openDirectoryAt(parent int, name string, effectiveUID uint32) (int, error) {
	directory, err := unix.Openat(
		parent,
		name,
		unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return -1, directoryError("open directory", err)
	}
	if err := validateDirectory(directory, effectiveUID); err != nil {
		_ = unix.Close(directory)
		return -1, err
	}
	return directory, nil
}

func validateDirectory(directory int, effectiveUID uint32) error {
	var status unix.Stat_t
	if err := unix.Fstat(directory, &status); err != nil {
		return directoryError("inspect directory", err)
	}
	if status.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("%w: managed path is not a directory", contract.ErrInsecureFallback)
	}
	if status.Uid != effectiveUID {
		return fmt.Errorf(
			"%w: directory owner %d does not match effective user %d",
			contract.ErrInsecureFallback,
			status.Uid,
			effectiveUID,
		)
	}
	if status.Mode&0o077 != 0 {
		return fmt.Errorf(
			"%w: directory mode %#o grants group or other access",
			contract.ErrInsecureFallback,
			status.Mode&0o777,
		)
	}
	return nil
}

func directoryError(operation string, err error) error {
	switch {
	case errors.Is(err, iofs.ErrNotExist):
		return fmt.Errorf("%s: %w", operation, err)
	case errors.Is(err, iofs.ErrPermission):
		return fmt.Errorf("%w: %s: %w", contract.ErrPermissionDenied, operation, err)
	case errors.Is(err, iofs.ErrExist), errors.Is(err, unix.ELOOP), errors.Is(err, unix.ENOTDIR):
		return fmt.Errorf("%w: %s: %w", contract.ErrInsecureFallback, operation, err)
	default:
		return fmt.Errorf("%w: %s: %w", contract.ErrBackendFailure, operation, err)
	}
}
