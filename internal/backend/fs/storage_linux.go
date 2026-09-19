//go:build linux

package fs

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	iofs "io/fs"
	"os"

	"common.queueb.org/keyring/internal/contract"

	"golang.org/x/sys/unix"
)

const (
	secretMode              = 0o600
	temporaryRandomBytes    = 16
	temporaryCreateAttempts = 128
)

type linuxSystem interface {
	validateMount(string) error
	prepareDirectories(string, layout, uint32) error
	openDirectory(string, uint32) (int, error)
	openDirectoryAt(int, string, uint32) (int, error)
	openFileAt(int, string, int, uint32) (int, error)
	fstat(int, *unix.Stat_t) error
	fchmod(int, uint32) error
	read(int, []byte) (int, error)
	write(int, []byte) (int, error)
	fsync(int) error
	close(int) error
	renameAt(int, string, int, string) error
	unlinkAt(int, string, int) error
}

type realLinuxSystem struct{}

func (realLinuxSystem) validateMount(rootPath string) error {
	return validateMount(rootPath)
}

func (realLinuxSystem) prepareDirectories(rootPath string, layout layout, effectiveUID uint32) error {
	return prepareDirectories(rootPath, layout, effectiveUID)
}

func (realLinuxSystem) openDirectory(path string, effectiveUID uint32) (int, error) {
	return openDirectory(path, effectiveUID)
}

func (realLinuxSystem) openDirectoryAt(parent int, name string, effectiveUID uint32) (int, error) {
	return openDirectoryAt(parent, name, effectiveUID)
}

func (realLinuxSystem) openFileAt(parent int, name string, flags int, mode uint32) (int, error) {
	return unix.Openat(parent, name, flags, mode)
}

func (realLinuxSystem) fstat(descriptor int, status *unix.Stat_t) error {
	return unix.Fstat(descriptor, status)
}

func (realLinuxSystem) fchmod(descriptor int, mode uint32) error {
	return unix.Fchmod(descriptor, mode)
}

func (realLinuxSystem) read(descriptor int, contents []byte) (int, error) {
	return unix.Read(descriptor, contents)
}

func (realLinuxSystem) write(descriptor int, contents []byte) (int, error) {
	return unix.Write(descriptor, contents)
}

func (realLinuxSystem) fsync(descriptor int) error {
	return unix.Fsync(descriptor)
}

func (realLinuxSystem) close(descriptor int) error {
	return unix.Close(descriptor)
}

func (realLinuxSystem) renameAt(oldDirectory int, oldName string, newDirectory int, newName string) error {
	return unix.Renameat(oldDirectory, oldName, newDirectory, newName)
}

func (realLinuxSystem) unlinkAt(directory int, name string, flags int) error {
	return unix.Unlinkat(directory, name, flags)
}

type linuxStorage struct {
	rootPath     string
	layout       layout
	effectiveUID uint32
	system       linuxSystem
	random       io.Reader
}

var _ storage = (*linuxStorage)(nil)

func openStorage(rootPath string, layout layout) (storage, error) {
	return openLinuxStorage(
		rootPath,
		layout,
		uint32(os.Geteuid()),
		realLinuxSystem{},
		rand.Reader,
	)
}

func openLinuxStorage(
	rootPath string,
	layout layout,
	effectiveUID uint32,
	system linuxSystem,
	random io.Reader,
) (storage, error) {
	if err := system.validateMount(rootPath); err != nil {
		return nil, operationError("initialize filesystem", false, err)
	}
	if err := system.prepareDirectories(rootPath, layout, effectiveUID); err != nil {
		return nil, operationError("initialize filesystem", false, err)
	}
	return &linuxStorage{
		rootPath:     rootPath,
		layout:       layout,
		effectiveUID: effectiveUID,
		system:       system,
		random:       random,
	}, nil
}

func (s *linuxStorage) get(key string) ([]byte, error) {
	directory, err := s.openServiceDirectory(false)
	if err != nil {
		return nil, operationError("get credential", true, err)
	}
	defer s.system.close(directory)

	descriptor, err := s.openCredential(directory, identifier(keyDomain, key))
	if err != nil {
		return nil, operationError("get credential", true, err)
	}
	contents, readErr := io.ReadAll(descriptorReader{system: s.system, descriptor: descriptor})
	closeErr := s.system.close(descriptor)
	if err := errors.Join(readErr, closeErr); err != nil {
		return nil, operationError("get credential", true, err)
	}
	return contents, nil
}

func (s *linuxStorage) set(key string, value []byte) error {
	directory, err := s.openServiceDirectory(true)
	if err != nil {
		return operationError("set credential", false, err)
	}
	defer s.system.close(directory)

	name := identifier(keyDomain, key)
	if err := s.validateExistingCredential(directory, name); err != nil {
		return operationError("set credential", false, err)
	}
	return operationError("set credential", false, s.writeAtomic(directory, name, value))
}

func (s *linuxStorage) delete(key string) error {
	directory, err := s.openServiceDirectory(false)
	if err != nil {
		return operationError("delete credential", true, err)
	}
	defer s.system.close(directory)

	name := identifier(keyDomain, key)
	descriptor, err := s.openCredential(directory, name)
	if err != nil {
		return operationError("delete credential", true, err)
	}
	if err := s.system.close(descriptor); err != nil {
		return operationError("delete credential", true, err)
	}
	if err := s.system.unlinkAt(directory, name, 0); err != nil {
		return operationError("delete credential", true, err)
	}
	if err := s.system.fsync(directory); err != nil {
		return operationError("delete credential", true, err)
	}
	return nil
}

func (s *linuxStorage) openServiceDirectory(create bool) (int, error) {
	if err := s.system.validateMount(s.rootPath); err != nil {
		return -1, err
	}
	if create {
		if err := s.system.prepareDirectories(s.rootPath, s.layout, s.effectiveUID); err != nil {
			return -1, err
		}
	}

	root, err := s.system.openDirectory(s.rootPath, s.effectiveUID)
	if err != nil {
		return -1, err
	}
	defer s.system.close(root)
	version, err := s.system.openDirectoryAt(root, layoutVersion, s.effectiveUID)
	if err != nil {
		return -1, err
	}
	defer s.system.close(version)
	return s.system.openDirectoryAt(version, s.layout.serviceID, s.effectiveUID)
}

func (s *linuxStorage) openCredential(directory int, name string) (int, error) {
	descriptor, err := s.system.openFileAt(
		directory,
		name,
		unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK,
		0,
	)
	if err != nil {
		return -1, err
	}
	if err := s.validateCredential(descriptor); err != nil {
		_ = s.system.close(descriptor)
		return -1, err
	}
	return descriptor, nil
}

func (s *linuxStorage) validateCredential(descriptor int) error {
	var status unix.Stat_t
	if err := s.system.fstat(descriptor, &status); err != nil {
		return err
	}
	if status.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("%w: credential is not a regular file", contract.ErrInsecureFallback)
	}
	if status.Uid != s.effectiveUID {
		return fmt.Errorf(
			"%w: credential owner %d does not match effective user %d",
			contract.ErrInsecureFallback,
			status.Uid,
			s.effectiveUID,
		)
	}
	if status.Mode&0o077 != 0 {
		return fmt.Errorf(
			"%w: credential mode %#o grants group or other access",
			contract.ErrInsecureFallback,
			status.Mode&0o777,
		)
	}
	return nil
}

func (s *linuxStorage) validateExistingCredential(directory int, name string) error {
	descriptor, err := s.openCredential(directory, name)
	if errors.Is(err, iofs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return s.system.close(descriptor)
}

func (s *linuxStorage) writeAtomic(directory int, name string, value []byte) (result error) {
	temporaryName, descriptor, err := s.createTemporary(directory)
	if err != nil {
		return err
	}
	open := true
	renamed := false
	defer func() {
		if open {
			result = errors.Join(result, s.system.close(descriptor))
		}
		if !renamed {
			cleanupErr := s.system.unlinkAt(directory, temporaryName, 0)
			if !errors.Is(cleanupErr, iofs.ErrNotExist) {
				result = errors.Join(result, cleanupErr)
			}
		}
	}()

	if err := s.system.fchmod(descriptor, secretMode); err != nil {
		return err
	}
	if err := writeAll(s.system, descriptor, value); err != nil {
		return err
	}
	if err := s.system.fsync(descriptor); err != nil {
		return err
	}
	if err := s.system.close(descriptor); err != nil {
		open = false
		return err
	}
	open = false
	if err := s.system.renameAt(directory, temporaryName, directory, name); err != nil {
		return err
	}
	renamed = true
	return s.system.fsync(directory)
}

func (s *linuxStorage) createTemporary(directory int) (string, int, error) {
	random := make([]byte, temporaryRandomBytes)
	for range temporaryCreateAttempts {
		if _, err := io.ReadFull(s.random, random); err != nil {
			return "", -1, err
		}
		name := ".tmp-" + hex.EncodeToString(random)
		descriptor, err := s.system.openFileAt(
			directory,
			name,
			unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW,
			secretMode,
		)
		if errors.Is(err, iofs.ErrExist) {
			continue
		}
		if err != nil {
			return "", -1, err
		}
		return name, descriptor, nil
	}
	return "", -1, fmt.Errorf("cannot allocate a unique temporary credential file")
}

func writeAll(system linuxSystem, descriptor int, contents []byte) error {
	for len(contents) != 0 {
		written, err := system.write(descriptor, contents)
		if written > 0 {
			contents = contents[written:]
		}
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

type descriptorReader struct {
	system     linuxSystem
	descriptor int
}

func (r descriptorReader) Read(contents []byte) (int, error) {
	read, err := r.system.read(r.descriptor, contents)
	if read == 0 && err == nil {
		return 0, io.EOF
	}
	return read, err
}

func operationError(operation string, missingIsNotFound bool, err error) error {
	if err == nil {
		return nil
	}
	switch {
	case missingIsNotFound && errors.Is(err, iofs.ErrNotExist):
		return fmt.Errorf("%w: %s: %w", contract.ErrNotFound, operation, err)
	case errors.Is(err, iofs.ErrPermission):
		return fmt.Errorf("%w: %s: %w", contract.ErrPermissionDenied, operation, err)
	case errors.Is(err, unix.ELOOP), errors.Is(err, unix.ENOTDIR), errors.Is(err, unix.EISDIR):
		return fmt.Errorf("%w: %s: %w", contract.ErrInsecureFallback, operation, err)
	case errors.Is(err, contract.ErrInvalidArgument),
		errors.Is(err, contract.ErrInsecureFallback),
		errors.Is(err, contract.ErrPermissionDenied),
		errors.Is(err, contract.ErrBackendUnavailable),
		errors.Is(err, contract.ErrUnsupported),
		errors.Is(err, contract.ErrBackendFailure):
		return fmt.Errorf("%s: %w", operation, err)
	default:
		return fmt.Errorf("%w: %s: %w", contract.ErrBackendFailure, operation, err)
	}
}
