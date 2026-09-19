package keyring

import "common.queueb.org/keyring/internal/contract"

// Keyringer is the canonical interface for credential storage operations.
// Implementations are safe for concurrent use.
type Keyringer = contract.Keyringer

// Error is a stable portable error category.
type Error = contract.Error

// Backend identifies a credential storage implementation.
type Backend = contract.Backend

const (
	// BackendCustom identifies a caller-provided Keyringer.
	BackendCustom = contract.BackendCustom
	// BackendSecretService identifies the freedesktop.org Secret Service.
	BackendSecretService = contract.BackendSecretService
	// BackendKernelKeyring identifies the Linux kernel keyring.
	BackendKernelKeyring = contract.BackendKernelKeyring
	// BackendFilesystem identifies explicit filesystem persistence.
	BackendFilesystem = contract.BackendFilesystem
	// BackendKeychain identifies macOS Keychain.
	BackendKeychain = contract.BackendKeychain
	// BackendWindowsCredentialManager identifies Windows Credential Manager.
	BackendWindowsCredentialManager = contract.BackendWindowsCredentialManager
)

// Persistence describes how long credentials are expected to survive.
type Persistence = contract.Persistence

const (
	// PersistenceUnknown means persistence cannot be inferred.
	PersistenceUnknown = contract.PersistenceUnknown
	// PersistenceSession means values may disappear with the user session.
	PersistenceSession = contract.PersistenceSession
	// PersistencePersistent means values are expected to survive sessions.
	PersistencePersistent = contract.PersistencePersistent
)

// Host identifies the system that owns the selected credential storage.
type Host = contract.Host

const (
	// HostUnknown means storage ownership cannot be inferred.
	HostUnknown = contract.HostUnknown
	// HostCurrent means the current operating-system environment owns storage.
	HostCurrent = contract.HostCurrent
	// HostWindows means the Windows host owns storage used from WSL2.
	HostWindows = contract.HostWindows
)

// Interaction describes whether backend operations may require user action.
type Interaction = contract.Interaction

const (
	// InteractionUnknown means interaction behavior cannot be inferred.
	InteractionUnknown = contract.InteractionUnknown
	// InteractionNone means operations do not require user interaction.
	InteractionNone = contract.InteractionNone
	// InteractionPossible means operations may require user interaction.
	InteractionPossible = contract.InteractionPossible
)

// Info describes the backend selected by an Open call.
type Info = contract.Info

// Rejection describes one backend rejected during discovery.
type Rejection = contract.Rejection

// SelectionError reports that backend selection could not complete.
type SelectionError = contract.SelectionError

const (
	// ErrNotFound reports that the requested credential does not exist.
	ErrNotFound = contract.ErrNotFound
	// ErrInvalidArgument reports invalid public input or unusable configuration.
	ErrInvalidArgument = contract.ErrInvalidArgument
	// ErrValueTooLarge reports a value exceeding a backend or protocol limit.
	ErrValueTooLarge = contract.ErrValueTooLarge
	// ErrBackendUnavailable reports an absent or unreachable backend.
	ErrBackendUnavailable = contract.ErrBackendUnavailable
	// ErrBackendLocked reports a reachable but locked backend.
	ErrBackendLocked = contract.ErrBackendLocked
	// ErrInteractionRequired reports that user action is required.
	ErrInteractionRequired = contract.ErrInteractionRequired
	// ErrPermissionDenied reports that an operation was refused.
	ErrPermissionDenied = contract.ErrPermissionDenied
	// ErrTimeout reports a library or backend timeout.
	ErrTimeout = contract.ErrTimeout
	// ErrInsecureFallback reports a fallback rejected by security policy.
	ErrInsecureFallback = contract.ErrInsecureFallback
	// ErrUnsupported reports a capability unsupported by the current environment.
	ErrUnsupported = contract.ErrUnsupported
	// ErrBackendFailure reports an unexpected, unclassified backend failure.
	ErrBackendFailure = contract.ErrBackendFailure
)
