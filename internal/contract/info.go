package contract

// Backend identifies the selected credential storage implementation.
type Backend string

const (
	// BackendCustom identifies a caller-provided Keyringer.
	BackendCustom Backend = "custom"
	// BackendSecretService identifies the freedesktop.org Secret Service.
	BackendSecretService Backend = "secret-service"
	// BackendKernelKeyring identifies the Linux kernel keyring.
	BackendKernelKeyring Backend = "kernel-keyring"
	// BackendFilesystem identifies explicit filesystem persistence.
	BackendFilesystem Backend = "filesystem"
	// BackendKeychain identifies macOS Keychain.
	BackendKeychain Backend = "keychain"
	// BackendWindowsCredentialManager identifies Windows Credential Manager.
	BackendWindowsCredentialManager Backend = "windows-credential-manager"
)

// Persistence describes how long credentials are expected to survive.
type Persistence string

const (
	// PersistenceUnknown means persistence cannot be inferred.
	PersistenceUnknown Persistence = "unknown"
	// PersistenceSession means values may disappear with the user session.
	PersistenceSession Persistence = "session"
	// PersistencePersistent means values are expected to survive sessions.
	PersistencePersistent Persistence = "persistent"
)

// Host identifies the system that owns the selected credential storage.
type Host string

const (
	// HostUnknown means storage ownership cannot be inferred.
	HostUnknown Host = "unknown"
	// HostCurrent means the current operating-system environment owns storage.
	HostCurrent Host = "current"
	// HostWindows means the Windows host owns storage used from WSL2.
	HostWindows Host = "windows"
)

// Interaction describes whether backend operations may require user action.
type Interaction string

const (
	// InteractionUnknown means interaction behavior cannot be inferred.
	InteractionUnknown Interaction = "unknown"
	// InteractionNone means operations do not require user interaction.
	InteractionNone Interaction = "none"
	// InteractionPossible means operations may require user interaction.
	InteractionPossible Interaction = "possible"
)

// Info describes the backend selected by an Open call.
type Info struct {
	// Backend identifies the selected implementation.
	Backend Backend
	// Persistence describes the expected credential lifetime.
	Persistence Persistence
	// Host identifies the system that owns the storage.
	Host Host
	// Interaction describes possible user interaction.
	Interaction Interaction
	// Fallback reports whether discovery reached this backend as a fallback.
	Fallback bool
	// Rejected contains candidates rejected before Backend was selected.
	// The slice is ordered by selection attempt and never contains secret values.
	Rejected []Rejection
}

// Rejection describes one backend rejected during discovery.
type Rejection struct {
	// Backend identifies the rejected implementation.
	Backend Backend
	// Err preserves the machine-readable reason and its backend cause.
	Err error
}
