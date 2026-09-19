package contract

// Error is a stable portable error category.
type Error string

// Error implements error.
func (e Error) Error() string {
	return string(e)
}

const (
	// ErrNotFound reports that the requested credential does not exist.
	ErrNotFound Error = "credential not found"
	// ErrInvalidArgument reports invalid public input or unusable configuration.
	ErrInvalidArgument Error = "invalid argument"
	// ErrValueTooLarge reports a value exceeding a backend or protocol limit.
	ErrValueTooLarge Error = "value too large"
	// ErrBackendUnavailable reports an absent or unreachable backend.
	ErrBackendUnavailable Error = "backend unavailable"
	// ErrBackendLocked reports a reachable but locked backend.
	ErrBackendLocked Error = "backend locked"
	// ErrInteractionRequired reports that user action is required.
	ErrInteractionRequired Error = "interaction required"
	// ErrPermissionDenied reports that an operation was refused.
	ErrPermissionDenied Error = "permission denied"
	// ErrTimeout reports a library or backend timeout.
	ErrTimeout Error = "operation timed out"
	// ErrInsecureFallback reports a fallback rejected by security policy.
	ErrInsecureFallback Error = "insecure fallback refused"
	// ErrUnsupported reports a capability unsupported by the current environment.
	ErrUnsupported Error = "unsupported"
	// ErrBackendFailure reports an unexpected, unclassified backend failure.
	ErrBackendFailure Error = "backend failure"
)
