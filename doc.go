// Package keyring selects and uses operating-system credential stores through
// a portable, context-aware interface.
//
// Open selects the current platform's native persistent backend. Filesystem
// fallback is considered only when a caller explicitly supplies FallbackDir.
// The returned Info describes the selected backend and any earlier candidates
// rejected during discovery.
//
// All implementations report a missing credential with an error matching
// ErrNotFound. Callers should inspect portable error categories with errors.Is
// and must not parse diagnostic error strings.
package keyring
