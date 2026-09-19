// Package fs provides a filesystem-backed implementation of the
// keyring.Keyringer contract.
//
// Secret values are stored as plaintext. The package protects filesystem
// access and persistence according to its documented policy, but
// confidentiality at rest depends on the underlying volume.
//
// The parent secure package does not select this backend. Applications opt in
// through the root keyring package or open the filesystem backend explicitly.
package fs
