// Package keyring selects credential backends without permitting filesystem
// fallback.
//
// On Linux, Open tries Secret Service and then the user-session kernel keyring.
// Inside WSL2 it first tries Windows Credential Manager through the separately
// installed keyring-winbridge.exe helper. On macOS and Windows it selects the
// platform-native persistent credential store.
//
// Selection stops on errors other than backend unavailable or unsupported.
// Callers should inspect the returned keyring.Info before relying on a
// backend's host or persistence properties.
package keyring
