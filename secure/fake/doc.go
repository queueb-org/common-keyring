// Package fake provides an in-memory keyring.Keyringer for tests.
//
// Keyring copies values on Set and Get, is safe for concurrent use, and can be
// injected into either public Open function without accessing an operating-
// system credential store.
package fake
