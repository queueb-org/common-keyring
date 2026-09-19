# Changelog

This file records user-visible changes to `common.queueb.org/keyring`.

## Release-note policy

Every release moves relevant entries from `Unreleased` into a dated version
section. Entries are grouped as added, changed, fixed, security, deprecated,
or removed when those groups are useful. Release notes must call out:

- public API and minimum Go version changes;
- backend order, persistence, interaction, limits, and security-boundary
  changes;
- filesystem layout or migration requirements;
- WSL2 helper protocol or compatibility changes;
- known limitations and environments not validated live.

Before `v1.0.0`, a minor release may contain incompatible API or behavior
changes and must identify them prominently. Patch releases within a minor line
remain compatible: fixes for `v0.1.0` belong in `v0.1.1`, while an incompatible
change requires `v0.2.0`. Published tags are never moved; a correction is
released under a new version.

## v0.1.0 - 2026-09-20

### Added

- Portable, context-aware `Keyringer` API with typed errors and observable
  backend selection.
- Native Secret Service, macOS Keychain, Windows Credential Manager, Linux
  kernel-keyring, WSL2 bridge, explicit Linux filesystem, and in-memory test
  implementations.
- Manual verification, integration-test, dependency, environment, and security
  documentation for the first OSS release.
