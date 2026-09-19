# Contributing

Contributions are welcome when they preserve the library's explicit backend,
error, and security contracts. Open an issue before a large API or storage
format change so the compatibility and migration policy can be agreed first.

By participating, you agree to the [community policy](CODE_OF_CONDUCT.md).
Security vulnerabilities must be reported through [SECURITY.md](SECURITY.md),
not through a public issue.

## Development setup

Use Go 1.27 or newer. The repository is intentionally tested with workspace
resolution disabled so a parent `go.work` cannot hide module problems.

Install the current development tools once:

```bash
./hack/install-dev-tools.sh
```

Run the complete local gate:

```bash
./hack/verify.sh
```

This checks formatting, tidy state, module checksums, vet, static analysis,
vulnerability databases, tests, the race detector, and 100% statement
coverage for both the library and standalone example module. CI is not part of
the initial release process; contributors and maintainers run these checks
manually.

Default tests use controlled adapters and do not require D-Bus, a desktop
session, a kernel keyring, macOS Keychain, or Windows Credential Manager. New
unit tests must keep that property. Use `secure/fake` or per-call
`Option.Keyringer` injection for application-facing examples and tests.

## Live integration tests

Live tests are opt-in because they depend on the current user, session, host,
and security policy and may briefly create a uniquely named test credential.
Read [hack/README.md](hack/README.md) before running them.

```bash
./hack/test-integration-linux.sh
./hack/test-integration-windows.sh
./hack/test-integration-container.sh denied
./hack/test-integration-container.sh unavailable
```

Run only the scripts applicable to the environment. Never point test changes
at production credential names or submit secret values, credential contents,
access tokens, or private logs.

## Change requirements

- Preserve `errors.Is` and `errors.As` behavior; error strings are not a public
  contract.
- Keep backend selection observable through `Info` and fail closed on terminal
  errors.
- Do not introduce implicit filesystem fallback or describe plaintext storage
  as secure.
- Add deterministic tests for every behavior branch and retain 100% statement
  coverage.
- Document backend-specific limits, persistence, interaction, and trust-boundary
  changes.
- Update `docs/dependencies.md` when the module graph, license inventory, or
  version rationale changes.
- Update `CHANGELOG.md` for user-visible changes.

Format Go sources with `gofmt`. Keep commits focused; generated artifacts,
coverage files, local credentials, and tool caches do not belong in the
repository.

## Pull requests

Describe the user-visible behavior, tests performed, affected backends, and any
environment that could not be tested live. A pull request does not need to
claim support for an environment unavailable to its author; document that gap
so maintainers can evaluate it explicitly.
