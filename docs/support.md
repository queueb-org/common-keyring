# Environment support and validation

Operating-system credential storage depends on more than the compiled target.
Session managers, desktop services, container policies, user identities, and
WSL configuration can all change backend availability and behavior.

The library has deterministic unit and contract coverage for these boundaries,
but that coverage does not replace running the complete credential lifecycle
in the real environment.

## Currently unvalidated environments

The following environment-specific cases cannot be exercised on the hosts
currently available to the project:

- WSL2 with Secret Service installed but its collection locked;
- WSL2 with systemd disabled, including both available and unavailable kernel
  keyrings;
- WSL2 with Windows executable interoperability disabled;
- headless Linux or an SSH-only session with a locked Secret Service
  collection;
- a container in which keyctl is fully allowed and supports the complete
  set/get/overwrite/delete lifecycle;
- system services running as a dedicated user or root, including services
  without a login session;
- desktop Linux with an unlocked Secret Service provider;
- macOS with both an unlocked Keychain and a Keychain operation requiring user
  interaction;
- Windows Credential Manager when access is denied by Windows policy or the
  current user context.

For the current release, behavior specific to these cases is provided **as
is**, without a live-validation or release-blocking compatibility guarantee.
The portable API and deterministic backend tests still apply, but users should
validate the complete lifecycle in their own deployment environment before
depending on it for production secrets.

This status is not a claim that a listed environment is known to be broken. It
means that the project cannot currently verify its real session, interaction,
permission, persistence, and shutdown behavior. An environment can move out of
this section after reproducible live validation has been recorded.

## Reporting an environment problem

If a listed environment behaves differently from the documented API, please
[create an issue](https://github.com/queueb-org/common-keyring/issues/new).
Include:

- operating system, version, and architecture;
- whether the process runs in WSL2, a container, a desktop session, an SSH
  session, or a system service;
- the selected `keyring.Info` fields and ordered rejection categories;
- the operation that failed and the errors visible through `errors.Is` or
  `errors.As`;
- a minimal reproducer when possible.

Never include secret values, credential contents, access tokens, private keys,
or other sensitive material in an issue. Redact service and account names when
they identify a private system.
