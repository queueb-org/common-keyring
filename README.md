# Keyring

`common.queueb.org/keyring` is a small Go library for storing arbitrary secret
bytes in operating-system credential stores on Linux, macOS, Windows, and
WSL2.

Filesystem storage is **never enabled implicitly**. It is an explicit Linux-only
fallback, stores secret values as plaintext, and is not equivalent to an OS
credential store. Use it only when the underlying volume and deployment policy
provide an acceptable confidentiality boundary.

## Requirements and installation

The `v0.1.x` line requires Go 1.27 or newer.

```bash
go get common.queueb.org/keyring
```

The library does not build or install an executable. WSL2 access to Windows
Credential Manager additionally requires the separately released
`keyring-winbridge.exe`; see the [WSL2 guide](docs/wsl2.md).

## Basic use

`Keyringer` is the common interface implemented by every backend:

```go
type Keyringer interface {
	Get(ctx context.Context, key string) ([]byte, error)
	Set(ctx context.Context, key string, value []byte) error
	Delete(ctx context.Context, key string) error
}
```

Open the native backend, inspect what was selected, and use the returned
implementation:

```go
ctx := context.Background()

storage, info, err := keyring.Open(ctx, &keyring.Option{
	Service: "example.application",
})
if err != nil {
	return err
}
log.Printf("credential backend: %s", info.Backend)

if err := storage.Set(ctx, "api-token", []byte("secret")); err != nil {
	return err
}
value, err := storage.Get(ctx, "api-token")
if err != nil {
	return err
}
defer clear(value)
```

`Service` namespaces one application's credentials and is required unless a
caller-provided `Keyringer` is injected. An `Open` call selects a backend once;
it does not silently switch storage if a later operation fails. Call `Open`
again if application policy permits reselection.

## Backend selection

There are two selection policies:

- `common.queueb.org/keyring` selects the platform-native persistent store. A
  filesystem fallback is appended only when `FallbackDir` is explicitly set.
- `common.queueb.org/keyring/secure` never selects filesystem storage. On Linux
  it can continue from Secret Service to the user-session kernel keyring; in
  WSL2 it first tries Windows Credential Manager through the bridge.

| Environment | Root package default | `secure` package default | Persistence |
| --- | --- | --- | --- |
| Desktop Linux | Secret Service | Secret Service, then kernel keyring | persistent, then session |
| Headless Linux | Secret Service | Secret Service, then kernel keyring | provider-dependent, then session |
| WSL2 | Secret Service | Windows Credential Manager, Secret Service, then kernel keyring | persistent, persistent, then session |
| macOS | Keychain | Keychain | persistent |
| Windows | Windows Credential Manager | Windows Credential Manager | persistent |
| Other Unix | Secret Service | unsupported | provider-dependent |
| Other targets | unsupported | unsupported | none |

The table describes selection order, not guaranteed availability. Only errors
matching `ErrBackendUnavailable` or `ErrUnsupported` permit discovery to try
the next candidate. Locked, denied, timed-out, interactive, and unexpected
failures stop selection.

`Info` reports the selected backend, expected persistence, owning host,
possible interaction, whether fallback occurred, and ordered rejected
candidates. Applications that require persistent or host-owned storage should
enforce that policy using `Info`.

An explicit non-empty `Backends` list replaces the default order:

```go
storage, info, err := securekeyring.Open(ctx, &securekeyring.Option{
	Service: "example.application",
	Backends: []keyring.Backend{
		keyring.BackendSecretService,
		keyring.BackendKernelKeyring,
	},
})
```

The root package can select its native backend or `BackendFilesystem`; the
`secure` package owns Linux's multi-backend policy. Unsupported entries are
recorded in `Info.Rejected` or `SelectionError.Rejected`.

Options use an ordered overlay: for each field, the last non-zero value wins.
The caller is responsible for passing a coherent option set. A non-nil
`Option.Keyringer` bypasses discovery and is the preferred way to inject a fake
in application tests.

## Explicit filesystem fallback

On Linux, configure fallback from the root package like this:

```go
storage, info, err := keyring.Open(ctx, &keyring.Option{
	Service:     "example.application",
	FallbackDir: "/var/lib/example/keyring",
})
if err != nil {
	return err
}
if info.Fallback {
	log.Printf("using fallback backend %s", info.Backend)
}
```

The native backend remains first in this form. To require filesystem storage,
set `Backends: []keyring.Backend{keyring.BackendFilesystem}` or call
`secure/fs.Open` directly.

Filesystem values are plaintext. The implementation requires directories
owned by the effective user with no group or other access, rejects symbolic
links and mounts without trustworthy Unix ownership/mode semantics (including
WSL DrvFS), writes credentials atomically with mode `0600`, and hashes service
and key names so user input cannot escape the configured root.

The `v0.1.0` filesystem layout is
`<root>/v1/<SHA-256 service ID>/<SHA-256 key ID>`. There is no migration layer
for unpublished pre-release layouts; older files are not discovered
automatically.

## Errors

Use `errors.Is`; error text is diagnostic, not an API:

```go
value, err := storage.Get(ctx, "api-token")
switch {
case err == nil:
	use(value)
case errors.Is(err, keyring.ErrNotFound):
	// The canonical missing-secret result for every backend.
case errors.Is(err, keyring.ErrBackendLocked):
	// Ask the user to unlock the store according to application policy.
case errors.Is(err, keyring.ErrPermissionDenied):
	// The backend exists, but this process identity cannot use it.
case errors.Is(err, keyring.ErrTimeout):
	// The context or a bounded backend operation expired.
default:
	return err
}
```

Portable categories also include `ErrInvalidArgument`, `ErrValueTooLarge`,
`ErrBackendUnavailable`, `ErrInteractionRequired`, `ErrInsecureFallback`,
`ErrUnsupported`, and `ErrBackendFailure`. Context cancellation remains
detectable with `errors.Is(err, context.Canceled)` or
`errors.Is(err, context.DeadlineExceeded)`.

When `Open` fails, `errors.As(err, *SelectionError)` exposes the ordered backend
rejections without secret values.

## Limits and naming

Use stable, non-empty UTF-8 service and key names without NUL characters. Exact
limits are backend-specific:

- Windows Credential Manager and the WSL2 bridge accept secret values up to
  2,560 bytes. A key is limited to 513 UTF-16 code units and the combined
  `service:key` target to 32,767 UTF-16 code units.
- The Linux kernel keyring accepts values up to 32,767 bytes and stores hashed
  service/key identifiers. Its credentials have session lifetime.
- macOS `Set` uses a bounded 4,096-byte `security` command after quoting and
  base64 encoding, so the usable secret size also depends on service and key
  lengths.
- Secret Service limits depend on the provider and session configuration.
- The Linux filesystem backend hashes service/key identifiers and imposes no
  additional library-level value-size limit.
- WSL2 helper protocol messages are bounded to 1 MiB and operations to 15
  seconds; the Windows secret-size limit is reached first for normal requests.

An oversized value returns an error matching `ErrValueTooLarge` where the
library can determine the limit before calling the backend.

## Environment and security boundaries

- Desktop Linux needs a reachable user D-Bus session and Secret Service
  provider. A locked collection or required prompt is a terminal condition,
  not a reason to downgrade storage.
- Headless, SSH-only, container, and system-service processes often have a
  different session, identity, D-Bus environment, or kernel-keyring policy.
  Validate the complete lifecycle under the actual service account.
- Kernel-keyring values can disappear at logout, distribution shutdown, or
  reboot. Do not use session persistence as the sole copy of an unrecoverable
  key.
- WSL2 bridge selection crosses into the Windows user's security boundary and
  trusts the `keyring-winbridge.exe` found through `PATH`.
- Context cancellation bounds discovery and subprocess/D-Bus operations where
  supported, but a synchronous native OS call may not be interruptible after
  it starts.
- Go does not provide a general guarantee that every copy of a secret is
  zeroized from process memory. Clear caller-owned buffers when useful, avoid
  command-line secrets, and never log secret values.
- A custom injected `Keyringer` is entirely inside the caller's trust and
  persistence boundary.

See [environment support and validation](docs/support.md) for environments
currently provided as is, and [dependencies and supply-chain policy](docs/dependencies.md)
for the reviewed module inventory.

## Examples and development

The package examples are executable with `go test`. A standalone Cobra CLI is
under [`examples/keyring-cli`](examples/README.md) in its own Go module so its
dependencies are not inherited by library consumers.

Contributors should start with [CONTRIBUTING.md](CONTRIBUTING.md). The complete
manual release gate is:

```bash
./hack/verify.sh
```

Default unit tests do not access a desktop keyring, D-Bus, the Linux kernel
keyring, or Windows Credential Manager. Live integration tests are separate
and opt-in.

## License

MIT. See [LICENSE](LICENSE).
