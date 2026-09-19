# WSL2

Inside WSL2, `common.queueb.org/keyring/secure` tries credential backends in
this order by default:

1. Windows Credential Manager through `keyring-winbridge.exe`;
2. Secret Service in the Linux user session;
3. the Linux user-session kernel keyring.

The returned `keyring.Info` identifies the selected backend, its persistence
boundary, and every earlier candidate rejected during discovery. The library
never enables filesystem storage through `secure.Open`.

## Install the Windows bridge

The bridge is a separate Windows application with its own release cycle. The
library does not download, install, or update it. The recommended installation
is the prebuilt `keyring-winbridge.exe` from the
[keyring-winbridge releases](https://github.com/queueb-org/keyring-winbridge/releases).

The Go toolchain is also supported. From Windows, install the released helper
with:

```powershell
go install queueb.org/keyring-winbridge@v0.1.0
```

`@latest` is valid, but pinning a tag is preferable for reproducible
installations. From WSL2, explicitly cross-install a Windows executable:

```bash
GOOS=windows GOARCH=amd64 GOAMD64=v1 \
  go install queueb.org/keyring-winbridge@v0.1.0
```

With the default Go configuration, a WSL2 cross-install writes the executable
to `$(go env GOPATH)/bin/windows_amd64/keyring-winbridge.exe`. `GOBIN` must be
unset for a cross-install. Running `go install` in WSL2 without `GOOS=windows`
produces a Linux executable and cannot provide Windows Credential Manager
access.

Place the Windows executable in a directory visible through the WSL2 `PATH`.
Verify discovery from the same Linux environment and user that will run the
application:

```bash
command -v keyring-winbridge.exe
```

Windows executable interoperability must be enabled. A helper that is present
but cannot be executed, times out, returns an incompatible response, or reports
a backend failure stops initialization. Only an absent helper permits discovery
to continue with Linux-context backends.

## Compatibility

This library uses the `keyring-winbridge/v1alpha1` protocol and probes the
helper before selecting it. The helper release version and protocol version
are independent.

Before helper version `1.0.0`, `0.MINOR` is the compatibility boundary: patch
releases within one minor line remain compatible, while a new minor release may
require a different protocol. Pin the helper release used with an application
and check both projects' release notes before changing minor versions.

## Persistence and WSL lifetime

Windows Credential Manager stores the secret for the Windows user that runs
the helper. Those credentials persist independently of a WSL distribution
restart. They are not shared with other Windows users.

The Linux kernel backend reports `keyring.PersistenceSession`. Its values live
only in the WSL2 kernel and user-session keyring; do not rely on them surviving
logout, distribution termination, `wsl --shutdown`, or a Windows reboot. Callers
that require persistent storage should check `keyring.Info.Persistence` after
`Open`.

Secret Service persistence and interaction depend on the provider and the
state of its collection. Installing and configuring a provider inside WSL2 is
outside the library's responsibility.

## Security boundary

Selecting the bridge deliberately crosses the WSL2 boundary. The Linux process
starts `keyring-winbridge.exe` directly and exchanges secret bytes through
bounded standard-input and standard-output messages. The helper then accesses
Windows Credential Manager as the current Windows user.

Treat the discovered executable as trusted code:

- install it from a trusted release or build source;
- keep its directory writable only by the intended Windows user and
  administrators;
- avoid an untrusted directory earlier in `PATH` with the same executable
  name;
- use the returned `keyring.Info.Host` and `Backend` fields when the owning
  system matters to application policy.

The explicit filesystem fallback in the root package is a different trust and
persistence choice. WSL2 ext4 storage may be used when it satisfies the
filesystem policy, but DrvFS paths such as `/mnt/c` are rejected because their
Unix ownership and mode semantics cannot be trusted by that policy.

## Current validation limits

Some WSL2 configurations require a separate distribution or a controlled host
restart and cannot currently be exercised by the project. They are listed in
[environment support and validation](support.md) and are provided as is until
reproducible live validation is available.
