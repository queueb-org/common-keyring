# Examples

Each example is an independent Go module. This boundary keeps example-only
dependencies out of `common.queueb.org/keyring` and excludes the applications
from the library module downloaded by its users.

## keyring-cli

`keyring-cli` is a small Cobra application using
`common.queueb.org/keyring/secure`. It can create, read, and delete a secret
without enabling the filesystem fallback.

From the repository root:

```bash
cd examples/keyring-cli

printf %s 'example-secret' | go run . --service example create api-token
go run . --service example get api-token
go run . --service example delete api-token
```

The `create` command reads the secret from standard input until EOF and stores
it unchanged. The `get` command writes the secret unchanged to standard output.
Avoid passing secrets as command-line arguments because they can be retained in
shell history or exposed through process inspection.

On WSL2, the secure package prefers Windows Credential Manager through
`keyring-winbridge.exe`. If the helper is not installed, backend discovery
continues with keyrings available in the Linux context. See the
[WSL2 guide](../docs/wsl2.md) for installation, persistence, compatibility,
and trust-boundary details.
