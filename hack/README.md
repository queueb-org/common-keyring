# Verification scripts

`verify.sh` is the release-blocking local gate. It first runs `lint.sh`, then
runs unit tests and the race detector, and enforces 100% statement coverage for
both the library and the standalone example module. It does not connect to
D-Bus, the Linux kernel keyring, or Windows Credential Manager. The
vulnerability scan downloads current Go vulnerability database data and
therefore requires network access.

`lint.sh` checks both Go modules with formatting, `go mod tidy -diff`,
`go mod verify`, `go vet`, `ineffassign`, `staticcheck`, and `govulncheck` for
both the current target and Windows-specific code. Run
`./hack/install-dev-tools.sh` once to install the development tools and ensure
that the Go installation destination is available through `PATH`.

`test-integration-linux.sh` is an explicit live-backend check. It verifies
bounded failure without a session bus and, when absent, without a Secret
Service provider. It may also create and delete test credentials in the Linux
kernel keyring and, inside WSL2, Windows Credential Manager through
`keyring-winbridge.exe`. Run it only in an intended integration environment.

`test-integration-windows.sh` cross-builds and runs the native Windows backend
test from Windows or WSL with Windows interop. It creates a uniquely named
temporary generic credential, verifies an arbitrary-byte round trip and
missing-item behavior, and removes the credential during test cleanup.

`test-integration-container.sh` runs the Linux kernel-keyring test in a
read-only, network-disabled Alpine container. Its required first argument is
`allowed`, `denied`, or `unavailable`. The denied case uses Docker's default
seccomp profile; unavailable uses `seccomp/keyctl-unavailable.json` to return
`ENOSYS`; allowed disables seccomp for the disposable test container and still
requires the host/container policy to permit complete keyring CRUD.
