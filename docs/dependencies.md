# Dependencies and supply-chain policy

This project keeps its production dependency graph small, does not vendor Go
modules, and performs dependency review manually. Automated dependency-update
pull requests and CI are intentionally outside the `v0.1.0` release scope.

## Reviewed dependencies

The following inventory was reviewed for `v0.1.0` on 2026-09-20.

| Module | Scope | Version | License | Decision |
| --- | --- | --- | --- | --- |
| `common.queueb.org/tests` | Tests only | `v0.1.1` | MIT | Current release; never imported by production files. |
| `github.com/alessio/shellescape` | macOS adapter | `v1.4.2` | MIT | Last release using this module path. Later releases declare `al.essio.dev/pkg/shellescape`; migration provides no required change to the single `Quote` use and adds another module to the graph. |
| `github.com/danieljoos/wincred` | Windows adapter | `v1.2.3` | MIT | Current release. |
| `github.com/godbus/dbus/v5` | Secret Service adapter | `v5.2.2` | BSD-2-Clause | Current release; includes the newer Unix transport and restores compile-only FreeBSD validation. |
| `golang.org/x/sys` | Linux and Windows adapters | `v0.48.0` | BSD-3-Clause | Current reviewed release and the sole Linux keyctl syscall provider. |

The standalone example additionally uses `github.com/spf13/cobra v1.10.2`
under Apache-2.0. Its transitive `pflag` dependency is BSD-3-Clause and
`mousetrap` is Apache-2.0.

The module graph also contains test dependencies declared by `wincred`:
`testify` and `objx` are MIT, `go-spew` is ISC, `go-difflib` is
BSD-3-Clause, and `yaml.v3` is dual MIT/Apache-2.0. They are not imported by
this library's production packages.

All reviewed licenses permit use and redistribution with this project's MIT
license. Their copyright, license, and notice conditions still apply to anyone
redistributing source or binaries that contain them. This repository does not
copy or vendor their source, and the library release does not distribute a
compiled binary.

## Linux keyctl decision

The project no longer depends on `github.com/jsipprell/keyctl`. Its latest
release is from 2021 and its private syscall tables cover only Linux 386,
amd64, and arm. The library already requires `golang.org/x/sys/unix`, which
provides the complete syscall surface used here:

- `KeyctlGetKeyringID`;
- `KeyctlSearch`;
- `AddKey`;
- `KeyctlBuffer` for payload reads;
- `KeyctlInt` for unlinking.

Using `x/sys/unix` removes a dependency and its duplicate syscall layer. The
adapter is compile-checked on Linux 386, amd64, arm, arm64, loong64, mips,
mips64, mips64le, mipsle, ppc64, ppc64le, riscv64, and s390x. Live support
still depends on the kernel configuration and runtime security policy.

## Manual update policy

Dependency updates are prepared and reviewed explicitly; they are never merged
solely because a newer version exists. For each update:

1. Review the upstream release notes, module path, minimum Go version,
   maintenance state, security advisories, and license changes.
2. Confirm that the dependency remains necessary and that a standard-library
   or already-required module cannot replace it with less code and risk.
3. Update `go.mod` and `go.sum`, then run `go mod tidy` for both the library
   and standalone example modules.
4. Run `go mod verify` and `./hack/verify.sh`; the latter scans both the current
   target and Windows-specific code with `govulncheck`.
5. Cross-compile affected operating systems and architectures, then run the
   relevant live integration scripts from `hack/` when backend behavior may
   have changed.
6. Update this inventory when the module graph, version rationale, or license
   obligations change.

The current development tools are installed by `hack/install-dev-tools.sh`
without project-pinned tool versions. Reviewers use the output of the current
`go vet`, `staticcheck`, `ineffassign`, and `govulncheck` releases as part of
the manual gate.

A reachable vulnerability must be fixed before release. If an advisory is
provably unreachable or does not apply to a supported target, record that
analysis in the release validation notes instead of silently ignoring it.
