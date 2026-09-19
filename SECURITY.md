# Security policy

## Supported versions

Before `v1.0.0`, security fixes are provided for the latest released minor
line only. The current unreleased development branch may change without a
compatibility guarantee. Release notes will identify any exception to this
policy.

## Report a vulnerability privately

Do not open a public issue for a suspected vulnerability. Use
[GitHub Private Vulnerability Reporting](https://github.com/queueb-org/common-keyring/security/advisories/new)
to send the maintainers a private report.

Include only the information needed to reproduce and assess the problem:

- affected version or commit;
- operating system, architecture, backend, and execution environment;
- impact and expected security boundary;
- minimal reproduction steps or a proof of concept;
- any known mitigations.

Do not include real credentials, tokens, private keys, production service or
account names, or unredacted logs. Use generated test secrets and redact
environment-specific identifiers.

The maintainers will acknowledge the report in the private advisory, assess
its scope, and coordinate remediation and disclosure there. No fixed response
or release-time SLA is promised for this volunteer-maintained project.

## Security boundaries

The repository's security model and known limitations are documented in the
[README](README.md#environment-and-security-boundaries), the
[WSL2 guide](docs/wsl2.md), and the
[environment support policy](docs/support.md). A behavior that contradicts
those documented boundaries may be a vulnerability; a request for a stronger
boundary is normally a feature proposal.
