# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| < 1.0.0 | Pre-release (best effort) |
| >= 1.0.0 | Full support |

## Reporting a Vulnerability

Please report security vulnerabilities via the repository's private vulnerability reporting feature on GitHub, or by emailing the maintainers directly.

- **GitHub**: Use the repository's Security > Advisories > Report a vulnerability
- **Email**: security@quic-lib.dev (PGP key: https://quic-lib.dev/pgp-security.asc)

## Severity Levels

| Severity | CVSS Score | Description | SLA |
|----------|------------|-------------|-----|
| Critical | 9.0-10.0 | Remote code execution, complete confidentiality/integrity loss, or widespread denial of service | 7 days |
| High | 7.0-8.9 | Significant confidentiality/integrity impact, or limited remote code execution | 14 days |
| Medium | 4.0-6.9 | Limited confidentiality/integrity impact, or local denial of service | 30 days |
| Low | 0.1-3.9 | Minor information disclosure, or low-impact denial of service | 60 days |

## Disclosure Policy

1. **Embargo period**: 90 days from fix release before public disclosure.
2. **Coordination**: Critical fixes are released simultaneously on `main` and the latest stable release branch.
3. **CVE requests**: High-severity issues will be assigned a CVE identifier.
4. **Acknowledgment**: Reporters will be credited in the advisory unless they request anonymity.

## Security Fix Process

1. Issue received and triaged within 48 hours.
2. Fix developed on a private security branch.
3. Fix backported to the two most recent minor release branches.
4. Advisory published alongside the release.
5. SBOM generation planned for v1.13.0 (currently not implemented).

## Pure-Dart Security Constraint

`quic_lib` commits to a pure-Dart implementation with no FFI or native extensions.
This reduces the risk of memory-safety vulnerabilities associated with native FFI boundaries and simplifies auditing of the Dart layer. See [ADR-001](doc/decisions/ADR-001_Pure_Dart_No_FFI.md).
