# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| < 1.0.0 | Pre-release (best effort) |
| >= 1.0.0 | Full support |

## Reporting a Vulnerability

Please report security vulnerabilities via the repository's private vulnerability reporting feature on GitHub, or by emailing the maintainers directly.

- **GitHub**: Use the repository's Security > Advisories > Report a vulnerability
- **Email**: Open an issue for security contact information.

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
5. SBOM updated and attached to the GitHub Release.

## Pure-Dart Security Constraint

`dart_quic` commits to a pure-Dart implementation with no FFI or native extensions.
This reduces the risk of memory-safety vulnerabilities associated with native FFI boundaries and simplifies auditing of the Dart layer. See [ADR-001](doc/decisions/ADR-001_Pure_Dart_No_FFI.md).
