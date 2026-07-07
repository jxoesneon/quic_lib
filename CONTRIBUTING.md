# Contributing to quic_lib

Thank you for helping improve `quic_lib`! This document covers the basics of reporting issues, submitting changes, and keeping the codebase consistent.

## How to contribute

1. **Open an issue first** for bug reports, feature requests, or design questions.
2. **Fork the repository** and create a feature branch from `main`.
3. **Make focused changes** — one logical fix or feature per pull request.
4. **Run the verification commands** (see below) and ensure they pass.
5. **Submit a pull request** with a clear description and reference to any related issues.

## Reporting bugs

When filing an issue, please include:

- A clear, minimal reproduction case or failing test.
- Dart SDK version (`dart --version`).
- Platform (Android, iOS, Linux, macOS, Windows).
- Relevant logs or error messages, with raw bytes redacted if they contain sensitive material.
- The package version from `pubspec.yaml` or `pubspec.lock`.

## Development workflow

```bash
# Install dependencies
dart pub get

# Run static analysis
dart analyze

# Check formatting (also applies it without --set-exit-if-changed)
dart format --set-exit-if-changed .

# Run the test suite
dart test

# Pub scoring dry-run (optional)
pana . --exit-code-threshold 0

# Dry-run publish (optional)
dart pub publish --dry-run
```

Pull requests must pass `dart analyze`, `dart format --set-exit-if-changed .`, and `dart test` before they can be merged.

## Code style expectations

- Run `dart format` before committing.
- Follow the existing style and naming conventions in the file you are editing.
- Add doc comments for new public APIs (`public_member_api_docs` is enforced).
- Keep the public API surface small and intentional.
- Add or update tests for new behavior and bug fixes. Aim to maintain the existing coverage level (80%+ line coverage target).
- Do not add native dependencies or `dart:ffi` in the core library without an ADR and Council review (see ADR-001).
- Do not bump `pubspec.yaml` version or edit `CHANGELOG.md` in the same PR as code changes; those are handled during release.

## Documentation changes

- Architecture or design changes require an update to `ARCHITECTURE.md` or a new ADR in `doc/decisions/`.
- New public APIs require matching updates in `doc/specs/DART_API_SPEC.md` and generated dartdocs.
- Doc-only PRs do not need version bumps.

## Review process

- All pull requests require at least one maintainer review.
- CI will run `dart analyze`, `dart format`, and `dart test` automatically.
- Address review feedback with additional commits or, preferably, amend and force-push a clean history for small changes.

## License

By contributing, you agree that your contributions will be licensed under the MIT license, the same license used by the rest of the project.
