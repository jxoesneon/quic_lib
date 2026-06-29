# Project Notes

## `quic_lib` Dart package

### Verification commands

```powershell
# Run all tests
dart test

# Static analysis
dart analyze

# Check formatting (also applies it without --set-exit-if-changed)
dart format --set-exit-if-changed .

# Pub scoring dry-run
pana . --exit-code-threshold 0

# Dry-run publish
dart pub publish --dry-run
```

### Release checklist

1. Update `pubspec.yaml` version.
2. Add entry to `CHANGELOG.md`.
3. Run verification commands above.
4. Commit and push.
5. Create and push a tag: `git tag vX.Y.Z; git push origin vX.Y.Z`.
6. The `Publish to pub.dev` GitHub Actions workflow triggers on `v*.*.*` tags.

### Known operational constraints

- **pub.dev rate limit:** publishing is limited to 12 packages per day per account. If the workflow fails with "The package-published operation is blocked, as its rate limit has been reached", wait ~24 hours and re-run the failed `Publish to pub.dev` job from the GitHub Actions UI.

### Deferred work

- Issue #10 (ECN): blocked on missing `IP_TOS`/`IPV6_TCLASS` socket options in Dart's `RawDatagramSocket`. Defer to v2.0.0 unless the ADR-001 "pure-Dart, no `dart:ffi`" constraint is relaxed.
