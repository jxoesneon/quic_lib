---
title: "Versioning Policy"
category: spec
version: "1.0-draft"
status: "Specification"
subsystem: "Unknown"
rfc_basis: []
dependencies:
  - "ROADMAP.md"
---

# Versioning Policy


## 1. Purpose

During the long pre-1.0 journey, downstream consumers like dart_ipfs need predictability about breaking changes, deprecation windows, and compatibility guarantees. Without a versioning policy, every minor update risks breaking existing code. This document establishes SemVer rules, phase-based stability, and release branching so that consumers can upgrade with confidence.

## 2. Detailed Specification
### 2.1 Scope

This policy applies to:

- The `dart_quic` package published on [pub.dev](https://pub.dev).
- Any public, documented API exported from `lib/dart_quic.dart` or its
  documented sub-libraries.
- Release artifacts, Git tags, and branch conventions in this repository.

It does not apply to:

- Internal implementation files not exported in the public API.
- Experimental/example code under `example/` or `test/`.
- Documentation-only repositories, such as the current specification stage.

---


### 2.2 Semantic Versioning Rules

`dart_quic` follows [Semantic Versioning 2.0.0](https://semver.org/):

```
MAJOR.MINOR.PATCH[-prerelease][+build]
```

| Position | Change Type | Example |
|----------|-------------|---------|
| **MAJOR** | Breaking change to the public API | Removing a class, renaming a required parameter |
| **MINOR** | New backwards-compatible functionality | Adding a new frame type, new public extension method |
| **PATCH** | Backwards-compatible bug or security fix | Fixing a reassembly buffer off-by-one error |

Additional rules:

1. **Pre-releases** use the form `X.Y.Z-alpha.N`, `X.Y.Z-beta.N`, or
   `X.Y.Z-rc.N` and are considered unstable.
2. **Build metadata** (e.g., `+build.123`) may be used for CI artifacts but is
   ignored for version ordering.
3. A change that fixes a security vulnerability or a serious bug may be released
   as a patch even if it technically alters behavior, provided the previous
   behavior was undocumented and insecure.

---


### 2.3 API Stability Guarantees by Phase

The roadmap is divided into phases. API stability is explicit at each phase:

| Phase | Version Range | Stability Guarantee |
|-------|---------------|---------------------|
| **Phase 0 (Specification)** | No published package | No API exists. This policy is in draft. |
| **Phase 1 (Core QUIC)** | `0.1.x` – `0.9.x` | **Experimental.** Breaking changes may occur in any minor or patch release. |
| **Phase 2 (HTTP/3)** | `0.10.x` – `0.19.x` | **Experimental.** Breaking API changes are expected as HTTP/3 abstractions settle. |
| **Phase 3 (WebTransport)** | `0.20.x` – `0.29.x` | **Experimental.** WebTransport API is subject to change. |
| **Phase 4 (libp2p)** | `0.30.x` – `0.49.x` | **Pre-release.** Breaking changes are announced but may still happen. |
| **Phase 5 (Optimization)** | `0.50.x` – `0.99.x` | **Release candidates.** API approaches 1.0 stability; only targeted breaking changes. |
| **Phase 6 (dart_ipfs)** | `1.0.0` | **Stable.** Semver guarantees apply to the public API. |

After `1.0.0`:

- A `MAJOR` release is required for any intentional breaking change.
- A `MINOR` release may add functionality but must not break existing consumers
  using documented APIs.
- A `PATCH` release only fixes bugs or security issues without changing public
  behavior.

---


### 2.4 Public API Definition

The public API consists of:

1. All symbols exported from the top-level library `package:dart_quic/dart_quic.dart`.
2. Any documented public members in exported classes, top-level functions,
   constants, and extension methods.
3. The behavior of documented classes as specified in the subsystem specs.

Undocumented members, private identifiers (prefixed with `_`), and files under
`src/` that are not re-exported are **not** part of the public API and may change
without a major version bump.

---


### 2.5 Deprecation Policy

Before removing or breaking a public API, `dart_quic` will follow a deprecation
period:

1. **Mark the old API** with `@Deprecated('Use NewApi instead; will be removed in X.Y.Z')`.
2. **Document the migration path** in the `CHANGELOG.md` under the `Deprecated`
   section.
3. **Provide a migration period**:
   - At least **one minor release** for simple renames or removals.
   - At least **two minor releases** for API restructuring or behavior changes.
4. **Remove only in a major or pre-1.0 minor release** after the migration period.

During the pre-1.0 experimental phase (Phases 1–4), deprecations may be shorter
and are not guaranteed to survive a full migration window. Breaking changes will
still be recorded in `CHANGELOG.md` with a clear migration note.

---


### 2.6 Release Process and Branching Strategy


### 2.7 Branching Model

- `main`: Active development. All PRs merge here. May contain unreleased changes.
- `release/x.y`: Release stabilization branches. Created when a new minor or
  major release is being prepared. Patches for `x.y.z` are merged here and
  tagged.
- `hotfix/x.y.z`: Short-lived branches for urgent security or critical fixes.


### 2.8 Release Steps

1. Ensure all tests pass on `main` and the target release branch.
2. Update `CHANGELOG.md` with the new version and release date.
3. Bump the version in `pubspec.yaml` according to the changes.
4. Open a release PR from `release/x.y` to `main` or merge the hotfix.
5. Tag the release commit with `vX.Y.Z`.
6. Create a GitHub Release with release notes copied from `CHANGELOG.md`.
7. Publish to pub.dev for stable releases (`dart pub publish`).


### 2.9 Pre-releases

Pre-release versions (`alpha`, `beta`, `rc`) are published to pub.dev with the
pre-release suffix and may be installed by consumers who explicitly opt in.

---


### 2.10 Changelog Maintenance

`dart_quic` follows the [Keep a Changelog](https://keepachangelog.com/) format.

The top-level `CHANGELOG.md` must contain:

- An `## [Unreleased]` section at the top for merged but unreleased changes.
- One section per released version, e.g., `## [1.2.3] - 2026-01-15`.
- Subsections:
  - `Added` — new features.
  - `Changed` — changes to existing functionality.
  - `Deprecated` — soon-to-be-removed features.
  - `Removed` — now-removed features.
  - `Fixed` — bug fixes.
  - `Security` — vulnerability fixes.

Each entry should reference the relevant issue or PR number when available,
e.g., `Add stream ID validation (#123)`.

---


### 2.11 Relationship to `dart_ipfs` Downstream Consumption

`dart_ipfs` is the primary downstream consumer of `dart_quic`. The integration
points are specified in [LIBP2P_QUIC_SPEC.md](LIBP2P_QUIC_SPEC.md) and
[DCUTR_SPEC.md](DCUTR_SPEC.md). The following rules apply to that relationship:

1. `dart_ipfs` should declare a concrete or compatible version of `dart_quic`
   in `pubspec.yaml` rather than using an open-ended constraint during the
   pre-1.0 phases.
2. `dart_quic` will maintain a compatibility table in `CHANGELOG.md` or a
   dedicated `doc/dart_ipfs_compat.md` document showing which `dart_quic`
   versions are supported by which `dart_ipfs` releases.
3. Breaking `dart_quic` changes that affect `dart_ipfs` will include a migration
   guide in `CHANGELOG.md`.
4. After `1.0.0`, `dart_quic` will not introduce breaking changes in a minor or
   patch release that would force an uncoordinated upgrade in `dart_ipfs`.
5. Security fixes are exempt from the coordinated-upgrade rule but will be
   clearly labeled as such.

---



## 3. Security Considerations

1. **Security Fix Coordination**: Critical security patches will be released as soon as possible on both `main` and the most recent stable release branch. A CVE identifier will be requested for high-severity issues.
2. **Vulnerability Disclosure**: Report security issues via the repository's SECURITY.md (or email the maintainers). Public disclosure is embargoed for 90 days after fix release to allow downstream consumers to upgrade.
3. **Backport Policy**: Security fixes are backported to the two most recent minor release branches. Fixes that touch public APIs are backported as non-breaking wrappers when possible.
4. **Dependency Audit**: Before every release, `dart pub outdated` and `dart pub audit` (or OSV integration) are run to detect known vulnerabilities in dependencies.
5. **SBOM**: A software bill of materials (SBOM) in SPDX JSON format is generated for each stable release and attached to the GitHub Release.

---



## 4. Acceptance Criteria

- [ ] This policy is approved and stored in `doc/specs/VERSIONING_POLICY.md`.
- [ ] `CHANGELOG.md` exists and follows the Keep a Changelog format.
- [ ] Deprecation annotations are applied to public APIs before removal.
- [ ] Release branches and tags follow the `release/x.y` and `vX.Y.Z` conventions.
- [ ] `pubspec.yaml` version is bumped and synchronized with `CHANGELOG.md` for
      every release.
- [ ] `dart_ipfs` compatibility is documented for each pre-1.0 and stable release.





## Used By

- [ROADMAP.md](ROADMAP.md) — References ROADMAP for phased implementation timeline.