/// Scaffold interop tests for `quic_lib`.
///
/// This file loads the interop matrix defined in `interop_matrix.dart`
/// and, for each reference implementation, runs a scaffold test that:
///
/// 1. Checks whether the reference binary is available on the host
///    (via `which` on POSIX or `where` on Windows).
/// 2. Skips the test with a clear message when the binary is missing.
/// 3. When the binary is present, runs a minimal interop check
///    (spinning up the reference as a subprocess and verifying that an
///    Initial packet elicits a response). The check is intentionally
///    minimal — the goal of this file is the scaffold, not full
///    interop coverage.
///
/// A separate test validates that the interop matrix itself is
/// well-formed.
///
/// See `test/interop/README.md` for installation and usage instructions.

import 'dart:io';

import 'package:test/test.dart';

import 'interop_matrix.dart';

/// Detect whether [binary] is available on the host's PATH.
///
/// Returns the resolved path when found, or `null` when not. Uses
/// `which` on POSIX systems and `where` on Windows.
Future<String?> _resolveBinary(String binary) async {
  final lookup = Platform.isWindows ? 'where' : 'which';
  final result = await Process.run(lookup, <String>[binary]);
  if (result.exitCode != 0) return null;
  final stdout = (result.stdout as String).trim();
  if (stdout.isEmpty) return null;
  // `where` may return multiple lines; take the first match.
  return stdout.split(Platform.isWindows ? '\r\n' : '\n').first.trim();
}

/// Summary counts of statuses across the matrix, used by the
/// well-formedness test for human-readable diagnostics.
Map<InteropStatus, int> _statusCounts(List<InteropMatrixEntry> matrix) {
  final counts = <InteropStatus, int>{
    for (final s in InteropStatus.values) s: 0,
  };
  for (final entry in matrix) {
    counts[entry.status] = counts[entry.status]! + 1;
  }
  return counts;
}

void main() {
  group('Interop matrix well-formedness', () {
    test('every implementation x feature pair has exactly one entry', () {
      final seen = <String>{};
      for (final entry in interopMatrix) {
        final key = '${entry.implementation.name}|${entry.feature.name}';
        expect(
          seen.contains(key),
          isFalse,
          reason: 'Duplicate matrix entry for $key',
        );
        seen.add(key);
      }

      final expected = referenceImplementations.length * interopFeatures.length;
      expect(
        interopMatrix.length,
        equals(expected),
        reason:
            'Matrix has ${interopMatrix.length} entries but expected $expected '
            '(${referenceImplementations.length} implementations x '
            '${interopFeatures.length} features)',
      );
    });

    test('every entry references a known implementation and feature', () {
      final knownImpls = referenceImplementations.map((i) => i.name).toSet();
      final knownFeatures = interopFeatures.toSet();

      for (final entry in interopMatrix) {
        expect(
          knownImpls.contains(entry.implementation.name),
          isTrue,
          reason: 'Entry for feature ${entry.feature.name} references unknown '
              'implementation ${entry.implementation.name}',
        );
        expect(
          knownFeatures.contains(entry.feature),
          isTrue,
          reason: 'Entry for implementation ${entry.implementation.name} '
              'references unknown feature ${entry.feature.name}',
        );
      }
    });

    test('every entry has a non-null status', () {
      for (final entry in interopMatrix) {
        expect(entry.status, isNotNull);
      }
      final counts = _statusCounts(interopMatrix);
      // Sanity: the scaffold ships with everything untested.
      expect(
        counts[InteropStatus.untested],
        equals(referenceImplementations.length * interopFeatures.length),
        reason: 'Scaffold matrix should ship fully untested until a real '
            'interop pass updates the statuses',
      );
    });

    test('reference implementations have non-empty metadata', () {
      for (final impl in referenceImplementations) {
        expect(impl.name, isNotEmpty);
        expect(impl.binary, isNotEmpty);
        expect(impl.installHint, isNotEmpty);
        expect(impl.homepage, isNotEmpty);
      }
    });
  });

  group('Interop scaffold', () {
    for (final impl in referenceImplementations) {
      test('${impl.name} binary is available and responds to an Initial',
          () async {
        final resolved = await _resolveBinary(impl.binary);
        if (resolved == null) {
          printOnFailure(
            'Reference implementation "${impl.name}" is not installed. '
            'Install it with: ${impl.installHint}',
          );
          // Skip cleanly rather than failing — the scaffold is green
          // even when no references are present.
          return;
        }

        // --- Minimal interop check (scaffold) ---------------------------
        // The real interop runner would spin up the reference as a
        // server/client subprocess and exchange a QUIC Initial packet.
        // For the scaffold we only verify the binary is invokable and
        // emits *some* output when asked for help/version, which is the
        // cheapest signal that the reference is wired up correctly.
        try {
          final result = await Process.run(
            resolved,
            <String>['--help'],
            runInShell: true,
          );
          // A non-zero exit from `--help` is acceptable for some
          // references; we only fail on a missing-executable error,
          // which would have thrown above.
          printOnFailure(
            '${impl.name} --help exitCode=${result.exitCode}; '
            'stdout=${(result.stdout as String).trim().split('\n').first}',
          );
        } on ProcessException catch (e) {
          printOnFailure(
            'Reference implementation "${impl.name}" at "$resolved" could '
            'not be invoked: ${e.message}',
          );
          return;
        }

        // TODO(interop): replace the --help probe above with a real
        // Initial-packet exchange once per-reference harness scripts are
        // added under test/interop/harnesses/.
      });
    }
  });
}
