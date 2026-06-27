import 'package:test/test.dart';
import 'package:dart_quic/src/wire/quic_versions.dart';

void main() {
  group('QuicVersions.isSupported', () {
    test('recognizes v1 as supported', () {
      expect(QuicVersions.isSupported(QuicVersions.v1), isTrue);
    });

    test('recognizes v2 as supported', () {
      expect(QuicVersions.isSupported(QuicVersions.v2), isTrue);
    });

    test('unknown version is not supported', () {
      expect(QuicVersions.isSupported(0x00000002), isFalse);
      expect(QuicVersions.isSupported(0xFFFFFFFF), isFalse);
      expect(QuicVersions.isSupported(0), isFalse);
    });
  });

  group('QuicVersions.name', () {
    test('returns "v1" for version 1', () {
      expect(QuicVersions.name(QuicVersions.v1), equals('v1'));
    });

    test('returns "v2" for version 2', () {
      expect(QuicVersions.name(QuicVersions.v2), equals('v2'));
    });

    test('returns "unknown" for unrecognized versions', () {
      expect(QuicVersions.name(0xDEADBEEF), equals('unknown'));
    });
  });
}
