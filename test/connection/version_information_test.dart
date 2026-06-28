import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:quic_lib/src/connection/version_information.dart';

void main() {
  group('VersionInformation', () {
    test('serialize/parse round-trip', () {
      final info = VersionInformation(
        chosenVersion: 0x00000001,
        availableVersions: [0x00000001],
      );
      final bytes = info.serialize();
      expect(bytes.length, equals(8));

      final parsed = VersionInformation.parse(bytes);
      expect(parsed.chosenVersion, equals(0x00000001));
      expect(parsed.availableVersions, equals([0x00000001]));
    });

    test('round-trip with multiple available versions', () {
      final info = VersionInformation(
        chosenVersion: 0x6b3343cf,
        availableVersions: [0x6b3343cf, 0x00000001],
        otherVersions: [0xbaadca11],
      );
      final bytes = info.serialize();
      expect(bytes.length, equals(4 + (3 * 4))); // chosen + 3 versions

      final parsed = VersionInformation.parse(bytes);
      expect(parsed.chosenVersion, equals(0x6b3343cf));
      expect(parsed.availableVersions,
          equals([0x6b3343cf, 0x00000001, 0xbaadca11]));
    });

    test('isVersionCompatible returns true when version is available', () {
      final info = VersionInformation(
        chosenVersion: 0x00000001,
        availableVersions: [0x00000001, 0x6b3343cf],
      );
      expect(info.isVersionCompatible(0x6b3343cf), isTrue);
    });

    test('isVersionCompatible returns false when version is not available', () {
      final info = VersionInformation(
        chosenVersion: 0x00000001,
        availableVersions: [0x00000001],
      );
      expect(info.isVersionCompatible(0x6b3343cf), isFalse);
    });

    test(
        'isZeroRttCompatible returns true when chosen version is in server available versions',
        () {
      final clientInfo = VersionInformation(
        chosenVersion: 0x00000001,
        availableVersions: [0x00000001, 0x6b3343cf],
      );
      final serverInfo = VersionInformation(
        chosenVersion: 0x6b3343cf,
        availableVersions: [0x6b3343cf, 0x00000001],
      );
      expect(clientInfo.isZeroRttCompatible(serverInfo), isTrue);
    });

    test(
        'isZeroRttCompatible returns false when chosen version is not in server available versions',
        () {
      final clientInfo = VersionInformation(
        chosenVersion: 0x6b3343cf,
        availableVersions: [0x6b3343cf],
      );
      final serverInfo = VersionInformation(
        chosenVersion: 0x00000001,
        availableVersions: [0x00000001],
      );
      expect(clientInfo.isZeroRttCompatible(serverInfo), isFalse);
    });

    test('parse throws FormatException for length less than 4', () {
      expect(
        () => VersionInformation.parse(Uint8List.fromList([0x00, 0x00, 0x00])),
        throwsA(isA<FormatException>()),
      );
    });

    test('parse throws FormatException for non-multiple-of-4 length', () {
      expect(
        () => VersionInformation.parse(
            Uint8List.fromList([0x00, 0x00, 0x00, 0x01, 0x00])),
        throwsA(isA<FormatException>()),
      );
    });
  });
}
