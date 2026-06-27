import 'package:test/test.dart';
import 'varint_test_cases.dart';

void main() {
  group('varintTestCases', () {
    test('contains the expected number of cases', () {
      expect(varintTestCases, hasLength(9));
    });

    test('case 0 encodes to [0x00]', () {
      final case0 = varintTestCases.firstWhere((c) => c['value'] == 0);
      expect(case0['bytes'], [0x00]);
      expect(case0['width'], 1);
    });

    test('case 1 encodes to [0x01]', () {
      final case1 = varintTestCases.firstWhere((c) => c['value'] == 1);
      expect(case1['bytes'], [0x01]);
      expect(case1['width'], 1);
    });

    test('case 63 encodes to [0x3f]', () {
      final case63 = varintTestCases.firstWhere((c) => c['value'] == 63);
      expect(case63['bytes'], [0x3f]);
      expect(case63['width'], 1);
    });

    test('case 64 encodes to [0x40, 0x40]', () {
      final case64 = varintTestCases.firstWhere((c) => c['value'] == 64);
      expect(case64['bytes'], [0x40, 0x40]);
      expect(case64['width'], 2);
    });

    test('case 16383 encodes to [0x7f, 0xff]', () {
      final case16383 = varintTestCases.firstWhere((c) => c['value'] == 16383);
      expect(case16383['bytes'], [0x7f, 0xff]);
      expect(case16383['width'], 2);
    });

    test('case 16384 encodes to [0x80, 0x00, 0x40, 0x00]', () {
      final case16384 = varintTestCases.firstWhere((c) => c['value'] == 16384);
      expect(case16384['bytes'], [0x80, 0x00, 0x40, 0x00]);
      expect(case16384['width'], 4);
    });

    test('case 1073741823 encodes to 4-byte width', () {
      final caseMax4 =
          varintTestCases.firstWhere((c) => c['value'] == 1073741823);
      expect(caseMax4['bytes'], [0xbf, 0xff, 0xff, 0xff]);
      expect(caseMax4['width'], 4);
    });

    test('case 1073741824 encodes to 8-byte width', () {
      final caseMin8 =
          varintTestCases.firstWhere((c) => c['value'] == 1073741824);
      expect(caseMin8['bytes'],
          [0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00]);
      expect(caseMin8['width'], 8);
    });

    test('case 4611686018427387903 encodes to all 0xff', () {
      final caseMax8 = varintTestCases
          .firstWhere((c) => c['value'] == 4611686018427387903);
      expect(caseMax8['bytes'],
          [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
      expect(caseMax8['width'], 8);
    });
  });
}
