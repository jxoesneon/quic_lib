import 'package:test/test.dart';
import 'hex.dart';

void main() {
  group('hexDecode', () {
    test('decodes empty string to empty list', () {
      expect(hexDecode(''), isEmpty);
    });

    test('decodes simple bytes', () {
      expect(hexDecode('00'), [0x00]);
      expect(hexDecode('ff'), [0xff]);
      expect(hexDecode('c0ffee'), [0xc0, 0xff, 0xee]);
    });

    test('ignores spaces', () {
      expect(hexDecode('c0 ff ee'), [0xc0, 0xff, 0xee]);
      expect(hexDecode('  c0  ff   ee  '), [0xc0, 0xff, 0xee]);
    });

    test('throws on odd-length input', () {
      expect(() => hexDecode('0'), throwsFormatException);
    });

    test('throws on invalid hex characters', () {
      expect(() => hexDecode('gg'), throwsFormatException);
    });
  });

  group('hexEncode', () {
    test('encodes empty list to empty string', () {
      expect(hexEncode([]), '');
    });

    test('encodes bytes with spaces', () {
      expect(hexEncode([0xc0, 0xff, 0xee]), 'c0 ff ee');
      expect(hexEncode([0x00, 0x0f, 0xff]), '00 0f ff');
    });
  });

  test('round-trip encode/decode', () {
    final original = [0x00, 0x01, 0x7f, 0x80, 0xff];
    expect(hexDecode(hexEncode(original)), original);
  });
}
