import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:quic_lib/src/http3/huffman.dart';
import 'package:quic_lib/src/http3/qpack_string.dart';

void main() {
  group('HuffmanEncoder', () {
    test('round-trip ASCII string', () {
      const input = 'Hello World';
      final encoded = HuffmanEncoder.encode(input);
      final decoded = HuffmanDecoder.decode(encoded);
      expect(decoded, equals(input));
    });

    test('round-trip common HTTP header characters', () {
      const input = 'content-type: application/json';
      final encoded = HuffmanEncoder.encode(input);
      final decoded = HuffmanDecoder.decode(encoded);
      expect(decoded, equals(input));
    });

    test('empty string', () {
      final encoded = HuffmanEncoder.encode('');
      expect(encoded, isEmpty);
      final decoded = HuffmanDecoder.decode(encoded);
      expect(decoded, isEmpty);
    });

    test('single character', () {
      const input = 'a';
      final encoded = HuffmanEncoder.encode(input);
      final decoded = HuffmanDecoder.decode(encoded);
      expect(decoded, equals(input));
    });

    test('single space character', () {
      const input = ' ';
      final encoded = HuffmanEncoder.encode(input);
      final decoded = HuffmanDecoder.decode(encoded);
      expect(decoded, equals(input));
    });
  });

  group('HuffmanDecoder', () {
    test('decodes all printable ASCII characters', () {
      const input =
          ' !"#\$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~';
      final encoded = HuffmanEncoder.encode(input);
      final decoded = HuffmanDecoder.decode(encoded);
      expect(decoded, equals(input));
    });

    test('decodes empty input to empty string', () {
      final decoded = HuffmanDecoder.decode(Uint8List(0));
      expect(decoded, isEmpty);
    });
  });

  group('QpackString Huffman integration', () {
    test('encode with huffman=true sets flag and encodes payload', () {
      const input = 'test';
      final encoded = QpackString.encode(input, huffman: true);
      expect(encoded[0] & 0x80, isNonZero); // Huffman flag set

      final (decoded, _) = QpackString.decode(encoded, 0);
      expect(decoded, equals(input));
    });

    test('encode with huffman=false does not set flag', () {
      const input = 'test';
      final encoded = QpackString.encode(input, huffman: false);
      expect(encoded[0] & 0x80, equals(0)); // Huffman flag clear

      final (decoded, _) = QpackString.decode(encoded, 0);
      expect(decoded, equals(input));
    });

    test('round-trip with huffman on long HTTP header value', () {
      const input =
          'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8';
      final encoded = QpackString.encode(input, huffman: true);
      final (decoded, _) = QpackString.decode(encoded, 0);
      expect(decoded, equals(input));
    });
  });
}
