import 'dart:convert';
import 'dart:typed_data';

import 'package:quic_lib/src/libp2p/multistream_select.dart';
import 'package:test/test.dart';

void main() {
  group('MultistreamSelect', () {
    test('header encoding', () {
      final header = MultistreamSelect.header;
      final expected = utf8.encode('/multistream/1.0.0\n');
      expect(header, equals(Uint8List.fromList(expected)));
    });

    test('encodeProtocol single', () {
      final bytes = MultistreamSelect.encodeProtocol('/ipfs/1.0.0');
      final expected = utf8.encode('/ipfs/1.0.0\n');
      expect(bytes, equals(Uint8List.fromList(expected)));
    });

    test('encodeProtocols list', () {
      final bytes = MultistreamSelect.encodeProtocols([
        '/ipfs/1.0.0',
        '/libp2p/1.0.0',
      ]);
      final expected = utf8.encode('/ipfs/1.0.0\n/libp2p/1.0.0\n');
      expect(bytes, equals(Uint8List.fromList(expected)));
    });

    test('na response', () {
      final na = MultistreamSelect.na;
      final expected = utf8.encode('na\n');
      expect(na, equals(Uint8List.fromList(expected)));
    });

    test('parseMessages single', () {
      final bytes = utf8.encode('/multistream/1.0.0\n');
      final messages = MultistreamSelect.parseMessages(
        Uint8List.fromList(bytes),
      );
      expect(messages, equals(['/multistream/1.0.0']));
    });

    test('parseMessages multiple', () {
      final bytes = utf8.encode('/ipfs/1.0.0\n/libp2p/1.0.0\n');
      final messages = MultistreamSelect.parseMessages(
        Uint8List.fromList(bytes),
      );
      expect(messages, equals(['/ipfs/1.0.0', '/libp2p/1.0.0']));
    });

    test('parseMessages ignores empty splits', () {
      final bytes = utf8.encode('/ipfs/1.0.0\n\n');
      final messages = MultistreamSelect.parseMessages(
        Uint8List.fromList(bytes),
      );
      expect(messages, equals(['/ipfs/1.0.0']));
    });

    test('roundtrip encode and parse', () {
      final protocols = ['/foo/1.0.0', '/bar/2.0.0'];
      final encoded = MultistreamSelect.encodeProtocols(protocols);
      final parsed = MultistreamSelect.parseMessages(encoded);
      expect(parsed, equals(protocols));
    });
  });
}
