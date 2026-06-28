import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:quic_lib/src/libp2p/multiaddr.dart';

void main() {
  group('Multiaddr', () {
    test('parse from human-readable string', () {
      final ma = Multiaddr.parse('/ip4/127.0.0.1/tcp/80');
      expect(ma.protocols, equals(['ip4', 'tcp']));
      expect(ma.components[0].value, equals('127.0.0.1'));
      expect(ma.components[1].value, equals('80'));
    });

    test('toHumanReadable round-trip', () {
      const input = '/ip4/127.0.0.1/udp/1234/quic-v1';
      final ma = Multiaddr.parse(input);
      expect(ma.toHumanReadable(), equals(input));
    });

    test('parse /ip4/127.0.0.1/udp/1234/quic-v1', () {
      final ma = Multiaddr.parse('/ip4/127.0.0.1/udp/1234/quic-v1');
      expect(ma.protocols, equals(['ip4', 'udp', 'quic-v1']));
      expect(ma.components[0].value, equals('127.0.0.1'));
      expect(ma.components[1].value, equals('1234'));
      expect(ma.components[2].value, isNull);
    });

    test('parse /dns4/example.com/tcp/443/tls/ws', () {
      final ma = Multiaddr.parse('/dns4/example.com/tcp/443/tls/ws');
      expect(ma.protocols, equals(['dns4', 'tcp', 'tls', 'ws']));
      expect(ma.components[0].value, equals('example.com'));
      expect(ma.components[1].value, equals('443'));
      expect(ma.components[2].value, isNull);
      expect(ma.components[3].value, isNull);
    });

    test('empty multiaddr', () {
      final ma = Multiaddr.parse('');
      expect(ma.protocols, isEmpty);
      expect(ma.toHumanReadable(), equals('/'));
      expect(ma.toBytes(), equals(Uint8List(0)));
    });

    test('fromBytes round-trip', () {
      final ma1 = Multiaddr.parse('/ip4/127.0.0.1/udp/1234/quic-v1');
      final bytes = ma1.toBytes();
      final ma2 = Multiaddr.fromBytes(bytes);
      expect(ma2, equals(ma1));
    });

    test('binary format for /ip4/127.0.0.1/udp/1234', () {
      final ma = Multiaddr.parse('/ip4/127.0.0.1/udp/1234');
      final bytes = ma.toBytes();
      // ip4 code=4 -> 0x04, ip4 value=127.0.0.1 -> 7f 00 00 01
      // udp code=273 -> uvarint: 0x11 0x02, udp value=1234 -> 0x04d2
      expect(
        bytes,
        equals(
          Uint8List.fromList([
            0x04,
            0x7f,
            0x00,
            0x00,
            0x01,
            0x91,
            0x02,
            0x04,
            0xd2,
          ]),
        ),
      );
    });

    test('binary format with variable-length protocol', () {
      final ma = Multiaddr.parse('/dns4/example.com/tcp/443');
      final bytes = ma.toBytes();
      // dns4 code=54 -> uvarint: 0x36
      // length=11 -> 0x0b
      // value = 'example.com' -> UTF-8 bytes
      // tcp code=6 -> 0x06
      // port=443 -> 0x01bb
      final expected = Uint8List.fromList([
        0x36, // dns4 code (54)
        0x0b, // length 11
        ...'example.com'.codeUnits,
        0x06, // tcp code
        0x01, // port high byte
        0xbb, // port low byte
      ]);
      expect(bytes, equals(expected));

      final ma2 = Multiaddr.fromBytes(bytes);
      expect(ma2, equals(ma));
    });

    test('p2p round-trip', () {
      const input = '/ip4/1.2.3.4/tcp/5678/p2p/QmPeerId';
      final ma1 = Multiaddr.parse(input);
      final bytes = ma1.toBytes();
      final ma2 = Multiaddr.fromBytes(bytes);
      expect(ma2.toHumanReadable(), equals(input));
    });
  });
}
