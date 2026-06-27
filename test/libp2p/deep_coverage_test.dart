import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:dart_quic/src/libp2p/multiaddr.dart';
import 'package:dart_quic/src/libp2p/peer_id.dart';

void main() {
  group('Multiaddr deep coverage', () {
    test('parse /ip6/::1/udp/1234/quic-v1', () {
      final ma = Multiaddr.parse('/ip6/::1/udp/1234/quic-v1');
      expect(ma.protocols, equals(['ip6', 'udp', 'quic-v1']));
      expect(ma.components[0].value, equals('::1'));
      expect(ma.components[1].value, equals('1234'));
      expect(ma.components[2].value, isNull);
    });

    test('parse /dns6/example.com/tcp/443', () {
      final ma = Multiaddr.parse('/dns6/example.com/tcp/443');
      expect(ma.protocols, equals(['dns6', 'tcp']));
      expect(ma.components[0].value, equals('example.com'));
      expect(ma.components[1].value, equals('443'));
    });

    test('parse /ws (protocol without value)', () {
      final ma = Multiaddr.parse('/ws');
      expect(ma.protocols, equals(['ws']));
      expect(ma.components[0].value, isNull);
      expect(ma.toHumanReadable(), equals('/ws'));
    });

    test('parse /wss (protocol without value)', () {
      final ma = Multiaddr.parse('/wss');
      expect(ma.protocols, equals(['wss']));
      expect(ma.components[0].value, isNull);
      expect(ma.toHumanReadable(), equals('/wss'));
    });

    test('parse /p2p/1220... (40-char hex peer ID)', () {
      const hex40 = '122000000000000000000000000000000000000000';
      final ma = Multiaddr.parse('/p2p/$hex40');
      expect(ma.protocols, equals(['p2p']));
      expect(ma.components[0].value, equals(hex40));
    });

    test('parse multiple consecutive same-type protocols', () {
      final ma = Multiaddr.parse('/ip4/1.2.3.4/tcp/80/tcp/443');
      expect(ma.protocols, equals(['ip4', 'tcp', 'tcp']));
      expect(ma.components[0].value, equals('1.2.3.4'));
      expect(ma.components[1].value, equals('80'));
      expect(ma.components[2].value, equals('443'));
    });

    test('fromBytes with binary format: uvarint(protocol_code) + value', () {
      // /ip4/192.168.1.1/tcp/80
      final bytes = Uint8List.fromList([
        0x04, // ip4 code
        192, 168, 1, 1, // ip4 value
        0x06, // tcp code
        0x00, 80, // port 80
      ]);
      final ma = Multiaddr.fromBytes(bytes);
      expect(ma.protocols, equals(['ip4', 'tcp']));
      expect(ma.components[0].value, equals('192.168.1.1'));
      expect(ma.components[1].value, equals('80'));
    });

    test('fromBytes with empty bytes (empty multiaddr)', () {
      final ma = Multiaddr.fromBytes(Uint8List(0));
      expect(ma.protocols, isEmpty);
      expect(ma.toHumanReadable(), equals('/'));
    });

    test('toBytes round-trip', () {
      final ma1 = Multiaddr.parse('/ip6/::1/udp/1234/quic-v1');
      final bytes = ma1.toBytes();
      final ma2 = Multiaddr.fromBytes(bytes);
      expect(ma2, equals(ma1));
      expect(ma2.toHumanReadable(), equals(ma1.toHumanReadable()));
    });

    test('toHumanReadable round-trip for complex addresses', () {
      const input = '/dns6/example.com/tcp/443/tls/ws';
      final ma = Multiaddr.parse(input);
      expect(ma.toHumanReadable(), equals(input));
    });

    test('MultiaddrComponent with protocol that has no value (quic-v1)', () {
      const comp = MultiaddrComponent(protocol: 'quic-v1');
      expect(comp.protocol, equals('quic-v1'));
      expect(comp.value, isNull);
      expect(comp, equals(const MultiaddrComponent(protocol: 'quic-v1')));
    });

    test('Multiaddr.get protocols for mixed address', () {
      final ma = Multiaddr.parse('/ip4/1.2.3.4/tcp/80/udp/1234/quic-v1');
      expect(ma.protocols, equals(['ip4', 'tcp', 'udp', 'quic-v1']));
    });

    test('parse /ip4/0.0.0.0/tcp/0 (edge values)', () {
      final ma = Multiaddr.parse('/ip4/0.0.0.0/tcp/0');
      expect(ma.components[0].value, equals('0.0.0.0'));
      expect(ma.components[1].value, equals('0'));
    });

    test('parse /ip6/2001:db8::1/tcp/8080', () {
      final ma = Multiaddr.parse('/ip6/2001:db8::1/tcp/8080');
      expect(ma.protocols, equals(['ip6', 'tcp']));
      expect(ma.components[0].value, equals('2001:db8::1'));
      expect(ma.components[1].value, equals('8080'));
    });

    test('fromBytes with variable-length protocol (dns4)', () {
      // /dns4/example.com/tcp/443
      final domain = utf8.encode('example.com');
      final bytes = Uint8List.fromList([
        0x36, // dns4 code (54)
        domain.length, // length uvarint
        ...domain,
        0x06, // tcp code
        0x01, 0xbb, // port 443
      ]);
      final ma = Multiaddr.fromBytes(bytes);
      expect(ma.protocols, equals(['dns4', 'tcp']));
      expect(ma.components[0].value, equals('example.com'));
      expect(ma.components[1].value, equals('443'));
    });

    test('fromBytes with fixed-length protocol (ip4)', () {
      // /ip4/10.0.0.1
      final bytes = Uint8List.fromList([
        0x04, // ip4 code
        10, 0, 0, 1,
      ]);
      final ma = Multiaddr.fromBytes(bytes);
      expect(ma.protocols, equals(['ip4']));
      expect(ma.components[0].value, equals('10.0.0.1'));
    });

    test('error handling: invalid IP format', () {
      expect(
        () => Multiaddr.parse('/ip4/999.999.999.999/tcp/80'),
        throwsA(isA<FormatException>()),
      );
    });

    test('error handling: unknown protocol in string', () {
      expect(
        () => Multiaddr.parse('/unknown/thing'),
        throwsA(isA<FormatException>()),
      );
    });

    test('error handling: malformed binary (truncated)', () {
      // ip4 code (4) followed by only 3 bytes instead of 4
      final bytes = Uint8List.fromList([0x04, 0x7f, 0x00, 0x00]);
      expect(
        () => Multiaddr.fromBytes(bytes),
        throwsA(isA<FormatException>()),
      );
    });

    test('MultiaddrComponent.toString with null value', () {
      const comp = MultiaddrComponent(protocol: 'ws');
      expect(comp.toString(), contains('MultiaddrComponent'));
    });

    test('MultiaddrComponent.toString with non-null value', () {
      const comp = MultiaddrComponent(protocol: 'ip4', value: '127.0.0.1');
      expect(comp.toString(), contains('MultiaddrComponent'));
    });
  });

  group('PeerId deep coverage', () {
    test('fromBytes with empty list', () {
      final peerId = PeerId.fromBytes(<int>[]);
      expect(peerId.bytes, isEmpty);
      expect(peerId.toString(), equals(''));
    });

    test('fromBytes with 32-byte list', () {
      final bytes = List<int>.generate(32, (i) => i % 256);
      final peerId = PeerId.fromBytes(bytes);
      expect(peerId.bytes, orderedEquals(bytes));
      expect(peerId.bytes.length, equals(32));
    });

    test('fromBytes with 34-byte list', () {
      final bytes = List<int>.generate(34, (i) => (i * 7) % 256);
      final peerId = PeerId.fromBytes(bytes);
      expect(peerId.bytes, orderedEquals(bytes));
      expect(peerId.bytes.length, equals(34));
    });

    test('toString returns hex', () {
      final peerId = PeerId.fromBytes(<int>[0xab, 0xcd, 0xef]);
      expect(peerId.toString(), equals('abcdef'));
    });

    test('equality with same bytes (different instances)', () {
      final a = PeerId.fromBytes(<int>[1, 2, 3, 4]);
      final b = PeerId.fromBytes(<int>[1, 2, 3, 4]);
      expect(a, equals(b));
      expect(a == b, isTrue);
      expect(identical(a, b), isFalse);
    });

    test('inequality with different length bytes', () {
      final a = PeerId.fromBytes(<int>[1, 2, 3]);
      final b = PeerId.fromBytes(<int>[1, 2, 3, 4]);
      expect(a, isNot(equals(b)));
      expect(a == b, isFalse);
    });

    test('hashCode consistent across instances with same bytes', () {
      final a = PeerId.fromBytes(<int>[5, 6, 7, 8, 9]);
      final b = PeerId.fromBytes(<int>[5, 6, 7, 8, 9]);
      expect(a.hashCode, equals(b.hashCode));
    });

    test('fromBase58 round-trips with toBase58', () {
      final peerId = PeerId.fromBytes(<int>[1, 2, 3]);
      final encoded = peerId.toBase58();
      final decoded = PeerId.fromBase58(encoded);
      expect(decoded, equals(peerId));
    });

    test('toBase58 produces non-empty string', () {
      final peerId = PeerId.fromBytes(<int>[1, 2, 3]);
      final encoded = peerId.toBase58();
      expect(encoded, isNotEmpty);
    });

    test('toBase36 produces non-empty string', () {
      final peerId = PeerId.fromBytes(<int>[1, 2, 3]);
      final encoded = peerId.toBase36();
      expect(encoded, isNotEmpty);
    });

    test('equality with non-PeerId object returns false', () {
      final peerId = PeerId.fromBytes(<int>[1, 2, 3]);
      final Object str = 'not a peer id';
      final Object num = 123;
      expect(peerId == str, isFalse);
      expect(peerId == num, isFalse);
    });

    test('toString with bytes containing all zeros', () {
      final peerId = PeerId.fromBytes(List<int>.filled(5, 0));
      expect(peerId.toString(), equals('0000000000'));
    });
  });
}
