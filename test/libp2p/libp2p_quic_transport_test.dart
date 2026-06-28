import 'dart:typed_data';

import 'package:quic_lib/src/libp2p/libp2p_quic_transport.dart';
import 'package:quic_lib/src/libp2p/multiaddr.dart';
import 'package:test/test.dart';

void main() {
  group('Libp2pQuicTransport', () {
    test('isClosed is false initially', () {
      final transport = Libp2pQuicTransport();
      expect(transport.isClosed, isFalse);
    });

    test('close sets isClosed to true', () async {
      final transport = Libp2pQuicTransport();
      await transport.close();
      expect(transport.isClosed, isTrue);
    });

    test('dial throws for invalid multiaddr', () async {
      final transport = Libp2pQuicTransport();
      final badAddr = Multiaddr.parse('/dns/example.com');
      expect(() => transport.dial(badAddr), throwsFormatException);
    });

    test('listen throws for invalid multiaddr', () async {
      final transport = Libp2pQuicTransport();
      final badAddr = Multiaddr.parse('/dns/example.com');
      expect(() => transport.listen(badAddr), throwsFormatException);
    });

    test('dial throws when transport is closed', () async {
      final transport = Libp2pQuicTransport();
      await transport.close();
      final addr = Multiaddr.parse('/ip4/127.0.0.1/udp/1234');
      expect(() => transport.dial(addr), throwsStateError);
    });

    test('listen throws when transport is closed', () async {
      final transport = Libp2pQuicTransport();
      await transport.close();
      final addr = Multiaddr.parse('/ip4/127.0.0.1/udp/1234');
      expect(() => transport.listen(addr), throwsStateError);
    });

    test('Libp2pQuicConnection getters', () {
      final conn = Libp2pQuicConnection('test-conn');
      expect(conn.quicConnection, equals('test-conn'));
    });

    test('Libp2pQuicConnection.send on dynamic object', () {
      final fakeConn = _FakeQuicConnection();
      final conn = Libp2pQuicConnection(fakeConn);
      conn.send(Uint8List.fromList([0x01]));
      expect(fakeConn.openUniCalled, isTrue);
    });

    test('Libp2pQuicConnection.close on dynamic object', () {
      final fakeConn = _FakeQuicConnection();
      final conn = Libp2pQuicConnection(fakeConn);
      conn.close();
      expect(fakeConn.closeCalled, isTrue);
    });

    test('Libp2pQuicConnection.send tolerates unsupported connection', () {
      final conn = Libp2pQuicConnection(Object());
      expect(() => conn.send(Uint8List(0)), returnsNormally);
    });

    test('Libp2pQuicConnection.close tolerates unsupported connection', () {
      final conn = Libp2pQuicConnection(Object());
      expect(() => conn.close(), returnsNormally);
    });

    test('dial throws for ip4 without udp', () async {
      final transport = Libp2pQuicTransport();
      final badAddr = Multiaddr.parse('/ip4/127.0.0.1');
      expect(() => transport.dial(badAddr), throwsFormatException);
    });

    test('listen throws for ip4 without udp', () async {
      final transport = Libp2pQuicTransport();
      final badAddr = Multiaddr.parse('/ip4/127.0.0.1');
      expect(() => transport.listen(badAddr), throwsFormatException);
    });

    test('dial throws for udp without ip', () async {
      final transport = Libp2pQuicTransport();
      final badAddr = Multiaddr.parse('/udp/1234');
      expect(() => transport.dial(badAddr), throwsFormatException);
    });

    test('listen throws for udp without ip', () async {
      final transport = Libp2pQuicTransport();
      final badAddr = Multiaddr.parse('/udp/1234');
      expect(() => transport.listen(badAddr), throwsFormatException);
    });

    test('dial throws for invalid IPv4 in multiaddr', () async {
      final transport = Libp2pQuicTransport();
      // Construct a multiaddr with an invalid IP by using ip4 but an invalid value.
      // Multiaddr.parse validates IP, so we build one manually with an invalid IP.
      final badAddr = Multiaddr(components: [
        const MultiaddrComponent(protocol: 'ip4', value: '999.999.999.999'),
        const MultiaddrComponent(protocol: 'udp', value: '1234'),
      ]);
      expect(() => transport.dial(badAddr), throwsFormatException);
    });

    test('listen throws for invalid IPv4 in multiaddr', () async {
      final transport = Libp2pQuicTransport();
      final badAddr = Multiaddr(components: [
        const MultiaddrComponent(protocol: 'ip4', value: '999.999.999.999'),
        const MultiaddrComponent(protocol: 'udp', value: '1234'),
      ]);
      expect(() => transport.listen(badAddr), throwsFormatException);
    });

    test('dial throws for invalid IPv6 in multiaddr', () async {
      final transport = Libp2pQuicTransport();
      final badAddr = Multiaddr(components: [
        const MultiaddrComponent(protocol: 'ip6', value: 'not-an-ipv6'),
        const MultiaddrComponent(protocol: 'udp', value: '1234'),
      ]);
      expect(() => transport.dial(badAddr), throwsFormatException);
    });

    test('listen throws for invalid IPv6 in multiaddr', () async {
      final transport = Libp2pQuicTransport();
      final badAddr = Multiaddr(components: [
        const MultiaddrComponent(protocol: 'ip6', value: 'not-an-ipv6'),
        const MultiaddrComponent(protocol: 'udp', value: '1234'),
      ]);
      expect(() => transport.listen(badAddr), throwsFormatException);
    });

    test('dial succeeds with valid ip4 multiaddr', () async {
      final transport = Libp2pQuicTransport();
      final addr = Multiaddr.parse('/ip4/127.0.0.1/udp/12345');
      final conn = await transport.dial(addr);
      expect(conn, isA<Libp2pQuicConnection>());
      await transport.close();
    });

    test('listen succeeds with valid ip4 multiaddr', () async {
      final transport = Libp2pQuicTransport();
      final addr = Multiaddr.parse('/ip4/127.0.0.1/udp/0');
      final stream = await transport.listen(addr);
      expect(stream, isA<Stream<Libp2pQuicConnection>>());
      await transport.close();
      expect(transport.isClosed, isTrue);
    });

    test('dial succeeds with valid ip6 multiaddr', () async {
      final transport = Libp2pQuicTransport();
      final addr = Multiaddr.parse('/ip6/::1/udp/12345');
      final conn = await transport.dial(addr);
      expect(conn, isA<Libp2pQuicConnection>());
      await transport.close();
    });

    test('listen succeeds with valid ip6 multiaddr', () async {
      final transport = Libp2pQuicTransport();
      final addr = Multiaddr.parse('/ip6/::1/udp/0');
      final stream = await transport.listen(addr);
      expect(stream, isA<Stream<Libp2pQuicConnection>>());
      await transport.close();
      expect(transport.isClosed, isTrue);
    });

    test('close clears listeners', () async {
      final transport = Libp2pQuicTransport();
      final addr = Multiaddr.parse('/ip4/127.0.0.1/udp/0');
      await transport.listen(addr);
      expect(transport.isClosed, isFalse);
      await transport.close();
      expect(transport.isClosed, isTrue);
    });

    test('ALPN defaults to [libp2p]', () {
      final transport = Libp2pQuicTransport();
      expect(transport.alpnProtocols, equals(['libp2p']));
    });

    test('custom ALPN protocols are stored', () {
      final transport = Libp2pQuicTransport(
        alpnProtocols: ['custom/1', 'custom/2'],
      );
      expect(transport.alpnProtocols, equals(['custom/1', 'custom/2']));
    });

    test('Libp2pQuicConnection exposes ALPN fields', () {
      final conn = Libp2pQuicConnection('test-conn');
      expect(conn.alpnProtocols, equals(['libp2p']));
      expect(conn.negotiatedAlpn, isNull);
      expect(conn.isAlpnValid, isFalse);
    });

    test('Libp2pQuicConnection validateAlpn throws when no ALPN negotiated',
        () {
      final conn = Libp2pQuicConnection('test-conn');
      expect(() => conn.validateAlpn(), throwsStateError);
    });

    test(
        'Libp2pQuicConnection validateAlpn throws when negotiated '
        'ALPN is not in list', () {
      final fakeConn = _FakeQuicConnectionWithAlpn('unknown');
      final conn = Libp2pQuicConnection(
        fakeConn,
        alpnProtocols: ['libp2p'],
      );
      expect(() => conn.validateAlpn(), throwsStateError);
    });

    test(
        'Libp2pQuicConnection validateAlpn succeeds when negotiated '
        'ALPN matches', () {
      final fakeConn = _FakeQuicConnectionWithAlpn('libp2p');
      final conn = Libp2pQuicConnection(
        fakeConn,
        alpnProtocols: ['libp2p'],
      );
      expect(conn.isAlpnValid, isTrue);
      expect(() => conn.validateAlpn(), returnsNormally);
    });
  });
}

class _FakeQuicConnection {
  bool openUniCalled = false;
  bool closeCalled = false;
  void openUnidirectionalStream() => openUniCalled = true;
  void close() => closeCalled = true;
}

class _FakeQuicConnectionWithAlpn {
  final String? negotiatedAlpn;
  _FakeQuicConnectionWithAlpn(this.negotiatedAlpn);
}
