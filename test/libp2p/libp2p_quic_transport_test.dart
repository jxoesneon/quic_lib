import 'dart:async';
import 'dart:typed_data';

import 'package:quic_lib/src/crypto/crypto_backend.dart';
import 'package:quic_lib/src/crypto/default_crypto_backend.dart';
import 'package:quic_lib/src/libp2p/libp2p_certificate_generator.dart';
import 'package:quic_lib/src/libp2p/libp2p_quic_transport.dart';
import 'package:quic_lib/src/libp2p/multiaddr.dart';
import 'package:quic_lib/src/libp2p/multistream_select.dart';
import 'package:quic_lib/src/libp2p/peer_id.dart';
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

    test('negotiatedAlpn falls back to dynamic access', () {
      final fakeConn = _FakeQuicConnectionWithAlpn('fallback');
      final conn = Libp2pQuicConnection(fakeConn);
      expect(conn.negotiatedAlpn, equals('fallback'));
    });

    test('negotiatedAlpn returns null when unsupported', () {
      final conn = Libp2pQuicConnection(Object());
      expect(conn.negotiatedAlpn, isNull);
    });

    test('negotiateProtocol uses direct write and read methods', () async {
      final response = MultistreamSelect.encodeLengthPrefixed(
        MultistreamSelect.encodeProtocol('/ipfs/1.0.0'),
      );
      final fakeConn = _FakeQuicConnectionForReadWrite(response);
      final conn = Libp2pQuicConnection(fakeConn);
      final selected = await conn.negotiateProtocol(['/ipfs/1.0.0']);
      expect(selected, equals('/ipfs/1.0.0'));
      expect(fakeConn.writeCalled, isTrue);
    });

    test('readRaw returns null when direct read returns null', () async {
      final fakeConn = _FakeQuicConnectionForReadWrite(null);
      final conn = Libp2pQuicConnection(fakeConn);
      final selected = await conn.negotiateProtocol(['/ipfs/1.0.0']);
      expect(selected, isNull);
    });

    test('negotiateProtocol returns null on empty list', () async {
      final conn = Libp2pQuicConnection(_FakeQuicConnectionWithAlpn(null));
      expect(await conn.negotiateProtocol([]), isNull);
    });

    test('negotiateProtocol handles na response and tries next protocol',
        () async {
      final na = MultistreamSelect.encodeLengthPrefixed(
        MultistreamSelect.encodeProtocol('na'),
      );
      final ok = MultistreamSelect.encodeLengthPrefixed(
        MultistreamSelect.encodeProtocol('/b/2'),
      );
      final fakeConn = _FakeQuicConnectionForReadSequence([na, ok]);
      final conn = Libp2pQuicConnection(fakeConn);
      final selected = await conn.negotiateProtocol(['/a/1', '/b/2']);
      expect(selected, equals('/b/2'));
    });

    test('verifyPeerCertificate validates a generated libp2p cert', () async {
      final backend = DefaultCryptoBackend();
      final hostKeyPair = await backend.ed25519GenerateKeyPair();
      final hostPublicKey = await hostKeyPair.publicKey;
      final expectedPeerId = await PeerId.fromPublicKey(hostPublicKey.bytes);

      final generator = Libp2pCertificateGenerator(backend);
      final chain = await generator.generate(
        hostIdentityPrivateKey: await hostKeyPair.secretKey,
        hostPublicKeyBytes: hostPublicKey.bytes,
      );

      final conn = Libp2pQuicConnection('test');
      final valid = await conn.verifyPeerCertificate(
        chain.certs.first.rawBytes,
        backend: backend,
      );
      expect(valid, isTrue);
      expect(conn.peerId, equals(expectedPeerId));
    });

    test('verifyPeerCertificate fails with mismatched expected PeerId',
        () async {
      final backend = DefaultCryptoBackend();
      final hostKeyPair = await backend.ed25519GenerateKeyPair();
      final hostPublicKey = await hostKeyPair.publicKey;
      final wrongPeerId = await PeerId.fromPublicKey(
        List<int>.generate(32, (i) => 0xFF),
      );

      final generator = Libp2pCertificateGenerator(backend);
      final chain = await generator.generate(
        hostIdentityPrivateKey: await hostKeyPair.secretKey,
        hostPublicKeyBytes: hostPublicKey.bytes,
      );

      final conn = Libp2pQuicConnection('test');
      final valid = await conn.verifyPeerCertificate(
        chain.certs.first.rawBytes,
        expectedPeerId: wrongPeerId,
        backend: backend,
      );
      expect(valid, isFalse);
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

class _FakeQuicConnectionForReadWrite {
  final Uint8List? _response;
  bool writeCalled = false;
  _FakeQuicConnectionForReadWrite(this._response);

  void write(Uint8List data) => writeCalled = true;
  Future<Uint8List?> read() async => _response;
}

class _FakeQuicConnectionForReadSequence {
  final List<Uint8List> _responses;
  int _index = 0;
  _FakeQuicConnectionForReadSequence(this._responses);

  void write(Uint8List data) {}
  Future<Uint8List?> read() async {
    if (_index >= _responses.length) return null;
    return _responses[_index++];
  }
}
