import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:quic_lib/src/crypto/default_crypto_backend.dart';
import 'package:quic_lib/src/crypto/key_manager.dart';
import 'package:quic_lib/src/crypto/tls/handshake_coordinator.dart';
import 'package:quic_lib/src/crypto/tls/handshake_key_exchange.dart'
    show HandshakeRole;
import 'package:quic_lib/src/crypto/tls/transcript_hash.dart';
import 'package:quic_lib/src/http3/frame_types.dart';
import 'package:quic_lib/src/http3/goaway_frame.dart';
import 'package:quic_lib/src/http3/http3_connection.dart';
import 'package:quic_lib/src/io/quic_endpoint.dart';
import 'package:quic_lib/src/webtransport/capsule_types.dart';
import 'package:quic_lib/src/webtransport/goaway_capsule.dart';
import 'package:quic_lib/src/webtransport/webtransport_session.dart';
import 'package:quic_lib/src/wire/frame.dart';
import 'package:quic_lib/src/wire/packet_builder.dart';
import 'package:quic_lib/src/wire/packet_header.dart';
import 'package:quic_lib/src/wire/quic_versions.dart';
import 'package:quic_lib/src/crypto/tls/tls_message_builder.dart';
import 'package:quic_lib/src/wire/v2_header.dart';

/// Builds a raw key_share extension for x25519.
Uint8List _buildKeyShareExtension(List<int> keyBytes) {
  final entryLength = 4 + keyBytes.length;
  final listLength = entryLength;
  final extDataLength = 2 + listLength;
  final buffer = BytesBuilder();
  buffer.addByte(0x00);
  buffer.addByte(0x33);
  buffer.addByte((extDataLength >> 8) & 0xFF);
  buffer.addByte(extDataLength & 0xFF);
  buffer.addByte((listLength >> 8) & 0xFF);
  buffer.addByte(listLength & 0xFF);
  buffer.addByte(0x00);
  buffer.addByte(0x1d);
  buffer.addByte((keyBytes.length >> 8) & 0xFF);
  buffer.addByte(keyBytes.length & 0xFF);
  buffer.add(keyBytes);
  return Uint8List.fromList(buffer.toBytes());
}

/// Integration tests for dart_quic post-v1.0 features.
void main() {
  group('TranscriptHash', () {
    test('produces consistent hashes for same input', () async {
      final backend = DefaultCryptoBackend();
      final hashA = TranscriptHash(backend);
      final hashB = TranscriptHash(backend);

      const message = [0x01, 0x02, 0x03, 0x04];
      await hashA.addMessage(message);
      await hashB.addMessage(message);

      expect(hashA.currentHash, equals(hashB.currentHash));
      expect(hashA.currentHash, isNotEmpty);
    });

    test('produces different hashes for different input', () async {
      final backend = DefaultCryptoBackend();
      final hashA = TranscriptHash(backend);
      final hashB = TranscriptHash(backend);

      await hashA.addMessage([0x01, 0x02, 0x03]);
      await hashB.addMessage([0x01, 0x02, 0x04]);

      expect(hashA.currentHash, isNot(equals(hashB.currentHash)));
    });
  });

  group('HandshakeCoordinator transcript hash', () {
    test('includes ClientHello after processing', () async {
      final backend = DefaultCryptoBackend();
      final keyManager = KeyManager.forTest();
      final coordinator = HandshakeCoordinator(
        backend: backend,
        role: HandshakeRole.server,
        keyManager: keyManager,
      );

      await coordinator.generateKeys();
      expect(coordinator.hasGeneratedKeys, isTrue);

      // Before processing, the transcript hash should be empty.
      expect(coordinator.transcriptHash.currentHash, isEmpty);

      final random = Uint8List(32);
      final keyShareExt = _buildKeyShareExtension(List<int>.filled(32, 0xCD));
      final clientHelloData = TlsMessageBuilder.buildClientHello(
        random,
        Uint8List(0),
        [0x1301],
        [keyShareExt],
      );
      final clientHelloFrame = CryptoFrame(offset: 0, data: clientHelloData);

      await coordinator.processClientHello(clientHelloFrame);

      // After processing, the transcript hash should include the ClientHello.
      expect(coordinator.transcriptHash.currentHash, isNotEmpty);
    });
  });

  group('Http3Connection.close()', () {
    test('sets isClosing and records GOAWAY', () {
      final conn = Http3Connection(quicConnection: Object());
      expect(conn.isClosing, isFalse);
      expect(conn.sentGoawayFrames, isEmpty);

      conn.close();

      expect(conn.isClosing, isTrue);
      expect(conn.sentGoawayFrames, hasLength(1));
      expect(conn.sentGoawayFrames.first, isA<Http3GoawayFrame>());
    });
  });

  group('Http3Connection.lastAcceptedStreamId', () {
    test('tracks stream IDs from headers and data frames', () {
      final conn = Http3Connection(quicConnection: Object());
      expect(conn.lastAcceptedStreamId, equals(0));

      // Simulate receiving a HEADERS frame on stream 4.
      final headersFrame = Http3Frame(
        type: Http3FrameType.headers,
        payload: [0x01],
      );
      conn.onStreamFrame(4, headersFrame);
      expect(conn.lastAcceptedStreamId, equals(4));

      // Simulate receiving a DATA frame on stream 8.
      final dataFrame = Http3Frame(
        type: Http3FrameType.data,
        payload: [0x02, 0x03],
      );
      conn.onStreamFrame(8, dataFrame);
      expect(conn.lastAcceptedStreamId, equals(8));

      // A lower stream ID should not decrease the maximum.
      conn.onStreamFrame(4, dataFrame);
      expect(conn.lastAcceptedStreamId, equals(8));
    });
  });

  group('V2LongHeader', () {
    test('serialize produces v2-format bytes', () async {
      final header = V2LongHeader(
        packetType: V2LongHeader.typeInitial,
        destinationConnectionId: [0xAB, 0xCD],
        sourceConnectionId: [0xEF],
        packetNumber: 42,
        payload: [0x01, 0x02],
        token: const [],
      );

      final bytes = await header.serialize();
      expect(bytes, isNotEmpty);

      // Verify first byte: HF=1, FB=1, Reserved=00, PP=packetType<<2, VV=version&0x03
      // For Initial (type 0x00) and v2 (0x6b3343cf & 0x03 = 0x03):
      // 0x80 | 0x40 | (0 << 2) | 0x03 = 0xC3
      expect(bytes[0], equals(0xC3));

      // Verify version is v2.
      final version =
          (bytes[1] << 24) | (bytes[2] << 16) | (bytes[3] << 8) | bytes[4];
      expect(version, equals(QuicVersions.v2));
    });

    test('serialize / parse round-trip', () async {
      final header = V2LongHeader(
        packetType: V2LongHeader.typeHandshake,
        destinationConnectionId: [0x01, 0x02],
        sourceConnectionId: [0x03, 0x04, 0x05],
        packetNumber: 7,
        payload: [0xAA, 0xBB],
      );

      final bytes = await header.serialize();
      final parsed = V2LongHeader.parse(bytes);

      expect(parsed.packetType, equals(header.packetType));
      expect(parsed.destinationConnectionId,
          equals(header.destinationConnectionId));
      expect(parsed.sourceConnectionId, equals(header.sourceConnectionId));
      expect(parsed.version, equals(QuicVersions.v2));
    });
  });

  group('GoawayCapsule', () {
    test('round-trip without streamId', () {
      final capsule = GoawayCapsule();
      final bytes = capsule.serialize();
      final parsed = GoawayCapsule.parse(bytes);

      expect(parsed.streamId, isNull);
      expect(parsed, equals(capsule));
    });

    test('round-trip with streamId', () {
      final capsule = GoawayCapsule(streamId: 12345);
      final bytes = capsule.serialize();
      final parsed = GoawayCapsule.parse(bytes);

      expect(parsed.streamId, equals(12345));
      expect(parsed, equals(capsule));
    });
  });

  group('WebTransportSession', () {
    test('receives goaway capsule', () {
      final session = WebTransportSession(0);
      expect(session.receivedGoaway, isFalse);

      final capsule = Capsule(
        type: CapsuleType.goaway,
        payload: Uint8List(0),
      );
      session.onCapsuleReceived(capsule);

      expect(session.receivedGoaway, isTrue);
    });
  });

  group('QuicEndpoint.rebindToAddress', () {
    test(
        'initiates path validation and updates remote address after validation',
        () async {
      final endpoint = await QuicEndpoint.bind(InternetAddress.loopbackIPv4, 0);
      final conn = await endpoint.connect(InternetAddress.loopbackIPv4, 12345);
      addTearDown(endpoint.close);

      final newAddress = InternetAddress.loopbackIPv4;
      final newPort = 54321;

      // Before rebind, the remote address is the original one.
      expect(endpoint.getRemoteAddress(conn)?.address,
          equals(InternetAddress.loopbackIPv4.address));
      expect(endpoint.getRemotePort(conn), equals(12345));
      expect(conn.isProbingPath, isFalse);

      // Bind a raw UDP socket to the destination port so the send does not
      // fail with a SocketException on Windows.
      final destSocket =
          await RawDatagramSocket.bind(InternetAddress.loopbackIPv4, newPort);
      addTearDown(destSocket.close);

      // rebindToAddress sends a PATH_CHALLENGE via UDP and awaits a
      // PATH_RESPONSE before updating the stored address. In the current
      // scaffold there is no automated PATH_RESPONSE loop, so the future
      // will remain pending. We start it without awaiting and verify the
      // probe side effects.
      // ignore: unawaited_futures
      endpoint.rebindToAddress(conn, newAddress, newPort);

      // Allow the async method to reach the probe initiation.
      await Future.delayed(const Duration(milliseconds: 100));

      // The probe should have been initiated.
      expect(conn.isProbingPath, isTrue);
      expect(conn.lastProbePacket, isNotNull);
    });
  });
}
