import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:quic_lib/src/connection/connection_state_machine.dart';
import 'package:quic_lib/src/connection/connection_id_manager.dart';
import 'package:quic_lib/src/connection/migration_helper.dart';
import 'package:quic_lib/src/connection/quic_connection.dart';
import 'package:quic_lib/src/crypto/cipher_suites.dart';
import 'package:quic_lib/src/crypto/crypto_backend.dart';
import 'package:quic_lib/src/crypto/default_crypto_backend.dart';
import 'package:quic_lib/src/crypto/initial_secrets.dart';
import 'package:quic_lib/src/crypto/tls/handshake_key_exchange.dart';
import 'package:quic_lib/src/http3/frame_types.dart';
import 'package:quic_lib/src/http3/headers_frame.dart';
import 'package:quic_lib/src/http3/http3_connection.dart';
import 'package:quic_lib/src/http3/http3_request.dart';
import 'package:quic_lib/src/http3/http3_response.dart';
import 'package:quic_lib/src/recovery/congestion_controller.dart';
import 'package:quic_lib/src/recovery/loss_detector.dart';
import 'package:quic_lib/src/recovery/packet_number_space.dart';
import 'package:quic_lib/src/recovery/pto_scheduler.dart';
import 'package:quic_lib/src/recovery/rtt_estimator.dart';
import 'package:quic_lib/src/streams/stream_id.dart';
import 'package:quic_lib/src/webtransport/capsule_types.dart';
import 'package:quic_lib/src/webtransport/datagram_capsule.dart';
import 'package:quic_lib/src/webtransport/webtransport_session.dart';
import 'package:quic_lib/src/wire/frame.dart';

/// Integration tests for dart_quic v0.2.0 features.
void main() {
  final backend = DefaultCryptoBackend();

  // -------------------------------------------------------------------------
  // 1. TLS Key Exchange
  // -------------------------------------------------------------------------
  group('TLS Key Exchange', () {
    test('HandshakeKeyExchange.generateEphemeralKeys produces key pair',
        () async {
      final kx = HandshakeKeyExchange(backend, HandshakeRole.client);
      await kx.generateEphemeralKeys();

      expect(kx.privateKey, isNotNull);
      expect(kx.publicKey, isNotNull);
      expect(kx.privateKey!.extractSync(), isNotEmpty);
      expect(kx.publicKey!.bytes, isNotEmpty);
    });

    test('Two HandshakeKeyExchange instances compute the same shared secret',
        () async {
      final client = HandshakeKeyExchange(backend, HandshakeRole.client);
      final server = HandshakeKeyExchange(backend, HandshakeRole.server);
      await client.generateEphemeralKeys();
      await server.generateEphemeralKeys();

      final clientSecret = await client.computeSharedSecret(server.publicKey!);
      final serverSecret = await server.computeSharedSecret(client.publicKey!);

      expect(clientSecret.extractSync(), equals(serverSecret.extractSync()));
    });

    test('deriveTrafficSecrets produces distinct client/server secrets',
        () async {
      final kx = HandshakeKeyExchange(backend, HandshakeRole.client);
      await kx.generateEphemeralKeys();

      final handshakeSecret = SimpleSecretKey(List<int>.filled(32, 0xAB));
      final secrets = await kx.deriveTrafficSecrets(handshakeSecret);

      expect(secrets.clientSecret.extractSync(), isNotEmpty);
      expect(secrets.serverSecret.extractSync(), isNotEmpty);
      expect(
        secrets.clientSecret.extractSync(),
        isNot(equals(secrets.serverSecret.extractSync())),
      );
    });
  });

  // -------------------------------------------------------------------------
  // 2. HTTP/3 Request/Response
  // -------------------------------------------------------------------------
  group('HTTP/3 Request/Response', () {
    test('Http3Request encode → decode round-trip for a GET request', () {
      final request = Http3Request(
        method: 'GET',
        path: '/index.html',
        headers: {
          'host': 'example.com',
          'accept': 'text/html',
        },
      );

      final encoded = request.encodeHeaders();
      final decoded = Http3Request.decodeHeaders(encoded);

      expect(decoded.method, equals('GET'));
      expect(decoded.path, equals('/index.html'));
      expect(decoded.headers['host'], equals('example.com'));
      expect(decoded.headers['accept'], equals('text/html'));
    });

    test('Http3Response encode → decode round-trip for a 200 OK', () {
      final response = Http3Response(
        statusCode: 200,
        headers: {'content-type': 'text/plain'},
      );

      final encoded = response.encodeHeaders();
      final decoded = Http3Response.decodeHeaders(encoded);

      expect(decoded.statusCode, equals(200));
      expect(decoded.headers['content-type'], equals('text/plain'));
    });

    test(
        'Http3Connection.getResponse returns response after receiving HEADERS frame',
        () {
      final conn = Http3Connection(quicConnection: Object());
      final response = Http3Response(
        statusCode: 200,
        headers: {'content-type': 'application/json'},
      );
      final headersFrame =
          Http3HeadersFrame(encodedFieldSection: response.encodeHeaders());
      final frame = headersFrame.toFrame();

      conn.onStreamFrame(4, frame);

      final result = conn.getResponse(4);
      expect(result, isNotNull);
      expect(result!.statusCode, equals(200));
      expect(result.headers['content-type'], equals('application/json'));
    });
  });

  // -------------------------------------------------------------------------
  // 3. WebTransport Datagrams
  // -------------------------------------------------------------------------
  group('WebTransport Datagrams', () {
    test('DatagramCapsule serialize → parse round-trip', () {
      final payload = Uint8List.fromList([0x01, 0x02, 0x03, 0x04]);
      final capsule = DatagramCapsule(payload);

      final serialized = capsule.serialize();
      final parsed = DatagramCapsule.parse(serialized);

      expect(parsed.payload, equals(payload));
    });

    test('WebTransportSession accumulates received datagrams', () {
      final session = WebTransportSession(42);
      final capsule = Capsule(
        type: CapsuleType.datagram,
        payload: Uint8List.fromList([0x0A, 0x0B, 0x0C]),
      );

      session.onCapsuleReceived(capsule);

      expect(session.receivedDatagrams.length, equals(1));
      expect(session.receivedDatagrams.first,
          equals(Uint8List.fromList([0x0A, 0x0B, 0x0C])));
    });

    test('sendDatagram produces capsule with type 0x00', () {
      final session = WebTransportSession(0);
      final data = Uint8List.fromList([0x11, 0x22, 0x33]);

      final capsule = session.sendDatagram(data);

      expect(capsule.type, equals(CapsuleType.datagram));
      expect(capsule.type.value, equals(0x00));
      expect(capsule.payload, equals(data));
    });
  });

  // -------------------------------------------------------------------------
  // 4. Connection Migration
  // -------------------------------------------------------------------------
  group('Connection Migration', () {
    late QuicConnection conn;

    setUp(() {
      conn = QuicConnection(
        stateMachine: ConnectionStateMachine(),
        cidManager: ConnectionIdManager(),
        pnSpaceManager: PacketNumberSpaceManager(),
        rttEstimator: RttEstimator(),
        lossDetector: LossDetector(),
        ptoScheduler: PtoScheduler(RttEstimator()),
        congestionController: CongestionController(),
        streamIdAllocator: StreamIdAllocator(),
      );
      conn.stateMachine
          .transitionTo(ConnectionState.handshaking, reason: 'test');
      conn.stateMachine
          .transitionTo(ConnectionState.established, reason: 'test');
      conn.onBytesReceived(100);
    });

    tearDown(() {
      conn.stateMachine.dispose();
    });

    test('QuicConnection processes PATH_CHALLENGE and generates challenge', () {
      final challenge =
          conn.migrationHelper.generateChallenge(currentTimeUs: 0);

      expect(challenge, isA<PathChallengeFrame>());
      expect(challenge.data.length, equals(8));
    });

    test('QuicConnection processes PATH_RESPONSE and validates path', () {
      final challenge =
          conn.migrationHelper.generateChallenge(currentTimeUs: 0);
      final response = PathResponseFrame(data: challenge.data);

      final validated = conn.migrationHelper.onResponseReceived(response);

      expect(validated, isTrue);
    });

    test('isPathValidated returns true after challenge/response pair', () {
      final challenge =
          conn.migrationHelper.generateChallenge(currentTimeUs: 0);
      final response = PathResponseFrame(data: challenge.data);

      conn.migrationHelper.onResponseReceived(response);

      expect(
        conn.migrationHelper.isPathValidated(challenge.data),
        isTrue,
      );
    });
  });
}
