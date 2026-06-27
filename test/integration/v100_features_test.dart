import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:dart_quic/src/connection/quic_connection.dart';
import 'package:dart_quic/src/connection/connection_state_machine.dart';
import 'package:dart_quic/src/connection/connection_id_manager.dart';
import 'package:dart_quic/src/connection/packet_receiver.dart';
import 'package:dart_quic/src/connection/version_negotiation.dart';
import 'package:dart_quic/src/crypto/crypto_backend.dart';
import 'package:dart_quic/src/crypto/default_crypto_backend.dart';
import 'package:dart_quic/src/crypto/key_manager.dart';
import 'package:dart_quic/src/crypto/tls/handshake_coordinator.dart';
import 'package:dart_quic/src/crypto/tls/handshake_key_exchange.dart';
import 'package:dart_quic/src/http3/push_promise_frame.dart';
import 'package:dart_quic/src/http3/frame_types.dart';
import 'package:dart_quic/src/libp2p/peer_id.dart';
import 'package:dart_quic/src/recovery/congestion_controller.dart';
import 'package:dart_quic/src/recovery/loss_detector.dart';
import 'package:dart_quic/src/recovery/packet_number_space.dart';
import 'package:dart_quic/src/recovery/pto_scheduler.dart';
import 'package:dart_quic/src/recovery/rtt_estimator.dart';
import 'package:dart_quic/src/streams/stream_id.dart';
import 'package:dart_quic/src/streams/stream_manager.dart';
import 'package:dart_quic/src/webtransport/capsule_types.dart';
import 'package:dart_quic/src/webtransport/stream_capsule.dart';
import 'package:dart_quic/src/webtransport/stream_types.dart';
import 'package:dart_quic/src/wire/frame.dart';
import 'package:dart_quic/src/wire/packet_builder.dart';
import 'package:dart_quic/src/wire/packet_header.dart';
import 'package:dart_quic/src/wire/quic_versions.dart';

/// Integration tests for dart_quic v1.0.0 features.
void main() {
  group('QuicVersions.isSupported', () {
    test('v1 is supported', () {
      expect(QuicVersions.isSupported(QuicVersions.v1), isTrue);
    });

    test('v2 is supported', () {
      expect(QuicVersions.isSupported(QuicVersions.v2), isTrue);
    });
  });

  group('VersionNegotiationPacket supported versions', () {
    test('includes v2 in supported versions list', () {
      expect(VersionNegotiation.supportedVersions, contains(QuicVersions.v2));
      expect(VersionNegotiation.supportedVersions, contains(QuicVersions.v1));
    });

    test('createPacket produces a VersionNegotiationPacket with v1 and v2', () {
      final packet = VersionNegotiation.createPacket(
        destinationConnectionId: [0x01, 0x02],
        sourceConnectionId: [0x03, 0x04],
      );
      expect(packet.supportedVersions, contains(QuicVersions.v1));
      expect(packet.supportedVersions, contains(QuicVersions.v2));
    });
  });

  group('PeerId Base58 round-trip', () {
    test('fromBase58 / toBase58 round-trip', () {
      final bytes = List<int>.generate(32, (i) => i + 1);
      final peerId = PeerId.fromBytes(bytes);

      final encoded = peerId.toBase58();
      expect(encoded, isNotEmpty);

      final decoded = PeerId.fromBase58(encoded);
      expect(decoded, equals(peerId));
    });
  });

  group('Http3PushPromiseFrame serialize/parse', () {
    test('serializePayload / parsePayload round-trip', () {
      final frame = Http3PushPromiseFrame(
        pushId: 42,
        encodedFieldSection: Uint8List.fromList([0x0A, 0x0B, 0x0C]),
      );
      final payload = frame.serializePayload();
      final parsed = Http3PushPromiseFrame.parsePayload(payload);

      expect(parsed.pushId, equals(42));
      expect(parsed.encodedFieldSection, equals([0x0A, 0x0B, 0x0C]));
      expect(parsed, equals(frame));
    });

    test('toFrame produces a valid Http3Frame', () {
      final pushPromise = Http3PushPromiseFrame(
        pushId: 7,
        encodedFieldSection: Uint8List.fromList([0x01, 0x02]),
      );
      final frame = pushPromise.toFrame();
      expect(frame.type, equals(Http3FrameType.pushPromise));
      expect(frame.payload, equals(pushPromise.serializePayload()));
    });
  });

  group('WebTransport StreamCapsule bidirectional registration', () {
    test('registers a capsule on a bidirectional stream', () {
      final registry = StreamCapsuleRegistry();
      final streamId = WebTransportStreamId.encode(
        type: WebTransportStreamId.typeClientBidi,
        sequence: 0,
      );
      expect(
        WebTransportStreamId.getType(streamId),
        equals(WebTransportStreamType.bidirectional),
      );

      final capsule = Capsule(
        type: CapsuleType.datagram,
        payload: [0x01, 0x02, 0x03],
      );
      registry.register(streamId, capsule);

      expect(registry.isRegistered(streamId), isTrue);
      final retrieved = registry.get(streamId);
      expect(retrieved, isNotNull);
      expect(retrieved!.streamId, equals(streamId));
      expect(retrieved.type, equals(CapsuleType.datagram));
    });
  });

  group('HandshakeCoordinator generates keys', () {
    test('generateKeys produces ephemeral keys', () async {
      final backend = DefaultCryptoBackend();
      final keyManager = KeyManager.forTest();
      final coordinator = HandshakeCoordinator(
        backend: backend,
        role: HandshakeRole.client,
        keyManager: keyManager,
      );

      expect(coordinator.hasGeneratedKeys, isFalse);
      await coordinator.generateKeys();
      expect(coordinator.hasGeneratedKeys, isTrue);
    });
  });

  group('QuicConnection.probeNewPath', () {
    test('generates a PATH_CHALLENGE packet', () async {
      final conn = QuicConnection(
        stateMachine: ConnectionStateMachine(),
        cidManager: ConnectionIdManager(),
        pnSpaceManager: PacketNumberSpaceManager(),
        rttEstimator: RttEstimator(),
        lossDetector: LossDetector(),
        ptoScheduler: PtoScheduler(RttEstimator()),
        congestionController: CongestionController(),
        streamIdAllocator: StreamIdAllocator(),
      );

      final dcid = List<int>.filled(8, 0xAB);
      final future = conn.probeNewPath(dcid);

      // The future should be pending until a PATH_RESPONSE is received.
      expect(conn.isProbingPath, isTrue);
      expect(conn.lastProbePacket, isNotNull);
      expect(future, isA<Future<void>>());
    });
  });

  group('PacketReceiver v2 scaffold', () {
    test('processes a v2 Initial packet the same way as v1', () {
      final header = LongHeader(
        version: QuicVersions.v2,
        packetType: LongHeader.typeInitial,
        destinationConnectionId: [0x01],
        sourceConnectionId: [0x02],
        packetNumber: 0,
        token: const [],
      );
      final frames = <Frame>[PingFrame(), CryptoFrame(offset: 0, data: [0x01])];
      final packet = PacketBuilder.build(header, frames);

      final result = PacketReceiver.processPacket(packet);
      expect(result, isNotNull);
      expect(result!.header, isA<LongHeader>());
      final longHeader = result.header as LongHeader;
      expect(longHeader.version, equals(QuicVersions.v2));
      expect(result.frames.length, greaterThanOrEqualTo(1));
    });
  });
}
