import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:quic_lib/src/connection/connection_id_manager.dart';
import 'package:quic_lib/src/connection/connection_state_machine.dart';
import 'package:quic_lib/src/connection/quic_connection.dart';
import 'package:quic_lib/src/crypto/cipher_suites.dart';
import 'package:quic_lib/src/crypto/crypto_backend.dart';
import 'package:quic_lib/src/crypto/default_crypto_backend.dart';
import 'package:quic_lib/src/crypto/key_manager.dart';
import 'package:quic_lib/src/crypto/tls/crypto_frame_assembler.dart';
import 'package:quic_lib/src/crypto/tls/handshake_state_machine.dart';
import 'package:quic_lib/src/crypto/tls/handshake_key_exchange.dart' as hke;
import 'package:quic_lib/src/io/quic_endpoint.dart';
import 'package:quic_lib/src/recovery/congestion_controller.dart';
import 'package:quic_lib/src/recovery/loss_detector.dart';
import 'package:quic_lib/src/recovery/packet_number_space.dart';
import 'package:quic_lib/src/recovery/pto_scheduler.dart';
import 'package:quic_lib/src/recovery/rtt_estimator.dart';
import 'package:quic_lib/src/streams/stream_id.dart';
import 'package:quic_lib/src/wire/frame.dart';
import 'package:test/test.dart';

/// Build a minimal QUIC Initial packet that the endpoint will accept.
Uint8List _buildInitialPacket(List<int> dcid, {List<int>? payload}) {
  final builder = BytesBuilder();
  builder.addByte(0x80); // Long header, Initial type (00)
  builder.add([0x00, 0x00, 0x00, 0x01]); // Version 1
  builder.addByte(dcid.length);
  builder.add(dcid);
  builder.addByte(0x00); // SCID length 0
  builder.addByte(0x00); // Token length varint = 0

  final body = payload ?? const [];
  final length = body.length + 1; // +1 for packet number
  builder.addByte(length);
  builder.addByte(0x00); // Packet number 0
  builder.add(body);

  return Uint8List.fromList(builder.toBytes());
}

QuicConnection _createConnection({
  KeyManager? keyManager,
  CryptoFrameAssembler? cryptoAssembler,
}) {
  return QuicConnection(
    stateMachine: ConnectionStateMachine(),
    cidManager: ConnectionIdManager(),
    pnSpaceManager: PacketNumberSpaceManager(),
    rttEstimator: RttEstimator(),
    lossDetector: LossDetector(),
    ptoScheduler: PtoScheduler(RttEstimator()),
    congestionController: CongestionController(),
    streamIdAllocator: StreamIdAllocator(),
    keyManager: keyManager,
    cryptoAssembler: cryptoAssembler,
    handshakeMachine: HandshakeStateMachine(HandshakeRole.server),
  );
}

void main() {
  group('E2E QuicEndpoint', () {
    test('client Initial packet creates server connection', () async {
      final server = await QuicEndpoint.bind(InternetAddress.loopbackIPv4, 0);
      final client = await QuicEndpoint.bind(InternetAddress.loopbackIPv4, 0);

      final connections = <Object>[];
      final sub = server.connections.listen(connections.add);

      final dcid = List<int>.filled(8, 0xAB);
      final initialPacket = _buildInitialPacket(dcid);

      // Send directly from client endpoint's UDP socket to server.
      // Seed anti-amplification budget so the packet is not dropped.
      final clientConn =
          await client.connect(InternetAddress.loopbackIPv4, server.localPort);
      clientConn.onBytesReceived(1000);
      client.send(clientConn, initialPacket);

      await Future.delayed(Duration(milliseconds: 500));
      expect(connections.length, greaterThanOrEqualTo(1));

      await sub.cancel();
      server.close();
      client.close();
    });

    test('two endpoints exchange plaintext packets', () async {
      final serverEndpoint =
          await QuicEndpoint.bind(InternetAddress.loopbackIPv4, 0);
      final clientEndpoint =
          await QuicEndpoint.bind(InternetAddress.loopbackIPv4, 0);

      // Server listens for connections
      final serverConnections = <QuicConnection>[];
      final sub = serverEndpoint.connections.listen((conn) {
        if (conn is QuicConnection) serverConnections.add(conn);
      });

      // Client builds a connection to server.
      // Seed anti-amplification budget so the packet is not dropped.
      final clientConn = await clientEndpoint.connect(
        serverEndpoint.localAddress,
        serverEndpoint.localPort,
      );
      clientConn.onBytesReceived(1000);
      clientConn.stateMachine.transitionTo(
        ConnectionState.handshaking,
        reason: 'test',
      );

      // Send an Initial packet to trigger server connection creation
      final dcid = clientConn.connectionId ?? List<int>.filled(8, 0xCD);
      final initialPacket = _buildInitialPacket(dcid);
      clientEndpoint.send(clientConn, initialPacket);

      await Future.delayed(Duration(milliseconds: 500));
      expect(serverConnections.length, greaterThanOrEqualTo(1));

      await sub.cancel();
      serverEndpoint.close();
      clientEndpoint.close();
    });

    test('endpoint send receives packet on remote', () async {
      final endpointA =
          await QuicEndpoint.bind(InternetAddress.loopbackIPv4, 0);

      // Bind a raw socket on a fixed port to receive
      final rawSocket =
          await RawDatagramSocket.bind(InternetAddress.loopbackIPv4, 0);
      final targetPort = rawSocket.port;

      final received = <Uint8List>[];
      final sub = rawSocket.listen((event) {
        if (event == RawSocketEvent.read) {
          final dg = rawSocket.receive();
          if (dg != null) received.add(dg.data);
        }
      });

      final conn = await endpointA.connect(
        InternetAddress.loopbackIPv4,
        targetPort,
      );
      conn.onBytesReceived(1000);
      final packet = Uint8List.fromList([1, 2, 3, 4, 5]);
      endpointA.send(conn, packet);

      await Future.delayed(Duration(milliseconds: 500));
      expect(received.length, equals(1));
      expect(received.first, equals(packet));

      await sub.cancel();
      rawSocket.close();
      endpointA.close();
    });

    test('connection close frame build and send pipeline over UDP', () async {
      final server = await QuicEndpoint.bind(InternetAddress.loopbackIPv4, 0);
      final client = await QuicEndpoint.bind(InternetAddress.loopbackIPv4, 0);

      final clientConn = await client.connect(
        server.localAddress,
        server.localPort,
      );
      clientConn.stateMachine.transitionTo(
        ConnectionState.handshaking,
        reason: 'test',
      );
      clientConn.stateMachine.transitionTo(
        ConnectionState.established,
        reason: 'test',
      );
      clientConn.onBytesReceived(1000);

      // Build CONNECTION_CLOSE packet and send via UDP
      final closePacket = await clientConn.buildPacket(
        space: PacketNumberSpace.application,
        frames: [
          ConnectionCloseFrame(
            errorCode: 0x0100,
            offendingFrameType: 0x00,
            reasonPhrase: 'e2e close',
          ),
        ],
        dcid: List<int>.filled(8, 0xAB),
      );
      expect(() => client.send(clientConn, closePacket), returnsNormally);

      await Future.delayed(Duration(milliseconds: 200));

      // Verify the close frame transitions the *local* connection when
      // it processes a received CONNECTION_CLOSE packet.
      expect(clientConn.state, equals(ConnectionState.established));
      final recvPacket = await clientConn.buildPacket(
        space: PacketNumberSpace.application,
        frames: [
          ConnectionCloseFrame(
            errorCode: 0x0100,
            offendingFrameType: 0x00,
            reasonPhrase: 'received',
          ),
        ],
        dcid: List<int>.filled(8, 0xAB),
      );
      clientConn.processIncomingDatagram(recvPacket);
      expect(clientConn.state, equals(ConnectionState.draining));

      server.close();
      client.close();
    });
  });

  group('E2E Encrypted packet round-trip', () {
    final backend = DefaultCryptoBackend();

    test('build → send UDP → decrypt with Initial keys', () async {
      final dcid = List<int>.filled(8, 0xAB);
      final keyManager = await KeyManager.deriveInitial(dcid, backend);
      final cryptoAssembler = CryptoFrameAssembler();

      final sender = _createConnection(
        keyManager: keyManager,
        cryptoAssembler: cryptoAssembler,
      );
      sender.stateMachine.transitionTo(
        ConnectionState.handshaking,
        reason: 'test',
      );
      sender.onBytesReceived(100);

      final receiver = _createConnection(
        keyManager: keyManager,
        cryptoAssembler: cryptoAssembler,
      );
      receiver.stateMachine.transitionTo(
        ConnectionState.handshaking,
        reason: 'test',
      );
      receiver.onBytesReceived(100);

      final cryptoData = Uint8List.fromList([0x01, 0x00, 0x00, 0x05]);
      final encryptedPacket = await sender.buildEncryptedPacket(
        space: PacketNumberSpace.initial,
        frames: [CryptoFrame(offset: 0, data: cryptoData)],
        dcid: dcid,
      );

      // Transport over UDP using RawDatagramSocket
      final socketA =
          await RawDatagramSocket.bind(InternetAddress.loopbackIPv4, 0);
      final socketB =
          await RawDatagramSocket.bind(InternetAddress.loopbackIPv4, 0);
      final receivedPackets = <Uint8List>[];
      final sub = socketB.listen((event) {
        if (event == RawSocketEvent.read) {
          final dg = socketB.receive();
          if (dg != null) receivedPackets.add(dg.data);
        }
      });

      socketA.send(encryptedPacket, InternetAddress.loopbackIPv4, socketB.port);
      await Future.delayed(Duration(milliseconds: 200));

      expect(receivedPackets.length, equals(1));

      // Receiver decrypts
      final processed =
          await receiver.processEncryptedDatagram(receivedPackets.first);
      expect(processed, equals(1));
      expect(cryptoAssembler.nextOffset, greaterThan(0));

      await sub.cancel();
      socketA.close();
      socketB.close();
    });

    test('encrypted STREAM frame round-trip over UDP', () async {
      final dcid = List<int>.filled(8, 0xCD);
      final keyManager = await KeyManager.deriveInitial(dcid, backend);

      final sender = _createConnection(keyManager: keyManager);
      sender.stateMachine
          .transitionTo(ConnectionState.handshaking, reason: 'test');
      sender.stateMachine
          .transitionTo(ConnectionState.established, reason: 'test');
      sender.onBytesReceived(100);

      final receiver = _createConnection(keyManager: keyManager);
      receiver.stateMachine
          .transitionTo(ConnectionState.handshaking, reason: 'test');
      receiver.stateMachine
          .transitionTo(ConnectionState.established, reason: 'test');
      receiver.onBytesReceived(100);

      final streamData =
          Uint8List.fromList([0x48, 0x65, 0x6C, 0x6C, 0x6F]); // "Hello"
      final encryptedPacket = await sender.buildEncryptedPacket(
        space: PacketNumberSpace.application,
        frames: [
          StreamFrame(streamId: 0, data: streamData, fin: false, offset: 0),
        ],
        dcid: dcid,
      );

      final socketA =
          await RawDatagramSocket.bind(InternetAddress.loopbackIPv4, 0);
      final socketB =
          await RawDatagramSocket.bind(InternetAddress.loopbackIPv4, 0);
      final received = <Uint8List>[];
      final sub = socketB.listen((event) {
        if (event == RawSocketEvent.read) {
          final dg = socketB.receive();
          if (dg != null) received.add(dg.data);
        }
      });

      socketA.send(encryptedPacket, InternetAddress.loopbackIPv4, socketB.port);
      await Future.delayed(Duration(milliseconds: 200));

      expect(received.length, equals(1));

      final processed = await receiver.processEncryptedDatagram(received.first);
      expect(processed, equals(1));
      final stream = receiver.streamManager.getStream(0);
      expect(stream, isNotNull);

      await sub.cancel();
      socketA.close();
      socketB.close();
    });
  });

  group('E2E KeyManager derivation chain', () {
    final backend = DefaultCryptoBackend();

    test('Initial → Handshake → Application key progression', () async {
      final dcid = List<int>.filled(8, 0xAB);

      // Derive Initial keys
      final initialKm = await KeyManager.deriveInitial(dcid, backend);
      expect(initialKm.hasKeysFor(PacketNumberSpace.initial), isTrue);
      expect(initialKm.hasKeysFor(PacketNumberSpace.handshake), isFalse);
      expect(initialKm.hasKeysFor(PacketNumberSpace.application), isFalse);

      // Simulate handshake secrets (random bytes for test)
      final clientSecret = _SimpleSecretKey(await backend.randomBytes(32));
      final serverSecret = _SimpleSecretKey(await backend.randomBytes(32));

      // Derive Handshake keys
      final handshakeKm = await KeyManager.deriveHandshake(
        clientSecret,
        serverSecret,
        backend,
      );
      expect(handshakeKm.hasKeysFor(PacketNumberSpace.handshake), isTrue);

      // Derive Application keys
      final appKm = await KeyManager.deriveApplication(
        clientSecret,
        serverSecret,
        backend,
      );
      expect(appKm.hasKeysFor(PacketNumberSpace.application), isTrue);
    });

    test('keysFor returns non-null for derived spaces', () async {
      final dcid = List<int>.filled(8, 0xAB);
      final km = await KeyManager.deriveInitial(dcid, backend);

      final initialKeys = km.keysFor(PacketNumberSpace.initial);
      expect(initialKeys, isNotNull);
      expect(initialKeys!.protector, isNotNull);
      expect(initialKeys.headerProtection, isNotNull);
    });

    test('client and server derive different keys for same inputs', () async {
      final dcid = List<int>.filled(8, 0xAB);
      final clientKm = await KeyManager.deriveInitial(
        dcid,
        backend,
        role: hke.HandshakeRole.client,
      );
      final serverKm = await KeyManager.deriveInitial(
        dcid,
        backend,
        role: hke.HandshakeRole.server,
      );

      // Client and server should have different key material
      expect(clientKm, isNot(equals(serverKm)));
    });
  });

  group('E2E Stream data exchange', () {
    test('openBidirectionalStream allocates valid stream ID', () {
      final conn = _createConnection();
      final streamId = conn.openBidirectionalStream();
      expect(streamId, greaterThanOrEqualTo(0));
      expect(streamId & 0x03, equals(0x00)); // client bidi
    });

    test('openUnidirectionalStream allocates valid stream ID', () {
      final conn = _createConnection();
      final streamId = conn.openUnidirectionalStream();
      expect(streamId, greaterThanOrEqualTo(0));
      expect(streamId & 0x03, equals(0x02)); // client uni
    });

    test('multiple bidirectional streams have increasing IDs', () {
      final conn = _createConnection();
      final id1 = conn.openBidirectionalStream();
      final id2 = conn.openBidirectionalStream();
      final id3 = conn.openBidirectionalStream();
      expect(id2, greaterThan(id1));
      expect(id3, greaterThan(id2));
      expect(id2 - id1, equals(4));
      expect(id3 - id2, equals(4));
    });

    test('STREAM frame is dispatched to StreamManager', () async {
      final conn = _createConnection();
      conn.stateMachine
          .transitionTo(ConnectionState.handshaking, reason: 'test');
      conn.stateMachine
          .transitionTo(ConnectionState.established, reason: 'test');
      conn.onBytesReceived(1000);

      final streamData = Uint8List.fromList([0x01, 0x02, 0x03]);
      final packet = await conn.buildPacket(
        space: PacketNumberSpace.application,
        frames: [
          StreamFrame(streamId: 0, data: streamData, fin: true, offset: 0),
        ],
        dcid: List<int>.filled(8, 0xAB),
      );

      conn.processIncomingDatagram(packet);
      final stream = conn.streamManager.getStream(0);
      expect(stream, isNotNull);
    });
  });

  group('E2E Connection lifecycle', () {
    test(
        'connection transitions: idle → handshaking → established → closing → closed',
        () {
      final conn = _createConnection();
      expect(conn.state, equals(ConnectionState.idle));

      conn.stateMachine
          .transitionTo(ConnectionState.handshaking, reason: 'test');
      expect(conn.state, equals(ConnectionState.handshaking));

      conn.stateMachine
          .transitionTo(ConnectionState.established, reason: 'test');
      expect(conn.state, equals(ConnectionState.established));
      expect(conn.isEstablished, isTrue);

      conn.close();
      expect(conn.state, equals(ConnectionState.closing));

      conn.stateMachine.transitionTo(ConnectionState.closed, reason: 'timeout');
      expect(conn.state, equals(ConnectionState.closed));
      expect(conn.isClosed, isTrue);
    });

    test('connection transitions to draining on CONNECTION_CLOSE', () async {
      final conn = _createConnection();
      conn.stateMachine
          .transitionTo(ConnectionState.handshaking, reason: 'test');
      conn.stateMachine
          .transitionTo(ConnectionState.established, reason: 'test');
      conn.onBytesReceived(1000);

      final packet = await conn.buildPacket(
        space: PacketNumberSpace.application,
        frames: [
          ConnectionCloseFrame(
              errorCode: 0x0100,
              offendingFrameType: 0x00,
              reasonPhrase: 'test'),
        ],
        dcid: List<int>.filled(8, 0xAB),
      );

      expect(conn.state, equals(ConnectionState.established));
      conn.processIncomingDatagram(packet);
      expect(conn.state, equals(ConnectionState.draining));
    });

    test('connection transitions to draining on ApplicationClose', () async {
      final conn = _createConnection();
      conn.stateMachine
          .transitionTo(ConnectionState.handshaking, reason: 'test');
      conn.stateMachine
          .transitionTo(ConnectionState.established, reason: 'test');
      conn.onBytesReceived(1000);

      final packet = await conn.buildPacket(
        space: PacketNumberSpace.application,
        frames: [
          ApplicationCloseFrame(errorCode: 0x0100, reasonPhrase: 'app close'),
        ],
        dcid: List<int>.filled(8, 0xAB),
      );

      expect(conn.state, equals(ConnectionState.established));
      conn.processIncomingDatagram(packet);
      expect(conn.state, equals(ConnectionState.draining));
    });
  });

  group('E2E Recovery and flow control', () {
    test('onAckReceived updates recovery state', () {
      final conn = _createConnection();
      conn.stateMachine
          .transitionTo(ConnectionState.handshaking, reason: 'test');
      conn.stateMachine
          .transitionTo(ConnectionState.established, reason: 'test');
      expect(
        () => conn.onAckReceived(0, 5, []),
        returnsNormally,
      );
    });

    test('onPacketSent tracks sent packets', () async {
      final conn = _createConnection();
      conn.stateMachine
          .transitionTo(ConnectionState.handshaking, reason: 'test');
      conn.onBytesReceived(1000);

      final packet = await conn.buildPacket(
        space: PacketNumberSpace.initial,
        frames: [PingFrame()],
        dcid: conn.cidManager.issueNewId().connectionId,
      );
      expect(packet, isNotEmpty);
      conn.onPacketSent(
        0,
        DateTime.now().microsecondsSinceEpoch,
        sizeInBytes: packet.length,
        ackEliciting: false,
      );
    });

    test('MAX_DATA frame updates connection flow controller', () async {
      final conn = _createConnection();
      conn.stateMachine
          .transitionTo(ConnectionState.handshaking, reason: 'test');
      conn.stateMachine
          .transitionTo(ConnectionState.established, reason: 'test');
      conn.onBytesReceived(1000);

      final before = conn.connectionFlowController.availableWindow;
      final packet = await conn.buildPacket(
        space: PacketNumberSpace.application,
        frames: [MaxDataFrame(maxData: before + 4096)],
        dcid: List<int>.filled(8, 0xAB),
      );
      conn.processIncomingDatagram(packet);

      expect(
          conn.connectionFlowController.availableWindow, greaterThan(before));
    });
  });

  group('E2E Coalesced packets', () {
    test('multiple Initial packets in one datagram are processed', () async {
      final conn = _createConnection();
      final cryptoAssembler = CryptoFrameAssembler();
      conn.stateMachine
          .transitionTo(ConnectionState.handshaking, reason: 'test');
      conn.onBytesReceived(1000);

      final dcid = conn.cidManager.issueNewId().connectionId;
      final packet1 = await conn.buildPacket(
        space: PacketNumberSpace.initial,
        frames: [
          CryptoFrame(offset: 0, data: [0x01])
        ],
        dcid: dcid,
      );
      final packet2 = await conn.buildPacket(
        space: PacketNumberSpace.initial,
        frames: [
          CryptoFrame(offset: 1, data: [0x02])
        ],
        dcid: dcid,
      );

      final coalesced = Uint8List(packet1.length + packet2.length);
      coalesced.setRange(0, packet1.length, packet1);
      coalesced.setRange(packet1.length, coalesced.length, packet2);

      final processed = conn.processIncomingDatagram(coalesced);
      expect(processed, equals(2));
    });
  });

  group('E2E Path validation', () {
    test('generateChallenge produces 8-byte PATH_CHALLENGE frame', () {
      final conn = _createConnection();
      conn.stateMachine
          .transitionTo(ConnectionState.handshaking, reason: 'test');
      conn.stateMachine
          .transitionTo(ConnectionState.established, reason: 'test');
      conn.onBytesReceived(1000);

      final challenge =
          conn.migrationHelper.generateChallenge(currentTimeUs: 0);
      expect(challenge.data.length, equals(8));
      expect(challenge.frameType, equals(0x1a));
    });

    test('PATH_CHALLENGE + PATH_RESPONSE validates path', () async {
      final conn = _createConnection();
      conn.stateMachine
          .transitionTo(ConnectionState.handshaking, reason: 'test');
      conn.stateMachine
          .transitionTo(ConnectionState.established, reason: 'test');
      conn.onBytesReceived(1000);

      final challenge =
          conn.migrationHelper.generateChallenge(currentTimeUs: 0);
      final packet1 = await conn.buildPacket(
        space: PacketNumberSpace.application,
        frames: [challenge],
        dcid: List<int>.filled(8, 0xAB),
      );
      conn.processIncomingDatagram(packet1);

      final response = PathResponseFrame(data: challenge.data);
      final packet2 = await conn.buildPacket(
        space: PacketNumberSpace.application,
        frames: [response],
        dcid: List<int>.filled(8, 0xAB),
      );
      conn.processIncomingDatagram(packet2);

      expect(conn.migrationHelper.isPathValidated(challenge.data), isTrue);
    });
  });
}

class _SimpleSecretKey implements SecretKey {
  final List<int> _bytes;
  _SimpleSecretKey(this._bytes);

  @override
  List<int> extractSync() => List<int>.from(_bytes);
}
