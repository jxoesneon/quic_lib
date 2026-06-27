import 'dart:io';
import 'dart:typed_data';

import 'package:dart_quic/src/io/udp_socket.dart';
import 'package:dart_quic/src/libp2p/dcutr.dart';
import 'package:dart_quic/src/libp2p/dcutr_state_machine.dart';
import 'package:dart_quic/src/libp2p/dcutr_udp_coordinator.dart';
import 'package:test/test.dart';

void main() {
  group('DCUtRUdpCoordinator', () {
    test('can send a CONNECT message with magic prefix', () async {
      final socketA = await UdpSocket.bind(InternetAddress.loopbackIPv4, 0);
      final socketB = await UdpSocket.bind(InternetAddress.loopbackIPv4, 0);
      addTearDown(() {
        socketA.close();
        socketB.close();
      });

      final sm = DCUtRStateMachine();
      final coordinator = DCUtRUdpCoordinator(socketA, sm);

      final received = socketB.incoming.first;
      final result = await coordinator.sendConnect(
        InternetAddress.loopbackIPv4,
        socketB.localPort,
        [192, 168, 1, 1, 0, 80],
      );
      expect(result, isTrue);

      final datagram = await received;
      expect(datagram.data.length, greaterThanOrEqualTo(4));

      // Verify magic prefix 0x44435452 ("DCTR")
      expect(datagram.data[0], equals(0x44));
      expect(datagram.data[1], equals(0x43));
      expect(datagram.data[2], equals(0x54));
      expect(datagram.data[3], equals(0x52));

      // Verify DCUtR message
      final message = DCUtRMessage.parse(datagram.data.sublist(4));
      expect(message.type, equals(DCUtRMessage.typeConnect));
      expect(message.observedAddr, equals([192, 168, 1, 1, 0, 80]));

      // Verify state machine transitioned
      expect(sm.state, equals(DCUtRState.connectSent));
    });

    test('parses incoming SYNC and transitions state machine', () async {
      final socketA = await UdpSocket.bind(InternetAddress.loopbackIPv4, 0);
      final socketB = await UdpSocket.bind(InternetAddress.loopbackIPv4, 0);
      addTearDown(() {
        socketA.close();
        socketB.close();
      });

      final sm = DCUtRStateMachine();
      final coordinator = DCUtRUdpCoordinator(socketA, sm);
      coordinator.startListening();

      // Move to connectSent first so onSyncReceived can advance the state.
      await coordinator.sendConnect(
        InternetAddress.loopbackIPv4,
        socketB.localPort,
        [10, 0, 0, 1],
      );
      expect(sm.state, equals(DCUtRState.connectSent));

      // Send SYNC from B to A with magic prefix
      final syncMessage = DCUtRMessage(
        type: DCUtRMessage.typeSync,
        observedAddr: [10, 0, 0, 2],
      );
      final syncBytes = Uint8List.fromList([
        0x44, 0x43, 0x54, 0x52, // magic
        ...syncMessage.serialize(),
      ]);
      socketB.send(syncBytes, InternetAddress.loopbackIPv4, socketA.localPort);

      // Allow time for async delivery and processing
      await Future<void>.delayed(const Duration(milliseconds: 50));
      expect(sm.state, equals(DCUtRState.syncReceived));
    });

    test('isConnected returns true after full handshake', () async {
      final socketA = await UdpSocket.bind(InternetAddress.loopbackIPv4, 0);
      final socketB = await UdpSocket.bind(InternetAddress.loopbackIPv4, 0);
      addTearDown(() {
        socketA.close();
        socketB.close();
      });

      final sm = DCUtRStateMachine();
      final coordinator = DCUtRUdpCoordinator(socketA, sm);
      coordinator.startListening();

      // Step 1: Send CONNECT -> connectSent
      await coordinator.sendConnect(
        InternetAddress.loopbackIPv4,
        socketB.localPort,
        [192, 168, 0, 1],
      );
      expect(coordinator.isConnected, isFalse);
      expect(sm.state, equals(DCUtRState.connectSent));

      // Step 2: Receive first SYNC -> syncReceived
      final syncMessage = DCUtRMessage(
        type: DCUtRMessage.typeSync,
        observedAddr: [192, 168, 0, 2],
      );
      final syncBytes = Uint8List.fromList([
        0x44, 0x43, 0x54, 0x52, // magic
        ...syncMessage.serialize(),
      ]);
      socketB.send(syncBytes, InternetAddress.loopbackIPv4, socketA.localPort);

      await Future<void>.delayed(const Duration(milliseconds: 50));
      expect(coordinator.isConnected, isFalse);
      expect(sm.state, equals(DCUtRState.syncReceived));

      // Step 3: Receive second SYNC -> connected
      socketB.send(syncBytes, InternetAddress.loopbackIPv4, socketA.localPort);

      await Future<void>.delayed(const Duration(milliseconds: 50));
      expect(coordinator.isConnected, isTrue);
      expect(sm.state, equals(DCUtRState.connected));
    });
  });
}
