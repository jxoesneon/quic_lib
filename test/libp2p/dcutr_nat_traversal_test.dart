import 'dart:io';

import 'package:quic_lib/src/io/udp_socket.dart';
import 'package:quic_lib/src/libp2p/dcutr_state_machine.dart';
import 'package:quic_lib/src/libp2p/dcutr_udp_coordinator.dart';
import 'package:test/test.dart';

void main() {
  group('DCUtR NAT hole punching with real endpoints', () {
    test('two peers complete handshake within 5 seconds', () async {
      // Bind two UDP sockets on different loopback ports to simulate NATted peers.
      final socketA = await UdpSocket.bind(InternetAddress.loopbackIPv4, 0);
      final socketB = await UdpSocket.bind(InternetAddress.loopbackIPv4, 0);
      addTearDown(() {
        socketA.close();
        socketB.close();
      });

      final smA = DCUtRStateMachine();
      final coordA = DCUtRUdpCoordinator(socketA, smA);
      coordA.startListening();

      final smB = DCUtRStateMachine();
      final coordB = DCUtRUdpCoordinator(socketB, smB);
      coordB.startListening();

      // Set up listener on B before sending so the event is not missed.
      final bReceived = socketB.incoming.first;

      // Peer A (dialer) sends DCUtR CONNECT to Peer B.
      await coordA.sendConnect(
        InternetAddress.loopbackIPv4,
        socketB.localPort,
        [192, 168, 1, 1],
      );
      expect(coordA.isConnected, isFalse);
      expect(smA.state, equals(DCUtRState.connectSent));

      // Wait for Peer B to receive CONNECT, then send two SYNCs back.
      // The current state machine requires two onSyncReceived transitions
      // for the dialer to reach the connected state.
      await bReceived.then((_) async {
        expect(coordB.isConnected, isTrue,
            reason: 'Peer B should transition to connected on CONNECT');

        await coordB.sendSync(
          InternetAddress.loopbackIPv4,
          socketA.localPort,
          [192, 168, 1, 2],
        );
        // Small spacing to avoid back-to-back processing races on loopback.
        await Future<void>.delayed(const Duration(milliseconds: 10));
        await coordB.sendSync(
          InternetAddress.loopbackIPv4,
          socketA.localPort,
          [192, 168, 1, 2],
        );
      });

      // Poll for Peer A to reach connected, with a 5-second timeout.
      final deadline = DateTime.now().add(const Duration(seconds: 5));
      while (!coordA.isConnected) {
        if (DateTime.now().isAfter(deadline)) {
          fail('Peer A did not reach connected within 5 seconds');
        }
        await Future<void>.delayed(const Duration(milliseconds: 50));
      }

      expect(coordA.isConnected, isTrue);
      expect(coordB.isConnected, isTrue);
      expect(smA.state, equals(DCUtRState.connected));
      expect(smB.state, equals(DCUtRState.connected));
    });
  });
}
