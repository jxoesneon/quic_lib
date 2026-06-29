import 'dart:async';
import 'dart:typed_data';

import '../io/platform_address.dart';
import '../io/udp_socket.dart';
import 'dcutr.dart';
import 'dcutr_state_machine.dart';

/// Coordinates DCUtR hole-punching over a [UdpSocket].
///
/// Each outgoing datagram is prefixed with a 4-byte magic (`0x44435452`,
/// i.e. "DCTR") followed by the serialized [DCUtRMessage].  Incoming
/// datagrams are parsed, validated, and used to drive the supplied
/// [DCUtRStateMachine].
class DCUtRUdpCoordinator {
  static const List<int> _magic = [0x44, 0x43, 0x54, 0x52]; // "DCTR"

  final UdpSocket _socket;
  final DCUtRStateMachine _stateMachine;
  StreamSubscription<({Uint8List data, InternetAddress address, int port})>?
      _subscription;

  DCUtRUdpCoordinator(this._socket, this._stateMachine);

  /// Starts listening to the underlying [UdpSocket] for DCUtR datagrams.
  ///
  /// Valid CONNECT messages trigger `_stateMachine.onConnectReceived()` and
  /// valid SYNC messages trigger `_stateMachine.onSyncReceived()`.
  void startListening() {
    _subscription = _socket.incoming.listen((datagram) {
      final data = datagram.data;
      if (data.length < 4) return;

      if (data[0] != _magic[0] ||
          data[1] != _magic[1] ||
          data[2] != _magic[2] ||
          data[3] != _magic[3]) {
        return;
      }

      final messageBytes = data.sublist(4);
      try {
        final message = DCUtRMessage.parse(messageBytes);
        if (!DCUtRHandler().isValid(message)) return;

        switch (message.type) {
          case DCUtRMessage.typeConnect:
            _stateMachine.onConnectReceived();
            break;
          case DCUtRMessage.typeSync:
            _stateMachine.onSyncReceived();
            break;
        }
      } on FormatException {
        // Ignore malformed DCUtR messages.
      }
    });
  }

  /// Sends a DCUtR CONNECT message to [addr]:[port] and transitions the
  /// state machine with `onConnectSent()`.
  Future<bool> sendConnect(
    InternetAddress addr,
    int port,
    List<int> observedAddr,
  ) async {
    final message = DCUtRHandler().initiateConnect(observedAddr);
    final bytes = Uint8List.fromList([..._magic, ...message.serialize()]);
    _socket.send(bytes, addr, port);
    _stateMachine.onConnectSent();
    return true;
  }

  /// Sends a DCUtR SYNC message to [addr]:[port] and transitions the
  /// state machine with `onSyncReceived()`.
  Future<bool> sendSync(
    InternetAddress addr,
    int port,
    List<int> observedAddr,
  ) async {
    final message = DCUtRHandler().respondSync(observedAddr);
    final bytes = Uint8List.fromList([..._magic, ...message.serialize()]);
    _socket.send(bytes, addr, port);
    _stateMachine.onSyncReceived();
    return true;
  }

  /// Whether the DCUtR handshake has reached the connected state.
  bool get isConnected => _stateMachine.isConnected;

  /// Cancels the subscription on the UDP socket.
  void stopListening() {
    _subscription?.cancel();
    _subscription = null;
  }
}
