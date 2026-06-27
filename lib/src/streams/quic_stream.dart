import 'dart:async';
import 'dart:typed_data';

import 'package:dart_quic/src/streams/send_state_machine.dart';
import 'package:dart_quic/src/streams/receive_state_machine.dart';

abstract class QuicStream {
  int get streamId;
  bool get isBidirectional;
  bool get isUnidirectional;
  Future<void> get done;
  void write(Uint8List data);
  void close();
  void reset({int errorCode = 0});
}

class QuicSendStream implements QuicStream {
  @override final int streamId;
  final StreamController<Uint8List> _dataController;
  final SendStateMachine _stateMachine;

  QuicSendStream(this.streamId, {required SendStateMachine stateMachine})
      : _stateMachine = stateMachine,
        _dataController = StreamController<Uint8List>.broadcast();

  @override void write(Uint8List data) { _stateMachine.onDataSent(); _dataController.add(data); }
  @override void close() {
    if (_stateMachine.state == SendStreamState.ready) {
      _stateMachine.onDataSent();
    }
    _stateMachine.onFinSent();
    _dataController.close();
  }
  @override void reset({int errorCode = 0}) { _stateMachine.onResetSent(); }
  @override Future<void> get done => _dataController.done;

  Stream<Uint8List> get outgoingData => _dataController.stream;

  @override bool get isBidirectional => (streamId & 0x02) == 0;
  @override bool get isUnidirectional => (streamId & 0x02) != 0;
}

class QuicReceiveStream implements QuicStream {
  @override final int streamId;
  final StreamController<Uint8List> _dataController;
  final ReceiveStateMachine _stateMachine;

  QuicReceiveStream(this.streamId, {required ReceiveStateMachine stateMachine})
      : _stateMachine = stateMachine,
        _dataController = StreamController<Uint8List>.broadcast();

  /// Deliver received data to the stream.
  ///
  /// [bytesReceived] is the cumulative total of bytes delivered so far
  /// (including this [data]). Required when [fin] is true to validate
  /// against the declared final size.
  void deliver(Uint8List data, {bool fin = false, int? finalSize, int bytesReceived = 0}) {
    if (_dataController.isClosed) return;
    _stateMachine.onDataReceived(fin: fin, finalSize: finalSize, bytesReceived: bytesReceived);
    _dataController.add(data);
    if (fin) {
      _stateMachine.onAllDataReceived();
      _dataController.close();
    }
  }

  @override void write(Uint8List data) => throw UnsupportedError('ReceiveStream cannot write');
  @override void close() { /* no-op for receive-only */ }
  @override void reset({int errorCode = 0}) { _stateMachine.onResetReceived(); }
  @override Future<void> get done => _dataController.done;

  Stream<Uint8List> get incomingData => _dataController.stream;

  @override bool get isBidirectional => (streamId & 0x02) == 0;
  @override bool get isUnidirectional => (streamId & 0x02) != 0;
}
