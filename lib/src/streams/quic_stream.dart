import 'dart:async';
import 'dart:typed_data';

import 'package:quic_lib/src/streams/send_state_machine.dart';
import 'package:quic_lib/src/streams/receive_state_machine.dart';

/// Base interface for a QUIC stream.
///
/// A QUIC stream is a lightweight, ordered byte stream multiplexed inside a
/// single QUIC connection. Streams can be bidirectional (both sides send and
/// receive) or unidirectional (one side sends, the other receives). QUIC
/// guarantees in-order delivery of bytes within a stream, but does not
/// guarantee ordering across different streams.
///
/// Callers interact with streams through [write] to enqueue data and [close]
/// to signal the end of the stream (FIN). The [done] future completes when
/// the stream has been fully closed or reset.
///
/// ## Example
/// ```dart
/// // Obtain a stream from a QuicConnection via the StreamManager.
/// final sendStream = streamManager.createSendStream(streamId);
/// sendStream.write(Uint8List.fromList([1, 2, 3]));
/// sendStream.close();
/// await sendStream.done;
/// ```
///
/// See also:
/// - [QuicSendStream] — sending side of a stream.
/// - [QuicReceiveStream] — receiving side of a stream.
/// - [QuicConnection.openBidirectionalStream] — allocates a new stream ID.
/// - RFC 9000 Section 2 — Streams.
abstract class QuicStream {
  /// The QUIC stream ID.
  ///
  /// Stream IDs encode both the initiator (client vs server) and the
  /// directionality (bidirectional vs unidirectional). See RFC 9000 Section 2.1.
  int get streamId;

  /// Whether this stream is bidirectional.
  ///
  /// Determined from the stream ID's second least-significant bit.
  bool get isBidirectional;

  /// Whether this stream is unidirectional.
  ///
  /// Determined from the stream ID's second least-significant bit.
  bool get isUnidirectional;

  /// A future that completes when the stream is closed or reset.
  Future<void> get done;

  /// Write [data] to the stream.
  ///
  /// The data is buffered and later framed into STREAM frames by the
  /// connection's packet builder. On a [QuicReceiveStream] this throws
  /// [UnsupportedError].
  void write(Uint8List data);

  /// Signal the end of the stream (send FIN).
  ///
  /// After closing, no more data can be written. The peer will receive a
  /// STREAM frame with the FIN bit set.
  void close();

  /// Reset the stream with an [errorCode].
  ///
  /// Sends a RESET_STREAM frame to abruptly terminate the stream. Any
  /// buffered but unsent data is discarded.
  void reset({int errorCode = 0});
}

/// QUIC send-side stream.
///
/// Buffers outgoing data and tracks the send state machine (Ready → Send →
/// Data Sent → Data Recvd → Reset Sent → Reset Recvd). Data written here
/// is emitted on [outgoingData] as [Uint8List] chunks, which the connection's
/// packet builder consumes and turns into STREAM frames.
///
/// ## Example
/// ```dart
/// final stream = QuicSendStream(0, stateMachine: sendStateMachine);
/// stream.write(Uint8List.fromList(utf8.encode('Hello, QUIC!')));
/// stream.close();
/// await stream.done;
/// ```
class QuicSendStream implements QuicStream {
  @override
  final int streamId;
  final StreamController<Uint8List> _dataController;
  final SendStateMachine _stateMachine;

  /// Creates a send stream for [streamId] backed by [stateMachine].
  QuicSendStream(this.streamId, {required SendStateMachine stateMachine})
      : _stateMachine = stateMachine,
        _dataController = StreamController<Uint8List>.broadcast();

  @override
  void write(Uint8List data) {
    _stateMachine.onDataSent();
    _dataController.add(data);
  }

  @override
  void close() {
    if (_stateMachine.state == SendStreamState.ready) {
      _stateMachine.onDataSent();
    }
    _stateMachine.onFinSent();
    _dataController.close();
  }

  @override
  void reset({int errorCode = 0}) {
    _stateMachine.onResetSent();
  }

  @override
  Future<void> get done => _dataController.done;

  /// A broadcast stream of data chunks written to this stream.
  ///
  /// Listeners receive every [Uint8List] passed to [write]. The stream
  /// closes when [close] is called.
  Stream<Uint8List> get outgoingData => _dataController.stream;

  @override
  bool get isBidirectional => (streamId & 0x02) == 0;
  @override
  bool get isUnidirectional => (streamId & 0x02) != 0;
}

/// QUIC receive-side stream.
///
/// Delivers incoming data via [incomingData] and tracks the receive state
/// machine (Recv → Size Known → Data Recvd → Data Read → Reset Recvd).
/// Data is pushed into the stream with [deliver]; when the FIN bit is seen,
/// the controller closes and [done] completes.
///
/// [write] is unsupported on this side; use [deliver] instead.
///
/// ## Example
/// ```dart
/// final stream = QuicReceiveStream(0, stateMachine: receiveStateMachine);
/// stream.incomingData.listen((data) {
///   print('Received ${data.length} bytes');
/// });
///
/// // Called by the connection's frame dispatcher when a STREAM frame arrives.
/// stream.deliver(payload, fin: true, bytesReceived: totalBytes);
/// await stream.done;
/// ```
class QuicReceiveStream implements QuicStream {
  @override
  final int streamId;
  final StreamController<Uint8List> _dataController;
  final ReceiveStateMachine _stateMachine;

  /// Creates a receive stream for [streamId] backed by [stateMachine].
  QuicReceiveStream(this.streamId, {required ReceiveStateMachine stateMachine})
      : _stateMachine = stateMachine,
        _dataController = StreamController<Uint8List>.broadcast();

  /// Deliver received [data] to the stream.
  ///
  /// [bytesReceived] is the cumulative total of bytes delivered so far
  /// (including this [data]). Required when [fin] is true to validate
  /// against the declared final size.
  ///
  /// If the controller is already closed the call is silently ignored.
  void deliver(Uint8List data,
      {bool fin = false, int? finalSize, int bytesReceived = 0}) {
    if (_dataController.isClosed) return;
    _stateMachine.onDataReceived(
        fin: fin, finalSize: finalSize, bytesReceived: bytesReceived);
    _dataController.add(data);
    if (fin) {
      _stateMachine.onAllDataReceived();
      _dataController.close();
    }
  }

  @override
  void write(Uint8List data) =>
      throw UnsupportedError('ReceiveStream cannot write');
  @override
  void close() {/* no-op for receive-only */}
  @override
  void reset({int errorCode = 0}) {
    _stateMachine.onResetReceived();
  }

  @override
  Future<void> get done => _dataController.done;

  /// A broadcast stream of data chunks delivered to this stream.
  ///
  /// Listeners receive every [Uint8List] passed to [deliver]. The stream
  /// closes when a chunk with [fin] == true is delivered.
  Stream<Uint8List> get incomingData => _dataController.stream;

  @override
  bool get isBidirectional => (streamId & 0x02) == 0;
  @override
  bool get isUnidirectional => (streamId & 0x02) != 0;
}
