import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:quic_lib/src/wire/varint.dart';
import 'package:quic_lib/src/webtransport/capsule_types.dart';
import 'package:quic_lib/src/webtransport/webtransport_flow_controller.dart';
import 'package:quic_lib/src/webtransport/webtransport_session.dart';

void main() {
  group('WebTransportFlowController', () {
    test('initial credit matches configured budgets', () {
      final fc = WebTransportFlowController(
        sessionId: 1,
        initialSessionSendCredit: 1024,
        initialSessionReceiveCredit: 2048,
      );
      expect(fc.availableSessionSendCredit, equals(1024));
      expect(fc.availableSessionReceiveCredit, equals(2048));
      expect(fc.isSessionSendBlocked, isFalse);
    });

    test('trySend consumes session credit', () {
      final fc = WebTransportFlowController(
        sessionId: 1,
        initialSessionSendCredit: 1024,
      );
      expect(fc.trySend(512), isTrue);
      expect(fc.availableSessionSendCredit, equals(512));
      expect(fc.trySend(512), isTrue);
      expect(fc.availableSessionSendCredit, equals(0));
    });

    test('trySend returns false when credit exhausted', () {
      final fc = WebTransportFlowController(
        sessionId: 1,
        initialSessionSendCredit: 100,
      );
      expect(fc.trySend(100), isTrue);
      expect(fc.isSessionSendBlocked, isTrue);
      expect(fc.trySend(1), isFalse);
      // Credit must not be consumed on a failed send.
      expect(fc.availableSessionSendCredit, equals(0));
    });

    test('send throws StateError when credit exhausted', () {
      final fc = WebTransportFlowController(
        sessionId: 1,
        initialSessionSendCredit: 50,
      );
      fc.send(50);
      expect(() => fc.send(1), throwsStateError);
    });

    test('trySend rejects negative byte counts', () {
      final fc = WebTransportFlowController(sessionId: 1);
      expect(() => fc.trySend(-1), throwsArgumentError);
    });

    test('trySend with streamId consumes both budgets', () {
      final fc = WebTransportFlowController(
        sessionId: 1,
        initialSessionSendCredit: 1024,
      );
      // Establish an explicit per-stream limit of 200 bytes.
      fc.processCapsule(WebTransportCapsule(
        type: CapsuleType.webtransportMaxStreamData,
        payload: _encodeStreamLimit(streamId: 8, limit: 200),
      ));
      expect(fc.trySend(100, streamId: 8), isTrue);
      expect(fc.availableSessionSendCredit, equals(924));
      expect(fc.availableStreamSendCredit(8), equals(100));
    });

    test('per-stream budget blocks independently of session budget', () {
      final fc = WebTransportFlowController(
        sessionId: 1,
        initialSessionSendCredit: 4096,
      );
      // Establish a tight per-stream limit via an incoming capsule.
      fc.processCapsule(WebTransportCapsule(
        type: CapsuleType.webtransportMaxStreamData,
        payload: _encodeStreamLimit(streamId: 4, limit: 10),
      ));
      expect(fc.availableStreamSendCredit(4), equals(10));
      // Session budget is large, but stream budget blocks the send.
      expect(fc.trySend(20, streamId: 4), isFalse);
      expect(fc.availableSessionSendCredit, equals(4096));
    });

    test('incoming WEBTRANSPORT_MAX_DATA raises session send credit', () {
      final fc = WebTransportFlowController(
        sessionId: 1,
        initialSessionSendCredit: 100,
      );
      fc.processCapsule(WebTransportCapsule(
        type: CapsuleType.webtransportMaxData,
        payload: VarInt.encode(4096),
      ));
      expect(fc.availableSessionSendCredit, equals(4096));
    });

    test('incoming WEBTRANSPORT_MAX_STREAM_DATA raises stream send credit', () {
      final fc = WebTransportFlowController(sessionId: 1);
      fc.processCapsule(WebTransportCapsule(
        type: CapsuleType.webtransportMaxStreamData,
        payload: _encodeStreamLimit(streamId: 7, limit: 500),
      ));
      expect(fc.availableStreamSendCredit(7), equals(500));
    });

    test('processCapsule returns false for non-flow-control capsules', () {
      final fc = WebTransportFlowController(sessionId: 1);
      expect(
        fc.processCapsule(WebTransportCapsule(
          type: CapsuleType.goaway,
          payload: [],
        )),
        isFalse,
      );
    });

    test('incoming DRAIN_CAPABILITIES reduces session send credit', () {
      final fc = WebTransportFlowController(
        sessionId: 1,
        initialSessionSendCredit: 1000,
      );
      fc.processCapsule(WebTransportCapsule(
        type: CapsuleType.drainCapabilities,
        payload: VarInt.encode(100),
      ));
      expect(fc.availableSessionSendCredit, equals(100));
    });

    test('DRAIN_CAPABILITIES never raises credit', () {
      final fc = WebTransportFlowController(
        sessionId: 1,
        initialSessionSendCredit: 50,
      );
      fc.processCapsule(WebTransportCapsule(
        type: CapsuleType.drainCapabilities,
        payload: VarInt.encode(500),
      ));
      // Drain must not grant more credit than the peer currently has.
      expect(fc.availableSessionSendCredit, equals(50));
    });

    test('buildDrainCapabilitiesCapsule encodes the new credit', () {
      final fc = WebTransportFlowController(sessionId: 1);
      final capsule = fc.buildDrainCapabilitiesCapsule(128);
      expect(capsule.type, equals(CapsuleType.drainCapabilities));
      expect(VarInt.decode(_asBuffer(capsule.payload)), equals(128));
    });

    test('buildMaxDataCapsule encodes the advertised limit', () {
      final fc = WebTransportFlowController(sessionId: 1);
      final capsule = fc.buildMaxDataCapsule(2048);
      expect(capsule.type, equals(CapsuleType.webtransportMaxData));
      expect(VarInt.decode(_asBuffer(capsule.payload)), equals(2048));
    });

    test('buildMaxStreamDataCapsule encodes streamId and limit', () {
      final fc = WebTransportFlowController(sessionId: 1);
      final capsule = fc.buildMaxStreamDataCapsule(12, 300);
      expect(capsule.type, equals(CapsuleType.webtransportMaxStreamData));
      final bytes = _asUint8List(capsule.payload);
      final streamId = VarInt.decode(bytes.buffer, offset: bytes.offsetInBytes);
      final limit = VarInt.decode(
        bytes.buffer,
        offset: bytes.offsetInBytes + VarInt.decodeLength(bytes[0]),
      );
      expect(streamId, equals(12));
      expect(limit, equals(300));
    });

    test('onDataReceived consumes receive credit and emits window update', () {
      final fc = WebTransportFlowController(
        sessionId: 1,
        initialSessionReceiveCredit: 100,
      );
      // Consume less than half: no update yet.
      expect(fc.onDataReceived(40), isNull);
      // Cross the half threshold: a window-update capsule is returned.
      final update = fc.onDataReceived(20);
      expect(update, isNotNull);
      expect(update!.type, equals(CapsuleType.webtransportMaxData));
    });

    test('onDataReceived throws when peer exceeds receive limit', () {
      final fc = WebTransportFlowController(
        sessionId: 1,
        initialSessionReceiveCredit: 50,
      );
      expect(() => fc.onDataReceived(51), throwsStateError);
    });

    test('reset restores budgets', () {
      final fc = WebTransportFlowController(
        sessionId: 1,
        initialSessionSendCredit: 100,
      );
      fc.send(100);
      expect(fc.isSessionSendBlocked, isTrue);
      fc.reset(sessionSendCredit: 200);
      expect(fc.availableSessionSendCredit, equals(200));
    });

    test('credit is clamped to maxCredit', () {
      final fc = WebTransportFlowController(
        sessionId: 1,
        initialSessionSendCredit: WebTransportFlowController.maxCredit + 100,
      );
      expect(
        fc.availableSessionSendCredit,
        equals(WebTransportFlowController.maxCredit),
      );
    });
  });

  group('WebTransportSession flow-control integration', () {
    test('sendDatagram enforces session send credit', () {
      final session = WebTransportSession(
        1,
        initialSessionSendCredit: 10,
      );
      // 10 bytes fit within the budget.
      session.sendDatagram(Uint8List(10));
      // The 11th byte exceeds the budget.
      expect(
        () => session.sendDatagram(Uint8List(1)),
        throwsStateError,
      );
    });

    test('sendStreamData enforces per-stream credit', () {
      final session = WebTransportSession(
        1,
        initialSessionSendCredit: 4096,
      );
      session.flowController.processCapsule(WebTransportCapsule(
        type: CapsuleType.webtransportMaxStreamData,
        payload: _encodeStreamLimit(streamId: 3, limit: 5),
      ));
      session.sendStreamData(3, Uint8List(5));
      expect(
        () => session.sendStreamData(3, Uint8List(1)),
        throwsStateError,
      );
    });

    test('incoming DRAIN_CAPABILITIES reduces send credit via session', () {
      final session = WebTransportSession(
        1,
        initialSessionSendCredit: 1000,
      );
      session.onCapsuleReceived(WebTransportCapsule(
        type: CapsuleType.drainCapabilities,
        payload: VarInt.encode(50),
      ));
      expect(session.flowController.availableSessionSendCredit, equals(50));
      expect(
        () => session.sendDatagram(Uint8List(51)),
        throwsStateError,
      );
    });

    test('incoming WEBTRANSPORT_MAX_DATA raises send credit via session', () {
      final session = WebTransportSession(
        1,
        initialSessionSendCredit: 5,
      );
      session.onCapsuleReceived(WebTransportCapsule(
        type: CapsuleType.webtransportMaxData,
        payload: VarInt.encode(500),
      ));
      // Now a larger datagram fits.
      session.sendDatagram(Uint8List(100));
      expect(session.flowController.availableSessionSendCredit, equals(400));
    });

    test('drainCapabilities builds a DRAIN_CAPABILITIES capsule', () {
      final session = WebTransportSession(1);
      final capsule = session.drainCapabilities(64);
      expect(capsule.type, equals(CapsuleType.drainCapabilities));
      expect(VarInt.decode(_asBuffer(capsule.payload)), equals(64));
    });

    test('incoming datagram accounts against receive credit', () {
      final session = WebTransportSession(
        1,
        initialSessionReceiveCredit: 100,
      );
      session.onCapsuleReceived(WebTransportCapsule(
        type: CapsuleType.datagram,
        payload: List.filled(30, 0),
      ));
      expect(session.receivedDatagrams.length, equals(1));
      expect(
        session.flowController.availableSessionReceiveCredit,
        equals(70),
      );
    });

    test('non-flow-control capsules still route normally', () {
      final session = WebTransportSession(1);
      session.onCapsuleReceived(WebTransportCapsule(
        type: CapsuleType.closeWebTransportSession,
        payload: [],
      ));
      expect(session.isClosed, isTrue);
    });
  });
}

Uint8List _encodeStreamLimit({required int streamId, required int limit}) {
  final builder = BytesBuilder();
  builder.add(VarInt.encode(streamId));
  builder.add(VarInt.encode(limit));
  return builder.toBytes();
}

Uint8List _asUint8List(List<int> bytes) => Uint8List.fromList(bytes);

ByteBuffer _asBuffer(List<int> bytes) => _asUint8List(bytes).buffer;
