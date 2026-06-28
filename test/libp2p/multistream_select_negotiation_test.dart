import 'dart:collection';
import 'dart:convert';
import 'dart:typed_data';

import 'package:quic_lib/src/libp2p/libp2p_quic_transport.dart';
import 'package:quic_lib/src/libp2p/multistream_select.dart';
import 'package:test/test.dart';

/// A fake QUIC connection that supports [write] and [read] for testing
/// multistream-select negotiation.
class _FakeNegotiableConnection {
  final List<Uint8List> written = <Uint8List>[];
  final Queue<Uint8List> _responses = Queue<Uint8List>();

  void openUnidirectionalStream() {}

  void write(Uint8List data) {
    written.add(Uint8List.fromList(data));
  }

  Future<Uint8List?> read() async {
    if (_responses.isEmpty) return null;
    return _responses.removeFirst();
  }

  void enqueueResponse(Uint8List data) {
    _responses.add(Uint8List.fromList(data));
  }
}

void main() {
  group('MultistreamSelect length-prefixed encoding', () {
    test('encodeLengthPrefixed prepends varint length', () {
      final data = Uint8List.fromList([0x01, 0x02, 0x03]);
      final encoded = MultistreamSelect.encodeLengthPrefixed(data);
      expect(encoded.length, equals(4));
      expect(encoded[0], equals(3)); // varint length = 3
      expect(encoded.sublist(1), equals(data));
    });

    test('encodeLengthPrefixed handles empty data', () {
      final data = Uint8List(0);
      final encoded = MultistreamSelect.encodeLengthPrefixed(data);
      expect(encoded.length, equals(1));
      expect(encoded[0], equals(0));
    });

    test('parseLengthPrefixed extracts message and bytes consumed', () {
      final data = Uint8List.fromList([0x05, 0x41, 0x42, 0x43, 0x44, 0x45]);
      final result = MultistreamSelect.parseLengthPrefixed(data);
      expect(result, isNotNull);
      expect(result!.$1, equals(Uint8List.fromList([0x41, 0x42, 0x43, 0x44, 0x45])));
      expect(result.$2, equals(6));
    });

    test('parseLengthPrefixed returns null for incomplete data', () {
      final data = Uint8List.fromList([0x05, 0x41]);
      final result = MultistreamSelect.parseLengthPrefixed(data);
      expect(result, isNull);
    });

    test('parseLengthPrefixed returns null for empty data', () {
      final result = MultistreamSelect.parseLengthPrefixed(Uint8List(0));
      expect(result, isNull);
    });

    test('roundtrip encode and parse', () {
      final original = utf8.encode('/multistream/1.0.0\n');
      final encoded = MultistreamSelect.encodeLengthPrefixed(
        Uint8List.fromList(original),
      );
      final result = MultistreamSelect.parseLengthPrefixed(encoded);
      expect(result, isNotNull);
      expect(result!.$1, equals(Uint8List.fromList(original)));
      expect(result.$2, equals(encoded.length));
    });
  });

  group('Libp2pQuicConnection negotiateProtocol', () {
    test('successful negotiation returns matched protocol', () async {
      final fakeConn = _FakeNegotiableConnection();
      final conn = Libp2pQuicConnection(fakeConn);

      // Peer responds with the same protocol.
      fakeConn.enqueueResponse(
        MultistreamSelect.encodeLengthPrefixed(
          MultistreamSelect.encodeProtocol('/ipfs/1.0.0'),
        ),
      );

      final result = await conn.negotiateProtocol(['/ipfs/1.0.0']);
      expect(result, equals('/ipfs/1.0.0'));

      // Verify the header was sent length-prefixed.
      expect(fakeConn.written.length, equals(2));
      final headerResult = MultistreamSelect.parseLengthPrefixed(fakeConn.written[0]);
      expect(headerResult, isNotNull);
      expect(
        MultistreamSelect.parseMessages(headerResult!.$1),
        equals(['/multistream/1.0.0']),
      );

      // Verify the protocol was sent length-prefixed.
      final protoResult = MultistreamSelect.parseLengthPrefixed(fakeConn.written[1]);
      expect(protoResult, isNotNull);
      expect(
        MultistreamSelect.parseMessages(protoResult!.$1),
        equals(['/ipfs/1.0.0']),
      );
    });

    test('na fallback tries next protocol', () async {
      final fakeConn = _FakeNegotiableConnection();
      final conn = Libp2pQuicConnection(fakeConn);

      // Peer responds with na for the first protocol.
      fakeConn.enqueueResponse(
        MultistreamSelect.encodeLengthPrefixed(MultistreamSelect.na),
      );
      // Peer responds with match for the second protocol.
      fakeConn.enqueueResponse(
        MultistreamSelect.encodeLengthPrefixed(
          MultistreamSelect.encodeProtocol('/libp2p/1.0.0'),
        ),
      );

      final result = await conn.negotiateProtocol([
        '/ipfs/1.0.0',
        '/libp2p/1.0.0',
      ]);
      expect(result, equals('/libp2p/1.0.0'));

      // Header + first protocol + second protocol = 3 writes.
      expect(fakeConn.written.length, equals(3));
    });

    test('all na responses returns null', () async {
      final fakeConn = _FakeNegotiableConnection();
      final conn = Libp2pQuicConnection(fakeConn);

      fakeConn.enqueueResponse(
        MultistreamSelect.encodeLengthPrefixed(MultistreamSelect.na),
      );
      fakeConn.enqueueResponse(
        MultistreamSelect.encodeLengthPrefixed(MultistreamSelect.na),
      );

      final result = await conn.negotiateProtocol([
        '/ipfs/1.0.0',
        '/libp2p/1.0.0',
      ]);
      expect(result, isNull);
    });

    test('empty protocol list returns null', () async {
      final fakeConn = _FakeNegotiableConnection();
      final conn = Libp2pQuicConnection(fakeConn);

      final result = await conn.negotiateProtocol([]);
      expect(result, isNull);
      expect(fakeConn.written, isEmpty);
    });

    test('handles peer returning an unexpected but known protocol', () async {
      final fakeConn = _FakeNegotiableConnection();
      final conn = Libp2pQuicConnection(fakeConn);

      // Peer returns a different protocol from the list.
      fakeConn.enqueueResponse(
        MultistreamSelect.encodeLengthPrefixed(
          MultistreamSelect.encodeProtocol('/libp2p/1.0.0'),
        ),
      );

      final result = await conn.negotiateProtocol([
        '/ipfs/1.0.0',
        '/libp2p/1.0.0',
      ]);
      expect(result, equals('/libp2p/1.0.0'));
    });
  });
}
