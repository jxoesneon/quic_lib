import 'dart:typed_data';

import 'package:quic_lib/src/http3/headers_frame.dart';
import 'package:quic_lib/src/http3/http3_connection.dart';
import 'package:quic_lib/src/http3/http3_response.dart';
import 'package:quic_lib/src/http3/qpack_decoder_stream.dart';
import 'package:quic_lib/src/http3/qpack_encoder_stream.dart';
import 'package:quic_lib/src/http3/settings_frame.dart';
import 'package:quic_lib/src/wire/varint.dart';
import 'package:test/test.dart';

class FakeQuicConnection {
  int _nextBidiStreamId = 0;
  int _nextUniStreamId = 2;

  int openBidirectionalStream() {
    final id = _nextBidiStreamId;
    _nextBidiStreamId += 4;
    return id;
  }

  int openUnidirectionalStream() {
    final id = _nextUniStreamId;
    _nextUniStreamId += 4;
    return id;
  }

  List<int>? get connectionId => [0xAB, 0xCD];

  Future<Uint8List> buildEncryptedPacket({
    required space,
    required List<dynamic> frames,
    required List<int> dcid,
  }) async {
    return Uint8List.fromList([0xFF, 0xFF]);
  }
}

/// Build a unidirectional stream data buffer with the given [streamType] prefix
/// followed by [payload].
Uint8List _buildStreamData(int streamType, Uint8List payload) {
  final typeBytes = VarInt.encode(streamType);
  final data = Uint8List(typeBytes.length + payload.length);
  data.setRange(0, typeBytes.length, typeBytes);
  data.setRange(typeBytes.length, data.length, payload);
  return data;
}

void main() {
  group('QPACK stream integration', () {
    test('openQpackStreams sets capacity and stages stream packets', () async {
      final quic = FakeQuicConnection();
      final conn = Http3Connection(
        quicConnection: quic,
        localSettings: Http3SettingsFrame.from(maxTableCapacity: 1024),
      );
      await conn.openQpackStreams();

      expect(conn.qpackDecoder.dynamicTable.capacity, equals(1024));
      expect(conn.qpackEncoder.dynamicTable.capacity, equals(1024));
      expect(conn.pendingQuicPackets, hasLength(2));
    });

    test('flushQpackEncoderInstructions sends emitted instructions', () async {
      final quic = FakeQuicConnection();
      final conn = Http3Connection(
        quicConnection: quic,
        localSettings: Http3SettingsFrame.from(maxTableCapacity: 1024),
      );
      await conn.openQpackStreams();

      conn.qpackEncoder.emittedInstructions.add(
        InsertWithoutNameReference(name: 'x-custom', value: 'value'),
      );
      await conn.flushQpackEncoderInstructions();

      expect(conn.qpackEncoder.emittedInstructions, isEmpty);
      // A new encoder stream packet was staged (the dummy encrypted bytes).
      expect(conn.pendingQuicPackets, hasLength(3));
    });

    test('onUnidirectionalStreamData parses encoder stream instructions', () {
      final conn = Http3Connection(
        quicConnection: FakeQuicConnection(),
        localSettings: Http3SettingsFrame.from(maxTableCapacity: 1024),
      );
      final instruction = InsertWithoutNameReference(
        name: 'x-peer',
        value: 'peer-value',
      );
      final data = _buildStreamData(0x02, instruction.serialize());

      conn.onUnidirectionalStreamData(10, data);
      expect(conn.qpackDecoder.dynamicTable.length, equals(1));
      final entry = conn.qpackDecoder.dynamicTable.get(0);
      expect(entry?.name, equals('x-peer'));
      expect(entry?.value, equals('peer-value'));
      expect(conn.pendingDecoderInstructions, hasLength(1));
      expect(conn.pendingDecoderInstructions.first, isA<InsertCountIncrement>());
      expect(
        (conn.pendingDecoderInstructions.first as InsertCountIncrement).increment,
        equals(1),
      );
    });

    test('onUnidirectionalStreamData parses SetDynamicTableCapacity', () {
      final conn = Http3Connection(
        quicConnection: FakeQuicConnection(),
        localSettings: Http3SettingsFrame.from(maxTableCapacity: 0),
      );
      final instruction = SetDynamicTableCapacity(capacity: 2048);
      final data = _buildStreamData(0x02, instruction.serialize());

      conn.onUnidirectionalStreamData(10, data);
      expect(conn.qpackDecoder.dynamicTable.capacity, equals(2048));
    });

    test('onUnidirectionalStreamData parses decoder stream instructions', () {
      final conn = Http3Connection(
        quicConnection: FakeQuicConnection(),
        localSettings: Http3SettingsFrame.from(maxTableCapacity: 1024),
      );
      final instruction = InsertCountIncrement(increment: 5);
      final data = _buildStreamData(0x03, instruction.serialize());

      conn.onUnidirectionalStreamData(11, data);
      expect(conn.qpackEncoder.knownReceivedCount, equals(5));
    });

    test('getResponse emits SectionAcknowledgment for decoded stream', () async {
      final conn = Http3Connection(
        quicConnection: FakeQuicConnection(),
        localSettings: Http3SettingsFrame.from(maxTableCapacity: 1024),
      );
      final response = Http3Response(
        statusCode: 200,
        headers: {'content-type': 'text/plain'},
      );
      final encoded = response.encodeHeaders(encoder: conn.qpackEncoder);

      final headersFrame = Http3HeadersFrame(encodedFieldSection: encoded);
      conn.onStreamFrame(0, headersFrame.toFrame());

      final decoded = conn.getResponse(0);
      expect(decoded, isNotNull);
      expect(decoded!.statusCode, equals(200));
      expect(conn.pendingDecoderInstructions, hasLength(1));
      expect(conn.pendingDecoderInstructions.first, isA<SectionAcknowledgment>());
      expect(
        (conn.pendingDecoderInstructions.first as SectionAcknowledgment).streamId,
        equals(0),
      );
    });

    test('flushQpackDecoderInstructions sends pending instructions', () async {
      final quic = FakeQuicConnection();
      final conn = Http3Connection(
        quicConnection: quic,
        localSettings: Http3SettingsFrame.from(maxTableCapacity: 1024),
      );
      await conn.openQpackStreams();
      // pendingDecoderInstructions is unmodifiable, so clear and add via the
      // private field through the test helper below. For this test we rely on
      // getResponse to populate the instruction list.
      final response = Http3Response(statusCode: 204);
      final encoded = response.encodeHeaders(encoder: conn.qpackEncoder);
      conn.onStreamFrame(4, Http3HeadersFrame(encodedFieldSection: encoded).toFrame());
      conn.getResponse(4);
      expect(conn.pendingDecoderInstructions, isNotEmpty);

      await conn.flushQpackDecoderInstructions();
      expect(conn.pendingDecoderInstructions, isEmpty);
      expect(conn.pendingQuicPackets, hasLength(3));
    });
  });
}
