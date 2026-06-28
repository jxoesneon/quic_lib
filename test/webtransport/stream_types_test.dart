import 'package:quic_lib/src/webtransport/stream_types.dart';
import 'package:test/test.dart';

void main() {
  group('WebTransportStreamType', () {
    test('has expected values', () {
      expect(WebTransportStreamType.values,
          contains(WebTransportStreamType.bidirectional));
      expect(WebTransportStreamType.values,
          contains(WebTransportStreamType.unidirectional));
    });
  });

  group('WebTransportStreamId', () {
    test('client bidi stream ID type is bidirectional', () {
      final id = WebTransportStreamId.encode(
        type: WebTransportStreamId.typeClientBidi,
        sequence: 0,
      );
      expect(WebTransportStreamId.getType(id),
          WebTransportStreamType.bidirectional);
      expect(WebTransportStreamId.isClientInitiated(id), isTrue);
      expect(WebTransportStreamId.isServerInitiated(id), isFalse);
    });

    test('server uni stream ID type is unidirectional', () {
      final id = WebTransportStreamId.encode(
        type: WebTransportStreamId.typeServerUni,
        sequence: 0,
      );
      expect(WebTransportStreamId.getType(id),
          WebTransportStreamType.unidirectional);
      expect(WebTransportStreamId.isClientInitiated(id), isFalse);
      expect(WebTransportStreamId.isServerInitiated(id), isTrue);
    });

    test('sequence extraction works for all types', () {
      const types = [
        WebTransportStreamId.typeClientBidi,
        WebTransportStreamId.typeServerBidi,
        WebTransportStreamId.typeClientUni,
        WebTransportStreamId.typeServerUni,
      ];

      for (final type in types) {
        for (final seq in [0, 1, 5, 100, 999999]) {
          final id = WebTransportStreamId.encode(type: type, sequence: seq);
          expect(
            WebTransportStreamId.sequence(id),
            equals(seq),
            reason: 'sequence mismatch for type=$type, sequence=$seq',
          );
        }
      }
    });

    test('encode/decode round-trip for all types', () {
      const types = [
        WebTransportStreamId.typeClientBidi,
        WebTransportStreamId.typeServerBidi,
        WebTransportStreamId.typeClientUni,
        WebTransportStreamId.typeServerUni,
      ];

      for (final type in types) {
        for (final seq in [0, 1, 5, 100, 999999]) {
          final id = WebTransportStreamId.encode(type: type, sequence: seq);
          final decodedType = id & 0x03;
          final decodedSeq = WebTransportStreamId.sequence(id);

          expect(decodedType, equals(type),
              reason: 'type mismatch for type=$type, sequence=$seq');
          expect(decodedSeq, equals(seq),
              reason: 'sequence mismatch for type=$type, sequence=$seq');
        }
      }
    });

    test('first few IDs match expected values', () {
      // Client bidi: 0, 4, 8, 12, ...
      expect(
        WebTransportStreamId.encode(
            type: WebTransportStreamId.typeClientBidi, sequence: 0),
        equals(0),
      );
      expect(
        WebTransportStreamId.encode(
            type: WebTransportStreamId.typeClientBidi, sequence: 1),
        equals(4),
      );

      // Server uni: 3, 7, 11, 15, ...
      expect(
        WebTransportStreamId.encode(
            type: WebTransportStreamId.typeServerUni, sequence: 0),
        equals(3),
      );
      expect(
        WebTransportStreamId.encode(
            type: WebTransportStreamId.typeServerUni, sequence: 1),
        equals(7),
      );
    });
  });
}
