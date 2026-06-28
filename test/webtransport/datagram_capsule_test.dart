import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:quic_lib/src/webtransport/capsule_types.dart';
import 'package:quic_lib/src/webtransport/datagram_capsule.dart';
import 'package:quic_lib/src/webtransport/webtransport_session.dart';

void main() {
  group('DatagramCapsule', () {
    test('serialize and parse round-trip', () {
      final original = DatagramCapsule(Uint8List.fromList([0x01, 0x02, 0x03]));
      final bytes = original.serialize();
      final parsed = DatagramCapsule.parse(bytes);

      expect(parsed.payload, equals(original.payload));
    });
  });

  group('WebTransportSession datagram handling', () {
    test('receives datagram capsules', () {
      final session = WebTransportSession(1);
      final payload = Uint8List.fromList([0x0a, 0x0b, 0x0c]);
      session.onCapsuleReceived(Capsule(
        type: CapsuleType.datagram,
        payload: payload,
      ));

      expect(session.receivedDatagrams, hasLength(1));
      expect(session.receivedDatagrams.first, equals(payload));
    });

    test('sendDatagram produces correct capsule type', () {
      final session = WebTransportSession(1);
      final data = Uint8List.fromList([0xde, 0xad, 0xbe, 0xef]);
      final capsule = session.sendDatagram(data);

      expect(capsule.type, equals(CapsuleType.datagram));
      expect(capsule.payload, equals(data));
    });
  });
}
