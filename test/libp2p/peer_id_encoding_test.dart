import 'package:dart_quic/src/http3/http3_connection.dart';
import 'package:dart_quic/src/http3/settings_frame.dart';
import 'package:dart_quic/src/libp2p/peer_id.dart';
import 'package:test/test.dart';

void main() {
  group('PeerId encoding', () {
    test('Base58 round-trip for known values', () {
      // Leading zero byte encodes as '1' in Base58.
      final peer1 = PeerId.fromBytes(<int>[0x00]);
      expect(peer1.encodeBase58(), equals('1'));
      expect(PeerId.decodeBase58('1').bytes, orderedEquals(<int>[0x00]));

      // A non-trivial round-trip.
      final peer2 = PeerId.fromBytes(<int>[0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);
      final encoded = peer2.encodeBase58();
      final decoded = PeerId.decodeBase58(encoded);
      expect(decoded.bytes, orderedEquals(peer2.bytes));
    });

    test('Base36 round-trip for known values', () {
      // Leading zero byte encodes as '0' in Base36.
      final peer1 = PeerId.fromBytes(<int>[0x00]);
      expect(peer1.encodeBase36(), equals('0'));
      expect(PeerId.decodeBase36('0').bytes, orderedEquals(<int>[0x00]));

      // A non-trivial round-trip.
      final peer2 = PeerId.fromBytes(<int>[0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);
      final encoded = peer2.encodeBase36();
      final decoded = PeerId.decodeBase36(encoded);
      expect(decoded.bytes, orderedEquals(peer2.bytes));
    });
  });

  group('Http3Connection.sendSettings', () {
    test('returns a settings frame with default values', () {
      final conn = Http3Connection(quicConnection: Object());
      final settings = conn.sendSettings();
      expect(settings, isA<Http3SettingsFrame>());
      expect(conn.pendingSettings, same(settings));
      expect(
        settings.settings[Http3SettingsId.maxFieldSectionSize.value],
        equals(65536),
      );
      expect(
        settings.settings[Http3SettingsId.maxTableCapacity.value],
        equals(0),
      );
      expect(
        settings.settings[Http3SettingsId.blockedStreams.value],
        equals(0),
      );
    });
  });
}
