import 'package:test/test.dart';
import 'package:quic_lib/src/http3/settings_frame.dart';

void main() {
  group('WebTransport SETTINGS', () {
    test('SETTINGS_WEBTRANSPORT_MAX_SESSIONS has correct value', () {
      expect(Http3SettingsId.wtMaxSessions.value, 0x2b60);
    });

    test('SETTINGS_WEBTRANSPORT_INITIAL_MAX_STREAMS_UNI has correct value', () {
      expect(Http3SettingsId.wtInitialMaxStreamsUni.value, 0x14e9cd29);
    });

    test('Http3SettingsFrame.from includes WebTransport settings', () {
      final frame = Http3SettingsFrame.from(
        wtMaxSessions: 10,
        wtInitialMaxStreamsUni: 100,
      );
      expect(frame.settings[0x2b60], 10);
      expect(frame.settings[0x14e9cd29], 100);
    });

    test('Http3SettingsFrame parse round-trip preserves WebTransport settings',
        () {
      final original = Http3SettingsFrame.from(
        maxTableCapacity: 4096,
        wtMaxSessions: 5,
        wtInitialMaxStreamsUni: 50,
      );
      final parsed = Http3SettingsFrame.parsePayload(original.serializePayload());
      expect(parsed.settings[0x2b60], 5);
      expect(parsed.settings[0x14e9cd29], 50);
      expect(parsed.settings[0x01], 4096);
    });
  });
}
