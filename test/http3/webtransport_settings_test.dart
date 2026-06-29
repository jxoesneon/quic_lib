import 'package:test/test.dart';
import 'package:quic_lib/src/http3/settings_frame.dart';

void main() {
  group('WebTransport SETTINGS', () {
    test('SETTINGS_WEBTRANSPORT_ENABLED has correct value', () {
      expect(Http3SettingsId.wtEnabled.value, 0x2c7cf000);
    });

    test('SETTINGS_WEBTRANSPORT_INITIAL_MAX_DATA has correct value', () {
      expect(Http3SettingsId.wtInitialMaxData.value, 0x2b61);
    });

    test('SETTINGS_WEBTRANSPORT_INITIAL_MAX_STREAMS_UNI has correct value', () {
      expect(Http3SettingsId.wtInitialMaxStreamsUni.value, 0x2b64);
    });

    test('SETTINGS_WEBTRANSPORT_INITIAL_MAX_STREAMS_BIDI has correct value', () {
      expect(Http3SettingsId.wtInitialMaxStreamsBidi.value, 0x2b65);
    });

    test('Http3SettingsFrame.from includes WebTransport settings', () {
      final frame = Http3SettingsFrame.from(
        wtEnabled: 1,
        wtInitialMaxData: 100000,
        wtInitialMaxStreamsUni: 100,
        wtInitialMaxStreamsBidi: 50,
      );
      expect(frame.settings[0x2c7cf000], 1);
      expect(frame.settings[0x2b61], 100000);
      expect(frame.settings[0x2b64], 100);
      expect(frame.settings[0x2b65], 50);
    });

    test('Http3SettingsFrame parse round-trip preserves WebTransport settings',
        () {
      final original = Http3SettingsFrame.from(
        maxTableCapacity: 4096,
        wtEnabled: 1,
        wtInitialMaxData: 65536,
        wtInitialMaxStreamsUni: 50,
        wtInitialMaxStreamsBidi: 25,
      );
      final parsed = Http3SettingsFrame.parsePayload(original.serializePayload());
      expect(parsed.settings[0x2c7cf000], 1);
      expect(parsed.settings[0x2b61], 65536);
      expect(parsed.settings[0x2b64], 50);
      expect(parsed.settings[0x2b65], 25);
      expect(parsed.settings[0x01], 4096);
    });
  });
}
