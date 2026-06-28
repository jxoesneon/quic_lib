import 'package:quic_lib/src/http3/settings_frame.dart';
import 'package:test/test.dart';

void main() {
  group('Http3SettingsFrame', () {
    test('serializePayload / parsePayload round-trip', () {
      final frame = Http3SettingsFrame.from(
        maxFieldSectionSize: 8192,
        maxTableCapacity: 4096,
        blockedStreams: 100,
      );
      final payload = frame.serializePayload();
      final parsed = Http3SettingsFrame.parsePayload(payload);

      expect(parsed, equals(frame));
    });

    test('from factory sets correct IDs', () {
      final frame = Http3SettingsFrame.from(
        maxFieldSectionSize: 16384,
        maxTableCapacity: 2048,
        blockedStreams: 50,
      );

      expect(frame.settings, hasLength(3));
      expect(frame.settings[0x06], equals(16384));
      expect(frame.settings[0x01], equals(2048));
      expect(frame.settings[0x02], equals(50));
    });

    test('empty settings works', () {
      final frame = Http3SettingsFrame();
      expect(frame.settings, isEmpty);

      final payload = frame.serializePayload();
      expect(payload, isEmpty);

      final parsed = Http3SettingsFrame.parsePayload(payload);
      expect(parsed.settings, isEmpty);
    });

    test('multiple settings preserved', () {
      final frame = Http3SettingsFrame(settings: {
        0x01: 100,
        0x06: 200,
        0x0b: 0, // GREASE
      });

      final payload = frame.serializePayload();
      final parsed = Http3SettingsFrame.parsePayload(payload);

      expect(parsed.settings, hasLength(3));
      expect(parsed.settings[0x01], equals(100));
      expect(parsed.settings[0x06], equals(200));
      expect(parsed.settings[0x0b], equals(0));
    });
  });
}
