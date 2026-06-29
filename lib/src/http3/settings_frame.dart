import 'dart:typed_data';

import 'package:quic_lib/src/wire/varint.dart';

/// HTTP/3 SETTINGS identifiers per RFC 9114 Section 7.2.4.
enum Http3SettingsId {
  /// SETTINGS_MAX_FIELD_SECTION_SIZE (0x06)
  maxFieldSectionSize(0x06),

  /// SETTINGS_QPACK_MAX_TABLE_CAPACITY (0x01)
  maxTableCapacity(0x01),

  /// SETTINGS_QPACK_BLOCKED_STREAMS (0x07) per RFC 9204 Section 5.
  blockedStreams(0x07),

  /// SETTINGS_ENABLE_CONNECT_PROTOCOL (0x08) per RFC 9220.
  enableConnectProtocol(0x08),

  /// SETTINGS_H3_DATAGRAM (0x33) per RFC 9297.
  h3Datagram(0x33),

  /// SETTINGS_WEBTRANSPORT_MAX_SESSIONS (0x2b60) per draft-ietf-webtrans-http3.
  wtMaxSessions(0x2b60),

  /// SETTINGS_WEBTRANSPORT_INITIAL_MAX_STREAMS_UNI (0x14e9cd29)
  /// per draft-ietf-webtrans-http3 §5.5.1.
  wtInitialMaxStreamsUni(0x14e9cd29),

  /// GREASE value for interoperability testing (0x1f * 1 + 0x21 = 0x40).
  grease0(0x40),

  /// GREASE value for interoperability testing (0x1f * 2 + 0x21 = 0x5f).
  grease1(0x5f);

  final int value;
  const Http3SettingsId(this.value);
}

/// HTTP/3 SETTINGS frame payload.
///
/// RFC 9114 Section 7.2.4: the payload is a sequence of
/// VarInt(identifier), VarInt(value) pairs.
class Http3SettingsFrame {
  final Map<int, int> settings;

  Http3SettingsFrame({this.settings = const {}});

  /// Serialize settings as a sequence of VarInt(id), VarInt(value) pairs.
  Uint8List serializePayload() {
    final builder = BytesBuilder();
    for (final entry in settings.entries) {
      builder.add(VarInt.encode(entry.key));
      builder.add(VarInt.encode(entry.value));
    }
    return builder.toBytes();
  }

  /// Parse settings payload.
  static Http3SettingsFrame parsePayload(Uint8List payload) {
    final result = <int, int>{};
    var offset = 0;

    while (offset < payload.length) {
      final id = VarInt.decode(payload.buffer, offset: offset);
      final idLength = VarInt.decodeLength(payload[offset]);
      offset += idLength;

      if (offset >= payload.length) {
        throw ArgumentError('Incomplete SETTINGS payload: missing value');
      }

      final value = VarInt.decode(payload.buffer, offset: offset);
      final valueLength = VarInt.decodeLength(payload[offset]);
      offset += valueLength;

      result[id] = value;
    }

    return Http3SettingsFrame(settings: result);
  }

  /// Convenience: create from known settings.
  factory Http3SettingsFrame.from({
    int? maxFieldSectionSize,
    int? maxTableCapacity,
    int? blockedStreams,
    int? enableConnectProtocol,
    int? h3Datagram,
    int? wtMaxSessions,
    int? wtInitialMaxStreamsUni,
  }) {
    final map = <int, int>{};
    if (maxFieldSectionSize != null) {
      map[Http3SettingsId.maxFieldSectionSize.value] = maxFieldSectionSize;
    }
    if (maxTableCapacity != null) {
      map[Http3SettingsId.maxTableCapacity.value] = maxTableCapacity;
    }
    if (blockedStreams != null) {
      map[Http3SettingsId.blockedStreams.value] = blockedStreams;
    }
    if (enableConnectProtocol != null) {
      map[Http3SettingsId.enableConnectProtocol.value] = enableConnectProtocol;
    }
    if (h3Datagram != null) {
      map[Http3SettingsId.h3Datagram.value] = h3Datagram;
    }
    if (wtMaxSessions != null) {
      map[Http3SettingsId.wtMaxSessions.value] = wtMaxSessions;
    }
    if (wtInitialMaxStreamsUni != null) {
      map[Http3SettingsId.wtInitialMaxStreamsUni.value] =
          wtInitialMaxStreamsUni;
    }
    return Http3SettingsFrame(settings: map);
  }

  @override
  String toString() => 'Http3SettingsFrame(${settings.length} settings)';

  @override
  bool operator ==(Object other) =>
      other is Http3SettingsFrame && _mapsEqual(settings, other.settings);

  @override
  int get hashCode {
    var hash = 0;
    for (final entry in settings.entries) {
      hash ^= Object.hash(entry.key, entry.value);
    }
    return hash;
  }

  static bool _mapsEqual(Map<int, int> a, Map<int, int> b) {
    if (a.length != b.length) return false;
    for (final key in a.keys) {
      if (b[key] != a[key]) return false;
    }
    return true;
  }
}
