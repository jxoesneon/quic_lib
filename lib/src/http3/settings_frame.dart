import 'dart:typed_data';

import 'package:quic_lib/src/wire/varint.dart';

/// HTTP/3 SETTINGS identifiers per RFC 9114 Section 7.2.4.
enum Http3SettingsId {
  /// SETTINGS_MAX_FIELD_SECTION_SIZE (0x06)
  maxFieldSectionSize(0x06),

  /// SETTINGS_QPACK_MAX_TABLE_CAPACITY (0x01)
  maxTableCapacity(0x01),

  /// SETTINGS_QPACK_BLOCKED_STREAMS (0x02)
  blockedStreams(0x02),

  /// GREASE value for interoperability testing.
  grease0(0x0b),

  /// GREASE value for interoperability testing.
  grease1(0x2a);

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
