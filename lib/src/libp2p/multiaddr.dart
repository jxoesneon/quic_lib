import 'dart:convert';
import 'dart:typed_data';

/// A self-describing network address following the libp2p multiaddr format.
///
/// [Multiaddr] encodes a stack of network protocols and their values (e.g.,
/// `/ip4/127.0.0.1/udp/1234/quic-v1`) as an ordered list of [MultiaddrComponent]s.
/// It supports parsing from human-readable strings or compact binary bytes, and
/// can serialize back to either form.
///
/// This type is used by the libp2p transport layer to identify peers and
/// endpoints without ambiguity about which protocols are in use.
///
/// ## Example
/// ```dart
/// final addr = Multiaddr.parse('/ip4/127.0.0.1/udp/1234/quic-v1');
/// final bytes = addr.toBytes();
/// ```
///
/// See also:
/// - [MultiaddrComponent] — a single protocol/value pair inside a multiaddr.
/// - [Libp2pQuicTransport] — the transport that uses these addresses.
class Multiaddr {
  final List<MultiaddrComponent> components;

  /// Creates a [Multiaddr] from an explicit list of [components].
  ///
  /// Most callers should use [Multiaddr.parse] or [Multiaddr.fromBytes] instead.
  Multiaddr({required this.components});

  /// Parse from human-readable string (e.g., "/ip4/127.0.0.1/udp/1234/quic-v1").
  factory Multiaddr.parse(String address) {
    if (address.isEmpty || address == '/') {
      return Multiaddr(components: const <MultiaddrComponent>[]);
    }

    final parts = address.split('/');
    if (parts.isEmpty || parts[0].isNotEmpty) {
      throw FormatException('multiaddr must start with /');
    }

    final components = <MultiaddrComponent>[];
    var i = 1;
    while (i < parts.length) {
      final name = parts[i];
      i++;
      if (name.isEmpty) {
        throw FormatException('empty protocol name');
      }

      final info = _protocolsByName[name];
      if (info == null) {
        throw FormatException('unknown protocol');
      }

      String? value;
      if (info.hasValue) {
        if (i >= parts.length) {
          throw FormatException('protocol requires a value');
        }
        value = parts[i];
        i++;
        _validateValue(name, value);
      }

      components.add(MultiaddrComponent(protocol: name, value: value));
    }

    return Multiaddr(components: components);
  }

  /// Parse from binary bytes.
  factory Multiaddr.fromBytes(Uint8List bytes) {
    final components = <MultiaddrComponent>[];
    var offset = 0;

    while (offset < bytes.length) {
      final (code, codeBytes) = _decodeUvarint(bytes, offset);
      offset += codeBytes;

      final name = _protocolsByCode[code];
      if (name == null) {
        throw FormatException('unknown protocol code: $code');
      }
      final info = _protocolsByName[name]!;

      String? value;
      if (info.hasValue) {
        if (info.size != null) {
          final size = info.size!;
          if (offset + size > bytes.length) {
            throw FormatException('truncated value for protocol $name');
          }
          final valueBytes = bytes.sublist(offset, offset + size);
          offset += size;
          value = _bytesToValue(name, valueBytes);
        } else {
          final (length, lengthBytes) = _decodeUvarint(bytes, offset);
          offset += lengthBytes;
          if (offset + length > bytes.length) {
            throw FormatException('truncated value for protocol $name');
          }
          final valueBytes = bytes.sublist(offset, offset + length);
          offset += length;
          value = utf8.decode(valueBytes);
        }
      }

      components.add(MultiaddrComponent(protocol: name, value: value));
    }

    return Multiaddr(components: components);
  }

  /// Serialize to human-readable string.
  String toHumanReadable() {
    if (components.isEmpty) {
      return '/';
    }
    final buffer = StringBuffer();
    for (final c in components) {
      buffer.write('/');
      buffer.write(c.protocol);
      if (c.value != null) {
        buffer.write('/');
        buffer.write(c.value);
      }
    }
    return buffer.toString();
  }

  /// Serialize to binary bytes.
  Uint8List toBytes() {
    final builder = BytesBuilder();
    for (final c in components) {
      final info = _protocolsByName[c.protocol]!;
      builder.add(_encodeUvarint(info.code));
      if (c.value != null) {
        final valueBytes = _valueToBytes(c.protocol, c.value!);
        if (info.size == null) {
          builder.add(_encodeUvarint(valueBytes.length));
        }
        builder.add(valueBytes);
      }
    }
    return builder.toBytes();
  }

  /// Get the protocol path (e.g., `["ip4", "udp", "quic-v1"]`).
  List<String> get protocols => components.map((c) => c.protocol).toList();

  @override
  String toString() => toHumanReadable();

  @override
  bool operator ==(Object other) =>
      other is Multiaddr &&
      other.components.length == components.length &&
      List.generate(
        components.length,
        (i) =>
            other.components[i].protocol == components[i].protocol &&
            other.components[i].value == components[i].value,
      ).every((x) => x);

  @override
  int get hashCode => Object.hashAll(components);
}

/// A single protocol/value pair within a [Multiaddr].
///
/// Each component describes one layer of the network stack, such as `ip4`,
/// `udp`, or `quic-v1`. Some protocols (e.g., `quic-v1`) have no value and
/// are represented with a `null` [value].
///
/// See also:
/// - [Multiaddr] — the aggregate address composed of these components.
class MultiaddrComponent {
  final String protocol;
  final String? value;

  /// Creates a [MultiaddrComponent] for [protocol] with an optional [value].
  ///
  /// The [protocol] must be a known protocol name (e.g., `ip4`, `udp`, `p2p`).
  const MultiaddrComponent({required this.protocol, this.value});

  @override
  bool operator ==(Object other) =>
      other is MultiaddrComponent &&
      other.protocol == protocol &&
      other.value == value;

  @override
  int get hashCode => Object.hash(protocol, value);
}

class _ProtocolInfo {
  final int code;
  final int? size;
  final bool hasValue;

  const _ProtocolInfo(this.code, this.size, {this.hasValue = true});
}

final Map<String, _ProtocolInfo> _protocolsByName = {
  'ip4': const _ProtocolInfo(4, 4),
  'ip6': const _ProtocolInfo(41, 16),
  'tcp': const _ProtocolInfo(6, 2),
  'udp': const _ProtocolInfo(273, 2),
  'dns': const _ProtocolInfo(53, null),
  'dns4': const _ProtocolInfo(54, null),
  'dns6': const _ProtocolInfo(55, null),
  'ws': const _ProtocolInfo(477, 0, hasValue: false),
  'wss': const _ProtocolInfo(478, 0, hasValue: false),
  'quic': const _ProtocolInfo(460, 0, hasValue: false),
  'quic-v1': const _ProtocolInfo(461, 0, hasValue: false),
  'tls': const _ProtocolInfo(448, 0, hasValue: false),
  'p2p': const _ProtocolInfo(421, null),
};

final Map<int, String> _protocolsByCode = {
  for (final entry in _protocolsByName.entries) entry.value.code: entry.key,
};

Uint8List _encodeUvarint(int value) {
  if (value < 0) {
    throw ArgumentError('uvarint must be non-negative');
  }
  final bytes = <int>[];
  while (value >= 0x80) {
    bytes.add((value & 0x7f) | 0x80);
    value >>= 7;
  }
  bytes.add(value & 0x7f);
  return Uint8List.fromList(bytes);
}

(int value, int bytesRead) _decodeUvarint(Uint8List bytes, int offset) {
  if (offset >= bytes.length) {
    throw ArgumentError('unexpected end of data');
  }
  var value = 0;
  var shift = 0;
  var pos = offset;
  while (pos < bytes.length) {
    final byte = bytes[pos];
    value |= (byte & 0x7f) << shift;
    pos++;
    if ((byte & 0x80) == 0) {
      return (value, pos - offset);
    }
    shift += 7;
    if (shift > 63) {
      throw ArgumentError('uvarint overflow');
    }
  }
  throw ArgumentError('truncated uvarint');
}

void _validateValue(String protocol, String value) {
  switch (protocol) {
    case 'ip4':
      _parseIPv4(value);
      return;
    case 'ip6':
      _parseIPv6(value);
      return;
    case 'tcp':
    case 'udp':
      final port = int.tryParse(value);
      if (port == null || port < 0 || port > 65535) {
        throw FormatException('invalid port: $value');
      }
      return;
    case 'dns':
    case 'dns4':
    case 'dns6':
    case 'p2p':
      if (value.isEmpty) {
        throw FormatException('protocol $protocol value must not be empty');
      }
      return;
  }
}

Uint8List _valueToBytes(String protocol, String value) {
  switch (protocol) {
    case 'ip4':
      return _parseIPv4(value);
    case 'ip6':
      return _parseIPv6(value);
    case 'tcp':
    case 'udp':
      final port = int.parse(value);
      return Uint8List(2)
        ..[0] = (port >> 8) & 0xff
        ..[1] = port & 0xff;
    case 'dns':
    case 'dns4':
    case 'dns6':
    case 'p2p':
      return Uint8List.fromList(utf8.encode(value));
    default:
      throw FormatException('protocol $protocol does not support values');
  }
}

String _bytesToValue(String protocol, Uint8List bytes) {
  switch (protocol) {
    case 'ip4':
      return bytes.map((b) => b.toString()).join('.');
    case 'ip6':
      return _formatIPv6(bytes);
    case 'tcp':
    case 'udp':
      final port = (bytes[0] << 8) | bytes[1];
      return port.toString();
    case 'dns':
    case 'dns4':
    case 'dns6':
    case 'p2p':
      return utf8.decode(bytes);
    default:
      throw FormatException('protocol $protocol does not support values');
  }
}

Uint8List _parseIPv4(String value) {
  final parts = value.split('.');
  if (parts.length != 4) {
    throw FormatException('invalid ip4');
  }
  return Uint8List.fromList(
    parts.map((p) {
      final n = int.parse(p);
      if (n < 0 || n > 255) {
        throw FormatException('invalid ip4 octet');
      }
      return n;
    }).toList(),
  );
}

Uint8List _parseIPv6(String value) {
  if (value.contains('::')) {
    if (value == '::') {
      return Uint8List(16);
    }
    final split = value.split('::');
    if (split.length != 2) {
      throw FormatException('invalid ip6');
    }
    final left = split[0].isEmpty ? <String>[] : split[0].split(':');
    final right = split[1].isEmpty ? <String>[] : split[1].split(':');
    if (left.length + right.length >= 8) {
      throw FormatException('invalid ip6');
    }
    final zeros = 8 - left.length - right.length;
    final groups = [...left, ...List.filled(zeros, '0'), ...right];
    value = groups.join(':');
  }

  final groups = value.split(':');
  if (groups.length != 8) {
    throw FormatException('invalid ip6');
  }
  final bytes = Uint8List(16);
  for (var i = 0; i < 8; i++) {
    final hex = groups[i];
    if (hex.length > 4) {
      throw FormatException('invalid ip6');
    }
    final n = int.parse(hex, radix: 16);
    if (n < 0 || n > 0xFFFF) {
      throw FormatException('invalid ip6');
    }
    bytes[i * 2] = (n >> 8) & 0xff;
    bytes[i * 2 + 1] = n & 0xff;
  }
  return bytes;
}

String _formatIPv6(Uint8List bytes) {
  final groups = <String>[];
  for (var i = 0; i < 16; i += 2) {
    final n = (bytes[i] << 8) | bytes[i + 1];
    groups.add(n.toRadixString(16));
  }

  // Find longest run of zeros for :: compression
  var bestStart = -1;
  var bestLen = 0;
  var currentStart = -1;
  var currentLen = 0;
  for (var i = 0; i < groups.length; i++) {
    if (groups[i] == '0') {
      if (currentStart == -1) {
        currentStart = i;
        currentLen = 1;
      } else {
        currentLen++;
      }
    } else {
      if (currentLen > bestLen) {
        bestLen = currentLen;
        bestStart = currentStart;
      }
      currentStart = -1;
      currentLen = 0;
    }
  }
  if (currentLen > bestLen) {
    bestLen = currentLen;
    bestStart = currentStart;
  }

  if (bestLen >= 2) {
    final left = groups.sublist(0, bestStart).join(':');
    final right = groups.sublist(bestStart + bestLen).join(':');
    if (left.isEmpty && right.isEmpty) return '::';
    if (left.isEmpty) return '::$right';
    if (right.isEmpty) return '$left::';
    return '$left::$right';
  }

  return groups.join(':');
}
