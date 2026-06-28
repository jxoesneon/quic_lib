import 'dart:typed_data';

/// TLS 1.3 ClientHello structure per RFC 8446 Section 4.1.2.
///
/// This class only implements the data structure and serializer; no
/// cryptographic operations are performed.
class ClientHello {
  /// Legacy version (always 0x0303 for TLS 1.3 compatibility).
  final int legacyVersion;

  /// 32 bytes of random data.
  final List<int> random;

  /// Legacy session ID (empty for TLS 1.3).
  final List<int> legacySessionId;

  /// List of supported cipher suites.
  final List<CipherSuite> cipherSuites;

  /// Legacy compression methods (always `0x00` for TLS 1.3).
  final List<int> legacyCompressionMethods;

  /// List of extensions.
  final List<TlsExtension> extensions;

  /// ALPN protocol names to advertise (e.g. `['libp2p']`).
  ///
  /// When non-empty an ALPN extension (type `0x0010`) is automatically
  /// appended to the serialized extension list.
  final List<String> alpnProtocols;

  /// Server Name Indication (SNI) hostname.
  ///
  /// When non-null an SNI extension (type `0x0000`) is automatically
  /// appended to the serialized extension list.
  final String? serverName;

  /// Supported named groups for key exchange.
  ///
  /// Defaults to x25519 (`0x001d`) and secp256r1 (`0x0017`).
  /// When non-empty a `supported_groups` extension (type `0x000a`) is
  /// automatically appended to the serialized extension list.
  final List<int> supportedGroups;

  ClientHello({
    required this.random,
    required this.cipherSuites,
    required this.extensions,
    this.alpnProtocols = const [],
    this.serverName,
    this.supportedGroups = const [0x001d, 0x0017],
    this.legacyVersion = 0x0303,
    this.legacySessionId = const [],
    this.legacyCompressionMethods = const [0x00],
  });

  /// Builds the ALPN extension data for a ClientHello.
  ///
  /// Format: `uint16 list_length + (uint8 name_length + name_bytes)...`
  static Uint8List buildAlpnData(List<String> protocols) {
    final builder = BytesBuilder();
    var listLength = 0;
    for (final p in protocols) {
      final nameBytes = p.codeUnits;
      listLength += 1 + nameBytes.length;
    }
    builder.addByte((listLength >> 8) & 0xFF);
    builder.addByte(listLength & 0xFF);
    for (final p in protocols) {
      final nameBytes = p.codeUnits;
      builder.addByte(nameBytes.length);
      builder.add(nameBytes);
    }
    return Uint8List.fromList(builder.toBytes());
  }

  /// Builds the SNI extension data for a ClientHello.
  ///
  /// Format: `uint16 list_length + (uint8 name_type=0 + uint16 name_length + name_bytes)`
  static Uint8List _buildSniData(String hostName) {
    final builder = BytesBuilder();
    final nameBytes = hostName.codeUnits;
    final entryLength = 1 + 2 + nameBytes.length;
    builder.addByte((entryLength >> 8) & 0xFF);
    builder.addByte(entryLength & 0xFF);
    builder.addByte(0); // name_type = host_name
    builder.addByte((nameBytes.length >> 8) & 0xFF);
    builder.addByte(nameBytes.length & 0xFF);
    builder.add(nameBytes);
    return Uint8List.fromList(builder.toBytes());
  }

  /// Builds the supported_groups extension data for a ClientHello.
  ///
  /// Format: `uint16 list_length + (uint16 group_id)...`
  static Uint8List _buildSupportedGroupsData(List<int> groups) {
    final builder = BytesBuilder();
    final listLength = groups.length * 2;
    builder.addByte((listLength >> 8) & 0xFF);
    builder.addByte(listLength & 0xFF);
    for (final g in groups) {
      builder.addByte((g >> 8) & 0xFF);
      builder.addByte(g & 0xFF);
    }
    return Uint8List.fromList(builder.toBytes());
  }

  /// Serializes the ClientHello to bytes in network (big-endian) order.
  Uint8List serialize() {
    final sessionIdLength = legacySessionId.length;
    final cipherSuitesLength = cipherSuites.length * 2;
    final compressionMethodsLength = legacyCompressionMethods.length;

    // Merge manually-provided extensions with auto-generated ones.
    final merged = List<TlsExtension>.from(extensions);
    final hasAlpn = merged.any((e) => e.type == 0x0010);
    if (alpnProtocols.isNotEmpty && !hasAlpn) {
      merged.add(TlsExtension(
        type: 0x0010,
        data: buildAlpnData(alpnProtocols),
      ));
    }
    final hasSni = merged.any((e) => e.type == 0x0000);
    if (serverName != null && serverName!.isNotEmpty && !hasSni) {
      merged.add(TlsExtension(
        type: 0x0000,
        data: _buildSniData(serverName!),
      ));
    }
    final hasSupportedGroups = merged.any((e) => e.type == 0x000a);
    if (supportedGroups.isNotEmpty && !hasSupportedGroups) {
      merged.add(TlsExtension(
        type: 0x000a,
        data: _buildSupportedGroupsData(supportedGroups),
      ));
    }

    var extensionsLength = 0;
    for (final ext in merged) {
      extensionsLength += 4 + ext.data.length; // type (2) + length (2) + data
    }

    final totalLength = 2 + // legacy_version
        32 + // random
        1 + // legacy_session_id_length
        sessionIdLength +
        2 + // cipher_suites_length
        cipherSuitesLength +
        1 + // legacy_compression_methods_length
        compressionMethodsLength +
        2 + // extensions_length
        extensionsLength;

    final buffer = ByteData(totalLength);
    var offset = 0;

    // legacy_version
    buffer.setUint16(offset, legacyVersion, Endian.big);
    offset += 2;

    // random
    for (var i = 0; i < 32; i++) {
      buffer.setUint8(offset + i, random[i]);
    }
    offset += 32;

    // legacy_session_id_length
    buffer.setUint8(offset, sessionIdLength);
    offset += 1;

    // legacy_session_id
    for (var i = 0; i < sessionIdLength; i++) {
      buffer.setUint8(offset + i, legacySessionId[i]);
    }
    offset += sessionIdLength;

    // cipher_suites_length
    buffer.setUint16(offset, cipherSuitesLength, Endian.big);
    offset += 2;

    // cipher_suites
    for (final cs in cipherSuites) {
      buffer.setUint16(offset, cs.id, Endian.big);
      offset += 2;
    }

    // legacy_compression_methods_length
    buffer.setUint8(offset, compressionMethodsLength);
    offset += 1;

    // legacy_compression_methods
    for (var i = 0; i < compressionMethodsLength; i++) {
      buffer.setUint8(offset + i, legacyCompressionMethods[i]);
    }
    offset += compressionMethodsLength;

    // extensions_length
    buffer.setUint16(offset, extensionsLength, Endian.big);
    offset += 2;

    // extensions
    for (final ext in merged) {
      buffer.setUint16(offset, ext.type, Endian.big);
      offset += 2;
      buffer.setUint16(offset, ext.data.length, Endian.big);
      offset += 2;
      for (var i = 0; i < ext.data.length; i++) {
        buffer.setUint8(offset + i, ext.data[i]);
      }
      offset += ext.data.length;
    }

    return buffer.buffer.asUint8List();
  }
}

/// TLS cipher suite identifier (2 bytes).
class CipherSuite {
  final int id;
  const CipherSuite(this.id);

  static const tlsAes128GcmSha256 = CipherSuite(0x1301);
  static const tlsAes256GcmSha384 = CipherSuite(0x1302);
  static const tlsChacha20Poly1305Sha256 = CipherSuite(0x1303);
}

/// TLS extension as a generic type + opaque data block.
class TlsExtension {
  final int type;
  final List<int> data;

  TlsExtension({required this.type, required this.data});
}
