import 'dart:typed_data';

import 'header_protection.dart';
import 'packet_protector.dart';

/// Holds the AEAD and header-protection keys for a single packet number space.
class PacketNumberSpaceKeys {
  final PacketProtector protector;
  final HeaderProtection headerProtection;

  PacketNumberSpaceKeys({
    required this.protector,
    required this.headerProtection,
  });

  /// Encrypt the payload and authenticate with the header as AAD.
  Future<Uint8List> encrypt(
    int packetNumber,
    Uint8List headerBytes,
    Uint8List payload,
  ) =>
      protector.encrypt(packetNumber, headerBytes, payload);

  /// Decrypt the payload.
  Future<Uint8List> decrypt(
    int packetNumber,
    Uint8List headerBytes,
    Uint8List ciphertext,
  ) =>
      protector.decrypt(packetNumber, headerBytes, ciphertext);

  /// Apply header protection.
  Uint8List protectHeader(Uint8List header, Uint8List payload) =>
      headerProtection.apply(header, payload);

  /// Remove header protection.
  Uint8List unprotectHeader(Uint8List header, Uint8List payload) =>
      headerProtection.remove(header, payload);
}
