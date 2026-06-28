import 'package:test/test.dart';
import 'package:quic_lib/src/crypto/default_crypto_backend.dart';
import 'package:quic_lib/src/crypto/initial_secrets.dart';
import 'package:quic_lib/src/crypto/packet/key_derivation.dart';
import 'package:quic_lib/src/wire/frame.dart';
import 'package:quic_lib/src/wire/packet_builder.dart';
import 'package:quic_lib/src/wire/packet_header.dart';

void main() {
  group('Initial packet exchange', () {
    test('client can build an Initial packet', () async {
      // 1. Choose a destination connection ID
      final dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];

      // 2. Derive initial secrets
      final secrets =
          await InitialSecrets.derive(dcid, backend: DefaultCryptoBackend());

      // 3. Derive keys
      final keys = await KeyDerivation.deriveKeys(
        secret: secrets.clientSecret,
        keyLength: 16,
        hpKeyLength: 16,
        backend: DefaultCryptoBackend(),
      );
      expect(keys.key.isNotEmpty, isTrue);

      // 4. Build a LongHeader Initial packet
      final header = LongHeader(
        version: 0x00000001,
        packetType: LongHeader.typeInitial,
        destinationConnectionId: dcid,
        sourceConnectionId: [0x01, 0x02],
        packetNumber: 0,
        token: const [],
      );

      // 5. Build a CRYPTO frame with ClientHello bytes (or dummy bytes for now)
      final frames = [
        CryptoFrame(offset: 0, data: [0x01, 0x00, 0x00, 0x05, 0x01])
      ];

      // 6. Build the packet
      final packet = PacketBuilder.build(header, frames);

      // 7. Verify packet is not empty and has correct form
      expect(packet.isNotEmpty, isTrue);
      expect(packet[0] & 0x80, isNot(equals(0))); // long header

      // 8. Verify we can parse the header back
      final parsed = PacketHeaderParser.parse(
        packet,
        destinationConnectionIdLength: dcid.length,
      );
      expect(parsed, isA<LongHeader>());
    });

    test('client Initial secrets are deterministic', () async {
      final dcid = [0x01, 0x02, 0x03];
      final secrets1 =
          await InitialSecrets.derive(dcid, backend: DefaultCryptoBackend());
      final secrets2 =
          await InitialSecrets.derive(dcid, backend: DefaultCryptoBackend());

      final key1 = secrets1.clientSecret.extractSync();
      final key2 = secrets2.clientSecret.extractSync();
      expect(key1, equals(key2));
    });
  });
}
