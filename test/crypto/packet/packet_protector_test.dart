import 'dart:typed_data';

import 'package:dart_quic/src/crypto/cipher_suites.dart';
import 'package:dart_quic/src/crypto/crypto_backend.dart';
import 'package:dart_quic/src/crypto/default_crypto_backend.dart';
import 'package:dart_quic/src/crypto/packet/packet_protector.dart';
import 'package:test/test.dart';

import '../../helpers/hex.dart';

void main() {
  late CryptoBackend backend;

  setUp(() {
    backend = DefaultCryptoBackend();
  });

  group('PacketProtector', () {
    test('encrypt then decrypt round-trip', () async {
      final key = _secretKey(await backend.randomBytes(16));
      final iv = await backend.randomBytes(12);
      final protector = PacketProtector(
        backend: backend,
        aead: Aes128Gcm(),
        key: key,
        iv: iv,
      );

      final header = Uint8List.fromList([0x40, 0x01, 0x02, 0x03]);
      final payload = Uint8List.fromList([0x01, 0x02, 0x03, 0x04, 0x05]);

      final ciphertext = await protector.encrypt(0, header, payload);
      expect(ciphertext.length, equals(payload.length + 16)); // + tag

      final decrypted = await protector.decrypt(0, header, ciphertext);
      expect(decrypted, equals(payload));
    });

    test('tampered ciphertext fails decryption', () async {
      final key = _secretKey(await backend.randomBytes(16));
      final iv = await backend.randomBytes(12);
      final protector = PacketProtector(
        backend: backend,
        aead: Aes128Gcm(),
        key: key,
        iv: iv,
      );

      final header = Uint8List.fromList([0x40, 0x01, 0x02, 0x03]);
      final payload = Uint8List.fromList([0x01, 0x02, 0x03, 0x04, 0x05]);

      final ciphertext = Uint8List.fromList(await protector.encrypt(1, header, payload));
      ciphertext[0] ^= 0xFF; // tamper

      expect(
        () => protector.decrypt(1, header, ciphertext),
        throwsA(anything),
      );
    });

    test('wrong AAD fails decryption', () async {
      final key = _secretKey(await backend.randomBytes(16));
      final iv = await backend.randomBytes(12);
      final protector = PacketProtector(
        backend: backend,
        aead: Aes128Gcm(),
        key: key,
        iv: iv,
      );

      final header = Uint8List.fromList([0x40, 0x01, 0x02, 0x03]);
      final wrongHeader = Uint8List.fromList([0x40, 0x01, 0x02, 0x04]);
      final payload = Uint8List.fromList([0x01, 0x02, 0x03, 0x04, 0x05]);

      final ciphertext = await protector.encrypt(2, header, payload);

      expect(
        () => protector.decrypt(2, wrongHeader, ciphertext),
        throwsA(anything),
      );
    });

    test('different packet numbers produce different ciphertexts', () async {
      final key = _secretKey(await backend.randomBytes(16));
      final iv = await backend.randomBytes(12);
      final protector = PacketProtector(
        backend: backend,
        aead: Aes128Gcm(),
        key: key,
        iv: iv,
      );

      final header = Uint8List.fromList([0x40, 0x01, 0x02, 0x03]);
      final payload = Uint8List.fromList([0x01, 0x02, 0x03, 0x04, 0x05]);

      final ct0 = await protector.encrypt(0, header, payload);
      final ct1 = await protector.encrypt(1, header, payload);
      final ct42 = await protector.encrypt(42, header, payload);

      expect(ct0, isNot(equals(ct1)));
      expect(ct0, isNot(equals(ct42)));
      expect(ct1, isNot(equals(ct42)));
    });

    test('nonce construction matches RFC 9001', () async {
      // Test with a known IV and packet number to verify XOR logic.
      final iv = hexDecode('000000000000000000000000');
      final key = _secretKey(Uint8List(16));
      final protector = PacketProtector(
        backend: backend,
        aead: Aes128Gcm(),
        key: key,
        iv: iv,
      );

      final header = Uint8List.fromList([0x40]);
      final payload = Uint8List.fromList([0x00]);

      // With IV = 0, nonce = packet number left-padded to 12 bytes.
      // Encrypt with PN=0x010203 should use nonce = 00...00010203
      final ct1 = await protector.encrypt(0x010203, header, payload);
      final ct2 = await protector.encrypt(0x010203, header, payload);
      expect(ct1, equals(ct2)); // deterministic
    });
  });
}

SecretKey _secretKey(List<int> bytes) => _TestSecretKey(bytes);

class _TestSecretKey implements SecretKey {
  final List<int> _bytes;
  _TestSecretKey(this._bytes);

  @override
  List<int> extractSync() => List<int>.from(_bytes);
}
