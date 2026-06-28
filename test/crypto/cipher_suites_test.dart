import 'package:quic_lib/src/crypto/cipher_suites.dart';
import 'package:test/test.dart';

void main() {
  group('Cipher suites', () {
    test('Aes128Gcm properties', () {
      final alg = Aes128Gcm();
      expect(alg.name, 'AES-128-GCM');
      expect(alg.keyLength, 16);
      expect(alg.nonceLength, 12);
      expect(alg.tagLength, 16);
    });

    test('Aes256Gcm properties', () {
      final alg = Aes256Gcm();
      expect(alg.name, 'AES-256-GCM');
      expect(alg.keyLength, 32);
      expect(alg.nonceLength, 12);
      expect(alg.tagLength, 16);
    });

    test('ChaCha20Poly1305 properties', () {
      final alg = ChaCha20Poly1305();
      expect(alg.name, 'ChaCha20-Poly1305');
      expect(alg.keyLength, 32);
      expect(alg.nonceLength, 12);
      expect(alg.tagLength, 16);
    });

    test('Sha256 properties', () {
      final alg = Sha256();
      expect(alg.name, 'SHA-256');
      expect(alg.hashLength, 32);
    });

    test('Sha384 properties', () {
      final alg = Sha384();
      expect(alg.name, 'SHA-384');
      expect(alg.hashLength, 48);
    });
  });
}
