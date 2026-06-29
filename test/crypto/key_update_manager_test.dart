import 'package:test/test.dart';
import 'package:quic_lib/src/crypto/key_manager.dart';

void main() {
  group('KeyManager key update tracking', () {
    test('initial key phase is 0 and not pending', () {
      final km = KeyManager.forTest();
      expect(km.keyPhase, 0);
      expect(km.keyUpdatePending, isFalse);
    });

    test('onPacketSentWithCurrentKey returns false before limit', () {
      final km = KeyManager.forTest();
      expect(km.onPacketSentWithCurrentKey(1), isFalse);
      expect(km.onPacketSentWithCurrentKey(2), isFalse);
    });

    test('initiateKeyUpdate toggles phase and sets pending', () {
      final km = KeyManager.forTest();
      km.onPacketSentWithCurrentKey(1);
      km.onAckReceived(1);
      km.initiateKeyUpdate();
      expect(km.keyPhase, 1);
      expect(km.keyUpdatePending, isTrue);
    });

    test('confirmKeyUpdate clears pending', () {
      final km = KeyManager.forTest();
      km.onPacketSentWithCurrentKey(1);
      km.onAckReceived(1);
      km.initiateKeyUpdate();
      expect(km.keyUpdatePending, isTrue);
      km.confirmKeyUpdate();
      expect(km.keyUpdatePending, isFalse);
    });

    test('double initiate throws StateError', () {
      final km = KeyManager.forTest();
      km.onPacketSentWithCurrentKey(1);
      km.onAckReceived(1);
      km.initiateKeyUpdate();
      expect(() => km.initiateKeyUpdate(), throwsA(isA<StateError>()));
    });

    test('packet counter resets on key update', () {
      final km = KeyManager.forTest();
      for (var i = 0; i < 10; i++) {
        km.onPacketSentWithCurrentKey(i);
      }
      km.onAckReceived(9);
      km.initiateKeyUpdate();
      // After update, counter resets, so we shouldn't hit limit immediately.
      expect(km.onPacketSentWithCurrentKey(10), isFalse);
    });

    test(
        'initiateKeyUpdate throws if no ACK received for current key phase packets',
        () {
      final km = KeyManager.forTest();
      km.onPacketSentWithCurrentKey(1);
      // No ACK received for packet 1.
      expect(() => km.initiateKeyUpdate(), throwsA(isA<StateError>()));
    });

    test('onAckReceived allows subsequent key update when ACK covers sent packet',
        () {
      final km = KeyManager.forTest();
      km.onPacketSentWithCurrentKey(5);
      km.onAckReceived(3);
      // ACK does not cover packet 5 yet.
      expect(() => km.initiateKeyUpdate(), throwsA(isA<StateError>()));
      km.onAckReceived(5);
      // Now the key update is allowed.
      expect(() => km.initiateKeyUpdate(), returnsNormally);
    });

    test('onPacketSentWithCurrentKey returns true at AES-GCM confidentiality limit',
        () {
      final km = KeyManager.forTest();
      for (var i = 0; i < 0x800000 - 1; i++) {
        km.onPacketSentWithCurrentKey(i);
      }
      expect(km.onPacketSentWithCurrentKey(0x800000), isTrue);
    });

    test('onPacketSentWithCurrentKey uses ChaCha20 limit when requested', () {
      final km = KeyManager.forTest();
      // ChaCha20 limit is 2^36, so a large count below that should not trigger.
      for (var i = 0; i < 0x1000000; i++) {
        km.onPacketSentWithCurrentKey(i, isChaCha20: true);
      }
      expect(km.onPacketSentWithCurrentKey(0x1000000, isChaCha20: true),
          isFalse);
    });
  });
}
