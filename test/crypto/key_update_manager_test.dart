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
      expect(km.onPacketSentWithCurrentKey(), isFalse);
      expect(km.onPacketSentWithCurrentKey(), isFalse);
    });

    test('initiateKeyUpdate toggles phase and sets pending', () {
      final km = KeyManager.forTest();
      km.initiateKeyUpdate();
      expect(km.keyPhase, 1);
      expect(km.keyUpdatePending, isTrue);
    });

    test('confirmKeyUpdate clears pending', () {
      final km = KeyManager.forTest();
      km.initiateKeyUpdate();
      expect(km.keyUpdatePending, isTrue);
      km.confirmKeyUpdate();
      expect(km.keyUpdatePending, isFalse);
    });

    test('double initiate throws StateError', () {
      final km = KeyManager.forTest();
      km.initiateKeyUpdate();
      expect(() => km.initiateKeyUpdate(), throwsA(isA<StateError>()));
    });

    test('packet counter resets on key update', () {
      final km = KeyManager.forTest();
      for (var i = 0; i < 10; i++) {
        km.onPacketSentWithCurrentKey();
      }
      km.initiateKeyUpdate();
      // After update, counter resets, so we shouldn't hit limit immediately.
      expect(km.onPacketSentWithCurrentKey(), isFalse);
    });
  });
}
