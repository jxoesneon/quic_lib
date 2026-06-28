import 'dart:typed_data';

import 'package:quic_lib/src/crypto/cipher_suites.dart';
import 'package:quic_lib/src/crypto/default_crypto_backend.dart';
import 'package:quic_lib/src/crypto/initial_secrets.dart';
import 'package:quic_lib/src/crypto/key_manager.dart';
import 'package:quic_lib/src/crypto/session_ticket_store.dart';
import 'package:quic_lib/src/crypto/zero_rtt_helper.dart';
import 'package:quic_lib/src/recovery/packet_number_space.dart';
import 'package:test/test.dart';

void main() {
  group('KeyManager 0-RTT', () {
    late DefaultCryptoBackend backend;

    setUp(() {
      backend = DefaultCryptoBackend();
    });

    test('deriveZeroRtt produces keys for zeroRtt space', () async {
      final psk = SimpleSecretKey(Uint8List(32));
      final manager = await KeyManager.deriveZeroRtt(psk, backend);

      expect(manager.hasKeysFor(PacketNumberSpace.zeroRtt), isTrue);
      expect(manager.hasKeysFor(PacketNumberSpace.initial), isFalse);
      expect(manager.hasKeysFor(PacketNumberSpace.handshake), isFalse);
      expect(manager.hasKeysFor(PacketNumberSpace.application), isFalse);

      final keys = manager.keysFor(PacketNumberSpace.zeroRtt)!;
      expect(keys.protector, isNotNull);
      expect(keys.headerProtection, isNotNull);
    });

    test('discardZeroRttKeys removes zeroRtt keys', () async {
      final psk = SimpleSecretKey(Uint8List(32));
      final manager = await KeyManager.deriveZeroRtt(psk, backend);

      expect(manager.hasKeysFor(PacketNumberSpace.zeroRtt), isTrue);
      manager.discardZeroRttKeys();
      expect(manager.hasKeysFor(PacketNumberSpace.zeroRtt), isFalse);
    });
  });

  group('ZeroRttHelper', () {
    late DefaultCryptoBackend backend;

    setUp(() {
      backend = DefaultCryptoBackend();
    });

    test('deriveKeys produces key/iv/hpKey of correct lengths', () async {
      final psk = SimpleSecretKey(Uint8List(32));
      final result = await ZeroRttHelper.deriveKeys(
        psk: psk,
        keyLength: Aes128Gcm().keyLength,
        hpKeyLength: 16,
        backend: backend,
      );

      expect(result.key.length, equals(16));
      expect(result.iv.length, equals(12));
      expect(result.hpKey.length, equals(16));
    });
  });

  group('SessionTicketStore', () {
    test('stores and retrieves tickets', () {
      final store = SessionTicketStore();
      final psk = SimpleSecretKey(Uint8List(32));
      final expiry = DateTime.now().add(const Duration(hours: 1));

      store.store('ticket-1', psk, expiry);
      final retrieved = store.retrieve('ticket-1');

      expect(retrieved, isNotNull);
      expect(retrieved!.extractSync(), equals(psk.extractSync()));
    });

    test('evicts expired tickets on retrieve', () {
      final store = SessionTicketStore();
      final psk = SimpleSecretKey(Uint8List(32));
      final expiry = DateTime.now().subtract(const Duration(hours: 1));

      store.store('expired-ticket', psk, expiry);
      final retrieved = store.retrieve('expired-ticket');

      expect(retrieved, isNull);
      expect(store.validTicketIds, isEmpty);
    });

    test('validTicketIds excludes expired tickets', () {
      final store = SessionTicketStore();
      final validPsk = SimpleSecretKey(Uint8List(32));
      final expiredPsk = SimpleSecretKey(Uint8List(32));

      store.store(
          'valid', validPsk, DateTime.now().add(const Duration(hours: 1)));
      store.store('expired', expiredPsk,
          DateTime.now().subtract(const Duration(hours: 1)));

      expect(store.validTicketIds, equals(['valid']));
    });

    test('caps at max tickets and evicts oldest on overflow', () {
      final store = SessionTicketStore();

      for (var i = 0; i < SessionTicketStore.maxTickets; i++) {
        final psk = SimpleSecretKey(Uint8List(32));
        store.store(
            'ticket-$i', psk, DateTime.now().add(const Duration(hours: 1)));
      }

      expect(
          store.validTicketIds.length, equals(SessionTicketStore.maxTickets));
      expect(store.validTicketIds, contains('ticket-0'));

      // Store one more to trigger eviction of the oldest ('ticket-0').
      final newPsk = SimpleSecretKey(Uint8List(32));
      store.store(
          'ticket-new', newPsk, DateTime.now().add(const Duration(hours: 1)));

      expect(
          store.validTicketIds.length, equals(SessionTicketStore.maxTickets));
      expect(store.validTicketIds, isNot(contains('ticket-0')));
      expect(store.validTicketIds, contains('ticket-new'));
    });

    test('refreshing existing ticket moves it to newest', () {
      final store = SessionTicketStore();

      for (var i = 0; i < SessionTicketStore.maxTickets; i++) {
        final psk = SimpleSecretKey(Uint8List(32));
        store.store(
            'ticket-$i', psk, DateTime.now().add(const Duration(hours: 1)));
      }

      // Refresh 'ticket-0' so it becomes newest.
      final refreshedPsk = SimpleSecretKey(Uint8List(32));
      store.store('ticket-0', refreshedPsk,
          DateTime.now().add(const Duration(hours: 1)));

      // Add a new ticket; the oldest should now be 'ticket-1'.
      final newPsk = SimpleSecretKey(Uint8List(32));
      store.store(
          'ticket-new', newPsk, DateTime.now().add(const Duration(hours: 1)));

      expect(store.validTicketIds, contains('ticket-0'));
      expect(store.validTicketIds, isNot(contains('ticket-1')));
    });

    test('remove deletes a ticket', () {
      final store = SessionTicketStore();
      final psk = SimpleSecretKey(Uint8List(32));
      store.store(
          'ticket-a', psk, DateTime.now().add(const Duration(hours: 1)));

      store.remove('ticket-a');
      expect(store.retrieve('ticket-a'), isNull);
      expect(store.validTicketIds, isEmpty);
    });
  });
}
