import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:quic_lib/src/streams/flow_controller.dart';
import 'package:quic_lib/src/connection/connection_id_manager.dart';
import 'package:quic_lib/src/security/anti_amplification_limit.dart';
import 'package:quic_lib/src/crypto/session_ticket_store.dart';
import 'package:quic_lib/src/crypto/initial_secrets.dart';

/// Final hardening tests for boundary conditions and limit enforcement.
void main() {
  // ---------------------------------------------------------------------------
  // FlowController.maxWindow boundary tests
  // ---------------------------------------------------------------------------
  group('FlowController maxWindow boundary', () {
    test('updateLimit clamps to maxWindow when peer advertises more', () {
      final fc = FlowController(initialLimit: 1024);
      fc.updateLimit(FlowController.maxWindow + 1);
      expect(fc.availableWindow, equals(FlowController.maxWindow));
    });

    test('updateLimit at exactly maxWindow is accepted', () {
      final fc = FlowController(initialLimit: 1024);
      fc.updateLimit(FlowController.maxWindow);
      expect(fc.availableWindow, equals(FlowController.maxWindow));
    });

    test('shouldUpdateWindow caps next limit at maxWindow', () {
      final fc = FlowController(initialLimit: FlowController.maxWindow ~/ 2);
      fc.consume(FlowController.maxWindow ~/ 2);
      final newLimit = fc.shouldUpdateWindow(threshold: 0);
      expect(newLimit, equals(FlowController.maxWindow));
      // Second call should still return maxWindow
      fc.onLimitSent(FlowController.maxWindow);
      fc.consume(FlowController.maxWindow);
      final secondLimit = fc.shouldUpdateWindow(threshold: 0);
      expect(secondLimit, equals(FlowController.maxWindow));
    });

    test('consume up to maxWindow then isBlocked', () {
      final fc = FlowController(initialLimit: FlowController.maxWindow);
      fc.consume(FlowController.maxWindow);
      expect(fc.isBlocked, isTrue);
      expect(fc.availableWindow, equals(0));
    });
  });

  // ---------------------------------------------------------------------------
  // ConnectionIdManager maxActiveIds enforcement
  // ---------------------------------------------------------------------------
  group('ConnectionIdManager maxActiveIds enforcement', () {
    test('issueNewId throws at exactly maxActiveIds + 1', () {
      final manager = ConnectionIdManager();
      for (var i = 0; i < ConnectionIdManager.maxActiveIds; i++) {
        manager.issueNewId();
      }
      expect(
          manager.activeIds.length, equals(ConnectionIdManager.maxActiveIds));
      expect(() => manager.issueNewId(), throwsA(isA<StateError>()));
    });

    test('registerId throws at exactly maxActiveIds + 1', () {
      final manager = ConnectionIdManager();
      for (var i = 0; i < ConnectionIdManager.maxActiveIds; i++) {
        manager.registerId(
          connectionId: List<int>.filled(8, i),
          sequenceNumber: i,
          statelessResetToken: List<int>.filled(16, i),
        );
      }
      expect(
          () => manager.registerId(
                connectionId: List<int>.filled(8, 99),
                sequenceNumber: 99,
                statelessResetToken: List<int>.filled(16, 99),
              ),
          throwsA(isA<StateError>()));
    });

    test('retiring frees capacity for issueNewId', () {
      final manager = ConnectionIdManager();
      final records = <ConnectionIdRecord>[];
      for (var i = 0; i < ConnectionIdManager.maxActiveIds; i++) {
        final r = manager.issueNewId();
        records.add(r);
      }
      manager.retireId(records.first.sequenceNumber);
      expect(manager.activeIds.length,
          equals(ConnectionIdManager.maxActiveIds - 1));
      // Should now succeed
      final fresh = manager.issueNewId();
      expect(fresh.sequenceNumber, greaterThan(records.last.sequenceNumber));
    });

    test('issueNewId with retirePriorTo respects maxActiveIds', () {
      final manager = ConnectionIdManager();
      final records = <ConnectionIdRecord>[];
      for (var i = 0; i < ConnectionIdManager.maxActiveIds; i++) {
        records.add(manager.issueNewId());
      }
      // retirePriorTo should free slots before attempting to issue
      final fresh =
          manager.issueNewId(retirePriorTo: ConnectionIdManager.maxActiveIds);
      expect(fresh.sequenceNumber,
          greaterThanOrEqualTo(ConnectionIdManager.maxActiveIds));
      expect(manager.activeIds.length,
          lessThanOrEqualTo(ConnectionIdManager.maxActiveIds));
    });
  });

  // ---------------------------------------------------------------------------
  // AntiAmplificationLimit exact budget edge cases
  // ---------------------------------------------------------------------------
  group('AntiAmplificationLimit exact budget edge cases', () {
    test('budget exactly at 3x received minus sent', () {
      final limit = AntiAmplificationLimit();
      limit.onBytesReceived(50);
      limit.onBytesSent(100);
      // budget = 50*3 - 100 = 50
      expect(limit.sendBudget, equals(50));
      expect(limit.canSend(50), isTrue);
      expect(limit.canSend(51), isFalse);
    });

    test('1 byte over exact budget is denied', () {
      final limit = AntiAmplificationLimit();
      limit.onBytesReceived(33);
      limit.onBytesSent(99);
      // budget = 33*3 - 99 = 0
      expect(limit.sendBudget, equals(0));
      expect(limit.canSend(1), isFalse);
    });

    test('sending exactly the full 3x budget in one call', () {
      final limit = AntiAmplificationLimit();
      limit.onBytesReceived(100);
      expect(limit.canSend(300), isTrue);
      limit.onBytesSent(300);
      expect(limit.canSend(0), isTrue);
      expect(limit.canSend(1), isFalse);
    });

    test('budget never goes negative even when sent exceeds 3x', () {
      final limit = AntiAmplificationLimit();
      limit.onBytesReceived(10);
      limit.onBytesSent(100);
      expect(limit.sendBudget, equals(0));
    });

    test('after validation canSend returns true regardless of budget', () {
      final limit = AntiAmplificationLimit();
      limit.onBytesReceived(10);
      limit.onBytesSent(1000);
      expect(limit.canSend(1), isFalse);
      limit.validateAddress();
      expect(limit.canSend(1000000), isTrue);
    });
  });

  // ---------------------------------------------------------------------------
  // SessionTicketStore maxTickets enforcement
  // ---------------------------------------------------------------------------
  group('SessionTicketStore maxTickets enforcement', () {
    test('exactly maxTickets is allowed, maxTickets+1 evicts oldest', () {
      final store = SessionTicketStore();
      final base = DateTime.now().add(const Duration(hours: 1));

      for (var i = 0; i < SessionTicketStore.maxTickets; i++) {
        store.store('ticket-$i', SimpleSecretKey(Uint8List(32)), base);
      }
      expect(
          store.validTicketIds.length, equals(SessionTicketStore.maxTickets));

      // One more store evicts 'ticket-0'
      store.store('ticket-new', SimpleSecretKey(Uint8List(32)), base);
      expect(
          store.validTicketIds.length, equals(SessionTicketStore.maxTickets));
      expect(store.validTicketIds, isNot(contains('ticket-0')));
      expect(store.validTicketIds, contains('ticket-new'));
    });

    test('storing maxTickets then retrieving all leaves store empty', () {
      final store = SessionTicketStore();
      final base = DateTime.now().add(const Duration(hours: 1));

      for (var i = 0; i < SessionTicketStore.maxTickets; i++) {
        store.store('ticket-$i', SimpleSecretKey(Uint8List(32)), base);
      }
      expect(
          store.validTicketIds.length, equals(SessionTicketStore.maxTickets));

      for (var i = 0; i < SessionTicketStore.maxTickets; i++) {
        store.remove('ticket-$i');
      }
      expect(store.validTicketIds, isEmpty);
    });

    test('refreshing existing ticket at maxTickets does not grow beyond limit',
        () {
      final store = SessionTicketStore();
      final base = DateTime.now().add(const Duration(hours: 1));

      for (var i = 0; i < SessionTicketStore.maxTickets; i++) {
        store.store('ticket-$i', SimpleSecretKey(Uint8List(32)), base);
      }
      // Refresh the oldest (ticket-0) — store size stays at max
      store.store('ticket-0', SimpleSecretKey(Uint8List(32)), base);
      expect(
          store.validTicketIds.length, equals(SessionTicketStore.maxTickets));
    });

    test('expired tickets do not count toward maxTickets capacity', () {
      final store = SessionTicketStore();
      final future = DateTime.now().add(const Duration(hours: 1));
      final past = DateTime.now().subtract(const Duration(hours: 1));

      // Fill store with valid tickets
      for (var i = 0; i < SessionTicketStore.maxTickets; i++) {
        store.store('ticket-$i', SimpleSecretKey(Uint8List(32)), future);
      }

      // Replace one with expired — store size stays max but valid count drops
      store.store('ticket-expired', SimpleSecretKey(Uint8List(32)), past);
      expect(store.validTicketIds.length,
          equals(SessionTicketStore.maxTickets - 1));
    });
  });
}
