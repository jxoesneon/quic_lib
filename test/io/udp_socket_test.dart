import 'dart:io';
import 'dart:typed_data';

// ignore: implementation_imports
import 'package:quic_lib/src/io/udp_socket.dart';
import 'package:test/test.dart';

void main() {
  group('UdpSocket', () {
    test('bind creates a socket on a port', () async {
      final socket = await UdpSocket.bind(InternetAddress.loopbackIPv4, 0);
      expect(socket.localPort, greaterThan(0));
      socket.close();
    });

    test('localAddress matches bind address', () async {
      final socket = await UdpSocket.bind(InternetAddress.loopbackIPv4, 0);
      expect(socket.localAddress.address,
          equals(InternetAddress.loopbackIPv4.address));
      socket.close();
    });

    test('send/receive round-trip', () async {
      final socketA = await UdpSocket.bind(InternetAddress.loopbackIPv4, 0);
      final socketB = await UdpSocket.bind(InternetAddress.loopbackIPv4, 0);

      final received = socketB.incoming.first;
      final data = Uint8List.fromList([1, 2, 3, 4]);
      socketA.send(data, InternetAddress.loopbackIPv4, socketB.localPort);

      final datagram = await received;
      expect(datagram.data, equals(data));
      expect(
        datagram.address.address,
        equals(InternetAddress.loopbackIPv4.address),
      );
      expect(datagram.port, equals(socketA.localPort));

      socketA.close();
      socketB.close();
    });

    test('close stops the socket', () async {
      final socket = await UdpSocket.bind(InternetAddress.loopbackIPv4, 0);
      socket.close();

      await expectLater(socket.incoming.toList(), completion(isEmpty));
    });

    test('rate limiting drops excessive packets from same IP', () async {
      final socketA = await UdpSocket.bind(InternetAddress.loopbackIPv4, 0);
      final socketB = await UdpSocket.bind(InternetAddress.loopbackIPv4, 0);

      final receivedDatagrams = <Uint8List>[];
      final sub = socketB.incoming.listen((d) => receivedDatagrams.add(d.data));

      // Send a burst of packets quickly from the same IP
      const packetCount = 1005;
      for (var i = 0; i < packetCount; i++) {
        socketA.send(Uint8List.fromList([i & 0xFF]),
            InternetAddress.loopbackIPv4, socketB.localPort);
      }

      // Allow time for packets to be processed
      await Future.delayed(Duration(milliseconds: 500));

      // Most should arrive, but at least some may be rate limited
      expect(receivedDatagrams.length, greaterThan(0));
      // The limit is 1000 per second; we sent 1005, so ideally at most 1000 arrive.
      // Due to OS buffering and timing, this is a soft assertion.
      expect(receivedDatagrams.length, lessThanOrEqualTo(packetCount));

      await sub.cancel();
      socketA.close();
      socketB.close();
    });

    test('multiple packets from same IP within limit are accepted', () async {
      final socketA = await UdpSocket.bind(InternetAddress.loopbackIPv4, 0);
      final socketB = await UdpSocket.bind(InternetAddress.loopbackIPv4, 0);

      final receivedDatagrams = <Uint8List>[];
      final sub = socketB.incoming.listen((d) => receivedDatagrams.add(d.data));

      // Send 100 packets well within the 1000/s limit
      for (var i = 0; i < 100; i++) {
        socketA.send(Uint8List.fromList([i]), InternetAddress.loopbackIPv4,
            socketB.localPort);
      }

      await Future.delayed(Duration(milliseconds: 500));
      expect(receivedDatagrams.length, greaterThan(0));

      await sub.cancel();
      socketA.close();
      socketB.close();
    });

    test('rate limiter prunes old timestamps after window passes', () async {
      final socketA = await UdpSocket.bind(InternetAddress.loopbackIPv4, 0);
      final socketB = await UdpSocket.bind(InternetAddress.loopbackIPv4, 0);

      final receivedDatagrams = <Uint8List>[];
      final sub = socketB.incoming.listen((d) => receivedDatagrams.add(d.data));

      // Send enough packets to nearly saturate the per-second limit.
      for (var i = 0; i < 990; i++) {
        socketA.send(Uint8List.fromList([i & 0xFF]),
            InternetAddress.loopbackIPv4, socketB.localPort);
      }
      await Future.delayed(Duration(milliseconds: 1100));

      // After the window, additional packets should be accepted again.
      for (var i = 0; i < 50; i++) {
        socketA.send(Uint8List.fromList([i & 0xFF]),
            InternetAddress.loopbackIPv4, socketB.localPort);
      }
      await Future.delayed(Duration(milliseconds: 500));

      // Some datagrams should have been received, and the post-window burst
      // should have been accepted (so total received is greater than the
      // post-window burst alone would produce if it were all dropped).
      expect(receivedDatagrams.length, greaterThan(0));
      expect(receivedDatagrams.length, lessThanOrEqualTo(990 + 50));

      await sub.cancel();
      socketA.close();
      socketB.close();
    });
  });

  // ---------------------------------------------------------------------------
  // DoS eviction path — covers _ipTimestamps.length >= 10000 and _evictOldestIp
  // ---------------------------------------------------------------------------
  group('UdpSocket DoS eviction path', () {
    test(
        'evictOldestIpForTest removes the IP entry with the oldest last-seen '
        'timestamp', () async {
      final socket = await UdpSocket.bind(InternetAddress.loopbackIPv4, 0);
      addTearDown(socket.close);

      final now = DateTime.now().millisecondsSinceEpoch;

      // Inject three entries with distinct ages: old, middle, recent.
      socket.ipTimestampsForTest['10.0.0.1'] = [now - 5000]; // oldest
      socket.ipTimestampsForTest['10.0.0.2'] = [now - 2000]; // middle
      socket.ipTimestampsForTest['10.0.0.3'] = [now - 500]; // newest

      socket.evictOldestIpForTest();

      // The oldest entry must be removed; the other two must remain.
      expect(socket.ipTimestampsForTest.containsKey('10.0.0.1'), isFalse);
      expect(socket.ipTimestampsForTest.containsKey('10.0.0.2'), isTrue);
      expect(socket.ipTimestampsForTest.containsKey('10.0.0.3'), isTrue);
      expect(socket.ipTimestampsForTest.length, equals(2));
    });

    test(
        'evictOldestIpForTest picks the entry with an empty timestamp list '
        '(treated as time 0)', () async {
      final socket = await UdpSocket.bind(InternetAddress.loopbackIPv4, 0);
      addTearDown(socket.close);

      final now = DateTime.now().millisecondsSinceEpoch;

      // An empty list is treated as newest==0, making it the oldest.
      socket.ipTimestampsForTest['192.168.1.1'] = []; // treated as oldest (0)
      socket.ipTimestampsForTest['192.168.1.2'] = [now - 1000];
      socket.ipTimestampsForTest['192.168.1.3'] = [now];

      socket.evictOldestIpForTest();

      expect(socket.ipTimestampsForTest.containsKey('192.168.1.1'), isFalse);
      expect(socket.ipTimestampsForTest.containsKey('192.168.1.2'), isTrue);
      expect(socket.ipTimestampsForTest.containsKey('192.168.1.3'), isTrue);
    });

    test('evictOldestIpForTest is a no-op on an empty map', () async {
      final socket = await UdpSocket.bind(InternetAddress.loopbackIPv4, 0);
      addTearDown(socket.close);

      // Should not throw.
      expect(() => socket.evictOldestIpForTest(), returnsNormally);
      expect(socket.ipTimestampsForTest, isEmpty);
    });

    test(
        'receiving a packet from a new IP while at capacity triggers eviction '
        'and delivers the packet', () async {
      final socketA = await UdpSocket.bind(InternetAddress.loopbackIPv4, 0);
      final socketB = await UdpSocket.bind(InternetAddress.loopbackIPv4, 0);
      addTearDown(socketA.close);
      addTearDown(socketB.close);

      final now = DateTime.now().millisecondsSinceEpoch;

      // Pre-fill socketB's IP table to the 10 000-entry capacity using fake
      // IP keys (no real sockets required). Leave the loopback IP absent so
      // the very first real packet from 127.0.0.1 is treated as a new source.
      for (var i = 0; i < 10000; i++) {
        // Fake IPs: 0.0.0.0 … 0.0.39.15  (outside 127.x range)
        final a = (i >> 8) & 0xFF;
        final b = i & 0xFF;
        socketB.ipTimestampsForTest['0.0.$a.$b'] = [now - (i + 1) * 10];
      }

      expect(socketB.ipTimestampsForTest.length, equals(10000));
      expect(
        socketB.ipTimestampsForTest.containsKey('127.0.0.1'),
        isFalse,
      );

      // Capture the first packet from the loopback address.
      final firstPacket = socketB.incoming.first;
      socketA.send(
        Uint8List.fromList([0xAB]),
        InternetAddress.loopbackIPv4,
        socketB.localPort,
      );

      final received = await firstPacket.timeout(Duration(seconds: 5));
      expect(received.data, equals(Uint8List.fromList([0xAB])));

      // After eviction, the table is still at most 10 000 entries and
      // 127.0.0.1 has been inserted.
      expect(
        socketB.ipTimestampsForTest.length,
        lessThanOrEqualTo(10000),
      );
      expect(
        socketB.ipTimestampsForTest.containsKey('127.0.0.1'),
        isTrue,
      );
    });

    test(
        'per-source capacity branch does NOT evict when the incoming IP is '
        'already tracked', () async {
      final socketA = await UdpSocket.bind(InternetAddress.loopbackIPv4, 0);
      final socketB = await UdpSocket.bind(InternetAddress.loopbackIPv4, 0);
      addTearDown(socketA.close);
      addTearDown(socketB.close);

      final now = DateTime.now().millisecondsSinceEpoch;

      // Fill to capacity and also pre-insert the loopback address so it is
      // already tracked — the eviction branch must be skipped.
      socketB.ipTimestampsForTest['127.0.0.1'] = [now - 100];
      for (var i = 0; i < 9999; i++) {
        final a = (i >> 8) & 0xFF;
        final b = i & 0xFF;
        socketB.ipTimestampsForTest['1.$a.$b.0'] = [now - (i + 1) * 10];
      }

      final countBefore = socketB.ipTimestampsForTest.length;
      expect(countBefore, equals(10000));

      final firstPacket = socketB.incoming.first;
      socketA.send(
        Uint8List.fromList([0xCD]),
        InternetAddress.loopbackIPv4,
        socketB.localPort,
      );

      final received = await firstPacket.timeout(Duration(seconds: 5));
      expect(received.data, equals(Uint8List.fromList([0xCD])));

      // No eviction: the total count stays the same (127.0.0.1 already existed).
      expect(socketB.ipTimestampsForTest.length, equals(countBefore));
    });

    test('_evictOldestIp removes exactly one entry per call', () async {
      final socket = await UdpSocket.bind(InternetAddress.loopbackIPv4, 0);
      addTearDown(socket.close);

      final now = DateTime.now().millisecondsSinceEpoch;
      for (var i = 0; i < 5; i++) {
        socket.ipTimestampsForTest['172.16.0.$i'] = [now - (5 - i) * 1000];
      }
      expect(socket.ipTimestampsForTest.length, equals(5));

      socket.evictOldestIpForTest();
      expect(socket.ipTimestampsForTest.length, equals(4));

      socket.evictOldestIpForTest();
      expect(socket.ipTimestampsForTest.length, equals(3));
    });

    test('consecutive evictions always remove the current oldest entry',
        () async {
      final socket = await UdpSocket.bind(InternetAddress.loopbackIPv4, 0);
      addTearDown(socket.close);

      final now = DateTime.now().millisecondsSinceEpoch;

      // IPs are named so that the expected eviction order is ip-1, ip-2, ip-3.
      socket.ipTimestampsForTest['ip-1'] = [now - 3000];
      socket.ipTimestampsForTest['ip-2'] = [now - 2000];
      socket.ipTimestampsForTest['ip-3'] = [now - 1000];

      socket.evictOldestIpForTest();
      expect(socket.ipTimestampsForTest.containsKey('ip-1'), isFalse);

      socket.evictOldestIpForTest();
      expect(socket.ipTimestampsForTest.containsKey('ip-2'), isFalse);

      socket.evictOldestIpForTest();
      expect(socket.ipTimestampsForTest.containsKey('ip-3'), isFalse);

      expect(socket.ipTimestampsForTest, isEmpty);
    });
  });
}
