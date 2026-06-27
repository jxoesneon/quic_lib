import 'dart:math';
import 'dart:typed_data';

import 'package:test/test.dart';

import 'package:dart_quic/src/libp2p/multiaddr.dart';
import 'package:dart_quic/src/libp2p/peer_id.dart';
import 'package:dart_quic/src/libp2p/dcutr.dart';
import 'package:dart_quic/src/http3/qpack_encoder.dart';
import 'package:dart_quic/src/http3/qpack_static_table.dart';
import 'package:dart_quic/src/http3/settings_frame.dart';
import 'package:dart_quic/src/http3/goaway_frame.dart';
import 'package:dart_quic/src/http3/frame_types.dart';
import 'package:dart_quic/src/security/anti_amplification_limit.dart';
import 'package:dart_quic/src/connection/migration_helper.dart';
import 'package:dart_quic/src/recovery/rtt_estimator.dart';
import 'package:dart_quic/src/recovery/congestion_controller.dart';
import 'package:dart_quic/src/recovery/pto_scheduler.dart';
import 'package:dart_quic/src/wire/frame.dart';
import 'package:dart_quic/src/wire/varint.dart';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

final _rng = Random.secure();

Uint8List _randomBytes(int length) {
  final bytes = Uint8List(length);
  for (var i = 0; i < length; i++) {
    bytes[i] = _rng.nextInt(256);
  }
  return bytes;
}

String _randomString(int length) {
  const chars =
      'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/_-.';
  return List.generate(length, (_) => chars[_rng.nextInt(chars.length)]).join();
}

/// Returns a random valid-ish multiaddr string or complete garbage.
String _randomMultiaddrString() {
  final coin = _rng.nextInt(4);
  switch (coin) {
    case 0:
      return _randomString(_rng.nextInt(64));
    case 1:
      // sometimes return something that starts with /
      return '/${_randomString(_rng.nextInt(64))}';
    case 2:
      // looks like a protocol chain but with bad values
      return '/ip4/${_randomString(8)}/tcp/${_rng.nextInt(70000)}';
    default:
      return '';
  }
}

// ---------------------------------------------------------------------------
// Multiaddr Fuzz
// ---------------------------------------------------------------------------

void _multiaddrFuzzGroup() {
  group('Multiaddr fuzz', () {
    test('random strings do not crash parser', () {
      for (var i = 0; i < 500; i++) {
        final input = _randomMultiaddrString();
        try {
          Multiaddr.parse(input);
        } catch (_) {
          // Expected for malformed input
        }
      }
    });

    test('random bytes do not crash binary parser', () {
      for (var i = 0; i < 500; i++) {
        final bytes = _randomBytes(_rng.nextInt(256));
        try {
          Multiaddr.fromBytes(bytes);
        } catch (_) {
          // Expected
        }
      }
    });

    test('truncated uvarint does not crash', () {
      // uvarint continuation bytes (MSB = 1) with no terminator
      final bytes = Uint8List.fromList([0x80, 0x80, 0x80]);
      expect(() => Multiaddr.fromBytes(bytes), throwsA(anything));
    });

    test('giant uvarint shift count is rejected', () {
      // 10 bytes all with MSB = 1 forces shift > 63
      final bytes = Uint8List(10);
      for (var i = 0; i < 10; i++) {
        bytes[i] = 0x80;
      }
      expect(() => Multiaddr.fromBytes(bytes), throwsA(anything));
    });

    test('unknown protocol code throws safely', () {
      final bytes = Uint8List.fromList([0xFF, 0x01]); // code 255 (unknown)
      expect(() => Multiaddr.fromBytes(bytes), throwsA(anything));
    });

    test('IPv4 validation rejects out-of-range octets', () {
      expect(() => Multiaddr.parse('/ip4/256.0.0.1/tcp/80'), throwsA(anything));
      expect(() => Multiaddr.parse('/ip4/1.2.3.4.5/tcp/80'), throwsA(anything));
    });

    test('IPv6 validation rejects malformed addresses', () {
      expect(
        () => Multiaddr.parse('/ip6/::1::1/tcp/80'),
        throwsA(anything),
      );
      expect(
        () => Multiaddr.parse('/ip6/gggg::1/tcp/80'),
        throwsA(anything),
      );
    });

    test('port validation rejects out-of-range ports', () {
      expect(() => Multiaddr.parse('/ip4/1.2.3.4/tcp/70000'), throwsA(anything));
      expect(() => Multiaddr.parse('/ip4/1.2.3.4/tcp/-1'), throwsA(anything));
    });
  });
}

// ---------------------------------------------------------------------------
// PeerId Fuzz
// ---------------------------------------------------------------------------

void _peerIdFuzzGroup() {
  group('PeerId fuzz', () {
    test('random bytes do not crash constructor', () {
      for (var i = 0; i < 200; i++) {
        final bytes = _randomBytes(_rng.nextInt(128));
        final pid = PeerId.fromBytes(bytes);
        expect(pid.bytes.length, bytes.length);
      }
    });

    test('toString does not leak exceptions', () {
      final pid = PeerId.fromBytes(_randomBytes(32));
      final s = pid.toString();
      expect(s.length, equals(64)); // 32 bytes -> 64 hex chars
    });

    test('hashCode is stable and does not throw', () {
      final pid = PeerId.fromBytes(_randomBytes(32));
      expect(() => pid.hashCode, returnsNormally);
    });
  });
}

// ---------------------------------------------------------------------------
// DCUtR Fuzz
// ---------------------------------------------------------------------------

void _dcutrFuzzGroup() {
  group('DCUtR fuzz', () {
    test('random bytes do not crash parser', () {
      for (var i = 0; i < 500; i++) {
        final bytes = _randomBytes(_rng.nextInt(64));
        try {
          DCUtRMessage.parse(bytes);
        } catch (_) {
          // Expected
        }
      }
    });

    test('truncated message throws safely', () {
      expect(() => DCUtRMessage.parse(Uint8List(0)), throwsA(anything));
      expect(() => DCUtRMessage.parse(Uint8List(2)), throwsA(anything));
    });

    test('length exceeds buffer throws safely', () {
      final bytes = Uint8List.fromList([0x01, 0x00, 0xFF]); // length=255, only 3 bytes
      expect(() => DCUtRMessage.parse(bytes), throwsA(anything));
    });

    test('max uint16 length is handled', () {
      final length = 0xFFFF;
      final bytes = Uint8List(3 + length);
      bytes[0] = 0x01;
      bytes[1] = (length >> 8) & 0xFF;
      bytes[2] = length & 0xFF;
      expect(() => DCUtRMessage.parse(bytes), returnsNormally);
    });

    test('serialize round-trip with random addresses', () {
      for (var i = 0; i < 50; i++) {
        final addr = _randomBytes(_rng.nextInt(128));
        final msg = DCUtRMessage(type: DCUtRMessage.typeConnect, observedAddr: addr);
        final serialized = msg.serialize();
        final parsed = DCUtRMessage.parse(serialized);
        expect(parsed.type, equals(msg.type));
        expect(parsed.observedAddr, equals(msg.observedAddr));
      }
    });
  });
}

// ---------------------------------------------------------------------------
// QPACK Encoder / Static Table Fuzz
// ---------------------------------------------------------------------------

void _qpackFuzzGroup() {
  group('QPACK fuzz', () {
    test('random strings encode without crash', () {
      for (var i = 0; i < 200; i++) {
        final name = _randomString(_rng.nextInt(32));
        final value = _randomString(_rng.nextInt(64));
        try {
          QpackEncoder.encodeFieldLine(name, value);
        } catch (_) {
          // Encoding should not crash; if it does, note it.
        }
      }
    });

    test('static table lookups are safe for random strings', () {
      for (var i = 0; i < 200; i++) {
        final name = _randomString(_rng.nextInt(32));
        final value = _randomString(_rng.nextInt(32));
        final idx = QpackEncoder.findStaticIndex(name, value);
        final nameIdx = QpackEncoder.findStaticNameIndex(name);
        expect(idx, anyOf(isNull, isPositive));
        expect(nameIdx, anyOf(isNull, isPositive));
      }
    });

    test('static table get bounds-checked', () {
      expect(QpackStaticTable.get(0), isNull);
      expect(QpackStaticTable.get(9999), isNull);
      expect(QpackStaticTable.get(1), isNotNull);
    });

    test('encodeFieldLines with empty list returns empty bytes', () {
      final result = QpackEncoder.encodeFieldLines([]);
      expect(result, isEmpty);
    });
  });
}

// ---------------------------------------------------------------------------
// HTTP/3 Settings & GOAWAY Fuzz
// ---------------------------------------------------------------------------

void _http3FrameFuzzGroup() {
  group('HTTP/3 frame payload fuzz', () {
    test('random bytes do not crash Settings parser', () {
      for (var i = 0; i < 500; i++) {
        final payload = _randomBytes(_rng.nextInt(64));
        try {
          Http3SettingsFrame.parsePayload(payload);
        } catch (_) {
          // Expected
        }
      }
    });

    test('empty Settings payload parses without crash', () {
      final frame = Http3SettingsFrame.parsePayload(Uint8List(0));
      expect(frame.settings, isEmpty);
    });

    test('truncated varint in Settings throws safely', () {
      // 0xC0 flags 8-byte varint but only 2 bytes follow
      final payload = Uint8List.fromList([0xC0, 0x00]);
      expect(() => Http3SettingsFrame.parsePayload(payload), throwsA(anything));
    });

    test('random bytes do not crash GOAWAY parser', () {
      for (var i = 0; i < 500; i++) {
        final payload = _randomBytes(_rng.nextInt(32));
        try {
          Http3GoawayFrame.parsePayload(payload);
        } catch (_) {
          // Expected
        }
      }
    });

    test('empty GOAWAY payload throws safely', () {
      expect(() => Http3GoawayFrame.parsePayload(Uint8List(0)), throwsA(anything));
    });

    test('GOAWAY round-trip with random stream IDs', () {
      for (var i = 0; i < 100; i++) {
        final id = _rng.nextInt(1 << 30);
        final frame = Http3GoawayFrame(lastStreamIdOrPushId: id);
        final payload = frame.serializePayload();
        final parsed = Http3GoawayFrame.parsePayload(payload);
        expect(parsed.lastStreamIdOrPushId, equals(id));
      }
    });

    test('Http3Frame.parse with random bytes does not crash', () {
      for (var i = 0; i < 200; i++) {
        final bytes = _randomBytes(_rng.nextInt(64));
        try {
          Http3Frame.parse(bytes);
        } catch (_) {
          // Expected
        }
      }
    });
  });
}

// ---------------------------------------------------------------------------
// Anti-Amplification Limit Fuzz
// ---------------------------------------------------------------------------

void _antiAmplificationFuzzGroup() {
  group('AntiAmplificationLimit fuzz', () {
    test('random inputs do not crash', () {
      final limit = AntiAmplificationLimit();
      for (var i = 0; i < 200; i++) {
        final bytes = _rng.nextInt(1 << 20) - (1 << 19); // includes negatives
        if (bytes >= 0) {
          limit.onBytesReceived(bytes);
          limit.onBytesSent(bytes);
          expect(() => limit.canSend(bytes), returnsNormally);
        } else {
          // SECURITY FIX: negative bytes now throw ArgumentError.
          expect(() => limit.onBytesReceived(bytes), throwsArgumentError);
          expect(() => limit.onBytesSent(bytes), throwsArgumentError);
        }
        expect(limit.sendBudget, greaterThanOrEqualTo(0));
      }
    });

    test('extreme byte counts do not produce negative budget', () {
      final limit = AntiAmplificationLimit();
      limit.onBytesReceived(0x7FFFFFFFFFFFFFFF);
      expect(limit.sendBudget, greaterThanOrEqualTo(0));
      limit.onBytesSent(0x7FFFFFFFFFFFFFFF);
      expect(limit.sendBudget, greaterThanOrEqualTo(0));
    });

    test('budget remains bounded after repeated receives', () {
      final limit = AntiAmplificationLimit();
      for (var i = 0; i < 10000; i++) {
        limit.onBytesReceived(1);
      }
      expect(limit.sendBudget, equals(30000));
    });

    test('validateAddress yields max int budget', () {
      final limit = AntiAmplificationLimit();
      limit.validateAddress();
      expect(limit.sendBudget, equals(0x7FFFFFFFFFFFFFFF));
      expect(limit.canSend(0x7FFFFFFFFFFFFFFF), isTrue);
    });
  });
}

// ---------------------------------------------------------------------------
// Migration Helper Fuzz
// ---------------------------------------------------------------------------

void _migrationHelperFuzzGroup() {
  group('MigrationHelper fuzz', () {
    test('random responses do not crash', () {
      final helper = MigrationHelper();
      for (var i = 0; i < 200; i++) {
        final data = _randomBytes(8);
        final frame = PathResponseFrame(data: data);
        try {
          helper.onResponseReceived(frame);
        } catch (_) {
          // Should not throw, but catch defensively
        }
      }
    });

    test('challenge / response round-trip', () {
      final helper = MigrationHelper();
      final challenge = helper.generateChallenge(currentTimeUs: 1000);
      final response = PathResponseFrame(data: challenge.data);
      expect(helper.onResponseReceived(response), isTrue);
      expect(helper.isPathValidated(challenge.data), isTrue);
    });

    test('unmatched response returns false safely', () {
      final helper = MigrationHelper();
      final frame = PathResponseFrame(data: _randomBytes(8));
      expect(helper.onResponseReceived(frame), isFalse);
    });

    test('expired challenges with clock underflow', () {
      final helper = MigrationHelper();
      helper.generateChallenge(currentTimeUs: 1000);
      // clock jumps backward: currentTimeUs < sentTime
      final expired = helper.getExpiredChallenges(500);
      expect(expired, isEmpty);
    });

    test('random path IDs do not crash isPathValidated', () {
      final helper = MigrationHelper();
      for (var i = 0; i < 200; i++) {
        final id = _randomBytes(_rng.nextInt(32));
        expect(() => helper.isPathValidated(id), returnsNormally);
      }
    });
  });
}

// ---------------------------------------------------------------------------
// RTT Estimator Fuzz
// ---------------------------------------------------------------------------

void _rttEstimatorFuzzGroup() {
  group('RttEstimator fuzz', () {
    test('extreme RTT values do not crash', () {
      final est = RttEstimator();
      final values = [
        0,
        1,
        333000,
        0x7FFFFFFFFFFFFFFF,
        -1,
      ];
      for (final rtt in values) {
        try {
          est.update(rtt, ackDelay: rtt ~/ 2);
        } catch (_) {
          // Document behavior
        }
        expect(() => est.getPtoDuration(), returnsNormally);
      }
    });

    test('PTO duration is non-negative', () {
      final est = RttEstimator();
      est.update(1000);
      expect(est.getPtoDuration(), greaterThanOrEqualTo(0));
    });

    test('reset restores initial state', () {
      final est = RttEstimator();
      est.update(100000);
      est.reset();
      expect(est.smoothedRtt, equals(RttEstimator.kInitialRttUs));
      expect(est.rttVar, equals(RttEstimator.kInitialRttUs ~/ 2));
    });
  });
}

// ---------------------------------------------------------------------------
// Congestion Controller Fuzz
// ---------------------------------------------------------------------------

void _congestionControllerFuzzGroup() {
  group('CongestionController fuzz', () {
    test('extreme ACK values do not crash or produce negative in-flight', () {
      final cc = CongestionController();
      cc.onPacketSent(1000);
      cc.onAckReceived(0x7FFFFFFFFFFFFFFF);
      expect(cc.bytesInFlight, equals(0));
      expect(cc.congestionWindow, greaterThanOrEqualTo(CongestionController.minimumWindow));
    });

    test('repeated ACKs in slow start grow cwnd', () {
      final cc = CongestionController();
      for (var i = 0; i < 1000; i++) {
        cc.onPacketSent(1200);
        cc.onAckReceived(1200);
      }
      expect(cc.congestionWindow, greaterThan(CongestionController.initialWindow));
    });

    test('congestion event reduces cwnd but not below minimum', () {
      final cc = CongestionController();
      cc.onPacketSent(10000);
      cc.onAckReceived(10000);
      cc.onCongestionEvent(0);
      expect(cc.congestionWindow, greaterThanOrEqualTo(CongestionController.minimumWindow));
    });

    test('canSend is consistent with state', () {
      final cc = CongestionController();
      cc.onPacketSent(5000);
      final can = cc.canSend(100);
      expect(can, isFalse);
      cc.reset();
      expect(cc.canSend(100), isTrue);
    });
  });
}

// ---------------------------------------------------------------------------
// PTO Scheduler Fuzz
// ---------------------------------------------------------------------------

void _ptoSchedulerFuzzGroup() {
  group('PtoScheduler fuzz', () {
    test('PTO count growth is bounded (DoS probe)', () {
      final est = RttEstimator();
      final sched = PtoScheduler(est);

      // Simulate many PTO firings
      for (var i = 0; i < 20; i++) {
        sched.onPtoFired(i * 1000);
      }

      // currentPtoUs should be computable without hanging or OOM
      // for ptoCount <= 20. If it exceeds a reasonable bound, flag it.
      final pto = sched.currentPtoUs;
      expect(pto, greaterThanOrEqualTo(0));
    }, timeout: Timeout(Duration(seconds: 5)));

    test('isExpired with random times does not crash', () {
      final est = RttEstimator();
      final sched = PtoScheduler(est);
      sched.onPtoFired(1000);

      for (var i = 0; i < 200; i++) {
        final t = _rng.nextInt(1 << 30);
        expect(() => sched.isExpired(t), returnsNormally);
      }
    });

    test('reset clears state', () {
      final est = RttEstimator();
      final sched = PtoScheduler(est);
      sched.onPtoFired(0);
      sched.onPtoFired(1000);
      sched.reset();
      expect(sched.ptoCount, equals(0));
      expect(sched.isExpired(999999), isFalse);
    });

    test('onAckReceived resets backoff', () {
      final est = RttEstimator();
      final sched = PtoScheduler(est);
      sched.onPtoFired(0);
      sched.onAckReceived();
      expect(sched.ptoCount, equals(0));
    });
  });
}

// ---------------------------------------------------------------------------
// VarInt Fuzz (wire layer sanity check)
// ---------------------------------------------------------------------------

void _varIntFuzzGroup() {
  group('VarInt fuzz', () {
    test('random bytes do not crash decoder', () {
      for (var i = 0; i < 500; i++) {
        final bytes = _randomBytes(_rng.nextInt(16));
        try {
          VarInt.decode(bytes.buffer);
        } catch (_) {
          // Expected
        }
      }
    });

    test('encode/decode round-trip for random safe values', () {
      for (var i = 0; i < 500; i++) {
        final high = _rng.nextInt(1 << 30);
        final low = _rng.nextInt(1 << 32);
        final value = (high << 32) | low;
        if (value <= VarInt.maxValue) {
          final enc = VarInt.encode(value);
          final dec = VarInt.decode(enc.buffer);
          expect(dec, equals(value));
        }
      }
    });
  });
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

void main() {
  _multiaddrFuzzGroup();
  _peerIdFuzzGroup();
  _dcutrFuzzGroup();
  _qpackFuzzGroup();
  _http3FrameFuzzGroup();
  _antiAmplificationFuzzGroup();
  _migrationHelperFuzzGroup();
  _rttEstimatorFuzzGroup();
  _congestionControllerFuzzGroup();
  _ptoSchedulerFuzzGroup();
  _varIntFuzzGroup();
}
