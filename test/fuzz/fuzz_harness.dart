import 'dart:math';
import 'dart:typed_data';

import 'package:quic_lib/src/wire/varint.dart';
import 'package:quic_lib/src/wire/frame.dart';
import 'package:quic_lib/src/wire/coalesced_packet.dart';
import 'package:quic_lib/src/libp2p/multiaddr.dart';

/// Structured fuzzing harness for dart_quic.
///
/// Targets:
/// - VarInt encode/decode round-trip
/// - FrameCodec.parse with random bytes
/// - CoalescedPacket.split with random datagrams
/// - Multiaddr.parse with random strings
///
/// Run: dart test test/fuzz/fuzz_harness.dart
///
/// **Status:** Scaffold — basic fuzz targets implemented. CI integration
/// and corpus seeding are pending (Phase 4).
void main() {
  final random = Random.secure();
  const iterations = 10000;

  var varIntFailures = 0;
  var frameFailures = 0;
  var coalescedFailures = 0;
  var multiaddrFailures = 0;

  for (var i = 0; i < iterations; i++) {
    // --- VarInt fuzz ---
    try {
      final value = random.nextInt(0x3FFFFFFF);
      final encoded = VarInt.encode(value);
      final decoded = VarInt.decode(Uint8List.fromList(encoded).buffer);
      if (decoded != value) varIntFailures++;
    } catch (_) {
      frameFailures++; // encode should never throw for valid int
    }

    // --- FrameCodec fuzz ---
    try {
      final bytes = Uint8List(random.nextInt(256));
      for (var b = 0; b < bytes.length; b++) {
        bytes[b] = random.nextInt(256);
      }
      FrameCodec.parse(bytes, offset: 0);
    } catch (_) {
      // Parsing failure is expected for random bytes.
    }

    // --- CoalescedPacket fuzz ---
    try {
      final datagram = Uint8List(random.nextInt(2048));
      for (var b = 0; b < datagram.length; b++) {
        datagram[b] = random.nextInt(256);
      }
      CoalescedPacket.split(datagram);
    } catch (_) {
      coalescedFailures++;
    }

    // --- Multiaddr fuzz ---
    try {
      final parts = <String>['/'];
      final protocols = ['ip4', 'ip6', 'tcp', 'udp', 'quic', 'dns'];
      final count = random.nextInt(5) + 1;
      for (var j = 0; j < count; j++) {
        parts.add(protocols[random.nextInt(protocols.length)]);
        if (random.nextBool()) {
          parts.add('${random.nextInt(256)}.${random.nextInt(256)}');
        }
      }
      Multiaddr.parse(parts.join('/'));
    } catch (_) {
      // Parse failure is expected for random combinations.
    }
  }

  // Frame parsing is expected to throw for random input.
  // We only report unexpected outcomes.
  print('Fuzz results ($iterations iterations):');
  print('  VarInt mismatches: $varIntFailures');
  print('  Coalesced crashes: $coalescedFailures');
  print('  Multiaddr crashes: $multiaddrFailures');

  if (varIntFailures > 0) {
    throw StateError('VarInt round-trip produced $varIntFailures mismatches');
  }
}
