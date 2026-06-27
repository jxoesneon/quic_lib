import 'dart:typed_data';

import 'package:dart_quic/src/connection/connection_state_machine.dart';
import 'package:dart_quic/src/connection/connection_id_manager.dart';
import 'package:dart_quic/src/crypto/crypto_backend.dart';
import 'package:dart_quic/src/crypto/default_crypto_backend.dart';
import 'package:dart_quic/src/crypto/initial_secrets.dart';
import 'package:dart_quic/src/recovery/packet_number_space.dart';
import 'package:dart_quic/src/wire/varint.dart';
import 'package:dart_quic/src/wire/frame.dart';

/// Benchmark harness for dart_quic performance regression testing.
///
/// Targets:
/// - VarInt encode/decode throughput
/// - ConnectionIdManager issueNewId latency
/// - InitialSecrets derivation latency
/// - FrameCodec.parse throughput
///
/// Run: dart run test/benchmark/benchmark_harness.dart
///
/// **Status:** Scaffold — basic micro-benchmarks. CI integration and
/// historical trending are pending (Phase 4).
void main() async {
  const iterations = 100000;
  const cidIterations = 10000;
  const secretIterations = 100;

  // --- VarInt benchmark ---
  final varIntStart = DateTime.now().millisecondsSinceEpoch;
  for (var i = 0; i < iterations; i++) {
    final encoded = VarInt.encode(i % 0x3FFFFFFF);
    VarInt.decode(Uint8List.fromList(encoded).buffer);
  }
  final varIntMs = DateTime.now().millisecondsSinceEpoch - varIntStart;
  print('VarInt encode/decode: ${iterations / (varIntMs / 1000)} ops/sec');

  // --- CID Manager benchmark ---
  final cidStart = DateTime.now().millisecondsSinceEpoch;
  for (var i = 0; i < cidIterations; i++) {
    // Create a fresh manager each iteration to avoid maxActiveIds cap.
    final cidManager = ConnectionIdManager();
    cidManager.issueNewId();
  }
  final cidMs = DateTime.now().millisecondsSinceEpoch - cidStart;
  print('CID issue: ${cidIterations / (cidMs / 1000)} ops/sec');

  // --- InitialSecrets benchmark ---
  final backend = DefaultCryptoBackend();
  final dcid = List<int>.generate(8, (i) => i);
  final secretStart = DateTime.now().millisecondsSinceEpoch;
  for (var i = 0; i < secretIterations; i++) {
    await InitialSecrets.derive(dcid, backend: backend);
  }
  final secretMs = DateTime.now().millisecondsSinceEpoch - secretStart;
  print('InitialSecrets derive: ${secretIterations / (secretMs / 1000)} ops/sec');

  // --- FrameCodec benchmark ---
  final sampleFrame = AckFrame(
    largestAcknowledged: 42,
    ackDelay: 0,
    ackRanges: [],
  );
  final frameBytes = sampleFrame.serialize();
  final frameStart = DateTime.now().millisecondsSinceEpoch;
  for (var i = 0; i < iterations; i++) {
    FrameCodec.parse(frameBytes, offset: 0);
  }
  final frameMs = DateTime.now().millisecondsSinceEpoch - frameStart;
  print('FrameCodec.parse (ACK): ${iterations / (frameMs / 1000)} ops/sec');

  // --- PacketNumberSpace benchmark ---
  final pnManager = PacketNumberSpaceManager();
  final pnStart = DateTime.now().millisecondsSinceEpoch;
  for (var i = 0; i < iterations; i++) {
    pnManager.allocate(PacketNumberSpace.application);
  }
  final pnMs = DateTime.now().millisecondsSinceEpoch - pnStart;
  print('PN allocate: ${iterations / (pnMs / 1000)} ops/sec');

  print('\nAll benchmarks completed.');
}
