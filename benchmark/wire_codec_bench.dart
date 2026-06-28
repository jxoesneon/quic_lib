import 'dart:math';

import 'package:quic_lib/src/wire/varint.dart';
import 'package:quic_lib/src/wire/packet_header.dart';
import 'package:quic_lib/src/wire/frame.dart';
import 'package:quic_lib/src/wire/packet_builder.dart';

// Simple benchmark runner (no external deps)
Future<void> main() async {
  final rng = Random(42);

  // Benchmark 1: VarInt encode/decode
  await _benchmark('VarInt encode/decode', () async {
    for (var i = 0; i < 100000; i++) {
      final value = rng.nextInt(1 << 30);
      final encoded = VarInt.encode(value);
      VarInt.decode(encoded.buffer);
    }
  });

  // Benchmark 2: LongHeader serialize/parse
  _benchmark('LongHeader serialize/parse', () async {
    final header = LongHeader(
      version: 0x00000001,
      packetType: LongHeader.typeInitial,
      destinationConnectionId: [0, 1, 2, 3, 4, 5, 6, 7],
      sourceConnectionId: [8, 9, 10, 11, 12, 13, 14, 15],
      packetNumber: 42,
      payload: [],
      token: null,
    );
    for (var i = 0; i < 10000; i++) {
      final bytes = await header.serialize();
      PacketHeaderParser.parse(bytes, destinationConnectionIdLength: 8);
    }
  });

  // Benchmark 3: Frame serialize/parse
  await _benchmark('Frame serialize/parse', () async {
    final frame = StreamFrame(
      streamId: 4,
      data: [0x48, 0x65, 0x6c, 0x6c, 0x6f],
      offset: 0,
      fin: false,
      hasExplicitLength: true,
    );
    for (var i = 0; i < 10000; i++) {
      final bytes = frame.serialize();
      FrameCodec.parse(bytes);
    }
  });

  // Benchmark 4: PacketBuilder
  await _benchmark('PacketBuilder', () async {
    final header = LongHeader(
      version: 0x00000001,
      packetType: LongHeader.typeInitial,
      destinationConnectionId: [0, 1, 2, 3, 4, 5, 6, 7],
      sourceConnectionId: [8, 9, 10, 11, 12, 13, 14, 15],
      packetNumber: 42,
      payload: [],
      token: null,
    );
    final frames = [
      CryptoFrame(offset: 0, data: [0x16, 0x03, 0x01]),
      StreamFrame(
        streamId: 4,
        data: [0x48, 0x69],
        offset: 0,
        fin: false,
        hasExplicitLength: true,
      ),
    ];
    for (var i = 0; i < 5000; i++) {
      await PacketBuilder.build(header, frames);
    }
  });
}

Future<void> _benchmark(String name, Future<void> Function() fn) async {
  // Warmup
  for (var i = 0; i < 100; i++) {
    await fn();
  }
  // Measure
  final sw = Stopwatch()..start();
  await fn();
  sw.stop();
  print('$name: ${sw.elapsedMicroseconds} us');
}
