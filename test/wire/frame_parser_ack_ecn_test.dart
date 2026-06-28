import 'package:test/test.dart';
import 'package:quic_lib/src/wire/frame.dart';

void main() {
  group('FrameCodec.parse ACK_ECN frames', () {
    test('parses ACK_ECN with no extra ranges', () {
      final frame = AckEcnFrame(
        largestAcknowledged: 200,
        ackDelay: 20,
        ackRanges: [],
        ect0Count: 1,
        ect1Count: 2,
        ceCount: 3,
      );
      final bytes = frame.serialize();
      final (parsed, nextOffset) = FrameCodec.parse(bytes);
      expect(parsed, isA<AckEcnFrame>());
      final ackEcn = parsed as AckEcnFrame;
      expect(ackEcn.largestAcknowledged, 200);
      expect(ackEcn.ackDelay, 20);
      expect(ackEcn.ackRanges, isEmpty);
      expect(ackEcn.ect0Count, 1);
      expect(ackEcn.ect1Count, 2);
      expect(ackEcn.ceCount, 3);
      expect(nextOffset, bytes.length);
    });

    test('parses ACK_ECN with extra ranges', () {
      final frame = AckEcnFrame(
        largestAcknowledged: 500,
        ackDelay: 50,
        ackRanges: [
          AckRange(gap: 0, length: 10),
          AckRange(gap: 5, length: 20),
          AckRange(gap: 3, length: 15),
        ],
        ect0Count: 100,
        ect1Count: 200,
        ceCount: 300,
      );
      final bytes = frame.serialize();
      final (parsed, nextOffset) = FrameCodec.parse(bytes);
      expect(parsed, isA<AckEcnFrame>());
      final ackEcn = parsed as AckEcnFrame;
      expect(ackEcn.largestAcknowledged, 500);
      expect(ackEcn.ackDelay, 50);
      expect(ackEcn.ackRanges.length, 3);
      expect(ackEcn.ackRanges[0].gap, 0);
      expect(ackEcn.ackRanges[0].length, 10);
      expect(ackEcn.ackRanges[1].gap, 5);
      expect(ackEcn.ackRanges[1].length, 20);
      expect(ackEcn.ackRanges[2].gap, 3);
      expect(ackEcn.ackRanges[2].length, 15);
      expect(ackEcn.ect0Count, 100);
      expect(ackEcn.ect1Count, 200);
      expect(ackEcn.ceCount, 300);
      expect(nextOffset, bytes.length);
    });

    test('parses ACK_ECN with zero ECN counts', () {
      final frame = AckEcnFrame(
        largestAcknowledged: 1,
        ackDelay: 0,
        ackRanges: [AckRange(gap: 0, length: 1)],
      );
      final bytes = frame.serialize();
      final (parsed, nextOffset) = FrameCodec.parse(bytes);
      expect(parsed, isA<AckEcnFrame>());
      final ackEcn = parsed as AckEcnFrame;
      expect(ackEcn.ect0Count, 0);
      expect(ackEcn.ect1Count, 0);
      expect(ackEcn.ceCount, 0);
      expect(nextOffset, bytes.length);
    });
  });
}
