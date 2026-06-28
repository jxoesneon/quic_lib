import 'dart:typed_data';

import 'package:quic_lib/src/http3/frame_types.dart';
import 'package:quic_lib/src/utils/collections.dart';

/// HTTP/3 HEADERS frame payload.
///
/// RFC 9114 Section 7.2.2: the payload of a HEADERS frame contains a
/// QPACK-encoded field section.
class Http3HeadersFrame {
  /// The encoded field section (QPACK-encoded header block).
  final List<int> encodedFieldSection;

  Http3HeadersFrame({required this.encodedFieldSection});

  /// Build a complete Http3Frame of type HEADERS.
  Http3Frame toFrame() {
    return Http3Frame(
      type: Http3FrameType.headers,
      payload: Uint8List.fromList(encodedFieldSection),
    );
  }

  /// Parse from an Http3Frame payload.
  static Http3HeadersFrame fromPayload(List<int> payload) {
    return Http3HeadersFrame(encodedFieldSection: payload);
  }

  @override
  String toString() => 'Http3HeadersFrame(${encodedFieldSection.length} bytes)';

  @override
  bool operator ==(Object other) =>
      other is Http3HeadersFrame &&
      listEquals(other.encodedFieldSection, encodedFieldSection);

  @override
  int get hashCode => Object.hashAll(encodedFieldSection);
}
