import 'dart:typed_data';

import 'package:dart_quic/src/http3/frame_types.dart';

/// HTTP/3 DATA frame payload.
///
/// RFC 9114 Section 7.2.1: the payload of a DATA frame consists of a sequence
/// of octets. The DATA frame (type=0x00) carries content of a message.
class Http3DataFrame {
  /// The raw data octets carried by this frame.
  final List<int> data;

  Http3DataFrame({required this.data});

  /// Build a complete Http3Frame of type DATA.
  Http3Frame toFrame() {
    return Http3Frame(
      type: Http3FrameType.data,
      payload: Uint8List.fromList(data),
    );
  }

  /// Parse from an Http3Frame payload.
  static Http3DataFrame fromPayload(List<int> payload) {
    return Http3DataFrame(data: payload);
  }

  /// Empty data frame.
  static Http3DataFrame empty() {
    return Http3DataFrame(data: []);
  }

  @override
  String toString() => 'Http3DataFrame(${data.length} bytes)';

  @override
  bool operator ==(Object other) =>
      other is Http3DataFrame && _listsEqual(other.data, data);

  @override
  int get hashCode => Object.hashAll(data);

  static bool _listsEqual(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}
