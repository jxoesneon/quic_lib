import 'dart:typed_data';

import 'package:quic_lib/src/http3/data_frame.dart';
import 'package:quic_lib/src/http3/http3_connection.dart';

/// Extension methods on [Http3Connection] for body streaming.
extension Http3BodyStreaming on Http3Connection {
  /// Send a body chunk on [streamId] by injecting a DATA frame.
  ///
  /// In a full implementation this would queue the chunk on the QUIC
  /// send buffer; here it records the frame locally so that [getBody]
  /// can retrieve it.
  void sendBody(int streamId, Uint8List chunk) {
    final frame = Http3DataFrame(data: chunk).toFrame();
    onStreamFrame(streamId, frame);
  }

  /// Retrieve the concatenated body data for [streamId].
  ///
  /// Returns `null` if no DATA frames have been received for the stream.
  Uint8List? getBody(int streamId) {
    final frames = getPendingData(streamId);
    if (frames.isEmpty) {
      return null;
    }
    final builder = BytesBuilder();
    for (final f in frames) {
      builder.add(f.data);
    }
    return builder.takeBytes();
  }
}
