/// Known varint encode/decode test cases from RFC 9000 §16 / Appendix A.1.
///
/// Each entry is a map with keys:
/// - `value`: the decoded integer (`int`)
/// - `bytes`: the encoded bytes (`List<int>`)
/// - `width`: the encoding width in bytes (1, 2, 4, or 8)
final List<Map<String, dynamic>> varintTestCases = [
  {
    'value': 0,
    'bytes': [0x00],
    'width': 1,
  },
  {
    'value': 1,
    'bytes': [0x01],
    'width': 1,
  },
  {
    'value': 63,
    'bytes': [0x3f],
    'width': 1,
  },
  {
    'value': 64,
    'bytes': [0x40, 0x40],
    'width': 2,
  },
  {
    'value': 16383,
    'bytes': [0x7f, 0xff],
    'width': 2,
  },
  {
    'value': 16384,
    'bytes': [0x80, 0x00, 0x40, 0x00],
    'width': 4,
  },
  {
    'value': 1073741823,
    'bytes': [0xbf, 0xff, 0xff, 0xff],
    'width': 4,
  },
  {
    'value': 1073741824,
    'bytes': [0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00],
    'width': 8,
  },
  {
    'value': 4611686018427387903, // 2^62 - 1
    'bytes': [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
    'width': 8,
  },
];
