/// The single hex encoding used throughout this library.
library;

import 'dart:typed_data';

/// Lowercase, fixed-width hexadecimal encoding.
///
/// Every hex string this library emits or accepts goes through here, so that
/// there is exactly one definition of what "hex" means: two lowercase digits
/// per byte, no prefix, no separators, no whitespace.
///
/// Malformed input throws [FormatException]. This is deliberate — it is the
/// same exception `webcrypto` raises for a byte string that is well formed
/// but not a valid key, so callers can catch one type for every kind of
/// bad encoding.
class HexCodec {
  const HexCodec._();

  static final RegExp _hexPattern = RegExp(r'^[0-9a-fA-F]*$');

  /// Encode [bytes] as lowercase hex.
  ///
  /// The result is always exactly `bytes.length * 2` characters; bytes below
  /// 0x10 are zero-padded rather than emitted as a single digit.
  static String encode(Uint8List bytes) {
    final StringBuffer buffer = StringBuffer();
    for (final int byte in bytes) {
      buffer.write(byte.toRadixString(16).padLeft(2, '0'));
    }
    return buffer.toString();
  }

  /// Decode [hex] into bytes, requiring exactly [expectedLength] characters.
  ///
  /// [expectedLength] is a character count, not a byte count. Uppercase input
  /// is accepted even though [encode] never produces it.
  ///
  /// Throws [FormatException] if the length is wrong, if the length is odd,
  /// or if any character is not a hex digit.
  static Uint8List decode(String hex, {required int expectedLength}) {
    if (hex.length != expectedLength) {
      throw FormatException(
        'Hex must be exactly $expectedLength characters (got ${hex.length})',
      );
    }

    if (expectedLength.isOdd) {
      throw FormatException(
        'Hex length must be even (got $expectedLength)',
      );
    }

    if (!_hexPattern.hasMatch(hex)) {
      throw const FormatException('Hex contains non-hexadecimal characters');
    }

    final Uint8List bytes = Uint8List(hex.length ~/ 2);
    for (int i = 0; i < bytes.length; i++) {
      bytes[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
    }
    return bytes;
  }
}
