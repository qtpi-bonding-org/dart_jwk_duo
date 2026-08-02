/// SEC1 uncompressed encoding of P-256 public keys.
library;

import 'dart:typed_data';
import 'constants.dart';
import 'hex_codec.dart';

/// Encoding rules for SEC1 uncompressed P-256 public keys (`04 || x || y`).
///
/// This is the only public key encoding this library speaks. It is SEC1
/// §2.3.3, and identically ANSI X9.62, RFC 5480, TLS, OpenSSL and WebCrypto's
/// `"raw"` format — 65 bytes, or 130 hex characters, always tagged `04`.
///
/// Both [SigningKeyPair] and [EncryptionKeyPair] route through here, so the
/// two key types are byte-for-byte interchangeable at the encoding boundary.
/// That is intentional: a P-256 public key carries no indication of whether
/// it is meant for signing or for key agreement. Purpose must be carried by
/// field names and types, never inferred from the bytes.
///
/// Everything here throws [FormatException] on malformed input, matching what
/// `webcrypto` throws for a well-formed byte string that is not a point on
/// the curve.
class Sec1PublicKey {
  const Sec1PublicKey._();

  /// Validate that [raw] is a structurally well-formed SEC1 uncompressed point.
  ///
  /// Checks the byte length and the `04` tag only. Whether the point actually
  /// lies on P-256 is not knowable here; that check happens inside
  /// `webcrypto`/BoringSSL when the bytes are imported, and it does reject
  /// off-curve points.
  ///
  /// Returns [raw] unchanged so it can be used inline.
  /// Throws [FormatException] if the length or tag is wrong.
  static Uint8List validateRaw(Uint8List raw) {
    if (raw.length != CryptoSizes.ecP256Sec1PublicKeyLength) {
      throw FormatException(
        'SEC1 public key must be ${CryptoSizes.ecP256Sec1PublicKeyLength} '
        'bytes (got ${raw.length})',
      );
    }

    if (raw[0] != CryptoSizes.sec1UncompressedTag) {
      throw FormatException(
        'SEC1 public key must begin with the uncompressed tag '
        '0x${CryptoSizes.sec1UncompressedTag.toRadixString(16).padLeft(2, '0')} '
        '(got 0x${raw[0].toRadixString(16).padLeft(2, '0')})',
      );
    }

    return raw;
  }

  /// Decode a 130-character SEC1 hex string into its 65 raw bytes.
  ///
  /// Throws [FormatException] if the length is not 130, if any character is
  /// not a hex digit, or if the leading byte is not `04`.
  static Uint8List decodeHex(String sec1Hex) {
    return validateRaw(HexCodec.decode(
      sec1Hex,
      expectedLength: CryptoSizes.ecP256Sec1PublicKeyHexLength,
    ));
  }

  /// Encode 65 raw SEC1 bytes as a 130-character lowercase hex string.
  ///
  /// Throws [FormatException] if [raw] is not a well-formed SEC1 point.
  static String encodeHex(Uint8List raw) {
    return HexCodec.encode(validateRaw(raw));
  }
}
