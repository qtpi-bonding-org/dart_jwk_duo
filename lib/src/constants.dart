/// Constants for JWK field values and algorithms.
library;

/// JWK key type constants
class JwkKeyType {
  const JwkKeyType._();
  
  /// Elliptic Curve key type (used for both signing and encryption)
  static const String ec = 'EC';
}

/// JWK algorithm constants
class JwkAlgorithm {
  const JwkAlgorithm._();
  
  /// ECDSA using P-256 and SHA-256
  static const String es256 = 'ES256';
  
  /// ECDH Ephemeral Static key agreement using Concat KDF and CEK wrapped with "A256KW"
  static const String ecdhEs256 = 'ECDH-ES+A256KW';
}

/// JWK use (public key use) constants
class JwkUse {
  const JwkUse._();
  
  /// Signature use
  static const String signature = 'sig';
  
  /// Encryption use
  static const String encryption = 'enc';
}

/// Elliptic curve names
class JwkCurve {
  const JwkCurve._();
  
  /// NIST P-256 curve
  static const String p256 = 'P-256';
}

/// Default key identifiers
class DefaultKeyIds {
  const DefaultKeyIds._();

  /// Default signing key identifier
  static const String signing = 'master-signing';

  /// Default encryption key identifier
  static const String encryption = 'master-encryption';
}

/// Cryptographic size constants (bytes unless noted)
class CryptoSizes {
  const CryptoSizes._();

  /// AES-GCM initialization vector length (12 bytes / 96 bits)
  static const int aesGcmIvLength = 12;

  /// AES-GCM authentication tag length (16 bytes / 128 bits)
  ///
  /// Appended to the ciphertext by `webcrypto`, so an AES-GCM ciphertext is
  /// always exactly this much longer than its plaintext.
  static const int aesGcmTagLength = 16;

  /// HKDF salt length (32 bytes / 256 bits, matches SHA-256 output per RFC 5869)
  static const int hkdfSaltLength = 32;

  /// SEC1 uncompressed point tag, the leading byte of `04 || x || y`.
  ///
  /// Defined in SEC1 §2.3.3 and identically in ANSI X9.62 and RFC 5480.
  /// The compressed tags (0x02, 0x03) are not used by this library.
  static const int sec1UncompressedTag = 0x04;

  /// EC P-256 SEC1 uncompressed public key length in bytes.
  ///
  /// 1 tag byte + 32-byte x + 32-byte y. This is the only public key byte
  /// encoding this library emits or accepts, and it is what WebCrypto calls
  /// the `"raw"` format.
  static const int ecP256Sec1PublicKeyLength = 65;

  /// EC P-256 SEC1 uncompressed public key length in hex characters (130).
  static const int ecP256Sec1PublicKeyHexLength =
      ecP256Sec1PublicKeyLength * 2;

  /// ECDSA P-256 signature length
  static const int ecdsaP256SignatureLength = 64;

  /// Fixed header length of a hybrid-encrypted blob.
  ///
  /// The layout is entirely fixed-size:
  ///
  /// ```
  /// | ephemeral SEC1 public key | HKDF salt | AES-GCM IV | ciphertext + tag |
  /// |         65 bytes          | 32 bytes  |  12 bytes  |     variable     |
  /// ```
  ///
  /// There are no length prefixes and nothing is JSON-encoded, so parsing is
  /// a handful of constant offsets and there is no attacker-controlled length
  /// to bound.
  static const int hybridHeaderLength =
      ecP256Sec1PublicKeyLength + hkdfSaltLength + aesGcmIvLength;
}

