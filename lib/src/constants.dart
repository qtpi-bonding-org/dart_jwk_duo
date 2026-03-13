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

  /// HKDF salt length (32 bytes / 256 bits, matches SHA-256 output per RFC 5869)
  static const int hkdfSaltLength = 32;

  /// EC P-256 uncompressed public key length (04 prefix + 32-byte x + 32-byte y)
  static const int ecP256RawPublicKeyLength = 65;

  /// EC P-256 coordinate data length (32-byte x + 32-byte y, no prefix)
  static const int ecP256CoordinatesLength = 64;

  /// EC P-256 public key hex string length (64 bytes as hex = 128 chars)
  static const int ecP256PublicKeyHexLength = 128;

  /// ECDSA P-256 signature length
  static const int ecdsaP256SignatureLength = 64;

  /// Wire format length prefix size (4 bytes, big-endian uint32)
  static const int lengthPrefixSize = 4;

  /// Maximum allowed ephemeral key length in wire format (prevents DoS)
  static const int maxEphemeralKeyLength = 4096;
}

