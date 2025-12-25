/// Constants for JWK field values and algorithms.
library;

/// JWK key type constants
class JwkKeyType {
  const JwkKeyType._();
  
  /// RSA key type
  static const String rsa = 'RSA';
  
  /// Elliptic Curve key type
  static const String ec = 'EC';
}

/// JWK algorithm constants
class JwkAlgorithm {
  const JwkAlgorithm._();
  
  /// ECDSA using P-256 and SHA-256
  static const String es256 = 'ES256';
  
  /// RSA-OAEP using SHA-256 and MGF1 with SHA-256
  static const String rsaOaep256 = 'RSA-OAEP-256';
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

/// RSA cryptographic parameters
class RsaParameters {
  const RsaParameters._();
  
  /// Default modulus length in bits (NIST recommendation for use until 2030)
  static const int modulusLength = 2048;
  
  /// Enhanced security modulus length for long-term protection beyond 2030
  static const int modulusLength3072 = 3072;
  
  /// High security modulus length for maximum protection
  static const int modulusLength4096 = 4096;
  
  /// Public exponent (standard value)
  static const int publicExponent = 65537;
}