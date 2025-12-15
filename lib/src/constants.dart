/// Constants for JWK field values and algorithms.
library;

/// JWK key type constants
class JwkKeyType {
  static const String rsa = 'RSA';
  
  const JwkKeyType._();
}

/// JWK algorithm constants
class JwkAlgorithm {
  /// RSA-PSS using SHA-256 and MGF1 with SHA-256
  static const String ps256 = 'PS256';
  
  /// RSA-OAEP using SHA-256 and MGF1 with SHA-256
  static const String rsaOaep256 = 'RSA-OAEP-256';
  
  const JwkAlgorithm._();
}

/// JWK use (public key use) constants
class JwkUse {
  /// Signature use
  static const String signature = 'sig';
  
  /// Encryption use
  static const String encryption = 'enc';
  
  const JwkUse._();
}

/// Default key identifiers
class DefaultKeyIds {
  /// Default signing key identifier
  static const String signing = 'master-signing';
  
  /// Default encryption key identifier
  static const String encryption = 'master-encryption';
  
  const DefaultKeyIds._();
}

/// RSA cryptographic parameters
class RsaParameters {
  /// Default modulus length in bits (NIST recommendation for use until 2030)
  static const int modulusLength = 2048;
  
  /// Enhanced security modulus length for long-term protection beyond 2030
  static const int modulusLength3072 = 3072;
  
  /// High security modulus length for maximum protection
  static const int modulusLength4096 = 4096;
  
  /// Public exponent (standard value)
  static const int publicExponent = 65537;
  
  const RsaParameters._();
}