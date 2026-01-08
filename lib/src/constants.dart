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

