/// Configuration for key identifier formatting.
library;

/// Configuration for key identifier formatting.
/// 
/// This library strictly follows RFC 7638 where the key identifier (kid)
/// is the SHA-256 thumbprint of the canonical JWK representation.
/// 
/// The 'use' field (sig/enc) already distinguishes between signing and
/// encryption keys, making prefixes unnecessary and ensuring maximum
/// interoperability with other systems.
class KeyIdFormatting {
  /// Creates a new KeyIdFormatting configuration.
  /// 
  /// All keys use standard RFC 7638 thumbprints as identifiers.
  const KeyIdFormatting();
  
  /// Default configuration using standard RFC 7638 thumbprints
  static const KeyIdFormatting defaultConfig = KeyIdFormatting();
}