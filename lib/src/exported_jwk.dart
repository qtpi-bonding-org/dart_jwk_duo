/// Data Transfer Object for type-safe JWK export with guaranteed metadata.
library;

import 'constants.dart';

/// A fully typed export object that guarantees metadata is attached to the key
/// before it becomes JSON.
/// 
/// This DTO ensures that kid, alg, and use are always present and validated
/// before serialization, preventing invalid states at compile time.
class ExportedJwk {
  /// The underlying JWK data as a Map
  final Map<String, dynamic> _keyData;
  
  /// Key identifier (kid) - RFC 7638 JWK thumbprint used for key lookup
  final String keyId;
  
  /// Algorithm (alg) - must match the key type and intended use
  final String alg;
  
  /// Public key use (use) - either 'sig' for signing or 'enc' for encryption
  final String use;
  
  /// Creates a new ExportedJwk with validation.
  /// 
  /// Validates that the algorithm and use are consistent with the key type.
  /// Throws [ArgumentError] if validation fails.
  /// 
  /// [keyData] - The JWK data as a Map
  /// [keyId] - RFC 7638 JWK thumbprint (populates 'kid' field)
  /// [alg] - Algorithm identifier
  /// [use] - Public key use ('sig' or 'enc')
  ExportedJwk({
    required Map<String, dynamic> keyData,
    required this.keyId,
    required this.alg,
    required this.use,
  }) : _keyData = Map.unmodifiable(keyData) {
    _validate();
  }
  
  /// Converts the ExportedJwk to a JSON Map.
  /// 
  /// Merges the raw key data with the metadata (kid, alg, use).
  /// The keyId (RFC 7638 thumbprint) becomes the 'kid' field in the JSON output.
  /// Returns a Map suitable for JSON serialization.
  Map<String, dynamic> toJson() {
    final Map<String, dynamic> result = Map<String, dynamic>.from(_keyData);
    
    // Add metadata fields
    result['kid'] = keyId;  // RFC 7638 JWK thumbprint
    result['alg'] = alg;
    result['use'] = use;
    
    return result;
  }
  
  /// Creates a public-only version of this ExportedJwk.
  /// 
  /// STRICTLY copies only the standard public RSA components (kty, n, e).
  /// Any other fields in the source map are dropped to prevent 
  /// accidental leakage of private data or non-standard metadata.
  /// 
  /// Returns a new ExportedJwk containing only public key components.
  ExportedJwk toPublicOnly() {
    // Allowlist approach: Only take what we explicitly know is public.
    final Map<String, dynamic> publicKeyData = {
      'kty': _keyData['kty'],  // Key type (RSA)
      'n': _keyData['n'],      // Modulus
      'e': _keyData['e'],      // Public exponent
    };
    
    // Check for nulls just in case the source was malformed
    if (publicKeyData.containsValue(null)) {
      throw FormatException('Cannot create public key: Source JWK missing n, e, or kty');
    }
    
    return ExportedJwk(
      keyData: publicKeyData,
      keyId: keyId,
      alg: alg,
      use: use,
    );
  }
  
  /// Validates that the algorithm and use are consistent.
  /// 
  /// Throws [ArgumentError] if validation fails.
  void _validate() {
    // Validate algorithm and use combinations
    if (alg == JwkAlgorithm.ps256 && use != JwkUse.signature) {
      throw ArgumentError('PS256 algorithm must be used with "sig" use');
    }
    
    if (alg == JwkAlgorithm.rsaOaep256 && use != JwkUse.encryption) {
      throw ArgumentError('RSA-OAEP-256 algorithm must be used with "enc" use');
    }
    
    if (use == JwkUse.signature && alg != JwkAlgorithm.ps256) {
      throw ArgumentError('Signature use must be used with PS256 algorithm');
    }
    
    if (use == JwkUse.encryption && alg != JwkAlgorithm.rsaOaep256) {
      throw ArgumentError('Encryption use must be used with RSA-OAEP-256 algorithm');
    }
    
    // Validate key type
    if (_keyData['kty'] != JwkKeyType.rsa) {
      throw ArgumentError('Only RSA keys are supported');
    }
  }
}