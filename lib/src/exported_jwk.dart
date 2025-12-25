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
  Map<String, dynamic> toJson() {
    final Map<String, dynamic> result = Map<String, dynamic>.from(_keyData);
    result['kid'] = keyId;
    result['alg'] = alg;
    result['use'] = use;
    return result;
  }
  
  /// Creates a public-only version of this ExportedJwk.
  /// 
  /// For EC keys: copies kty, crv, x, y
  /// For RSA keys: copies kty, n, e
  ExportedJwk toPublicOnly() {
    final String? kty = _keyData['kty'] as String?;
    
    final Map<String, dynamic> publicKeyData;
    
    if (kty == JwkKeyType.ec) {
      // EC key - copy curve and coordinates
      publicKeyData = {
        'kty': _keyData['kty'],
        'crv': _keyData['crv'],
        'x': _keyData['x'],
        'y': _keyData['y'],
      };
    } else if (kty == JwkKeyType.rsa) {
      // RSA key - copy modulus and exponent
      publicKeyData = {
        'kty': _keyData['kty'],
        'n': _keyData['n'],
        'e': _keyData['e'],
      };
    } else {
      throw const FormatException('Unknown key type');
    }
    
    if (publicKeyData.containsValue(null)) {
      throw const FormatException('Cannot create public key: missing required components');
    }
    
    return ExportedJwk(
      keyData: publicKeyData,
      keyId: keyId,
      alg: alg,
      use: use,
    );
  }
  
  void _validate() {
    final String? kty = _keyData['kty'] as String?;
    
    // Validate ES256 (ECDSA P-256) for signing
    if (alg == JwkAlgorithm.es256) {
      if (use != JwkUse.signature) {
        throw ArgumentError('ES256 algorithm must be used with "sig" use');
      }
      if (kty != JwkKeyType.ec) {
        throw ArgumentError('ES256 algorithm requires EC key type');
      }
    }
    
    // Validate RSA-OAEP-256 for encryption
    if (alg == JwkAlgorithm.rsaOaep256) {
      if (use != JwkUse.encryption) {
        throw ArgumentError('RSA-OAEP-256 algorithm must be used with "enc" use');
      }
      if (kty != JwkKeyType.rsa) {
        throw ArgumentError('RSA-OAEP-256 algorithm requires RSA key type');
      }
    }
    
    // Validate use matches algorithm
    if (use == JwkUse.signature && alg != JwkAlgorithm.es256) {
      throw ArgumentError('Signature use must be used with ES256 algorithm');
    }
    
    if (use == JwkUse.encryption && alg != JwkAlgorithm.rsaOaep256) {
      throw ArgumentError('Encryption use must be used with RSA-OAEP-256 algorithm');
    }
  }
}
